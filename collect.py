#!/usr/bin/env python3
"""Periodic collection of candidate domains for the CSuite campaign via urlscan.io.

Produces CANDIDATES with a heuristic confidence level. It does not verify that
a domain is malicious: that still requires manual analysis.

State files (repository root):
  state.json  full state (meta + IOCs). Each IOC's "status" field can be edited
              by hand (new | reviewed | blocked | false_positive); the script
              never overwrites it.
  iocs.csv    export of the state, regenerated on every run.
"""
import csv
import ipaddress
import json
import math
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests
import tldextract

API = "https://urlscan.io/api/v1/search/"
STATE_FILE = Path("state.json")
CSV_FILE = Path("iocs.csv")

PAGE_SIZE = 100
MAX_PAGES = 5
OVERLAP_HOURS = 1
MAX_LOOKBACK_HOURS = 72
INITIAL_LOOKBACK_HOURS = int(os.getenv("INITIAL_LOOKBACK_HOURS", "24"))
PAUSE_SECONDS = 1.0
USER_AGENT = "csuite-collector/0.1"

# On shared hosting the subdomain identifies the tenant, so the dedup key is
# the full hostname instead of the registrable domain. Edit freely (dyndns,
# other CDNs, etc.).
SHARED_HOSTING = {
    "vercel.app",
    "r2.dev",
    "github.io",
    "amazonaws.com",
    "pages.dev",
    "netlify.app",
    "office-on-the.net",
}

# Gate file hashes (utils.js, captcha.js, fingerprint.js) from the ANY.RUN article.
HASHES = [
    "c0eb04dcfa745653c466c34978a1f3b4e5041f526be8c2e46b8c722498ca746a",
    "74e306072561731adf55afd4de461ec0736ca22c0b458a78e7512b2701341f28",
    "394d7be5ecbe326062c1de1fb674bdcbb4dbe3ce03b4227994607047b832debd",
]

QUERIES = {
    "Q1a_edocusign": 'filename:"eDocusign.php"',
    "Q1b_esign": 'filename:"e-sign.php"',
    "Q1c_icon": 'filename:"Icon-pdf-file-svg.png"',
    "Q2_turnstile": 'page.title:"Secure Document Verification" AND filename:"yes.html"',
    "Q3a_adobe_html": 'filename:"Adobe_Installer.html"',
    "Q3b_utils_pdfviewer": 'filename:"utils.js" AND page.title:"PDF Viewer"',
    "Q4_hash": "(" + " OR ".join(f"hash:{h}" for h in HASHES) + ")",
}

RANK = {"low": 0, "medium": 1, "high": 2}
CSV_FIELDS = [
    "key", "status", "confidence", "queries", "first_seen", "last_seen",
    "ip", "asn", "title", "hosts", "urls", "uuids",
]

_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


# --------------------------------------------------------------------------
# Keys and confidence
# --------------------------------------------------------------------------
def is_ip(host):
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def registered_domain(host):
    ext = _EXTRACT(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def make_key(host):
    if is_ip(host):
        return host
    reg = registered_domain(host)
    return host if reg in SHARED_HOSTING else reg


def confidence(queries):
    """Initial heuristic, to be tuned with real data."""
    q = set(queries)
    if "Q4_hash" in q or len(q) >= 2:
        return "high"
    if q & {
        "Q1a_edocusign",
        "Q1b_esign",
        "Q2_turnstile",
        "Q3a_adobe_html",
        "Q3b_utils_pdfviewer",
        "Q3_adobe",  # legacy label from the first version; safe to drop after re-seeding
    }:
        return "medium"
    return "low"


# --------------------------------------------------------------------------
# urlscan API
# --------------------------------------------------------------------------
def search(session, query, search_after=None):
    params = {"q": query, "size": PAGE_SIZE}
    if search_after:
        params["search_after"] = ",".join(str(v) for v in search_after)
    for _ in range(4):
        resp = session.get(API, params=params, timeout=60)
        remaining = resp.headers.get("X-Rate-Limit-Remaining")
        if remaining is not None:
            window = resp.headers.get("X-Rate-Limit-Window", "?")
            print(f"  search quota ({window}): {remaining} remaining")
        if resp.status_code == 429:
            try:
                wait = int(resp.headers.get("X-Rate-Limit-Reset-After", "30"))
            except ValueError:
                wait = 30
            wait = min(wait + 1, 90)
            print(f"  429, waiting {wait}s")
            time.sleep(wait)
            continue
        resp.raise_for_status()
        return resp.json()
    raise RuntimeError("rate limit still exceeded after several retries")


def collect_query(session, query, hours):
    full = f"({query}) AND date:>now-{hours}h"
    results, after, truncated = [], None, False
    for page in range(MAX_PAGES):
        data = search(session, full, after)
        batch = data.get("results", [])
        results.extend(batch)
        more = data.get("has_more", len(batch) >= PAGE_SIZE)
        if not batch or not more:
            break
        after = batch[-1].get("sort")
        if not after:
            break
        if page == MAX_PAGES - 1:
            truncated = True
        time.sleep(PAUSE_SECONDS)
    return results, truncated


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------
def load_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {"meta": {}, "iocs": {}}


def save_state(state):
    STATE_FILE.write_text(
        json.dumps(state, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def window_hours(last_success, now):
    if last_success:
        last = datetime.strptime(last_success, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
        hours = math.ceil((now - last).total_seconds() / 3600) + OVERLAP_HOURS
    else:
        hours = INITIAL_LOOKBACK_HOURS
    return min(max(hours, 2), MAX_LOOKBACK_HOURS)


def add_unique(items, value, cap):
    if value not in items and (cap is None or len(items) < cap):
        items.append(value)


def strip_query(url):
    # Drop the query string: avoids storing tokens and session identifiers.
    return url.split("?", 1)[0]


def ingest(hit, qname, iocs, run_ts, new_keys, upgraded):
    task = hit.get("task") or {}
    page = hit.get("page") or {}
    # The search also returns your own private/unlisted scans: ignore them.
    if task.get("visibility") != "public":
        return
    url = page.get("url") or task.get("url") or ""
    host = (
        page.get("domain") or task.get("domain") or urlparse(url).hostname or ""
    ).lower()
    if not host:
        return
    key = make_key(host)
    uuid = hit.get("_id") or task.get("uuid")
    seen_time = task.get("time") or run_ts

    rec = iocs.get(key)
    created = rec is None
    if created:
        rec = {
            "key": key,
            "status": "new",
            "first_seen": seen_time,
            "first_run": run_ts,
            "queries": [],
            "hosts": [],
            "urls": [],
            "uuids": [],
        }
        iocs[key] = rec
        new_keys.add(key)

    old_rank = RANK.get(rec.get("confidence"), -1)
    rec["first_seen"] = min(rec["first_seen"], seen_time)
    rec["last_seen"] = max(rec.get("last_seen", seen_time), seen_time)
    add_unique(rec["queries"], qname, None)
    add_unique(rec["hosts"], host, 10)
    if url:
        add_unique(rec["urls"], strip_query(url), 5)
    if uuid:
        add_unique(rec["uuids"], uuid, 10)
    for field, value in (
        ("ip", page.get("ip")),
        ("asn", page.get("asn")),
        ("title", page.get("title")),
    ):
        if value and not rec.get(field):
            rec[field] = value

    rec["confidence"] = confidence(rec["queries"])
    if not created and key not in new_keys and RANK[rec["confidence"]] > old_rank:
        upgraded.add(key)


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
def csv_safe(value):
    # Prevents formula injection if the CSV is opened in Excel (page titles
    # come from content controlled by third parties).
    text = str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text


def write_csv(iocs):
    with CSV_FILE.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        writer.writeheader()
        for key in sorted(iocs):
            rec = iocs[key]
            row = {}
            for field in CSV_FIELDS:
                value = rec.get(field, "")
                if isinstance(value, list):
                    value = " | ".join(value)
                row[field] = csv_safe(value)
            writer.writerow(row)


def defang(text):
    return str(text).replace(".", "[.]")


def md_escape(text):
    return (
        str(text or "")
        .replace("|", "\\|")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\n", " ")
        .replace("\r", " ")
    )


def write_summary(lines):
    text = "\n".join(lines) + "\n"
    path = os.getenv("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(text)
    print(text)


def build_summary(run_ts, hours, counts, new_keys, upgraded, iocs, failed, truncated):
    lines = [f"## CSuite collection {run_ts} ({hours}h window)", ""]
    lines.append("Heuristic candidates. None has been verified as malicious.")
    lines.append("")
    lines.append("Results per query (before deduplication):")
    lines.append("")
    for name, n in counts.items():
        lines.append(f"- {name}: {n}")
    lines.append("")
    if failed:
        lines.append(f"**Queries with errors (window not advanced):** {', '.join(failed)}")
        lines.append("")
    if truncated:
        lines.append(
            f"**Pagination truncated at {MAX_PAGES} pages:** {', '.join(truncated)}"
        )
        lines.append("")

    def table(keys):
        rows = [
            "| Confidence | Key | Queries | IP | ASN | Title | Scan |",
            "|---|---|---|---|---|---|---|",
        ]
        ordered = sorted(keys, key=lambda k: (-RANK[iocs[k]["confidence"]], k))
        for k in ordered:
            r = iocs[k]
            scan = f"https://urlscan.io/result/{r['uuids'][0]}/" if r["uuids"] else ""
            rows.append(
                "| {c} | `{k}` | {q} | {ip} | {asn} | {t} | {s} |".format(
                    c=r["confidence"],
                    k=defang(k),
                    q=md_escape(", ".join(r["queries"])),
                    ip=defang(r.get("ip", "")),
                    asn=md_escape(r.get("asn", "")),
                    t=md_escape(r.get("title", "")),
                    s=scan,
                )
            )
        return rows

    lines.append(f"### New ({len(new_keys)})")
    lines.append("")
    lines.extend(table(new_keys) if new_keys else ["None."])
    lines.append("")
    lines.append(f"### Confidence increased ({len(upgraded)})")
    lines.append("")
    lines.extend(table(upgraded) if upgraded else ["None."])
    return lines


# --------------------------------------------------------------------------
def main():
    api_key = os.environ.get("URLSCAN_API_KEY", "").strip()
    if not api_key:
        sys.exit("URLSCAN_API_KEY is missing")

    now = datetime.now(timezone.utc)
    run_ts = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    state = load_state()
    iocs = state.setdefault("iocs", {})
    meta = state.setdefault("meta", {})
    hours = window_hours(meta.get("last_success"), now)
    print(f"Window: last {hours}h")

    session = requests.Session()
    session.headers.update({"API-Key": api_key, "User-Agent": USER_AGENT})

    failed, truncated = [], []
    counts = {}
    new_keys, upgraded = set(), set()
    for name, query in QUERIES.items():
        print(f"[{name}]")
        try:
            results, was_truncated = collect_query(session, query, hours)
        except Exception as exc:  # noqa: BLE001 - keep going with the other queries
            print(f"  ERROR: {exc}")
            failed.append(name)
            continue
        counts[name] = len(results)
        if was_truncated:
            truncated.append(name)
        for hit in results:
            ingest(hit, name, iocs, run_ts, new_keys, upgraded)
        time.sleep(PAUSE_SECONDS)

    meta["last_run"] = run_ts
    meta["window_hours"] = hours
    if not failed:
        meta["last_success"] = run_ts

    save_state(state)
    write_csv(iocs)
    write_summary(
        build_summary(run_ts, hours, counts, new_keys, upgraded, iocs, failed, truncated)
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
