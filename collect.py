#!/usr/bin/env python3
"""Periodic collection of candidate domains for the CSuite campaign via urlscan.io.

Produces CANDIDATES with a heuristic confidence level. It does not verify that
a domain is malicious: that still requires manual analysis.

State files (repository root):
  state.json   full state (meta + IOCs). Each IOC's "status" field can be edited
               by hand (new | reviewed | blocked | false_positive); the script
               never overwrites it.
  iocs.csv     export of the state, regenerated on every run.
  iocs.kql     KQL `let` statements (domains, regex, IPs, URLs) to paste in front
               of a hunting query (see KQL_detection_rule.kql).
  domains.txt  one domain/hostname per line (for `externaldata` once the repo
  ips.txt      is public, or for any other tool that wants plain lists).
  urls.txt     URLs without query string.

The kql/txt exports honour MIN_CONFIDENCE and skip status=false_positive.

Platform hosts where the tenant lives in the URL path (storage.googleapis.com, S3
path-style, docs.google.com, ...) are tracked at URL level only (key "host/bucket",
scope "url") and never appear in domains.txt, iocs.kql hosts or the iocs.csv hosts
column.

Environment variables:
  URLSCAN_API_KEY          required
  MIN_CONFIDENCE           low | medium | high (default low = everything).
                           KQL_MIN_CONFIDENCE is still read as a fallback.
  BACKFILL_DAYS            optional, one-off history window in days (e.g. 60).
                           Queries that come back incomplete (plan result ceiling
                           or page cap) are re-run one day at a time.
  INITIAL_LOOKBACK_HOURS   first-run window when there is no state (default 24)
"""
import csv
import ipaddress
import json
import math
import os
import re
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
KQL_FILE = Path("iocs.kql")
DOMAINS_FILE = Path("domains.txt")
IPS_FILE = Path("ips.txt")
URLS_FILE = Path("urls.txt")

PAGE_SIZE = 100
MAX_PAGES = 5
BACKFILL_MAX_PAGES = 30
OVERLAP_HOURS = 1
MAX_LOOKBACK_HOURS = 72
INITIAL_LOOKBACK_HOURS = int(os.getenv("INITIAL_LOOKBACK_HOURS", "24"))
MIN_CONFIDENCE = (
    os.getenv("MIN_CONFIDENCE") or os.getenv("KQL_MIN_CONFIDENCE") or "low"
).strip().lower()
PAUSE_SECONDS = 1.0
USER_AGENT = "csuite-collector/0.3"

# On shared hosting the subdomain identifies the tenant, so the dedup key is
# the full hostname instead of the registrable domain. Edit freely (dyndns,
# other CDNs, etc.).
# Matched by hostname suffix, so multi-label platforms work too.
SHARED_HOSTING = {
    "vercel.app",
    "r2.dev",
    "github.io",
    "amazonaws.com",
    "pages.dev",
    "netlify.app",
    "office-on-the.net",
    "workers.dev",
    "web.app",
    "firebaseapp.com",
    "herokuapp.com",
    "onrender.com",
    "azurewebsites.net",
    "blob.core.windows.net",
    "web.core.windows.net",
    "cloudfront.net",
    "trycloudflare.com",
    "ngrok-free.app",
    "ngrok.io",
    "glitch.me",
    "blogspot.com",
    "weebly.com",
    "wixsite.com",
    "webflow.io",
    "framer.app",
    "lovable.app",
    "surge.sh",
    "myshopify.com",
}

# Platforms whose HOSTNAME is the same for everyone, with the tenant in the URL path
# (cloud storage, file sharing). Flagging the hostname would flag all legitimate
# traffic to the platform (this caused hundreds of false positives on
# storage.googleapis.com). They are tracked at URL level only: the key becomes
# "host/first-path-segment" (for example a storage bucket) and the host itself never
# goes into the host/domain exports.
PATH_TENANT_HOSTS = {
    "storage.googleapis.com",
    "firebasestorage.googleapis.com",
    "docs.google.com",
    "drive.google.com",
    "sites.google.com",
    "dropbox.com",
    "www.dropbox.com",
    "github.com",
    "raw.githubusercontent.com",
    "onedrive.live.com",
}
# Path-style S3 endpoints (s3.amazonaws.com, s3.us-east-1.amazonaws.com, s3-us-west-2...).
# Virtual-hosted buckets (bucket.s3.amazonaws.com) do not match: there the tenant is
# in the hostname.
_S3_PATH_STYLE = re.compile(r"^s3[.-]([a-z0-9-]+\.)?amazonaws\.com$")

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
    "Q3c_installer_adobe": 'filename:"Installer_Adobe.html"',
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


def is_shared_hosting(host):
    return any(host == p or host.endswith("." + p) for p in SHARED_HOSTING)


def is_path_tenant(host):
    return host in PATH_TENANT_HOSTS or bool(_S3_PATH_STYLE.match(host))


def make_key(host, url=""):
    """Dedup key, or None when the hit cannot be identified safely."""
    if is_ip(host):
        return host
    if is_path_tenant(host):
        segment = urlparse(url).path.strip("/").split("/")[0]
        # Without a path segment we cannot tell tenants apart: skip the hit.
        return f"{host}/{segment}" if segment else None
    return host if is_shared_hosting(host) else registered_domain(host)


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
        "Q3c_installer_adobe",
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


def collect_query(session, query, date_clause, max_pages):
    """Run one query over one date clause. Returns (results, truncated, total)."""
    full = f"({query}) AND {date_clause}"
    results, after, total, truncated = [], None, None, False
    for page in range(max_pages):
        data = search(session, full, after)
        if total is None and isinstance(data.get("total"), int):
            total = data["total"]
        batch = data.get("results", [])
        results.extend(batch)
        more = data.get("has_more", len(batch) >= PAGE_SIZE)
        if not batch or not more:
            break
        after = batch[-1].get("sort")
        if not after:
            break
        if page == max_pages - 1:
            truncated = True
        time.sleep(PAUSE_SECONDS)
    return results, truncated, total


def run_query(session, query, hours, max_pages, by_day):
    """Run a query over the last `hours`; in backfill mode, split by day if incomplete."""
    results, truncated, total = collect_query(
        session, query, f"date:>now-{hours}h", max_pages
    )
    incomplete = truncated or (total is not None and len(results) < total)
    if not incomplete:
        return results, False
    if not by_day:
        return results, True

    print(f"  incomplete ({len(results)} of {total}), splitting by day")
    seen = {r.get("_id") for r in results}
    any_truncated = False
    for day in range(math.ceil(hours / 24)):
        clause = f"date:>=now-{(day + 1) * 24}h"
        if day:
            clause += f" AND date:<now-{day * 24}h"
        batch, slice_truncated, _ = collect_query(session, query, clause, max_pages)
        any_truncated = any_truncated or slice_truncated
        for r in batch:
            if r.get("_id") not in seen:
                seen.add(r.get("_id"))
                results.append(r)
        time.sleep(PAUSE_SECONDS)
    return results, any_truncated


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


def migrate_platform_records(iocs):
    """Fix records created before PATH_TENANT_HOSTS existed.

    Those were keyed by the registrable domain of a platform (for example
    googleapis.com) and listed the platform host, so every device talking to the
    platform matched. Strip the host and, if still untouched, mark them as false
    positives. Run a backfill afterwards to re-create the real tenant (URL level).
    """
    fixed = []
    for key, rec in iocs.items():
        if rec.get("scope") == "url":
            continue
        # A record keyed by the platform apex itself (for example "workers.dev") would
        # match every tenant of the platform. Drop it; tenants are re-collected per host.
        if key in SHARED_HOSTING:
            if rec.get("status", "new") == "new":
                rec["status"] = "false_positive"
            rec["note"] = "platform apex: tenants are tracked per hostname"
            fixed.append(key)
            continue
        hosts = rec.get("hosts", [])
        if not any(is_path_tenant(h) for h in hosts):
            continue
        rec["hosts"] = [h for h in hosts if not is_path_tenant(h)]
        if rec.get("status", "new") == "new":
            rec["status"] = "false_positive"
        rec["note"] = "platform host: tracked at URL level only"
        fixed.append(key)
    return fixed


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
    key = make_key(host, url)
    if key is None:
        return
    url_scope = is_path_tenant(host)
    uuid = hit.get("_id") or task.get("uuid")
    seen_time = task.get("time") or run_ts

    rec = iocs.get(key)
    created = rec is None
    if created:
        rec = {
            "key": key,
            "scope": "url" if url_scope else "host",
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
    if not url_scope:
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


def select_iocs(iocs):
    """Pick what goes into the kql/txt exports (MIN_CONFIDENCE, no false positives)."""
    min_rank = RANK.get(MIN_CONFIDENCE, 0)
    domains, ips, urls = set(), set(), set()
    for rec in iocs.values():
        if rec.get("status") == "false_positive":
            continue
        if RANK.get(rec.get("confidence"), 0) < min_rank:
            continue
        key = rec["key"]
        urls.update(rec.get("urls", []))
        if rec.get("scope") == "url":
            continue  # platform tenant: URL-level only, never host/domain level
        (ips if is_ip(key) else domains).add(key)
    return sorted(domains), sorted(ips), sorted(urls)


def write_lists(domains, ips, urls):
    """Plain one-per-line lists (same shape as a urlscan-tracker domains.txt)."""
    for path, values in ((DOMAINS_FILE, domains), (IPS_FILE, ips), (URLS_FILE, urls)):
        clean = [v.replace("\r", "").replace("\n", "") for v in values]
        path.write_text(
            "\n".join(clean) + ("\n" if clean else ""), encoding="utf-8"
        )


def kql_str(value):
    # Single-line KQL string literal. Nothing from scan data ever goes into a
    # comment, only into escaped string literals.
    text = str(value).replace("\r", "").replace("\n", "")
    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def kql_array(name, values):
    if not values:
        return f"let {name} = dynamic([]);"
    body = ",\n    ".join(kql_str(v) for v in values)
    return f"let {name} = dynamic([\n    {body}\n]);"


def write_kql(domains, ips, urls, run_ts):
    """Write KQL `let` statements with the candidate IOCs (domains, IPs, URLs)."""
    if domains:
        alternation = "|".join(re.escape(d) for d in domains)
        regex = f"(?i)(^|\\.)({alternation})$"  # matches the domain and its subdomains
    else:
        regex = "a^"  # never matches
    lines = [
        f"// CSuite candidate IOCs, generated {run_ts} by collect.py",
        "// Heuristic candidates, NOT verified as malicious.",
        f"// Minimum confidence: {MIN_CONFIDENCE}. Excludes status=false_positive.",
        f"// domains: {len(domains)} | ips: {len(ips)} | urls: {len(urls)}",
        kql_array("csuite_domains", domains),
        f'let csuite_re = @"{regex}";',
        kql_array("csuite_ips", ips),
        kql_array("csuite_urls", urls),
        "",
    ]
    KQL_FILE.write_text("\n".join(lines), encoding="utf-8")


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


def build_summary(
    run_ts, hours, backfill, counts, new_keys, upgraded, iocs,
    failed, truncated, max_pages, exported,
):
    mode = "BACKFILL " if backfill else ""
    lines = [f"## CSuite {mode}collection {run_ts} ({hours}h window)", ""]
    lines.append("Heuristic candidates. None has been verified as malicious.")
    lines.append("")
    lines.append("Results per query (before deduplication):")
    lines.append("")
    for name, n in counts.items():
        lines.append(f"- {name}: {n}")
    lines.append("")
    d, i, u = exported
    lines.append(
        f"Exported (min confidence {MIN_CONFIDENCE}): "
        f"{d} domains, {i} IPs, {u} URLs."
    )
    lines.append("")
    if failed:
        lines.append(f"**Queries with errors (window not advanced):** {', '.join(failed)}")
        lines.append("")
    if truncated:
        lines.append(
            f"**Results may be incomplete (page cap {max_pages} or plan ceiling):** "
            f"{', '.join(truncated)}"
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
                    k=defang(k).replace("`", "'"),
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
    migrated = migrate_platform_records(iocs)
    if migrated:
        print(f"Migrated legacy platform records: {', '.join(migrated)}")

    backfill_raw = os.getenv("BACKFILL_DAYS", "").strip()
    backfill = bool(backfill_raw)
    if backfill:
        try:
            hours = int(backfill_raw) * 24
        except ValueError:
            sys.exit(f"BACKFILL_DAYS must be an integer, got {backfill_raw!r}")
        if hours <= 0:
            sys.exit("BACKFILL_DAYS must be positive")
        max_pages = BACKFILL_MAX_PAGES
    else:
        hours = window_hours(meta.get("last_success"), now)
        max_pages = MAX_PAGES
    print(f"Window: last {hours}h" + (" (backfill)" if backfill else ""))

    session = requests.Session()
    session.headers.update({"API-Key": api_key, "User-Agent": USER_AGENT})

    failed, truncated = [], []
    counts = {}
    new_keys, upgraded = set(), set()
    for name, query in QUERIES.items():
        print(f"[{name}]")
        try:
            results, incomplete = run_query(session, query, hours, max_pages, backfill)
        except Exception as exc:  # noqa: BLE001 - keep going with the other queries
            print(f"  ERROR: {exc}")
            failed.append(name)
            continue
        counts[name] = len(results)
        if incomplete:
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
    domains, ips, urls = select_iocs(iocs)
    write_kql(domains, ips, urls, run_ts)
    write_lists(domains, ips, urls)
    write_summary(
        build_summary(
            run_ts, hours, backfill, counts, new_keys, upgraded, iocs,
            failed, truncated, max_pages, (len(domains), len(ips), len(urls)),
        )
    )
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
