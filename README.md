# Csuite-collector

Scheduled collector of **candidate** infrastructure for the CSuite phishing campaign
(Adobe and DocuSign lures, Cloudflare Turnstile gate, Microsoft 365 session theft),
based on public analysis by ANY.RUN. It searches [urlscan.io](https://urlscan.io) on a
schedule, deduplicates what it finds, scores it with a simple heuristic and exports
lists ready to use in KQL (Microsoft Defender / Sentinel).

> **Read this first.** Everything here is a heuristic *candidate*, not a verified
> indicator. The lists include low-confidence entries and legitimate websites that were
> probably compromised (for example a small business site hosting a gate page). A match
> means **investigate**, not **block**. Do not wire these lists to automatic blocking or
> device isolation without a human review step.

## How it works

1. A GitHub Actions workflow runs `collect.py` every 6 hours (`17 */6 * * *`, UTC) and
   on demand.
2. For each query in `QUERIES` it calls the urlscan.io search API, paginating with
   `search_after`, over a time window that starts at the last successful run (plus one
   hour of overlap, minimum 2 h, maximum 72 h). The first run uses
   `INITIAL_LOOKBACK_HOURS` (default 24).
3. Only **public** scans are kept. The search API also returns your own private and
   unlisted scans, and those are ignored.
4. Hits are deduplicated into one record per key:
   * the registrable domain (`mail.example.com` and `example.com` become `example.com`);
   * the full hostname for shared hosting where the subdomain identifies the tenant
     (`vercel.app`, `r2.dev`, `github.io`, `amazonaws.com`, `pages.dev`, `netlify.app`,
     `office-on-the.net`; edit `SHARED_HOSTING` in `collect.py`);
   * the IP itself when the host is an IP address.
5. Each record gets a confidence level, and the state and exports are written back to
   the repository by the workflow.
6. If any query fails, the time window does **not** advance, so the next run covers the
   gap. The run exits with an error so it shows red in Actions.

### Queries

| Id | urlscan query | What it is aimed at |
|---|---|---|
| Q1a | `filename:"eDocusign.php"` | DocuSign-themed PHP build |
| Q1b | `filename:"e-sign.php"` | Same family, alternate filename |
| Q1c | `filename:"Icon-pdf-file-svg.png"` | Shared icon. Broad: also matches pages with other URL patterns (`/ftx/...`, `/dsb/...`) that may be a different family |
| Q2 | `page.title:"Secure Document Verification" AND filename:"yes.html"` | First-stage Turnstile gate page |
| Q3a | `filename:"Adobe_Installer.html"` | Adobe-themed lure |
| Q3b | `filename:"utils.js" AND page.title:"PDF Viewer"` | Gate script request. urlscan records the request even when the file returns 404 |
| Q4 | `hash:` of the three gate files (`utils.js`, `captcha.js`, `fingerprint.js`) | Complete deployments with byte-identical files. Mostly older builds |

### Confidence (heuristic, tune with real data)

* **high**: matched by Q4, or by two or more different queries.
* **medium**: matched by one of Q1a, Q1b, Q2, Q3a, Q3b.
* **low**: matched only by Q1c.

## Outputs

| File | Content |
|---|---|
| `state.json` | Full state: run metadata and one record per IOC. **This is the source of truth.** |
| `iocs.csv` | Export of the state, regenerated every run. Do not edit it, edits are overwritten |
| `iocs.kql` | KQL `let` statements: `csuite_domains`, `csuite_re`, `csuite_ips`, `csuite_urls` |
| `domains.txt` | One domain or hostname per line |
| `ips.txt` | One IP per line (only IOCs whose key is an IP, not the IP of each scan) |
| `urls.txt` | One URL per line, query string removed |

`iocs.csv` columns: `key, status, confidence, queries, first_seen, last_seen, ip, asn,
title, hosts, urls, uuids`. List fields are joined with ` | `. `ip`, `asn` and `title`
come from the first scan seen. `uuids` are urlscan result ids
(`https://urlscan.io/result/<uuid>/`).

The `iocs.kql` and `.txt` exports honour `MIN_CONFIDENCE` and skip any IOC whose
`status` is `false_positive`. The KQL regex matches the domain and its subdomains.

Safety details: query strings are stripped from stored URLs (they carry tokens and
victim identifiers), CSV cells starting with `= + - @` are prefixed to prevent formula
injection, the run summary defangs domains and IPs, and nothing taken from scan data is
ever written into a KQL comment.

### Reviewing candidates

Set an IOC's `status` in `state.json` to one of `new` (default), `reviewed`, `blocked`
or `false_positive`. The script never overwrites `status`. `false_positive` removes the
IOC from `iocs.kql`, the `.txt` lists and the hosts check.

## Setup

1. Create a GitHub repository and add `collect.py` to the root and the workflow to
   `.github/workflows/collect.yml`.
2. Add a repository secret `URLSCAN_API_KEY` (Settings, Secrets and variables, Actions).
3. Make sure the workflow can push: the workflow declares `contents: write`, but an
   organisation policy may override it (Settings, Actions, General, Workflow
   permissions).
4. Run it once manually: Actions, `csuite-collect`, Run workflow. Check the job summary
   (per-query counts and the table of new candidates) and that the state files were
   committed.

### Backfill

To load history once, run the workflow manually and set `backfill_days` (for example
`60`). Queries that come back incomplete (more matches than the plan returns, or more
than 30 pages) are re-run one day at a time. How much history you can search depends on
your urlscan plan. Errors show up in the run log.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `URLSCAN_API_KEY` | required | urlscan.io API key |
| `MIN_CONFIDENCE` | `low` | Minimum confidence for `iocs.kql` and the `.txt` lists (`low`, `medium`, `high`). `KQL_MIN_CONFIDENCE` is still read as a fallback |
| `BACKFILL_DAYS` | empty | One-off history window in days (workflow input `backfill_days`) |
| `INITIAL_LOOKBACK_HOURS` | `24` | Window for the first run when there is no state |

### Quota

With 7 queries and 4 runs a day this is roughly 30 search requests a day plus
pagination. The plan used while building this had a search quota of 1000 per day, 1000
per hour and 120 per minute. Check yours:

```
curl -s https://urlscan.io/user/quotas/ -H "API-Key: <your_key>"
```

The response also lists `queryableFields`. If a field used here is not allowed on your
plan the API answers 403.

## Using the IOCs in KQL

Two ways to hunt with the data. Both were written without access to a live workspace
and are untested there, so run them over a short window first. Advanced Hunting uses
`Timestamp`; in Sentinel use `TimeGenerated`.

* **`csuite_hosts_check.kql`** reads the `hosts` column of `iocs.csv` with
  `externaldata`, explodes it to one row per host and matches it exactly against
  `DeviceNetworkEvents` (URL host and DNS queries). The raw URL must be reachable
  without authentication, so this only works while the repository is public. It
  excludes `false_positive`. Subdomains that are not listed in `hosts` are not matched.
* **`KQL_detection_rule.kql`** expects the contents of `iocs.kql` pasted above the
  query and matches by anchored regex (domain and subdomains), IP and URL. It also
  contains a commented block for reading `domains.txt` with `externaldata`, and a
  query for `UrlClickEvents`.

### Custom detection tips (Defender)

* Use *every hour*. Near real time rules have query restrictions, and these queries use
  `externaldata` and a lookup.
* The portal limits the alert title and description to 3 `{{Column}}` placeholders.
* Map `DeviceId` as the impacted asset. For DNS events `RemoteIP` is likely to be the
  resolver, not the malicious host, so be careful using it as evidence.
* Leave automatic actions off while the list contains unverified candidates.

## Known limitations

* **Coverage.** urlscan only knows what was scanned. Hosts nobody submitted are
  invisible, and Turnstile-gated pages only show the first stage (the real phishing
  page is behind the challenge).
* **File hashes (Q4)** only match complete deployments with identical files, and the
  operator can change a file at any time. `/m/js/utils.js` often returns 404 on lure
  hosts, which is why Q3b matches on the request instead.
* **Q1c is noisy** and probably mixes more than one family.
* **Compromised legitimate sites** (old domains with a recent `/iv/...` or
  `/eDocusign.php` path) match at domain level and will also match normal traffic. The
  URL list is more specific, but keeps at most 5 URLs per IOC.
* A host without an IP and title in its record (no resolution at scan time) is weaker
  evidence than the confidence level suggests.
* The day-split query syntax used by backfill
  (`date:>=now-48h AND date:<now-24h`) has not been verified against the live API.
* The repository is public, so `iocs.csv` and `state.json` expose every candidate,
  including low-confidence ones. If that is a problem, publish only the filtered
  `.txt` lists and keep the full state somewhere private.

## Repository layout

```
.
├── .github/workflows/collect.yml   # schedule (every 6 h) + manual run + backfill input
├── collect.py                      # collector
├── state.json                      # full state (source of truth)
├── iocs.csv                        # export of the state
├── iocs.kql                        # KQL let statements
├── domains.txt / ips.txt / urls.txt
├── KQL_detection_rule.kql          # detection / retro-hunt using iocs.kql
└── csuite_hosts_check.kql          # detection using externaldata over iocs.csv
```

## References

* ANY.RUN: [CSuite attack analysis](https://any.run/cybersecurity-blog/csuite-attack-analysis/)
  (the source of the lure filenames and gate file hashes used here)
* The Hacker News: [US-focused CSuite phishing steals Microsoft 365 sessions](https://thehackernews.com/2026/09/us-focused-csuite-phishing-steals.html)
* ANY.RUN TI Lookup pivot for manual enrichment: `url:"/m/js/utils.js$"`
* urlscan.io [search API](https://urlscan.io/docs/api/) and
  [rate limits](https://docs.urlscan.io/pages/api-rate-limits)
