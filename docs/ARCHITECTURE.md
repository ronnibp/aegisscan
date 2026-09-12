# AegisScan — Architecture

```
                    ┌──────────────────────────────────────────────────┐
                    │                     CLI (cli.py)                 │
                    │   scan · secrets · sast · sca · web · tls ·      │
                    │   ports · report · ui · demo                     │
                    └───────────────┬──────────────────────────────────┘
                                    │ ScanConfig
                    ┌───────────────▼──────────────┐
                    │        ScanEngine (core/engine.py)
                    │  target kinds → module pipeline
                    │  repo   → [secrets, sast, sca]
                    │  github → [github, secrets, sast, sca]
                    │  web    → [web, tls]
                    │  host   → [network]      tls → [tls]
                    └───┬──────┬──────┬──────┬──────┬──────┬──────┬──────┘
                        │      │      │      │      │      │      │
                   secrets  sast   sca    web    tls   network  github
                   (scanners/*.py — each returns list[Finding])
                        │
                        ▼
              ScanResult (core/models.py)
              findings · module statuses · counts · risk score · TLS grades
                        │
        ┌───────────────┼────────────────┬───────────────┐
        ▼               ▼                ▼               ▼
   report.py        server/app.py     aegisscan-data/   exit code
   HTML/MD/JSON/    stdlib HTTP API   scans/*.json      --fail-on
   SARIF            + web dashboard   (persistence)     (CI gate)
```

## Design principles

1. **Zero dependencies** — everything (HTTP client, TLS inspector, port
   scanner, web server, chart rendering) is built on the Python standard
   library. If Python runs, AegisScan runs: Windows, Linux, macOS, CI.
2. **One finding model** — every scanner emits `Finding` objects with
   severity, risk score, evidence (redacted), remediation, references, CWE and
   MITRE ATT&CK technique IDs. Reporting and the UI are pure projections.
3. **Fail-soft modules** — a crashing module marks itself `error` and never
   kills the scan; the result is flagged `partial`.
4. **Deduplicated fingerprints** — findings are identified by
   sha1(scanner, category, title, location, target) so repeats collapse.
5. **Risk model** — `risk_score` weights the top findings
   (`1.0, 0.5, 0.3, 0.2, 0.1, 0.05 × score`, clamped to 10) so one critical
   dominates a pile of infos, mirroring how practitioners triage.

## Core components

### `core/models.py`
`Severity` (ranked, with default CVSS-ish scores), `Finding`, `ModuleStatus`,
`ScanTarget`, `ScanConfig`, `ScanResult` (JSON round-trip via
`to_dict/from_dict`) and the module label registry.

### `core/mitre.py`
The ATT&CK technique catalogue relevant to AegisScan's findings
(25 techniques across 9 tactics), normalization, and `aggregate()` which
builds `{tactic: {technique: [finding ids]}}` for the UI matrix and reports.

### `core/engine.py`
`ScanEngine` maps target kinds to module pipelines, runs modules sequentially
with live `ModuleStatus` updates (the server polls this), deduplicates
findings, computes the risk score and finalizes statuses. Temporary GitHub
checkouts are cleaned up in `finally`.

### `core/report.py`
Pure string/SVG rendering. The HTML report is a self-contained document
(inline CSS, SVG gauge/donut, ATT&CK matrix, TLS tables, remediation roadmap,
print stylesheet). SARIF 2.1.0 maps findings to `rules` + `results` with
`security-severity` so GitHub Code Scanning shows severity.

### `core/utils.py`
`fetch()` (urllib wrapper: gzip/deflate, redirects, optional TLS-verify-off,
5xx/4xx uniform), file walking with binary/size filters, Shannon entropy,
ANSI console colors.

## Scanners (`scanners/`)

| Module | Method |
|---|---|
| `secrets.py` | 17 regex families for known token formats + entropy analysis near key-like identifiers + `.env`/key-file detection; values redacted to 4 chars in evidence; placeholder values (example/changeme) downgraded to info |
| `sast.py` | Per-language sink patterns (Python/JS/TS/Java/PHP/Go/C#) mapped to rich finding metadata; infrastructure rules for Dockerfile, Terraform, GitHub Actions/GitLab CI, Apache/nginx, SQL dumps |
| `sca.py` | Manifest parsers → ecosystem+name+version; batch query to OSV.dev `/v1/querybatch` (500/batch); CVSS-derived severities and fixed-version remediation; offline fallback DB for notorious CVEs |
| `web.py` | Polite same-host crawl (≤ `web_max_pages`); header hardening (grouped per header across pages); sensitive-file probes with content signatures; CORS reflection; TRACE/PUT; cookie flags; form CSRF/http analysis; non-destructive injection probes (XSS reflection, SQL error signatures, `/etc/passwd` traversal) |
| `tls.py` | Protocol matrix by pinned handshakes (SSLv2/3 → TLS 1.3); per-cipher probes classified weak/acceptable/strong + forward secrecy; certificate parse (stdlib `_test_decode_cert`), chain validation, IP/DNS SAN hostname match, HSTS parse; SSL-Labs-style grading with fatal conditions (expired cert, hostname mismatch, SSLv3) |
| `network.py` | ThreadPool TCP connect scan, banner grab (passive + benign HTTP probe), risky-service findings table |
| `github.py` | Repo slug parsing, metadata via GitHub API (posture findings incl. branch protection with token), tarball download with member-path stripping and safe extraction (`filter="data"`) |

## Server (`server/app.py`)
`ThreadingHTTPServer` with a small router: JSON API (`/api/*`) + static
dashboard. Scans run in daemon threads; `REGISTRY` holds live `ScanResult`
objects that the engine mutates, so `GET /api/scans/<id>` is live progress.
Completed scans persist to `aegisscan-data/scans/<id>.json` and are reloaded
on startup.

## UI (`web/`)
Vanilla JS single-page app (hash routing) + one stylesheet. All charts
(gauge, donut) are generated inline SVG — no CDN, works air-gapped.

## Extending
Add a scanner: create `scanners/myscanner.py` exposing `scan(...) -> list[Finding]`,
register it in `core/engine.py` (`MODULES_FOR_TARGET` + a branch in
`_run_module`), add a label in `core/models.py:MODULE_LABELS`. UI/reports pick
it up automatically.
