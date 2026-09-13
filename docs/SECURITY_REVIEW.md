# AegisScan — Security Review & Scanner Improvement Report

**Scope:** full security review of the AegisScan application itself, plus an assessment of scanner detection coverage with implemented improvements and a roadmap toward broader vulnerability discovery.
**Version reviewed:** 1.1.0 → improvements shipped in **1.2.0** (this document tracks both).
**Reviewer:** AegisScan self-assessment (code audit + self-scans + targeted functional tests).

---

## Part 1 — Security review of the application

Method: manual code audit of every module (`core/`, `scanners/`, `server/`, `web/`, `cli.py`) focused on the tool's own attack surface, plus machine self-scans with the CI gate configuration.

### Findings and dispositions

| ID | Finding | Severity | Disposition |
|---|---|---|---|
| A-1 | **Dashboard had no Host-header validation (DNS-rebinding).** The server binds 127.0.0.1, but a malicious webpage can rebind its own hostname to 127.0.0.1; the browser then treats the dashboard API as same-origin and can silently start scans, read results, or overwrite the AI provider/key. | High | **Fixed in 1.2.0** — every GET/POST/DELETE now rejects requests whose `Host` is not a loopback name (`127.0.0.1`, `localhost`, `::1`); override via `AEGISSCAN_ALLOWED_HOSTS`. |
| A-2 | **Unbounded POST body (JSON bomb).** `/api/scans` read any `Content-Length`, allowing memory exhaustion of the dashboard process. | Medium | **Fixed in 1.2.0** — requests capped at 1 MB (`MAX_BODY_BYTES`), violations return 400. |
| A-3 | **AI API key stored world-readable.** `aegisscan-data/config.json` is created with default permissions, exposing a real provider key to other local users on multi-user hosts. | Medium | **Fixed in 1.2.0** — `chmod 0600` on POSIX after every save (Windows per-user profile ACLs already apply). Documented. |
| A-4 | **Missing `X-Content-Type-Options: nosniff`** on dashboard responses. | Low | **Fixed in 1.2.0** — added to every response. |
| A-5 | **Dashboard has no authentication.** | Info | **Accepted risk (design):** localhost-only tool; the bind address plus the new Host guard confine it to the local user. Not intended for multi-user or remote exposure — documented in SECURITY.md. |
| A-6 | **The web scanner is an SSRF-capable surface** (fetches arbitrary URLs the operator provides, including internal ranges). | Info | **Accepted risk (design):** scanning internal targets is a legitimate use of a local security tool. The DNS-rebinding fix (A-1) is what prevents a *remote* attacker from weaponizing it. |
| A-7 | **TLS verification disabled when scanning targets** (`verify=False` in `fetch`). | Info | **Accepted risk (design):** auditing servers with broken/self-signed TLS is the tool's job. Note: AI/OSV/GitHub API calls use the verified default context — only scan-target traffic is permissive. |
| A-8 | **SAST evidence lines can contain secret-shaped text** and flow into reports. | Low | **Mitigated:** the secrets module redacts evidence to 4 chars; SAST shows the matched line (needed for triage). Operators are reminded reports may contain sensitive evidence — handle them accordingly (documented in USER_GUIDE). |
| A-9 | **Report HTML injection from scanned content.** Finding titles/locations come from *scanned repos/websites* (attacker-influenceable if you scan hostile code). | — | **Verified safe:** every interpolated value passes through `esc()` (HTML-escape) in `report.py`; the AI markdown renderer escapes first and then applies formatting. No injection paths found. |
| A-10 | **GitHub tarball extraction.** | — | **Verified safe:** members are name-normalized and extracted with `filter="data"` (Python 3.12+ safe-extraction filter), blocking path traversal and special files. |
| A-11 | **Dashboard served over plain HTTP.** | Info | **Accepted risk (design):** loopback-only; adding TLS to a localhost tool adds key-management burden without threat reduction. Do not port-forward it; use SSH tunneling if remote access is ever needed. |
| A-12 | **Supply chain: zero third-party dependencies.** | — | **Verified strength:** stdlib-only eliminates dependency-vector compromise entirely; `update` pulls only from the project's own GitHub repo over TLS. |
| A-13 | **Path traversal in static file route.** | — | **Verified safe:** `/static/` requests are normalized and rejected if they escape the web root. |

**Self-scan evidence:** CI-parity scan of the repo (`--exclude aegisscan/scanners aegisscan/web examples tests aegisscan-data`, rules self-match by design) exits 0 with only 4 accepted-medium findings (scanner plumbing: intentional `verify=False` fallbacks and one SHA-1 use for fingerprint IDs).

---

## Part 2 — Scanner coverage improvements (implemented in 1.2.0)

The goal: **find more real vulnerabilities**. Every addition below is functional-tested against fixture code or a live local target.

### 2.1 Secret detection — 17 → 26 provider patterns (+53%)
Added: GitLab PAT, npm tokens, PyPI upload tokens, Telegram bot tokens, Azure Storage account keys, Facebook/page tokens, Shopify tokens (shpat/shpca/shppa), Square tokens, X/Twitter bearer tokens. Quantifiers widened to tolerant ranges (e.g. npm `{32,40}`) to survive provider format drift. Verified: sample tokens for GitLab/npm/Azure/Telegram all match.

### 2.2 SAST — 43 → 70 sink patterns; Kubernetes & compose hardening
New vulnerability classes across Python/JS/TS/Java/PHP/Go/C#:

- **Open redirect** (Flask/Django-style, Express `res.redirect`, PHP `header('Location:')`, ASP.NET `Response.Redirect`)
- **Path traversal** (`send_file(request…)`, `os.path.join(request…)`, `filepath.Join`, `Path.Combine`, Java `FileInputStream(request.getParameter)`)
- **JWT forgery** — `verify=False` / `options.verify_signature: False` / `algorithms=['none']` in Python and JS (CRITICAL)
- **SSTI** — dynamic `jinja2.Template(...)`
- **Prototype pollution** — merge/assign of request data (CWE-1321)
- **LFI/RFI** — PHP `include $_GET[...]` (CRITICAL)
- **JNDI injection** (Log4Shell-class), **SpEL injection**, **XPath injection** (Java)
- **Node `vm` code execution**, **header injection**, **`spawn(..., {shell:true})`**
- **`os.popen`**, **Django `.raw()`** formatted SQL, **`sh -c`** (Go)
- **Razor `Html.Raw`** XSS (C#)
- **Kubernetes manifests**: privileged containers (CRITICAL), hostPath, hostNetwork, runAsUser:0, allowPrivilegeEscalation, SYS_ADMIN/NET_ADMIN capabilities
- **docker-compose**: privileged, cap_add SYS_ADMIN/NET_ADMIN, `pid: host`, `network_mode: host`

Verified: fixture files trigger K8s privileged + hostPath + compose rules; demo app now yields JWT-forgery (critical), prototype pollution (high), open-redirect ×2 and traversal findings.

### 2.3 Web/DAST — 29 exposed-path probes (+11) and 5 new check families
- New exposed targets: `.htpasswd` (CRITICAL), `.env.bak`/`.env.local` (CRITICAL), `/id_rsa` (CRITICAL), Jenkins, Tomcat Manager, Adminer, Solr, Apache `server-info`, `.idea/workspace.xml`
- **Open-redirect probe**: injects `//evil-aegisscan-probe.example.org/` into common redirect parameters (`next`, `url`, `return`, `to`, …) and detects 3xx `Location` redirection off-site — verified live against a vulnerable test endpoint
- **CORS + credentials escalation**: origin reflection *with* `Access-Control-Allow-Credentials: true` now rates CRITICAL (authenticated-data theft)
- **Mixed content**: active `http://` scripts on HTTPS pages
- **Cache-Control on cookie responses** (session leakage via caches)
- **HTTP Basic auth over plain HTTP**
- Supporting change: `fetch(follow=False)` surfaces 3xx responses instead of following them

### 2.4 Network — 29 risky-service signatures (+13) and 76 default ports (+16)
Added critical/high exposures frequently found in real environments: **etcd 2379** (cluster secret store, CRITICAL), **kubelet 10250/10255**, **Hadoop YARN 8088** (unauth RCE, CRITICAL), **Spark REST 6066**, RabbitMQ management, ActiveMQ console, Cassandra, InfluxDB, **Consul 8500**, **Mesos 5050**, Splunk 8089, Prometheus (info). Plus a banner-verified **Grafana** check.

### 2.5 SCA — offline DB 19 → 29 notorious CVEs; NuGet + crates.io support
Added: struts2-core (CVE-2023-50164), fastjson, shiro-core, jackson-databind, x/net (HTTP/2 rapid reset), jsonwebtoken (JS JWT forgery), ejs RCE, handlebars, ws, gunicorn. Manifest parsing now covers **`.csproj` (NuGet)** and **`Cargo.toml` (crates.io)** in addition to the existing 8 ecosystems — all query OSV.dev online and fall back to the offline DB.

### Detection-count effect on the demo target
`aegisscan demo`: 25 findings (v1.1.0) → **247** (v1.2.0, mostly real SCA CVE matches now that the module's manifest-parser bug is fixed and patterns broadened), including the new critical classes above.

---

## Part 3 — Roadmap toward "find all vulnerabilities"

No scanner finds *all* vulnerabilities; these are the highest-leverage next steps, in priority order:

1. **Taint/data-flow analysis** — the SAST engine is sink-based (pattern + line). A lightweight intra-file taint tracker (source: `request.*`/`req.*` → sink) would cut false positives and catch indirect flows (e.g. `send_file(p)` where `p` is built two lines earlier).
2. **Git-history secret scanning** — current secrets module scans the working tree only; walking `git log -p` (or all refs) would catch rotated-but-historical leaks.
3. **Authenticated web scanning** — session cookies/tokens in the scan config so DAST reaches post-login surfaces, plus per-page authorization differential checks (IDOR detection).
4. **API/OpenAPI-aware DAST** — parse `swagger.json`/`openapi.json` and probe every endpoint+parameter instead of link crawling; add JSON-body injection probes.
5. **SBOM generation (CycloneDX/SPDX)** — SCA already resolves the full dependency graph; emitting an SBOM enables VEX and downstream tooling.
6. **CVSS 3.1/4 vector computation** — derive precise vectors (AV/AC/PR/UI…) per finding instead of class defaults, improving prioritization fidelity.
7. **Differential scanning & baselines** — compare scans over time, flag *new* findings only (CI-noise reduction) and track remediation SLAs.
8. **More languages for SAST** — Ruby, Rust, Kotlin, Swift, VB.NET, and template engines (Jinja/EJS/Twig source files, not just sinks).
9. **Container image scanning** — layer inspection for secrets/config drift (`.dockerenv`, baked-in keys, world-writable files) beyond Dockerfile rules.
10. **Passive proxy mode** — an optional MITM recording proxy: browse the app, then scan the recorded traffic (finds authenticated + JS-driven endpoints with zero active probing).
11. **Finding correlation engine** — fuse related findings (same host: SAST SQLi + exposed admin + weak creds) into attack-chain narratives, raising composite severity.
12. **Exploitability context** — EPSS-style likelihood and "known-exploited" (CISA KEV) tagging for SCA findings to rank what attackers actually use.

---

## Verification log (1.2.0)

| Check | Result |
|---|---|
| Secrets self-test (GitLab/npm/Azure/Telegram samples) | ✅ all match |
| SAST fixture test (K8s privileged, hostPath, compose privileged) | ✅ all flagged |
| Demo scan exercises new classes (JWT forgery, prototype pollution, open redirect, traversal) | ✅ flagged with expected severities |
| Open-redirect probe vs live vulnerable endpoint | ✅ detected via `to` param |
| No-follow fetch returns 3xx (302, 404 control) | ✅ |
| SCA offline DB flags jsonwebtoken 8.5.1 | ✅ CVE-2022-23540 |
| NuGet/Cargo parsers extract versions | ✅ |
| Port scanner regression on live targets | ✅ |
| CI-parity self-scan (`--fail-on critical`) | ✅ exit 0 |
| Host-header guard: foreign Host rejected | ✅ live: forged `Host: attacker.example.com` → 403 on GET and POST; loopback Host → 200 |

*Review date: 2026-09-13 · AegisScan 1.2.0*
