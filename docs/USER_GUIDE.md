# AegisScan — User Guide

Everything you need to install, scan and report with AegisScan on **Windows, Linux and macOS**.

---

## 1. Installation

AegisScan needs only **Python 3.9 or newer**. There are **no third-party packages** to install.

### Windows
```powershell
# check python (3.9+)
python --version

# from the project folder
cd path\to\aegisscan
python -m aegisscan --help

# optional: install as a global `aegisscan` command
pip install .
```

### Linux / macOS
```bash
python3 --version
cd /path/to/aegisscan
python3 -m aegisscan --help

# optional global install
pip3 install .
```

> Tip: `aegisscan` and `python -m aegisscan` are equivalent. Data (scan results and reports) is written to `./aegisscan-data/` by default — set `AEGISSCAN_DATA` to change the location.

---

## 2. Your first scan (60 seconds)

```bash
python -m aegisscan demo
```

This scans a bundled intentionally-vulnerable application and prints colorized
findings, then writes a full HTML + JSON report to `aegisscan-data/reports/`.
Open the HTML report in a browser — it contains the executive summary, risk
gauge, remediation roadmap and every finding with its fix.

---

## 3. Scan types

### 3.1 Local repository / codebase (Secrets + SAST + SCA)
```bash
python -m aegisscan scan --repo /path/to/project -v
```
Runs:
- **Secret Detection** — cloud keys, tokens, private keys, connection strings, `.env` files
- **Static Analysis (SAST)** — injection sinks, weak crypto, unsafe deserialization, Dockerfile/Terraform/CI checks
- **Dependency Analysis (SCA)** — parses `requirements.txt`, `package.json`/`package-lock.json`, `pom.xml`, `go.mod`, `composer.json`, `Gemfile` and queries OSV.dev (use `--offline` for the built-in database)

Individual tools:
```bash
python -m aegisscan secrets --repo .
python -m aegisscan sast    --repo .
python -m aegisscan sca     --repo .          # add --offline to skip the network
```

### 3.2 GitHub repository
```bash
python -m aegisscan scan --github owner/repo
python -m aegisscan scan --github https://github.com/owner/repo
```
Downloads the default branch, runs the full code pipeline, and adds repository
posture findings (public repo, missing license, unprotected default branch).

For private repositories or higher API rate limits:
```bash
export GITHUB_TOKEN=github_pat_xxx      # Windows: setx GITHUB_TOKEN "github_pat_xxx"
```

### 3.3 Website / web application (DAST + TLS)
```bash
python -m aegisscan scan --url https://example.com --max-pages 25
```
Checks security headers, exposed sensitive files (`.env`, `.git`, backups,
phpinfo, actuator…), TLS downgrade, permissive CORS, TRACE method, cookie
flags, CSRF-less login forms and light non-destructive injection probes
(reflected XSS, SQL errors, path traversal). Disable probes with
`--no-injection`. Because the target is HTTPS, a full TLS audit runs too.

### 3.4 TLS / SSL audit (SSL-Labs-style)
```bash
python -m aegisscan tls --https example.com
```
Enumerates offered protocols and cipher suites, checks forward secrecy,
certificate chain/expiry/hostname match and HSTS, then prints an **A+ … F grade**:

```
TLS / SSL audit — example.com
  grade: A  (92/100)
    SSLv3    ✖ not offered
    TLS 1.2  ✔ offered
    TLS 1.3  ✔ offered
  cert: example.com (DigiCert Inc), expires Mar 12 2027 GMT, 546 days left
```

### 3.5 Network ports
```bash
python -m aegisscan ports --host 10.0.0.5 --ports top100     # or 1-1024, 80,443,3389
```
TCP connect scan with banner grabbing and risky-service findings (exposed
Docker API, Redis, MongoDB, RDP, SMB, databases…). No root/admin needed.

### 3.6 Everything at once
```bash
python -m aegisscan scan --repo ./app --url https://app.example.com --host app.example.com --https app.example.com
```

---

## 4. The web dashboard

```bash
python -m aegisscan ui                 # opens http://127.0.0.1:8899
python -m aegisscan ui --port 9000 --no-browser
```

| Page | What you do there |
|---|---|
| **Dashboard** | Aggregate risk posture: severity cards, risk gauge, severity donut, top categories, ATT&CK tactics in play, recent scans |
| **New Scan** | Pick a target type (local repo / GitHub / website / host / TLS), set options, run — you land on the live scan view |
| **Live scan view** | Per-module progress with durations, findings preview, download buttons for all report formats |
| **Findings** | All findings across all scans; filter by severity/category/scan or search; click a row for evidence, fix and ATT&CK mapping |
| **MITRE ATT&CK** | The ATT&CK Enterprise matrix with finding counts per technique; click a technique to filter findings |
| **Reports** | Every scan with one-click export to HTML / JSON / Markdown / SARIF, and delete |

---

## 5. Reports

```bash
python -m aegisscan scan --repo . --formats html,json,md,sarif --out reports/
python -m aegisscan report --input aegisscan-data/scans/<id>.json --format md --output report.md
```

| Format | Use it for |
|---|---|
| **HTML** | Management/audience-ready: cover, executive summary, risk gauge, severity mix, remediation roadmap, per-finding detail with fixes, TLS tables, ATT&CK matrix. Self-contained single file. |
| **JSON** | Full machine-readable results for your own tooling |
| **Markdown** | Pull requests, wikis, issue trackers |
| **SARIF 2.1** | GitHub Code Scanning, VS Code, CI gates |

Each finding contains: title, severity (critical→info), risk score 0–10,
category, exact location (file:line / URL / host:port), description, evidence
(redacted), **recommended fix**, references (OWASP/CVE), CWE and **MITRE ATT&CK
techniques**.

### CI/CD gating
```bash
python -m aegisscan scan --repo . --fail-on high   # exit 1 if any high/critical finding
```
A ready GitHub Actions workflow (runs the scanner on every push and uploads
SARIF to Code Scanning) ships at `.github/workflows/aegisscan.yml`.

### Scheduled scans
- **cron (Linux/macOS):** `0 2 * * * cd /opt/aegisscan && python3 -m aegisscan scan --url https://intranet.local --formats html --out /var/www/reports`
- **Task Scheduler (Windows):** action `python.exe`, args `-m aegisscan scan --repo C:\code\app --formats html,json`
- **GitHub Actions:** use the included workflow's `schedule:` trigger (weekly by default)

---

## 6. AI analysis (bring your own API key)

AegisScan can augment any scan with an LLM-written executive analysis —
summary, top-priority fixes, quick wins and next steps — shown in the
dashboard and embedded in HTML/Markdown reports.

### 6.1 Configure a provider

```bash
python -m aegisscan ai setup              # list all providers + where to get keys
python -m aegisscan ai setup --provider openai    --api-key sk-...
python -m aegisscan ai setup --provider anthropic --api-key sk-ant-...
python -m aegisscan ai setup --provider google    --api-key AIza...
python -m aegisscan ai setup --provider zai       --api-key ...     # Z.ai / GLM
python -m aegisscan ai setup --provider zhipu     --api-key ...     # GLM mainland
python -m aegisscan ai setup --provider mistral|groq|deepseek|xai|cohere|openrouter --api-key ...
python -m aegisscan ai setup --provider custom --base-url http://localhost:11434/v1 --model llama3
python -m aegisscan ai show      # current config (key masked)
python -m aegisscan ai test      # minimal round-trip
```

Alternatively use the dashboard's **AI Settings** page (provider dropdown, key,
model, test button). Keys are stored in `aegisscan-data/config.json` (local
only) or read from environment variables: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
`GEMINI_API_KEY`/`GOOGLE_API_KEY`, `ZAI_API_KEY`, `ZHIPU_API_KEY`,
`MISTRAL_API_KEY`, `GROQ_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`,
`COHERE_API_KEY`, `OPENROUTER_API_KEY`.

### 6.2 Use it

```bash
python -m aegisscan demo --ai                       # during any scan (--scan too: scan --repo . --ai)
python -m aegisscan ai explain <scan-id|file.json>  # analyze a saved scan afterwards
```

In the dashboard: set up AI under **AI Settings**, then open any scan and click
**✨ Generate AI analysis** — or tick *AI executive analysis after scan* in the
New Scan form.

Only finding metadata (title, severity, location, ATT&CK ids) is sent — never
file contents or secret values. AI output is advisory and labelled as such.

## 7. Updating & uninstalling

```bash
python -m aegisscan update            # compare with upstream and self-update
python -m aegisscan update --check    # versions only
python -m aegisscan uninstall         # remove the pip package (keeps data)
python -m aegisscan uninstall --purge-data --yes    # also delete aegisscan-data/
```

`update` checks the latest version on GitHub, then runs `git pull --ff-only`
(source checkouts) or `pip install --upgrade` (pip installs). Your scan data
is never touched by updates.

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `sca` module shows few results | You ran `--offline` (built-in DB only) or OSV.dev was unreachable. Re-run online. |
| TLS grade `-` | The host refused TLS on that port; check the URL/port (`--https host:port`). |
| Port scan seems slow | You chose a wide range; a connect scan is sequential per thread pool — narrow the range. |
| Web scan missed a page | Increase `--max-pages` (crawler only follows same-host links from the entry page). |
| GitHub 403/rate limit | Set `GITHUB_TOKEN`. |

## 9. Ethics

Only scan assets you own or are authorized to test in writing. Web probes are
non-destructive but still generate requests — respect scope and rate limits.
