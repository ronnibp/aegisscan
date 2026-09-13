<div align="center">

# 🛡️ AegisScan

**A unified, cross-platform security scanner with a professional dashboard — SAST · SCA · Secrets · Web/DAST · TLS audit · Ports · GitHub integration — every finding mapped to MITRE ATT&CK with a concrete fix.**

*Zero third-party dependencies. Pure Python. Runs on Windows, Linux and macOS.*

</div>

---

## Why AegisScan

Most scanners do one thing. AegisScan combines the checks you'd normally run
half a dozen tools for — Semgrep-style SAST, safety/npm-audit-style dependency
analysis, TruffleHog-style secret detection, Nikto/ZAP-style web scanning,
SSL-Labs-style TLS grading and an nmap-style port scanner — into one engine,
one risk model, one professional report, and one dashboard. Every finding
tells you **what** is wrong, **why** it matters (MITRE ATT&CK technique an
attacker would use), and **how to fix it**.

## Features

| Layer | What it finds | Inspired by |
|---|---|---|
| 🔍 **Secrets** | AWS/GitHub/Google/Slack/Stripe/OpenAI keys, private keys, connection strings, high-entropy credentials, committed `.env` files | TruffleHog, gitleaks |
| 📝 **SAST** | SQL injection, command injection, eval/RCE, deserialization, weak crypto, disabled TLS verification, XSS sinks + Dockerfile/Terraform/CI checks | Semgrep, Bandit |
| 📦 **SCA** | Vulnerable dependencies from `requirements.txt`, `package.json`/lock, `pom.xml`, `go.mod`, `composer.json`, `Gemfile` — via the OSV.dev database (offline DB fallback) | safety, npm audit |
| 🌐 **Web/DAST** | Missing security headers, exposed `.env`/`.git`/backups/phpinfo, TLS downgrade, permissive CORS, TRACE, cookie flags, CSRF-less login forms, reflected XSS / SQLi / path-traversal probes (non-destructive) | Nikto, ZAP |
| 🔒 **TLS audit** | Protocol & cipher enumeration, forward secrecy, certificate expiry/chain/hostname, HSTS — with an **A+ … F grade** | SSL Labs |
| 🖧 **Network** | TCP connect scan of top-100 / custom ranges, banner grabbing, risky-service exposure (Docker, Redis, MongoDB, RDP, SMB…) | nmap |
| 🐙 **GitHub** | Scan any public/token-readable repo by `owner/repo` — plus repository posture (public repo, missing license, unprotected default branch) | GitHub Advanced Security |
| ⚔️ **MITRE ATT&CK** | Every finding mapped to the ATT&CK Enterprise technique it enables; interactive matrix in the UI and reports | MITRE ATT&CK |
| ✨ **AI analysis** | Bring your own key: **OpenAI, Anthropic (Claude), Google Gemini, Z.ai (GLM), Zhipu GLM, Mistral, Groq, DeepSeek, xAI (Grok), Cohere, OpenRouter** or any OpenAI-compatible endpoint (Ollama, vLLM…) — executive summary, prioritized fixes and quick wins in the dashboard and reports | — |
| 📄 **Reporting** | Self-contained **HTML** report (executive summary, risk gauge, remediation roadmap, TLS tables, ATT&CK matrix), plus **JSON**, **Markdown** and **SARIF** (GitHub Code Scanning) | — |
| 🔧 **Lifecycle** | `aegisscan update` (self-update via git or pip with upstream version check) and `aegisscan uninstall` (with `--purge-data`) | — |

## Install

AegisScan needs only **Python 3.9+** — no other dependencies, ever.

### Windows (easiest)

One command — installs straight from GitHub, no git required:

```powershell
pip install https://github.com/ronnibp/aegisscan/archive/refs/heads/main.zip
```

Then run it from any folder:

```powershell
aegisscan --version      # verify the install
aegisscan demo           # scan the bundled vulnerable demo app
aegisscan ui             # dashboard → http://127.0.0.1:8899
```

> No Python yet? Install it from [python.org/downloads](https://www.python.org/downloads/) and tick **"Add python.exe to PATH"** in the installer.

### Linux / macOS

```bash
pip3 install https://github.com/ronnibp/aegisscan/archive/refs/heads/main.zip
```

### From source with git (any OS)

```bash
git clone https://github.com/ronnibp/aegisscan.git
cd aegisscan
pip install .                    # installs the `aegisscan` command
# …or without installing, run straight from the folder:
python -m aegisscan demo
```

Windows users can also just run the bundled installer script:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force; .\install.ps1
```

### Keep it fresh / remove it

```bash
aegisscan update                 # self-update (git pull or pip upgrade)
aegisscan uninstall              # remove (add --purge-data --yes to wipe data too)
```

## Quick start

Already installed? No dependencies, no build step — just run:

```bash
# 1. Run the demo scan against a bundled intentionally-vulnerable app
python -m aegisscan demo

# 2. Scan a local repository
python -m aegisscan scan --repo /path/to/project

# 3. Scan a website (DAST) and a TLS audit
python -m aegisscan scan --url https://example.com

# 4. Scan a GitHub repository
python -m aegisscan scan --github owner/repo

# 5. Launch the web dashboard
python -m aegisscan ui
# → http://127.0.0.1:8899
```

Or install as a CLI tool:

```bash
pip install .
aegisscan --version
```

## The dashboard

`python -m aegisscan ui` opens a professional security-operations dashboard:

- **Dashboard** — live risk posture: severity cards, risk gauge, severity donut, top categories, ATT&CK tactics in play, recent scans
- **New Scan** — one form for every target type (local repo / GitHub / website / host / TLS) with module options
- **Live scan view** — per-module progress, findings feed, one-click report downloads
- **Findings explorer** — filter across all scans by severity, category, scan or free text; a detail drawer with evidence, remediation and ATT&CK mapping
- **MITRE ATT&CK matrix** — techniques in play across your estate, click-through to findings
- **Reports** — download every scan as HTML / JSON / Markdown / SARIF

## Reports

Every scan produces a complete report with all findings and recommended fixes:

```bash
python -m aegisscan scan --repo . --formats html,json,md,sarif --out reports/
```

- **HTML** — executive summary, risk gauge, prioritized remediation roadmap, full finding detail, TLS tables, ATT&CK matrix (self-contained file, printable)
- **SARIF 2.1.0** — uploads to GitHub Code Scanning (see [.github/workflows/aegisscan.yml](.github/workflows/aegisscan.yml) for a ready CI workflow)
- **Markdown** — for PRs and wikis
- **JSON** — full machine-readable results

CI gate: `--fail-on critical|high|medium|low` makes the CLI exit `1` when findings at or above the threshold exist.

## CLI reference (Kali-style tools)

```
aegisscan scan     unified scanner (--repo / --github / --url / --host / --https)
aegisscan secrets  secret & credential detection        [--repo PATH]
aegisscan sast     static analysis (dangerous sinks)    [--repo PATH]
aegisscan sca      dependency vulnerability scan        [--repo PATH] [--offline]
aegisscan web      web application DAST                 [--url URL]
aegisscan tls      SSL-Labs-style TLS audit             [--https HOST]
aegisscan ports    TCP port scan + banners              [--host H] [--ports top100|1-1024|80,443]
aegisscan report   re-render a saved scan               [--input scan.json --format html]
aegisscan ui       web dashboard                        [--port 8899]
aegisscan demo     scan the bundled vulnerable app
```

Common options: `--formats html,json,md,sarif` · `--out DIR` · `--fail-on SEVERITY` · `-v` (verbose) · `--top N`.

## GitHub integration

```bash
# scan any public repo
python -m aegisscan scan --github python/cpython --formats html

# private repos / higher rate limits: export a token first
export GITHUB_TOKEN=ghp_xxx           # or a fine-grained token
python -m aegisscan scan --github my-org/my-repo
```

The integration downloads the repo tarball, runs the full code pipeline
(secrets + SAST + SCA), and reports repository posture (visibility, license,
branch protection when a token is supplied).

## AI analysis (bring your own key)

AegisScan can send a compact, redacted digest of your findings to an LLM and
return an **executive summary, top-priority fixes, quick wins and next steps** —
embedded in the dashboard and in HTML/Markdown reports.

```bash
# pick a provider (no args lists all + where to get keys)
python -m aegisscan ai setup
python -m aegisscan ai setup --provider openai     --api-key sk-...     [--model gpt-4o-mini]
python -m aegisscan ai setup --provider anthropic  --api-key sk-ant-... [--model claude-sonnet-4-5]
python -m aegisscan ai setup --provider google     --api-key AIza...    [--model gemini-2.0-flash]
python -m aegisscan ai setup --provider zai        --api-key ...        [--model glm-4.6]
python -m aegisscan ai setup --provider custom --base-url http://localhost:11434/v1 --model llama3

python -m aegisscan ai test                        # verify the round-trip
python -m aegisscan demo --ai                      # analyze while scanning
python -m aegisscan ai explain <scan-id-or-json>   # analyze a saved scan
python -m aegisscan scan --repo . --ai             # same, any scan command
```

Keys are stored locally in `aegisscan-data/config.json` (never committed) or
read from standard environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`,
`GEMINI_API_KEY`, `ZAI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`,
`DEEPSEEK_API_KEY`, `XAI_API_KEY`, `COHERE_API_KEY`, `OPENROUTER_API_KEY`).
You can also configure everything in the dashboard's **AI Settings** page.

## Updating & uninstalling

```bash
python -m aegisscan update            # check GitHub and self-update (git pull or pip upgrade)
python -m aegisscan update --check    # only compare versions
python -m aegisscan uninstall         # remove the package (keeps your data)
python -m aegisscan uninstall --purge-data --yes   # also delete scans, reports, AI config
```

## Documentation

- [User guide](docs/USER_GUIDE.md) — installation on Windows/Linux/macOS, every scan type, dashboard walkthrough, scheduling, CI/CD
- [Security review](docs/SECURITY_REVIEW.md) — full self-assessment of the app's own security, detection-coverage improvements, and the roadmap toward broader vulnerability discovery
- [Architecture](docs/ARCHITECTURE.md) — how the engine, scanners and server fit together
- [MITRE ATT&CK mapping](docs/MITRE_MAPPING.md) — finding → technique reference
- [Scanning methodology](docs/SCANNERS.md) — exactly what each module checks

## Ethics & responsible use

AegisScan is a **defensive** tool. Only scan systems you own or have explicit
written permission to test. Web probes are deliberately light and
non-destructive, but a scan is still traffic — respect scope, rate limits and
the law.

## License

[MIT](LICENSE) · AegisScan is an independent project; SSL Labs is a trademark of Qualys, MITRE ATT&CK® is a registered trademark of The MITRE Corporation — grades/mappings are inspired by their public methodologies.
