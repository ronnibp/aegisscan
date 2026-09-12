# AegisScan — Scanning Methodology

Exactly what each module checks, how it decides, and what it can miss.
Version 1.0.0.

---

## 1. Secret Detection (`secrets`)

**Approach:** regex signatures + entropy analysis over every readable file
(skips binaries, `node_modules`, `.git`, files > 2 MB).

Checks:
- 17 token families: AWS (AKIA/ASIA…), AWS secret assignments, GitHub
  (ghp_/gho_/ghu_/ghs_/github_pat_), Google API (AIza…), Google OAuth
  (GOCSPX-), Slack (xox…), Stripe live keys, OpenAI, Anthropic, SendGrid,
  Twilio, Mailgun, private-key PEM blocks, JWTs, hardcoded password
  assignments, DB connection strings with credentials, generic token assignments
- Shannon-entropy ≥ 4.3 on 32+ char strings adjacent to key-like identifiers
- `.env`-style files with credential-shaped values
- Key-material files by extension (`.pem`, `.key`, `.p12`, `.pfx`)

False-positive controls: placeholder values (`example`, `changeme`, `your_…`,
`<…>`) are downgraded to Info; evidence is always redacted to the first 4
characters + length.

Can miss: obfuscated/split secrets, base64-of-secrets without context, secrets
in git history (this scanner reads the working tree — run
`git filter-repo`/trufflehog for history audits).

## 2. Static Analysis / SAST (`sast`)

**Approach:** per-language sink patterns with curated remediation metadata,
plus infrastructure-as-code rules.

Languages: Python, JavaScript/TypeScript (incl. JSX/TSX), Java, PHP, Go, C#.
Patterns include: `eval/exec`, `os.system`, `shell=True`, unsafe `yaml.load`,
pickle/marshal deserialization, `verify=False`, MD5/SHA-1, `random` for
tokens, Flask `debug=True`, string-formatted SQL, SSRF-shaped dynamic URLs,
`innerHTML`/`document.write`/`dangerouslySetInnerHTML`, `rejectUnauthorized:false`,
trust-all TrustManagers, XXE-prone parser factories, PHP `unserialize($_GET)`,
Go `InsecureSkipVerify`, `BinaryFormatter`, and more.

Infrastructure: Dockerfile (root user, `:latest`, ENV secrets), Terraform
(`0.0.0.0/0` ingress, secrets in user_data), CI (plaintext secrets,
`pull_request_target`), Apache/nginx (SSLv3/TLS1.0 enabled), SQL grants.

Comment lines (`#`, `//`, `*`) are skipped. Patterns are sinks — the engine
does not perform full data-flow taint tracking, so some findings need manual
confirmation (each finding shows the matched line as evidence).

## 3. Dependency Analysis / SCA (`sca`)

Parses `requirements*.txt`, `pyproject.toml` (pinned deps), `package.json`,
`package-lock.json`, `pom.xml`, `go.mod`, `composer.json`, `Gemfile`, then:

- **Online (default):** batch query to the OSV.dev `querybatch` API.
  Severity from CVSS scores attached to each vuln; remediation is the OSV
  `fixed` event version; references link to OSV/NVD.
- **Offline (`--offline`):** a built-in database of notorious, unambiguous
  version boundaries (e.g. log4shell, django/pyyaml/lodash CVEs).

Unpinned requirements (`flask` with no `==`) are scanned as range-only when
OSV supports it and otherwise skipped — pin your dependencies.

## 4. Web Application DAST (`web`)

Polite crawler: same-host links from the entry page, ≤ `--max-pages` (25 default).

Checks (non-destructive):
- Security headers: CSP, HSTS, X-Content-Type-Options, X-Frame-Options /
  CSP frame-ancestors, Referrer-Policy, Permissions-Policy — grouped into one
  finding per header listing affected pages
- Server/X-Powered-By version disclosure; cookie Secure/HttpOnly/SameSite flags
- Exposed sensitive paths with **content signatures** (not just status 200):
  `/.env`, `/.git/config`, `/.git/HEAD`, `/.svn`, `backup.sql`, `phpinfo.php`,
  `/server-status`, `/.aws/credentials`, Spring `/actuator[/env]`, Go
  `/debug/vars`, `web.config`, admin panels…
- HTTPS downgrade (http:// must redirect), CORS origin reflection & wildcard
- Directory listing, login-form over http://, password form without CSRF token
- HTTP OPTIONS: TRACE (XST), PUT/DELETE advertisement
- Light injection probes (disable with `--no-injection`):
  - reflected XSS: `"><svg/onload=alert(1)>` reflected unescaped
  - SQL errors: `' OR '1'='1` + database error-signature matching
  - path traversal: `../../../../etc/passwd` with `root:x:0:0` signature
  - probes go to GET parameters only, one request each

## 5. TLS / SSL audit (`tls`)

Handshake-level inspection, one connection per probe:

1. Baseline handshake (client's default OpenSSL).
2. **Protocol matrix:** SSLv2/SSLv3, TLS 1.0/1.1/1.2/1.3 — each tested with a
   version-pinned context. (Protocols the local OpenSSL cannot construct are
   reported "not offered" — on modern stacks SSLv2/3 fail closed.)
3. **Cipher enumeration (TLS 1.2 and below):** up to 40 suite names probed
   individually, classified weak (RC4/3DES/NULL/EXP/MD5/SEED/IDEA…) /
   acceptable / strong (AEAD + ephemeral key exchange), plus forward-secrecy
   coverage. TLS 1.3 suites are inherently strong.
4. **Certificate:** parse (subject, issuer, validity, SANs, signature
   algorithm), expiry window (expired ⇒ F, ≤ 30 days ⇒ warn), chain validation
   with a trusting context (self-signed / incomplete chain / expired), and
   hostname match over DNS **and IP** SANs with wildcard rules.
5. **HSTS:** presence, max-age, includeSubDomains, preload.
6. **TLS compression** (CRIME) if negotiated.

**Grade:** starts at 100; deductions for legacy protocols (SSLv3 ⇒ fatal),
weak ciphers, no forward secrecy, missing/short HSTS, no TLS 1.3, cert issues;
fatal conditions (expired cert, hostname mismatch, no modern TLS, SSLv3) force
**F**; TLS 1.0/1.1 caps the grade at B; weak ciphers cap at C. A+ requires
≥ 95, HSTS ≥ 180 days and TLS 1.3.

## 6. Network / Ports (`network`)

TCP connect scan (thread pool, default top-100 ports, `--ports 1-1024|80,443|…`),
banner grabbing (passive read, then a benign `HEAD / HTTP/1.0` probe), service
name mapping for ~60 common ports, and risky-service findings for exposed
Telnet, FTP, RDP, SMB, unauthenticated Docker API (critical), Redis, MongoDB,
Elasticsearch, Memcached, databases, VNC, Kubernetes API, suspicious
exploitation/debug ports. Always includes an attack-surface summary finding.
No SYN/stealth scanning — a connect scan is visible in service logs.

## 7. GitHub integration (`github`)

- Parses `owner/repo` or any github.com URL
- Metadata via the GitHub API: visibility, license, stars/forks, default
  branch, branch protection (token required) → posture findings
- Downloads the default-branch tarball (302 to codeload), strips the leading
  directory component, extracts with `filter="data"` (path-traversal safe),
  runs the code pipeline (secrets + SAST + SCA) on the extracted tree, and
  removes the temp directory afterwards
- Auth: `GITHUB_TOKEN` env var (fine-grained PATs work); without a token,
  public repos only, subject to 60 req/h rate limits

## 8. Risk scoring & severity

- Severity ladder: critical / high / medium / low / info with default scores
  9.5 / 7.5 / 5.0 / 3.0 / 1.0; explicit CVSS overrides (SCA) map 9–10 → critical,
  7–8.9 → high, 4–6.9 → medium, else low.
- Scan risk score: weighted sum of the six highest finding scores
  (weights 1.0 → 0.05) normalized to 10 — one critical dominates many infos.
- CLI `--fail-on SEVERITY` gates CI on the severity rank.
