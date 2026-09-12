"""Web application scanner (DAST) — header hardening, exposure checks,
TLS redirect, cookie flags, form analysis and light non-destructive
injection probes (Nikto/ZAP-lite)."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

from ..core.models import Finding, Severity
from ..core.utils import fetch, normalize_url

MITRE_WEB = ["T1190", "T1595.002"]
MITRE_EXPOSED = ["T1552.001", "T1213"]
MITRE_XSS = ["T1190"]
MITRE_SQLI = ["T1190", "T1565"]

SUSPECT_PATHS = [
    ("/.env", "Environment file exposed", Severity.CRITICAL,
     ["DB_PASSWORD=", "APP_KEY=", "AWS_SECRET", "MAIL_PASSWORD="]),
    ("/.git/config", "Git repository exposed (.git/config)", Severity.CRITICAL,
     ["[core]", "repositoryformatversion"]),
    ("/.git/HEAD", "Git repository exposed (.git/HEAD)", Severity.HIGH,
     ["ref: refs/"]),
    ("/.svn/entries", "SVN repository exposed", Severity.HIGH, ["dir", "\n12"]),
    ("/backup.sql", "Database backup file exposed", Severity.HIGH, ["INSERT INTO", "CREATE TABLE"]),
    ("/dump.sql", "Database dump exposed", Severity.HIGH, ["INSERT INTO", "CREATE TABLE"]),
    ("/phpinfo.php", "phpinfo() page exposed", Severity.HIGH, ["PHP Version", "phpinfo()"]),
    ("/info.php", "phpinfo() page exposed", Severity.HIGH, ["PHP Version", "phpinfo()"]),
    ("/server-status", "Apache server-status exposed", Severity.MEDIUM, ["Apache Status", "Server uptime"]),
    ("/.DS_Store", "macOS .DS_Store directory listing leaked", Severity.LOW, ["Bud1"]),
    ("/web.config", "IIS web.config exposed", Severity.MEDIUM, ["<configuration", "connectionString"]),
    ("/admin", "Admin panel reachable", Severity.LOW, ["login", "admin", "dashboard"]),
    ("/wp-admin/", "WordPress admin reachable", Severity.LOW, ["wp-admin", "wordpress"]),
    ("/actuator", "Spring Boot actuator exposed", Severity.HIGH, ["_links", "health"]),
    ("/actuator/env", "Spring Boot environment endpoint exposed", Severity.CRITICAL, ["propertySources"]),
    ("/debug/vars", "Go pprof/debug vars exposed", Severity.MEDIUM, ["memstats", "cmdline"]),
    ("/.aws/credentials", "AWS credentials file exposed", Severity.CRITICAL, ["aws_access_key_id"]),
    ("/composer.json", "composer.json exposed (stack fingerprinting)", Severity.LOW, ["require"]),
    ("/package.json", "package.json exposed (stack fingerprinting)", Severity.LOW, ["dependencies"]),
]

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated", "pg_query()", "postgresql", "sqlite3.",
    "ora-[0-9]{5}", "sqlsyntaxerrorexception", "mysqlifetch", "odbc",
]

XSS_PROBE = '"><svg/onload=alert(1)>'
SQLI_PROBE = "' OR '1'='1"
TRAVERSAL_PROBE = "../../../../etc/passwd"
TRAVERSAL_SIG = "root:x:0:0"

SECURITY_HEADERS = [
    ("content-security-policy", "Content-Security-Policy missing", Severity.MEDIUM,
     "CSP prevents injected scripts from executing (XSS mitigation).",
     "Add a Content-Security-Policy header, starting report-only: 'Content-Security-Policy: default-src 'self'; upgrade-insecure-requests' and tighten iteratively.",
     "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"),
    ("strict-transport-security", "Strict-Transport-Security (HSTS) missing", Severity.MEDIUM,
     "Without HSTS the first request can be downgraded to http by an attacker.",
     "Send 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload'.",
     "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"),
    ("x-content-type-options", "X-Content-Type-Options missing", Severity.LOW,
     "Browsers may MIME-sniff responses and execute uploads as scripts.",
     "Send 'X-Content-Type-Options: nosniff'.",
     "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"),
    ("x-frame-options", "Clickjacking protection missing (X-Frame-Options / frame-ancestors)", Severity.MEDIUM,
     "The page can be framed by any site, enabling UI-redressing (clickjacking) attacks.",
     "Send 'X-Frame-Options: DENY' or CSP 'frame-ancestors \"none\"'.",
     "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html"),
    ("referrer-policy", "Referrer-Policy missing", Severity.LOW,
     "Full URLs (possibly with tokens) leak to third-party sites via the Referer header.",
     "Send 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
     "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"),
    ("permissions-policy", "Permissions-Policy missing", Severity.LOW,
     "Powerful browser APIs (camera, geolocation, mic) are not explicitly restricted.",
     "Send 'Permissions-Policy: camera=(), microphone=(), geolocation=()'.",
     "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"),
]


def _mk(title, sev, cat, url, desc, evidence, fix, refs, mitre=MITRE_WEB, cwe="", tags=("web",)):
    return Finding(scanner="web", category=cat, title=title, severity=sev, target=url,
                   location=url, description=desc, evidence=evidence[:400],
                   remediation=fix, references=refs, mitre=list(mitre), cwe=cwe,
                   tags=list(tags) + ["dast"])


def _links(html: str, base: str, max_links: int = 60) -> list:
    out, seen = [], set()
    for m in re.finditer(r'(?:href|src|action)\s*=\s*["\']([^"\'#]+)["\']', html, re.I):
        url = urljoin(base, m.group(1).strip())
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            continue
        if url.rstrip("/") != base.rstrip("/") and url not in seen:
            seen.add(url)
            out.append(url)
        if len(out) >= max_links:
            break
    return out


def scan(url: str, max_pages: int = 25, probe_injection: bool = True,
         timeout: int = 15, progress=None) -> list:
    findings: list[Finding] = []
    base = normalize_url(url)
    base = base.rstrip("/")
    visited = set()
    pages = []

    def prog(done, total):
        if progress:
            progress(done, total)

    prog(2, 100)

    # ---- fetch root ------------------------------------------------------
    try:
        resp = fetch(base, timeout=timeout)
    except Exception as e:
        findings.append(_mk("Target unreachable", Severity.INFO, "Connectivity", base,
                            f"The scanner could not fetch {base}: {e}",
                            str(e), "Verify the URL and network connectivity.",
                            [], tags=["web", "info"]))
        prog(100, 100)
        return findings

    if resp.status >= 400:
        findings.append(_mk(f"Root URL returns HTTP {resp.status}", Severity.LOW,
                            "HTTP Behaviour", base,
                            f"The entry point responds with status {resp.status}.",
                            f"HTTP {resp.status} on {base}",
                            "If intentional (e.g. SSO redirect) ignore; otherwise fix routing.",
                            [], tags=["web", "info"]))

    visited.add(base)
    pages.append((base, resp))
    # polite crawl
    for link in _links(resp.text, base)[:max_pages]:
        if link in visited or len(pages) >= max_pages:
            continue
        p = urlparse(link)
        if p.netloc != urlparse(base).netloc:
            continue
        try:
            r = fetch(link, timeout=timeout)
            visited.add(link)
            pages.append((link, r))
        except Exception:
            continue
        prog(min(40, 5 + len(pages)), 100)

    prog(45, 100)

    # ---- security headers on every page -----------------------------------
    header_gaps: dict = {}          # header -> {meta, urls}
    for page_url, r in pages:
        for header, title, sev, why, fix, ref in SECURITY_HEADERS:
            val = r.header(header)
            if header == "x-frame-options" and ("frame-ancestors" in r.header("content-security-policy")):
                continue
            if header == "strict-transport-security" and not header_present_https_only(r):
                continue
            if not val:
                gap = header_gaps.setdefault(header, {
                    "title": title, "sev": sev, "why": why, "fix": fix, "ref": ref, "urls": []})
                gap["urls"].append(page_url)
        # server disclosure
        srv = r.header("server")
        if srv and re.search(r"\d+\.\d+", srv):
            findings.append(_mk(f"Server version disclosed: {srv}", Severity.LOW,
                                "Information Disclosure", page_url,
                                "The Server header reveals the exact software version, letting attackers match known CVEs.",
                                srv, "Remove or genericize the Server header (server_tokens off in nginx; ServerTokens Prod in Apache).",
                                ["https://owasp.org/www-project-secure-headers/"], cwe="CWE-200"))
        xp = r.header("x-powered-by")
        if xp:
            findings.append(_mk(f"Technology disclosed via X-Powered-By: {xp}", Severity.LOW,
                                "Information Disclosure", page_url,
                                "The X-Powered-By header fingerprints the backend framework.",
                                xp, "Remove the X-Powered-By header (e.g. app.disable('x-powered-by') in Express, expose_php=Off in PHP).",
                                ["https://owasp.org/www-project-secure-headers/"], cwe="CWE-200"))
        # cookies
        for cookie_line in r.header("set-cookie", "").split(",") if r.header("set-cookie") else []:
            cookie_line = cookie_line.strip()
            name = cookie_line.split("=")[0]
            low = cookie_line.lower()
            if "httponly" not in low or "secure" not in low:
                missing = [f for f, kw in (("Secure", "secure"), ("HttpOnly", "httponly")) if kw not in low]
                if not name.lower().startswith("deletion") and "=" in cookie_line and name:
                    findings.append(_mk(f"Cookie '{name}' missing {(' and '.join(missing))} flag(s)",
                                        Severity.MEDIUM, "Session Management", page_url,
                                        "Session cookies without Secure/HttpOnly can be stolen via MitM or XSS.",
                                        cookie_line[:120],
                                        "Set Secure, HttpOnly and SameSite=Lax/Strict on every session cookie.",
                                        ["https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"],
                                        cwe="CWE-1004"))
                    break

    # emit grouped header findings
    for header, gap in header_gaps.items():
        urls = gap["urls"]
        loc = urls[0]
        more = f" (and {len(urls) - 1} more page(s))" if len(urls) > 1 else ""
        findings.append(_mk(gap["title"], gap["sev"], "HTTP Security Headers", loc,
                            gap["why"] + " Observed on: " + loc + more,
                            f"response headers of {loc} do not include {header}",
                            gap["fix"], [gap["ref"]],
                            cwe="CWE-693" if gap["sev"] == Severity.MEDIUM else "CWE-16"))

    prog(55, 100)

    # ---- HTTPS downgrade ----------------------------------------------------
    if base.startswith("https://"):
        http_url = urlunparse(urlparse(base)._replace(scheme="http"))
        try:
            r2 = fetch(http_url, timeout=timeout)
            loc = r2.header("location")
            if r2.status in (301, 302, 303, 307, 308) and loc.startswith("https"):
                pass  # redirects to https: good
            elif r2.status == 200 and r2.body:
                findings.append(_mk("Plain HTTP serves content (no redirect to HTTPS)", Severity.MEDIUM,
                                    "Transport Security", http_url,
                                    "The site answers on http:// with real content instead of redirecting to https://, enabling SSL stripping.",
                                    f"HTTP 200 from {http_url}",
                                    "Redirect all HTTP traffic (301) to HTTPS and enable HSTS.",
                                    ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                                    cwe="CWE-319"))
        except Exception:
            pass

    # ---- CORS reflection ------------------------------------------------------
    try:
        r3 = fetch(base, headers={"Origin": "https://evil.example.com"}, timeout=timeout)
        acao = r3.header("access-control-allow-origin")
        if acao == "https://evil.example.com":
            findings.append(_mk("CORS reflects arbitrary Origin (ACAO: <attacker>)", Severity.HIGH,
                                "Access Control", base,
                                "The server reflects any Origin in Access-Control-Allow-Origin, letting any site read authenticated responses.",
                                f"Access-Control-Allow-Origin: {acao}",
                                "Validate the Origin against an allow-list instead of echoing it.",
                                ["https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html"],
                                cwe="CWE-942"))
        elif acao == "*":
            findings.append(_mk("Permissive CORS policy (Access-Control-Allow-Origin: *)", Severity.LOW,
                                "Access Control", base,
                                "A wildcard CORS policy allows any website to read public responses; harmless for public data but risky with credentials.",
                                "Access-Control-Allow-Origin: *",
                                "Restrict to the exact origins that need access.", ["https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"],
                                cwe="CWE-942"))
    except Exception:
        pass

    prog(65, 100)

    # ---- exposed files ---------------------------------------------------------
    for path_suffix, title, sev, signatures in SUSPECT_PATHS:
        probe_url = base + path_suffix
        try:
            r4 = fetch(probe_url, timeout=timeout)
        except Exception:
            continue
        body_head = r4.body[:4096].decode("utf-8", "replace")
        if r4.status == 200 and any(sig.lower() in body_head.lower() for sig in signatures if sig.strip()):
            findings.append(_mk(title, sev, "Sensitive Exposure", probe_url,
                                f"{title}. Such files leak source code, credentials or infrastructure details and are a primary recon target.",
                                f"HTTP 200 with matching content at {probe_url}",
                                "Remove the file from the webroot, block the path at the server/CDN (deny /.git, /.env, backups), and rotate any secret it contained.",
                                ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"],
                                mitre=MITRE_EXPOSED, cwe="CWE-538"))
        elif r4.status == 200 and path_suffix in ("/.env", "/.git/config", "/.aws/credentials"):
            findings.append(_mk(title + " (status 200, content unrecognized)", Severity.MEDIUM,
                                "Sensitive Exposure", probe_url,
                                f"{probe_url} returns HTTP 200 — verify the content manually.",
                                f"HTTP 200 at {probe_url}",
                                "Block this path at the reverse proxy and confirm no secrets are exposed.",
                                [], mitre=MITRE_EXPOSED, cwe="CWE-538"))
        prog(65 + int(20 * (SUSPECT_PATHS.index((path_suffix, title, sev, signatures)) + 1) / len(SUSPECT_PATHS)), 100)

    # ---- directory listing ---------------------------------------------------------
    if resp.status == 200:
        low = resp.text[:2000].lower()
        if ("index of /" in low and "directory listing" in low) or ("<title>index of" in low):
            findings.append(_mk("Directory listing enabled", Severity.MEDIUM, "Sensitive Exposure", base,
                                "Autoindex exposes the file tree, revealing files that are not linked.",
                                "Index of /",
                                "Disable autoindex (Options -Indexes in Apache; autoindex off in nginx) and move files out of the webroot.",
                                [], cwe="CWE-548"))

    # ---- forms & methods ---------------------------------------------------------------
    for page_url, r in pages:
        html = r.text
        if "<form" not in html.lower():
            continue
        for fm in re.finditer(r"<form[^>]*>.*?</form>", html, re.I | re.S):
            form_html = fm.group(0)
            action = re.search(r"action\s*=\s*[\"']([^\"']*)[\"']", form_html, re.I)
            action_url = urljoin(page_url, action.group(1)) if action else page_url
            has_password = re.search(r"<input[^>]*type\s*=\s*[\"']?password", form_html, re.I) is not None
            has_csrf = re.search(r"(csrf|_token|authenticity_token|xsrf)", form_html, re.I) is not None
            if action_url.startswith("http://"):
                findings.append(_mk("Login/form posts over plain HTTP", Severity.HIGH,
                                    "Transport Security", action_url,
                                    "A form posts credentials or data to an http:// endpoint — interceptable in transit.",
                                    action_url,
                                    "Serve the form over HTTPS and post to https:// endpoints.",
                                    ["https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"],
                                    cwe="CWE-319"))
            if has_password and not has_csrf:
                findings.append(_mk("Login form without CSRF token", Severity.MEDIUM,
                                    "Session Management", page_url,
                                    "A password form has no visible CSRF token; login CSRF may be possible.",
                                    form_html[:160],
                                    "Embed a per-session CSRF token and verify it server-side.",
                                    ["https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"],
                                    cwe="CWE-352"))
    prog(88, 100)

    # ---- HTTP methods -----------------------------------------------------------------
    try:
        r5 = fetch(base, method="OPTIONS", timeout=timeout)
        allow = (r5.header("allow") or r5.header("public")).upper()
        if "TRACE" in allow:
            findings.append(_mk("TRACE method enabled (XST)", Severity.MEDIUM, "HTTP Methods", base,
                                "TRACE echoes requests and can be used to steal HttpOnly cookies via cross-site tracing.",
                                f"Allow: {allow}",
                                "Disable TRACE (TraceEnable off in Apache).",
                                ["https://owasp.org/www-community/attacks/Cross_Site_Tracing"], cwe="CWE-693"))
        if "PUT" in allow or "DELETE" in allow:
            findings.append(_mk(f"Dangerous HTTP methods advertised: {allow}", Severity.MEDIUM,
                                "HTTP Methods", base,
                                "OPTIONS advertises PUT/DELETE. If unauthenticated, attackers can upload or delete files.",
                                f"Allow: {allow}",
                                "Restrict methods at the web server and require authentication for write methods.",
                                [], cwe="CWE-650"))
    except Exception:
        pass

    prog(92, 100)

    # ---- light injection probes (non-destructive) ----------------------------------------
    if probe_injection:
        tested = 0
        for page_url, r in pages:
            if tested >= 12:
                break
            q = parse_qsl(urlparse(page_url).query)
            if not q:
                continue
            tested += 1
            for name, _orig in q:
                # reflected XSS
                parts = list(urlparse(page_url))
                query = [(k, XSS_PROBE if k == name else v) for k, v in q]
                probe_url = urlunparse(urlparse(page_url)._replace(query=urlencode(query)))
                try:
                    rx = fetch(probe_url, timeout=timeout)
                    if XSS_PROBE in rx.text and "<svg" in rx.text:
                        findings.append(_mk("Possible reflected XSS (payload reflected unescaped)", Severity.HIGH,
                                            "Cross-Site Scripting", probe_url,
                                            "The injected probe string is reflected in the response without encoding, indicating a likely reflected XSS.",
                                            f"parameter '{name}' reflects: {XSS_PROBE}",
                                            "HTML-encode all reflected values in the output context and add a CSP as defense in depth.",
                                            ["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
                                            mitre=MITRE_XSS, cwe="CWE-79"))
                except Exception:
                    pass
                # SQLi error-based
                query = [(k, SQLI_PROBE if k == name else v) for k, v in q]
                probe_url = urlunparse(urlparse(page_url)._replace(query=urlencode(query)))
                try:
                    rs = fetch(probe_url, timeout=timeout)
                    body_low = rs.text[:200000].lower()
                    import re as _re
                    for sig in SQL_ERROR_SIGNATURES:
                        if _re.search(sig, body_low):
                            findings.append(_mk(f"SQL error disclosed on parameter '{name}' (possible SQL injection)", Severity.HIGH,
                                                "SQL Injection", probe_url,
                                                "Injecting a quote produces a database error message, exposing SQL structure and likely injectability.",
                                                rs.text[:200],
                                                "Use parameterized queries; suppress detailed DB errors in production (generic error page).",
                                                ["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
                                                mitre=MITRE_SQLI, cwe="CWE-89"))
                            break
                except Exception:
                    pass
                # path traversal
                query = [(k, TRAVERSAL_PROBE if k == name else v) for k, v in q]
                probe_url = urlunparse(urlparse(page_url)._replace(query=urlencode(query)))
                try:
                    rt = fetch(probe_url, timeout=timeout)
                    if TRAVERSAL_SIG in rt.text[:200000]:
                        findings.append(_mk("Possible path traversal (/etc/passwd readable)", Severity.CRITICAL,
                                            "Path Traversal", probe_url,
                                            "A traversal sequence in the parameter returned the contents of /etc/passwd.",
                                            f"parameter '{name}' accepted ../ sequences",
                                            "Normalize and allow-list file paths server-side; never pass user input to filesystem APIs.",
                                            ["https://owasp.org/www-community/attacks/Path_Traversal"],
                                            mitre=["T1190", "T1083", "T1005"], cwe="CWE-22"))
                except Exception:
                    pass
    prog(100, 100)
    return findings


def header_present_https_only(r) -> bool:
    return r.url.startswith("https://")
