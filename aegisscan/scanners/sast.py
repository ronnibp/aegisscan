"""Static Application Security Testing (SAST) — pattern-based taint indicators.

Language-aware rules for Python, JavaScript/TypeScript, Java, PHP, Go, C#,
plus infrastructure-as-code checks (Dockerfile, Terraform, CI pipelines).
The rules flag *dangerous sinks and configurations* with their exploit path,
severity and ATT&CK mapping.
"""

from __future__ import annotations

import os
import re

from ..core.models import Finding, Severity
from ..core.utils import read_text, walk_files

R = {
    "sql": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    "xss": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    "cmd": "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html",
    "deser": "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html",
    "tls": "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
    "crypto": "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
    "auth": "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
    "docker": "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
    "ssrf": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
}

M_EXEC = ["T1059", "T1190"]
M_SQLI = ["T1190", "T1565"]
M_XSS = ["T1190"]
M_DESER = ["T1203", "T1190"]
M_WEAKCRYPTO = ["T1552.004", "T1557"]
M_TLSOFF = ["T1557", "T1190"]
M_AUTHZ = ["T1078", "T1190"]
M_IAC = ["T1190", "T1078"]
M_UPLOAD = ["T1505.003", "T1190"]


def _f(title, sev, cat, desc, fix, refs, mitre, cwe, tags):
    return {"title": title, "severity": sev, "category": cat, "description": desc,
            "remediation": fix, "references": refs, "mitre": mitre, "cwe": cwe, "tags": tags}


LANG_RULES = {
    ".py": [
        _f("Use of eval()/exec() on dynamic input", Severity.CRITICAL, "Code Injection",
           "eval()/exec() executes arbitrary Python from a string. If any part of the input is attacker-influenced this is direct remote code execution.",
           "Remove eval/exec; parse data with json/ast.literal_eval and dispatch through explicit functions.",
           [R["cmd"], R["deser"]], M_EXEC, "CWE-95", ["rce"]),
        _f("os.system() shell call", Severity.HIGH, "Command Injection",
           "os.system() runs a shell command; concatenated arguments enable OS command injection.",
           "Use subprocess.run([...], shell=False) with argument lists and validated inputs.",
           [R["cmd"]], M_EXEC, "CWE-78", ["command-injection"]),
        _f("subprocess with shell=True", Severity.HIGH, "Command Injection",
           "shell=True passes the command through the shell, enabling command injection via metacharacters.",
           "Pass an argument list and shell=False; if a shell is unavoidable, strictly validate/quote input with shlex.",
           [R["cmd"]], M_EXEC, "CWE-78", ["command-injection"]),
        _f("Unsafe YAML load (yaml.load without SafeLoader)", Severity.HIGH, "Deserialization",
           "yaml.load with the default Loader can construct arbitrary Python objects -> RCE.",
           "Use yaml.safe_load() or pass Loader=yaml.SafeLoader.",
           [R["deser"]], M_DESER, "CWE-502", ["deserialization"]),
        _f("Unsafe deserialization with pickle.loads/marshal.loads", Severity.HIGH, "Deserialization",
           "Deserializing attacker-controlled bytes with pickle/marshal executes embedded code.",
           "Prefer JSON; if unavoidable, authenticate and integrity-protect the payload (e.g. HMAC) before unpickling.",
           [R["deser"]], M_DESER, "CWE-502", ["deserialization"]),
        _f("TLS certificate verification disabled (verify=False)", Severity.MEDIUM, "Transport Security",
           "requests/urllib called with verify=False disables server certificate validation, enabling machine-in-the-middle attacks.",
           "Remove verify=False; if self-signed certs are the issue, pin the CA bundle via REQUESTS_CA_BUNDLE.",
           [R["tls"]], M_TLSOFF, "CWE-295", ["tls"]),
        _f("Weak hash used for security purpose (MD5/SHA1)", Severity.MEDIUM, "Cryptography",
           "MD5/SHA1 are broken for password hashing and signatures. Collisions are practical.",
           "Use SHA-256+ for digests and argon2id/bcrypt/scrypt/PBKDF2 for passwords.",
           [R["crypto"]], M_WEAKCRYPTO, "CWE-327", ["crypto"]),
        _f("Insecure randomness (random module) for tokens", Severity.MEDIUM, "Cryptography",
           "The random module is not cryptographically secure; predictable tokens enable session/ID forgery.",
           "Use secrets.token_hex/token_urlsafe or os.urandom for any security token.",
           [R["crypto"]], M_WEAKCRYPTO, "CWE-338", ["crypto"]),
        _f("Flask debug mode enabled", Severity.HIGH, "Debug Configuration",
           "debug=True exposes the Werkzeug debugger with an interactive console that allows remote code execution when reachable.",
           "Disable debug in production; run behind a WSGI server (gunicorn/uwsgi) with debug off.",
           [R["auth"]], M_EXEC, "CWE-489", ["debug"]),
        _f("Potential SQL injection (string-formatted query)", Severity.CRITICAL, "SQL Injection",
           "A SQL statement is built with f-strings/`.format()`/`%` formatting. User data concatenated into SQL allows injection.",
           "Use parameterized queries (cursor.execute(sql, params)) or an ORM; never format user input into SQL.",
           [R["sql"]], M_SQLI, "CWE-89", ["sqli"]),
        _f("Server-side request with user-controlled URL (SSRF risk)", Severity.MEDIUM, "SSRF",
           "An HTTP call appears to take a dynamic URL. If the URL is attacker-controlled, internal services may be reachable (SSRF).",
           "Validate against an allow-list of hosts/schemes; block link-local/loopback addresses; use a egress proxy.",
           [R["ssrf"]], ["T1190"], "CWE-918", ["ssrf"]),
        _f("Password stored/compared in plain form", Severity.HIGH, "Authentication",
           "Passwords appear to be handled in plaintext (assignment/concat with 'password').",
           "Hash passwords with argon2id/bcrypt (salted, tuned cost); never store or log plaintext.",
           [R["auth"]], ["T1552.001"], "CWE-256", ["auth"]),
        _f("Auto file upload without validation pattern", Severity.MEDIUM, "File Upload",
           "File writes take a user-derived filename. Unvalidated names can enable path traversal or web shell upload.",
           "Sanitize filenames (werkzeug.secure_filename), enforce extension/size allow-lists and store outside the webroot.",
           [R["docker"]], M_UPLOAD, "CWE-434", ["upload"]),
    ],
    ".js": [
        _f("eval()/new Function() dynamic code execution", Severity.CRITICAL, "Code Injection",
           "eval executes arbitrary JavaScript; attacker-controlled data leads to full XSS-to-RCE chains.",
           "Replace with JSON.parse or explicit logic maps; never eval user input.",
           [R["cmd"]], M_EXEC, "CWE-95", ["rce", "xss"]),
        _f("innerHTML assignment with dynamic data", Severity.HIGH, "Cross-Site Scripting",
           "Assigning unsanitized data to innerHTML enables stored/reflected XSS.",
           "Use textContent, or sanitize with DOMPurify before injecting HTML.",
           [R["xss"]], M_XSS, "CWE-79", ["xss"]),
        _f("document.write with dynamic data", Severity.MEDIUM, "Cross-Site Scripting",
           "document.write of untrusted data can inject markup and scripts (XSS).",
           "Manipulate DOM via createElement/textContent instead.",
           [R["xss"]], M_XSS, "CWE-79", ["xss"]),
        _f("child_process exec with concatenated command", Severity.CRITICAL, "Command Injection",
           "exec() runs through the shell; injected metacharacters give OS command execution.",
           "Use execFile/spawn with argument arrays and shell:false.",
           [R["cmd"]], M_EXEC, "CWE-78", ["command-injection"]),
        _f("TLS verification disabled (rejectUnauthorized: false)", Severity.MEDIUM, "Transport Security",
           "Node agent configured to accept invalid certificates -> MitM possible.",
           "Remove rejectUnauthorized:false; trust a custom CA instead.",
           [R["tls"]], M_TLSOFF, "CWE-295", ["tls"]),
        _f("Weak crypto primitive (md5/sha1) used", Severity.MEDIUM, "Cryptography",
           "MD5/SHA1 via crypto.createHash for security purposes is deprecated.",
           "Use sha256+; for passwords use bcrypt/argon2 (with salt).",
           [R["crypto"]], M_WEAKCRYPTO, "CWE-327", ["crypto"]),
        _f("Hardcoded secret in JavaScript source", Severity.HIGH, "Hardcoded Secret",
           "A credential-like literal is embedded in shipped JavaScript where any user can read it.",
           "Move secrets server-side; expose only short-lived, scoped tokens to the browser.",
           [R["auth"]], ["T1552.001"], "CWE-798", ["secret"]),
        _f("CORS wildcard with credentials", Severity.MEDIUM, "Access Control",
           "Access-Control-Allow-Origin:* combined with credentials=true allows any origin to make credentialed requests.",
           "Echo a validated origin allow-list instead of '*' when credentials are sent.",
           [R["auth"]], ["T1190"], "CWE-942", ["cors"]),
    ],
    ".jsx": [],  # covered by .js rules below
    ".ts": [
        _f("eval()/Function constructor in TypeScript", Severity.CRITICAL, "Code Injection",
           "eval executes arbitrary code; defeats TypeScript safety entirely.",
           "Remove eval; use typed parsing (JSON.parse with validation, e.g. zod).",
           [R["cmd"]], M_EXEC, "CWE-95", ["rce"]),
        _f("dangerouslySetInnerHTML with dynamic value", Severity.HIGH, "Cross-Site Scripting",
           "React escapes by default; dangerouslySetInnerHTML bypasses it and enables XSS.",
           "Sanitize with DOMPurify or render text nodes.",
           [R["xss"]], M_XSS, "CWE-79", ["xss"]),
    ],
    ".java": [
        _f("Runtime.exec / ProcessBuilder shell execution", Severity.HIGH, "Command Injection",
           "Executing OS commands with concatenated input enables command injection.",
           "Avoid exec; if required, use argument arrays without shell and validate input.",
           [R["cmd"]], M_EXEC, "CWE-78", ["command-injection"]),
        _f("Java deserialization (ObjectInputStream)", Severity.HIGH, "Deserialization",
           "Deserializing untrusted streams enables gadget-chain RCE.",
           "Prefer JSON; enforce a look-ahead deserialization filter (ObjectInputFilter).",
           [R["deser"]], M_DESER, "CWE-502", ["deserialization"]),
        _f("Trust-all X509TrustManager / HostnameVerifier", Severity.HIGH, "Transport Security",
           "A TrustManager/HostnameVerifier that accepts everything disables TLS validation.",
           "Remove the permissive implementation and trust the default CA store or pin CAs.",
           [R["tls"]], M_TLSOFF, "CWE-295", ["tls"]),
        _f("MessageDigest MD5/SHA-1 for security", Severity.MEDIUM, "Cryptography",
           "Weak digest used; collisions undermine signatures/integrity.",
           "Use SHA-256+ or bcrypt for passwords.",
           [R["crypto"]], M_WEAKCRYPTO, "CWE-327", ["crypto"]),
        _f("Potential SQL injection via string concatenation", Severity.CRITICAL, "SQL Injection",
           "SQL built by concatenation with variables enables injection.",
           "Use PreparedStatement with bound parameters.",
           [R["sql"]], M_SQLI, "CWE-89", ["sqli"]),
        _f("XXE risk: XML parser without secure processing", Severity.HIGH, "XML External Entities",
           "Default DocumentBuilderFactory/SAXParser resolves external entities -> file read/SSRF.",
           "Set factory features: disallow-doctype-decl true and external entities false.",
           [R["ssrf"]], ["T1190"], "CWE-611", ["xxe"]),
    ],
    ".php": [
        _f("eval() / assert() code execution", Severity.CRITICAL, "Code Injection",
           "eval executes arbitrary PHP.",
           "Remove eval; whitelist dispatch.",
           [R["cmd"]], M_EXEC, "CWE-95", ["rce"]),
        _f("Command execution via shell_exec/system/exec/passthru/backticks", Severity.CRITICAL, "Command Injection",
           "Shell command with dynamic input gives OS command execution.",
           "Use escapeshellarg on every argument or avoid the shell entirely.",
           [R["cmd"]], M_EXEC, "CWE-78", ["command-injection"]),
        _f("Unsafe unserialize of user input", Severity.CRITICAL, "Deserialization",
           "PHP object injection via unserialize on request data is a common RCE path.",
           "Use json_decode; if unavoidable use allowed_classes:false.",
           [R["deser"]], M_DESER, "CWE-502", ["deserialization"]),
        _f("Potential SQL injection (query with concatenation)", Severity.CRITICAL, "SQL Injection",
           "mysql_/mysqli query built from concatenated variables.",
           "Use PDO prepared statements with bound parameters.",
           [R["sql"]], M_SQLI, "CWE-89", ["sqli"]),
        _f("Weak hash function md5()/sha1() for credentials", Severity.MEDIUM, "Cryptography",
           "Fast weak hashes are trivially brute forced.",
           "Use password_hash() (bcrypt/argon2id) and password_verify().",
           [R["crypto"]], M_WEAKCRYPTO, "CWE-916", ["crypto"]),
    ],
    ".go": [
        _f("exec.Command with concatenated input", Severity.HIGH, "Command Injection",
           "Dynamic command construction enables injection.",
           "Pass arguments as separate elements; validate inputs.",
           [R["cmd"]], M_EXEC, "CWE-78", ["command-injection"]),
        _f("Insecure TLS config (InsecureSkipVerify)", Severity.MEDIUM, "Transport Security",
           "tls.Config{InsecureSkipVerify:true} disables certificate validation.",
           "Remove InsecureSkipVerify; add custom RootCAs if needed.",
           [R["tls"]], M_TLSOFF, "CWE-295", ["tls"]),
        _f("Weak crypto (md5/sha1/des)", Severity.MEDIUM, "Cryptography",
           "Weak primitives used.",
           "Use sha256/aes-gcm; for passwords use argon2/bcrypt.",
           [R["crypto"]], M_WEAKCRYPTO, "CWE-327", ["crypto"]),
        _f("Potential SQL string concatenation (fmt.Sprintf into Query)", Severity.CRITICAL, "SQL Injection",
           "Query formatted with Sprintf instead of placeholders.",
           "Use db.Query(sql, args...) placeholders.",
           [R["sql"]], M_SQLI, "CWE-89", ["sqli"]),
    ],
    ".cs": [
        _f("Process.Start with shell commands (cmd.exe /c)", Severity.HIGH, "Command Injection",
           "Dynamic shell invocation enables command injection.",
           "Use ProcessStartInfo with argument list and UseShellExecute=false; validate inputs.",
           [R["cmd"]], M_EXEC, "CWE-78", ["command-injection"]),
        _f("BinaryFormatter deserialization", Severity.CRITICAL, "Deserialization",
           "BinaryFormatter on untrusted data is remote code execution by design.",
           "Migrate to System.Text.Json; never deserialize untrusted data with BinaryFormatter.",
           [R["deser"]], M_DESER, "CWE-502", ["deserialization"]),
        _f("Cert validation disabled (ServerCertificateCustomValidationCallback)", Severity.MEDIUM, "Transport Security",
           "HttpClient callback accepting any certificate enables MitM.",
           "Remove the dangerous callback; validate against custom CA if needed.",
           [R["tls"]], M_TLSOFF, "CWE-295", ["tls"]),
        _f("MD5/SHA1 usage", Severity.MEDIUM, "Cryptography",
           "Weak hash algorithm.",
           "Use SHA256+ / PBKDF2 for passwords.",
           [R["crypto"]], M_WEAKCRYPTO, "CWE-327", ["crypto"]),
        _f("Potential SQL injection (string concatenation into SqlCommand)", Severity.CRITICAL, "SQL Injection",
           "SQL built via concatenation.",
           "Use SqlParameter parameters.",
           [R["sql"]], M_SQLI, "CWE-89", ["sqli"]),
    ],
}

# .jsx/.tsx reuse the JavaScript/TypeScript rules
LANG_RULES[".jsx"] = LANG_RULES[".js"]
LANG_RULES[".tsx"] = LANG_RULES[".ts"]

# (regex, message, severity, remediation, refs, mitre, cwe)
GENERIC_RULES = [
    (re.compile(r"(?i)(password|secret|api_key|apikey|token)\s*[:=]\s*[\"'][^\"']{8,}[\"']\s*$"),
     "Possible hardcoded credential", Severity.MEDIUM, "Hardcoded Secret",
     "Move to environment/secret store and rotate.",
     [R["auth"]], ["T1552.001"], "CWE-798"),
]

DOCKERFILE_RULES = [
    (re.compile(r"(?i)^\s*USER\s+(root|0)\b"), "Container runs as root",
     Severity.MEDIUM,
     "Add a dedicated non-root user (USER app) in the Dockerfile and drop privileges at runtime.",
     M_IAC, "CWE-250"),
    (re.compile(r"(?i)^\s*FROM\s+\S+:latest\b"), "Base image uses the mutable :latest tag",
     Severity.LOW,
     "Pin base images to an immutable digest or version tag.",
     M_IAC, "CWE-1357"),
    (re.compile(r"(?i)\b(AWS_SECRET|PASSWORD|API_KEY|TOKEN)\s*=\s*\S+"),
     "Secret passed via ENV in Dockerfile", Severity.HIGH,
     "ENV values are visible in image layers/history. Use BuildKit --mount=type=secret or runtime secrets.",
     ["T1552.001"], "CWE-798"),
]

TERRAFORM_RULES = [
    (re.compile(r"(?i)cidr_blocks\s*=\s*\[?\s*\"0\.0\.0\.0/0\""),
     "Security group allows ingress from the entire internet (0.0.0.0/0)",
     Severity.MEDIUM,
     "Restrict ingress to known CIDRs; put admin ports behind a bastion/VPN.",
     ["T1133"], "CWE-284"),
    (re.compile(r"(?i)^\s*inline\s*=\s*\"(sudo )?(echo\s+)?.*(password|secret)"),
     "Possible secret in user_data/startup script", Severity.MEDIUM,
     "Move secrets to SSM Parameter Store/Secrets Manager instead of instance bootstrap scripts.",
     ["T1552.001"], "CWE-798"),
]

CI_RULES = [
    (re.compile(r"(?i)(password|token|api_?key|secret)\s*:\s*[\"']?[A-Za-z0-9_\-/+=]{12,}"),
     "Possible plaintext secret in CI pipeline definition", Severity.HIGH,
     "Use masked repository/organization secrets instead of literals.",
     ["T1552.001"], "CWE-798"),
    (re.compile(r"pull_request_target"),
     "Workflow uses pull_request_target (untrusted code with repo secrets)",
     Severity.MEDIUM,
     "Ensure the workflow never checks out and executes untrusted PR code with write permissions; split into two jobs.",
     ["T1195"], "CWE-283"),
]

APACHE_NGINX_RULES = [
    (re.compile(r"(?i)^\s*SSLProtocol\s+.*(-all)?\s*(\+?SSLv3|\+?TLSv1( |$))"),
     "Deprecated SSL/TLS protocols enabled in server config", Severity.MEDIUM,
     "Restrict to TLSv1.2 and TLSv1.3 only (e.g. 'SSLProtocol -all +TLSv1.2 +TLSv1.3').",
     M_TLSOFF, "CWE-327"),
]

SQL_FILE_RULES = [
    (re.compile(r"(?i)GRANT\s+ALL\s+PRIVILEGES\s+ON\s+\*?\.\*?\s+TO"),
     "Database superuser grant on all databases", Severity.MEDIUM,
     "Grant least-privilege per database/schema to application accounts.",
     ["T1078"], "CWE-250"),
]


SINK_PATTERNS = {
    "Use of eval()/exec() on dynamic input": r"\b(eval|exec)\s*\(",
    "os.system() shell call": r"\bos\.system\s*\(",
    "subprocess with shell=True": r"shell\s*=\s*True",
    "Unsafe YAML load (yaml.load without SafeLoader)": r"yaml\.load\s*\((?![^)]*SafeLoader)",
    "Unsafe deserialization with pickle.loads/marshal.loads": r"\b(pickle|marshal|dill|shelve)\.loads?\s*\(",
    "TLS certificate verification disabled (verify=False)": r"(verify|cert_validate)\s*=\s*False",
    "Weak hash used for security purpose (MD5/SHA1)": r"\b(hashlib\.)?(md5|sha1)\s*\(",
    "Insecure randomness (random module) for tokens": r"\brandom\.(randint|choice|random|randrange|getrandbits)\s*\(",
    "Flask debug mode enabled": r"debug\s*=\s*True",
    "Potential SQL injection (string-formatted query)": r"(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[^\n]{0,120}(%s|%\(|\.format\(|f[\"'])",
    "Server-side request with user-controlled URL (SSRF risk)": r"(requests\.(get|post|put|delete|head)|urlopen)\s*\(\s*[a-z_]*(url|link|target|endpoint)",
    "Password stored/compared in plain form": r"(?i)(password|passwd)\s*=\s*[a-z_][a-z0-9_]*(?!['\"])",
    "Auto file upload without validation pattern": r"(?i)(open|save|write)\s*\(\s*[a-z_.]*(file|upload|name)",
    "eval()/new Function() dynamic code execution": r"(\beval\s*\(|new\s+Function\s*\()",
    "innerHTML assignment with dynamic data": r"innerHTML\s*=",
    "document.write with dynamic data": r"document\.write\s*\(",
    "child_process exec with concatenated command": r"(child_process\.)?exec\s*\(\s*[^\)]*(\+|\`|\$\{)",
    "TLS verification disabled (rejectUnauthorized: false)": r"rejectUnauthorized\s*:\s*false",
    "Weak crypto primitive (md5/sha1) used": r"createHash\s*\(\s*[\"'](md5|sha1)[\"']",
    "Hardcoded secret in JavaScript source": r"(?i)(const|let|var)\s+\w*(secret|password|apikey|api_key|token)\w*\s*=\s*[\"'][^\"']{8,}[\"']",
    "CORS wildcard with credentials": r"credentials\s*:\s*true",
    "eval()/Function constructor in TypeScript": r"(\beval\s*\(|new\s+Function\s*\()",
    "dangerouslySetInnerHTML with dynamic value": r"dangerouslySetInnerHTML",
    "Runtime.exec / ProcessBuilder shell execution": r"(\bRuntime\.getRuntime\(\)\.exec|\bnew\s+ProcessBuilder)",
    "Java deserialization (ObjectInputStream)": r"new\s+ObjectInputStream\s*\(",
    "Trust-all X509TrustManager / HostnameVerifier": r"(checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|return\s+true\s*;\s*//\s*trust|setHostnameVerifier\s*\(\s*\(\s*\w+,\s*\w+\s*\)\s*->\s*true)",
    "MessageDigest MD5/SHA-1 for security": r"MessageDigest\.getInstance\s*\(\s*\"(MD5|SHA-?1)\"",
    "Potential SQL injection via string concatenation": r"(SELECT|INSERT|UPDATE|DELETE)[^\n;]{0,120}(\+\s*\w+|String\.format)",
    "XXE risk: XML parser without secure processing": r"(DocumentBuilderFactory|SAXParserFactory)\.newInstance\s*\(",
    "eval() / assert() code execution": r"\b(eval\s*\(|assert\s*\(\s*[^\s,)]+\s*(and|or))",
    "Command execution via shell_exec/system/exec/passthru/backticks": r"\b(shell_exec|system|passthru|exec)\s*\(",
    "Unsafe unserialize of user input": r"unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)",
    "Potential SQL injection (query with concatenation)": r"(SELECT|INSERT|UPDATE|DELETE)[^\n;]{0,120}(\.\s*\$|\{\$)",
    "Weak hash function md5()/sha1() for credentials": r"\b(md5|sha1)\s*\(",
    "exec.Command with concatenated input": r"exec\.Command\s*\([^,)]*(",
    "Insecure TLS config (InsecureSkipVerify)": r"InsecureSkipVerify\s*:\s*true",
    "Weak crypto (md5/sha1/des)": r"(md5\.New|sha1\.New|des\.)",
    "Potential SQL string concatenation (fmt.Sprintf into Query)": r"(Query|Exec)\s*\(\s*fmt\.Sprintf",
    "Process.Start with shell commands (cmd.exe /c)": r"(cmd\.exe|Process\.Start)",
    "BinaryFormatter deserialization": r"BinaryFormatter",
    "Cert validation disabled (ServerCertificateCustomValidationCallback)": r"ServerCertificateCustomValidationCallback\s*=",
    "MD5/SHA1 usage": r"MD5\.Create|SHA1\.Create",
    "Potential SQL injection (string concatenation into SqlCommand)": r"(SELECT|INSERT|UPDATE|DELETE)[^\n;]{0,120}(\+\s*\w+|\$\"|\{)",
}


def scan(root: str, max_file_size: int = 2 * 1024 * 1024, progress=None, excludes: list | None = None) -> list:
    findings: list[Finding] = []
    files = list(walk_files(root, max_file_size, excludes=excludes))
    total = len(files)
    for i, (path, rel) in enumerate(files):
        if progress and i % 25 == 0:
            progress(i, total)
        text = read_text(path)
        if not text:
            continue
        ext = os.path.splitext(rel)[1].lower()
        base = os.path.basename(rel).lower()

        if ext in LANG_RULES:
            # language rules: pair each declared rule with its sink pattern
            for item in LANG_RULES[ext]:
                rx = re.compile(SINK_PATTERNS.get(item["title"], r"(?!)x-none"))
                for j, line in enumerate(text.splitlines(), 1):
                    s = line.strip()
                    if s.startswith(("#", "//", "*", "<!--")):
                        continue
                    if rx.search(line):
                        findings.append(Finding(
                            scanner="sast", category=item["category"], title=item["title"],
                            severity=item["severity"], target=rel, location=f"{rel}:{j}",
                            description=item["description"], evidence=s[:160],
                            remediation=item["remediation"], references=item["references"],
                            mitre=item["mitre"], cwe=item["cwe"], tags=item["tags"] + ["sast"],
                        ))
        if base == "dockerfile":
            for rx, msg, sev, fix, mitre, cwe in DOCKERFILE_RULES:
                for j, line in enumerate(text.splitlines(), 1):
                    if rx.search(line):
                        findings.append(Finding(
                            scanner="sast", category="Container Security", title=msg,
                            severity=sev, target=rel, location=f"{rel}:{j}",
                            description=f"{msg} (Dockerfile).", evidence=line.strip()[:160],
                            remediation=fix, references=[R["docker"]], mitre=mitre,
                            cwe=cwe, tags=["docker", "sast"],
                        ))
        if ext == ".tf":
            for rx, msg, sev, fix, mitre, cwe in TERRAFORM_RULES:
                for j, line in enumerate(text.splitlines(), 1):
                    if rx.search(line):
                        findings.append(Finding(
                            scanner="sast", category="Infrastructure as Code", title=msg,
                            severity=sev, target=rel, location=f"{rel}:{j}",
                            description=f"{msg} (Terraform).", evidence=line.strip()[:160],
                            remediation=fix, references=["https://developer.hashicorp.com/terraform/cloud-docs/workspaces"],
                            mitre=mitre, cwe=cwe, tags=["iac", "sast"],
                        ))
        if base.endswith(".yml") or base.endswith(".yaml"):
            if ".github/workflows" in rel.replace("\\", "/") or "gitlab-ci" in base:
                for rx, msg, sev, fix, mitre, cwe in CI_RULES:
                    for j, line in enumerate(text.splitlines(), 1):
                        if rx.search(line):
                            findings.append(Finding(
                                scanner="sast", category="CI/CD Pipeline", title=msg,
                                severity=sev, target=rel, location=f"{rel}:{j}",
                                description=f"{msg} ({base}).", evidence=line.strip()[:160],
                                remediation=fix, references=["https://docs.github.com/en/actions/security-guides"],
                                mitre=mitre, cwe=cwe, tags=["ci", "sast"],
                            ))
        if ext in (".conf", ".cfg") and ("apache" in base or "nginx" in base or "default" in base):
            for rx, msg, sev, fix, mitre, cwe in APACHE_NGINX_RULES:
                for j, line in enumerate(text.splitlines(), 1):
                    if rx.search(line):
                        findings.append(Finding(
                            scanner="sast", category="Server Configuration", title=msg,
                            severity=sev, target=rel, location=f"{rel}:{j}",
                            description=f"{msg}.", evidence=line.strip()[:160],
                            remediation=fix, references=[R["tls"]], mitre=mitre, cwe=cwe,
                            tags=["webserver", "sast"],
                        ))
        if ext == ".sql":
            for rx, msg, sev, fix, mitre, cwe in SQL_FILE_RULES:
                for j, line in enumerate(text.splitlines(), 1):
                    if rx.search(line):
                        findings.append(Finding(
                            scanner="sast", category="Database Configuration", title=msg,
                            severity=sev, target=rel, location=f"{rel}:{j}",
                            description=f"{msg}.", evidence=line.strip()[:160],
                            remediation=fix, references=[R["auth"]], mitre=mitre, cwe=cwe,
                            tags=["database", "sast"],
                        ))
    if progress:
        progress(total, total)
    return findings
