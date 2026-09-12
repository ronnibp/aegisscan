"""Hardcoded secret & credential detection (TruffleHog-style, offline regex+entropy).

Covers cloud provider keys, tokens, private key material, connection strings
and high-entropy literals committed to source or .env files.
"""

from __future__ import annotations

import re

from ..core.models import Finding, Severity
from ..core.utils import read_text, walk_files

MITRE_CREDS = ["T1552", "T1552.001"]
MITRE_PRIVKEY = ["T1552.004", "T1078"]

# (name, compiled regex, severity, remediation, reference)
PATTERNS = [
    ("AWS Access Key ID",
     re.compile(r"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"),
     Severity.HIGH,
     "Rotate the AWS access key in IAM, remove it from the code history and store it in a secret manager or environment variable.",
     ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"]),
    ("AWS Secret Access Key",
     re.compile(r"(?i)aws(.{0,20})?(secret|sk)[_a-z0-9]*\s*[:=]\s*['\"]([a-z0-9/+=]{40})['\"]"),
     Severity.CRITICAL,
     "Rotate the AWS secret key immediately, purge it from git history (git filter-repo) and move it to a secrets manager.",
     ["https://docs.aws.amazon.com/general/latest/gr/aws-security-credentials.html"]),
    ("GitHub Token",
     re.compile(r"\b(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b"),
     Severity.CRITICAL,
     "Revoke the token at GitHub -> Settings -> Developer settings, then use a fine-grained token stored in a secret store.",
     ["https://docs.github.com/en/authentication/keeping-your-account-and-data-secure"]),
    ("Google API Key",
     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
     Severity.HIGH,
     "Restrict the API key by referrer/IP in Google Cloud console and rotate it; keep it out of source.",
     ["https://cloud.google.com/docs/authentication/api-keys"]),
    ("Google OAuth Client Secret",
     re.compile(r"\bGOCSPX-[A-Za-z0-9_\-]{28,}\b"),
     Severity.CRITICAL,
     "Revoke and regenerate the OAuth client secret in Google Cloud Console credentials page.",
     ["https://cloud.google.com/docs/authentication"]),
    ("Slack Token",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
     Severity.HIGH,
     "Rotate the Slack token (app management console) and load it from a secure environment variable.",
     ["https://api.slack.com/authentication/token-types"]),
    ("Stripe Live Secret Key",
     re.compile(r"\b(sk|rk)_live_[0-9a-zA-Z]{20,}\b"),
     Severity.CRITICAL,
     "Roll the Stripe live secret key in the Stripe dashboard immediately; publishable keys only in frontend code.",
     ["https://stripe.com/docs/keys"]),
    ("OpenAI API Key",
     re.compile(r"\bsk-(proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b"),
     Severity.CRITICAL,
     "Revoke the OpenAI key in the platform dashboard and reissue; inject via environment.",
     ["https://platform.openai.com/docs/api-reference/authentication"]),
    ("Anthropic API Key",
     re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{30,}\b"),
     Severity.CRITICAL,
     "Revoke the Anthropic key in the console and reissue; inject via environment.",
     ["https://docs.anthropic.com/en/docs/get-started/keys"]),
    ("SendGrid API Key",
     re.compile(r"\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}\b"),
     Severity.HIGH,
     "Rotate the SendGrid API key and restrict its scopes; store outside source control.",
     ["https://docs.sendgrid.com/ui/account-and-settings/api-keys"]),
    ("Twilio API Key",
     re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
     Severity.MEDIUM,
     "Rotate the Twilio API key and use short-lived keys where possible.",
     ["https://www.twilio.com/docs/iam/keys/api-key"]),
    ("Mailgun API Key",
     re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"),
     Severity.MEDIUM,
     "Rotate the Mailgun private API key and restrict to required domains.",
     ["https://documentation.mailgun.com/docs/mailgun/api-intro/"]),
    ("Private Key Block",
     re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----"),
     Severity.CRITICAL,
     "Never commit private keys. Revoke/re-issue the key pair, purge from git history and encrypt key material at rest.",
     ["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"]),
    ("JWT Hardcoded",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}\b"),
     Severity.MEDIUM,
     "Tokens embedded in code may leak long-lived access. Use short-lived tokens issued at runtime.",
     ["https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"]),
    ("Hardcoded Password (assignment)",
     re.compile(r"(?i)\b(pass(word|wd)?|pwd|secret|api[_-]?key|admin[_-]?pass)\b\s*[:=]\s*[\"']([^\"'\s]{6,})[\"']"),
     Severity.HIGH,
     "Remove the hardcoded password; read it from an environment variable or a vault. Review auth logs for misuse.",
     ["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"]),
    ("Database Connection String with Credentials",
     re.compile(r"(?i)\b(mongodb(?:\+srv)?|postgres(ql)?|mysql|redis|amqp|mssql)://[^\s:/\"']+:[^\s@/\"']+@[^\s\"']+"),
     Severity.CRITICAL,
     "Move DB credentials out of the connection string in code; use environment config and rotate the exposed password.",
     ["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"]),
    ("Heroku / Generic API Key Assignment",
     re.compile(r"(?i)\b(api[_-]?token|auth[_-]?token|access[_-]?token)\b\s*[:=]\s*[\"'][A-Za-z0-9_\-\.]{20,}[\"']"),
     Severity.MEDIUM,
     "Store tokens in a secret manager; rotate the exposed token.",
     ["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"]),
]

ENTROPY_RE = re.compile(r"[\"']([A-Za-z0-9_\-+/=]{32,})[\"']")
KEY_NAME_RE = re.compile(r"(?i)(key|secret|token|password|passwd|credential|auth)")

ENV_FILE_RE = re.compile(r"(?i)^[A-Z0-9_]*(KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD)[A-Z0-9_]*\s*=\s*\S+")


def _redact(match_text: str, keep: int = 4) -> str:
    t = match_text.strip()
    if len(t) <= keep:
        return t[:2] + "…"
    return t[:keep] + "…" + f" ({len(t)} chars)"


def scan(root: str, max_file_size: int = 2 * 1024 * 1024, progress=None, excludes: list | None = None) -> list:
    findings: list[Finding] = []
    seen_spans: set = set()
    files = list(walk_files(root, max_file_size, excludes=excludes))
    total = len(files)
    for i, (path, rel) in enumerate(files):
        if progress and i % 25 == 0:
            progress(i, total)
        text = read_text(path)
        if not text:
            continue
        lines = text.splitlines()
        is_envfile = rel.endswith(".env") or rel.endswith(".env.example") or ".env" in rel.split("/")

        for j, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "*", "<!--")) and not is_envfile:
                continue
            for (name, rx, sev, fix, refs) in PATTERNS:
                m = rx.search(line)
                if not m:
                    continue
                # obvious placeholder values are informational only
                val = m.group(0).lower()
                if any(p in val for p in ("example", "changeme", "change_me", "xxxxxx", "<", "your_", "placeholder", "dummy", "test123")):
                    sev = Severity.INFO
                key = (rel, j, name)
                if key in seen_spans:
                    continue
                seen_spans.add(key)
                findings.append(Finding(
                    scanner="secrets", category="Hardcoded Secret",
                    title=f"{name} committed in {rel}",
                    severity=sev, target=root, location=f"{rel}:{j}",
                    description=f"A {name.lower()} appears to be hardcoded in the repository. "
                                f"Anyone with read access to the code (including git history, forks and CI logs) can extract it and impersonate the service.",
                    evidence=_redact(m.group(0)),
                    remediation=fix,
                    references=refs, mitre=MITRE_CREDS, cwe="CWE-798",
                    tags=["secret", "credentials"],
                ))
            # high-entropy string next to a key-ish identifier
            if not is_envfile:
                for em in ENTROPY_RE.finditer(line):
                    token = em.group(1)
                    if len(token) >= 32 and KEY_NAME_RE.search(line):
                        import math
                        from ..core.utils import shannon_entropy
                        if shannon_entropy(token) > 4.3:
                            findings.append(Finding(
                                scanner="secrets", category="Hardcoded Secret",
                                title=f"High-entropy credential-like string in {rel}",
                                severity=Severity.MEDIUM, target=root,
                                location=f"{rel}:{j}",
                                description="A long high-entropy string is assigned near a key/secret/password identifier. "
                                            "This frequently indicates an embedded API key or cryptographic secret.",
                                evidence=_redact(token),
                                remediation="Confirm the string is not a credential; if it is, rotate it and load it from a secret store.",
                                references=["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
                                mitre=MITRE_CREDS, cwe="CWE-798", tags=["secret", "entropy"],
                            ))
            elif is_envfile:
                if ENV_FILE_RE.match(stripped) and not stripped.lower().endswith("=") and "your_" not in stripped.lower() and "changeme" not in stripped.lower():
                    k = stripped.split("=")[0]
                    if (rel, j, "dotenv") not in seen_spans:
                        seen_spans.add((rel, j, "dotenv"))
                        findings.append(Finding(
                            scanner="secrets", category="Configuration",
                            title=f".env file with real-looking values committed ({k})",
                            severity=Severity.MEDIUM, target=root, location=f"{rel}:{j}",
                            description="A .env-style file containing credential-looking variables is stored in the repository. "
                                        "If this file is deployed it may leak live secrets; if it is a template, values should be empty.",
                            evidence=f"{k}=<redacted>",
                            remediation="Keep .env out of version control (.gitignore), ship a .env.example with placeholders, and rotate any value that was ever committed.",
                            references=["https://12factor.net/config"], mitre=MITRE_CREDS,
                            cwe="CWE-312", tags=["config", "secret"],
                        ))
        # committed private key files
        import os
        if rel.endswith(".pem") or rel.endswith(".p12") or rel.endswith(".pfx") or rel.endswith(".key"):
            findings.append(Finding(
                scanner="secrets", category="Hardcoded Secret",
                title=f"Potential key material file committed: {rel}",
                severity=Severity.CRITICAL, target=root, location=rel,
                description="A file with a private-key extension is present in the repository.",
                evidence=os.path.basename(rel),
                remediation="Verify the file, revoke the key if private, and remove it from history with git filter-repo.",
                references=["https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"],
                mitre=MITRE_PRIVKEY, cwe="CWE-321", tags=["secret", "keys"],
            ))
    if progress:
        progress(total, total)
    return findings
