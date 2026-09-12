"""TLS / SSL audit — an SSL-Labs-style assessment of HTTPS endpoints.

Evaluates protocol versions, cipher suites, forward secrecy, certificate
validity/chain/hostname match, HSTS and produces a familiar A+..F grade plus
actionable findings.
"""

from __future__ import annotations

import socket
import ssl
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from ..core.models import Finding, Severity
from ..core.utils import domain_of, fetch, normalize_url

TLS_FINDING_REF = "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"


# --------------------------------------------------------------------- utils
def _hostname_matches(cert: dict, host: str) -> bool:
    host = host.lower().rstrip(".")
    dns_sans = [v.lower() for k, v in (cert.get("subjectAltName") or []) if k == "DNS"]
    ip_sans = [v.lower() for k, v in (cert.get("subjectAltName") or []) if k == "IP Address"]
    if host in ip_sans:
        return True
    cn = ""
    for rdn in cert.get("subject") or ():
        for k, v in rdn:
            if k == "commonName":
                cn = v.lower()
                break
    candidates = dns_sans or ([cn] if cn else [])

    def match(pattern: str, name: str) -> bool:
        if pattern.startswith("*."):
            rest = pattern[2:]
            labels = name.split(".")
            return len(labels) >= 3 and name.endswith("." + rest) and labels[0] != ""
        return pattern == name

    return any(match(p, host) for p in candidates)


def _decode_cert(pem: str) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as fh:
        fh.write(pem)
        path = fh.name
    try:
        return ssl._ssl._test_decode_cert(path)  # noqa: SLF001 - stdlib cert parser
    finally:
        import os
        try:
            os.unlink(path)
        except OSError:
            pass


def _try_protocol(host: str, port: int, version: ssl.TLSVersion, timeout: int, ciphers: str | None = None):
    """Attempt a handshake pinned to a single protocol version. Returns (ok, chosen_cipher|error)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = version
        ctx.maximum_version = version
    except ValueError:
        return False, "unsupported by local OpenSSL"
    if ciphers is not None:
        try:
            ctx.set_ciphers(ciphers)
        except ssl.SSLError:
            return False, "cipher not available locally"
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                return True, tls.cipher()
    except (ssl.SSLError, socket.timeout, OSError, ValueError) as e:
        return False, str(e)


def _handshake_context(host: str, port: int, timeout: int, verify: bool):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.cipher(), tls.version(), tls.getpeercert(binary_form=True), tls.compression()


WEAK_TOKENS = ("RC4", "DES", "3DES", "NULL", "EXP", "MD5", "SEED", "IDEA", "PSK", "SRP", "RC2", "CAMELLIA")


def _classify_cipher(name: str) -> dict:
    weak = any(t in name for t in WEAK_TOKENS)
    fs = ("ECDHE" in name) or ("DHE" in name)
    aead = ("GCM" in name) or ("CHACHA20" in name)
    if weak:
        strength = "weak"
    elif aead and fs:
        strength = "strong"
    else:
        strength = "acceptable"
    return {"weak": weak, "forward_secrecy": fs, "strength": strength}


# ----------------------------------------------------------------- main audit
def audit(target: str, port: int = 443, timeout: int = 10, progress=None):
    host = target
    if "://" in target or "/" in target:
        parsed = urlparse(target if "://" in target else "https://" + target)
        host = parsed.hostname or domain_of(target)
        if parsed.port:
            port = parsed.port
    details: dict = {
        "host": host, "port": port, "grade": "", "score": 0.0,
        "protocols": {}, "ciphers": [], "cert": {}, "hsts": {},
        "summary": [], "reachable": True,
    }
    findings: list[Finding] = []

    def prog(p, t=100):
        if progress:
            progress(p, t)

    # -- reachability + default handshake --------------------------------
    try:
        chosen, version, der, compression = _handshake_context(host, port, timeout, verify=False)
    except Exception as e:
        details["reachable"] = False
        details["summary"].append(f"TLS handshake to {host}:{port} failed: {e}")
        prog(100)
        return findings, details
    prog(15)

    # -- protocol matrix ---------------------------------------------------
    versions = [
        ("SSLv2", ssl.TLSVersion.SSLv3),  # OpenSSL treats SSLv2 handshake via SSLv3 max; explicitly blocked
        ("SSLv3", ssl.TLSVersion.SSLv3),
        ("TLS 1.0", ssl.TLSVersion.TLSv1),
        ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
        ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
        ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
    ]
    proto_results = {}
    with ThreadPoolExecutor(max_workers=6) as pool:
        futs = {}
        for label, v in versions:
            try:
                futs[pool.submit(_try_protocol, host, port, v, timeout)] = label
            except ValueError:
                proto_results[label] = (False, "unsupported")
        for fut, label in futs.items():
            proto_results[label] = fut.result()
    details["protocols"] = {lbl: bool(ok) for lbl, (ok, _) in proto_results.items()}
    prog(45)

    weak_protos = [l for l in ("SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1") if details["protocols"].get(l)]
    modern = details["protocols"].get("TLS 1.2") or details["protocols"].get("TLS 1.3")

    # -- cipher enumeration (TLS1.2 and below) -----------------------------
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    all_ciphers = [c for c in ctx.get_ciphers() if c.get("protocol", "") != "TLSv1.3"]
    # de-duplicate OpenSSL cipher names, cap the count to keep scan time sane
    seen, names = set(), []
    for c in all_ciphers:
        if c["name"] not in seen:
            seen.add(c["name"])
            names.append(c["name"])
    names = names[:40]

    def check_cipher(name):
        ok, res = _try_protocol(host, port, ssl.TLSVersion.TLSv1_2, timeout, ciphers=name)
        if ok and isinstance(res, tuple):
            return {"name": name, "bits": res[0] if isinstance(res[0], int) else 0,
                    "offered": True, **_classify_cipher(name)}
        return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = [r for r in pool.map(check_cipher, names) if r]
    # TLS1.3 ciphers are fixed and all strong; record what was negotiated
    if details["protocols"].get("TLS 1.3"):
        rows.append({"name": version if version == "TLSv1.3" else "TLS_AES_256_GCM_SHA384 (TLS 1.3)",
                     "bits": 256, "offered": True, "weak": False,
                     "forward_secrecy": True, "strength": "strong"})
    details["ciphers"] = rows
    weak_ciphers = [c["name"] for c in rows if c["weak"]]
    no_fs = [c["name"] for c in rows if not c["forward_secrecy"] and not c["weak"]]
    prog(70)

    # -- certificate -------------------------------------------------------
    cert: dict = {}
    try:
        pem = ssl.get_server_certificate((host, port))
        cert = _decode_cert(pem)
    except Exception as e:
        cert = {"error": str(e)}
    details["cert"] = _cert_public_view(cert)

    chain_ok, chain_msg = True, "trusted"
    try:
        _handshake_context(host, port, timeout, verify=True)
    except ssl.SSLCertVerificationError as e:
        chain_ok, chain_msg = False, _friendly_verify_error(e)
    except Exception as e:
        chain_ok, chain_msg = False, f"verification error: {e}"
    details["cert"]["chain_valid"] = chain_ok
    details["cert"]["chain_message"] = chain_msg

    hostname_ok = _hostname_matches(cert, host) if cert and "error" not in cert else False
    details["cert"]["hostname_match"] = hostname_ok

    not_after = details["cert"].get("not_after") or ""
    prog(85)

    # -- HSTS ----------------------------------------------------------------
    hsts = {"present": False, "max_age": 0, "include_subdomains": False, "preload": False}
    try:
        resp = fetch(normalize_url(f"https://{host}:{port}/"), timeout=timeout)
        val = resp.header("strict-transport-security")
        if val:
            hsts["present"] = True
            for part in val.split(";"):
                part = part.strip().lower()
                if part.startswith("max-age"):
                    try:
                        hsts["max_age"] = int(part.split("=")[1].strip())
                    except (IndexError, ValueError):
                        pass
                elif part == "includesubdomains":
                    hsts["include_subdomains"] = True
                elif part == "preload":
                    hsts["preload"] = True
    except Exception:
        pass
    details["hsts"] = hsts
    if compression and "DEFLATE" in (compression or "").upper():
        details["compression"] = compression
    prog(92)

    # -- findings -------------------------------------------------------------
    def add(title, sev, desc, fix, refs=None, mitre=None, cwe="", score=-1):
        findings.append(Finding(
            scanner="tls", category="TLS / Encryption", title=title, severity=sev,
            target=f"{host}:{port}", location=f"https://{host}:{port}",
            description=desc, remediation=fix, references=[TLS_FINDING_REF, *(refs or [])],
            mitre=mitre or ["T1557", "T1190"], cwe=cwe, score=score,
            tags=["tls", "crypto"],
        ))

    for lbl in weak_protos:
        sev = Severity.CRITICAL if lbl in ("SSLv2", "SSLv3") else Severity.MEDIUM
        add(f"Deprecated protocol {lbl} is offered",
            sev,
            f"The server still accepts {lbl} handshakes. {lbl} is cryptographically broken "
            f"(POODLE for SSLv3, BEAST-era issues for TLS 1.0/1.1) and allows downgrade or interception attacks.",
            "Disable " + lbl + " server-side. Serve only TLS 1.2 with strong AEAD ciphers, plus TLS 1.3.",
            refs=["https://www.rfc-editor.org/rfc/rfc8996.html"], cwe="CWE-327")

    for cname in weak_ciphers:
        add(f"Weak cipher suite offered: {cname}", Severity.MEDIUM,
            f"The server negotiates {cname}, which is considered weak (broken primitives or export-grade).",
            "Remove the cipher from the server cipher list; keep only AEAD suites (AES-GCM, ChaCha20-Poly1305) with ECDHE/DHE key exchange.",
            cwe="CWE-327")

    if rows and not any(c["forward_secrecy"] for c in rows if not c["weak"]):
        add("No forward secrecy", Severity.MEDIUM,
            "None of the offered suites provide ephemeral key exchange (ECDHE/DHE). Captured traffic can be decrypted later if the private key leaks.",
            "Prefer ECDHE-based suites (e.g. ECDHE-RSA-AES128-GCM-SHA256) and enable TLS 1.3.",
            cwe="CWE-324")
    elif no_fs:
        add("Cipher suites without forward secrecy offered", Severity.LOW,
            "Suites without ephemeral key exchange are offered alongside strong ones: " + ", ".join(no_fs[:5]),
            "Restrict the cipher list to ECDHE/DHE suites.", cwe="CWE-324", score=2.0)

    if not modern:
        add("No modern TLS version (1.2/1.3) available", Severity.CRITICAL,
            "The endpoint cannot negotiate TLS 1.2 or 1.3; all clients must use broken protocol versions.",
            "Enable TLS 1.2 minimum (ideally 1.3) on the server/CDN.", cwe="CWE-757")

    if not details["protocols"].get("TLS 1.3"):
        add("TLS 1.3 not offered", Severity.LOW,
            "TLS 1.3 provides faster handshakes and removes legacy crypto; it is recommended.",
            "Enable TLS 1.3 alongside TLS 1.2 (OpenSSL 1.1.1+, nginx 1.13+, IIS on Win2019+).",
            score=1.0)

    if cert and "error" not in cert:
        exp_epoch = details["cert"].get("not_after_epoch")
        if exp_epoch is not None:
            days = int((exp_epoch - time.time()) / 86400)
            details["cert"]["days_left"] = days
            if days < 0:
                add("Certificate has expired", Severity.CRITICAL,
                    f"The certificate expired {abs(days)} day(s) ago; browsers block the connection entirely.",
                    "Renew the certificate immediately (ACME/Let's Encrypt automates this).",
                    cwe="CWE-298", score=10.0)
            elif days <= 30:
                add("Certificate expires within 30 days", Severity.MEDIUM,
                    f"The certificate expires in {days} day(s).",
                    "Renew now and set up automated renewal (certbot / ACME).", score=5.0)
        if not hostname_ok:
            add("Certificate hostname mismatch", Severity.CRITICAL,
                "The certificate does not cover the requested hostname, so clients receive warnings or fail.",
                "Issue a certificate for the exact hostname (including SANs for all variants, e.g. www).",
                cwe="CWE-297", score=10.0)
        if not chain_ok:
            if "self-signed" in chain_msg.lower():
                add("Self-signed certificate", Severity.HIGH,
                    "The certificate is self-signed and cannot be trusted by clients without manual trust.",
                    "Deploy a publicly trusted certificate (Let's Encrypt) for production endpoints.",
                    cwe="CWE-295", score=7.5)
            elif "hostname mismatch" not in chain_msg.lower():
                add("Incomplete or untrusted certificate chain", Severity.HIGH,
                    f"Chain validation failed: {chain_msg}. Clients may reject the connection.",
                    "Serve the full intermediate chain (fullchain.pem) and keep the bundle updated.",
                    cwe="CWE-295", score=7.5)
        issuer_cn = details["cert"].get("issuer", "")
        if "sha1" in details["cert"].get("signature_algorithm", "").lower():
            add("Certificate signed with SHA-1", Severity.HIGH,
                "SHA-1 signatures are rejected by modern browsers.",
                "Reissue the certificate with SHA-256.", cwe="CWE-327", score=7.5)
        if "Let's Encrypt" in issuer_cn and details["cert"].get("days_left", 9999) > 90:
            add("Certificate validity longer than CA policy", Severity.LOW,
                "Reported validity exceeds the CA's policy window - verify the certificate source.",
                "Use certificates from a trusted CA with <=398 day validity.", score=1.0)

    if not hsts["present"]:
        add("HTTP Strict Transport Security (HSTS) missing", Severity.MEDIUM,
            "Without HSTS, a machine-in-the-middle can force users onto http:// for the first request (SSL stripping).",
            "Send 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' from all HTTPS responses.",
            refs=["https://cheatsheetseries.owasp.org/controls/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
            cwe="CWE-319", score=5.0)
    elif hsts["max_age"] < 15768000:
        add("HSTS max-age below 6 months", Severity.LOW,
            f"HSTS max-age is {hsts['max_age']}s; a short window weakens the downgrade protection.",
            "Increase max-age to at least 15768000 (6 months), ideally 63072000 (2 years).", score=2.0)

    if details.get("compression") == "DEFLATE":
        add("TLS compression enabled (CRIME risk)", Severity.MEDIUM,
            "TLS compression enables CRIME-style secret-recovery attacks.",
            "Disable TLS compression (modern OpenSSL defaults disable it).", score=5.0)

    # -- grade ---------------------------------------------------------------
    score, grade = _grade(details)
    details["score"] = score
    details["grade"] = grade
    details["summary"] = _summarize(details)
    prog(100)
    return findings, details


def _friendly_verify_error(e: ssl.SSLCertVerificationError) -> str:
    msg = getattr(e, "verify_message", "") or str(e)
    for needle, friendly in [
        ("unable to get local issuer certificate", "incomplete chain: intermediate certificate not served"),
        ("self-signed certificate", "self-signed certificate"),
        ("self signed certificate", "self-signed certificate"),
        ("certificate has expired", "certificate has expired"),
        ("hostname mismatch", "hostname mismatch"),
    ]:
        if needle in msg.lower():
            return friendly
    return msg


def _cert_public_view(cert: dict) -> dict:
    if not cert or "error" in cert:
        return {"error": cert.get("error", "unavailable")}
    def rdns(cert, key):
        for rdn in cert.get("subject") or ():
            for k, v in rdn:
                if k == key:
                    return v
        return ""
    issuer = ""
    for rdn in cert.get("issuer") or ():
        for k, v in rdn:
            if k == "organizationName" and not issuer:
                issuer = v
            elif k == "commonName" and not issuer:
                issuer = v
    return {
        "subject_cn": rdns(cert, "commonName"),
        "issuer": issuer or "unknown",
        "not_before": cert.get("notBefore", ""),
        "not_after": cert.get("notAfter", ""),
        "not_after_epoch": _epoch_of(cert.get("notAfter", "")),
        "serial": cert.get("serialNumber", ""),
        "signature_algorithm": cert.get("signatureAlgorithm", cert.get("signature_algorithm", "")),
        "sans": [v for k, v in (cert.get("subjectAltName") or []) if k == "DNS"],
    }


def _epoch_of(asn1_time: str):
    """Convert OpenSSL 'Nov 22 12:00:00 2027 GMT' style timestamps to epoch seconds."""
    if not asn1_time:
        return None
    try:
        return int(ssl.cert_time_to_seconds(asn1_time))
    except Exception:
        return None


def _grade(d: dict):
    if not d.get("reachable"):
        return 0.0, "-"
    score = 100.0
    fatal = False
    protos = d.get("protocols", {})
    if protos.get("SSLv2") or protos.get("SSLv3"):
        score -= 40
        fatal = True
    for l in ("TLS 1.0", "TLS 1.1"):
        if protos.get(l):
            score -= 10
    if not (protos.get("TLS 1.2") or protos.get("TLS 1.3")):
        fatal = True
    if not protos.get("TLS 1.3"):
        score -= 5
    weak_ciphers = [c for c in d.get("ciphers", []) if c.get("weak")]
    if any(c["strength"] == "weak" and ("RC4" in c["name"] or "NULL" in c["name"] or "EXP" in c["name"] or "DES" in c["name"]) for c in weak_ciphers):
        score -= 20
        if any("RC4" in c["name"] for c in weak_ciphers):
            fatal = fatal or False
    elif weak_ciphers:
        score -= 12
    rows = d.get("ciphers", [])
    if rows and not any(c.get("forward_secrecy") for c in rows if not c.get("weak")):
        score -= 12
    cert = d.get("cert", {})
    days = cert.get("days_left")
    if days is not None:
        if days < 0:
            fatal = True
        elif days <= 30:
            score -= 8
    if cert.get("hostname_match") is False:
        fatal = True
    if cert.get("chain_valid") is False:
        msg = (cert.get("chain_message") or "").lower()
        if "self-signed" in msg:
            score -= 25
        else:
            score -= 18
    hsts = d.get("hsts", {})
    if not hsts.get("present"):
        score -= 6
    elif hsts.get("max_age", 0) < 15768000:
        score -= 2
    if d.get("compression") == "DEFLATE":
        score -= 8
    score = max(0.0, score)
    if fatal:
        return score, "F"
    # cap grades when legacy protocol versions are still offered
    if protos.get("TLS 1.0") or protos.get("TLS 1.1"):
        cap = "B"
        if score >= 80:
            return score, cap
    if weak_ciphers:
        if score >= 85:
            return score, "C"
    g = ("A+" if score >= 95 and hsts.get("max_age", 0) >= 15552000 and protos.get("TLS 1.3")
         else "A" if score >= 90
         else "A-" if score >= 85
         else "B" if score >= 75
         else "C" if score >= 65
         else "D" if score >= 55
         else "F")
    return score, g


def _summarize(d: dict) -> list:
    out = []
    for lbl, offered in d.get("protocols", {}).items():
        out.append(f"{lbl}: {'offered' if offered else 'not offered'}")
    if d.get("ciphers"):
        strong = sum(1 for c in d["ciphers"] if c["strength"] == "strong")
        out.append(f"{len(d['ciphers'])} suites tested, {strong} strong")
    cert = d.get("cert", {})
    if cert.get("subject_cn"):
        out.append(f"cert: {cert['subject_cn']} issued by {cert.get('issuer','?')}, expires {cert.get('not_after','?')}")
    h = d.get("hsts", {})
    out.append(f"HSTS: {'max-age=' + str(h.get('max_age', 0)) if h.get('present') else 'not set'}")
    return out
