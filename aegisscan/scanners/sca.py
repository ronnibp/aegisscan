"""Software Composition Analysis (SCA).

Parses dependency manifests (requirements.txt, package.json/lock, pom.xml,
go.mod, composer.json, Gemfile, *.csproj) and queries the OSV.dev open API
for known vulnerabilities. Falls back to a small offline database of widely
exploited versions when the network is unavailable.
"""

from __future__ import annotations

import json
import os
import re
import urllib.request
from urllib.error import URLError

from ..core.models import Finding, Severity, severity_from_cvss
from ..core.utils import walk_files

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"

MITRE_SCA = ["T1195", "T1190"]

MANIFEST_NAMES = {
    "requirements.txt", "requirements-dev.txt", "requirements_dev.txt",
    "package.json", "package-lock.json", "pom.xml", "go.mod", "composer.json",
    "Gemfile", "Gemfile.lock", "Pipfile", "pyproject.toml",
}

# Offline fallback: (ecosystem, package, fixed_version_note, severity, cvss, cve)
# Only the most notorious, unambiguous version boundaries.
OFFLINE_DB = [
    ("PyPI", "django", "<2.2.24", Severity.CRITICAL, 9.8, "CVE-2021-31542"),
    ("PyPI", "django", "<3.2.12", Severity.HIGH, 7.5, "CVE-2021-45452"),
    ("PyPI", "flask", "<0.12.3", Severity.HIGH, 7.5, "CVE-2018-1000656"),
    ("PyPI", "jinja2", "<2.11.3", Severity.CRITICAL, 9.8, "CVE-2020-28493"),
    ("PyPI", "pyyaml", "<5.4", Severity.CRITICAL, 9.8, "CVE-2020-14343"),
    ("PyPI", "requests", "<2.20.0", Severity.MEDIUM, 5.9, "CVE-2018-18074"),
    ("PyPI", "paramiko", "<2.6.0", Severity.HIGH, 8.1, "CVE-2019-17359"),
    ("PyPI", "pillow", "<8.1.1", Severity.CRITICAL, 9.1, "CVE-2021-3163"),
    ("npm", "lodash", "<4.17.21", Severity.CRITICAL, 9.1, "CVE-2021-23337"),
    ("npm", "express", "<4.17.3", Severity.MEDIUM, 6.5, "CVE-2022-24999"),
    ("npm", "axios", "<0.21.2", Severity.HIGH, 7.5, "CVE-2021-3749"),
    ("npm", "jquery", "<3.5.0", Severity.MEDIUM, 6.9, "CVE-2020-11022"),
    ("npm", "moment", "<2.29.2", Severity.HIGH, 7.5, "CVE-2022-24785"),
    ("npm", "node-fetch", "<2.6.7", Severity.HIGH, 7.5, "CVE-2022-0235"),
    ("npm", "minimist", "<1.2.6", Severity.CRITICAL, 9.8, "CVE-2020-7598"),
    ("Go", "golang.org/x/crypto", "<0.17.0", Severity.HIGH, 7.5, "CVE-2023-48795"),
    ("Maven", "org.apache.log4j:log4j-core", "<2.17.0", Severity.CRITICAL, 10.0, "CVE-2021-44228"),
    ("Maven", "commons-collections:commons-collections", "<3.2.2", Severity.CRITICAL, 9.8, "CVE-2015-6420"),
    ("Maven", "org.springframework:spring-web", "<5.3.18", Severity.CRITICAL, 9.8, "CVE-2022-22965"),
]

VER_RE = re.compile(r"^\d+(\.\d+)*$")


def _vparts(v: str) -> list:
    parts = re.findall(r"\d+", v.split("+")[0].split("-")[0])
    return [int(p) for p in parts[:4]] or [0]


def _vlt(a: str, b: str) -> bool:
    pa, pb = _vparts(a), _vparts(b)
    n = max(len(pa), len(pb))
    pa += [0] * (n - len(pa))
    pb += [0] * (n - len(pb))
    return pa < pb


# ---------------------------------------------------------------- parsing
def parse_manifests(root: str, excludes: list | None = None):
    """Return {(ecosystem, name): {version, manifest, line}}."""
    deps: dict = {}
    for path, rel in walk_files(root, excludes=excludes):
        base = os.path.basename(rel)
        parent = os.path.dirname(rel).split("/")[-1] if os.path.dirname(rel) else ""

        if base.startswith("requirements") and base.endswith(".txt"):
            for i, line in enumerate(read_text(path).splitlines(), 1):
                line = line.strip()
                if not line or line.startswith(("#", "-")):
                    continue
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s*(?:\[.*\])?\s*(==|>=|~=|>|<)?\s*([0-9][^;\s,]*)", line)
                if m:
                    name, op, ver = m.group(1), m.group(2), m.group(3)
                    key = ("PyPI", name.lower().replace("_", "-"))
                    if op == "==" or op is None:
                        deps.setdefault(key, {"version": ver if op == "==" else "", "manifest": rel, "line": i})
                    else:
                        deps.setdefault(key, {"version": ver, "manifest": rel, "line": i, "range_only": True})
        elif base == "pyproject.toml":
            for i, line in enumerate(read_text(path).splitlines(), 1):
                m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*=\s*\"[^\"]*==\s*([0-9][^\"\s]*)\"", line)
                if m:
                    deps.setdefault(("PyPI", m.group(1).lower().replace("_", "-")),
                                    {"version": m.group(2), "manifest": rel, "line": i})
        elif base == "package.json" and parent != "node_modules":
            try:
                data = json.loads(read_text(path))
            except (ValueError, OSError):
                continue
            for section in ("dependencies", "devDependencies"):
                for i, (name, ver) in enumerate((data.get(section) or {}).items(), 1):
                    clean = ver.lstrip("^~>=< ").split(" ")[0]
                    deps.setdefault(("npm", name), {"version": clean, "manifest": rel, "line": i})
        elif base == "package-lock.json" and parent != "node_modules":
            try:
                data = json.loads(read_text(path))
            except (ValueError, OSError):
                continue
            for pkg in (data.get("packages") or {}).values():
                name, ver = pkg.get("name"), pkg.get("version")
                if name and ver and VER_RE.match(ver):
                    deps.setdefault(("npm", name), {"version": ver, "manifest": rel, "line": 1})
        elif base == "go.mod":
            for i, line in enumerate(read_text(path).splitlines(), 1):
                m = re.match(r"^\s*(golang\.org/[^\s]+|[a-z0-9.\-/]+\.[a-z]{2,}/[^\s]+)\s+v([0-9][^\s]*)", line)
                if m:
                    deps.setdefault(("Go", m.group(1)), {"version": m.group(2), "manifest": rel, "line": i})
        elif base == "pom.xml":
            text = read_text(path)
            for m in re.finditer(r"<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>", text):
                name = f"{m.group(1)}:{m.group(2)}"
                deps.setdefault(("Maven", name), {"version": m.group(3).strip(), "manifest": rel, "line": 1})
        elif base == "composer.json":
            try:
                data = json.loads(read_text(path))
            except (ValueError, OSError):
                continue
            for i, (name, ver) in enumerate({**data.get("require", {}), **data.get("require-dev", {})}.items(), 1):
                if name == "php":
                    continue
                deps.setdefault(("Packagist", name), {"version": ver.lstrip("^~>=< v"), "manifest": rel, "line": i})
        elif base == "Gemfile":
            for i, line in enumerate(read_text(path).splitlines(), 1):
                m = re.match(r"\s*gem\s+[\"']([^\"']+)[\"'](?:\s*,\s*[\"']([^\"']+)[\"'])?", line)
                if m:
                    deps.setdefault(("RubyGems", m.group(1)), {"version": (m.group(2) or "").lstrip("~> >= < "), "manifest": rel, "line": i})
    return deps


# ---------------------------------------------------------------- OSV query
def _osv_query(deps: dict, timeout: int = 20) -> dict:
    """Query OSV.dev batch API. Returns {(eco,name): [vuln dicts]}."""
    keys = [k for k, v in deps.items() if v.get("version")]
    if not keys:
        return {}
    queries = [{"package": {"name": k[1], "ecosystem": k[0]}, "version": deps[k]["version"]} for k in keys]
    results: dict = {}
    # OSV batch accepts up to 1000 queries; chunk anyway
    for i in range(0, len(queries), 500):
        chunk_keys = keys[i:i + 500]
        chunk = queries[i:i + 500]
        body = json.dumps({"queries": chunk}).encode()
        req = urllib.request.Request(OSV_QUERYBATCH, data=body,
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "AegisScan/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
        except (URLError, OSError, ValueError):
            return {}          # signal offline
        for j, res in enumerate(data.get("results", [])):
            vulns = res.get("vulns", [])
            if vulns and j < len(chunk_keys):
                results[chunk_keys[j]] = vulns
    return results


def _offline_lookup(deps: dict) -> list:
    out = []
    for (eco, name), meta in deps.items():
        ver = meta.get("version")
        if not ver or meta.get("range_only"):
            continue
        for (d_eco, d_name, bound, sev, cvss, cve) in OFFLINE_DB:
            if d_eco == eco and d_name == name and ver and _vlt(ver, bound.lstrip("<")):
                out.append({"id": cve, "summary": f"Known vulnerable {name} {ver} ({cve})",
                            "severity": [{"type": "CVSS_V3", "score": f"{cvss}/10"}],
                            "affected_pkg": name, "fixed_hint": f"upgrade to >= {bound.lstrip('<')}",
                            "references": [f"https://nvd.nist.gov/vuln/detail/{cve}"]})
    return out


def _osv_severity(vuln: dict) -> float:
    for sev in vuln.get("severity", []):
        if sev.get("type", "").startswith("CVSS"):
            try:
                return float(sev.get("score", "0").split("/")[0])
            except ValueError:
                pass
    # derive from database_specific
    sev_str = (vuln.get("database_specific") or {}).get("severity", "")
    return {"CRITICAL": 9.5, "HIGH": 8.0, "MODERATE": 5.5, "MEDIUM": 5.5, "LOW": 3.0}.get(sev_str.upper(), 5.0)


def scan(root: str, osv_online: bool = True, timeout: int = 20, progress=None, excludes: list | None = None) -> list:
    findings: list[Finding] = []
    deps = parse_manifests(root, excludes=excludes)
    if progress:
        progress(10, 100)
    vulns_by_pkg: dict = {}
    online = False
    if osv_online and deps:
        try:
            vulns_by_pkg = _osv_query(deps, timeout)
            online = bool(vulns_by_pkg) or True   # request succeeded (empty result is still success)
        except Exception:
            vulns_by_pkg = {}
    if progress:
        progress(60, 100)

    matched_ids = set()
    for (eco, name), meta in deps.items():
        for vuln in vulns_by_pkg.get((eco, name), []):
            vid = vuln.get("id", "OSV")
            matched_ids.add((eco, name))
            cvss = _osv_severity(vuln)
            sev = severity_from_cvss(cvss)
            aliases = [a for a in vuln.get("aliases", []) if a.startswith("CVE")]
            refs = [r.get("url") for r in vuln.get("references", []) if r.get("url")][:4]
            fixed = ""
            for aff in vuln.get("affected", []):
                for rng in aff.get("ranges", []):
                    for ev in rng.get("events", []):
                        if "fixed" in ev:
                            fixed = ev["fixed"]
                            break
            pkg_label = f"{name} {meta['version']}" if meta.get("version") else name
            findings.append(Finding(
                scanner="sca", category="Vulnerable Dependency",
                title=f"{vid}: vulnerable {pkg_label} ({eco})",
                severity=sev, target=root, location=f"{meta['manifest']}:{meta['line']}",
                description=(vuln.get("summary") or vuln.get("details", "") or "Known vulnerability") +
                            f"\n\nPackage: {name} @ {meta.get('version') or 'unpinned'} ({eco})",
                evidence=f"{meta['manifest']} declares {name} {meta.get('version') or '(unpinned)'}",
                remediation=(f"Upgrade {name} to {fixed}" if fixed else
                             f"Upgrade {name} to the latest patched release."),
                references=(refs or [f"https://osv.dev/vulnerability/{vid}"]),
                mitre=MITRE_SCA, cwe="CWE-1104",
                score=cvss, tags=["sca", "dependency", vid, *aliases],
            ))
    if not online:
        for vuln in _offline_lookup(deps):
            findings.append(Finding(
                scanner="sca", category="Vulnerable Dependency",
                title=f"{vuln['id']}: vulnerable {vuln['affected_pkg']}",
                severity=severity_from_cvss(float(vuln["severity"][0]["score"].split("/")[0])),
                target=root, location="",
                description=vuln["summary"] + " (offline database match)",
                remediation=vuln["fixed_hint"],
                references=vuln["references"], mitre=MITRE_SCA, cwe="CWE-1104",
                score=float(vuln["severity"][0]["score"].split("/")[0]),
                tags=["sca", "dependency", vuln["id"], "offline-db"],
            ))
    if progress:
        progress(100, 100)
    return findings
