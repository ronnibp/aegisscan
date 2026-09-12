"""Data models shared by every scanner, the engine and the reporting layer."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    PASS = "pass"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @property
    def score(self) -> float:
        """Default risk score (0-10) when a scanner does not supply one."""
        return _SEVERITY_SCORE[self]

    @property
    def label(self) -> str:
        return self.value.upper() if self != Severity.INFO else "INFO"


_SEVERITY_RANK = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
    Severity.PASS: 0,
}

_SEVERITY_SCORE = {
    Severity.CRITICAL: 9.5,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 3.0,
    Severity.INFO: 1.0,
    Severity.PASS: 0.0,
}


def severity_from_cvss(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO


MODULE_LABELS = {
    "github": "GitHub Integration",
    "secrets": "Secret Detection",
    "sast": "Static Analysis (SAST)",
    "sca": "Dependency Analysis (SCA)",
    "web": "Web Application (DAST)",
    "tls": "TLS / SSL Audit",
    "network": "Network / Ports",
    "ai": "AI Analysis (LLM)",
}


@dataclass
class Finding:
    """A single, actionable security finding."""

    scanner: str                      # secrets | sast | sca | web | tls | network
    category: str                     # human group, e.g. "Hardcoded Secrets"
    title: str
    severity: Severity
    target: str                       # repo path, URL or host the finding belongs to
    location: str = ""                # file:line, URL or host:port
    description: str = ""
    evidence: str = ""                # snippet / response proof (redacted)
    remediation: str = ""             # how to fix
    references: list = field(default_factory=list)
    mitre: list = field(default_factory=list)   # ATT&CK technique IDs, e.g. T1552.001
    cwe: str = ""                     # e.g. CWE-798
    score: float = -1.0               # explicit risk score; -1 => derive from severity
    tags: list = field(default_factory=list)
    id: str = ""

    def __post_init__(self) -> None:
        if isinstance(self.severity, str):
            try:
                self.severity = Severity(self.severity.lower())
            except ValueError:
                self.severity = Severity.INFO
        if not self.id:
            raw = "|".join([self.scanner, self.category, self.title, self.location, self.target])
            self.id = hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()[:12]

    @property
    def risk_score(self) -> float:
        return round(self.score, 1) if self.score >= 0 else self.severity.score

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["severity"] = self.severity.value
        d["score"] = self.risk_score
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d = dict(d)
        d.pop("score", None)
        return cls(**d)


@dataclass
class ModuleStatus:
    name: str
    status: str = "pending"           # pending | running | done | error | skipped
    detail: str = ""
    findings: int = 0
    duration: float = 0.0

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class ScanTarget:
    kind: str                         # repo | github | web | host
    value: str                        # path, owner/repo, URL or host
    options: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "value": self.value, "options": self.options}


@dataclass
class ScanResult:
    scan_id: str
    targets: list                     # list[ScanTarget.to_dict()]
    modules: list = field(default_factory=list)   # list[ModuleStatus]
    findings: list = field(default_factory=list)  # list[Finding]
    started: str = field(default_factory=utc_now)
    finished: str = ""
    status: str = "running"           # running | completed | failed | partial
    tls_grade: str = ""               # overall SSL-Labs-style grade when TLS scanned
    tls_details: dict = field(default_factory=dict)
    github_meta: dict = field(default_factory=dict)
    ai_summary: str = ""              # optional AI executive analysis (markdown)
    ai_meta: dict = field(default_factory=dict)   # {"provider","label","model"}
    mitre_tactics: list = field(default_factory=list)
    risk_score: float = 0.0
    label: str = ""

    # ------------------------------------------------------------------
    def add_finding(self, f: Finding) -> None:
        if not any(x.id == f.id for x in self.findings):
            self.findings.append(f)

    @property
    def counts(self) -> dict:
        c = {s.value: 0 for s in Severity}
        for f in self.findings:
            c[f.severity.value] += 1
        return c

    def compute_risk(self) -> float:
        """Overall risk score 0-10: weighted by the worst findings present."""
        if not self.findings:
            self.risk_score = 0.0
            return 0.0
        scores = sorted((f.risk_score for f in self.findings), reverse=True)
        # weight the top findings so one critical dominates many infos
        weights = [1.0, 0.5, 0.3, 0.2, 0.1, 0.05]
        total = sum(s * w for s, w in zip(scores, weights))
        max_total = 10 * sum(weights)
        self.risk_score = round(min(10.0, total / max_total * 10), 1)
        return self.risk_score

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "label": self.label,
            "targets": self.targets,
            "modules": [m.to_dict() for m in self.modules],
            "findings": [f.to_dict() for f in self.findings],
            "counts": self.counts,
            "started": self.started,
            "finished": self.finished,
            "status": self.status,
            "tls_grade": self.tls_grade,
            "tls_details": self.tls_details,
            "github_meta": self.github_meta,
            "ai_summary": self.ai_summary,
            "ai_meta": self.ai_meta,
            "mitre_tactics": self.mitre_tactics,
            "risk_score": self.risk_score,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @classmethod
    def from_dict(cls, d: dict) -> "ScanResult":
        r = cls(
            scan_id=d["scan_id"],
            targets=d.get("targets", []),
            label=d.get("label", ""),
            started=d.get("started", ""),
            finished=d.get("finished", ""),
            status=d.get("status", "completed"),
            tls_grade=d.get("tls_grade", ""),
            tls_details=d.get("tls_details", {}),
            github_meta=d.get("github_meta", {}),
            ai_summary=d.get("ai_summary", ""),
            ai_meta=d.get("ai_meta", {}),
            risk_score=d.get("risk_score", 0.0),
            mitre_tactics=d.get("mitre_tactics", []),
        )
        r.modules = [ModuleStatus(**m) for m in d.get("modules", [])]
        r.findings = [Finding.from_dict(f) for f in d.get("findings", [])]
        return r


@dataclass
class ScanConfig:
    """What the user asked to scan and with which modules."""

    targets: list = field(default_factory=list)   # list[ScanTarget]
    modules: Optional[list] = None                # None => auto per target kind
    max_file_size: int = 2 * 1024 * 1024          # 2 MB per-file cap for code scans
    timeout: int = 15                             # network timeout seconds
    ports: str = "top100"
    osv_online: bool = True                       # query OSV.dev for dependency vulns
    github_token: str = ""
    web_probe_injection: bool = True              # light, non-destructive injection probes
    web_max_pages: int = 25
    excludes: list = field(default_factory=list)  # path substrings to skip in code scans
    ai: bool = False                              # run AI analysis after the scan
    label: str = ""

    def to_dict(self) -> dict:
        return {
            "targets": [t.to_dict() if isinstance(t, ScanTarget) else t for t in self.targets],
            "modules": self.modules,
            "ports": self.ports,
            "osv_online": self.osv_online,
            "web_probe_injection": self.web_probe_injection,
            "web_max_pages": self.web_max_pages,
            "excludes": self.excludes,
            "ai": self.ai,
            "label": self.label,
        }
