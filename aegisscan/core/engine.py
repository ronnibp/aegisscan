"""Scan orchestration engine.

Runs the module pipeline for every configured target, tracks per-module
status, deduplicates findings, computes risk scores and persists results.
"""

from __future__ import annotations

import os
import shutil
import time
import uuid
from datetime import datetime, timezone

from . import mitre
from .models import (MODULE_LABELS, Finding, ModuleStatus, ScanConfig, ScanResult,
                     ScanTarget, Severity)

MODULES_FOR_TARGET = {
    "repo":   ["secrets", "sast", "sca"],
    "github": ["github", "secrets", "sast", "sca"],
    "web":    ["web", "tls"],
    "host":   ["network"],
    "tls":    ["tls"],
}


class ScanEngine:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.result = ScanResult(
            scan_id=uuid.uuid4().hex[:12],
            targets=[],
            label=config.label,
        )
        self._cleanup: list = []

    # ------------------------------------------------------------------
    def run(self, progress_cb=None) -> ScanResult:
        cfg = self.config
        status_cb = progress_cb or (lambda *a, **k: None)
        self.result.targets = [t.to_dict() if isinstance(t, ScanTarget) else t for t in cfg.targets]

        wanted = cfg.modules  # explicit module list or None => auto
        statuses: dict = {}

        try:
            for target in cfg.targets:
                if not isinstance(target, ScanTarget):
                    target = ScanTarget(**target)
                mods = wanted or MODULES_FOR_TARGET.get(target.kind, [])
                for mod in mods:
                    key = f"{mod}:{target.value}"
                    if key in statuses:
                        continue
                    st = ModuleStatus(name=mod, status="running")
                    statuses[key] = st
                    self.result.modules = list(statuses.values())
                    status_cb(self.result)
                    t0 = time.time()
                    try:
                        count = self._run_module(mod, target, st)
                        st.findings = count
                        st.status = "done"
                    except Exception as e:  # a failing module never kills the scan
                        st.status = "error"
                        st.detail = f"{type(e).__name__}: {e}"
                    st.duration = round(time.time() - t0, 2)
                    status_cb(self.result)

            self.result.status = ("completed"
                                  if not any(m.status == "error" for m in statuses.values())
                                  else "partial")
        except Exception as e:
            self.result.status = "failed"
            for st in statuses.values():
                if st.status == "running":
                    st.status = "error"
                    st.detail = str(e)
        finally:
            self._finalize()
            for path in self._cleanup:
                shutil.rmtree(path, ignore_errors=True)
        status_cb(self.result)
        return self.result

    # ------------------------------------------------------------------
    def _run_module(self, mod: str, target: ScanTarget, st: ModuleStatus) -> int:
        before = len(self.result.findings)
        cfg = self.config

        if mod == "secrets":
            from ..scanners import secrets as m
            for f in m.scan(target.value, cfg.max_file_size, excludes=cfg.excludes):
                self.result.add_finding(f)

        elif mod == "sast":
            from ..scanners import sast as m
            for f in m.scan(target.value, cfg.max_file_size, excludes=cfg.excludes):
                self.result.add_finding(f)

        elif mod == "sca":
            from ..scanners import sca as m
            for f in m.scan(target.value, osv_online=cfg.osv_online, timeout=cfg.timeout,
                            excludes=cfg.excludes):
                self.result.add_finding(f)

        elif mod == "web":
            from ..scanners import web as m
            for f in m.scan(target.value, max_pages=cfg.web_max_pages,
                            probe_injection=cfg.web_probe_injection,
                            timeout=cfg.timeout):
                self.result.add_finding(f)

        elif mod == "tls":
            from ..scanners import tls as m
            host = target.value
            findings, details = m.audit(host, timeout=cfg.timeout)
            self.result.tls_grade = details.get("grade", "")
            # merge tls details if several https targets: keep per-host map
            merged = dict(self.result.tls_details or {})
            merged[details.get("host", host)] = details
            self.result.tls_details = merged
            for f in findings:
                self.result.add_finding(f)

        elif mod == "network":
            from ..scanners import network as m
            host = target.value.replace("http://", "").replace("https://", "").split("/")[0]
            ports, findings = m.scan(host, ports=cfg.ports, timeout=min(2.0, cfg.timeout / 8))
            for f in findings:
                self.result.add_finding(f)

        elif mod == "github":
            from ..scanners import github as m
            token = cfg.github_token or os.environ.get("GITHUB_TOKEN", "")
            local, meta = m.download_repo(target.value, token=token)
            self._cleanup.append(local)
            self.result.github_meta = meta
            for f in m.posture_findings(meta, target.value):
                self.result.add_finding(f)
            st.detail = f"downloaded {meta.get('full_name', target.value)}"

        else:
            raise ValueError(f"Unknown module: {mod}")

        return len(self.result.findings) - before

    # ------------------------------------------------------------------
    def _finalize(self):
        # normalize MITRE mappings and compute aggregates
        for f in self.result.findings:
            f.mitre = mitre.normalize(f.mitre)
        matrix = mitre.aggregate(self.result.findings)
        self.result.mitre_tactics = list(matrix.keys())
        self.result.compute_risk()
        self.result.finished = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.result.findings.sort(
            key=lambda f: (-f.severity.rank, -f.risk_score, f.category))


def run_scan(config: ScanConfig, progress_cb=None) -> ScanResult:
    """Convenience entrypoint."""
    return ScanEngine(config).run(progress_cb)
