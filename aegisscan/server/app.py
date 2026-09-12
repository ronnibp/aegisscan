"""AegisScan dashboard server — zero-dependency HTTP API + static UI.

Serves the professional web dashboard and a JSON API:

  GET    /                          dashboard single-page app
  GET    /static/<file>             css/js assets
  GET    /api/meta                  version + module info
  GET    /api/dashboard             aggregate stats across all scans
  GET    /api/scans                 list scans
  POST   /api/scans                 start a scan  {"targets":[{"kind","value"}], ...}
  GET    /api/scans/<id>            scan status + findings (live during run)
  DELETE /api/scans/<id>            delete a scan
  GET    /api/scans/<id>/report?format=html|json|md|sarif
  GET    /api/mitre                 aggregated ATT&CK matrix over all scans
"""

from __future__ import annotations

import json
import os
import threading
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .. import __product__, __version__
from ..core import mitre
from ..core import ai as ai_mod
from ..core.engine import ScanEngine, MODULES_FOR_TARGET
from ..core.models import ScanConfig, ScanResult, ScanTarget
from ..core.report import render
from ..cli import data_dir, save_result

WEB_DIR = os.path.join(os.path.dirname(__file__), "..", "web")

# scan_id -> ScanResult (shared with worker threads)
REGISTRY: dict = {}
REGISTRY_LOCK = threading.Lock()


def load_saved_scans() -> dict:
    scans_dir = os.path.join(data_dir(), "scans")
    for fn in os.listdir(scans_dir):
        if not fn.endswith(".json"):
            continue
        sid = fn[:-5]
        if sid in REGISTRY:
            continue
        try:
            with open(os.path.join(scans_dir, fn), "r", encoding="utf-8") as fh:
                REGISTRY[sid] = ScanResult.from_dict(json.load(fh))
        except Exception:
            continue


def start_scan(payload: dict) -> str:
    targets = []
    for t in payload.get("targets", []):
        kind, value = t.get("kind", "").strip(), (t.get("value") or "").strip()
        if kind and value:
            targets.append(ScanTarget(kind, value))
    if not targets:
        raise ValueError("no targets given")
    cfg = ScanConfig(
        targets=targets,
        modules=payload.get("modules") or None,
        ports=payload.get("ports") or "top100",
        osv_online=payload.get("osv_online", True),
        web_max_pages=int(payload.get("web_max_pages") or 25),
        web_probe_injection=payload.get("web_probe_injection", True),
        excludes=payload.get("excludes") or [],
        ai=bool(payload.get("ai", False)),
        label=payload.get("label") or "",
        github_token=os.environ.get("GITHUB_TOKEN", ""),
    )
    engine = ScanEngine(cfg)
    result = engine.result
    with REGISTRY_LOCK:
        REGISTRY[result.scan_id] = result
    t = threading.Thread(target=engine.run, daemon=True)
    t.start()
    return result.scan_id


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # ---------------------------------------------------------------- utils
    def _send(self, code: int, body: bytes, ctype: str = "application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, code: int, obj):
        self._send(code, json.dumps(obj, default=str).encode("utf-8"))

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw or b"{}")

    def log_message(self, fmt, *args):  # quiet
        pass

    # ---------------------------------------------------------------- routing
    def do_GET(self):
        try:
            parsed = urllib.parse.urlparse(self.path)
            path, query = parsed.path, urllib.parse.parse_qs(parsed.query)

            if path.startswith("/api/"):
                load_saved_scans()
                if path == "/api/meta":
                    return self._json(200, {"product": __product__, "version": __version__,
                                            "modules": sorted({m for mods in MODULES_FOR_TARGET.values() for m in mods} | {"ai"})})
                if path == "/api/settings":
                    return self._json(200, self.ai_settings())
                if path == "/api/dashboard":
                    return self._json(200, self.dashboard())
                if path == "/api/scans":
                    return self._json(200, [self.scan_summary(r) for r in self.sorted_results()])
                if path == "/api/mitre":
                    all_findings = [f for r in REGISTRY.values() for f in r.findings]
                    return self._json(200, {"matrix": mitre.aggregate(all_findings),
                                            "tactics": [{"id": i, "name": n} for i, n in mitre.TACTICS],
                                            "techniques": mitre.TECHNIQUES})
                parts = path.strip("/").split("/")
                if len(parts) == 3 and parts[1] == "scans":
                    sid = parts[2]
                    r = REGISTRY.get(sid)
                    if not r:
                        return self._json(404, {"error": "scan not found"})
                    return self._json(200, r.to_dict())
                if len(parts) == 4 and parts[1] == "scans" and parts[3] == "report":
                    sid = parts[2]
                    r = REGISTRY.get(sid)
                    if not r:
                        return self._json(404, {"error": "scan not found"})
                    fmt = (query.get("format") or ["html"])[0]
                    if r.status == "running":
                        return self._json(409, {"error": "scan still running"})
                    content = render(r, fmt)
                    if fmt == "html":
                        ctype = "text/html; charset=utf-8"
                        # inline frame-friendly headers
                        self.send_response(200)
                        self.send_header("Content-Type", ctype)
                        self.send_header("Content-Length", str(len(content.encode())))
                        self.send_header("Content-Security-Policy", "frame-ancestors 'self'")
                        self.end_headers()
                        self.wfile.write(content.encode("utf-8"))
                        return
                    if fmt == "json":
                        return self._json(200, r.to_dict())
                    return self._send(200, content.encode("utf-8"),
                                      "text/markdown; charset=utf-8" if fmt == "md" else "application/sarif+json")
                return self._json(404, {"error": "not found"})

            if path == "/":
                return self._file("index.html", "text/html; charset=utf-8")
            if path.startswith("/static/"):
                rel = path[len("/static/"):]
                # normalize and refuse traversal outside the web dir
                rel = os.path.normpath(urllib.parse.unquote(rel)).lstrip("\\/").replace("\\", "/")
                if rel.startswith("../") or "/../" in rel or rel == "..":
                    return self._json(403, {"error": "forbidden"})
                fp_rel = os.path.join("static", rel)
                ext = rel.rsplit(".", 1)[-1].lower()
                ctype = {("css"): "text/css", ("js"): "application/javascript",
                         ("svg"): "image/svg+xml", ("png"): "image/png",
                         ("html"): "text/html; charset=utf-8"}.get(ext, "application/octet-stream")
                return self._file(fp_rel, ctype)
            return self._json(404, {"error": "not found"})
        except Exception as e:
            traceback.print_exc()
            return self._json(500, {"error": str(e)})

    def do_POST(self):
        try:
            path = urllib.parse.urlparse(self.path).path
            load_saved_scans()
            if path == "/api/scans":
                payload = self._body()
                sid = start_scan(payload)
                return self._json(200, {"scan_id": sid})
            if path == "/api/settings":
                payload = self._body()
                cfg = ai_mod.save_config(provider=payload.get("provider") or "",
                                         api_key=payload.get("api_key") or "",
                                         model=payload.get("model") or "",
                                         base_url=payload.get("base_url") or "")
                return self._json(200, self.ai_settings(cfg))
            if path == "/api/ai/test":
                try:
                    msg = ai_mod.test_connection()
                    return self._json(200, {"ok": True, "message": msg})
                except ai_mod.AIError as e:
                    return self._json(400, {"ok": False, "error": str(e)})
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[1] == "scans" and parts[3] == "ai":
                r = REGISTRY.get(parts[2])
                if not r:
                    return self._json(404, {"error": "scan not found"})
                if r.status == "running":
                    return self._json(409, {"error": "scan still running"})
                if not len(r.findings):
                    return self._json(400, {"error": "no findings to analyze"})
                try:
                    out = ai_mod.analyze_result(r.to_dict())
                except ai_mod.AIError as e:
                    return self._json(400, {"error": str(e)})
                r.ai_summary = out["summary"]
                r.ai_meta = {"provider": out["provider"], "label": out["label"],
                             "model": out["model"]}
                save_result(r)
                return self._json(200, {"ai_summary": r.ai_summary, "ai_meta": r.ai_meta})
            return self._json(404, {"error": "not found"})
        except ValueError as e:
            return self._json(400, {"error": str(e)})
        except Exception as e:
            traceback.print_exc()
            return self._json(500, {"error": str(e)})

    def do_DELETE(self):
        try:
            path = urllib.parse.urlparse(self.path).path
            parts = path.strip("/").split("/")
            if len(parts) == 3 and parts[1] == "scans":
                sid = parts[2]
                r = REGISTRY.pop(sid, None)
                fp = os.path.join(data_dir(), "scans", f"{sid}.json")
                if os.path.exists(fp):
                    os.unlink(fp)
                return self._json(200, {"deleted": bool(r)})
            return self._json(404, {"error": "not found"})
        except Exception as e:
            return self._json(500, {"error": str(e)})

    # ---------------------------------------------------------------- helpers
    def _file(self, name: str, ctype: str):
        fp = os.path.join(WEB_DIR, name)
        if not os.path.exists(fp):
            return self._json(404, {"error": f"missing asset {name}"})
        with open(fp, "rb") as fh:
            body = fh.read()
        self._send(200, body, ctype)

    @staticmethod
    def sorted_results():
        return sorted(REGISTRY.values(),
                      key=lambda r: r.started or "", reverse=True)

    @staticmethod
    def scan_summary(r: ScanResult) -> dict:
        return {"scan_id": r.scan_id, "label": r.label,
                "targets": r.targets, "status": r.status,
                "counts": r.counts, "risk_score": r.risk_score,
                "started": r.started, "finished": r.finished,
                "tls_grade": r.tls_grade, "modules": [m.to_dict() for m in r.modules],
                "total": len(r.findings)}

    @staticmethod
    def ai_settings(cfg: dict | None = None) -> dict:
        cfg = cfg or ai_mod.load_config()
        resolved = ""
        try:
            eff = ai_mod.resolve_ai(cfg)
            resolved = f"{eff['label']} · {eff['model']}"
        except ai_mod.AIError:
            pass
        return {
            "provider": cfg.get("provider", ""),
            "model": cfg.get("model", ""),
            "base_url": cfg.get("base_url", ""),
            "key_masked": ai_mod.mask_key(cfg.get("api_key", "")),
            "key_set": bool(cfg.get("api_key")),
            "resolved": resolved,
            "providers": [{"id": pid, "label": m["label"], "default_model": m["default_model"],
                           "key_url": m["key_url"], "api": m["api"]}
                          for pid, m in ai_mod.PROVIDERS.items()],
        }

    @staticmethod
    def dashboard() -> dict:
        results = list(REGISTRY.values())
        agg = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        categories: dict = {}
        for r in results:
            c = r.counts
            for k in agg:
                agg[k] += c.get(k, 0)
            for f in r.findings:
                categories.setdefault(f.category, [0, f.severity.value])
                categories[f.category][0] += 1
        matrix = mitre.aggregate([f for r in results for f in r.findings])
        return {
            "scans": len(results),
            "findings_total": sum(agg.values()),
            "counts": agg,
            "categories": [{"name": k, "count": v[0], "severity": v[1]}
                           for k, v in sorted(categories.items(), key=lambda kv: -kv[1][0])[:8]],
            "mitre": {"matrix": matrix,
                      "tactics": [{"id": i, "name": n} for i, n in mitre.TACTICS],
                      "techniques": mitre.TECHNIQUES},
            "recent": [Handler.scan_summary(r) for r in Handler.sorted_results()[:6]],
        }


def serve(port: int = 8899):
    load_saved_scans()
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
