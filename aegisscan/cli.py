"""AegisScan command-line interface.

Kali-style subcommands over a cross-platform, dependency-free engine:

  aegisscan scan    unified scanner (repo / GitHub / web / host targets)
  aegisscan secrets TruffleHog-style secret detection
  aegisscan sast    static code analysis (Semgrep-style)
  aegisscan sca     dependency vulnerability scan (safety/npm-audit-style, OSV.dev)
  aegisscan web     web application DAST (Nikto/ZAP-style)
  aegisscan tls     SSL-Labs-style TLS audit
  aegisscan ports   TCP port scanner with banner grabbing (nmap-style)
  aegisscan report  re-render a report from a saved scan
  aegisscan ui      launch the professional web dashboard
  aegisscan demo    scan the bundled vulnerable demo application
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import urllib.request
import uuid
import webbrowser
from datetime import datetime, timezone

from . import __product__, __version__
from .core import ai as ai_mod
from .core.engine import ScanConfig, ScanEngine, ScanTarget
from .core.models import ScanResult, Severity
from .core.report import render
from .core.utils import Ansi

UPSTREAM_REPO = "ronnibp/aegisscan"
UPSTREAM_RAW = f"https://raw.githubusercontent.com/{UPSTREAM_REPO}/main/pyproject.toml"

DATA_DIR_NAME = "aegisscan-data"


def data_dir() -> str:
    base = os.environ.get("AEGISSCAN_DATA") or os.path.join(os.getcwd(), DATA_DIR_NAME)
    d = os.path.join(base, "scans")
    os.makedirs(d, exist_ok=True)
    return base


def save_result(result) -> str:
    base = data_dir()
    jpath = os.path.join(base, "scans", f"{result.scan_id}.json")
    with open(jpath, "w", encoding="utf-8") as fh:
        fh.write(result.to_json())
    return jpath


def _sev_counts_line(result) -> str:
    c = result.counts
    parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        if c[sev]:
            parts.append(Ansi.severity(sev, f"{c[sev]} {sev}"))
    return ", ".join(parts) or "none"


def _print_findings(result, verbose=False, limit=0):
    rows = sorted(result.findings, key=lambda f: (-f.severity.rank, -f.risk_score))
    if limit:
        rows = rows[:limit]
    if not rows:
        print(Ansi.green("\n✔ No findings — target looks clean for the executed checks."))
        return
    print()
    for f in rows:
        loc = f"  {Ansi.dim(f.location or f.target)}"
        print(f" {Ansi.severity(f.severity.value, f.severity.label):9} "
              f"[{f.risk_score:>4.1f}] {Ansi.bold(f.title)}{loc}")
        if verbose:
            if f.description:
                print(Ansi.gray(f"        {f.description[:220]}"))
            if f.evidence:
                print(Ansi.gray(f"        evidence: {f.evidence[:120]}"))
            if f.remediation:
                print(f"        {Ansi.cyan('fix:')} {f.remediation[:180]}")
            if f.mitre:
                print(Ansi.gray(f"        MITRE: {', '.join(f.mitre)}"))
    print()


def _progress_printer(module_label="scan"):
    state = {"last": 0}

    def cb(done, total):
        pct = int(done * 100 / max(1, total))
        if pct != state["last"] and pct % 5 == 0:
            state["last"] = pct
            sys.stderr.write(f"\r  {Ansi.dim(module_label)} [{pct:3d}%] {'█' * (pct // 5)}{'·' * (20 - pct // 5)}")
            sys.stderr.flush()
    return cb


def _print_ai_summary(result):
    if not result.ai_summary:
        return
    meta = result.ai_meta or {}
    print(f"\n{Ansi.bold('AI executive analysis')} "
          f"{Ansi.dim('— ' + meta.get('label', '') + ' · ' + meta.get('model', '') + ' (advisory)')}\n")
    for ln in result.ai_summary.splitlines():
        print(Ansi.gray("  " + ln))


def _finish_and_report(result, out: str, formats, fail_on: str) -> int:
    if isinstance(formats, str):
        formats = [f.strip().lower() for f in formats.split(",") if f.strip()]
    jpath = save_result(result)
    for fmt in formats:
        content = render(result, fmt)
        ext = {"html": "html", "json": "json", "md": "md", "sarif": "sarif"}[fmt]
        fpath = os.path.join(out, f"report-{result.scan_id}.{ext}")
        _write_report(fpath, content)
        print(Ansi.cyan(f"  report ({fmt}): {fpath}"))
        # stable alias so CI pipelines can reference a fixed filename
        latest = os.path.join(out, f"report-latest.{ext}")
        _write_report(latest, content)
    print(Ansi.cyan(f"  results json: {jpath}"))
    print(f"\n  {Ansi.bold('Findings:')} {_sev_counts_line(result)}  "
          f"{Ansi.dim(f'(risk {result.risk_score:.1f}/10)')}")
    if result.tls_grade:
        print(f"  {Ansi.bold('TLS grade:')} {Ansi.bold(result.tls_grade)}")
    threshold = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(fail_on, 0)
    bad = [f for f in result.findings if f.severity.rank >= threshold and f.severity != Severity.INFO]
    return 1 if bad else 0


def _write_report(fpath: str, content) -> None:
    mode = "wb" if isinstance(content, bytes) else "w"
    kwargs = {} if mode == "wb" else {"encoding": "utf-8"}
    with open(fpath, mode, **kwargs) as fh:
        fh.write(content)


def _build_config(args) -> ScanConfig:
    cfg = ScanConfig()
    cfg.targets = []
    if getattr(args, "repo", None):
        cfg.targets.append(ScanTarget("repo", args.repo))
    if getattr(args, "github", None):
        cfg.targets.append(ScanTarget("github", args.github))
    if getattr(args, "url", None):
        cfg.targets.append(ScanTarget("web", args.url))
    if getattr(args, "host", None):
        cfg.targets.append(ScanTarget("host", args.host))
    if getattr(args, "https", None):
        cfg.targets.append(ScanTarget("tls", args.https))
    if not cfg.targets:
        return cfg
    cfg.ports = getattr(args, "ports", "top100") or "top100"
    cfg.osv_online = not getattr(args, "offline", False)
    cfg.label = getattr(args, "label", "") or ""
    cfg.github_token = os.environ.get("GITHUB_TOKEN", "")
    cfg.web_max_pages = getattr(args, "max_pages", 25) or 25
    cfg.web_probe_injection = not getattr(args, "no_injection", False)
    cfg.excludes = list(getattr(args, "exclude", None) or [])
    cfg.ai = bool(getattr(args, "ai", False))
    return cfg


# --------------------------------------------------------------------------- commands
def cmd_scan(args) -> int:
    cfg = _build_config(args)
    if not cfg.targets:
        print(Ansi.red("No target given. Use --repo, --github, --url, --host or --https."))
        return 2
    if cfg.ai:
        try:
            eff = ai_mod.resolve_ai()
            print(Ansi.magenta(f"  AI analysis enabled: {eff['label']} · {eff['model']}"))
        except ai_mod.AIError as e:
            print(Ansi.yellow(f"  AI disabled: {e}"))
            cfg.ai = False
    engine = ScanEngine(cfg)
    result = engine.run()
    print(f"\n{Ansi.bold(__product__ + ' scan')} {Ansi.dim('— ' + ', '.join(t.get('value', '') for t in result.targets))}")
    for m in result.modules:
        icon = {"done": Ansi.green("✔"), "error": Ansi.red("✖"), "running": Ansi.yellow("…"),
                "skipped": Ansi.dim("-")}.get(m.status, "·")
        print(f"  {icon} {Ansi.bold(m.name):28} {m.status:8} {Ansi.dim(f'{m.findings} findings, {m.duration:.1f}s')}"
              + (Ansi.red(f"  {m.detail[:80]}") if m.detail and m.status == "error" else ""))
    if result.tls_grade:
        print(f"\n  TLS grade: {Ansi.bold(result.tls_grade)}")
    _print_findings(result, verbose=args.verbose, limit=args.top)
    _print_ai_summary(result)
    return _finish_and_report(result, args.out, args.formats, args.fail_on)


def _single_module(module: str, label: str):
    def runner(args) -> int:
        target_kind = {"secrets": "repo", "sast": "repo", "sca": "repo"}.get(module)
        value = getattr(args, "repo", None) if target_kind else getattr(args, "url", None)
        if not value:
            flag = "--repo" if target_kind else "--url"
            print(Ansi.red(f"{label} requires {flag} <target>"))
            return 2
        cfg = ScanConfig(targets=[ScanTarget(target_kind or "web", value)], label=label)
        cfg.osv_online = not getattr(args, "offline", False)
        engine = ScanEngine(cfg)
        result = engine.run()
        print(f"\n{Ansi.bold(label)} {Ansi.dim('— ' + value)}")
        _print_findings(result, verbose=args.verbose)
        return _finish_and_report(result, args.out, args.formats, args.fail_on)
    return runner


def cmd_tls(args) -> int:
    cfg = ScanConfig(targets=[ScanTarget("tls", args.https)], label="TLS audit")
    engine = ScanEngine(cfg)
    result = engine.run()
    print(f"\n{Ansi.bold('TLS / SSL audit')} {Ansi.dim('— ' + args.https)}")
    d = next(iter(result.tls_details.values()), None)
    if d:
        print(f"  grade: {Ansi.bold(Ansi.green(d.get('grade', '-')))}  ({d.get('score', 0):.0f}/100)")
        for lbl, offered in d.get("protocols", {}).items():
            mark = Ansi.green("✔ offered") if offered else Ansi.dim("✖ not offered")
            print(f"    {lbl:8} {mark}")
        cert = d.get("cert", {})
        if cert.get("subject_cn"):
            print(f"  cert: {cert['subject_cn']} ({cert.get('issuer', '?')}), expires {cert.get('not_after', '?')}"
                  + (f", {cert['days_left']} days left" if cert.get("days_left") is not None else ""))
    _print_findings(result, verbose=args.verbose)
    return _finish_and_report(result, args.out, args.formats, args.fail_on)


def cmd_ports(args) -> int:
    from .scanners import network
    host = args.host
    print(f"\n{Ansi.bold('TCP port scan')} {Ansi.dim('— ' + host)}")
    cb = _progress_printer("ports")
    open_ports, findings = network.scan(host, ports=args.ports, progress=cb)
    sys.stderr.write("\n")
    if not open_ports:
        print(Ansi.green("  no open ports found in the scanned range"))
    for o in open_ports:
        banner = Ansi.gray(f"  {o['banner'][:60]}") if o["banner"] else ""
        print(f"  {Ansi.green('OPEN'):8} {o['port']:>5}/tcp {Ansi.bold(o['service']):24}{banner}")
    result = ScanResult(scan_id=f"ports-{uuid.uuid4().hex[:8]}",
                        targets=[{"kind": "host", "value": host}])
    for f in findings:
        result.add_finding(f)
    result.compute_risk()
    result.status = "completed"
    result.finished = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return _finish_and_report(result, args.out, args.formats, args.fail_on)


def cmd_report(args) -> int:
    path = args.input
    with open(path, "r", encoding="utf-8") as fh:
        result = ScanResult.from_dict(json.load(fh))
    content = render(result, args.format)
    ext = {"html": "html", "json": "json", "md": "md", "sarif": "sarif"}[args.format]
    out_path = args.output or os.path.join(args.out, f"report-{result.scan_id}.{ext}")
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(content)
    print(Ansi.green(f"  wrote {out_path}"))
    return 0


def cmd_ui(args) -> int:
    from .server.app import serve
    url = f"http://127.0.0.1:{args.port}"
    print(f"\n{Ansi.bold(__product__)} dashboard {Ansi.dim('v' + __version__)}")
    print(Ansi.cyan(f"  → {url}"))
    print(Ansi.dim("  Ctrl+C to stop"))
    if not args.no_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    serve(args.port)
    return 0


def cmd_demo(args) -> int:
    example = os.path.join(os.path.dirname(__file__), "..", "examples", "vulnerable-app")
    example = os.path.abspath(example)
    if not os.path.isdir(example):
        print(Ansi.red(f"Demo app not found at {example}"))
        return 2
    print(f"{Ansi.bold('Running demo scan')} {Ansi.dim('— bundled intentionally vulnerable application')}")
    cfg = ScanConfig(targets=[ScanTarget("repo", example)], label="Demo vulnerable app")
    cfg.ai = bool(getattr(args, "ai", False))
    if cfg.ai:
        try:
            eff = ai_mod.resolve_ai()
            print(Ansi.magenta(f"  AI analysis enabled: {eff['label']} · {eff['model']}"))
        except ai_mod.AIError as e:
            print(Ansi.yellow(f"  AI disabled: {e}"))
            cfg.ai = False
    engine = ScanEngine(cfg)
    result = engine.run()
    _print_findings(result, verbose=True, limit=args.top)
    _print_ai_summary(result)
    return _finish_and_report(result, args.out, args.formats, args.fail_on)


# --------------------------------------------------------------------------- AI commands
def cmd_ai(args) -> int:
    if args.ai_cmd == "setup":
        provider = args.provider or ""
        if not provider:
            print(Ansi.bold("Supported AI providers:") + "\n" + Ansi.gray(ai_mod.provider_help()))
            print(f"\nRun: {Ansi.cyan('aegisscan ai setup --provider <id> --api-key <KEY> [--model M] [--base-url URL]')}")
            return 0
        cfg = ai_mod.save_config(provider=provider, api_key=args.api_key or "",
                                 model=args.model or "", base_url=args.base_url or "")
        print(Ansi.green(f"✔ AI provider saved: {ai_mod.PROVIDERS[cfg['provider']]['label']}"))
        print(Ansi.gray(f"  model: {cfg['model'] or ai_mod.PROVIDERS[cfg['provider']]['default_model'] or '(must set)'}"))
        print(Ansi.gray(f"  key:   {ai_mod.mask_key(cfg['api_key']) or '(from environment)'}  "
                        f"stored in {ai_mod.config_path()}"))
        print(Ansi.dim("  test it: aegisscan ai test"))
        return 0

    if args.ai_cmd == "show":
        cfg = ai_mod.load_config()
        if not cfg.get("provider"):
            print("No AI provider configured. Run 'aegisscan ai setup' (no args) to list providers.")
            return 0
        print(f"provider: {Ansi.bold(cfg['provider'])} ({ai_mod.PROVIDERS.get(cfg['provider'], {}).get('label', '?')})")
        print(f"model:    {cfg['model'] or ai_mod.PROVIDERS[cfg['provider']]['default_model']}")
        env_key = ""
        for env_name in ai_mod.PROVIDERS[cfg["provider"]]["env"]:
            if os.environ.get(env_name):
                env_key = f"{env_name} (environment)"
                break
        print(f"api key:  {ai_mod.mask_key(cfg['api_key']) or env_key or '(not set)'}")
        if cfg.get("base_url"):
            print(f"base url: {cfg['base_url']}")
        return 0

    if args.ai_cmd == "test":
        try:
            print(Ansi.green("✔ " + ai_mod.test_connection()))
            return 0
        except ai_mod.AIError as e:
            print(Ansi.red(f"✖ {e}"))
            return 1

    if args.ai_cmd == "explain":
        path = args.scan
        if os.path.isdir(path):
            candidate = os.path.join(path, "scans")
        elif path.endswith(".json") and os.path.exists(path):
            candidate = path
        else:
            candidate = os.path.join(data_dir(), "scans", f"{path}.json")
        if os.path.isdir(candidate):
            files = [os.path.join(candidate, f) for f in sorted(os.listdir(candidate)) if f.endswith(".json")]
            if not files:
                print(Ansi.red("No saved scans found."))
                return 2
            path = files[-1]
        elif not os.path.exists(candidate):
            print(Ansi.red(f"Scan not found: {path}"))
            return 2
        else:
            path = candidate
        with open(path, "r", encoding="utf-8") as fh:
            result = ScanResult.from_dict(json.load(fh))
        print(Ansi.dim(f"Analyzing {result.scan_id} ({len(result.findings)} findings) with AI…\n"))
        try:
            out = ai_mod.analyze_result(result.to_dict())
        except ai_mod.AIError as e:
            print(Ansi.red(f"✖ {e}"))
            return 1
        result.ai_summary = out["summary"]
        result.ai_meta = {"provider": out["provider"], "label": out["label"], "model": out["model"]}
        save_result(result)          # persist so reports/UI include it
        print(Ansi.bold(f"AI analysis ({out['label']} · {out['model']}) — advisory, verify before acting:\n"))
        print(result.ai_summary)
        print(Ansi.cyan(f"\n  saved to scan {result.scan_id}; reports now include it "
                        f"(aegisscan report --input {os.path.join(data_dir(), 'scans', result.scan_id + '.json')} --format html)"))
        return 0
    return 2


# --------------------------------------------------------------------------- update
def _latest_upstream_version(timeout: int = 15) -> str:
    req = urllib.request.Request(UPSTREAM_RAW, headers={"User-Agent": f"AegisScan/{__version__}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        text = resp.read().decode("utf-8", "replace")
    m = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M)
    if not m:
        raise RuntimeError("could not parse upstream version")
    return m.group(1)


def _vkey(v: str) -> tuple:
    return tuple(int(p) for p in re.findall(r"\d+", v)[:3])


def _install_kind() -> str:
    """Return 'git' (source checkout), 'pip' (site-packages), or 'source'."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.path.isdir(os.path.join(here, ".git")):
        return "git"
    try:
        out = subprocess.run([sys.executable, "-m", "pip", "show", "aegisscan"],
                             capture_output=True, text=True, timeout=60)
        if "Name: aegisscan" in out.stdout and "Location: " + here not in out.stdout:
            return "pip"
    except Exception:
        pass
    return "source"


def cmd_update(args) -> int:
    print(f"{Ansi.bold(__product__)} update")
    print(f"  installed version: {Ansi.bold(__version__)}")

    latest = ""
    try:
        latest = _latest_upstream_version()
        print(f"  latest version:    {Ansi.bold(latest)}")
    except Exception as e:
        print(Ansi.yellow(f"  could not check upstream version: {e}"))
    if args.check:
        return 0
    if latest and _vkey(latest) <= _vkey(__version__):
        print(Ansi.green("\n✔ AegisScan is up to date."))
        return 0

    kind = _install_kind()
    if kind == "git":
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        print(Ansi.cyan("\n  updating source checkout (git)…"))
        for cmd in (["git", "fetch", "origin"], ["git", "pull", "--ff-only", "origin", "main"]):
            r = subprocess.run(cmd, cwd=repo_root)
            if r.returncode != 0:
                print(Ansi.red("  git update failed — resolve locally and retry."))
                return 1
        print(Ansi.green("✔ source updated. Restart any running dashboard to pick it up."))
        return 0

    print(Ansi.cyan(f"\n  updating via pip ({kind or 'pip'} install)…"))
    targets = ["--upgrade", f"git+https://github.com/{UPSTREAM_REPO}.git"]
    r = subprocess.run([sys.executable, "-m", "pip", "install", *targets])
    if r.returncode != 0:
        print(Ansi.red("  pip update failed."))
        return 1
    print(Ansi.green("✔ AegisScan updated. Restart any running dashboard to pick it up."))
    return 0


# --------------------------------------------------------------------------- uninstall
def cmd_uninstall(args) -> int:
    kind = _install_kind()
    data_path = os.environ.get("AEGISSCAN_DATA") or os.path.join(os.getcwd(), ai_mod.DATA_DIR_NAME)
    print(f"{Ansi.bold(__product__)} uninstall")
    print(f"  install type: {kind}")
    print(f"  data dir:     {data_path}")

    if args.purge_data:
        if not args.yes:
            print(Ansi.yellow("\n  --purge-data will DELETE all saved scans, reports and AI config."))
            print(Ansi.yellow(f"  Re-run with --yes to confirm deletion of: {data_path}"))
            return 2
        if os.path.isdir(data_path):
            shutil.rmtree(data_path, ignore_errors=True)
            print(Ansi.green(f"✔ removed data directory {data_path}"))
        else:
            print(Ansi.dim(f"  data directory not found: {data_path}"))

    if kind == "pip":
        print(Ansi.cyan("\n  running: pip uninstall aegisscan"))
        r = subprocess.run([sys.executable, "-m", "pip", "uninstall", "-y", "aegisscan"])
        if r.returncode == 0:
            print(Ansi.green("✔ AegisScan package uninstalled."))
        return r.returncode

    print(Ansi.yellow("\n  This copy runs from a source checkout — there is nothing pip-managed to remove."))
    print("  To remove it completely:")
    print(f"    1. delete this folder (or: {Ansi.cyan('aegisscan uninstall --purge-data --yes')} to also wipe data)")
    print("    2. remove any PATH/alias entries you created")
    print(f"  Data is kept unless you pass {Ansi.cyan('--purge-data --yes')}.")
    return 0



# --------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aegisscan",
        description=f"{__product__} {__version__} — unified multi-layer security scanner "
                    "(SAST · SCA · secrets · web/DAST · TLS · ports · GitHub), MITRE ATT&CK mapped.",
        epilog="examples: aegisscan demo | aegisscan scan --repo . --url https://example.com | aegisscan tls https://example.com")
    p.add_argument("--version", action="version", version=f"{__product__} {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--out", default=None, help="output directory for reports (default: aegisscan-data/)")
        sp.add_argument("--formats", default="html,json", help="comma list: html,json,md,sarif")
        sp.add_argument("--fail-on", default="high",
                        choices=["critical", "high", "medium", "low", "info", "none"],
                        help="exit code 1 when findings at/above this severity exist (CI gate)")
        sp.add_argument("-v", "--verbose", action="store_true", help="show finding details")
        sp.add_argument("--top", type=int, default=0, help="only show first N findings in console")

    scan_p = sub.add_parser("scan", help="unified scan across targets and modules")
    scan_p.add_argument("--repo", help="local repository/path to scan with code scanners")
    scan_p.add_argument("--github", help="GitHub repo (owner/repo or URL) — downloads and scans")
    scan_p.add_argument("--url", help="website URL for web/DAST (+TLS when https)")
    scan_p.add_argument("--host", help="hostname/IP for TCP port scan")
    scan_p.add_argument("--https", help="hostname/URL for deep TLS audit")
    scan_p.add_argument("--ports", default="top100", help="ports spec: top100, 1-1024, 80,443")
    scan_p.add_argument("--max-pages", type=int, default=25, help="max pages crawled in web scan")
    scan_p.add_argument("--no-injection", action="store_true", help="disable light injection probes")
    scan_p.add_argument("--offline", action="store_true", help="no network for SCA (offline DB)")
    scan_p.add_argument("--exclude", action="append", default=[],
                        help="skip files whose relative path contains this substring (repeatable)")
    scan_p.add_argument("--label", default="", help="label for this scan")
    scan_p.add_argument("--ai", action="store_true",
                        help="add an AI executive analysis (requires 'aegisscan ai setup')")
    common(scan_p)
    scan_p.set_defaults(func=cmd_scan)

    for name, help_text in [("secrets", "detect hardcoded secrets/credentials"),
                            ("sast", "static analysis for dangerous code patterns"),
                            ("sca", "vulnerable dependency analysis (OSV.dev)")]:
        sp = sub.add_parser(name, help=help_text)
        sp.add_argument("--repo", required=True, help="path to codebase")
        sp.add_argument("--offline", action="store_true", help="offline DB only (sca)")
        common(sp)
        sp.set_defaults(func=_single_module(name, name.upper()))

    web_p = sub.add_parser("web", help="web application DAST scan")
    web_p.add_argument("--url", required=True)
    web_p.add_argument("--max-pages", type=int, default=25)
    web_p.add_argument("--no-injection", action="store_true")
    common(web_p)
    web_p.set_defaults(func=_single_module("web", "Web DAST"))

    tls_p = sub.add_parser("tls", help="SSL-Labs-style TLS audit")
    tls_p.add_argument("--https", required=True, help="hostname or URL")
    common(tls_p)
    tls_p.set_defaults(func=cmd_tls)

    ports_p = sub.add_parser("ports", help="TCP port scanner with banner grabbing")
    ports_p.add_argument("--host", required=True)
    ports_p.add_argument("--ports", default="top100")
    common(ports_p)
    ports_p.set_defaults(func=cmd_ports)

    rep_p = sub.add_parser("report", help="render a report from a saved scan JSON")
    rep_p.add_argument("--input", required=True, help="path to scan JSON")
    rep_p.add_argument("--format", default="html", choices=["html", "json", "md", "sarif"])
    rep_p.add_argument("--output", default=None, help="output file path")
    rep_p.add_argument("--out", default=".")
    rep_p.set_defaults(func=cmd_report)

    ui_p = sub.add_parser("ui", help="launch the web dashboard")
    ui_p.add_argument("--port", type=int, default=8899)
    ui_p.add_argument("--no-browser", action="store_true")
    ui_p.set_defaults(func=cmd_ui)

    demo_p = sub.add_parser("demo", help="scan the bundled vulnerable demo app")
    demo_p.add_argument("--ai", action="store_true", help="add an AI executive analysis")
    common(demo_p)
    demo_p.set_defaults(func=cmd_demo)

    ai_p = sub.add_parser("ai", help="configure and use AI analysis (OpenAI, Anthropic, Gemini, GLM/Z.ai, …)")
    ai_sub = ai_p.add_subparsers(dest="ai_cmd", required=True)

    setup_p = ai_sub.add_parser("setup", help="configure provider, API key and model (no args = list providers)")
    setup_p.add_argument("--provider", default="", help=f"one of: {', '.join(ai_mod.PROVIDERS)}")
    setup_p.add_argument("--api-key", default="", help="API key (stored locally in aegisscan-data/config.json)")
    setup_p.add_argument("--model", default="", help="model id (default depends on provider)")
    setup_p.add_argument("--base-url", default="", help="base URL for the 'custom' provider")
    setup_p.set_defaults(func=cmd_ai)

    show_p = ai_sub.add_parser("show", help="show current AI configuration (key masked)")
    show_p.set_defaults(func=cmd_ai)

    test_p = ai_sub.add_parser("test", help="verify the API key with a minimal round-trip")
    test_p.set_defaults(func=cmd_ai)

    explain_p = ai_sub.add_parser("explain", help="run AI analysis on a saved scan and update its reports")
    explain_p.add_argument("scan", help="scan id, path to scan JSON, or directory of scans")
    explain_p.set_defaults(func=cmd_ai)

    upd_p = sub.add_parser("update", help="update AegisScan to the latest version (git or pip)")
    upd_p.add_argument("--check", action="store_true", help="only check the latest version, do not update")
    upd_p.set_defaults(func=cmd_update)

    uni_p = sub.add_parser("uninstall", help="remove AegisScan (package and/or data)")
    uni_p.add_argument("--purge-data", action="store_true",
                       help="also delete saved scans, reports and AI config (aegisscan-data/)")
    uni_p.add_argument("--yes", action="store_true", help="confirm destructive actions (required with --purge-data)")
    uni_p.set_defaults(func=cmd_uninstall)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "out", None) is None:
        args.out = os.path.join(data_dir(), "reports")
    os.makedirs(args.out, exist_ok=True)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print(Ansi.yellow("\n  interrupted"))
        return 130
    except Exception as e:
        print(Ansi.red(f"error: {e}"))
        if os.environ.get("AEGISSCAN_DEBUG"):
            raise
        return 2


if __name__ == "__main__":
    sys.exit(main())
