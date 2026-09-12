"""Report generation — professional HTML, Markdown, JSON and SARIF output.

The HTML report is a self-contained document (inline CSS + SVG charts):
executive summary, risk gauge, severity distribution, prioritized remediation
roadmap, full finding details, TLS audit tables and the MITRE ATT&CK matrix.
"""

from __future__ import annotations

import html
import json
from datetime import datetime

from . import mitre
from .models import MODULE_LABELS, Finding, ScanResult, Severity

SEV_COLORS = {
    "critical": "#e11d48",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "info": "#94a3b8",
    "pass": "#10b981",
}

SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def esc(s) -> str:
    return html.escape(str(s or ""))


# --------------------------------------------------------------------------- HTML
_CSS = """
:root{--bg:#0b1220;--panel:#101a2e;--panel2:#0d1526;--border:#1e2a44;--text:#e2e8f0;
--muted:#8b9cb8;--accent:#22d3ee;--accent2:#34d399;}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',system-ui,-apple-system,Roboto,Arial,sans-serif;background:var(--bg);
color:var(--text);line-height:1.55;font-size:15px}
.wrap{max-width:1080px;margin:0 auto;padding:32px 24px 80px}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.hero{background:linear-gradient(135deg,#0e1830 0%,#122240 55%,#0d2a33 100%);
border:1px solid var(--border);border-radius:16px;padding:36px 40px;position:relative;overflow:hidden}
.hero:before{content:'';position:absolute;inset:0;
background:radial-gradient(600px 200px at 85% -10%,rgba(34,211,238,.18),transparent)}
.brand{display:flex;align-items:center;gap:14px;font-size:26px;font-weight:700;letter-spacing:.4px}
.brand .logo{width:40px;height:40px;flex:none}
.brand em{font-style:normal;background:linear-gradient(90deg,var(--accent),var(--accent2));
-webkit-background-clip:text;background-clip:text;color:transparent}
.subtitle{color:var(--muted);margin-top:6px;font-size:14px}
.grid{display:grid;gap:16px;margin-top:28px}
.g4{grid-template-columns:repeat(auto-fit,minmax(180px,1fr))}
.g2{grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}
.card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:20px 22px}
.card h3{font-size:13px;text-transform:uppercase;letter-spacing:1.2px;color:var(--muted);margin-bottom:10px}
.big{font-size:34px;font-weight:700}
.sevchip{display:inline-block;padding:3px 10px;border-radius:999px;font-size:12px;font-weight:700;
letter-spacing:.6px;text-transform:uppercase}
.bar{height:8px;border-radius:99px;background:#1b2740;overflow:hidden;margin-top:6px}
.bar>span{display:block;height:100%;border-radius:99px}
table{width:100%;border-collapse:collapse;font-size:14px}
th{color:var(--muted);text-transform:uppercase;font-size:11px;letter-spacing:1px;text-align:left;
padding:10px 12px;border-bottom:1px solid var(--border)}
td{padding:10px 12px;border-bottom:1px solid #16223a;vertical-align:top}
tr:hover td{background:#111d34}
.mono{font-family:Consolas,'JetBrains Mono',monospace;font-size:12.5px;background:#0a1120;
border:1px solid var(--border);border-radius:8px;padding:10px 12px;color:#93c5fd;
overflow-x:auto;white-space:pre-wrap;word-break:break-word}
.finding{background:var(--panel);border:1px solid var(--border);border-left:4px solid var(--muted);
border-radius:12px;padding:18px 20px;margin-top:14px}
.finding h4{font-size:16px;margin-bottom:4px}
.meta{color:var(--muted);font-size:12.5px;margin-bottom:10px}
.fix{background:#0c2018;border:1px solid #14532d;border-radius:8px;padding:10px 14px;margin-top:10px;font-size:14px}
.fix b{color:#34d399}
.grade{display:inline-flex;align-items:center;justify-content:center;min-width:74px;height:74px;
border-radius:18px;font-size:34px;font-weight:800}
.section{margin-top:40px}
.section>h2{font-size:20px;margin-bottom:6px}
.section>p.lead{color:var(--muted);margin-bottom:16px}
.pill{display:inline-block;background:#16233d;border:1px solid var(--border);color:var(--muted);
border-radius:999px;padding:2px 10px;font-size:12px;margin:2px 4px 2px 0}
.tactic-col{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:10px;min-width:140px}
.tactic-col h5{font-size:12px;text-transform:uppercase;letter-spacing:1px;color:var(--accent);
margin-bottom:8px;text-align:center}
.tech{background:#152238;border:1px solid var(--border);border-radius:7px;padding:6px 8px;
margin-bottom:6px;font-size:12.5px}
.tech .tid{color:var(--accent2);font-weight:700;font-size:11px}
.tech .cnt{float:right;color:var(--muted)}
footer{margin-top:60px;color:var(--muted);font-size:12.5px;text-align:center}
@media print{body{background:#fff;color:#111} .card,.finding,.hero,.tactic-col{background:#fff;border-color:#ddd}
 td{border-color:#ddd}.mono{background:#f5f5f5;color:#111}}
"""


def _donut(counts: dict) -> str:
    total = sum(counts.values()) or 1
    # reserve 0 for pass
    segs, offset, r = [], 25.0, 34.0
    import math
    circ = 2 * math.pi * r
    start = 0.0
    for sev in ("critical", "high", "medium", "low", "info"):
        n = counts.get(sev, 0)
        if not n:
            continue
        frac = n / total
        dash = frac * circ
        segs.append(
            f'<circle r="{r}" cx="50" cy="50" fill="none" stroke="{SEV_COLORS[sev]}" stroke-width="11" '
            f'stroke-dasharray="{dash:.1f} {circ - dash:.1f}" stroke-dashoffset="{-start:.1f}" '
            f'transform="rotate(-90 50 50)"/>')
        start += dash
    return (f'<svg viewBox="0 0 100 100" width="130" height="130">'
            f'<circle r="{r}" cx="50" cy="50" fill="none" stroke="#1b2740" stroke-width="11"/>'
            + "".join(segs) +
            f'<text x="50" y="47" text-anchor="middle" fill="#e2e8f0" font-size="15" font-weight="700">{total}</text>'
            f'<text x="50" y="61" text-anchor="middle" fill="#8b9cb8" font-size="7">FINDINGS</text></svg>')


def _gauge(score: float) -> str:
    pct = max(0, min(10, score)) / 10
    angle = -90 + pct * 180
    color = "#e11d48" if score >= 7 else "#f97316" if score >= 5 else "#eab308" if score >= 3 else "#10b981"
    return (f'<svg viewBox="0 0 140 84" width="170" height="102">'
            f'<path d="M14 74 A 56 56 0 0 1 126 74" fill="none" stroke="#1b2740" stroke-width="12" stroke-linecap="round"/>'
            f'<path d="M14 74 A 56 56 0 0 1 126 74" fill="none" stroke="{color}" stroke-width="12" stroke-linecap="round" '
            f'stroke-dasharray="{pct*176:.0f} 999"/>'
            f'<g transform="rotate({angle:.0f} 70 74)"><line x1="70" y1="74" x2="70" y2="28" stroke="#e2e8f0" stroke-width="2.5"/></g>'
            f'<circle cx="70" cy="74" r="5" fill="#e2e8f0"/>'
            f'<text x="70" y="66" text-anchor="middle" fill="#e2e8f0" font-size="17" font-weight="800">{score:.1f}</text></svg>')


def _grade_color(g: str) -> str:
    if not g or g == "-":
        return "#94a3b8"
    if g.startswith("A"):
        return "#10b981"
    if g == "B":
        return "#84cc16"
    if g == "C":
        return "#eab308"
    if g == "D":
        return "#f97316"
    return "#e11d48"


def _chip(sev) -> str:
    c = SEV_COLORS.get(sev.value if hasattr(sev, "value") else sev, "#94a3b8")
    label = (sev.value if hasattr(sev, "value") else sev).upper()
    return f'<span class="sevchip" style="background:{c}22;color:{c};border:1px solid {c}66">{label}</span>'


def _finding_card(f: Finding, idx: int) -> str:
    color = SEV_COLORS[f.severity.value]
    mitre_pills = "".join(
        f'<span class="pill" title="{esc(mitre.TECHNIQUES.get(t, {}).get("desc", ""))}">'
        f'{esc(t)} · {esc(mitre.TECHNIQUES.get(t, {}).get("name", ""))}</span>'
        for t in f.mitre)
    refs = "".join(f'<a href="{esc(r)}" target="_blank" rel="noopener">{esc(r)}</a>' for r in f.references)
    evidence = f'<div class="mono" style="margin-top:10px">{esc(f.evidence)}</div>' if f.evidence else ""
    loc = f" &nbsp;·&nbsp; {esc(f.location)}" if f.location else ""
    return f"""
<div class="finding" style="border-left-color:{color}">
  <h4>#{idx} {esc(f.title)}</h4>
  <div class="meta">{_chip(f.severity)} &nbsp;<b style="color:{color}">{f.risk_score:.1f}/10</b>{loc}
    &nbsp;·&nbsp; scanner: {esc(f.scanner)} &nbsp;·&nbsp; category: {esc(f.category)}
    {f' &nbsp;·&nbsp; {esc(f.cwe)}' if f.cwe else ''}</div>
  <p style="margin:8px 0">{esc(f.description)}</p>
  {evidence}
  <div class="fix"><b>Recommended fix:</b> {esc(f.remediation)}</div>
  <div style="margin-top:10px">{mitre_pills}</div>
  <div style="margin-top:8px;font-size:12.5px">{refs}</div>
</div>"""


def render_html(result: ScanResult) -> str:
    counts = result.counts
    tls = result.tls_details or {}
    matrix = mitre.aggregate(result.findings)
    targets = ", ".join(t.get("value", "") for t in result.targets)

    stat_cards = "".join(
        f'<div class="card"><h3>{s.upper()}</h3><div class="big" style="color:{SEV_COLORS[s]}">{counts.get(s, 0)}</div>'
        f'<div class="bar"><span style="width:{min(100, counts.get(s, 0) * 100 // max(1, max(counts.values() or [1])))}%;background:{SEV_COLORS[s]}"></span></div></div>'
        for s in ("critical", "high", "medium", "low", "info"))

    tls_html = ""
    if tls:
        for host, d in tls.items():
            if not d.get("reachable"):
                continue
            rows = "".join(
                f'<tr><td>{esc(lbl)}</td><td>{_chip("pass" if ok else "medium").replace("PASS", "offered").replace("MEDIUM", "not offered")}</td></tr>'
                for lbl, ok in d.get("protocols", {}).items())
            crows = "".join(
                f'<tr><td class="mono" style="background:none;border:none;padding:4px 12px">{esc(c["name"])}</td>'
                f'<td>{c["bits"]}</td><td>{_chip("pass" if c["strength"] == "strong" else "high" if c["weak"] else "low").replace("PASS", "strong").replace("HIGH", "weak").replace("LOW", "acceptable")}</td>'
                f'<td>{"yes" if c["forward_secrecy"] else "no"}</td></tr>'
                for c in d.get("ciphers", []) if c.get("offered"))
            cert = d.get("cert", {})
            h = d.get("hsts", {})
            tls_html += f"""
<div class="grid g2">
 <div class="card">
   <h3>{esc(host)} — grade</h3>
   <div style="display:flex;align-items:center;gap:22px">
     <span class="grade" style="background:{_grade_color(d.get('grade',''))}22;color:{_grade_color(d.get('grade',''))};border:2px solid {_grade_color(d.get('grade',''))}">{esc(d.get('grade', '-'))}</span>
     <div>
       <div style="font-size:22px;font-weight:700">{d.get('score', 0):.0f}/100</div>
       <div class="meta">SSL-Labs-style assessment</div>
     </div>
   </div>
   <table style="margin-top:14px"><tr><th>Protocol</th><th>Status</th></tr>{rows}</table>
 </div>
 <div class="card">
   <h3>Certificate</h3>
   <table>
     <tr><td>Subject</td><td>{esc(cert.get('subject_cn', ''))}</td></tr>
     <tr><td>Issuer</td><td>{esc(cert.get('issuer', ''))}</td></tr>
     <tr><td>Valid to</td><td>{esc(cert.get('not_after', ''))} {f'({cert.get("days_left")} days left)' if cert.get('days_left') is not None else ''}</td></tr>
     <tr><td>Chain</td><td>{_chip('pass' if cert.get('chain_valid') else 'critical').replace('PASS','valid').replace('CRITICAL','invalid')} {esc(cert.get('chain_message',''))}</td></tr>
     <tr><td>Hostname</td><td>{_chip('pass' if cert.get('hostname_match') else 'critical').replace('PASS','match').replace('CRITICAL','mismatch')}</td></tr>
     <tr><td>HSTS</td><td>{('max-age=' + str(h.get('max_age', 0))) if h.get('present') else 'not set'}</td></tr>
   </table>
   <h3 style="margin-top:16px">Cipher suites ({len(d.get('ciphers', []))} tested)</h3>
   <div style="max-height:260px;overflow:auto"><table><tr><th>Suite</th><th>Bits</th><th>Strength</th><th>FS</th></tr>{crows}</table></div>
 </div>
</div>"""

    mitre_html = ""
    if matrix:
        cols = []
        for tac_id, tac_name in mitre.TACTICS:
            if tac_id not in matrix:
                continue
            techs = "".join(
                f'<div class="tech" title="{esc(mitre.TECHNIQUES[t]["desc"])}"><span class="tid">{esc(t)}</span>'
                f'<span class="cnt">{len(ids)} finding(s)</span><br>{esc(mitre.TECHNIQUES[t]["name"])}</div>'
                for t, ids in sorted(matrix[tac_id].items()))
            cols.append(f'<div class="tactic-col"><h5>{esc(tac_name)}</h5>{techs}</div>')
        mitre_html = f'<div style="display:flex;gap:10px;overflow-x:auto;padding-bottom:8px">{"".join(cols)}</div>'
    else:
        mitre_html = '<p class="lead">No ATT&CK mappings were triggered by this scan.</p>'

    # remediation roadmap grouped by severity
    roadmap = []
    for sev in SEV_ORDER:
        items = [f for f in result.findings if f.severity == sev and f.severity != Severity.INFO]
        if not items:
            continue
        lis = "".join(f"<li>{esc(f.title)} → <i>{esc(f.remediation[:140])}{'…' if len(f.remediation) > 140 else ''}</i></li>"
                      for f in items[:8])
        roadmap.append(f'<div class="card" style="margin-top:12px"><h3>{_chip(sev)} fix first ({len(items)})</h3><ul style="margin-left:18px;font-size:14px">{lis}</ul></div>')
    roadmap_html = "".join(roadmap) or '<p class="lead">Nothing above informational severity — well done.</p>'

    # findings sorted by severity
    sorted_findings = sorted(result.findings, key=lambda f: (-f.severity.rank, -f.risk_score))
    findings_html = "".join(_finding_card(f, i + 1) for i, f in enumerate(sorted_findings)) or \
        '<p class="lead">No findings. Target looks clean for the executed checks.</p>'

    module_rows = "".join(
        f'<tr><td>{esc(MODULE_LABELS.get(m.name, m.name))}</td>'
        f'<td>{_chip("pass" if m.status == "done" else "high" if m.status == "error" else "info").replace("PASS","done").replace("HIGH","error").replace("INFO",m.status)}</td>'
        f'<td>{m.findings}</td><td>{m.duration:.1f}s</td><td class="meta">{esc(m.detail[:80])}</td></tr>'
        for m in result.modules)

    gh = result.github_meta or {}
    gh_html = ""
    if gh:
        gh_html = ('<div class="section"><h2>Repository Posture</h2><div class="card"><table>'
                   f'<tr><td>Repository</td><td><a href="{esc(gh.get("url", ""))}">{esc(gh.get("full_name", ""))}</a></td></tr>'
                   f'<tr><td>Visibility</td><td>{esc(gh.get("visibility", ""))}</td></tr>'
                   f'<tr><td>License</td><td>{esc(gh.get("license", ""))}</td></tr>'
                   f'<tr><td>Default branch</td><td>{esc(gh.get("default_branch", ""))} '
                   f'{_chip("pass" if gh.get("branch_protection") else "medium").replace("PASS","protected").replace("MEDIUM","unprotected") if "branch_protection" in gh else ""}</td></tr>'
                   f'<tr><td>Stars / forks</td><td>{esc(gh.get("stars", ""))} / {esc(gh.get("forks", ""))}</td></tr>'
                   '</table></div></div>')

    logo = ('<svg class="logo" viewBox="0 0 24 24" fill="none"><path d="M12 2L4 5v6c0 5 3.4 9.4 8 11 '
            '4.6-1.6 8-6 8-11V5l-8-3z" fill="url(#g)"/><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">'
            '<stop offset="0" stop-color="#22d3ee"/><stop offset="1" stop-color="#34d399"/></linearGradient></defs>'
            '<path d="M9 12l2 2 4-4" stroke="#0b1220" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" fill="none"/></svg>')

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AegisScan Report — {esc(targets or result.scan_id)}</title>
<style>{_CSS}</style></head>
<body><div class="wrap">

<div class="hero">
  <div class="brand">{logo} <span><em>Aegis</em>Scan</span> <span style="font-size:13px;color:var(--muted);font-weight:400">Security Assessment Report</span></div>
  <div class="subtitle">Target: <b style="color:var(--text)">{esc(targets or result.scan_id)}</b>
    &nbsp;·&nbsp; Scan ID {esc(result.scan_id)}
    &nbsp;·&nbsp; {esc(result.started)} → {esc(result.finished or 'running')}
    &nbsp;·&nbsp; status {esc(result.status)}</div>
  <div class="grid g4" style="margin-top:24px">
    <div class="card"><h3>Overall risk</h3><div style="display:flex;align-items:center;gap:6px">{_gauge(result.risk_score)}</div></div>
    <div class="card"><h3>Severity mix</h3><div style="display:flex;align-items:center;gap:14px">{_donut(counts)}
      <div style="font-size:12px;color:var(--muted)">{"".join(f'<div><span style="color:{SEV_COLORS[s]}">●</span> {s} <b style="color:var(--text)">{counts.get(s,0)}</b></div>' for s in ("critical","high","medium","low","info"))}</div></div></div>
    {f'<div class="card"><h3>TLS grade</h3><span class="grade" style="background:{_grade_color(result.tls_grade)}22;color:{_grade_color(result.tls_grade)};border:2px solid {_grade_color(result.tls_grade)}">{esc(result.tls_grade or "-")}</span><div class="meta" style="margin-top:10px">SSL-Labs-style</div></div>' if result.tls_grade else ''}
  </div>
</div>

<div class="section">
  <h2>Executive Summary</h2>
  <p class="lead">AegisScan executed {len(result.modules)} scan module(s) against <b>{esc(targets)}</b> and produced
  <b>{len(result.findings)}</b> finding(s). Risk score is <b>{result.risk_score:.1f}/10</b>
  ({'critical' if result.risk_score >= 7 else 'elevated' if result.risk_score >= 5 else 'moderate' if result.risk_score >= 3 else 'low'}).
  The prioritized remediation roadmap below lists what to fix first; every finding includes its MITRE ATT&CK mapping and a concrete fix.</p>
  <div class="grid g4">{stat_cards}</div>
</div>

{f'<div class="section"><h2>TLS / SSL Audit</h2><p class="lead">SSL-Labs-style deep assessment of encryption posture.</p>{tls_html}</div>' if tls_html else ''}

{gh_html}

<div class="section">
  <h2>MITRE ATT&CK Coverage</h2>
  <p class="lead">Each finding is mapped to the ATT&CK technique an attacker would use through the discovered weakness.</p>
  {mitre_html}
</div>

<div class="section">
  <h2>Remediation Roadmap</h2>
  <p class="lead">Fix in severity order. Each card groups the findings to address first.</p>
  {roadmap_html}
</div>

<div class="section">
  <h2>Modules Executed</h2>
  <div class="card"><table><tr><th>Module</th><th>Status</th><th>Findings</th><th>Duration</th><th>Notes</th></tr>{module_rows}</table></div>
</div>

<div class="section">
  <h2>All Findings ({len(result.findings)})</h2>
  <p class="lead">Full detail for every finding: evidence, impact and recommended fix.</p>
  {findings_html}
</div>

<footer>Generated by AegisScan · {esc(datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'))} ·
Mapping: MITRE ATT&CK® Enterprise · Grades inspired by SSL Labs methodology</footer>
</div></body></html>"""


# --------------------------------------------------------------------------- Markdown
def render_markdown(result: ScanResult) -> str:
    counts = result.counts
    lines = [
        f"# AegisScan Security Report",
        "",
        f"- **Scan ID:** {result.scan_id}",
        f"- **Targets:** {', '.join(t.get('value', '') for t in result.targets)}",
        f"- **Started:** {result.started}  |  **Finished:** {result.finished or '—'}",
        f"- **Status:** {result.status}  |  **Overall risk:** {result.risk_score:.1f}/10",
    ]
    if result.tls_grade:
        lines.append(f"- **TLS grade:** {result.tls_grade}")
    lines += [
        "",
        "## Summary",
        "",
        f"| Severity | Count |", "|---|---|",
        f"| Critical | {counts['critical']} |",
        f"| High | {counts['high']} |",
        f"| Medium | {counts['medium']} |",
        f"| Low | {counts['low']} |",
        f"| Info | {counts['info']} |",
        "",
        "## MITRE ATT&CK mapping",
        "",
    ]
    matrix = mitre.aggregate(result.findings)
    for tac_id, techs in matrix.items():
        tac_name = mitre.tactic_name(tac_id)
        lines.append(f"**{tac_name} ({tac_id})**")
        for t, ids in techs.items():
            lines.append(f"- `{t}` {mitre.TECHNIQUES[t]['name']} — {len(ids)} finding(s)")
        lines.append("")
    if result.tls_details:
        lines += ["## TLS / SSL audit", ""]
        for host, d in result.tls_details.items():
            if not d.get("reachable"):
                continue
            lines.append(f"### {host} — grade **{d.get('grade','-')}** ({d.get('score',0):.0f}/100)")
            lines.append("")
            lines.append("| Protocol | Offered |")
            lines.append("|---|---|")
            for lbl, ok in d.get("protocols", {}).items():
                lines.append(f"| {lbl} | {'✅' if ok else '—'} |")
            cert = d.get("cert", {})
            lines.append("")
            lines.append(f"Certificate: `{cert.get('subject_cn','?')}` issued by **{cert.get('issuer','?')}**, "
                         f"expires {cert.get('not_after','?')}, chain {'valid ✅' if cert.get('chain_valid') else 'INVALID ❌ (' + str(cert.get('chain_message','')) + ')'}")
            lines.append("")
    lines += ["## Findings", ""]
    sorted_f = sorted(result.findings, key=lambda f: (-f.severity.rank, -f.risk_score))
    for i, f in enumerate(sorted_f, 1):
        lines += [
            f"### {i}. [{f.severity.value.upper()}] {f.title}",
            "",
            f"- **Location:** {f.location or '—'}",
            f"- **Category:** {f.category}  |  **Scanner:** {f.scanner}  |  **Score:** {f.risk_score:.1f}/10"
            + (f"  |  **CWE:** {f.cwe}" if f.cwe else ""),
            f"- **MITRE ATT&CK:** {', '.join(f.mitre) if f.mitre else '—'}",
            "",
            f.description,
            "",
        ]
        if f.evidence:
            lines += [f"**Evidence:** `{f.evidence[:200]}`", ""]
        lines += [f"**Recommended fix:** {f.remediation}", ""]
        for r in f.references:
            lines.append(f"- Ref: {r}")
        lines.append("")
        lines.append("---")
        lines.append("")
    return "\n".join(lines)


# --------------------------------------------------------------------------- SARIF
_SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning",
                "low": "note", "info": "note", "pass": "note"}


def render_sarif(result: ScanResult) -> str:
    rules, results = [], []
    rule_index = {}
    for f in result.findings:
        rid = f"AEG-{f.id[:8]}"
        if rid not in rule_index:
            rule_index[rid] = len(rules)
            rules.append({
                "id": rid,
                "name": f.title[:120],
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description[:1024]},
                "help": {"text": f.remediation[:1024],
                         "markdown": f"**Recommended fix:** {f.remediation}"},
                "properties": {"severity": f.severity.value, "category": f.category,
                               "mitre": f.mitre, "cwe": f.cwe, "security-severity": f"{f.risk_score:.1f}"},
            })
        loc_uri = f.location or f.target or "unknown"
        if f.scanner in ("sast", "secrets", "sca"):
            loc_uri = f"file:///{f.location}" if f.location else loc_uri
        results.append({
            "ruleId": rid,
            "ruleIndex": rule_index[rid],
            "level": _SARIF_LEVEL[f.severity.value],
            "message": {"text": f"{f.title} — {f.description[:512]}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": loc_uri},
                                                "region": {"startLine": 1}}}],
            "properties": {"target": f.target, "score": f.risk_score},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "AegisScan", "version": "1.0.0",
                                "informationUri": "https://github.com/ronnibp/aegisscan",
                                "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2)


# --------------------------------------------------------------------------- entry
def render(result: ScanResult, fmt: str) -> str | bytes:
    fmt = fmt.lower()
    if fmt == "json":
        return result.to_json()
    if fmt == "html":
        return render_html(result)
    if fmt == "md" or fmt == "markdown":
        return render_markdown(result)
    if fmt == "sarif":
        return render_sarif(result)
    raise ValueError(f"Unknown report format: {fmt}")
