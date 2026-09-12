/* AegisScan dashboard — vanilla JS single-page app */
"use strict";

const SEV_COLORS = {critical:"#e11d48", high:"#f97316", medium:"#eab308", low:"#3b82f6", info:"#94a3b8"};
const MODULE_LABELS = {
  github:"GitHub Integration", secrets:"Secret Detection", sast:"Static Analysis (SAST)",
  sca:"Dependency Analysis (SCA)", web:"Web Application (DAST)", tls:"TLS / SSL Audit",
  network:"Network / Ports"
};
const $ = sel => document.querySelector(sel);
const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

const API = {
  async get(p){ const r = await fetch(p); if(!r.ok) throw new Error((await r.json()).error||r.status); return r.json(); },
  async post(p, body){ const r = await fetch(p,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
    if(!r.ok) throw new Error((await r.json()).error||r.status); return r.json(); },
  async del(p){ const r = await fetch(p,{method:"DELETE"}); return r.json(); }
};

const chip = sev => `<span class="chip ${sev}">${sev==="pass"?"PASS":sev.toUpperCase()}</span>`;

function donut(counts, size=150){
  const total = counts.critical+counts.high+counts.medium+counts.low+counts.info;
  const r = 38, circ = 2*Math.PI*r; let off = 0, segs = "";
  for(const s of ["critical","high","medium","low","info"]){
    const n = counts[s]||0; if(!n) continue;
    const dash = n/total*circ;
    segs += `<circle r="${r}" cx="50" cy="50" fill="none" stroke="${SEV_COLORS[s]}" stroke-width="12"
      stroke-dasharray="${dash.toFixed(1)} ${(circ-dash).toFixed(1)}" stroke-dashoffset="${(-off).toFixed(1)}"
      transform="rotate(-90 50 50)" style="transition:stroke-dasharray .6s"/>`;
    off += dash;
  }
  return `<svg viewBox="0 0 100 100" width="${size}" height="${size}">
    <circle r="${r}" cx="50" cy="50" fill="none" stroke="#16233f" stroke-width="12"/>${segs}
    <text x="50" y="48" text-anchor="middle" fill="#e6edf7" font-size="14" font-weight="800">${total}</text>
    <text x="50" y="60" text-anchor="middle" fill="#8fa1c0" font-size="6.5">FINDINGS</text></svg>`;
}

function gauge(score){
  const pct = Math.max(0, Math.min(10, score))/10;
  const color = score>=7 ? "#e11d48" : score>=5 ? "#f97316" : score>=3 ? "#eab308" : "#10b981";
  return `<svg viewBox="0 0 140 84" width="168" height="100">
    <path d="M14 74 A 56 56 0 0 1 126 74" fill="none" stroke="#16233f" stroke-width="12" stroke-linecap="round"/>
    <path d="M14 74 A 56 56 0 0 1 126 74" fill="none" stroke="${color}" stroke-width="12" stroke-linecap="round"
      stroke-dasharray="${(pct*176).toFixed(0)} 999"/>
    <g transform="rotate(${-90+pct*180} 70 74)"><line x1="70" y1="74" x2="70" y2="30" stroke="#e6edf7" stroke-width="2.5"/></g>
    <circle cx="70" cy="74" r="5" fill="#e6edf7"/>
    <text x="70" y="65" text-anchor="middle" fill="#e6edf7" font-size="16" font-weight="800">${(+score).toFixed(1)}</text></svg>`;
}

function riskWord(s){ return s>=7?"CRITICAL RISK":s>=5?"ELEVATED RISK":s>=3?"MODERATE RISK":"LOW RISK"; }
function gradeColor(g){ return !g||g==="-"?"#94a3b8":g[0]==="A"?"#10b981":g==="B"?"#84cc16":g==="C"?"#eab308":g==="D"?"#f97316":"#e11d48"; }

/* ============================================================ views */
const Views = {};

Views.dashboard = async (el) => {
  el.innerHTML = `<div class="empty"><div class="big-ic">◫</div>Loading telemetry…</div>`;
  const d = await API.get("/api/dashboard");
  const c = d.counts, maxc = Math.max(1, ...Object.values(c));
  const statCard = (s)=>`
    <div class="card stat"><h3>${s}</h3>
      <div class="num sev-${s}">${c[s]||0}</div>
      <div class="bar"><span style="width:${Math.min(100,(c[s]||0)/maxc*100)}%;background:${SEV_COLORS[s]}"></span></div>
    </div>`;
  const cats = (d.categories||[]).map(x=>`
    <tr><td>${esc(x.name)}</td><td>${chip(x.severity)}</td><td style="text-align:right"><b>${x.count}</b></td></tr>`).join("");
  const recent = (d.recent||[]).map(r=>{
    const t = (r.targets||[]).map(t=>t.value).join(", ");
    return `<tr class="clickable" onclick="location.hash='#/scan/${r.scan_id}'">
      <td class="mono">${esc(t||r.scan_id)}</td>
      <td>${esc(r.label||"—")}</td>
      <td>${chip(r.status==="completed"?"pass":r.status==="running"?"info":"high").replace("PASS","done").replace("INFO","running").replace("HIGH",esc(r.status))}</td>
      <td>${r.tls_grade?`<span class="grade sm" style="color:${gradeColor(r.tls_grade)};border-color:${gradeColor(r.tls_grade)}">${esc(r.tls_grade)}</span>`:'<span class="dim">—</span>'}</td>
      <td><b>${(r.risk_score||0).toFixed(1)}</b></td>
      <td class="muted">${new Date(r.started).toLocaleString()}</td></tr>`;
  }).join("");
  // tactics coverage strip
  const cov = (d.mitre.tactics||[]).map(t=>{
    const n = Object.values(d.mitre.matrix[t.id]||{}).reduce((a,b)=>a+b.length,0);
    return `<div class="pill" title="${esc(t.name)}"><b>${t.name}</b>${n?` — ${n}`:""}</div>`;
  }).join("");

  el.innerHTML = `
  <div class="grid g5">
    ${["critical","high","medium","low","info"].map(statCard).join("")}
  </div>
  <div class="grid g23" style="margin-top:16px">
    <div class="card"><h3>Overall risk</h3>
      <div style="display:flex;align-items:center;gap:8px">${gauge(d.findings_total? weightedRisk(c):0)}
      <div><div style="font-weight:800;font-size:17px">${riskWord(weightedRisk(c))}</div>
      <div class="muted" style="font-size:13px">${d.findings_total} findings across ${d.scans} scan(s)</div></div></div>
      <div class="grid" style="grid-template-columns:auto 1fr;align-items:center;margin-top:8px">${donut(c,140)}
        <div>${["critical","high","medium","low","info"].map(s=>`<div class="muted" style="font-size:12.5px">
          <span style="color:${SEV_COLORS[s]}">●</span> ${s} — <b style="color:var(--text)">${c[s]||0}</b></div>`).join("")}</div></div>
    </div>
    <div class="card"><h3>Top finding categories</h3>
      ${cats?`<table class="tbl"><tr><th>Category</th><th>Peak severity</th><th style="text-align:right">Findings</th></tr>${cats}</table>`
        :`<div class="empty"><div class="big-ic">✓</div>No findings yet — launch your first scan.</div>`}
    </div>
  </div>
  <div class="section-title"><h2>MITRE ATT&amp;CK tactics in play</h2><span class="muted">from all scans</span></div>
  <div class="card"><div class="pills">${cov||'<span class="dim">no mappings yet</span>'}</div></div>
  <div class="section-title"><h2>Recent scans</h2><span class="muted">click a row to open</span></div>
  <div class="card" style="padding:6px 12px">
    ${recent?`<table class="tbl"><tr><th>Target</th><th>Label</th><th>Status</th><th>TLS</th><th>Risk</th><th>Started</th></tr>${recent}</table>`
      :`<div class="empty"><div class="big-ic">⌖</div>No scans yet.<div class="hero-cta"><button class="btn primary" onclick="location.hash='#/scan'">Run your first scan</button></div></div>`}
  </div>`;
  updateNavBadge(d.findings_total);
};

function weightedRisk(c){
  const w = {critical:10,high:7.5,medium:5,low:3,info:0};
  let tot = 0, n = 0;
  for(const k in w){ tot += (c[k]||0)*w[k]; n += (c[k]||0); }
  return n ? Math.min(10, tot/n) : 0;
}

/* ---------------- new scan form ---------------- */
Views.scan = async (el) => {
  const meta = await API.get("/api/meta");
  const modFor = {
    repo:["secrets","sast","sca"], github:["github","secrets","sast","sca"],
    web:["web","tls"], host:["network"], tls:["tls"]
  };
  let kind = "repo";
  el.innerHTML = `
  <div class="grid" style="max-width:820px">
    <div class="card">
      <h3>Target type</h3>
      <div class="seg" id="seg">
        ${Object.entries({repo:"📁 Local repository", github:"🐙 GitHub repository", web:"🌐 Website / web app", host:"🖧 Host / ports", tls:"🔒 TLS / SSL audit"}).map(([k,l])=>
          `<button data-k="${k}" class="${k===kind?"active":""}">${l}</button>`).join("")}
      </div>
      <div id="target-inputs"></div>
      <label class="f">Options</label>
      <div class="checks" id="opts">
        <label class="on"><input type="checkbox" checked data-opt="osv_online"> Query OSV.dev for dependency CVEs</label>
        <label class="on"><input type="checkbox" checked data-opt="web_probe_injection"> Light injection probes (non-destructive)</label>
        <label><input type="checkbox" data-opt="ports_all"> Wider port range (1–1024)</label>
      </div>
      <label class="f">Label (optional)</label>
      <input type="text" id="scan-label" placeholder="e.g. pre-release audit of payments-api">
      <div style="display:flex;gap:12px;margin-top:22px">
        <button class="btn primary" id="run">▶ Run scan</button>
        <span class="muted" id="run-err" style="color:var(--critical);align-self:center"></span>
      </div>
    </div>
    <div class="card">
      <h3>Modules by target type</h3>
      <table class="tbl">
        ${Object.entries(modFor).map(([k,mods])=>`<tr><td><b>${k}</b></td><td class="muted">${mods.map(m=>MODULE_LABELS[m]||m).join(" · ")}</td></tr>`).join("")}
      </table>
      <p class="muted" style="margin-top:12px;font-size:13px">Engine v${esc(meta.version)} · ${meta.modules.length} scan modules · every finding is MITRE ATT&amp;CK mapped.</p>
    </div>
  </div>`;

  const targetInput = () => {
    const holders = {
      repo:['Local path to scan', '/path/to/project or C:\\code\\project'],
      github:['GitHub repository', 'owner/repo or https://github.com/owner/repo'],
      web:['Website URL', 'https://example.com'],
      host:['Hostname / IP', 'example.com or 10.0.0.5'],
      tls:['Host for TLS audit', 'example.com']
    };
    const [lbl, ph] = holders[kind];
    $("#target-inputs").innerHTML = `<label class="f">${lbl}</label><input type="text" id="target-value" placeholder="${ph}">`;
    $("#target-value").focus();
  };
  targetInput();

  $("#seg").onclick = e => {
    const b = e.target.closest("button"); if(!b) return;
    kind = b.dataset.k;
    document.querySelectorAll("#seg button").forEach(x=>x.classList.toggle("active", x===b));
    targetInput();
  };
  $("#opts").onchange = e => e.target.closest("label").classList.toggle("on", e.target.checked);

  $("#run").onclick = async () => {
    const value = $("#target-value").value.trim();
    const err = $("#run-err");
    err.textContent = "";
    if(!value){ err.textContent = "Enter a target first."; return; }
    const targets = [{kind, value}];
    // web target also gets a TLS audit automatically (engine handles it)
    const body = { targets, label:$("#scan-label").value.trim(),
      osv_online: $('[data-opt="osv_online"]').checked,
      web_probe_injection: $('[data-opt="web_probe_injection"]').checked,
      ports: $('[data-opt="ports_all"]').checked ? "1-1024" : "top100" };
    try{
      const {scan_id} = await API.post("/api/scans", body);
      location.hash = `#/scan/${scan_id}`;
    }catch(e){ err.textContent = e.message; }
  };
};

/* ---------------- scan detail (live) ---------------- */
Views.scanDetail = async (el, id) => {
  let done = false;
  const draw = (r) => {
    const mods = (r.modules||[]).map(m=>{
      const icon = {done:"✓", error:"✕", running:"•", pending:"…"}[m.status]||"…";
      return `<div class="mod"><div class="st ${m.status}">${icon}</div>
        <div class="grow"><div class="name">${MODULE_LABELS[m.name]||m.name}</div>
        <div class="sub">${esc(m.detail||"")}</div></div>
        <div class="muted" style="text-align:right;font-size:12.5px">${m.findings} finding(s)<br>${m.duration?m.duration.toFixed(1)+"s":""}</div></div>`;
    }).join("");
    const t = (r.targets||[]).map(t=>t.value).join(", ");
    const counts = r.counts||{};
    const rows = (r.findings||[]).slice().sort((a,b)=>b.score-a.score).slice(0,25).map(fRow).join("");
    const running = r.status==="running";
    el.innerHTML = `
    <div class="grid g4">
      <div class="card"><h3>Target</h3><div class="mono" style="font-size:13px">${esc(t)}</div>
        <div class="muted" style="margin-top:8px;font-size:12.5px">${esc(r.label||"unlabeled scan")} · ${esc(r.scan_id)}</div>
        ${r.tls_grade?`<div style="margin-top:12px;display:flex;align-items:center;gap:10px">
          <span class="grade sm" style="color:${gradeColor(r.tls_grade)};border-color:${gradeColor(r.tls_grade)}">${esc(r.tls_grade)}</span>
          <span class="muted">TLS grade</span></div>`:""}</div>
      <div class="card"><h3>Overall risk</h3><div style="display:flex;align-items:center;gap:6px">${gauge(r.risk_score||0)}
        <div><b style="font-size:15px">${riskWord(r.risk_score||0)}</b></div></div></div>
      <div class="card"><h3>Severity mix</h3><div style="display:flex;gap:10px;align-items:center">${donut(counts,110)}
        <div>${["critical","high","medium","low","info"].map(s=>`<div class="muted" style="font-size:12px"><span style="color:${SEV_COLORS[s]}">●</span> ${s} <b style="color:var(--text)">${counts[s]||0}</b></div>`).join("")}</div></div></div>
      <div class="card"><h3>Actions</h3>
        <div style="display:flex;flex-direction:column;gap:8px">
          <a class="btn" href="/api/scans/${esc(r.scan_id)}/report?format=html" target="_blank">▤ Open full report</a>
          <a class="btn" href="/api/scans/${esc(r.scan_id)}/report?format=json" download="aegisscan-${esc(r.scan_id)}.json">⬇ Download JSON</a>
          <a class="btn" href="/api/scans/${esc(r.scan_id)}/report?format=md" download="aegisscan-${esc(r.scan_id)}.md">⬇ Download Markdown</a>
          <a class="btn" href="/api/scans/${esc(r.scan_id)}/report?format=sarif" download="aegisscan-${esc(r.scan_id)}.sarif">⬇ Download SARIF</a>
          <button class="btn danger" id="del-scan">✕ Delete scan</button>
        </div></div>
    </div>
    <div class="grid g23" style="margin-top:16px">
      <div class="card"><h3>Findings preview</h3>
        ${rows?`<table class="tbl"><tr><th></th><th>Finding</th><th>Location</th><th style="text-align:right">Score</th></tr>${rows}</table>`
          : running?`<div class="empty"><div class="big-ic">⏳</div>Scanning…</div>`:`<div class="empty"><div class="big-ic">✓</div>No findings.</div>`}</div>
      <div class="card"><h3>Modules</h3>${mods||'<div class="muted">starting…</div>'}
        ${running?'<div class="progress-line"><span style="width:40%;animation:none" id="live-line"></span></div>':""}</div>
    </div>`;
    $("#del-scan").onclick = async () => { await API.del(`/api/scans/${r.scan_id}`); location.hash = "#/reports"; };
  };
  const poll = async () => {
    const r = await API.get(`/api/scans/${id}`);
    CURRENT_SCAN = r;
    draw(r);
    bindDrawer("#view");
    const live = r.status==="running";
    document.querySelectorAll("#scan-live").forEach(x=>x.hidden=!live);
    if(live && location.hash === `#/scan/${id}`) setTimeout(poll, 1500);
    else { done = true; refreshBadge(); }
  };
  await poll();
};

/* ---------------- findings explorer ---------------- */
let ALL_FINDINGS = [];
Views.findings = async (el) => {
  el.innerHTML = `<div class="empty"><div class="big-ic">⚑</div>Loading findings…</div>`;
  const scans = await API.get("/api/scans");
  ALL_FINDINGS = [];
  await Promise.all(scans.map(async s => {
    const r = await API.get(`/api/scans/${s.scan_id}`);
    r.findings.forEach(f => ALL_FINDINGS.push({...f, scan_id: s.scan_id, scan_label: s.label}));
  }));
  const cats = [...new Set(ALL_FINDINGS.map(f=>f.category))].sort();
  el.innerHTML = `
  <div class="card">
    <div class="filters">
      <select id="f-sev"><option value="">All severities</option>
        ${["critical","high","medium","low","info"].map(s=>`<option>${s}</option>`).join("")}</select>
      <select id="f-cat"><option value="">All categories</option>
        ${cats.map(c=>`<option>${esc(c)}</option>`).join("")}</select>
      <select id="f-scan"><option value="">All scans</option>
        ${scans.map(s=>`<option value="${esc(s.scan_id)}">${esc(s.label||s.scan_id)}</option>`).join("")}</select>
      <input type="text" id="f-q" placeholder="Search title, location, MITRE id…">
      <span class="muted" style="align-self:center" id="f-count"></span>
    </div>
    <div id="f-table"></div>
  </div>`;
  const redraw = () => {
    const sev = $("#f-sev").value, cat = $("#f-cat").value, scan = $("#f-scan").value;
    const q = $("#f-q").value.toLowerCase();
    let list = ALL_FINDINGS;
    if(sev) list = list.filter(f=>f.severity===sev);
    if(cat) list = list.filter(f=>f.category===cat);
    if(scan) list = list.filter(f=>f.scan_id===scan);
    if(q) list = list.filter(f=>(f.title+f.location+f.target+(f.mitre||[]).join(",")).toLowerCase().includes(q));
    list.sort((a,b)=>b.score-a.score);
    $("#f-count").textContent = `${list.length} finding(s)`;
    const rows = list.slice(0,300).map(fRow).join("");
    $("#f-table").innerHTML = rows
      ? `<table class="tbl"><tr><th></th><th>Finding</th><th>Category</th><th>Location</th><th>MITRE</th><th style="text-align:right">Score</th></tr>${rows}</table>`
      : `<div class="empty"><div class="big-ic">✓</div>Nothing matches the filters.</div>`;
    bindDrawer("#f-table");
  };
  ["f-sev","f-cat","f-scan","f-q"].forEach(id=>{
    $("#"+id).oninput = redraw; $("#"+id).onchange = redraw;
  });
  redraw();
};

function fRow(f){
  const mitre = (f.mitre||[]).map(m=>`<span class="pill"><b>${esc(m)}</b></span>`).join(" ");
  return `<tr class="f-row sev-${esc(f.severity)} clickable" data-finding="${esc(f.id)}">
    <td>${chip(f.severity)}</td>
    <td><b>${esc(f.title)}</b></td>
    <td class="muted">${esc(f.category)}</td>
    <td class="mono" style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(f.location||f.target)}</td>
    <td>${mitre}</td>
    <td style="text-align:right"><b>${(+f.score).toFixed(1)}</b></td></tr>`;
}

/* ---------------- drawer ---------------- */
window.UI = {
  closeDrawer(){
    $("#drawer").classList.remove("open");
    $("#drawer-backdrop").classList.remove("open");
  }
};
function openDrawer(f){
  const d = $("#drawer");
  $("#drawer-body").innerHTML = `
    <button class="x" onclick="UI.closeDrawer()">×</button>
    ${chip(f.severity)} <span class="muted" style="margin-left:8px">${esc(f.category)} · ${esc(f.scanner)} · score ${(+f.score).toFixed(1)}/10${f.cwe?" · "+esc(f.cwe):""}</span>
    <h2>${esc(f.title)}</h2>
    <div class="mono" style="margin-top:4px">${esc(f.location||f.target)}</div>
    <p style="margin-top:14px;color:var(--text)">${esc(f.description)}</p>
    ${f.evidence?`<div class="ev-box">${esc(f.evidence)}</div>`:""}
    <div class="fix-box"><b>Recommended fix:</b> ${esc(f.remediation)}</div>
    ${(f.mitre&&f.mitre.length)?`<div class="kv">
      <div class="k">MITRE ATT&CK</div>
      <div class="pills">${f.mitre.map(m=>`<span class="pill"><b>${esc(m)}</b> ${esc((MITRE_NAMES[m]||"").name||"")}</span>`).join("")}</div></div>`:""}
    ${(f.references&&f.references.length)?`<div class="kv"><div class="k">References</div><div class="ref">
      ${f.references.map(r=>`<a href="${esc(r)}" target="_blank" rel="noopener">${esc(r)}</a>`).join("")}</div></div>`:""}
    <div class="kv"><div class="k">First seen</div><div class="muted">scan ${esc(f.scan_id||"")} ${f.scan_label?`(${esc(f.scan_label)})`:""}</div></div>`;
  d.classList.add("open"); $("#drawer-backdrop").classList.add("open");
}
function bindDrawer(scopeSel){
  document.querySelectorAll(`${scopeSel} tr[data-finding]`).forEach(tr=>{
    tr.onclick = () => {
      const f = ALL_FINDINGS.find(x=>x.id===tr.dataset.finding) ||
                ((CURRENT_SCAN && CURRENT_SCAN.findings || []).find(x=>x.id===tr.dataset.finding));
      if(f) openDrawer(f);
    };
  });
}

/* ---------------- mitre matrix ---------------- */
let MITRE_NAMES = {};
Views.mitre = async (el) => {
  const d = await API.get("/api/mitre");
  MITRE_NAMES = d.techniques;
  // find counts per technique across all scans
  const scans = await API.get("/api/scans");
  const counts = {};
  await Promise.all(scans.map(async s=>{
    const r = await API.get(`/api/scans/${s.scan_id}`);
    (r.findings||[]).forEach(f=>(f.mitre||[]).forEach(m=>{ counts[m]=(counts[m]||0)+1; }));
  }));
  el.innerHTML = `
  <div class="card"><h3>ATT&amp;CK Enterprise matrix — techniques reachable through discovered weaknesses</h3>
  <div class="matrix">
    ${d.tactics.map(t=>{
      const techs = Object.entries(d.techniques).filter(([,v])=>v.tactic===t.id);
      return `<div class="tactic"><h5>${esc(t.name)}</h5>
        ${techs.map(([id,v])=>{
          const n = counts[id]||0;
          return `<div class="tech ${n?"":"empty"}" title="${esc(v.desc)}" ${n?`data-mitre="${esc(id)}"`:""}>
            <span class="tid">${esc(id)}</span>${n?`<span class="cnt">${n}</span>`:""}
            <div class="nm">${esc(v.name)}</div></div>`;
        }).join("")}</div>`;
    }).join("")}
  </div></div>`;
  document.querySelectorAll(".tech[data-mitre]").forEach(elm=>{
    elm.onclick = () => {
      const id = elm.dataset.mitre;
      Views.findings($("#view")).then(()=>{
        $("#f-q").value = id; $("#f-q").dispatchEvent(new Event("input"));
      });
    };
  });
};

/* ---------------- reports ---------------- */
Views.reports = async (el) => {
  el.innerHTML = `<div class="empty"><div class="big-ic">▤</div>Loading scans…</div>`;
  const scans = await API.get("/api/scans");
  const rows = scans.map(s=>{
    const t = (s.targets||[]).map(x=>x.value).join(", ");
    const c = s.counts||{};
    return `<tr>
      <td><div class="mono">${esc(t)}</div><div class="dim" style="font-size:12px">${esc(s.scan_id)} · ${new Date(s.started).toLocaleString()}</div></td>
      <td>${esc(s.label||"—")}</td>
      <td>${chip(s.status==="completed"?"pass":s.status==="running"?"info":"high").replace("PASS","done").replace("INFO","running").replace("HIGH",esc(s.status))}</td>
      <td>${["critical","high","medium","low","info"].filter(k=>c[k]).map(k=>`<span class="chip ${k}" style="margin:1px">${c[k]}</span>`).join(" ")||'<span class="dim">0</span>'}</td>
      <td>${s.tls_grade?`<span class="grade sm" style="color:${gradeColor(s.tls_grade)};border-color:${gradeColor(s.tls_grade)}">${esc(s.tls_grade)}</span>`:"—"}</td>
      <td style="white-space:nowrap">
        <a class="btn sm" href="/api/scans/${esc(s.scan_id)}/report?format=html" target="_blank">HTML</a>
        <a class="btn sm" href="/api/scans/${esc(s.scan_id)}/report?format=json" download>JSON</a>
        <a class="btn sm" href="/api/scans/${esc(s.scan_id)}/report?format=md" download>MD</a>
        <a class="btn sm" href="/api/scans/${esc(s.scan_id)}/report?format=sarif" download>SARIF</a>
        <button class="btn sm danger" data-del="${esc(s.scan_id)}">✕</button></td></tr>`;
  }).join("");
  el.innerHTML = `<div class="card" style="padding:6px 12px">
    ${rows?`<table class="tbl"><tr><th>Scan</th><th>Label</th><th>Status</th><th>Findings</th><th>TLS</th><th>Export</th></tr>${rows}</table>`
      :`<div class="empty"><div class="big-ic">▤</div>No scans yet.<div class="hero-cta"><button class="btn primary" onclick="location.hash='#/scan'">Run your first scan</button></div></div>`}
  </div>`;
  el.querySelectorAll("[data-del]").forEach(b=>{
    b.onclick = async ()=>{ await API.del(`/api/scans/${b.dataset.del}`); Views.reports(el); };
  });
};

/* ============================================================ router */
const TITLES = {"/":"Dashboard","/scan":"New Scan","/findings":"Findings Explorer",
  "/mitre":"MITRE ATT&CK Coverage","/reports":"Reports & Exports"};
let CURRENT_SCAN = null;

async function route(){
  UI.closeDrawer();
  const hash = location.hash.replace(/^#/, "") || "/";
  const [_, kind, arg] = hash.split("/");
  const path = "/" + (kind||"");
  document.querySelectorAll("#nav a").forEach(a=>a.classList.toggle("active", a.dataset.route===path));
  $("#page-title").textContent = (TITLES[path]||"AegisScan") + (arg&&kind==="scan"?` · ${arg}`:"");
  const el = $("#view");
  el.scrollTop = 0;
  try{
    if(kind==="scan" && arg){ CURRENT_SCAN = await API.get(`/api/scans/${arg}`); await Views.scanDetail(el, arg); }
    else if(Views[path.slice(1)]||Views.dashboard){ CURRENT_SCAN=null; await (Views[path.slice(1)]||Views.dashboard)(el); }
  }catch(e){
    el.innerHTML = `<div class="empty"><div class="big-ic">⚠</div>${esc(e.message)}</div>`;
  }
}
window.addEventListener("hashchange", route);

async function refreshBadge(){
  try{
    const d = await API.get("/api/dashboard");
    updateNavBadge(d.findings_total);
  }catch(e){}
}
function updateNavBadge(n){
  const b = $("#nav-findings");
  b.textContent = n||0;
  b.classList.toggle("hot", (n||0) > 0 && n >= 1);
}

(async function init(){
  try{ const m = await API.get("/api/meta"); $("#ver").textContent = `${m.product} v${m.version}`; }catch(e){}
  await route();
})();
