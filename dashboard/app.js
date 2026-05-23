// CERBERUS — Panel de Operación. Vanilla ES module: fetch + render + SVG charts.
const REFRESH_MS = 5000;
const $ = (id) => document.getElementById(id);
const SVGNS = "http://www.w3.org/2000/svg";

const SEV_COLOR = {
  CRITICAL: "var(--red)", HIGH: "#ff8a5c", MEDIUM: "var(--amber)",
  LOW: "var(--blue)", INFO: "var(--txt-dim)",
};
const SRC_COLOR = { proc: "#a78bfa", net: "#5cc8ff", fs: "#3ddc91", evt: "#ffb454" };

async function getJSON(path) {
  const r = await fetch(path, { headers: { Accept: "application/json" } });
  if (!r.ok) throw new Error(`${path} -> ${r.status}`);
  return r.json();
}

function setConn(ok) {
  const el = $("conn");
  el.classList.toggle("ok", ok);
  el.classList.toggle("bad", !ok);
  $("connText").textContent = ok ? "Conectado" : "Desconectado";
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

function badge(text, kind) {
  const b = el("span", `badge badge-${kind}`, text);
  return b;
}

function sevKind(sev) {
  return { CRITICAL: "red", HIGH: "red", MEDIUM: "amber", LOW: "blue", INFO: "mut" }[sev] || "mut";
}

// ---------- renderers ----------
function renderStatus(s) {
  $("version").textContent = "v" + s.version;
  const cols = s.collectors || {};
  const active = Object.values(cols).filter(Boolean).length;
  const total = Object.keys(cols).length;
  $("tActive").textContent = `${active}/${total}`;
  const healthy = active > 0 && !s.killswitch_active;
  $("kpiAgent").textContent = healthy ? "OK" : (s.killswitch_active ? "KILL" : "—");
  $("kpiAgentBadge").textContent = s.killswitch_active ? "Killswitch" : (healthy ? "Saludable" : "Revisar");
  $("kpiAgentBadge").className = "badge " + (s.killswitch_active ? "badge-red" : healthy ? "badge-green" : "badge-amber");
  $("kpiAgentFoot").textContent = `${active}/${total} collectors · integridad ${s.integrity_enabled ? "on" : "off"}`;

  // modo
  const mode = s.mode || "dry_run";
  $("kpiMode").textContent = mode;
  const modeKind = { dry_run: "gold", monitor: "blue", auto_critical: "amber", auto_all: "red" }[mode] || "mut";
  $("kpiModeBadge").textContent = s.killswitch_active ? "KILLSWITCH" : (mode.startsWith("auto") ? "Auto" : "Seguro");
  $("kpiModeBadge").className = "badge badge-" + (s.killswitch_active ? "red" : modeKind);
  $("kpiModeFoot").textContent = s.response_enabled ? "Respuesta habilitada" : "Respuesta deshabilitada";
}

function renderSummary(s) {
  $("kpiFindings").textContent = s.findings_total;
  const crit = (s.findings_by_severity || {}).CRITICAL || 0;
  const high = (s.findings_by_severity || {}).HIGH || 0;
  $("kpiFindingsBadge").textContent = `${crit} CRIT · ${high} HIGH`;
  $("kpiActions").textContent = `${s.actions_executed} / ${s.actions_total}`;
  $("kpiActionsBadge").textContent = s.actions_total ? `${Math.round(100 * s.actions_executed / s.actions_total)}%` : "0%";
  $("tEvents").textContent = s.events_total;
  $("rTotal").textContent = s.actions_total;
  $("rExec").textContent = s.actions_executed;
}

function renderFindings(items) {
  const ul = $("findingsList");
  ul.replaceChildren();
  $("dRuleFindings").textContent = items.filter((f) => (f.rule_ids || []).length).length;
  if (!items.length) { ul.append(el("li", "empty", "Sin findings todavía")); return; }
  for (const f of items.slice(0, 5)) {
    const li = el("li");
    const left = el("div", "li-main");
    left.append(el("p", "li-title", (f.rule_ids && f.rule_ids[0]) || "(sin regla)"));
    left.append(el("p", "li-sub", `pid ${f.pid ?? "—"} · ${(f.sources || []).join("/")}`));
    const right = el("div", "li-right");
    if (f.ai_family) right.append(badge(f.ai_family, "blue"));
    right.append(badge(f.severity, sevKind(f.severity)));
    li.append(left, right);
    ul.append(li);
  }
}

function renderCollectors(events, status) {
  const ul = $("collectorsList");
  ul.replaceChildren();
  const bySrc = events.by_source || {};
  const cols = (status && status.collectors) || {};
  const sources = ["proc", "net", "fs", "evt"];
  for (const src of sources) {
    const li = el("li");
    const left = el("div", "li-main");
    left.append(el("p", "li-title", src));
    left.append(el("p", "li-sub", `${bySrc[src] || 0} eventos`));
    const right = el("div", "li-right");
    right.append(badge(cols[src] ? "activo" : "off", cols[src] ? "green" : "mut"));
    li.append(left, right);
    ul.append(li);
  }
}

function renderActions(items) {
  const ul = $("actionsList");
  ul.replaceChildren();
  if (!items.length) { ul.append(el("li", "empty", "Sin acciones registradas")); return; }
  for (const a of items.slice(0, 5)) {
    const li = el("li");
    const left = el("div", "li-main");
    left.append(el("p", "li-title", a.action_type));
    left.append(el("p", "li-sub", `${a.policy_id} · ${a.mode}`));
    const right = el("div", "li-right");
    right.append(badge(a.executed ? "ejecutada" : a.reason, a.executed ? (a.success ? "green" : "red") : "mut"));
    li.append(left, right);
    ul.append(li);
  }
}

function renderMetrics(m) {
  $("mFindings").textContent = m.findings_total;
  $("mRules").textContent = m.distinct_rules;
  $("mAi").textContent = m.findings_with_ai;
  $("mAuto").textContent = m.auto_executed_pct + "%";
  $("dRules").textContent = m.distinct_rules;
}

function renderChart(events) {
  const data = events.timeline || [];
  const box = $("eventsChart");
  box.replaceChildren();
  const W = box.clientWidth || 600, H = box.clientHeight || 220;
  const svg = document.createElementNS(SVGNS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  if (!data.length) {
    const t = document.createElementNS(SVGNS, "text");
    t.setAttribute("x", "16"); t.setAttribute("y", "28"); t.setAttribute("fill", "var(--txt-dim)");
    t.setAttribute("font-size", "13"); t.textContent = "Sin eventos en el intervalo";
    svg.append(t); box.append(svg); return;
  }
  const pad = { l: 34, r: 12, t: 14, b: 22 };
  const max = Math.max(...data.map((d) => d.count), 1);
  const cw = (W - pad.l - pad.r) / data.length;
  // gridlines
  for (let i = 0; i <= 3; i++) {
    const y = pad.t + (H - pad.t - pad.b) * (i / 3);
    const line = document.createElementNS(SVGNS, "line");
    line.setAttribute("x1", pad.l); line.setAttribute("x2", W - pad.r);
    line.setAttribute("y1", y); line.setAttribute("y2", y);
    line.setAttribute("stroke", "rgba(255,255,255,.06)");
    svg.append(line);
    const lbl = document.createElementNS(SVGNS, "text");
    lbl.setAttribute("x", "6"); lbl.setAttribute("y", y + 4);
    lbl.setAttribute("fill", "var(--txt-dim)"); lbl.setAttribute("font-size", "10");
    lbl.textContent = Math.round(max * (1 - i / 3));
    svg.append(lbl);
  }
  // bars
  data.forEach((d, i) => {
    const bh = (H - pad.t - pad.b) * (d.count / max);
    const x = pad.l + i * cw + cw * 0.18;
    const y = H - pad.b - bh;
    const rect = document.createElementNS(SVGNS, "rect");
    rect.setAttribute("x", x); rect.setAttribute("y", y);
    rect.setAttribute("width", cw * 0.64); rect.setAttribute("height", Math.max(bh, 1));
    rect.setAttribute("rx", "4"); rect.setAttribute("fill", "url(#g)");
    svg.append(rect);
  });
  const defs = document.createElementNS(SVGNS, "defs");
  defs.innerHTML = `<linearGradient id="g" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="#a78bfa"/><stop offset="1" stop-color="#7c5cff" stop-opacity=".4"/></linearGradient>`;
  svg.append(defs);
  box.append(svg);
}

// ---------- refresh loop ----------
async function refresh() {
  try {
    const [status, summary, findings, events, actions, metrics] = await Promise.all([
      getJSON("/api/status"), getJSON("/api/summary"), getJSON("/api/findings?limit=10"),
      getJSON("/api/events"), getJSON("/api/actions?limit=10"), getJSON("/api/metrics"),
    ]);
    setConn(true);
    renderStatus(status);
    renderSummary(summary);
    renderFindings(findings.findings || []);
    renderCollectors(events, status);
    renderActions(actions.actions || []);
    renderMetrics(metrics);
    renderChart(events);
    $("updated").textContent = "Actualizado " + new Date().toLocaleTimeString();
  } catch (err) {
    setConn(false);
    $("updated").textContent = "Error de conexión: " + err.message;
  }
}

// ---------- ui wiring ----------
$("themeBtn").addEventListener("click", () => {
  const r = document.documentElement;
  const next = r.getAttribute("data-theme") === "dark" ? "light" : "dark";
  r.setAttribute("data-theme", next);
  $("themeBtn").textContent = next === "dark" ? "🌙" : "☀️";
});
$("collapseBtn").addEventListener("click", () => {
  document.querySelector(".app").classList.toggle("collapsed");
});
document.querySelectorAll(".nav-item[data-target]").forEach((a) => {
  a.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach((n) => n.classList.remove("active"));
    a.classList.add("active");
    const t = document.getElementById(a.dataset.target);
    if (t) t.scrollIntoView({ behavior: "smooth", block: "center" });
  });
});

refresh();
setInterval(refresh, REFRESH_MS);
