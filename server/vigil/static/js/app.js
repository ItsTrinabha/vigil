// Vigil analyst console: hash router + pages.
import { areaChart, hideTip, stackedColumns } from "./charts.js";
import {
  ago, api, debounce, flag, fmtBytes, fmtCompact, fmtNum, fmtTime, html, icon, jsonView, raw, riskBadge,
  SEV_VAR, SEVERITIES, sev, statusLabel, tacticLabel, toast,
} from "./lib.js";

const state = {
  user: null,
  range: localStorageGet("vigil.range") || "24h",
  openAlerts: 0,
};
const RANGES = ["15m", "1h", "6h", "24h", "7d", "30d"];
const NAV = [
  ["overview", "Overview"], ["alerts", "Alerts"], ["incidents", "Incidents"], ["search", "Hunt"],
  ["attack", "ATT&CK"], ["entities", "Entities (UEBA)"], null,
  ["rules", "Detection rules"], ["agents", "Agents"], ["intel", "Threat intel"], ["settings", "Settings"],
];

function localStorageGet(k) { try { return localStorage.getItem(k); } catch { return null; } }
function localStorageSet(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } }

const $app = document.getElementById("app");
let $content, $title;
let stream;

// ------------------------------------------------------------------ boot
(function initTheme() {
  const t = localStorageGet("vigil.theme");
  if (t) document.documentElement.dataset.theme = t;
})();

window.addEventListener("vigil:logout", () => { state.user = null; renderLogin(); });
window.addEventListener("hashchange", route);

boot();
async function boot() {
  try {
    state.user = await api("/api/auth/me");
    renderShell();
    route();
  } catch {
    renderLogin();
  }
}

function renderLogin(err = "") {
  if (stream) { stream.close(); stream = null; }
  $app.innerHTML = html`<div class="login"><form class="box" id="login">
    <div class="brand"><img src="/static/favicon.svg" alt=""><div>Vigil<small>Security monitoring</small></div></div>
    <label class="field">Username<input class="input" name="username" autocomplete="username" required autofocus></label>
    <label class="field">Password<input class="input" name="password" type="password" autocomplete="current-password" required></label>
    <div class="err">${err}</div>
    <button class="btn primary" type="submit" style="justify-content:center;padding:9px">Sign in</button>
    <div class="muted" style="font-size:12px;text-align:center">First run? The admin password is printed in the server log and saved to <code>initial_admin_password.txt</code> in the data volume.</div>
  </form></div>`.s;
  document.getElementById("login").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    try {
      state.user = await api("/api/auth/login", { method: "POST", body: { username: f.get("username"), password: f.get("password") } });
      renderShell();
      if (!location.hash || location.hash === "#/") location.hash = "#/overview"; else route();
    } catch (ex) {
      renderLogin(ex.message);
    }
  });
}

function renderShell() {
  $app.innerHTML = html`<div class="shell">
    <aside class="sidebar">
      <div class="brand"><img src="/static/favicon.svg" alt=""><div>Vigil<small>SIEM · v1.0</small></div></div>
      <nav class="nav">${NAV.map((n) => n ? html`<a href="#/${n[0]}" data-nav="${n[0]}">${icon(n[0])}<span>${n[1]}</span>${n[0] === "alerts" ? html`<span class="count" id="open-count" hidden></span>` : ""}</a>` : html`<div class="nav-sep"></div>`)}</nav>
      <div class="foot">Signed in as <b>${state.user.username}</b> (${state.user.role})</div>
    </aside>
    <div class="main">
      <header class="topbar">
        <span class="title" id="page-title"></span>
        <span class="spacer"></span>
        <span class="live off" id="live"><span class="dot"></span><span id="eps">connecting…</span></span>
        <div class="seg" id="range">${RANGES.map((r) => html`<button data-r="${r}" class="${r === state.range ? "on" : ""}">${r}</button>`)}</div>
        <button class="btn small" id="theme" title="Toggle light/dark theme" aria-label="Toggle theme">${icon("theme")}</button>
        <button class="btn small" id="logout" title="Sign out" aria-label="Sign out">${icon("logout")}</button>
      </header>
      <main class="content" id="content"></main>
    </div></div>`.s;
  $content = document.getElementById("content");
  $title = document.getElementById("page-title");
  document.getElementById("range").addEventListener("click", (e) => {
    const r = e.target.dataset.r;
    if (!r) return;
    state.range = r;
    localStorageSet("vigil.range", r);
    document.querySelectorAll("#range button").forEach((b) => b.classList.toggle("on", b.dataset.r === r));
    route();
  });
  document.getElementById("theme").addEventListener("click", () => {
    const t = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    document.documentElement.dataset.theme = t;
    localStorageSet("vigil.theme", t);
    route();
  });
  document.getElementById("logout").addEventListener("click", async () => {
    await api("/api/auth/logout", { method: "POST" }).catch(() => {});
    state.user = null;
    renderLogin();
  });
  connectStream();
  refreshOpenCount();
}

function connectStream() {
  if (stream) stream.close();
  stream = new EventSource("/api/stream");
  const live = document.getElementById("live");
  stream.onopen = () => {
    live?.classList.remove("off");
    const el = document.getElementById("eps");
    if (el && el.textContent.startsWith("connecting")) el.textContent = "Live";
  };
  stream.onerror = () => live?.classList.add("off");
  stream.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.kind === "stats") {
      const el = document.getElementById("eps");
      if (el) el.textContent = `Live · ${msg.data.eps} events/s`;
    } else if (msg.kind === "alert") {
      const a = msg.data;
      refreshOpenCount();
      if (["medium", "high", "critical"].includes(a.severity)) {
        const t = toast(`${a.severity.toUpperCase()} · ${a.rule_title}`, [a.host, a.src_ip, a.user_name].filter(Boolean).join(" · "), SEV_VAR[a.severity]);
        t.addEventListener("click", () => { location.hash = `#/alerts/${a.id}`; });
      }
    } else if (msg.kind === "incident") {
      const i = msg.data;
      const t = toast(`Incident #${i.id} · ${i.severity.toUpperCase()}`, i.title, SEV_VAR[i.severity]);
      t.addEventListener("click", () => { location.hash = `#/incidents/${i.id}`; });
    }
  };
}

const refreshOpenCount = debounce(async () => {
  try {
    const r = await api("/api/alerts", { query: { status: "open", limit: 1, range: "30d" } });
    const el = document.getElementById("open-count");
    if (el) { el.hidden = !r.total; el.textContent = fmtCompact(r.total); }
  } catch { /* ignore */ }
}, 800);

// ------------------------------------------------------------------ router
const ROUTES = [
  [/^overview$/, pageOverview], [/^alerts$/, pageAlerts], [/^alerts\/(\d+)$/, pageAlert],
  [/^incidents$/, pageIncidents], [/^incidents\/(\d+)$/, pageIncident], [/^search$/, pageSearch],
  [/^attack$/, pageAttack], [/^entities$/, pageEntities], [/^entities\/(.+)$/, pageEntity],
  [/^rules$/, pageRules], [/^rules\/(.+)$/, pageRule], [/^agents$/, pageAgents], [/^intel$/, pageIntel],
  [/^settings$/, pageSettings],
];

async function route() {
  if (!state.user || !$content) return;
  hideTip();
  const [path, qs] = (location.hash.replace(/^#\/?/, "") || "overview").split("?");
  const params = new URLSearchParams(qs || "");
  const section = path.split("/")[0];
  document.querySelectorAll("[data-nav]").forEach((a) => a.classList.toggle("active", a.dataset.nav === section));
  for (const [rx, fn] of ROUTES) {
    const m = path.match(rx);
    if (m) {
      $content.innerHTML = '<div class="empty">Loading…</div>';
      try {
        await fn(...m.slice(1).map(decodeURIComponent), params);
      } catch (e) {
        if (e.status !== 401) $content.innerHTML = html`<div class="card empty">Could not load this page: ${e.message}</div>`.s;
      }
      return;
    }
  }
  location.hash = "#/overview";
}

function setPage(title, body) {
  $title.textContent = title;
  document.title = `${title} · Vigil`;
  $content.innerHTML = body.s;
}
const on = (sel, ev, fn) => $content.querySelectorAll(sel).forEach((el) => el.addEventListener(ev, fn));
const rowLinks = () => on("tr[data-href]", "click", (e) => {
  if (e.target.closest("input,button,a")) return;
  location.hash = e.currentTarget.dataset.href;
});
const tactics = (list) => html`<div class="chain">${(list || []).map((t, i) => html`${i ? html`<span class="arrow">›</span>` : ""}<span class="step">${tacticLabel(t)}</span>`)}</div>`;
const techChips = (list) => html`${(list || []).map((t) => html`<a class="pill accent tech" target="_blank" rel="noopener" href="https://attack.mitre.org/techniques/${t.replace(".", "/")}/">${t}</a> `)}`;
const ipLink = (ip, cc) => ip ? html`<a href="#/search?q=${encodeURIComponent(`source.ip:${ip}`)}" class="mono">${cc ? html`<span class="flag">${flag(cc)}</span> ` : ""}${ip}</a>` : html`<span class="muted">—</span>`;

// ------------------------------------------------------------------ overview
async function pageOverview() {
  const d = await api("/api/overview", { query: { range: state.range } });
  const sevTotal = SEVERITIES.reduce((a, s) => a + (d.alerts_by_severity[s] || 0), 0);
  const maxTac = Math.max(1, ...d.tactics.map((t) => t.count));
  const maxSrc = Math.max(1, ...d.top_sources.map((s) => s.n));
  const maxCountry = Math.max(1, ...d.countries.map((c) => c.n));
  setPage("Overview", html`
    <div class="grid g-6">
      ${statTile("Events ingested", fmtCompact(d.events_total), `${d.eps} events/s now`)}
      ${statTile("Alerts", fmtNum(sevTotal), html`<span class="sev critical">${d.alerts_by_severity.critical || 0}</span> <span class="sev high">${d.alerts_by_severity.high || 0}</span> <span class="sev medium">${d.alerts_by_severity.medium || 0}</span>`)}
      ${statTile("Open incidents", fmtNum(d.open_incidents), `${fmtNum(d.open_alerts)} open alerts`, "#/incidents")}
      ${statTile("Failed logins", fmtCompact(d.auth.failed), `${fmtCompact(d.auth.success)} successful`)}
      ${statTile("Agents healthy", `${d.agents.healthy}/${d.agents.total}`, d.agents.total ? "reporting in" : "no agents enrolled yet", "#/agents")}
      ${statTile("Detections loaded", fmtNum(d.rules.sigma + d.rules.correlation), `${fmtNum(d.rules.sigma)} Sigma · ${d.rules.correlation} correlation`, "#/rules")}
    </div>
    <div class="grid g-2">
      <div class="card"><div class="card-head"><h2>Event volume</h2><span class="right muted">${d.range.bucket >= 3600 ? `${d.range.bucket / 3600}h` : `${Math.round(d.range.bucket / 60)}m`} buckets</span></div><div class="chart" id="ch-events"></div></div>
      <div class="card"><div class="card-head"><h2>Alerts by severity</h2><div class="right legend">${["critical", "high", "medium", "low"].map((s) => html`<span><i style="background:${raw(SEV_VAR[s])}"></i>${s}</span>`)}</div></div><div class="chart" id="ch-alerts"></div></div>
    </div>
    <div class="grid g-21">
      <div class="card"><div class="card-head"><h2>Open incidents</h2><a class="right" href="#/incidents">View all</a></div>
        ${d.incidents.length ? html`<div class="grid g-2">${d.incidents.map(incCard)}</div>` : html`<div class="empty">No open incidents. Vigil groups related alerts here.</div>`}
      </div>
      <div class="card"><div class="card-head"><h2>Top source IPs</h2></div>
        ${d.top_sources.length ? d.top_sources.map((s) => html`<div class="hbar"><span class="name">${ipLink(s.ip, s.country)} ${s.intel.length ? html`<span class="pill danger" title="${s.intel.join(", ")}">intel</span>` : ""}</span><span class="track"><span class="fill" style="width:${(100 * s.n) / maxSrc}%"></span></span><span class="num">${fmtCompact(s.n)}</span></div>`) : html`<div class="empty">No external sources yet</div>`}
      </div>
    </div>
    <div class="card"><div class="card-head"><h2>MITRE ATT&amp;CK tactics observed</h2><a class="right" href="#/attack">Open matrix</a></div>
      <div class="tactic-strip">${d.tactics.map((t) => html`<div class="t ${t.count ? `heat-${Math.min(5, 1 + Math.floor((4 * t.count) / maxTac))}` : ""}" title="${t.count} alerts"><span>${t.name}</span><b>${t.count || ""}</b></div>`)}</div>
    </div>
    <div class="grid g-2">
      <div class="card"><div class="card-head"><h2>Top detections</h2><a class="right" href="#/alerts">All alerts</a></div>
        ${d.top_rules.length ? html`<div class="list">${d.top_rules.map((r) => html`<div class="row">${sev(r.severity)}<span class="grow">${r.rule_title}</span><span class="muted">${fmtNum(r.alerts)} alerts · ${fmtCompact(r.hits)} hits</span></div>`)}</div>` : html`<div class="empty">No detections in this time range</div>`}
      </div>
      <div class="card"><div class="card-head"><h2>Source countries</h2><span class="right muted">from offline GeoIP</span></div>
        ${d.countries.length ? d.countries.map((c) => html`<div class="hbar"><span class="name"><span class="flag">${flag(c.country)}</span> ${c.country}</span><span class="track"><span class="fill" style="width:${(100 * c.n) / maxCountry}%"></span></span><span class="num">${fmtCompact(c.n)}</span></div>`) : html`<div class="empty">No geolocated sources yet</div>`}
      </div>
    </div>`);
  const start = d.range.start, step = d.range.bucket;
  areaChart(document.getElementById("ch-events"), { values: d.events_series, start, step, label: "Events" });
  stackedColumns(document.getElementById("ch-alerts"), {
    start, step, series: ["low", "medium", "high", "critical"].map((s) => ({ label: s, color: SEV_VAR[s], values: d.alerts_series[s] })),
  });
}
function statTile(label, value, hint, href) {
  const inner = html`<div class="stat"><span class="label">${label}</span><span class="value">${value}</span><span class="hint">${hint}</span></div>`;
  return href ? html`<a class="card" href="${href}" style="color:inherit;text-decoration:none">${inner}</a>` : html`<div class="card">${inner}</div>`;
}
function incCard(i) {
  return html`<a class="inc-card" href="#/incidents/${i.id}">
    <div class="toolbar">${sev(i.severity)}${riskBadge(i.risk)}<span class="muted" style="margin-left:auto">${ago(i.last_ts)}</span></div>
    <div class="t">#${i.id} ${i.title}</div>
    ${tactics(i.tactics)}
    <div class="muted" style="font-size:12px;margin-top:6px">${i.alert_count} alerts · ${[...(i.entities.ip || []), ...(i.entities.user || [])].slice(0, 4).join(", ")}</div></a>`;
}

// ------------------------------------------------------------------ alerts
async function pageAlerts(params) {
  const f = { status: params.get("status") ?? "open", severity: params.get("severity") || "", q: params.get("q") || "", rule_type: params.get("type") || "" };
  const offset = +(params.get("offset") || 0);
  const r = await api("/api/alerts", { query: { ...f, range: state.range, limit: 50, offset } });
  const canTriage = state.user.role !== "viewer";
  const qs = (o) => "#/alerts?" + new URLSearchParams({ ...f, ...o }).toString();
  setPage("Alerts", html`
    <div class="page-head"><h1>Alerts</h1><span class="sub">${fmtNum(r.total)} matching · last ${state.range}</span></div>
    <div class="card"><div class="toolbar">
      <div class="seg">${[["open", "Open"], ["new", "New"], ["in_progress", "In progress"], ["closed", "Closed"], ["", "All"]].map(([v, l]) => html`<button class="${f.status === v ? "on" : ""}" data-status="${v}">${l}</button>`)}</div>
      <div class="seg">${["", ...SEVERITIES.slice(0, 4)].map((s) => html`<button class="${f.severity === s ? "on" : ""}" data-sev="${s}">${s || "Any severity"}</button>`)}</div>
      <select class="input" id="type"><option value="">All sources</option>${["sigma", "correlation", "ueba", "threatintel", "system"].map((t) => html`<option ${f.rule_type === t ? "selected" : ""}>${t}</option>`)}</select>
      <input class="input" id="q" placeholder="Filter by rule, host, user, IP" value="${f.q}" style="flex:1;min-width:200px">
      ${canTriage ? html`<button class="btn" id="bulk-progress" disabled>Mark in progress</button><button class="btn" id="bulk-close" disabled>Close as benign</button>` : ""}
    </div></div>
    <div class="card flush"><div class="table-wrap"><table>
      <thead><tr>${canTriage ? html`<th style="width:28px"><input type="checkbox" id="all" aria-label="Select all"></th>` : ""}<th>Severity</th><th>Risk</th><th>Alert</th><th>Host</th><th>Source</th><th>User</th><th>ATT&amp;CK</th><th>Hits</th><th>Status</th><th class="nowrap">Last seen</th></tr></thead>
      <tbody>${r.items.map((a) => html`<tr class="click" data-href="#/alerts/${a.id}">
        ${canTriage ? html`<td><input type="checkbox" class="sel" value="${a.id}" aria-label="Select alert ${a.id}"></td>` : ""}
        <td>${sev(a.severity)}</td><td>${riskBadge(a.risk)}</td>
        <td><b>${a.rule_title}</b><div class="muted" style="font-size:12px">${a.rule_type}${a.incident_id ? html` · incident #${a.incident_id}` : ""}</div></td>
        <td>${a.host || "—"}</td><td>${ipLink(a.src_ip)}</td><td>${a.user_name || "—"}</td>
        <td>${a.techniques.slice(0, 2).map((t) => html`<span class="pill tech">${t}</span> `)}</td>
        <td>${fmtNum(a.count)}</td><td>${statusLabel(a.status)}${a.assignee ? html`<div class="muted" style="font-size:12px">${a.assignee}</div>` : ""}</td>
        <td class="nowrap muted">${ago(a.last_ts)}</td></tr>`)}</tbody></table>
      ${r.items.length ? "" : html`<div class="empty">No alerts match these filters.</div>`}
    </div></div>
    <div class="toolbar">${offset > 0 ? html`<a class="btn" href="${qs({ offset: Math.max(0, offset - 50) })}">Previous</a>` : ""}${offset + 50 < r.total ? html`<a class="btn" href="${qs({ offset: offset + 50 })}">Next</a>` : ""}</div>`);
  rowLinks();
  on("[data-status]", "click", (e) => { location.hash = qs({ status: e.target.dataset.status, offset: 0 }); });
  on("[data-sev]", "click", (e) => { location.hash = qs({ severity: e.target.dataset.sev, offset: 0 }); });
  on("#type", "change", (e) => { location.hash = qs({ type: e.target.value, offset: 0 }); });
  on("#q", "keydown", (e) => { if (e.key === "Enter") location.hash = qs({ q: e.target.value, offset: 0 }); });
  const sel = () => [...$content.querySelectorAll(".sel:checked")].map((c) => +c.value);
  const upd = () => { const n = sel().length; ["#bulk-progress", "#bulk-close"].forEach((s) => { const b = $content.querySelector(s); if (b) b.disabled = !n; }); };
  on(".sel", "change", upd);
  on("#all", "change", (e) => { $content.querySelectorAll(".sel").forEach((c) => { c.checked = e.target.checked; }); upd(); });
  const bulk = async (body) => { await api("/api/alerts/bulk", { method: "POST", body: { ids: sel(), ...body } }); toast("Alerts updated", `${sel().length} alerts`); route(); refreshOpenCount(); };
  on("#bulk-progress", "click", () => bulk({ status: "in_progress", assignee: state.user.username }));
  on("#bulk-close", "click", () => bulk({ status: "closed", resolution: "benign" }));
}

async function usersList() {
  if (state.user.role !== "admin") return [state.user.username];
  try { return (await api("/api/users")).filter((u) => !u.disabled).map((u) => u.username); } catch { return [state.user.username]; }
}

function triageControls(obj, users) {
  if (state.user.role === "viewer") return "";
  return html`<div class="triage">
    <label class="field">Status<select class="input" id="t-status">${["new", "in_progress", "closed"].map((s) => html`<option value="${s}" ${obj.status === s ? "selected" : ""}>${s.replace("_", " ")}</option>`)}</select></label>
    <label class="field">Resolution<select class="input" id="t-res"><option value="">—</option>${[["true_positive", "True positive"], ["false_positive", "False positive"], ["benign", "Benign / expected"]].map(([v, l]) => html`<option value="${v}" ${obj.resolution === v ? "selected" : ""}>${l}</option>`)}</select></label>
    <label class="field">Assignee<select class="input" id="t-assignee"><option value="">Unassigned</option>${[...new Set([...users, obj.assignee].filter(Boolean))].map((u) => html`<option ${obj.assignee === u ? "selected" : ""}>${u}</option>`)}</select></label>
    <button class="btn primary" id="t-save">Save</button>
    <button class="btn" id="t-mine">Assign to me</button></div>`;
}
function bindTriage(kind, id) {
  const save = async (extra = {}) => {
    const body = { status: $content.querySelector("#t-status").value, resolution: $content.querySelector("#t-res").value, assignee: $content.querySelector("#t-assignee").value, ...extra };
    await api(`/api/${kind}/${id}`, { method: "PATCH", body });
    toast("Saved", `${kind.slice(0, -1)} #${id} updated`);
    refreshOpenCount();
    route();
  };
  on("#t-save", "click", () => save());
  on("#t-mine", "click", () => save({ assignee: state.user.username, status: "in_progress" }));
}
function commentsBlock(comments) {
  return html`<div class="card"><h2>Notes</h2>
    ${comments.length ? comments.map((c) => html`<div class="comment"><div class="by"><b>${c.author}</b> · ${fmtTime(c.ts)}</div><p>${c.body}</p></div>`) : html`<div class="muted" style="margin-bottom:10px">No notes yet. Record what you checked and what you concluded.</div>`}
    ${state.user.role !== "viewer" ? html`<textarea class="input" id="c-body" rows="3" placeholder="Add an investigation note"></textarea><div style="margin-top:8px"><button class="btn" id="c-add">Add note</button></div>` : ""}</div>`;
}
function bindComments(kind, id) {
  on("#c-add", "click", async () => {
    const body = $content.querySelector("#c-body").value.trim();
    if (!body) return;
    await api(`/api/${kind}/${id}/comments`, { method: "POST", body: { body } });
    route();
  });
}

function eventsTable(events, compact = false) {
  if (!events.length) return html`<div class="empty">No raw events attached.</div>`;
  return html`<div class="table-wrap"><table><thead><tr><th class="nowrap">Time</th><th>Host</th><th>Action</th><th>Raw event</th></tr></thead><tbody>
    ${events.map((e) => html`<tr class="click" data-ev="${e.id}"><td class="nowrap mono">${fmtTime(e.ts)}</td><td>${e.host || ""}</td><td><span class="pill">${e.fields["event.action"] || "log"}</span></td><td class="msg">${(e.message || "").slice(0, compact ? 200 : 600)}</td></tr>
    <tr class="ev-detail" data-evd="${e.id}" hidden><td colspan="4">${jsonView(e.fields)}</td></tr>`)}</tbody></table></div>`;
}
const bindEventRows = () => on("tr[data-ev]", "click", (e) => {
  const d = $content.querySelector(`tr[data-evd="${e.currentTarget.dataset.ev}"]`);
  if (d) d.hidden = !d.hidden;
});

function ipCard(ctx) {
  if (!ctx) return "";
  const g = ctx.geo || {};
  return html`<div class="card"><h2>Source IP context</h2><dl class="kv">
    <dt>IP</dt><dd>${ipLink(ctx.ip, g["geo.country_iso_code"])}</dd>
    <dt>Network</dt><dd>${g["network.type"] || "—"}${g["as.number"] ? html` · AS${g["as.number"]} ${g["as.organization.name"] || ""}` : ""}</dd>
    <dt>Location</dt><dd>${g["geo.city_name"] ? `${g["geo.city_name"]}, ` : ""}${g["geo.country_iso_code"] || "—"}</dd>
    <dt>Threat intel</dt><dd>${ctx.intel.length ? ctx.intel.map((h) => html`<span class="pill danger">${h.feed}</span> `) : html`<span class="muted">not listed on loaded feeds</span>`}</dd>
    <dt>Activity</dt><dd>${fmtNum(ctx.events)} events · ${fmtNum(ctx.failures)} failures · ${fmtNum(ctx.successes)} successes · ${fmtNum(ctx.alerts)} alerts</dd>
    <dt>First / last seen</dt><dd>${fmtTime(ctx.first_seen)} → ${fmtTime(ctx.last_seen)}</dd>
    <dt>Usernames tried</dt><dd>${ctx.users.length ? ctx.users.map((u) => html`<span class="pill">${u.user_name} · ${u.n}</span> `) : "—"}</dd>
  </dl></div>`;
}

async function pageAlert(id) {
  const [a, users] = await Promise.all([api(`/api/alerts/${id}`), usersList()]);
  const ipctx = a.src_ip ? await api(`/api/ip/${encodeURIComponent(a.src_ip)}`).catch(() => null) : null;
  const d = a.details || {};
  const factors = d.factors || [];
  const maxBits = Math.max(1, ...factors.map((f) => f.bits));
  setPage(`Alert #${a.id}`, html`
    <div><a href="#/alerts" class="muted">${icon("back")} Alerts</a></div>
    <div class="card"><div class="detail-head"><div style="flex:1;min-width:260px">
      <div class="toolbar">${sev(a.severity)}${riskBadge(a.risk)}<span class="pill">${a.rule_type}</span>${statusLabel(a.status)}${a.resolution ? html`<span class="pill">${a.resolution.replace("_", " ")}</span>` : ""}</div>
      <h1 style="margin-top:8px">${a.rule_title}</h1>
      <div class="meta"><span>First ${fmtTime(a.first_ts)}</span><span>Last ${fmtTime(a.last_ts)}</span><span>${fmtNum(a.count)} occurrence${a.count > 1 ? "s" : ""}</span>${a.incident ? html`<a href="#/incidents/${a.incident.id}">Part of incident #${a.incident.id}</a>` : ""}</div>
    </div>${triageControls(a, users)}</div></div>
    <div class="grid g-21">
      <div class="grid" style="align-content:start">
        <div class="card"><h2>What happened</h2>
          <p class="secondary" style="margin-top:0;white-space:pre-wrap">${d.description || a.rule?.description || "No description."}</p>
          <dl class="kv">
            <dt>Host</dt><dd>${a.host || "—"}</dd><dt>User</dt><dd>${a.user_name || "—"}</dd><dt>Source IP</dt><dd>${ipLink(a.src_ip)}</dd>
            ${d.correlation_type ? html`<dt>Correlation</dt><dd>${d.correlation_type.replace("_", " ")} within ${Math.round(d.timespan_s / 60)} min${d.event_count ? ` · ${d.event_count} events` : ""}${d.value_count ? ` · ${d.value_count} distinct ${d.field}` : ""}</dd>` : ""}
            ${d.values ? html`<dt>Distinct values</dt><dd>${d.values.map((v) => html`<span class="pill">${v}</span> `)}</dd>` : ""}
            ${d.sequence ? html`<dt>Sequence</dt><dd>${d.sequence.join(" → ")}</dd>` : ""}
            ${d.group && Object.keys(d.group).length ? html`<dt>Grouped by</dt><dd>${Object.entries(d.group).map(([k, v]) => html`<span class="pill mono">${k}=${v}</span> `)}</dd>` : ""}
            ${d.feeds ? html`<dt>Intel feeds</dt><dd>${d.feeds.map((f) => html`<span class="pill danger">${f}</span> `)}</dd>` : ""}
          </dl></div>
        ${factors.length ? html`<div class="card"><h2>Why this is anomalous</h2><p class="muted" style="margin-top:0">Each factor is scored in bits of surprise against the baseline Vigil learned for ${d.entity}. Risk ${d.risk}/100.</p>
          ${factors.map((f) => html`<div class="factor"><div><b>${f.feature.replace(/_/g, " ")}</b><div class="secondary">${f.detail}</div></div><div><div class="bar"><i style="width:${(100 * f.bits) / maxBits}%"></i></div><div class="muted" style="font-size:11px;text-align:right">${f.bits} bits</div></div></div>`)}
          <div style="margin-top:10px"><a href="#/entities/${encodeURIComponent(d.entity)}">Open entity profile</a></div></div>` : ""}
        <div class="card flush"><div class="card-head"><h2>Evidence (${a.events.length} events)</h2><span class="right muted">click a row for all fields</span></div>${eventsTable(a.events)}</div>
        ${commentsBlock(a.comments)}
      </div>
      <div class="grid" style="align-content:start">
        <div class="card"><h2>MITRE ATT&amp;CK</h2>
          ${a.tactics.length ? html`<div style="margin-bottom:10px">${tactics(a.tactics)}</div>` : ""}
          ${(d.technique_details || []).length ? html`<div class="list">${d.technique_details.map((t) => html`<div class="row"><a class="tech" target="_blank" rel="noopener" href="${t.url}">${t.id}</a><span class="grow">${t.parent_name ? `${t.parent_name}: ` : ""}${t.name}</span></div>`)}</div>` : html`<div class="muted">No technique mapping</div>`}
        </div>
        ${ipCard(ipctx)}
        ${a.rule ? html`<div class="card"><h2>Detection rule</h2><dl class="kv"><dt>Rule</dt><dd><a href="#/rules/${encodeURIComponent(a.rule.id)}">${a.rule.title}</a></dd><dt>Type</dt><dd>${a.rule.type}</dd><dt>Level</dt><dd>${sev(a.rule.level)}</dd>${a.rule.author ? html`<dt>Author</dt><dd>${a.rule.author}</dd>` : ""}${a.rule.falsepositives?.length ? html`<dt>False positives</dt><dd>${a.rule.falsepositives.join("; ")}</dd>` : ""}</dl></div>` : ""}
        ${a.history.length ? html`<div class="card"><h2>History</h2><div class="timeline">${a.history.map((h) => html`<div class="item"><div class="when">${fmtTime(h.ts)}</div><div><b>${h.actor}</b> ${h.action.replace("_", " ")} <span class="muted">${h.details || ""}</span></div></div>`)}</div></div>` : ""}
      </div>
    </div>`);
  bindTriage("alerts", a.id);
  bindComments("alerts", a.id);
  bindEventRows();
}

// ------------------------------------------------------------------ incidents
async function pageIncidents(params) {
  const status = params.get("status") ?? "open";
  const r = await api("/api/incidents", { query: { status, range: state.range, limit: 100 } });
  setPage("Incidents", html`
    <div class="page-head"><h1>Incidents</h1><span class="sub">Related alerts grouped by shared attacker IP or user and host</span>
      <div class="seg" style="margin-left:auto">${[["open", "Open"], ["closed", "Closed"], ["", "All"]].map(([v, l]) => html`<button class="${status === v ? "on" : ""}" data-status="${v}">${l}</button>`)}</div></div>
    <div class="card flush"><div class="table-wrap"><table><thead><tr><th>Severity</th><th>Risk</th><th>Incident</th><th>Kill chain</th><th>Entities</th><th>Alerts</th><th>Status</th><th class="nowrap">Last activity</th></tr></thead><tbody>
      ${r.items.map((i) => html`<tr class="click" data-href="#/incidents/${i.id}"><td>${sev(i.severity)}</td><td>${riskBadge(i.risk)}</td>
        <td><b>#${i.id} ${i.title}</b><div class="muted" style="font-size:12px">${fmtTime(i.first_ts)} → ${fmtTime(i.last_ts, false)}</div></td>
        <td>${tactics(i.tactics)}</td><td class="mono" style="font-size:12px">${[...(i.entities.ip || []), ...(i.entities.host || [])].slice(0, 3).join(", ")}</td>
        <td>${i.alert_count}</td><td>${statusLabel(i.status)}${i.assignee ? html`<div class="muted" style="font-size:12px">${i.assignee}</div>` : ""}</td><td class="nowrap muted">${ago(i.last_ts)}</td></tr>`)}
    </tbody></table>${r.items.length ? "" : html`<div class="empty">No incidents in this view.</div>`}</div></div>`);
  rowLinks();
  on("[data-status]", "click", (e) => { location.hash = `#/incidents?status=${e.target.dataset.status}`; });
}

async function pageIncident(id) {
  const [inc, users] = await Promise.all([api(`/api/incidents/${id}`), usersList()]);
  const tacs = await api("/api/attack", { query: { range: "30d" } }).then((m) => m.matrix.map((t) => [t.short, t.name])).catch(() => []);
  const items = [
    ...inc.alerts.map((a) => ({ ts: a.first_ts, kind: "alert", a })),
  ].sort((x, y) => x.ts - y.ts);
  setPage(`Incident #${inc.id}`, html`
    <div><a href="#/incidents" class="muted">${icon("back")} Incidents</a></div>
    <div class="card"><div class="detail-head"><div style="flex:1;min-width:260px">
      <div class="toolbar">${sev(inc.severity)}${riskBadge(inc.risk)}${statusLabel(inc.status)}${inc.resolution ? html`<span class="pill">${inc.resolution.replace("_", " ")}</span>` : ""}</div>
      <h1 style="margin-top:8px">#${inc.id} ${inc.title}</h1>
      <div class="meta"><span>${fmtTime(inc.first_ts)} → ${fmtTime(inc.last_ts)}</span><span>${inc.alert_count} alerts</span><span>${inc.techniques.length} techniques</span></div>
    </div>${triageControls(inc, users)}</div></div>
    <div class="card"><h2>Kill-chain progression</h2><div class="killchain">${tacs.map(([s, n]) => html`<div class="${inc.tactics.includes(s) ? "on" : ""}">${n}</div>`)}</div></div>
    <div class="grid g-21">
      <div class="grid" style="align-content:start">
        <div class="card"><h2>Attack timeline</h2><div class="timeline">${items.map(({ a }) => html`<div class="item" style="--c:${raw(SEV_VAR[a.severity])}">
          <div class="when">${fmtTime(a.first_ts)}${a.count > 1 ? ` · ×${a.count}` : ""}</div>
          <div><a href="#/alerts/${a.id}"><b>${a.rule_title}</b></a> ${sev(a.severity)}</div>
          <div class="secondary" style="font-size:12.5px">${[a.host, a.src_ip, a.user_name].filter(Boolean).join(" · ")} ${a.techniques.map((t) => html`<span class="pill tech">${t}</span> `)}</div></div>`)}</div></div>
        <div class="card flush"><div class="card-head"><h2>Raw evidence (${inc.events.length} events)</h2></div>${eventsTable(inc.events, true)}</div>
        ${commentsBlock(inc.comments)}
      </div>
      <div class="grid" style="align-content:start">
        <div class="card"><h2>Entities</h2><dl class="kv">
          <dt>Source IPs</dt><dd>${(inc.entities.ip || []).map((ip) => html`${ipLink(ip)} `) || "—"}</dd>
          <dt>Users</dt><dd>${(inc.entities.user || []).map((u) => html`<a class="pill" href="#/entities/${encodeURIComponent(`user:${u}`)}">${u}</a> `)}</dd>
          <dt>Hosts</dt><dd>${(inc.entities.host || []).map((h) => html`<span class="pill">${h}</span> `)}</dd></dl></div>
        ${Object.values(inc.ip_context).map(ipCard)}
        <div class="card"><h2>Techniques</h2><div class="list">${inc.technique_details.map((t) => html`<div class="row"><a class="tech" target="_blank" rel="noopener" href="${t.url}">${t.id}</a><span class="grow">${t.name}</span></div>`)}</div></div>
      </div>
    </div>`);
  bindTriage("incidents", inc.id);
  bindComments("incidents", inc.id);
  bindEventRows();
}

// ------------------------------------------------------------------ search
const EXAMPLES = [
  "event.action:ssh_login_failed | stats count by source.ip",
  "event.action:ssh_login_success | table @timestamp, user.name, source.ip, source.geo.country_iso_code",
  "http.response.status_code>=400 | top url.path",
  "log.category:process_creation | top process.executable",
  "threat.indicator.matched:true | stats count by source.ip, threat.indicator.feeds",
  '"Accepted publickey"',
  "user.name:root NOT event.outcome:success",
  "source.ip:10.0.0.0/8",
];
const FIELDS = ["host.name", "event.action", "event.outcome", "user.name", "source.ip", "source.geo.country_iso_code",
  "source.as.organization.name", "log.category", "process.executable", "process.command_line", "url.path",
  "http.response.status_code", "user_agent.original", "destination.port", "auth.method", "log.file.path"];

async function pageSearch(params) {
  const q = params.get("q") || "";
  setPage("Hunt", html`
    <div class="page-head"><h1>Threat hunting</h1><span class="sub">Search every stored event with VQL · last ${state.range}</span></div>
    <div class="card"><form class="searchbar" id="sform"><input class="input" id="sq" value="${q}" placeholder='e.g. event.action:ssh_login_failed AND source.geo.country_iso_code:CN | stats count by source.ip' spellcheck="false" autocomplete="off"><button class="btn primary">${icon("search")} Search</button></form>
      <div class="examples" style="margin-top:10px">${EXAMPLES.map((e) => html`<button class="btn small" data-ex="${e}">${e}</button>`)}</div>
      <details style="margin-top:10px"><summary class="muted" style="cursor:pointer">Query syntax</summary><div class="secondary" style="font-size:13px;margin-top:6px">
        <code>field:value</code> (case-insensitive, <code>*</code> wildcards, CIDR for IPs) · <code>field!=value</code> · <code>field&gt;N</code>, <code>&gt;=</code>, <code>&lt;</code>, <code>&lt;=</code> · <code>field:*</code> exists ·
        bare words or <code>"phrases"</code> search the raw log (full-text index) · <code>AND</code> (implicit), <code>OR</code>, <code>NOT</code>, parentheses ·
        pipes: <code>| stats count by f1, f2</code>, <code>| top f</code>, <code>| head N</code>, <code>| sort -f</code>, <code>| table f1, f2</code></div></details></div>
    <div class="hunt"><div class="card"><h3>Fields</h3><div class="fieldlist">${FIELDS.map((f) => html`<button data-field="${f}" title="Top values of ${f}">${f}</button>`)}</div><div id="fvals" style="margin-top:10px"></div></div>
      <div class="grid" style="align-content:start" id="results"><div class="card empty">Run a query to see matching events.</div></div></div>`);
  const run = async (query) => {
    const res = $content.querySelector("#results");
    res.innerHTML = '<div class="card empty">Searching…</div>';
    try {
      const r = await api("/api/search", { query: { q: query, range: state.range, limit: 200 } });
      if (r.type === "stats") {
        const max = Math.max(1, ...r.rows.map((x) => x[x.length - 1]));
        res.innerHTML = html`<div class="card flush"><div class="card-head"><h2>${r.rows.length} rows</h2></div><div class="table-wrap"><table><thead><tr>${r.columns.map((c) => html`<th>${c}</th>`)}<th></th></tr></thead><tbody>
          ${r.rows.map((row) => html`<tr>${row.map((v, i) => html`<td class="${i < row.length - 1 ? "mono" : ""}">${i < row.length - 1 && r.columns[i] === "source.ip" && v ? ipLink(v) : (v ?? html`<span class="muted">null</span>`)}</td>`)}<td style="width:30%"><div class="progress"><i style="width:${(100 * row[row.length - 1]) / max}%"></i></div></td></tr>`)}</tbody></table></div></div>`.s;
        return;
      }
      const cols = r.columns;
      res.innerHTML = html`<div class="card"><div class="card-head"><h2>${fmtNum(r.total)}${r.total_capped ? "+" : ""} events</h2><span class="right muted">showing ${r.events.length}</span></div><div class="chart" id="hist"></div></div>
        <div class="card flush"><div class="table-wrap"><table><thead><tr><th class="nowrap">Time</th>${cols ? cols.map((c) => html`<th>${c}</th>`) : html`<th>Host</th><th>Raw event</th>`}</tr></thead><tbody>
        ${r.events.map((e) => html`<tr class="click" data-ev="${e.id}"><td class="nowrap mono">${fmtTime(e.ts)}</td>${cols ? cols.map((c) => html`<td class="mono">${c === "@timestamp" ? fmtTime(e.fields[c]) : e.fields[c] ?? ""}</td>`) : html`<td>${e.host || ""}</td><td class="msg">${(e.message || "").slice(0, 500)}</td>`}</tr>
        <tr class="ev-detail" data-evd="${e.id}" hidden><td colspan="${cols ? cols.length + 1 : 3}">${jsonView(e.fields)}</td></tr>`)}</tbody></table>
        ${r.events.length ? "" : html`<div class="empty">No events match.</div>`}</div></div>`.s;
      areaChart(res.querySelector("#hist"), { values: r.histogram.counts, start: r.histogram.start, step: r.histogram.width, label: "Matching events", height: 120 });
      bindEventRows();
    } catch (e) {
      res.innerHTML = html`<div class="card empty">Query error: ${e.message}</div>`.s;
    }
  };
  on("#sform", "submit", (e) => {
    e.preventDefault();
    const v = $content.querySelector("#sq").value;
    history.replaceState(null, "", `#/search?q=${encodeURIComponent(v)}`);
    run(v);
  });
  on("[data-ex]", "click", (e) => { $content.querySelector("#sq").value = e.target.dataset.ex; $content.querySelector("#sform").requestSubmit(); });
  on("[data-field]", "click", async (e) => {
    const f = e.target.dataset.field;
    const box = $content.querySelector("#fvals");
    const r = await api("/api/search/field", { query: { field: f, q: $content.querySelector("#sq").value.split("|")[0], range: state.range } }).catch(() => null);
    if (!r) return;
    box.innerHTML = html`<h3>${f}</h3>${r.rows.length ? r.rows.map(([v, n]) => html`<div class="hbar" style="grid-template-columns:1fr 40px"><a class="name mono" href="#/search?q=${encodeURIComponent(`${f}:"${v}"`)}">${v ?? "null"}</a><span class="num">${fmtCompact(n)}</span></div>`) : html`<div class="muted">no values</div>`}`.s;
  });
  if (q) run(q);
}

// ------------------------------------------------------------------ ATT&CK
async function pageAttack() {
  const d = await api("/api/attack", { query: { range: state.range } });
  const color = { critical: "var(--sev-critical)", high: "#c4602f", medium: "#a8770a", low: "#2a78d6", informational: "#52514e" };
  setPage("ATT&CK", html`
    <div class="page-head"><h1>MITRE ATT&amp;CK coverage</h1><span class="sub">${d.covered} of ${d.total} techniques have at least one enabled detection (${Math.round((100 * d.covered) / d.total)}%) · ${d.source}</span></div>
    <div class="legend"><span><i style="background:var(--sev-critical)"></i>Detected (colored by highest severity)</span><span><i style="background:var(--surface-3);border:1px solid var(--border-strong)"></i>Covered by rules</span><span><i style="background:var(--surface-1);border:1px solid var(--border)"></i>No detection</span></div>
    <div class="card"><div class="matrix">${d.matrix.map((t) => html`<div class="col"><h4>${t.name}<small>${t.id} · ${t.techniques.filter((x) => x.rules).length}/${t.techniques.length} covered</small></h4>
      ${t.techniques.map((x) => html`<a class="cell ${x.alerts ? "detected" : x.rules ? "covered" : ""}" ${x.alerts ? raw(`style="background:${color[x.max_severity]}"`) : ""} target="_blank" rel="noopener" href="https://attack.mitre.org/techniques/${x.id}/" title="${x.rules} rules · ${x.alerts} alerts"><span class="id">${x.id}${x.alerts ? ` · ${x.alerts} alerts` : ""}</span>${x.name}</a>`)}</div>`)}</div></div>`);
}

// ------------------------------------------------------------------ entities
async function pageEntities() {
  const d = await api("/api/entities");
  if (!d.enabled) { setPage("Entities", html`<div class="card empty">UEBA is disabled (VIGIL_UEBA=0).</div>`); return; }
  const users = d.items.filter((i) => i.kind === "user"), hosts = d.items.filter((i) => i.kind === "host");
  const table = (items, kind) => html`<div class="card flush"><div class="card-head"><h2>${kind === "user" ? "Users" : "Hosts"} (${items.length})</h2></div><div class="table-wrap"><table><thead><tr><th>Entity</th><th>Baseline</th><th>Observations</th>${kind === "user" ? html`<th>Countries</th><th>Hosts</th><th>Last login risk</th>` : html`<th>Executables</th><th>Process lineages</th>`}<th>Anomalies</th><th>Updated</th></tr></thead><tbody>
    ${items.map((i) => html`<tr class="click" data-href="#/entities/${encodeURIComponent(i.entity)}"><td><b>${i.name}</b></td>
      <td style="width:160px"><div class="progress ${i.learning_progress >= 100 ? "done" : ""}"><i style="width:${i.learning_progress}%"></i></div><div class="muted" style="font-size:11px">${i.learning_progress >= 100 ? "learned, scoring" : `learning ${i.learning_progress}%`}</div></td>
      <td>${fmtNum(i.observations)}</td>
      ${kind === "user" ? html`<td>${Object.keys(i.countries).map((c) => html`<span class="flag" title="${c}">${flag(c)}</span>`)}</td><td>${i.hosts.length}</td><td>${i.last_risk == null ? html`<span class="muted">—</span>` : riskBadge(i.last_risk)}</td>` : html`<td>${fmtNum(i.executables)}</td><td>${fmtNum(i.lineages)}</td>`}
      <td>${i.alerts ? html`<span class="pill danger">${i.alerts}</span>` : "0"}</td><td class="muted nowrap">${ago(i.updated)}</td></tr>`)}</tbody></table>
    ${items.length ? "" : html`<div class="empty">No ${kind} profiles yet. They build automatically from incoming ${kind === "user" ? "successful logins" : "process events"}.</div>`}</div></div>`;
  setPage("Entities", html`
    <div class="page-head"><h1>Behavioural baselines (UEBA)</h1><span class="sub">Unsupervised profiles learned from your own logs. Scoring starts after ${d.min_observations} logins per user; alert threshold risk ${d.threshold}.</span></div>
    ${table(users, "user")}${table(hosts, "host")}`);
  rowLinks();
}

async function pageEntity(entity) {
  const p = await api(`/api/entities/${encodeURIComponent(entity)}`);
  const maxH = Math.max(1, ...(p.hours || [1]));
  const kv = (obj) => Object.entries(obj || {}).sort((a, b) => b[1] - a[1]).slice(0, 12);
  setPage(p.name, html`
    <div><a href="#/entities" class="muted">${icon("back")} Entities</a></div>
    <div class="page-head"><h1>${p.kind === "user" ? "User" : "Host"} · ${p.name}</h1><span class="sub">${fmtNum(Math.round(p.n))} observations since ${fmtTime(p.first_seen)}</span></div>
    ${p.kind === "user" ? html`<div class="grid g-2">
      <div class="card"><h2>Login hours (UTC)</h2><div class="hours">${p.hours.map((h, i) => html`<i style="height:${(100 * h) / maxH}%" title="${String(i).padStart(2, "0")}:00 · ${h.toFixed(1)} logins"></i>`)}</div><div class="hours-axis"><span>00</span><span>06</span><span>12</span><span>18</span><span>23</span></div></div>
      <div class="card"><h2>Learned profile</h2><dl class="kv">
        <dt>Countries</dt><dd>${kv(p.countries).map(([k, v]) => html`<span class="pill"><span class="flag">${flag(k)}</span> ${k} · ${Math.round(v)}</span> `)}</dd>
        <dt>Networks (ASN)</dt><dd>${kv(p.asns).map(([k, v]) => html`<span class="pill">AS${k} · ${Math.round(v)}</span> `)}</dd>
        <dt>Hosts</dt><dd>${kv(p.hosts).map(([k, v]) => html`<span class="pill">${k} · ${Math.round(v)}</span> `)}</dd>
        <dt>Auth methods</dt><dd>${kv(p.methods).map(([k, v]) => html`<span class="pill">${k} · ${Math.round(v)}</span> `)}</dd>
        <dt>Source IPs</dt><dd>${Object.keys(p.ips || {}).length} distinct</dd>
        <dt>Last login</dt><dd>${p.last ? html`${fmtTime(p.last.ts)} from ${ipLink(p.last.ip, p.last.cc)}` : "—"}</dd></dl></div></div>`
    : html`<div class="grid g-2"><div class="card"><h2>Most common executables</h2>${kv(p.exes).map(([k, v]) => html`<div class="hbar"><span class="name mono">${k}</span><span class="track"><span class="fill" style="width:${(100 * v) / Math.max(1, kv(p.exes)[0][1])}%"></span></span><span class="num">${fmtCompact(v)}</span></div>`)}</div>
      <div class="card"><h2>Process lineages (parent → child)</h2>${kv(p.pairs).map(([k, v]) => html`<div class="hbar"><span class="name mono">${k.replace(">", " → ")}</span><span class="track"><span class="fill" style="width:${(100 * v) / Math.max(1, kv(p.pairs)[0][1])}%"></span></span><span class="num">${fmtCompact(v)}</span></div>`)}</div></div>`}
    <div class="card flush"><div class="card-head"><h2>Recent alerts</h2></div><div class="table-wrap"><table><tbody>${p.recent_alerts.map((a) => html`<tr class="click" data-href="#/alerts/${a.id}"><td>${sev(a.severity)}</td><td>${a.rule_title}</td><td>${riskBadge(a.risk)}</td><td>${statusLabel(a.status)}</td><td class="muted">${ago(a.created_ts)}</td></tr>`)}</tbody></table>${p.recent_alerts.length ? "" : html`<div class="empty">No alerts for this entity.</div>`}</div></div>`);
  rowLinks();
}

// ------------------------------------------------------------------ rules
async function pageRules(params) {
  const q = params.get("q") || "", src = params.get("src") || "";
  const d = await api("/api/rules", { query: { q } });
  let items = d.items;
  if (src) items = items.filter((r) => r.source === src);
  items.sort((a, b) => (b.hits - a.hits) || (a.source === "vigil" ? -1 : 0) - (b.source === "vigil" ? -1 : 0));
  const shown = items.slice(0, 300);
  const isAdmin = state.user.role === "admin";
  const counts = d.items.reduce((m, r) => ({ ...m, [r.source]: (m[r.source] || 0) + 1 }), {});
  setPage("Detection rules", html`
    <div class="page-head"><h1>Detection rules</h1><span class="sub">${fmtNum(d.report.rules)} Sigma rules + ${d.report.correlations} correlation rules from ${fmtNum(d.report.files)} files, compiled in ${d.report.seconds}s${d.report.error_count ? ` · ${d.report.error_count} skipped (unsupported features)` : ""}</span>
      ${state.user.role !== "viewer" ? html`<button class="btn primary" id="new-rule" style="margin-left:auto">${icon("plus")} New rule / back-test</button>` : ""}</div>
    <div class="card"><div class="toolbar">
      <div class="seg">${[["", `All (${d.items.length})`], ["vigil", `Vigil (${counts.vigil || 0})`], ["sigmahq", `SigmaHQ (${counts.sigmahq || 0})`], ["custom", `Custom (${counts.custom || 0})`]].map(([v, l]) => html`<button class="${src === v ? "on" : ""}" data-src="${v}">${l}</button>`)}</div>
      <input class="input" id="rq" value="${q}" placeholder="Search title, id or tag (e.g. t1110, sshd)" style="flex:1;min-width:220px">
      ${isAdmin ? html`<button class="btn" id="reload">${icon("refresh")} Reload from disk</button>` : ""}</div></div>
    <div class="card flush"><div class="table-wrap"><table><thead><tr><th>Level</th><th>Rule</th><th>Source</th><th>Log source</th><th>ATT&amp;CK</th><th>Hits</th><th>Enabled</th></tr></thead><tbody>
      ${shown.map((r) => html`<tr class="click" data-href="#/rules/${encodeURIComponent(r.id)}"><td>${sev(r.level)}</td><td><b>${r.title}</b><div class="muted" style="font-size:12px">${r.type === "correlation" ? `correlation · ${r.correlation.type}` : r.status}</div></td>
        <td><span class="pill ${r.source === "vigil" ? "accent" : ""}">${r.source}</span></td>
        <td class="mono" style="font-size:12px">${Object.values(r.logsource || {}).filter((v) => typeof v === "string").join(" / ") || "—"}</td>
        <td>${r.techniques.slice(0, 3).map((t) => html`<span class="pill tech">${t}</span> `)}</td><td>${fmtNum(r.hits)}</td>
        <td><label class="switch" title="${isAdmin ? "Enable/disable" : "Admins only"}"><input type="checkbox" data-toggle="${r.id}" ${r.enabled ? "checked" : ""} ${isAdmin ? "" : "disabled"}><span></span></label></td></tr>`)}
    </tbody></table>${items.length > shown.length ? html`<div class="empty">Showing ${shown.length} of ${items.length}. Refine the search to see more.</div>` : ""}</div></div>`);
  rowLinks();
  on("[data-src]", "click", (e) => { location.hash = `#/rules?src=${e.target.dataset.src}&q=${encodeURIComponent(q)}`; });
  on("#rq", "keydown", (e) => { if (e.key === "Enter") location.hash = `#/rules?src=${src}&q=${encodeURIComponent(e.target.value)}`; });
  on("[data-toggle]", "change", async (e) => {
    await api(`/api/rules/${encodeURIComponent(e.target.dataset.toggle)}`, { method: "PATCH", body: { enabled: e.target.checked } });
    toast(e.target.checked ? "Rule enabled" : "Rule disabled", "");
  });
  on("#reload", "click", async () => { const r = await api("/api/rules/reload", { method: "POST" }); toast("Rules reloaded", `${r.rules} Sigma + ${r.correlations} correlation in ${r.seconds}s`); route(); });
  on("#new-rule", "click", () => ruleEditor());
}

const RULE_TEMPLATE = `title: Login From Service Account
id: 11111111-2222-4333-8444-555555555555
status: experimental
description: A service account logged in interactively over SSH.
author: you
tags:
    - attack.initial-access
    - attack.t1078.003
logsource:
    product: linux
    service: sshd
detection:
    selection:
        event.action: ssh_login_success
        user.name|startswith: 'svc_'
    condition: selection
level: high
`;
function ruleEditor() {
  const bg = document.createElement("div");
  bg.className = "modal-bg";
  bg.innerHTML = html`<div class="modal" role="dialog" aria-label="Rule editor"><h2>New Sigma rule</h2>
    <p class="muted" style="margin-top:0">Write a Sigma rule (or a correlation rule), back-test it against stored events, then save it. Saved rules go live immediately.</p>
    <textarea class="input" id="ry" rows="20" spellcheck="false">${RULE_TEMPLATE}</textarea>
    <div class="toolbar" style="margin-top:10px"><button class="btn" id="rt">Back-test last 24h</button>${state.user.role === "admin" ? html`<button class="btn primary" id="rs">Save &amp; enable</button>` : ""}<button class="btn" id="rc" style="margin-left:auto">Close</button></div>
    <div id="rr" style="margin-top:12px"></div></div>`.s;
  document.body.appendChild(bg);
  const out = bg.querySelector("#rr");
  bg.querySelector("#rc").onclick = () => bg.remove();
  bg.addEventListener("click", (e) => { if (e.target === bg) bg.remove(); });
  bg.querySelector("#rt").onclick = async () => {
    out.innerHTML = '<div class="muted">Testing…</div>';
    try {
      const r = await api("/api/rules/test", { method: "POST", body: { yaml: bg.querySelector("#ry").value, hours: 24 } });
      out.innerHTML = html`<div class="card"><b>${fmtNum(r.matched)}</b> of ${fmtNum(r.scanned)} events matched (${r.seconds}s)
        ${r.samples.length ? html`<table style="margin-top:8px"><tbody>${r.samples.map((s) => html`<tr><td class="nowrap mono">${fmtTime(s.ts)}</td><td>${s.host}</td><td class="msg">${s.message}</td></tr>`)}</tbody></table>` : ""}</div>`.s;
    } catch (e) { out.innerHTML = html`<div class="card" style="color:var(--sev-critical)">${e.message}</div>`.s; }
  };
  const save = bg.querySelector("#rs");
  if (save) save.onclick = async () => {
    try {
      const r = await api("/api/rules/custom", { method: "POST", body: { yaml: bg.querySelector("#ry").value } });
      toast("Rule saved", `${r.file} · ${r.rules} rules active`);
      bg.remove();
      route();
    } catch (e) { out.innerHTML = html`<div class="card" style="color:var(--sev-critical)">${e.message}</div>`.s; }
  };
}

async function pageRule(id) {
  const r = await api(`/api/rules/${encodeURIComponent(id)}`);
  setPage(r.title, html`
    <div><a href="#/rules" class="muted">${icon("back")} Rules</a></div>
    <div class="card"><div class="toolbar">${sev(r.level)}<span class="pill">${r.type}</span><span class="pill">${r.status}</span><span class="muted">${fmtNum(r.hits)} hits since start</span></div>
      <h1 style="margin:8px 0">${r.title}</h1><p class="secondary" style="white-space:pre-wrap;margin:0">${r.description}</p></div>
    <div class="grid g-12"><div class="card"><h2>Details</h2><dl class="kv"><dt>ID</dt><dd class="mono">${r.id}</dd><dt>File</dt><dd class="mono">${r.path.split("/").slice(-2).join("/")}</dd>${r.author ? html`<dt>Author</dt><dd>${r.author}</dd>` : ""}
      <dt>Techniques</dt><dd>${r.technique_details.map((t) => html`<div><a class="tech" target="_blank" rel="noopener" href="${t.url}">${t.id}</a> ${t.name}</div>`)}</dd>
      ${r.falsepositives?.length ? html`<dt>False positives</dt><dd>${r.falsepositives.join("; ")}</dd>` : ""}
      ${r.references?.length ? html`<dt>References</dt><dd>${r.references.slice(0, 5).map((u) => html`<div><a href="${/^https?:/.test(u) ? u : "#"}" target="_blank" rel="noopener">${u}</a></div>`)}</dd>` : ""}
      ${r.error ? html`<dt>Not loaded</dt><dd style="color:var(--sev-critical)">${r.error}</dd>` : ""}</dl>
      <div style="margin-top:10px"><a class="btn" href="#/alerts?status=&q=${encodeURIComponent(r.title)}">View alerts from this rule</a></div></div>
    <div class="card"><h2>Rule source (Sigma YAML)</h2><div class="code-block"><pre>${r.yaml}</pre></div></div></div>`);
}

// ------------------------------------------------------------------ agents
async function pageAgents() {
  const agents = await api("/api/agents");
  const enroll = state.user.role === "admin" ? await api("/api/agents/enrollment").catch(() => null) : null;
  setPage("Agents", html`
    <div class="page-head"><h1>Agents &amp; log sources</h1><span class="sub">${agents.filter((a) => a.health === "healthy").length} of ${agents.length} reporting</span></div>
    <div class="card flush"><div class="table-wrap"><table><thead><tr><th>Health</th><th>Host</th><th>Agent</th><th>OS</th><th>Inputs</th><th>Events</th><th>Last seen</th>${state.user.role === "admin" ? html`<th></th>` : ""}</tr></thead><tbody>
      ${agents.map((a) => html`<tr><td><span class="pill ${a.health === "healthy" ? "good" : "danger"}">${a.health === "healthy" ? "● healthy" : a.health}</span></td><td><b>${a.hostname}</b><div class="muted mono" style="font-size:12px">${a.ip}</div></td>
        <td class="mono" style="font-size:12px">${a.id}<div class="muted">v${a.version}</div></td><td>${a.os}</td>
        <td style="font-size:12px">${a.inputs.map((i) => html`<div class="mono">${i.type === "file" ? `${i.path} (${i.sourcetype})` : i.type}</div>`)}</td>
        <td>${fmtNum(a.events_received)}</td><td class="nowrap">${ago(a.last_seen)}</td>
        ${state.user.role === "admin" ? html`<td>${a.status === "active" ? html`<button class="btn small danger" data-revoke="${a.id}">Revoke</button>` : ""}</td>` : ""}</tr>`)}
    </tbody></table>${agents.length ? "" : html`<div class="empty">No agents enrolled yet.</div>`}</div></div>
    ${enroll ? html`<div class="card"><h2>Add a Linux server</h2><p class="secondary" style="margin-top:0">Run this on the server you want to monitor (needs Python 3 and root to read auth logs). It installs the agent as a systemd service, pins this server's TLS certificate and starts shipping logs.</p>
      <div class="code-block"><pre>${enroll.install_command}</pre></div>
      ${enroll.ca_sha256 ? html`<p class="muted" style="font-size:12px">Server certificate SHA-256: <span class="mono">${enroll.ca_sha256}</span>. The installer refuses to continue if the certificate it downloads does not match.</p>` : ""}
      <p class="muted">Network devices and firewalls can send syslog straight to UDP/TCP port 5514 instead. Windows: run <code>python vigil_agent.py</code> with <code>VIGIL_SERVER</code> and <code>VIGIL_ENROLL_TOKEN</code> set to collect Security, System, Sysmon and PowerShell event logs.</p></div>` : ""}`);
  on("[data-revoke]", "click", async (e) => {
    if (!confirm("Revoke this agent? It will stop being able to send logs.")) return;
    await api(`/api/agents/${e.target.dataset.revoke}/revoke`, { method: "POST" });
    route();
  });
}

// ------------------------------------------------------------------ intel
async function pageIntel() {
  const d = await api("/api/intel");
  const canEdit = state.user.role !== "viewer";
  setPage("Threat intel", html`
    <div class="page-head"><h1>Threat intelligence &amp; enrichment</h1><span class="sub">${fmtNum(d.total_ranges)} malicious IPs/networks loaded from free public feeds</span>
      ${state.user.role === "admin" ? html`<button class="btn" id="refresh" style="margin-left:auto">${icon("refresh")} Refresh feeds</button>` : ""}</div>
    <div class="card flush"><div class="table-wrap"><table><thead><tr><th>Feed</th><th>Category</th><th>Confidence</th><th>Entries</th><th>Updated</th><th>Status</th></tr></thead><tbody>
      ${d.feeds.map((f) => html`<tr><td><b>${f.name}</b><div class="muted" style="font-size:12px">${f.description}</div></td><td>${f.category}</td><td>${f.confidence}</td><td>${fmtNum(f.entries)}</td><td class="nowrap">${f.updated ? ago(f.updated) : "—"}</td>
        <td>${f.error ? html`<span class="pill danger" title="${f.error}">${f.entries ? "stale (using cache)" : "unavailable"}</span>` : html`<span class="pill good">● ok</span>`}</td></tr>`)}
    </tbody></table>${d.feeds.length ? "" : html`<div class="empty">${d.enabled ? "Feeds are downloading in the background…" : "Threat-intel downloads are disabled (VIGIL_THREATINTEL=0)."}</div>`}</div></div>
    <div class="grid g-2">
      <div class="card"><h2>Watchlist (custom indicators)</h2><p class="muted" style="margin-top:0">Any event from these IPs or networks raises an alert.</p>
        ${canEdit ? html`<form class="toolbar" id="addind"><input class="input" name="indicator" placeholder="IP or CIDR, e.g. 203.0.113.0/24" required><input class="input" name="note" placeholder="Note (optional)" style="flex:1"><button class="btn primary">Add</button></form>` : ""}
        <div class="list" style="margin-top:10px">${d.custom.map((c) => html`<div class="row"><span class="mono">${c.indicator}</span><span class="grow muted">${c.note} · ${c.author}</span>${canEdit ? html`<button class="btn small" data-del="${c.indicator}">Remove</button>` : ""}</div>`)}</div></div>
      <div class="card"><h2>Offline enrichment</h2><dl class="kv"><dt>Country GeoIP</dt><dd>${d.geoip.country ? "loaded (DB-IP Lite, CC BY 4.0)" : "missing"}</dd><dt>City GeoIP</dt><dd>${d.geoip.city ? "loaded" : html`<span class="muted">optional: drop a GeoLite2-City or dbip-city .mmdb into the GeoIP directory</span>`}</dd><dt>ASN</dt><dd>${d.geoip.asn ? "loaded (origin-asn, public domain)" : "missing"}</dd><dt>ATT&amp;CK</dt><dd>Enterprise matrix bundled offline</dd></dl></div>
    </div>`);
  on("#refresh", "click", async () => { await api("/api/intel/refresh", { method: "POST" }); toast("Refreshing feeds", "This runs in the background"); });
  on("#addind", "submit", async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    try { await api("/api/intel/indicators", { method: "POST", body: { indicator: f.get("indicator"), note: f.get("note") } }); route(); } catch (ex) { toast("Could not add", ex.message, "var(--sev-critical)"); }
  });
  on("[data-del]", "click", async (e) => { await api(`/api/intel/indicators/${encodeURIComponent(e.target.dataset.del)}`, { method: "DELETE" }); route(); });
}

// ------------------------------------------------------------------ settings
async function pageSettings(params) {
  const tab = params.get("tab") || (state.user.role === "admin" ? "notifications" : "account");
  const tabs = state.user.role === "admin" ? [["notifications", "Notifications"], ["users", "Users"], ["system", "System"], ["audit", "Audit log"], ["account", "My account"]] : [["system", "System"], ["account", "My account"]];
  let body = html``;
  if (tab === "notifications") {
    const { config: c, history } = await api("/api/settings/notifications");
    const inp = (ch, k, label, type = "text") => html`<label class="field">${label}<input class="input" data-ch="${ch}" data-k="${k}" type="${type}" value="${c[ch][k] ?? ""}"></label>`;
    const chan = (ch, title, fields) => html`<div class="card"><div class="card-head"><h2>${title}</h2><div class="right"><label class="switch"><input type="checkbox" data-ch="${ch}" data-k="enabled" ${c[ch].enabled ? "checked" : ""}><span></span></label><button class="btn small" data-test="${ch}">Send test</button></div></div><div class="grid" style="gap:10px">${fields}</div></div>`;
    body = html`<div class="card"><div class="toolbar"><label class="field">Notify for alerts at or above<select class="input" id="minsev">${["low", "medium", "high", "critical"].map((s) => html`<option ${c.min_severity === s ? "selected" : ""}>${s}</option>`)}</select></label>
        <label class="field">Max messages per channel per hour<input class="input" id="maxph" type="number" min="1" value="${c.max_per_hour}"></label>
        <label class="field" style="flex-direction:row;align-items:center;gap:8px;margin-top:16px"><label class="switch"><input type="checkbox" id="notinc" ${c.notify_incidents ? "checked" : ""}><span></span></label>Also notify on new / escalated incidents</label>
        <button class="btn primary" id="savenot" style="margin-left:auto">Save</button></div></div>
      <div class="grid g-2">
        ${chan("slack", "Slack", inp("slack", "webhook_url", "Incoming webhook URL", "password"))}
        ${chan("telegram", "Telegram", html`${inp("telegram", "bot_token", "Bot token", "password")}${inp("telegram", "chat_id", "Chat ID")}`)}
        ${chan("email", "Email (SMTP)", html`<div class="grid g-2" style="gap:10px">${inp("email", "host", "SMTP host")}${inp("email", "port", "Port", "number")}${inp("email", "username", "Username")}${inp("email", "password", "Password", "password")}${inp("email", "from", "From")}${inp("email", "to", "To")}</div>`)}
        ${chan("webhook", "Generic webhook (JSON)", html`${inp("webhook", "url", "URL")}<div class="muted" style="font-size:12px">POSTs {source, kind, title, text, data} for SOAR, n8n, PagerDuty Events and similar.</div>`)}
      </div>
      <div class="card"><h2>Delivery log</h2>${history.length ? html`<div class="list">${history.map((h) => html`<div class="row"><span class="pill ${h.ok ? "good" : "danger"}">${h.ok ? "sent" : "failed"}</span><span class="pill">${h.channel}</span><span class="grow">${h.title}</span><span class="muted">${h.error || ""} ${ago(h.ts)}</span></div>`)}</div>` : html`<div class="muted">Nothing sent yet.</div>`}</div>`;
  } else if (tab === "users") {
    const users = await api("/api/users");
    body = html`<div class="card flush"><div class="table-wrap"><table><thead><tr><th>User</th><th>Role</th><th>Created</th><th>Status</th><th></th></tr></thead><tbody>${users.map((u) => html`<tr><td><b>${u.username}</b></td><td>${u.role}</td><td>${fmtTime(u.created_ts)}</td><td>${u.disabled ? "disabled" : "active"}</td><td>${!u.disabled && u.username !== state.user.username ? html`<button class="btn small danger" data-deluser="${u.username}">Disable</button>` : ""}</td></tr>`)}</tbody></table></div></div>
      <div class="card"><h2>Add user</h2><form class="toolbar" id="adduser"><input class="input" name="username" placeholder="username" required><input class="input" name="password" type="password" placeholder="password (10+ chars)" minlength="10" required><select class="input" name="role"><option>analyst</option><option>viewer</option><option>admin</option></select><button class="btn primary">Create</button></form>
      <p class="muted">Roles: <b>admin</b> manages users, rules, agents and settings · <b>analyst</b> triages alerts and incidents · <b>viewer</b> is read-only.</p></div>`;
  } else if (tab === "system") {
    const s = await api("/api/system");
    body = html`<div class="grid g-3">${statTile("Events stored", fmtNum(s.events_stored), `retention ${s.retention_days} days`)}${statTile("Database size", fmtBytes(s.db_bytes), "SQLite (WAL) with FTS5 index")}${statTile("Pipeline", `${s.eps} ev/s`, `queue ${s.queue} · ${fmtNum(s.events_processed)} processed since start`)}</div>
      <div class="card"><dl class="kv"><dt>Version</dt><dd>${s.version}</dd><dt>Uptime</dt><dd>${Math.round(s.uptime_s / 60)} min</dd><dt>Detections since start</dt><dd>${fmtNum(s.detections)}</dd><dt>Pipeline errors</dt><dd>${s.errors}${s.last_error ? html` <span class="muted mono">${s.last_error}</span>` : ""}</dd><dt>Syslog receiver</dt><dd>${s.syslog_port ? `UDP/TCP ${s.syslog_port}` : "disabled"}</dd><dt>UEBA</dt><dd>${s.ueba ? "enabled" : "disabled"}</dd><dt>API docs</dt><dd><a href="/api/docs" target="_blank">OpenAPI / Swagger UI</a> · <a href="/metrics" target="_blank">Prometheus metrics</a></dd></dl></div>`;
  } else if (tab === "audit") {
    const log = await api("/api/audit");
    body = html`<div class="card flush"><div class="table-wrap"><table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Details</th></tr></thead><tbody>${log.map((l) => html`<tr><td class="nowrap mono">${fmtTime(l.ts)}</td><td>${l.actor}</td><td>${l.action}</td><td class="mono">${l.target || ""}</td><td class="msg">${l.details || ""}</td></tr>`)}</tbody></table></div></div>`;
  } else {
    body = html`<div class="card" style="max-width:520px"><h2>Change password</h2><form class="grid" id="pw" style="gap:10px"><label class="field">Current password<input class="input" type="password" name="current" required autocomplete="current-password"></label><label class="field">New password (10+ characters)<input class="input" type="password" name="new" minlength="10" required autocomplete="new-password"></label><div><button class="btn primary">Update password</button></div></form></div>`;
  }
  setPage("Settings", html`<div class="page-head"><h1>Settings</h1></div><div class="tabs">${tabs.map(([t, l]) => html`<button class="${t === tab ? "on" : ""}" data-tab="${t}">${l}</button>`)}</div>${body}`);
  on("[data-tab]", "click", (e) => { location.hash = `#/settings?tab=${e.target.dataset.tab}`; });
  on("#savenot", "click", async () => {
    const cfg = { min_severity: $content.querySelector("#minsev").value, max_per_hour: +$content.querySelector("#maxph").value, notify_incidents: $content.querySelector("#notinc").checked };
    $content.querySelectorAll("[data-ch]").forEach((el) => {
      cfg[el.dataset.ch] = cfg[el.dataset.ch] || {};
      cfg[el.dataset.ch][el.dataset.k] = el.type === "checkbox" ? el.checked : el.type === "number" ? +el.value : el.value;
    });
    await api("/api/settings/notifications", { method: "PUT", body: cfg });
    toast("Notification settings saved", "");
  });
  on("[data-test]", "click", async (e) => {
    const r = await api(`/api/settings/notifications/test/${e.target.dataset.test}`, { method: "POST" });
    r.ok ? toast("Test sent", e.target.dataset.test) : toast("Test failed", r.error, "var(--sev-critical)");
  });
  on("#adduser", "submit", async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    try { await api("/api/users", { method: "POST", body: Object.fromEntries(f) }); route(); } catch (ex) { toast("Could not create user", ex.message, "var(--sev-critical)"); }
  });
  on("[data-deluser]", "click", async (e) => { if (confirm(`Disable ${e.target.dataset.deluser}?`)) { await api(`/api/users/${e.target.dataset.deluser}`, { method: "DELETE" }); route(); } });
  on("#pw", "submit", async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    try { await api("/api/auth/password", { method: "POST", body: Object.fromEntries(f) }); toast("Password updated", "Sign in again on other devices"); e.target.reset(); } catch (ex) { toast("Could not update", ex.message, "var(--sev-critical)"); }
  });
}

