"use strict";

/* Mirage deception lab console.
 * SECURITY: every value from the API is attacker-controlled. It is only ever
 * placed with textContent or DOM attribute setters, never innerHTML.
 */

// ------------------------------------------------------------------ vocab
const ATTACK = {
  "T1003.008": "OS Credential Dumping: passwd & shadow", "T1016": "Network Configuration Discovery",
  "T1021.004": "Remote Services: SSH", "T1033": "System Owner/User Discovery",
  "T1046": "Network Service Discovery", "T1049": "Network Connections Discovery",
  "T1053.003": "Scheduled Task/Job: Cron", "T1057": "Process Discovery",
  "T1059.004": "Command & Scripting: Unix Shell", "T1070.002": "Indicator Removal: System Logs",
  "T1070.003": "Indicator Removal: Command History", "T1078": "Valid Accounts",
  "T1078.004": "Valid Accounts: Cloud Accounts", "T1082": "System Information Discovery",
  "T1083": "File & Directory Discovery", "T1087.001": "Account Discovery: Local Account",
  "T1098.004": "Account Manipulation: SSH Keys", "T1105": "Ingress Tool Transfer",
  "T1110": "Brute Force", "T1136.001": "Create Account: Local Account",
  "T1222.002": "File Permissions Modification", "T1530": "Data from Cloud Storage",
  "T1546.004": "Triggered Execution: Shell Config", "T1548.003": "Sudo and Sudo Caching",
  "T1552.001": "Unsecured Credentials In Files", "T1552.003": "Unsecured Credentials: Bash History",
  "T1580": "Cloud Infrastructure Discovery", "T1595": "Active Scanning",
  "T1595.003": "Active Scanning: Wordlist",
};
const TACTICS = [
  ["reconnaissance", "Reconnaissance"], ["initial-access", "Initial access"], ["execution", "Execution"],
  ["persistence", "Persistence"], ["privilege-escalation", "Privilege escalation"], ["defense-evasion", "Defense evasion"],
  ["credential-access", "Credential access"], ["discovery", "Discovery"], ["lateral-movement", "Lateral movement"],
  ["collection", "Collection"], ["command-and-control", "Command and control"], ["exfiltration", "Exfiltration"],
];
const TACTIC_OF = {
  "T1595": "reconnaissance", "T1595.003": "reconnaissance",
  "T1078": "initial-access", "T1078.004": "initial-access",
  "T1059.004": "execution",
  "T1053.003": "persistence", "T1098.004": "persistence", "T1136.001": "persistence", "T1546.004": "persistence",
  "T1548.003": "privilege-escalation",
  "T1070.002": "defense-evasion", "T1070.003": "defense-evasion", "T1222.002": "defense-evasion",
  "T1003.008": "credential-access", "T1110": "credential-access", "T1552.001": "credential-access", "T1552.003": "credential-access",
  "T1016": "discovery", "T1033": "discovery", "T1046": "discovery", "T1049": "discovery", "T1057": "discovery",
  "T1082": "discovery", "T1083": "discovery", "T1087.001": "discovery", "T1580": "discovery",
  "T1021.004": "lateral-movement",
  "T1530": "collection",
  "T1105": "command-and-control",
};
const STAGES = [
  { n: 1, name: "robots.txt", desc: "Disallow entry points at a hidden backup folder", decoy: "admin", token: "ht-robots-backup-link" },
  { n: 2, name: "Backup .env", desc: "Exposed backup file carries the SSH password", decoy: "admin", token: "ht-env-backup-file" },
  { n: 3, name: "SSH login", desc: "Logs in to the SSH decoy with the leaked password", decoy: "ssh", token: "ht-ssh-password" },
  { n: 4, name: "AWS credentials", desc: "Reads the planted ~/.aws/credentials file", decoy: "ssh", token: "ht-aws-credentials-file" },
  { n: 5, name: "S3 access", desc: "Uses the stolen keys against the bucket", decoy: "s3", token: "ht-aws-access-key" },
  { n: 6, name: "passwords.xlsx", desc: "Downloads the bait spreadsheet", decoy: "s3", token: "ht-passwords-xlsx" },
];
const TOKEN_NAME = {
  "ht-robots-backup-link": "robots.txt breadcrumb", "ht-env-backup-file": "backup .env file",
  "ht-ssh-password": "SSH password", "ht-aws-credentials-file": "AWS credentials file",
  "ht-aws-access-key": "AWS access key", "ht-passwords-xlsx": "passwords.xlsx",
};
const DECOY_OF_SOURCE = { "admin-panel": "admin", ssh: "ssh", s3: "s3" };
const DECOY_IP = { admin: "10.66.0.20", ssh: "10.66.0.21", s3: "10.66.0.22" };
const SRC_CHIP = { "admin-panel": ["src-web", "WEB"], ssh: ["src-ssh", "SSH"], s3: ["src-s3", "S3"] };
const BAND_WORD = { idle: "clear", watch: "watch", tarpit: "tarpit", contain: "contain" };
const RGB = { idle: [107, 115, 130], watch: [255, 194, 71], tarpit: [255, 138, 61], contain: [255, 68, 56] };
const COL = { gold: [255, 194, 71], red: [255, 68, 56], ice: [143, 211, 255], green: [79, 211, 138], steel: [107, 115, 130],
              admin: [180, 140, 255], ssh: [95, 211, 240], s3: [255, 179, 71] };

const MAX_FEED = 300, MAX_EVENTS = 420;
const RM = matchMedia("(prefers-reduced-motion: reduce)").matches;

// ------------------------------------------------------------------ state
const state = {
  attackers: new Map(), events: [], alerts: [], responses: [],
  techniques: new Map(), tactics: new Map(),
  counts: { events: 0, alerts: 0 }, perSource: { "admin-panel": 0, ssh: 0, s3: 0 },
  theft: [], tokensSeen: new Set(), riskHist: [], fresh: new Set(),
};
const dirty = { model: true, feed: true, alerts: true, responses: true, theft: true, tech: true, charts: true };
let band = "idle", prevContainedIps = new Set(), lastChartDraw = 0, tl = null;

// ------------------------------------------------------------------ helpers
const $ = (id) => document.getElementById(id);
function el(tag, cls, text) { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
function tms(ts) { const t = +new Date(ts); return isNaN(t) ? 0 : t; }
function fmtTime(ts) { const d = new Date(ts); if (isNaN(d)) return String(ts || ""); return d.toLocaleTimeString([], { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0"); }
function fmtDur(ms) {
  if (ms == null || isNaN(ms)) return "·";
  if (ms < 1) return "under 1 ms";
  if (ms < 1000) return Math.round(ms) + " ms";
  if (ms < 60000) return (ms / 1000).toFixed(2) + " s";
  const m = Math.floor(ms / 60000), s = Math.round((ms % 60000) / 1000);
  return m + "m " + String(s).padStart(2, "0") + "s";
}
function fmtRel(ms) { return (ms < 0 ? "-" : "+") + (Math.abs(ms) < 10000 ? (Math.abs(ms) / 1000).toFixed(2) + " s" : fmtDur(Math.abs(ms))); }
function bandOf(a) {
  if (!a) return "idle"; if (a.contained_at) return "contain";
  const p = a.playbook; if (p === "watch" || p === "tarpit" || p === "contain") return p;   // the controller's verdict wins
  const r = a.risk_score || 0; return r >= 75 ? "contain" : r >= 40 ? "tarpit" : "watch";
}
function rgba(c, a) { return `rgba(${c[0]},${c[1]},${c[2]},${a})`; }
function lead() {
  let b = null;
  for (const a of state.attackers.values())
    if (!b || (a.risk_score || 0) > (b.risk_score || 0) || ((a.risk_score || 0) === (b.risk_score || 0) && (a.max_stage || 0) > (b.max_stage || 0))) b = a;
  return b;
}
function model() {
  const a = lead();
  const stage = a ? (a.max_stage || 0) : 0;
  const contained = a ? !!a.contained_at : false;
  const cur = !a ? null : stage >= 5 ? "s3" : stage >= 3 ? "ssh" : "admin";
  const lit = [!!a, stage >= 3, stage >= 5];
  const severed = contained ? (cur === "s3" ? 2 : cur === "ssh" ? 1 : 0) : -1;
  const t0 = a ? tms(a.first_seen) : 0;
  const ttc = contained && t0 ? tms(a.contained_at) - t0 : null;
  return { a, stage, contained, cur, lit, severed, t0, ttc, risk: a ? (a.risk_score || 0) : 0 };
}

// ------------------------------------------------------------------ ingest
function noteTechniques(list) {
  for (const t of list || []) {
    state.techniques.set(t, (state.techniques.get(t) || 0) + 1);
    const tac = TACTIC_OF[t]; if (tac) state.tactics.set(tac, (state.tactics.get(tac) || 0) + 1);
  }
}
function addEvent(e, live) {
  state.counts.events += 1;
  if (e.source in state.perSource) state.perSource[e.source] += 1;
  state.events.push(e);
  noteTechniques(e.techniques);
  if (e.honeytoken_id) { state.theft.unshift(e); state.tokensSeen.add(e.honeytoken_id); if (state.theft.length > 60) state.theft.length = 60; dirty.theft = true; }
  if (live) { state.fresh.add(e.id); const d = DECOY_OF_SOURCE[e.source]; if (d) heroPulse(d); }
  dirty.feed = dirty.tech = dirty.charts = dirty.model = true;
}
function sortEvents() {
  state.events.sort((a, b) => tms(b.ts) - tms(a.ts));
  if (state.events.length > MAX_EVENTS) state.events.length = MAX_EVENTS;
}
function addAlert(a) { state.counts.alerts += 1; state.alerts.unshift(a); if (state.alerts.length > 120) state.alerts.length = 120; dirty.alerts = dirty.charts = dirty.model = true; }
function addResponse(r) { state.responses.unshift(r); if (state.responses.length > 80) state.responses.length = 80; dirty.responses = dirty.model = dirty.charts = true; }
function upsertAttacker(a) {
  state.attackers.set(a.ip, a);
  state.riskHist.push({ t: Date.now(), r: a.risk_score || 0 }); if (state.riskHist.length > 90) state.riskHist.shift();
  if (a.contained_at && !prevContainedIps.has(a.ip)) { prevContainedIps.add(a.ip); onContained(a); }
  if (!a.contained_at) prevContainedIps.delete(a.ip);
  dirty.model = dirty.charts = true;
}
function onContained(a) {
  const m = model();
  const node = (m.a && m.a.ip === a.ip) ? m.cur : ((a.max_stage || 0) >= 5 ? "s3" : (a.max_stage || 0) >= 3 ? "ssh" : "admin");
  heroShock(node);
  const v = $("int-verdict"); v.classList.remove("slam"); void v.offsetWidth; v.classList.add("slam");
}

// ------------------------------------------------------------------ render: top + intruder + hero tiles + KPI + trail
function renderModel() {
  const m = model();
  const list = [...state.attackers.values()];
  const maxRisk = list.reduce((x, a) => Math.max(x, a.risk_score || 0), 0);
  const anyContained = list.some((a) => a.contained_at);
  band = anyContained ? "contain" : m.a ? bandOf(m.a) : "idle";
  document.body.dataset.band = band;

  // top ladder
  $("ladder-pin").style.left = `calc(${maxRisk}% - 1px)`;
  $("ladder-read").textContent = `${maxRisk} · ${anyContained ? "contained" : BAND_WORD[band]}`;

  // headline
  const h = $("hero-line"); h.replaceChildren();
  const hl = (t) => el("span", "hl", t);
  if (!m.a) h.append("Decoys armed. Nothing in the trap.");
  else if (m.contained) h.append(`${m.a.ip} walked ${m.stage} of 6 stages into the trap. `, hl(`Cut off ${fmtDur(m.ttc)} after first contact.`));
  else if (band === "tarpit") h.append(`${m.a.ip} is on the trail at stage ${m.stage} of 6. `, hl(`Tarpit active, risk ${m.risk}.`));
  else if (m.stage > 0) h.append(`${m.a.ip} took the bait. `, hl(`Stage ${m.stage} of 6, risk ${m.risk}.`));
  else h.append(`${m.a.ip} is probing the admin panel decoy. `, hl(`Risk ${m.risk}, watching.`));
  $("hero-kicker").textContent = m.a
    ? `First contact ${fmtTime(m.a.first_seen)} · ${m.a.event_count || state.counts.events} events · ${(m.a.tokens || []).length} of 6 honeytokens`
    : "Isolated lab · 3 decoys · 6-stage breadcrumb trail";

  // intruder panel
  const verdict = !m.a ? "decoys armed" : m.contained ? "contained" : (m.a.playbook || BAND_WORD[band]);
  $("int-seen").textContent = m.a ? `first seen ${fmtTime(m.a.first_seen)}` : "not seen";
  $("int-ip").textContent = m.a ? m.a.ip : "0.0.0.0";
  $("int-ip").style.opacity = m.a ? 1 : .25;
  $("int-verdict-word").textContent = verdict;
  $("int-risk").textContent = m.risk;
  $("risk-fill").style.width = m.risk + "%";
  $("int-stage-word").textContent = `stage ${m.stage} of 6`;
  const segs = $("int-segs").children;
  for (let i = 0; i < 6; i++) {
    const s = segs[i]; s.className = "";
    if (i + 1 < m.stage || (i + 1 === m.stage && m.contained)) s.classList.add("on");
    if (i + 1 === m.stage && !m.contained) s.classList.add("cur");
    if (m.contained && i + 1 === m.stage) s.classList.add("cut");
  }
  $("int-events").textContent = m.a ? (m.a.event_count || 0) : 0;
  $("int-tech").textContent = m.a ? (m.a.techniques || []).length : 0;
  $("int-tokens").textContent = m.a ? (m.a.tokens || []).length : 0;
  $("btn-contain").disabled = !m.a || m.contained;
  $("btn-release").disabled = !m.a || !m.contained;

  // hero tiles
  const atk = $("tile-atk");
  atk.classList.toggle("on", !!m.a); atk.classList.toggle("banned", m.contained);
  $("atk-ip").textContent = m.a ? m.a.ip : "none yet";
  $("atk-state").textContent = !m.a ? "no contact" : m.contained ? "banned on all 3 decoys" : m.stage > 0 ? `on the trail · stage ${m.stage}` : "scanning the admin panel";
  const tileState = {
    admin: !m.a ? "armed" : m.cur === "admin" ? (m.contained ? "intruder blocked here" : m.stage >= 1 ? "lure taken" : "being scanned") : "breadcrumbs taken",
    ssh: !m.a || m.stage < 3 ? "armed" : m.cur === "ssh" ? (m.contained ? "session evicted · blocked" : "intruder inside") : "credentials leaked",
    s3: !m.a || m.stage < 5 ? "armed" : (m.contained ? "download blocked" : "intruder reading the bucket"),
  };
  for (const d of ["admin", "ssh", "s3"]) {
    const t = $("tile-" + d); t.classList.remove("reached", "current", "trapped");
    const reached = d === "admin" ? m.stage >= 1 : d === "ssh" ? m.stage >= 3 : m.stage >= 5;
    if (m.cur === d && m.a) t.classList.add(m.contained ? "trapped" : "current"); else if (reached) t.classList.add("reached");
    $("st-" + d).textContent = tileState[d];
    const n = state.perSource[d === "admin" ? "admin-panel" : d];
    $("ct-" + d).textContent = n ? n + " ev" : "0"; t.classList.toggle("hit", n > 0);
  }
  $("st-ctrl").textContent = !m.a ? "watching 3 decoys" : m.contained ? "contain playbook fired" : `${m.a.playbook || "watch"} playbook · risk ${m.risk}`;

  // KPI strip
  $("k-trap").textContent = list.length; $("k-trap-s").textContent = m.a ? m.a.ip : "decoys armed";
  // The controller's own per-attacker counts are authoritative; the feed only
  // holds the newest 200 rows from first paint plus live arrivals.
  const recorded = list.reduce((s, a) => s + (a.event_count || 0), 0);
  $("k-events").textContent = Math.max(recorded, state.counts.events);
  $("k-alerts").textContent = state.counts.alerts;
  $("k-alerts-s").textContent = `${state.alerts.filter((x) => x.severity === "high" || x.severity === "critical").length} high or worse`;
  $("k-risk").textContent = maxRisk; $("k-risk-s").textContent = anyContained ? "contained" : BAND_WORD[band];
  $("k-risk").parentElement.classList.add("band");
  const nC = list.filter((a) => a.contained_at).length;
  $("k-contained").textContent = nC; $("k-contained").parentElement.classList.toggle("hot", nC > 0);
  const lastC = state.responses.find((r) => r.action === "containment_sequence");
  const reached = lastC && lastC.details && lastC.details.actions && lastC.details.actions.enforcement ? (lastC.details.actions.enforcement.reached || []).length : 0;
  $("k-contained-s").textContent = nC ? `blocked on ${reached} of 3 decoys` : "no ban active";
  const blocks = $("k-blocks").children; for (let i = 0; i < 3; i++) blocks[i].classList.toggle("on", nC > 0 && i < reached);
  $("k-ttc").textContent = m.ttc != null ? fmtDur(m.ttc) : "·";
  $("k-ttc").parentElement.classList.toggle("hot", m.ttc != null);
  $("k-ttc-s").textContent = m.ttc != null ? `from first contact · stage ${m.stage}` : "from first contact";
  $("k-ttd-s").textContent = "detect lag " + fmtDur(detectLag());

  renderTrail(m);
  renderTactics();
}
function detectLag() {
  const byId = new Map(); for (const e of state.events) byId.set(e.id, e);
  let sum = 0, n = 0;
  for (const a of state.alerts) { const e = byId.get(a.event_id); if (e) { sum += Math.max(0, tms(a.ts) - tms(e.ts)); n++; } }
  return n ? sum / n : NaN;
}
function firstTouch() {
  const ft = {};
  for (const e of state.events) {
    const s = e.stage || 0; if (!s) continue;
    const t = tms(e.ts); if (!ft[s] || t < ft[s]) ft[s] = t;
  }
  return ft;
}
function renderTrail(m) {
  const host = $("stages"); host.replaceChildren();
  const ft = firstTouch(); const t0 = m.t0 || Math.min(...Object.values(ft), Infinity);
  for (const s of STAGES) {
    const li = el("li", "stage");
    const reached = m.a && s.n <= m.stage, cur = m.a && s.n === m.stage && !m.contained;
    if (reached && !cur) li.classList.add("on"); if (cur) li.classList.add("cur"); if (m.a && s.n > m.stage) li.classList.add("beyond");
    li.append(el("span", "stage-n", "Stage " + s.n), el("span", "stage-name", s.name), el("span", "stage-desc", s.desc));
    const time = ft[s.n] && t0 && reached ? fmtRel(ft[s.n] - t0) : (m.a ? (reached ? "touched" : "not reached") : "waiting");
    li.append(el("span", "stage-time mono", time), el("span", "stage-decoy mono", `${s.decoy === "admin" ? "admin panel" : s.decoy} · ${DECOY_IP[s.decoy]}`));
    host.append(li);
  }
  const W = host.clientWidth, gap = 10, col = (W - gap * 5) / 6, dotX = (n) => (n - 1) * (col + gap) + 5;
  $("trail-fill").style.width = (m.a && m.stage > 0 ? dotX(m.stage) : 0) + "px";
  const cut = $("trail-cut"); cut.hidden = !m.contained;
  if (m.contained) cut.style.left = (m.stage >= 6 ? W - 2 : m.stage === 0 ? 0 : dotX(m.stage) + col * .55) + "px";
  $("trail-meta").textContent = !m.a ? "no intruder" : m.contained ? `cut after stage ${m.stage} · ${fmtDur(m.ttc)} after first contact` : `stage ${m.stage} of 6 · ${(m.a.tokens || []).length} tokens taken`;
}
function renderTactics() {
  const host = $("tactics"); host.replaceChildren(); let on = 0;
  const idsOf = {}; for (const [tid, tac] of Object.entries(TACTIC_OF)) if (state.techniques.has(tid)) (idsOf[tac] = idsOf[tac] || []).push(tid);
  for (const [id, name] of TACTICS) {
    const n = state.tactics.get(id) || 0; const t = el("div", "tactic" + (n ? " on" : ""));
    if (n && (id === "collection" || id === "exfiltration")) t.classList.add("hot");
    t.append(el("span", "tactic-name", name), el("span", "tactic-ids mono", n ? (idsOf[id] || []).join(" ") : "not seen"), el("span", "tactic-n", n ? n : "·"));
    host.append(t); if (n) on++;
  }
  $("tactics-meta").textContent = `${on} of 12`;
}

// ------------------------------------------------------------------ render: lists
function describe(e) {
  const d = e.details || {}, what = el("span", "what");
  const b = (t) => el("b", null, t);
  switch (e.event_type) {
    case "http_request":
    case "file_access":
      what.append(`${d.method || "GET"} `, b(e.asset || "/"), ` ${d.status != null ? d.status : ""}`);
      if (d.user_agent) what.append(` · ${d.user_agent}`);
      break;
    case "login_attempt": {
      what.append("login ", b(d.username || e.asset || "?"));
      if (d.password != null) what.append(` · pw "${d.password}"`);
      what.append(" · ", el("span", d.success ? "ok" : "fail", d.success ? "accepted" : (d.contained ? "refused, contained" : "failed")));
      break;
    }
    case "command": what.append("$ ", b(d.command || "")); if (d.exit_status != null) what.append(` → ${d.exit_status}`); break;
    case "session_start": what.append("session ", b(String(e.session_id || "").slice(0, 12)), ` opened · ${d.mode || "shell"}`); break;
    case "session_end": what.append("session ", b(String(e.session_id || "").slice(0, 12)), ` closed · ${d.commands ?? 0} cmd · ${d.duration ?? 0} s`); break;
    case "honeytoken_used": what.append("honeytoken ", b(e.honeytoken_id || ""), " used", e.asset ? ` on ${e.asset}` : ""); break;
    default: what.append(String(e.event_type || "").replace(/_/g, " "), " ", b(e.asset || ""));
  }
  return what;
}
function feedRow(e) {
  const stage = e.stage || 0;
  const row = el("div", "row-ev" + (stage ? " stage s" + stage : "") + (state.fresh.has(e.id) ? " fresh" : ""));
  row.append(el("span", "t", fmtTime(e.ts)));
  const [cls, lab] = SRC_CHIP[e.source] || ["", String(e.source || "")];
  row.append(el("span", "src " + cls, lab), describe(e), el("span", "sx", stage ? "S" + stage : ""));
  return row;
}
function renderFeed() {
  sortEvents();
  const host = $("feed-list"), frag = document.createDocumentFragment();
  const n = Math.min(state.events.length, MAX_FEED);
  for (let i = 0; i < n; i++) frag.append(feedRow(state.events[i]));
  host.replaceChildren(frag); state.fresh.clear();
  $("feed-empty").hidden = n > 0;
  $("feed-meta").textContent = n ? `${n} shown · newest first` : "newest first";
}
function renderAlerts() {
  const host = $("alert-list"), frag = document.createDocumentFragment();
  for (const a of state.alerts.slice(0, 80)) {
    const row = el("div", "alert sev-" + (a.severity || "low"));
    row.append(el("span", "sev", String(a.severity || "low").toUpperCase()));
    const body = el("div");
    body.append(el("div", "alert-title", a.title), el("div", "alert-sub", `${a.src_ip} · ${fmtTime(a.ts)}${a.stage ? " · stage " + a.stage : ""}`));
    row.append(body); frag.append(row);
  }
  host.replaceChildren(frag);
  $("alerts-empty").hidden = state.alerts.length > 0;
  $("alerts-meta").textContent = state.counts.alerts;
}
const ACTION_NAME = { containment_sequence: "Containment sequence", throttle_connection: "Tarpit", release: "Release" };
function renderResponses() {
  const host = $("resp-list"), frag = document.createDocumentFragment();
  for (const r of state.responses.slice(0, 60)) {
    const resp = el("div", "resp " + (r.playbook || "watch"));
    const top = el("div", "resp-top");
    top.append(el("span", "resp-act", ACTION_NAME[r.action] || String(r.action || "").replace(/_/g, " ")), el("span", "resp-ip", `${r.src_ip} · ${fmtTime(r.ts)}`));
    resp.append(top);
    const d = r.details || {}, acts = d.actions || {};
    if (d.reason) resp.append(el("div", "resp-why", d.reason));
    const steps = el("div", "resp-steps");
    const add = (txt, kind) => steps.append(el("span", "step " + kind, txt));
    if (acts.eviction) { const n = acts.eviction.terminated || 0; add(n ? `evicted ${n} session${n > 1 ? "s" : ""}` : "evict · no live session", n ? "real" : "none"); }
    if (acts.enforcement) {
      const n = Array.isArray(acts.enforcement) ? acts.enforcement.length : (acts.enforcement.reached || []).length;
      const f = Array.isArray(acts.enforcement) ? 0 : (acts.enforcement.failed || []).length;
      add(`blocked on ${n} decoy${n === 1 ? "" : "s"}`, n ? "real" : "none"); if (f) add(`${f} decoy${f === 1 ? "" : "s"} unreachable`, "none");
    }
    if (acts.firewall) { const be = acts.firewall.backend || (typeof acts.firewall === "string" ? acts.firewall : ""); add(`firewall ban · ${be || "unknown"}`, be && be !== "simulated" ? "real" : "sim"); }
    if (acts.snapshot) { const be = acts.snapshot.backend || ""; add(`evidence snapshot · ${be || "unknown"}`, be && be !== "simulated" ? "real" : "sim"); }
    if (d.delay_seconds) add(`${d.delay_seconds} s delay`, "real");
    if (r.action === "release") add("ban lifted", "real");
    if (steps.childElementCount) resp.append(steps);
    frag.append(resp);
  }
  host.replaceChildren(frag);
  $("resp-empty").hidden = state.responses.length > 0;
}
function renderTheft() {
  const host = $("theft-list"), frag = document.createDocumentFragment();
  for (const e of state.theft.slice(0, 40)) {
    const row = el("div", "theft-row" + (e.stage ? " s" + e.stage : ""));
    const d = e.details || {};
    const where = e.event_type === "login_attempt" ? `${e.honeytoken_id} · user ${d.username || e.asset || ""}` : `${e.honeytoken_id} · ${e.asset || e.src_ip || ""}`;
    row.append(el("span", "t", fmtTime(e.ts)), el("span", "tok", TOKEN_NAME[e.honeytoken_id] || e.honeytoken_id), el("span", "loc", where));
    frag.append(row);
  }
  host.replaceChildren(frag);
  $("theft-empty").hidden = state.theft.length > 0;
  $("theft-meta").textContent = `${state.tokensSeen.size} of 6 honeytokens`;
}
function renderTechniques() {
  const host = $("tech-list"), frag = document.createDocumentFragment();
  const items = [...state.techniques.entries()].sort((a, b) => b[1] - a[1]);
  const max = items.length ? items[0][1] : 1;
  for (const [id, n] of items) {
    const t = el("div", "tech"); t.style.setProperty("--w", Math.round((n / max) * 100) + "%");
    t.append(el("span", "tech-id", id), el("span", "tech-name", ATTACK[id] || "technique"), el("span", "tech-n", "×" + n));
    frag.append(t);
  }
  host.replaceChildren(frag);
  $("tech-count").textContent = items.length;
  $("tech-empty").hidden = items.length > 0;
}

// ------------------------------------------------------------------ timeline model + charts
function buildTimeline() {
  if (!state.events.length) return null;
  let t0 = Infinity, t1 = -Infinity;
  for (const e of state.events) { const t = tms(e.ts); if (t < t0) t0 = t; if (t > t1) t1 = t; }
  const m = model();
  if (m.a) { const c = tms(m.a.contained_at); if (c) t1 = Math.max(t1, c); t0 = Math.min(t0, tms(m.a.first_seen) || t0); }
  for (const a of state.alerts) t1 = Math.max(t1, tms(a.ts));
  const span = Math.max(t1 - t0, 1000) * 1.05;
  const N = 120, binMs = span / N;
  const src = { "admin-panel": new Float32Array(N), ssh: new Float32Array(N), s3: new Float32Array(N) }, total = new Float32Array(N), alerts = new Float32Array(N);
  const idx = (t) => Math.max(0, Math.min(N - 1, Math.floor((t - t0) / binMs)));
  for (const e of state.events) { const i = idx(tms(e.ts)); total[i] += 1; if (src[e.source]) src[e.source][i] += 1; }
  for (const a of state.alerts) alerts[idx(tms(a.ts))] += 1;
  const perSec = 1000 / binMs;
  let peak = 0; for (let i = 0; i < N; i++) peak = Math.max(peak, total[i]);
  return { t0, span, N, binMs, src, total, alerts, perSec, peak: peak * perSec, stages: firstTouch(), containedAt: m.contained ? tms(m.a.contained_at) : 0, alertList: state.alerts };
}
function fitCanvas(cv) {
  const dpr = Math.min(devicePixelRatio || 1, 2), w = cv.clientWidth, h = cv.clientHeight;
  if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) { cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr); }
  const g = cv.getContext("2d"); g.setTransform(dpr, 0, 0, dpr, 0, 0); return [g, w, h];
}
function drawTimeline() {
  const cv = $("timeline"); const [g, W, H] = fitCanvas(cv);
  g.clearRect(0, 0, W, H);
  $("chart-empty").hidden = !!tl;
  if (!tl) return;
  const L = 50, R = 14, T = 40, B = 22, pw = W - L - R, ph = H - T - B;
  const ymax = Math.max(1, niceCeil(tl.peak));
  const x = (t) => L + ((t - tl.t0) / tl.span) * pw;
  const y = (v) => T + ph - (v / ymax) * ph;
  // grid
  g.strokeStyle = "rgba(255,255,255,.05)"; g.lineWidth = 1; g.font = "10px JetBrains Mono, monospace"; g.fillStyle = "rgba(255,255,255,.35)"; g.textAlign = "right"; g.textBaseline = "middle";
  for (let i = 0; i <= 3; i++) { const v = (ymax / 3) * i, yy = y(v); g.beginPath(); g.moveTo(L, yy); g.lineTo(W - R, yy); g.stroke(); g.fillText(fmtRate(v), L - 6, yy); }
  g.textBaseline = "top";
  for (let i = 0; i <= 5; i++) { const t = tl.t0 + (tl.span * i) / 5; g.textAlign = i === 0 ? "left" : i === 5 ? "right" : "center"; g.fillText(fmtRel(t - tl.t0), x(t), T + ph + 6); }
  g.save(); g.translate(11, T + ph / 2); g.rotate(-Math.PI / 2); g.textAlign = "center"; g.textBaseline = "middle"; g.fillStyle = "rgba(255,255,255,.3)"; g.fillText("events / s", 0, 0); g.restore();
  // stacked areas
  const order = [["admin-panel", COL.admin], ["ssh", COL.ssh], ["s3", COL.s3]];
  const base = new Float32Array(tl.N);
  const bx = (i) => L + ((i + .5) / tl.N) * pw;
  for (const [k, c] of order) {
    const arr = tl.src[k]; let any = false; for (let i = 0; i < tl.N; i++) if (arr[i]) { any = true; break; }
    if (!any) continue;
    g.beginPath();
    for (let i = 0; i < tl.N; i++) { const yy = y((base[i] + arr[i]) * tl.perSec); i ? g.lineTo(bx(i), yy) : g.moveTo(bx(i), yy); }
    for (let i = tl.N - 1; i >= 0; i--) g.lineTo(bx(i), y(base[i] * tl.perSec));
    g.closePath();
    const grad = g.createLinearGradient(0, T, 0, T + ph); grad.addColorStop(0, rgba(c, .55)); grad.addColorStop(1, rgba(c, .08));
    g.fillStyle = grad; g.fill();
    g.beginPath(); for (let i = 0; i < tl.N; i++) { const yy = y((base[i] + arr[i]) * tl.perSec); i ? g.lineTo(bx(i), yy) : g.moveTo(bx(i), yy); }
    g.strokeStyle = rgba(c, .35); g.lineWidth = 4; g.stroke();
    g.strokeStyle = rgba(c, 1); g.lineWidth = 1.3; g.stroke();
    for (let i = 0; i < tl.N; i++) base[i] += arr[i];
  }
  // alert ticks
  for (const a of tl.alertList) {
    const xx = x(tms(a.ts)); const c = a.severity === "critical" ? COL.red : a.severity === "high" ? [255, 138, 61] : a.severity === "medium" ? COL.gold : COL.steel;
    g.strokeStyle = rgba(c, .9); g.lineWidth = 1.5; g.beginPath(); g.moveTo(xx, T + ph - 1); g.lineTo(xx, T + ph - 7); g.stroke();
  }
  // stage markers: numbered pins at the first touch of each trail stage (names only where there is room)
  const keys = Object.keys(tl.stages).sort((a, b) => a - b), pinY = T - 12;
  g.textBaseline = "middle";
  for (let i = 0; i < keys.length; i++) {
    const n = keys[i], xx = x(tl.stages[n]), st = STAGES[n - 1];
    const nextX = i + 1 < keys.length ? x(tl.stages[keys[i + 1]]) : W - R + 20;
    g.strokeStyle = rgba(COL.gold, .35); g.lineWidth = 1; g.setLineDash([2, 4]); g.beginPath(); g.moveTo(xx, pinY + 8); g.lineTo(xx, T + ph); g.stroke(); g.setLineDash([]);
    g.fillStyle = "#0b0d12"; g.beginPath(); g.arc(xx, pinY, 7, 0, 7); g.fill();
    g.strokeStyle = rgba(COL.gold, 1); g.lineWidth = 1.2; g.stroke();
    g.font = "600 10px Barlow Condensed, sans-serif"; g.textAlign = "center"; g.fillStyle = rgba(COL.gold, 1); g.fillText(String(n), xx, pinY + .5);
    if (st) { g.font = "500 10px Inter, sans-serif"; const tw = g.measureText(st.name).width; if (xx + 10 + tw < nextX - 10 && xx + 10 + tw < W - R) { g.textAlign = "left"; g.fillStyle = "rgba(255,255,255,.55)"; g.fillText(st.name, xx + 10, pinY); } }
  }
  // containment cut: the label sits on its own row above the pins
  if (tl.containedAt) {
    const xx = x(tl.containedAt);
    g.strokeStyle = rgba(COL.red, .95); g.lineWidth = 2; g.shadowColor = rgba(COL.red, .9); g.shadowBlur = 10;
    g.beginPath(); g.moveTo(xx, 14); g.lineTo(xx, T + ph); g.stroke(); g.shadowBlur = 0;
    g.font = "600 11px Barlow Condensed, sans-serif"; g.fillStyle = rgba(COL.red, 1); g.textBaseline = "middle";
    const label = `trap sprang ${fmtRel(tl.containedAt - tl.t0)}`; const tw = g.measureText(label).width;
    const right = xx + tw + 8 > W - R; g.textAlign = right ? "right" : "left"; g.fillText(label, xx + (right ? -7 : 7), 8);
  }
}
function niceCeil(v) { if (v <= 0) return 1; const p = Math.pow(10, Math.floor(Math.log10(v))); const m = v / p; const n = m <= 1 ? 1 : m <= 2 ? 2 : m <= 3 ? 3 : m <= 5 ? 5 : 10; return n * p; }
function fmtRate(v) { return v >= 1000 ? (v / 1000).toFixed(v >= 10000 ? 0 : 1) + "k" : v >= 10 ? Math.round(v) : v.toFixed(v ? 1 : 0); }
function drawSpark(id, series, c, step) {
  const cv = $(id); const [g, W, H] = fitCanvas(cv); g.clearRect(0, 0, W, H);
  if (!series || series.length < 2) return;
  let max = 0; for (const v of series) max = Math.max(max, v); if (!max) max = 1;
  const n = series.length, sx = (i) => (i / (n - 1)) * (W - 2) + 1, sy = (v) => H - 2 - (v / max) * (H - 5);
  g.beginPath();
  for (let i = 0; i < n; i++) { const xx = sx(i), yy = sy(series[i]); if (!i) g.moveTo(xx, yy); else if (step) { g.lineTo(xx, sy(series[i - 1])); g.lineTo(xx, yy); } else g.lineTo(xx, yy); }
  g.strokeStyle = rgba(c, .95); g.lineWidth = 1.4; g.lineJoin = "round"; g.stroke();
  g.lineTo(W - 1, H); g.lineTo(1, H); g.closePath();
  const grad = g.createLinearGradient(0, 0, 0, H); grad.addColorStop(0, rgba(c, .35)); grad.addColorStop(1, rgba(c, 0)); g.fillStyle = grad; g.fill();
}
function drawCharts() {
  tl = buildTimeline();
  drawTimeline();
  drawSpark("sp-events", tl ? Array.from(tl.total) : null, COL.gold);
  drawSpark("sp-alerts", tl ? Array.from(tl.alerts) : null, [255, 138, 61]);
  drawSpark("sp-risk", state.riskHist.length > 1 ? state.riskHist.map((p) => p.r) : null, RGB[band === "idle" ? "watch" : band], true);
  $("k-events-s").textContent = tl ? `${fmtRate(tl.peak)} ev/s peak` : "0 ev/s peak";
}

// ------------------------------------------------------------------ hero: the lab floor
const hero = { cv: null, g: null, W: 0, H: 0, cx: 0, cy: 0, k: 1, floor: null, fade: null, pts: {}, mon: {}, pulses: [], shocks: [], flash: {}, banAt: 0 };
const PITCH = 0.66, PC = Math.cos(PITCH), PS = Math.sin(PITCH), YAW = -0.22, YC = Math.cos(YAW), YS = Math.sin(YAW), FOCAL = 1500, CAMD = 1700;
const NODES = {
  atk:   { x: -540, z: 260, h: 80 },
  admin: { x: -240, z: 120, h: 74 },
  ssh:   { x: 20, z: -60, h: 74 },
  s3:    { x: 360, z: 140, h: 74 },
  ctrl:  { x: 280, z: -320, h: 78 },
  legit: { x: 620, z: -110, h: 70 },
};
const SEGS = [["atk", "admin"], ["admin", "ssh"], ["ssh", "s3"]];
function proj(x, y, z) {
  const x1 = x * YC - z * YS, z1 = x * YS + z * YC;
  const yc = y * PC - z1 * PS, zc = y * PS + z1 * PC, s = (FOCAL / (CAMD - zc)) * hero.k;
  return [hero.cx + x1 * s, hero.cy - yc * s, s];
}
function bez3(a, b, lift, n) {
  const out = [], p0 = [a.x, 4, a.z], p3 = [b.x, 4, b.z];
  const p1 = [a.x + (b.x - a.x) * .28, lift, a.z + (b.z - a.z) * .28], p2 = [a.x + (b.x - a.x) * .72, lift, a.z + (b.z - a.z) * .72];
  for (let i = 0; i <= n; i++) {
    const t = i / n, u = 1 - t, w0 = u * u * u, w1 = 3 * u * u * t, w2 = 3 * u * t * t, w3 = t * t * t;
    out.push(proj(w0 * p0[0] + w1 * p1[0] + w2 * p2[0] + w3 * p3[0], w0 * p0[1] + w1 * p1[1] + w2 * p2[1] + w3 * p3[1], w0 * p0[2] + w1 * p1[2] + w2 * p2[2] + w3 * p3[2]));
  }
  return out;
}
function ellipsePath(g, x, z, r, y) {
  g.beginPath();
  for (let i = 0; i <= 36; i++) { const a = (i / 36) * Math.PI * 2, p = proj(x + Math.cos(a) * r, y || 0, z + Math.sin(a) * r); i ? g.lineTo(p[0], p[1]) : g.moveTo(p[0], p[1]); }
  g.closePath();
}
function sizeHero() {
  const host = $("hero"), cv = $("net"); hero.cv = cv; hero.g = cv.getContext("2d");
  const dpr = Math.min(devicePixelRatio || 1, 2);
  hero.W = host.clientWidth; hero.H = host.clientHeight;
  cv.width = Math.round(hero.W * dpr); cv.height = Math.round(hero.H * dpr); hero.g.setTransform(dpr, 0, 0, dpr, 0, 0);
  const region = hero.W - 380;
  hero.cx = region * .5 + 44; hero.cy = hero.H * .64; hero.k = Math.min(region / 1200, hero.H / 420);
  hero.pts = {}; for (const [i, [a, b]] of SEGS.entries()) hero.pts[i] = bez3(NODES[a], NODES[b], 95, 48);
  hero.mon = {}; for (const d of ["admin", "ssh", "s3"]) hero.mon[d] = bez3(NODES[d], NODES.ctrl, 160, 30);
  // cached floor grid: brighter near the camera, dissolving toward the horizon
  const fl = document.createElement("canvas"); fl.width = cv.width; fl.height = cv.height; const f = fl.getContext("2d"); f.setTransform(dpr, 0, 0, dpr, 0, 0);
  f.lineWidth = 1;
  const Z0 = -900, Z1 = 460, STEP = 64;
  for (let z = Z0; z <= Z1; z += STEP) { const u = (z - Z0) / (Z1 - Z0); f.strokeStyle = `rgba(205,215,235,${.025 + .13 * u * u})`; f.beginPath(); let p = proj(-1900, 0, z); f.moveTo(p[0], p[1]); p = proj(1900, 0, z); f.lineTo(p[0], p[1]); f.stroke(); }
  for (let x = -1900; x <= 1900; x += STEP) {
    const gr = f.createLinearGradient(...proj(x, 0, Z0).slice(0, 2), ...proj(x, 0, Z1).slice(0, 2));
    gr.addColorStop(0, "rgba(205,215,235,.02)"); gr.addColorStop(1, "rgba(205,215,235,.15)");
    f.strokeStyle = gr; f.beginPath(); let p = proj(x, 0, Z0); f.moveTo(p[0], p[1]); p = proj(x, 0, Z1); f.lineTo(p[0], p[1]); f.stroke();
  }
  hero.floor = fl;
  // cached edge fade
  const fd = document.createElement("canvas"); fd.width = cv.width; fd.height = cv.height; const e = fd.getContext("2d"); e.setTransform(dpr, 0, 0, dpr, 0, 0);
  const vo = "#07080b";
  let gr = e.createLinearGradient(0, 0, 0, hero.H); gr.addColorStop(0, vo); gr.addColorStop(.16, "rgba(7,8,11,0)"); gr.addColorStop(.84, "rgba(7,8,11,0)"); gr.addColorStop(1, vo); e.fillStyle = gr; e.fillRect(0, 0, hero.W, hero.H);
  gr = e.createLinearGradient(0, 0, hero.W, 0); gr.addColorStop(0, vo); gr.addColorStop(.07, "rgba(7,8,11,0)"); gr.addColorStop(Math.max(.5, (region - 20) / hero.W), "rgba(7,8,11,0)"); gr.addColorStop(Math.min(1, (region + 60) / hero.W), "rgba(7,8,11,.55)"); gr.addColorStop(1, "rgba(7,8,11,.8)"); e.fillStyle = gr; e.fillRect(0, 0, hero.W, hero.H);
  hero.fade = fd;
  // tiles follow the pillar tops and shrink with the scene on narrow screens (camera is static, so only on resize)
  const ts = Math.max(.72, Math.min(1, hero.k / .88));
  for (const id of Object.keys(NODES)) { const n = NODES[id], p = proj(n.x, n.h, n.z); const t = $("tile-" + id); if (t) t.style.transform = `translate(${p[0].toFixed(1)}px, ${p[1].toFixed(1)}px) translate(-50%, -100%) scale(${ts.toFixed(3)})`; }
}
function heroPulse(decoy) { if (RM || hero.pulses.length > 70) return; hero.pulses.push({ d: decoy, born: performance.now() }); }
function heroShock(node) { if (RM) return; const now = performance.now(); hero.banAt = now; hero.shocks.push({ node, born: now }, { node, born: now + 160 }); for (const d of ["admin", "ssh", "s3"]) hero.flash[d] = now + 120; }
function ptAt(pts, t) { t = t < 0 ? 0 : t > 1 ? 1 : t; const f = t * (pts.length - 1), i = Math.floor(f), u = f - i, a = pts[Math.min(i, pts.length - 1)], b = pts[Math.min(i + 1, pts.length - 1)]; return [a[0] + (b[0] - a[0]) * u, a[1] + (b[1] - a[1]) * u]; }
function strokePts(g, pts, from, to) { g.beginPath(); const i0 = Math.max(0, Math.floor(from * (pts.length - 1))), i1 = Math.min(pts.length - 1, Math.ceil(to * (pts.length - 1))); for (let i = i0; i <= i1; i++) i === i0 ? g.moveTo(pts[i][0], pts[i][1]) : g.lineTo(pts[i][0], pts[i][1]); g.stroke(); }
function drawHero(now) {
  const g = hero.g; if (!g) return;
  const W = hero.W, H = hero.H, m = model(), bc = RGB[band] || RGB.idle;
  g.clearRect(0, 0, W, H);
  // horizon glow in the band colour, then the cached floor grid on top
  { const hp = proj(0, 0, -900); const gr = g.createRadialGradient(hp[0], hp[1], 0, hp[0], hp[1], W * .55); gr.addColorStop(0, rgba(bc, band === "idle" ? .10 : .20)); gr.addColorStop(.5, rgba(bc, .04)); gr.addColorStop(1, rgba(bc, 0)); g.fillStyle = gr; g.fillRect(0, 0, W, H); }
  g.drawImage(hero.floor, 0, 0, W, H);

  // floor glows
  const glow = (id, c, a, r) => { const n = NODES[id], p = proj(n.x, 0, n.z), s = p[2] * r; const gr = g.createRadialGradient(p[0], p[1], 0, p[0], p[1], s); gr.addColorStop(0, rgba(c, a)); gr.addColorStop(1, rgba(c, 0)); g.fillStyle = gr; g.save(); g.translate(p[0], p[1]); g.scale(1, .42); g.translate(-p[0], -p[1]); g.beginPath(); g.arc(p[0], p[1], s, 0, 7); g.fill(); g.restore(); };
  if (m.a) glow("atk", COL.red, m.contained ? .16 : .28, 230);
  if (m.cur) glow(m.cur, m.contained ? COL.red : bc, .30, 250);
  glow("ctrl", COL.ice, .12, 220);

  // monitoring beams (controller watches each decoy); they flare red when the ban lands
  const banAge = hero.banAt ? now - hero.banAt : 1e9, banHot = Math.max(0, 1 - banAge / 1800);
  g.setLineDash([2, 6]); g.lineWidth = 1; g.lineDashOffset = RM ? 0 : -(now * .02) % 8;
  for (const d of ["admin", "ssh", "s3"]) {
    g.strokeStyle = banHot ? rgba(COL.ice, .25 + .6 * banHot) : rgba(COL.ice, .34); g.lineWidth = 1 + banHot * 1.2; strokePts(g, hero.mon[d], 0, 1);
  }
  g.setLineDash([]); g.lineDashOffset = 0;
  // telemetry pulses
  if (hero.pulses.length) {
    const keep = [];
    for (const p of hero.pulses) { const t = (now - p.born) / 700; if (t > 1) continue; keep.push(p); const q = ptAt(hero.mon[p.d], t); g.fillStyle = rgba(COL.ice, .9 * (1 - t * .5)); g.beginPath(); g.arc(q[0], q[1], 2.2, 0, 7); g.fill(); g.fillStyle = rgba(COL.ice, .18); g.beginPath(); g.arc(q[0], q[1], 6, 0, 7); g.fill(); }
    hero.pulses = keep;
  }

  // trail segments
  for (let i = 0; i < 3; i++) {
    const pts = hero.pts[i], lit = m.lit[i], sev = m.severed === i;
    g.lineWidth = 2; g.strokeStyle = "rgba(255,255,255,.11)"; strokePts(g, pts, 0, 1);
    g.setLineDash([1, 9]); g.lineWidth = 3; g.strokeStyle = "rgba(255,255,255,.14)"; strokePts(g, pts, 0, 1); g.setLineDash([]);
    if (!lit) continue;
    if (sev) {
      g.lineWidth = 7; g.strokeStyle = rgba(COL.red, .14); strokePts(g, pts, 0, 1);
      g.lineWidth = 1.8; g.strokeStyle = rgba(COL.red, .9); g.setLineDash([4, 6]); g.lineDashOffset = RM ? 0 : (now * .03) % 10;
      strokePts(g, pts, 0, .44); strokePts(g, pts, .56, 1); g.setLineDash([]); g.lineDashOffset = 0;
      const c = ptAt(pts, .5); g.strokeStyle = rgba(COL.red, 1); g.lineWidth = 2.2;
      g.beginPath(); g.moveTo(c[0] - 7, c[1] - 7); g.lineTo(c[0] + 7, c[1] + 7); g.moveTo(c[0] + 7, c[1] - 7); g.lineTo(c[0] - 7, c[1] + 7); g.stroke();
      const gr = g.createRadialGradient(c[0], c[1], 0, c[0], c[1], 22); gr.addColorStop(0, rgba(COL.red, .35)); gr.addColorStop(1, rgba(COL.red, 0)); g.fillStyle = gr; g.beginPath(); g.arc(c[0], c[1], 22, 0, 7); g.fill();
      continue;
    }
    const walked = m.contained || (i < 2 && m.lit[i + 1]);
    g.lineWidth = 12; g.strokeStyle = rgba(COL.gold, walked ? .07 : .12); strokePts(g, pts, 0, 1);
    g.lineWidth = 5; g.strokeStyle = rgba(COL.gold, walked ? .14 : .25); strokePts(g, pts, 0, 1);
    g.lineWidth = 1.8; g.strokeStyle = rgba(COL.gold, walked ? .55 : .95); strokePts(g, pts, 0, 1);
    if (!m.contained) {
      const n = 4;
      for (let j = 0; j < n; j++) {
        const t = RM ? (j + .5) / n : ((now * 0.00022) + j / n) % 1;
        for (let k = 5; k >= 0; k--) { const tt = Math.max(0, t - k * .012); const q = ptAt(pts, tt); g.fillStyle = k ? rgba(COL.gold, .35 * (1 - k / 6)) : "rgba(255,245,220,1)"; g.beginPath(); g.arc(q[0], q[1], k ? 2.2 - k * .25 : 2.6, 0, 7); g.fill(); }
        const q = ptAt(pts, t); const gr = g.createRadialGradient(q[0], q[1], 0, q[0], q[1], 11); gr.addColorStop(0, rgba(COL.gold, .5)); gr.addColorStop(1, rgba(COL.gold, 0)); g.fillStyle = gr; g.beginPath(); g.arc(q[0], q[1], 11, 0, 7); g.fill();
      }
    }
  }

  // shockwaves
  if (hero.shocks.length) {
    const keep = [];
    for (const s of hero.shocks) {
      const age = now - s.born; if (age < 0) { keep.push(s); continue; } if (age > 1500) continue; keep.push(s);
      const n = NODES[s.node], r = 24 + age * .5, a = (1 - age / 1500);
      g.lineWidth = 2.2 * a + .4; g.strokeStyle = rgba(COL.red, .85 * a); ellipsePath(g, n.x, n.z, r); g.stroke();
      g.lineWidth = 10; g.strokeStyle = rgba(COL.red, .12 * a); g.stroke();
    }
    hero.shocks = keep;
  }

  // node discs + pillars
  const disc = (id, c, a, ring) => {
    const n = NODES[id], p = proj(n.x, 0, n.z), top = proj(n.x, n.h, n.z);
    const gr = g.createRadialGradient(p[0], p[1], 0, p[0], p[1], 40 * p[2]); gr.addColorStop(0, rgba(c, a * .45)); gr.addColorStop(1, rgba(c, 0));
    ellipsePath(g, n.x, n.z, 38); g.fillStyle = gr; g.fill();
    ellipsePath(g, n.x, n.z, 38); g.lineWidth = 1.4; g.strokeStyle = rgba(c, a); g.stroke();
    ellipsePath(g, n.x, n.z, 20); g.lineWidth = 1; g.strokeStyle = rgba(c, a * .55); g.stroke();
    if (ring) { ellipsePath(g, n.x, n.z, 54); g.lineWidth = 1; g.setLineDash([3, 6]); g.strokeStyle = rgba(c, a * .7); g.stroke(); g.setLineDash([]); }
    const lg = g.createLinearGradient(p[0], p[1], top[0], top[1]); lg.addColorStop(0, rgba(c, a * .9)); lg.addColorStop(1, rgba(c, a * .15));
    g.strokeStyle = lg; g.lineWidth = 1.2; g.beginPath(); g.moveTo(p[0], p[1]); g.lineTo(top[0], top[1]); g.stroke();
    g.fillStyle = "#fff"; g.beginPath(); g.arc(p[0], p[1], 2.2, 0, 7); g.fill();
    g.fillStyle = rgba(c, a); g.beginPath(); g.arc(p[0], p[1], 4.5, 0, 7); g.fill();
  };
  const pulse = RM ? 1 : .75 + .25 * Math.sin(now / 420);
  disc("ctrl", COL.ice, .8);
  disc("legit", COL.green, .45);
  // after containment every decoy wears a slowly turning red "blocked" ring
  const banRing = (id, r) => { const n = NODES[id]; g.setLineDash([5, 7]); g.lineDashOffset = RM ? 0 : -(now * .012) % 12; g.lineWidth = 1.2; g.strokeStyle = rgba(COL.red, .75); ellipsePath(g, n.x, n.z, r); g.stroke(); g.setLineDash([]); g.lineDashOffset = 0; };
  for (const d of ["admin", "ssh", "s3"]) {
    const flash = hero.flash[d] && now > hero.flash[d] && now - hero.flash[d] < 500;
    const reached = d === "admin" ? m.stage >= 1 || (m.a && m.cur === "admin") : d === "ssh" ? m.stage >= 3 : m.stage >= 5;
    if (flash) { const n = NODES[d], a = 1 - (now - hero.flash[d]) / 500; g.lineWidth = 2; g.strokeStyle = rgba(COL.red, a); ellipsePath(g, n.x, n.z, 40 + (1 - a) * 30); g.stroke(); }
    if (m.cur === d && m.a) disc(d, m.contained ? COL.red : bc, m.contained ? .95 : .6 + .4 * pulse, !m.contained);
    else if (reached) disc(d, COL.gold, .7);
    else disc(d, COL.steel, .6);
    if (m.contained) banRing(d, 46);
  }
  if (m.a) { disc("atk", COL.red, m.contained ? .95 : .6 + .4 * pulse, false); if (m.contained) banRing("atk", 50); }
  else disc("atk", COL.steel, .35);

  g.drawImage(hero.fade, 0, 0, W, H);
}

// ------------------------------------------------------------------ loop
let lastClock = "", errCount = 0;
function flush(now) {
  if (dirty.model) { dirty.model = false; renderModel(); }
  if (dirty.feed) { dirty.feed = false; renderFeed(); }
  if (dirty.alerts) { dirty.alerts = false; renderAlerts(); }
  if (dirty.responses) { dirty.responses = false; renderResponses(); }
  if (dirty.theft) { dirty.theft = false; renderTheft(); }
  if (dirty.tech) { dirty.tech = false; renderTechniques(); }
  if (dirty.charts && now - lastChartDraw > 120) { dirty.charts = false; lastChartDraw = now; drawCharts(); }
  const c = new Date().toLocaleTimeString([], { hour12: false }); if (c !== lastClock) { lastClock = c; $("clock").textContent = c; }
}
function tick(now) {
  try { drawHero(now); flush(now); }
  catch (e) { if (errCount++ < 5) console.error("render error", e); }
  requestAnimationFrame(tick);
}
// rAF pauses in a hidden tab; keep the DOM current so the page is right when it comes back
setInterval(() => { if (document.hidden) { try { flush(performance.now()); } catch (e) { if (errCount++ < 5) console.error("render error", e); } } }, 1000);

// ------------------------------------------------------------------ io
async function control(kind, ip) {
  try { await fetch(`/api/${kind === "contain" ? "contain" : "uncontain"}/${encodeURIComponent(ip)}`, { method: "POST" }); }
  catch (e) { console.warn("control failed", e); }
}
$("btn-contain").addEventListener("click", () => { const a = lead(); if (a) control("contain", a.ip); });
$("btn-release").addEventListener("click", () => { const a = lead(); if (a) control("uncontain", a.ip); });

async function loadInitial() {
  const [events, alerts, responses, attackers] = await Promise.all([
    fetch("/api/events?limit=200").then((r) => r.json()),
    fetch("/api/alerts?limit=80").then((r) => r.json()),
    fetch("/api/responses?limit=60").then((r) => r.json()),
    fetch("/api/attackers").then((r) => r.json()),
  ]);
  for (const e of [...events].reverse()) addEvent(e, false);
  for (const a of [...alerts].reverse()) addAlert(a);
  for (const r of [...responses].reverse()) addResponse(r);
  for (const a of attackers) { state.riskHist.push({ t: tms(a.first_seen), r: 0 }); upsertAttacker(a); }
}
function setConn(up, text) { const c = $("conn"); c.classList.toggle("up", up); c.classList.toggle("down", !up); $("conn-text").textContent = text; }
let backoff = 500;
function connect() {
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
  ws.onopen = () => { setConn(true, "live"); backoff = 500; };
  ws.onclose = () => { setConn(false, "reconnecting"); setTimeout(connect, backoff); backoff = Math.min(backoff * 2, 8000); };
  ws.onerror = () => ws.close();
  ws.onmessage = (ev) => {
    let msg; try { msg = JSON.parse(ev.data); } catch { return; }
    if (!msg || typeof msg !== "object" || !msg.data) return;
    if (msg.type === "event") addEvent(msg.data, true);
    else if (msg.type === "alert") addAlert(msg.data);
    else if (msg.type === "response") addResponse(msg.data);
    else if (msg.type === "attacker") upsertAttacker(msg.data);
  };
}

// ------------------------------------------------------------------ boot
sizeHero();
new ResizeObserver(() => { sizeHero(); dirty.charts = true; dirty.model = true; }).observe($("hero"));
new ResizeObserver(() => { dirty.charts = true; }).observe($("timeline").parentElement);
requestAnimationFrame(tick);
loadInitial().catch((e) => console.warn("initial load failed", e)).finally(connect);
