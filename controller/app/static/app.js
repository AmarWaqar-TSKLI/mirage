"use strict";

/* Mirage deception grid — live cinematic console.
 * SECURITY: every value is attacker-controlled. Only ever placed with
 * textContent or DOM attributes, never innerHTML. Keep it that way.
 */

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

const state = { attackers: new Map(), events: [], techniques: new Map(), counts: { events: 0, alerts: 0 } };
const MAX_FEED = 200, GAUGE_C = 314.16;

const $ = (id) => document.getElementById(id);
function el(tag, cls, text) { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
function fmtTime(ts) { const d = new Date(ts); if (isNaN(d)) return String(ts || ""); return d.toLocaleTimeString([], { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0"); }
function band(r) { return r >= 75 ? "hot" : r >= 40 ? "warn" : r > 0 ? "calm" : "idle"; }
const BAND_VAR = { hot: "var(--hot)", warn: "var(--warn)", calm: "var(--calm)", idle: "var(--ink-faint)" };
const BAND_WORD = { hot: "critical", warn: "elevated", calm: "watching", idle: "clear" };
const RGB = { hot: [255, 61, 110], warn: [255, 176, 46], calm: [63, 224, 207], idle: [90, 102, 120] };
let threatBand = "idle";

function lead() {
  let b = null;
  for (const a of state.attackers.values())
    if (!b || (a.risk_score || 0) > (b.risk_score || 0) ||
        ((a.risk_score || 0) === (b.risk_score || 0) && (a.max_stage || 0) > (b.max_stage || 0))) b = a;
  return b;
}

// ------------------------------------------------------------ ambient
function paintThreat() {
  const list = [...state.attackers.values()];
  const max = list.reduce((m, a) => Math.max(m, a.risk_score || 0), 0);
  threatBand = band(max);
  document.documentElement.style.setProperty("--threat", BAND_VAR[threatBand]);
  document.body.dataset.threat = threatBand;
  $("meter-fill").style.width = max + "%";
  $("meter-read").textContent = BAND_WORD[threatBand];
  $("stat-attackers").textContent = list.length;
  $("stat-contained").textContent = list.filter((a) => a.contained_at).length;
  $("map-hint").textContent = list.length ? `${list.length} in the trap` : "decoys armed";
}

// ------------------------------------------------------------ topology
function renderMap() {
  const a = lead();
  const reached = a ? (a.max_stage || 0) : 0;
  const contained = a ? !!a.contained_at : false;
  for (const id of ["n-admin", "n-ssh", "n-s3"]) $(id).classList.remove("reached", "current", "trapped");
  if (reached >= 1) $("n-admin").classList.add("reached");
  if (reached >= 3) $("n-ssh").classList.add("reached");
  if (reached >= 5) $("n-s3").classList.add("reached");
  const cur = reached >= 5 ? "n-s3" : reached >= 3 ? "n-ssh" : reached >= 1 ? "n-admin" : null;
  if (cur) { $(cur).classList.remove("reached"); $(cur).classList.add(contained ? "trapped" : "current"); }
  const link = (id, lit) => { const e = $(id); e.classList.toggle("lit", lit && !contained); e.classList.toggle("severed", false); };
  link("lk-a", reached >= 1); link("lk-1", reached >= 3); link("lk-2", reached >= 5);
  if (contained) {
    const sev = cur === "n-s3" ? "lk-2" : cur === "n-ssh" ? "lk-1" : "lk-a";
    $(sev).classList.remove("lit"); $(sev).classList.add("severed");
  }
}

// ------------------------------------------------------------ dossier
function renderDossier() {
  const a = lead();
  const empty = $("dossier-empty"), live = $("dossier-live");
  if (!a) { empty.hidden = false; live.hidden = true; $("dossier-hint").textContent = "—"; return; }
  empty.hidden = true; live.hidden = false;
  const risk = a.risk_score || 0, contained = !!a.contained_at, b = band(risk);
  $("dossier-hint").textContent = BAND_WORD[b];
  $("d-risk").textContent = risk;
  $("g-arc").style.strokeDashoffset = GAUGE_C * (1 - risk / 100);
  $("d-ip").textContent = a.ip;
  const word = contained ? "contained" : (a.playbook || "watch");
  const v = $("d-verdict");
  if (v.textContent !== word) { v.textContent = word; v.classList.toggle("locked", contained); }
  $("d-stage").textContent = (a.max_stage || 0) + "/6";
  $("d-tech").textContent = (a.techniques || []).length;
  $("d-tokens").textContent = (a.tokens || []).length;
  $("d-contain").onclick = () => control("contain", a.ip);
  $("d-release").onclick = () => control("uncontain", a.ip);
}
function refresh() { paintThreat(); renderMap(); renderDossier(); }

// --------------------------------------------------------------- feed
const SRC = { "admin-panel": ["src-web", "WEB"], ssh: ["src-ssh", "SSH"], s3: ["src-s3", "S3"] };
function feedRow(e, fresh) {
  const row = el("div", "row" + (e.stage ? " s" + e.stage : "") + (fresh ? " fresh" : ""));
  row.append(el("span", "t", fmtTime(e.ts)));
  const [cls, lab] = SRC[e.source] || ["", e.source];
  row.append(el("span", "src " + cls, lab));
  row.append(el("span", "etype", (e.event_type || "").replace(/_/g, " ")));
  row.append(el("span", "asset", e.asset || "—"));
  row.append(el("span", "sx", e.stage ? "S" + e.stage : ""));
  return row;
}
function renderFeed() {
  const host = $("feed-list"); host.replaceChildren();
  for (const e of state.events.slice(0, MAX_FEED)) host.append(feedRow(e, false));
  $("stat-events").textContent = state.counts.events;
}
function pushEvent(e) {
  state.counts.events += 1;
  pulse += 1.1;                        // drives the intrusion-pulse wave
  state.events.unshift(e);
  state.events.sort((a, b) => String(b.ts).localeCompare(String(a.ts)));
  if (state.events.length > MAX_FEED * 2) state.events.length = MAX_FEED;
  for (const t of e.techniques || []) state.techniques.set(t, (state.techniques.get(t) || 0) + 1);
  if (e.honeytoken_id && (e.event_type === "honeytoken_used" || e.event_type === "file_access")) pushTheft(e);
  $("stat-events").textContent = state.counts.events;
  const host = $("feed-list");
  host.prepend(feedRow(e, true));
  while (host.childElementCount > MAX_FEED) host.lastElementChild.remove();
  renderTechniques();
}
function pushTheft(e) {
  const host = $("theft-list");
  const row = el("div", "theft-row");
  row.append(el("span", "t", fmtTime(e.ts)), el("span", "tok", e.honeytoken_id), el("span", "loc", e.asset || e.src_ip));
  host.prepend(row);
  while (host.childElementCount > 40) host.lastElementChild.remove();
}
function pushAlert(a) {
  state.counts.alerts += 1;
  $("stat-alerts").textContent = state.counts.alerts;
  const host = $("alert-list");
  const row = el("div", "alert sev-" + (a.severity || "low"));
  row.append(el("span", "sev", (a.severity || "low").slice(0, 4).toUpperCase()));
  const body = el("div");
  body.append(el("div", "alert-title", a.title), el("div", "alert-sub", `${a.src_ip} · ${fmtTime(a.ts)}`));
  row.append(body); host.prepend(row);
  while (host.childElementCount > 60) host.lastElementChild.remove();
}
function pushResponse(r) {
  const host = $("resp-list");
  const resp = el("div", "resp " + (r.playbook || "watch"));
  const top = el("div", "resp-top");
  top.append(el("span", "resp-act", (r.action || "").replace(/_/g, " ")), el("span", "resp-ip", r.src_ip));
  resp.append(top);
  const d = r.details || {}, acts = d.actions || {};
  const steps = el("div", "resp-steps");
  const add = (txt, real) => steps.append(el("span", "step" + (real ? " real" : ""), txt));
  if (acts.eviction) add(`evicted ${acts.eviction.terminated ?? 0}`, (acts.eviction.terminated || 0) > 0);
  if (acts.enforcement) { const n = Array.isArray(acts.enforcement) ? acts.enforcement.length : (acts.enforcement.reached || []).length; add(`blocked ${n} decoys`, n > 0); }
  if (acts.firewall) { const be = acts.firewall.backend || acts.firewall; add(`fw ${be}`, be && be !== "simulated"); }
  if (acts.snapshot) { const be = acts.snapshot.backend || ""; add(`snapshot ${be}`, be && be !== "simulated"); }
  if (d.delay_seconds) add(`${d.delay_seconds}s tarpit`, true);
  if (d.firewall) add("released", true);
  if (steps.childElementCount) resp.append(steps);
  host.prepend(resp);
  while (host.childElementCount > 50) host.lastElementChild.remove();
}
function renderTechniques() {
  const host = $("tech-list"); host.replaceChildren();
  const items = [...state.techniques.entries()].sort((a, b) => b[1] - a[1]);
  $("tech-count").textContent = items.length;
  for (const [id, n] of items) {
    const t = el("div", "tech");
    t.append(el("span", "tech-id", id), el("span", "tech-name", ATTACK[id] || "technique"), el("span", "tech-n", "×" + n));
    host.append(t);
  }
}
function upsertAttacker(a) { state.attackers.set(a.ip, a); refresh(); }

// ============================================================ animation
// 1) ambient particle field  2) light flowing the attack path  3) pulse wave
let pulse = 0;
const hist = new Array(170).fill(0);

function threatRGB() { return RGB[threatBand] || RGB.idle; }

// ---- background constellation
const bg = $("bg"), bgx = bg.getContext("2d");
let parts = [];
function sizeBg() {
  const dpr = Math.min(devicePixelRatio || 1, 2);
  bg.width = innerWidth * dpr; bg.height = innerHeight * dpr; bgx.setTransform(dpr, 0, 0, dpr, 0, 0);
  if (!parts.length) parts = Array.from({ length: 64 }, () => ({
    x: Math.random() * innerWidth, y: Math.random() * innerHeight,
    vx: (Math.random() - .5) * .18, vy: (Math.random() - .5) * .18,
  }));
}
function drawBg() {
  bgx.clearRect(0, 0, innerWidth, innerHeight);
  const [r, g, b] = threatRGB();
  for (const p of parts) {
    p.x += p.vx; p.y += p.vy;
    if (p.x < 0 || p.x > innerWidth) p.vx *= -1;
    if (p.y < 0 || p.y > innerHeight) p.vy *= -1;
  }
  for (let i = 0; i < parts.length; i++) {
    for (let j = i + 1; j < parts.length; j++) {
      const a = parts[i], c = parts[j], dx = a.x - c.x, dy = a.y - c.y, d = Math.hypot(dx, dy);
      if (d < 140) { bgx.strokeStyle = `rgba(${r},${g},${b},${0.05 * (1 - d / 140)})`; bgx.lineWidth = 1; bgx.beginPath(); bgx.moveTo(a.x, a.y); bgx.lineTo(c.x, c.y); bgx.stroke(); }
    }
  }
  bgx.fillStyle = `rgba(${r},${g},${b},0.5)`;
  for (const p of parts) { bgx.beginPath(); bgx.arc(p.x, p.y, 1.1, 0, 7); bgx.fill(); }
}

// ---- traveling sparks along lit trail links
const SPARK = [["lk-a", "sp-a"], ["lk-1", "sp-1"], ["lk-2", "sp-2"]];
let st = 0;
function drawSparks() {
  st = (st + 0.006) % 1;
  for (const [lk, sp] of SPARK) {
    const path = $(lk), spark = $(sp);
    if (path.classList.contains("lit")) {
      const L = path.getTotalLength(), pt = path.getPointAtLength(st * L);
      spark.setAttribute("cx", pt.x); spark.setAttribute("cy", pt.y); spark.classList.add("on");
    } else spark.classList.remove("on");
  }
}

// ---- intrusion-pulse waveform
const wave = $("wave"), wx = wave.getContext("2d");
function sizeWave() {
  const dpr = Math.min(devicePixelRatio || 1, 2);
  wave.width = wave.clientWidth * dpr; wave.height = wave.clientHeight * dpr; wx.setTransform(dpr, 0, 0, dpr, 0, 0);
}
function drawWave() {
  pulse *= 0.93;
  hist.push(Math.min(pulse, 6)); hist.shift();
  $("pulse-rate").textContent = pulse.toFixed(1) + " ev/s";
  const W = wave.clientWidth, H = wave.clientHeight, [r, g, b] = threatRGB();
  wx.clearRect(0, 0, W, H);
  const step = W / (hist.length - 1), base = H - 2;
  wx.beginPath(); wx.moveTo(0, base);
  for (let i = 0; i < hist.length; i++) wx.lineTo(i * step, base - (hist[i] / 6) * (H - 6));
  wx.lineTo(W, base); wx.closePath();
  const grad = wx.createLinearGradient(0, 0, 0, H);
  grad.addColorStop(0, `rgba(${r},${g},${b},0.35)`); grad.addColorStop(1, `rgba(${r},${g},${b},0)`);
  wx.fillStyle = grad; wx.fill();
  wx.beginPath();
  for (let i = 0; i < hist.length; i++) { const x = i * step, y = base - (hist[i] / 6) * (H - 6); i ? wx.lineTo(x, y) : wx.moveTo(x, y); }
  wx.strokeStyle = `rgb(${r},${g},${b})`; wx.lineWidth = 1.8; wx.shadowColor = `rgb(${r},${g},${b})`; wx.shadowBlur = 8; wx.stroke(); wx.shadowBlur = 0;
}

function tick() { drawBg(); drawSparks(); drawWave(); requestAnimationFrame(tick); }
function onResize() { sizeBg(); sizeWave(); }
addEventListener("resize", onResize);

// ------------------------------------------------------------- io
async function control(kind, ip) {
  try { await fetch(`/api/${kind === "contain" ? "contain" : "uncontain"}/${encodeURIComponent(ip)}`, { method: "POST" }); }
  catch (e) { console.warn("control failed", e); }
}
async function loadInitial() {
  const [events, alerts, responses, attackers] = await Promise.all([
    fetch("/api/events?limit=200").then((r) => r.json()),
    fetch("/api/alerts?limit=80").then((r) => r.json()),
    fetch("/api/responses?limit=60").then((r) => r.json()),
    fetch("/api/attackers").then((r) => r.json()),
  ]);
  for (const a of attackers) state.attackers.set(a.ip, a);
  state.events = events.slice();
  state.counts.events = events.length;
  for (const e of events) for (const t of e.techniques || []) state.techniques.set(t, (state.techniques.get(t) || 0) + 1);
  refresh(); renderFeed(); renderTechniques();
  for (const e of [...events].reverse()) if (e.honeytoken_id && (e.event_type === "honeytoken_used" || e.event_type === "file_access")) pushTheft(e);
  for (const a of [...alerts].reverse()) pushAlert(a);
  for (const r of [...responses].reverse()) pushResponse(r);
}
function setConn(up, text) { const c = $("conn"); c.classList.toggle("up", up); c.classList.toggle("down", !up); $("conn-text").textContent = text; }
function connect() {
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
  let backoff = 500;
  ws.onopen = () => { setConn(true, "live"); backoff = 500; };
  ws.onclose = () => { setConn(false, "reconnecting"); setTimeout(connect, backoff); backoff = Math.min(backoff * 2, 8000); };
  ws.onerror = () => ws.close();
  ws.onmessage = (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    if (m.type === "event") pushEvent(m.data);
    else if (m.type === "alert") pushAlert(m.data);
    else if (m.type === "response") pushResponse(m.data);
    else if (m.type === "attacker") upsertAttacker(m.data);
  };
}

onResize();
requestAnimationFrame(tick);
loadInitial().catch((e) => console.warn("initial load failed", e)).finally(connect);
