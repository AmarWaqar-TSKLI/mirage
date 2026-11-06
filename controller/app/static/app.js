"use strict";

/* Mirage dashboard.
 *
 * SECURITY: every field rendered here is attacker-controlled (usernames,
 * passwords, shell commands, paths, user agents, access keys). It is ONLY ever
 * placed with textContent or as element attributes set via the DOM API, never
 * with innerHTML. Do not introduce innerHTML on any data path.
 */

const TRAIL_STAGES = [
  "robots.txt",
  "backup .env",
  "SSH login",
  "AWS creds",
  "S3 access",
  "passwords.xlsx",
];

// ATT&CK technique id -> readable name. Covers every id the decoys emit;
// anything unmapped falls back to showing the raw id.
const ATTACK = {
  "T1003.008": "OS Credential Dumping: /etc/passwd & /etc/shadow",
  "T1016": "System Network Configuration Discovery",
  "T1021.004": "Remote Services: SSH",
  "T1033": "System Owner/User Discovery",
  "T1046": "Network Service Discovery",
  "T1049": "System Network Connections Discovery",
  "T1053.003": "Scheduled Task/Job: Cron",
  "T1057": "Process Discovery",
  "T1059.004": "Command & Scripting Interpreter: Unix Shell",
  "T1070.002": "Indicator Removal: Clear Linux System Logs",
  "T1070.003": "Indicator Removal: Clear Command History",
  "T1078": "Valid Accounts",
  "T1078.004": "Valid Accounts: Cloud Accounts",
  "T1082": "System Information Discovery",
  "T1083": "File & Directory Discovery",
  "T1087.001": "Account Discovery: Local Account",
  "T1098.004": "Account Manipulation: SSH Authorized Keys",
  "T1105": "Ingress Tool Transfer",
  "T1110": "Brute Force",
  "T1136.001": "Create Account: Local Account",
  "T1222.002": "File & Directory Permissions Modification: Linux",
  "T1530": "Data from Cloud Storage",
  "T1546.004": "Event Triggered Execution: Unix Shell Config",
  "T1548.003": "Abuse Elevation Control: Sudo & Sudo Caching",
  "T1552.001": "Unsecured Credentials: Credentials In Files",
  "T1552.003": "Unsecured Credentials: Bash History",
  "T1580": "Cloud Infrastructure Discovery",
  "T1595": "Active Scanning",
  "T1595.003": "Active Scanning: Wordlist Scanning",
};

// MITRE Engage activity name -> official EAC id (engage.mitre.org).
const ENGAGE_IDS = {
  "Lures": "EAC0005",
  "Network Monitoring": "EAC0014",
  "System Activity Monitoring": "EAC0021",
};

const state = {
  attackers: new Map(),
  events: [],
  techniques: new Map(), // id -> count
  counts: { events: 0, alerts: 0 },
};

const MAX_FEED = 200;

// ---------------------------------------------------------------- utilities

const $ = (id) => document.getElementById(id);

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}

function fmtTime(ts) {
  if (!ts) return "";
  const d = new Date(ts);
  if (isNaN(d)) return String(ts);
  return d.toLocaleTimeString([], { hour12: false }) + "." +
    String(d.getMilliseconds()).padStart(3, "0");
}

function playbookClass(pb) {
  return pb === "contain" ? "pb-contain" : pb === "tarpit" ? "pb-tarpit" : "pb-watch";
}

function riskBand(score) {
  if (score >= 75) return "risk-crit";
  if (score >= 40) return "risk-warn";
  return "risk-low";
}

// ------------------------------------------------------------------ rendering

function renderAttackers() {
  const host = $("attackers");
  host.replaceChildren();
  const list = [...state.attackers.values()].sort(
    (a, b) => (b.risk_score || 0) - (a.risk_score || 0)
  );
  $("attackers-empty").style.display = list.length ? "none" : "";
  $("stat-attackers").textContent = list.length;
  $("stat-contained").textContent = list.filter((a) => a.contained_at).length;

  for (const a of list) {
    const card = el("div", "attacker " + (a.contained_at ? "is-contained" : ""));

    const head = el("div", "attacker-head");
    head.append(el("span", "ip", a.ip));
    const score = el("span", "risk " + riskBand(a.risk_score || 0), a.risk_score ?? 0);
    head.append(score);
    card.append(head);

    const meta = el("div", "attacker-meta");
    meta.append(el("span", "pill " + playbookClass(a.playbook), a.playbook || "watch"));
    if (a.contained_at) meta.append(el("span", "pill pill-contained", "CONTAINED"));
    meta.append(el("span", "muted", `${(a.techniques || []).length} tech · ${(a.tokens || []).length} tokens`));
    card.append(meta);

    // 6-stage trail progress
    const trail = el("div", "trail");
    for (let i = 0; i < TRAIL_STAGES.length; i++) {
      const seg = el("div", "seg" + ((a.max_stage || 0) > i ? " on" : ""));
      seg.title = `Stage ${i + 1}: ${TRAIL_STAGES[i]}`;
      trail.append(seg);
    }
    card.append(trail);
    card.append(el("div", "trail-label muted", `stage ${a.max_stage || 0}/6 · ${TRAIL_STAGES[(a.max_stage || 1) - 1] || "—"}`));

    const actions = el("div", "attacker-actions");
    const contain = el("button", "btn btn-contain", "Contain");
    contain.onclick = () => control("contain", a.ip);
    const release = el("button", "btn btn-release", "Release");
    release.onclick = () => control("uncontain", a.ip);
    actions.append(contain, release);
    card.append(actions);

    host.append(card);
  }
}

function sourceBadge(source) {
  const map = { "admin-panel": "src-web", "ssh": "src-ssh", "s3": "src-s3" };
  return el("span", "badge " + (map[source] || ""), source);
}

function feedRow(e) {
  const row = el("div", "feed-row" + (e.stage ? " stage-" + e.stage : ""));
  row.append(el("span", "t", fmtTime(e.ts)));
  row.append(sourceBadge(e.source));
  row.append(el("span", "etype", e.event_type));
  row.append(el("span", "asset", e.asset || "—"));
  if (e.stage) row.append(el("span", "stage-tag", "S" + e.stage));
  const techs = (e.techniques || []).slice(0, 3);
  for (const t of techs) {
    const chip = el("span", "tchip", t);
    chip.title = ATTACK[t] || t;
    row.append(chip);
  }
  return row;
}

function renderFeed() {
  const host = $("feed");
  host.replaceChildren();
  for (const e of state.events.slice(0, MAX_FEED)) host.append(feedRow(e));
  $("stat-events").textContent = state.counts.events;
}

function pushEvent(e) {
  state.counts.events += 1;
  state.events.unshift(e);
  if (state.events.length > MAX_FEED * 2) state.events.length = MAX_FEED;
  // keep newest-first by timestamp (decoys can deliver slightly out of order)
  state.events.sort((a, b) => String(b.ts).localeCompare(String(a.ts)));
  for (const t of e.techniques || []) {
    state.techniques.set(t, (state.techniques.get(t) || 0) + 1);
  }
  if (e.honeytoken_id && (e.event_type === "honeytoken_used" || e.event_type === "file_access")) {
    pushTheft(e);
  }
  renderFeed();
  renderTechniques();
}

function pushTheft(e) {
  const host = $("theft");
  const row = el("div", "theft-row");
  row.append(el("span", "t", fmtTime(e.ts)));
  row.append(el("span", "token", e.honeytoken_id));
  row.append(el("span", "asset", e.asset || ""));
  row.append(el("span", "ip muted", e.src_ip));
  host.prepend(row);
  while (host.childElementCount > 40) host.lastElementChild.remove();
}

function pushAlert(a) {
  state.counts.alerts += 1;
  $("stat-alerts").textContent = state.counts.alerts;
  const host = $("alerts");
  const row = el("div", "alert sev-" + (a.severity || "low"));
  row.append(el("span", "sev", (a.severity || "low").toUpperCase()));
  const body = el("div", "alert-body");
  body.append(el("div", "alert-title", a.title));
  body.append(el("div", "alert-meta muted", `${a.src_ip} · ${fmtTime(a.ts)}`));
  row.append(body);
  host.prepend(row);
  while (host.childElementCount > 60) host.lastElementChild.remove();
}

function pushResponse(r) {
  const host = $("responses");
  const row = el("div", "response pb-" + (r.playbook || "watch"));
  row.append(el("span", "t", fmtTime(r.ts)));
  row.append(el("span", "r-action", r.action));
  row.append(el("span", "r-ip muted", r.src_ip));
  const d = r.details || {};
  const actions = d.actions || {};
  // containment_sequence: show each sub-step and whether it was real or simulated
  const steps = [];
  if (actions.eviction) steps.push("evict:" + (actions.eviction.terminated ?? "?"));
  if (actions.firewall) steps.push("fw:" + (actions.firewall.backend || "?"));
  if (actions.snapshot) steps.push("snap:" + (actions.snapshot.backend || "?"));
  if (d.delay_seconds) steps.push(d.delay_seconds + "s delay");
  if (d.firewall) steps.push("fw:" + (d.firewall.backend || d.firewall.success));
  if (steps.length) row.append(el("span", "r-steps", steps.join("  ·  ")));
  host.prepend(row);
  while (host.childElementCount > 60) host.lastElementChild.remove();
}

function renderTechniques() {
  const host = $("techniques");
  host.replaceChildren();
  const items = [...state.techniques.entries()].sort((a, b) => b[1] - a[1]);
  for (const [id, n] of items) {
    const chip = el("div", "tech");
    chip.append(el("span", "tech-id", id));
    chip.append(el("span", "tech-name", ATTACK[id] || "unmapped technique"));
    chip.append(el("span", "tech-n", n));
    host.append(chip);
  }
}

function upsertAttacker(a) {
  state.attackers.set(a.ip, a);
  renderAttackers();
}

// ------------------------------------------------------------- controls + io

async function control(kind, ip) {
  try {
    const r = await fetch(`/api/${kind === "contain" ? "contain" : "uncontain"}/${encodeURIComponent(ip)}`, {
      method: "POST",
    });
    if (!r.ok) console.warn("control failed", kind, ip, r.status);
  } catch (err) {
    console.warn("control error", err);
  }
}

async function loadInitial() {
  const [events, alerts, responses, attackers] = await Promise.all([
    fetch("/api/events?limit=200").then((r) => r.json()),
    fetch("/api/alerts?limit=100").then((r) => r.json()),
    fetch("/api/responses?limit=100").then((r) => r.json()),
    fetch("/api/attackers").then((r) => r.json()),
  ]);

  for (const a of attackers) state.attackers.set(a.ip, a);
  renderAttackers();

  // events come newest-first from the API
  state.events = events.slice();
  state.counts.events = events.length;
  for (const e of events) {
    for (const t of e.techniques || []) state.techniques.set(t, (state.techniques.get(t) || 0) + 1);
  }
  renderFeed();
  renderTechniques();

  // Replay newest-last so prepend leaves the most recent on top, counts stay exact.
  for (const e of [...events].reverse()) {
    if (e.honeytoken_id && (e.event_type === "honeytoken_used" || e.event_type === "file_access")) pushTheft(e);
  }
  for (const a of [...alerts].reverse()) pushAlert(a);
  for (const r of [...responses].reverse()) pushResponse(r);
}

function setConn(ok, text) {
  const c = $("conn");
  c.classList.toggle("live", ok);
  c.classList.toggle("down", !ok);
  $("conn-text").textContent = text;
}

function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/ws`);
  let backoff = 500;

  ws.onopen = () => { setConn(true, "live"); backoff = 500; };
  ws.onclose = () => {
    setConn(false, "reconnecting");
    setTimeout(connect, backoff);
    backoff = Math.min(backoff * 2, 8000);
  };
  ws.onerror = () => ws.close();
  ws.onmessage = (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch { return; }
    switch (msg.type) {
      case "event": pushEvent(msg.data); break;
      case "alert": pushAlert(msg.data); break;
      case "response": pushResponse(msg.data); break;
      case "attacker": upsertAttacker(msg.data); break;
    }
  };
}

loadInitial().catch((e) => console.warn("initial load failed", e)).finally(connect);
