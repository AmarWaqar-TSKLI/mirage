"use strict";

/* Mirage · airspace command.
 *
 * The lab is drawn as airspace. Each decoy is a base, Mirage's controller is
 * the radar station, and every intruder is a hostile track that flies the real
 * route between bases as it takes each bait. Containment fires an interceptor.
 *
 * Data: one REST read for first paint, then live deltas over /ws
 * (event, alert, response, attacker).
 *
 * SECURITY: every value from the API is attacker-controlled. It is only ever
 * placed with textContent, DOM attribute setters or canvas fillText, never
 * innerHTML.
 */

// ------------------------------------------------------------------ vocabulary
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
  { n: 1, name: "robots.txt", bait: "the robots.txt hint", decoy: "admin", token: "ht-robots-backup-link" },
  { n: 2, name: "Backup .env", bait: "the leaked backup file", decoy: "admin", token: "ht-env-backup-file" },
  { n: 3, name: "SSH login", bait: "the SSH login", decoy: "ssh", token: "ht-ssh-password" },
  { n: 4, name: "AWS keys", bait: "the planted AWS keys", decoy: "ssh", token: "ht-aws-credentials-file" },
  { n: 5, name: "S3 access", bait: "the S3 bucket", decoy: "s3", token: "ht-aws-access-key" },
  { n: 6, name: "passwords.xlsx", bait: "the crown jewel", decoy: "s3", token: "ht-passwords-xlsx" },
];
const TOKEN_NAME = {
  "ht-robots-backup-link": "robots.txt breadcrumb", "ht-env-backup-file": "Backup .env file",
  "ht-ssh-password": "SSH password", "ht-aws-credentials-file": "AWS credentials file",
  "ht-aws-access-key": "AWS access key", "ht-passwords-xlsx": "passwords.xlsx",
};
const DECOYS = ["admin", "ssh", "s3"];
const DECOY_OF_SOURCE = { "admin-panel": "admin", ssh: "ssh", s3: "s3" };
const SRC_TAG = { admin: "WEB", ssh: "SSH", s3: "S3" };

// ------------------------------------------------------------------ the map's world (1000 x 640 units)
const BASES = {
  admin: { x: 285, y: 210, name: "Admin panel", ip: "10.66.0.20", role: "Web base", holds: "stages 1–2" },
  ssh: { x: 515, y: 400, name: "SSH server", ip: "10.66.0.21", role: "Server base", holds: "stages 3–4" },
  s3: { x: 760, y: 215, name: "S3 bucket", ip: "10.66.0.22", role: "Data vault", holds: "stages 5–6" },
};
const STATION = { x: 560, y: 110, name: "Mirage radar", ip: "10.66.0.10" };
const FRIEND = { x: 150, y: 470, name: "Staff portal", ip: "10.66.0.30" };
const JEWEL = { x: 885, y: 430, name: "Crown jewel", file: "passwords.xlsx" };
// where a track sits after reaching each stage; index 0 is the entry corridor off the map
const ROUTE = [
  { x: -60, y: 110 }, { x: 170, y: 150 },
  { x: 245, y: 160 }, { x: 330, y: 168 },
  { x: 470, y: 352 }, { x: 562, y: 360 },
  { x: 718, y: 168 }, JEWEL,
];
const PLACE = ["the entry corridor", "the admin panel", "the admin panel", "the admin panel", "the SSH server", "the SSH server", "the S3 bucket", "the crown jewel"];

// canvas palette
const K = {
  lime: [214, 242, 76], red: [255, 74, 61], amber: [255, 178, 36], fg: [243, 243, 238],
  mute: [143, 144, 138], faint: [87, 88, 82], line: [36, 37, 34], bg: [7, 8, 7],
};
const rgba = (c, a) => `rgba(${c[0]},${c[1]},${c[2]},${a})`;
const RM = matchMedia("(prefers-reduced-motion: reduce)").matches;
const MONO = '"Geist Mono", ui-monospace, monospace';
const SANS = 'Geist, Inter, system-ui, sans-serif';
const MAX_EVENTS = 5000, MAX_ROWS = 250;

// ------------------------------------------------------------------ state
const state = {
  attackers: new Map(), events: [], alerts: [], responses: [],
  selected: null, booted: false, order: [],   // order = ips by first contact, for T-01, T-02 …
  fresh: new Map(),
};
const dirty = { model: true, queue: true, charts: true };
const layers = { route: true, history: true, sweep: true };

// ------------------------------------------------------------------ helpers
const $ = (id) => document.getElementById(id);
function el(tag, cls, text) { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
const SVGNS = "http://www.w3.org/2000/svg";
function S(tag, attrs, parent, text) { const n = document.createElementNS(SVGNS, tag); for (const k in attrs || {}) n.setAttribute(k, attrs[k]); if (text != null) n.textContent = String(text); if (parent) parent.append(n); return n; }
const tms = (ts) => { const t = +new Date(ts); return isNaN(t) ? 0 : t; };
const clamp = (v, a = 0, b = 1) => Math.max(a, Math.min(b, v));
const easeOut = (k) => 1 - Math.pow(1 - clamp(k), 3);
const lerp = (a, b, k) => a + (b - a) * k;
function fmtTime(ts) { const d = new Date(ts); return isNaN(d) ? "" : d.toLocaleTimeString([], { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0"); }
function fmtClock(ts) { const d = new Date(ts); return isNaN(d) ? "" : d.toLocaleTimeString([], { hour12: false }); }
function fmtDur(ms) {
  if (ms == null || isNaN(ms)) return "—";
  if (ms < 1) return "<1 ms";
  if (ms < 1000) return Math.round(ms) + " ms";
  if (ms < 60000) return (ms / 1000).toFixed(2) + " s";
  const m = Math.floor(ms / 60000), s = Math.round((ms % 60000) / 1000);
  return m + "m " + String(s).padStart(2, "0") + "s";
}
const fmtRel = (ms) => "+" + fmtDur(Math.max(0, ms));
function bandOf(a) {
  if (!a) return "idle";
  if (a.contained_at) return "contain";
  const p = a.playbook; if (p === "watch" || p === "tarpit" || p === "contain") return p;
  const r = a.risk_score || 0; return r >= 75 ? "contain" : r >= 40 ? "tarpit" : "watch";
}
const trackId = (ip) => { const i = state.order.indexOf(ip); return "T-" + String(i < 0 ? 0 : i + 1).padStart(2, "0"); };
function ranked() {
  return [...state.attackers.values()].sort((a, b) =>
    (!!a.contained_at - !!b.contained_at) || (b.risk_score || 0) - (a.risk_score || 0) || tms(a.first_seen) - tms(b.first_seen));
}
function current() {
  if (state.selected && state.attackers.has(state.selected)) return state.attackers.get(state.selected);
  return ranked()[0] || null;
}
const eventsOf = (ip) => state.events.filter((e) => e.src_ip === ip);
function stageTimes(evs) { const ft = {}; for (const e of evs) { const s = e.stage || 0; if (s && !(s in ft)) ft[s] = e._t; } return ft; }
function firstAlert(ip) { let f = null; for (const a of state.alerts) if (a.src_ip === ip && (!f || tms(a.ts) < tms(f.ts))) f = a; return f; }
function detectLag(a) {
  const al = a && firstAlert(a.ip); if (!al) return NaN;
  const ev = state.events.find((e) => e.id === al.event_id);
  return Math.max(0, tms(al.ts) - (ev ? ev._t : tms(a.first_seen)));
}

/** An event as text parts: kind 0 plain, 1 code, 2 bad (accepted), 3 muted. */
function describe(e) {
  const d = e.details || {}, P = [];
  const t = (s) => P.push([String(s), 0]), b = (s) => P.push([String(s), 1]);
  switch (e.event_type) {
    case "http_request":
    case "file_access":
      t(e.source === "ssh" ? "read " : `${d.method || d.action || "GET"} `); b(e.asset || "/"); if (d.status != null) t(` → ${d.status}`);
      break;
    case "login_attempt":
      t("login as "); b(d.username || e.asset || "?");
      P.push(d.success ? [" · accepted", 2] : [d.contained ? " · refused, contained" : " · failed", 3]);
      break;
    case "command": t("$ "); b(d.command || ""); break;
    case "session_start": t("SSH session opened"); break;
    case "session_end": t(`SSH session closed · ${d.commands ?? 0} commands`); break;
    case "honeytoken_used": t("used "); b(TOKEN_NAME[e.honeytoken_id] || e.honeytoken_id || "honeytoken"); break;
    default: t(String(e.event_type || "event").replace(/_/g, " ") + " "); if (e.asset) b(e.asset);
  }
  return P;
}
function partsInto(node, parts) {
  for (const [text, kind] of parts) {
    if (!kind) node.append(text);
    else if (kind === 1) node.append(el("code", null, text));
    else node.append(el("span", kind === 2 ? "ok" : null, text));
  }
  return node;
}

// ------------------------------------------------------------------ ingest
function addEvent(e, live) {
  e._t = tms(e.ts);
  const ev = state.events;
  if (!ev.length || e._t >= ev[ev.length - 1]._t) ev.push(e);
  else { let lo = 0, hi = ev.length; while (lo < hi) { const m = (lo + hi) >> 1; if (ev[m]._t <= e._t) lo = m + 1; else hi = m; } ev.splice(lo, 0, e); }
  if (ev.length > MAX_EVENTS) ev.splice(0, ev.length - MAX_EVENTS);
  if (live) {
    state.fresh.set(e.id, performance.now());
    const d = DECOY_OF_SOURCE[e.source]; if (d) basePing(d, e.stage ? K.red : K.fg);
  }
  dirty.model = dirty.queue = dirty.charts = true;
}
function addAlert(a) { state.alerts.unshift(a); if (state.alerts.length > 300) state.alerts.length = 300; dirty.model = dirty.queue = dirty.charts = true; }
function addResponse(r) {
  state.responses.unshift(r); if (state.responses.length > 200) state.responses.length = 200;
  if (state.booted && r.action === "throttle_connection") toast("warn", "!", `${trackId(r.src_ip)} is being slowed down`, "Every request from it now waits before it is answered.");
  dirty.model = dirty.queue = dirty.charts = true;
}
function upsertAttacker(a) {
  const prev = state.attackers.get(a.ip);
  if (!state.order.includes(a.ip)) state.order.push(a.ip);
  state.attackers.set(a.ip, a);
  const tr = track(a.ip);
  if (state.booted) {
    if (!prev) { toast("hot", "◆", `New hostile contact ${trackId(a.ip)}`, `${a.ip} touched a decoy. Tracking it now.`); flashEdge(K.red); banner("", "New hostile contact", trackId(a.ip), `${a.ip} just touched a decoy`); }
    if (prev && (a.max_stage || 0) > (prev.max_stage || 0)) {
      const s = STAGES[(a.max_stage || 1) - 1];
      toast("hot", String(a.max_stage), `${trackId(a.ip)} took ${s.bait}`, `Stage ${a.max_stage} of 6 · now at ${PLACE[a.max_stage + 1]}.`);
      flashEdge(K.red); tr.flareAt = performance.now();
      banner("", `Stage ${a.max_stage} of 6`, STAGE_LINE[a.max_stage] || s.name, `${trackId(a.ip)} · ${a.ip}`);
      chainHit = a.max_stage;
    }
    if (a.contained_at && !(prev && prev.contained_at)) {
      tr.missileAt = performance.now();
      setTimeout(() => { toast("win", "✓", `${trackId(a.ip)} intercepted`, `Blocked on every decoy ${fmtDur(tms(a.contained_at) - tms(a.first_seen))} after first contact.`); flashEdge(K.lime); takeover(a); }, RM ? 0 : 1100);
    }
    if (prev && prev.contained_at && !a.contained_at) toast("warn", "↺", `${trackId(a.ip)} released`, "The block was lifted. Mirage is tracking it again.");
  } else if (a.contained_at) tr.missileAt = -1e9;   // already intercepted before the page opened
  dirty.model = dirty.queue = dirty.charts = true;
}

// ------------------------------------------------------------------ banner + takeover
const STAGE_LINE = {
  1: "Took the first bait: robots.txt", 2: "Stole the leaked backup file", 3: "Logged in with the stolen password",
  4: "Grabbed the planted AWS keys", 5: "Broke into the S3 bucket", 6: "Took the crown jewel",
};
// With several hackers, banners arrive in bursts: queue them so each one is
// readable (2.2 s each), and drop the oldest if the queue backs up.
const bannerQueue = [];
let bannerBusy = false;
function banner(kind, k, title, sub) {
  bannerQueue.push([kind, k, title, sub]);
  if (bannerQueue.length > 3) bannerQueue.shift();
  if (!bannerBusy) nextBanner();
}
function nextBanner() {
  const item = bannerQueue.shift(), b = $("banner");
  if (!item) { bannerBusy = false; b.hidden = true; return; }
  bannerBusy = true;
  const [kind, k, title, sub] = item, quick = bannerQueue.length > 0;
  b.hidden = true; void b.offsetWidth;
  b.className = "banner" + (kind === "win" ? " win" : "");
  b.style.animationDuration = quick ? "2.2s" : "3.2s";
  $("banner-k").textContent = k; $("banner-t").textContent = title; $("banner-s").textContent = sub;
  b.hidden = false;
  setTimeout(nextBanner, quick ? 2200 : 3300);
}
let toTimer = 0;
const takenDown = [];   // tracks intercepted while the takeover is on screen
function takeover(a) {
  const t = $("takeover"), ttc = tms(a.contained_at) - tms(a.first_seen);
  if (t.hidden) takenDown.length = 0;
  if (!takenDown.includes(a.ip)) takenDown.push(a.ip);
  const line = $("to-line");
  if (takenDown.length === 1) line.replaceChildren(el("b", null, trackId(a.ip)), ` · ${a.ip} was stopped `, el("b", null, fmtDur(ttc)), " after first contact");
  else line.replaceChildren(el("b", null, takenDown.map(trackId).join(", ")), ` intercepted · latest ${trackId(a.ip)} in `, el("b", null, fmtDur(ttc)));
  // every chip comes from Mirage's own record of what it did
  const r = state.responses.find((x) => x.src_ip === a.ip && x.action === "containment_sequence"), acts = (r && r.details && r.details.actions) || {};
  const reached = acts.enforcement ? (Array.isArray(acts.enforcement) ? acts.enforcement.length : (acts.enforcement.reached || []).length) : 0;
  const cut = acts.eviction ? acts.eviction.terminated || 0 : 0, left = 6 - (a.max_stage || 0);
  const facts = [`stage ${a.max_stage || 0} of 6`, reached ? `blocked on ${reached} decoy${reached === 1 ? "" : "s"}` : "blocked on every decoy"];
  if (cut) facts.push(`${cut} SSH session${cut === 1 ? "" : "s"} cut`);
  if (left) facts.push(`${left} bait${left === 1 ? "" : "s"} never reached`);
  $("to-facts").replaceChildren(...facts.map((f) => el("span", null, f)));
  t.classList.remove("out"); t.hidden = false;
  clearTimeout(toTimer); toTimer = setTimeout(closeTakeover, 4800);
}
function closeTakeover() { const t = $("takeover"); if (t.hidden) return; t.classList.add("out"); setTimeout(() => { t.hidden = true; t.classList.remove("out"); }, 480); }

// ------------------------------------------------------------------ attack chain
const CHAIN = [
  ["robots.txt", "Hint to a hidden folder"], ["Backup file", "Leaks the SSH password"], ["SSH login", "Uses the stolen password"],
  ["AWS keys", "Planted cloud keys"], ["S3 bucket", "Opened with the stolen keys"], ["passwords.xlsx", "The crown jewel"],
];
let chainHit = 0;
function renderChain() {
  const a = current(), host = $("chain"), st = a ? a.max_stage || 0 : 0, ft = a ? stageTimes(eventsOf(a.ip)) : {}, t0 = a ? tms(a.first_seen) : 0;
  host.replaceChildren();
  CHAIN.forEach(([name, desc], i) => {
    const n = i + 1, li = el("div", "lnk");
    if (a && n <= st) li.classList.add("taken");
    if (a && n === st && !a.contained_at) li.classList.add("now");
    if (a && n === st + 1 && !a.contained_at) li.classList.add("next");
    if (a && a.contained_at && n > st) li.classList.add("never");
    if (n === chainHit) li.classList.add("hit");
    li.append(el("span", "n", n), el("b", null, name), el("span", null, desc),
      el("em", null, !a ? "" : n <= st ? (ft[n] ? fmtRel(ft[n] - t0) : "taken") : a.contained_at ? "never" : ""));
    host.append(li);
  });
  if (a && a.contained_at && st < 6) {   // the wall Mirage put up, between the last bait taken and the next
    const w = el("i", "chain-wall"), items = host.children;
    requestAnimationFrame(() => { const x = st === 0 ? items[0].offsetLeft - 7 : items[st - 1].offsetLeft + items[st - 1].offsetWidth + 3; w.style.left = x + "px"; });
    host.append(w);
  }
  chainHit = 0;
}

// ------------------------------------------------------------------ toasts + edge pulse
function toast(kind, icon, title, text) {
  const host = $("toasts"), t = el("div", "toast " + (kind === "win" ? "win" : kind === "warn" ? "warn" : ""));
  const b = el("div"); b.append(el("b", null, title), el("span", null, text));
  t.append(el("i", null, icon), b); host.append(t);
  while (host.children.length > 4) host.firstChild.remove();
  setTimeout(() => { t.classList.add("out"); setTimeout(() => t.remove(), 400); }, 5000);
}
function flashEdge(c) { if (RM) return; const e = $("edge"); e.style.setProperty("--c", rgba(c, .5)); e.classList.remove("go"); void e.offsetWidth; e.classList.add("go"); }

// ------------------------------------------------------------------ hero
let headKey = "";
function renderHero() {
  const list = ranked(), a = current(), live = list.filter((x) => !x.contained_at);
  let words;
  if (!a) words = [["Airspace", ""], ["clear", "em"]];
  else if (live.length > 1) words = [["Tracking", ""], [`${live.length} hostiles`, "hot"]];
  else if (live.length === 1) words = [["Hostile", ""], [trackId(live[0].ip), "hot"], ["inbound", ""]];
  else words = [[list.length > 1 ? `${list.length} tracks` : trackId(a.ip), ""], ["intercepted", "em"]];
  const key = words.map((w) => w.join(":")).join("|");
  if (key !== headKey) {
    headKey = key;
    const h = $("headline"); h.replaceChildren();
    words.forEach(([text, cls], i) => {
      const w = el(cls === "em" ? "em" : "span", "w" + (cls === "hot" ? " hot" : ""), text); w.style.setProperty("--d", i);
      if (i) h.append(" "); h.append(w);
    });
  }
  // the plain-language sentence
  const sub = $("subline"); sub.replaceChildren();
  if (!a) sub.append("No contacts. Every decoy is armed and the radar is sweeping the lab.");
  else {
    const st = a.max_stage || 0, ip = el("b", null, a.ip);
    if (a.contained_at) sub.append(ip, ` reached stage ${st} of 6, then Mirage blocked it on every decoy `, el("b", null, fmtDur(tms(a.contained_at) - tms(a.first_seen))), " after first contact.");
    else {
      const lines = [
        " is probing the admin panel for hidden pages.",
        " took the first bait: robots.txt pointed it to a hidden /backup/ folder.",
        " downloaded the fake backup file, which leaks an SSH password.",
        " logged in to the SSH decoy with the leaked password.",
        " stole the planted AWS keys from the SSH server.",
        " is using the stolen keys on the S3 bucket.",
        " downloaded passwords.xlsx, the last bait.",
      ];
      sub.append(ip, lines[st] || lines[0]);
      if (bandOf(a) === "tarpit") sub.append(" Mirage is slowing it down.");
    }
  }
  $("eyebrow").textContent = a
    ? `First contact ${fmtClock(a.first_seen)} · ${a.event_count || 0} events · ${(a.tokens || []).length} of 6 baits taken`
    : "Deception lab · 3 decoy bases armed";
}

// ------------------------------------------------------------------ KPI counters
const counters = new Map();
function countTo(id, value, fmt) {
  const node = $(id), c = counters.get(id) || { v: 0, to: 0 };
  if (c.to === value && c.done) return;
  const from = c.v, start = performance.now(), dur = RM ? 0 : 700;
  c.to = value; c.done = false; counters.set(id, c);
  const card = node.closest(".kpi");
  if (card && value > from && state.booted) { card.classList.remove("bump"); void card.offsetWidth; card.classList.add("bump"); }
  const step = (now) => {
    const k = dur ? easeOut((now - start) / dur) : 1; c.v = lerp(from, value, k);
    node.textContent = fmt ? fmt(c.v) : Math.round(c.v).toLocaleString();
    if (k < 1 && c.to === value) requestAnimationFrame(step); else if (k >= 1) c.done = true;
  };
  requestAnimationFrame(step);
}
function renderKpis() {
  const list = ranked(), live = list.filter((x) => !x.contained_at), a = current();
  countTo("k-tracks", live.length);
  $("k-tracks-tag").textContent = list.length ? `${list.length - live.length} intercepted` : "clear";
  $("k-tracks").closest(".kpi").classList.toggle("alarm", live.length > 0);
  countTo("k-alerts", state.alerts.length);
  $("k-alerts-tag").textContent = `${state.alerts.filter((x) => x.severity === "critical" || x.severity === "high").length} high or critical`;
  const lastC = list.filter((x) => x.contained_at).sort((p, q) => tms(q.contained_at) - tms(p.contained_at))[0];
  const ttc = lastC ? tms(lastC.contained_at) - tms(lastC.first_seen) : null;
  if (ttc == null) { $("k-ttc").textContent = "—"; counters.delete("k-ttc"); }
  else countTo("k-ttc", ttc, (v) => (v < 1000 ? Math.round(v) + "ms" : (v / 1000).toFixed(v < 10000 ? 2 : 1) + "s"));
  $("k-ttc-tag").textContent = ttc == null ? "no intercept" : `${trackId(lastC.ip)} · stage ${lastC.max_stage || 0} of 6`;
  const bn = $("bell-n"); bn.hidden = !state.alerts.length; bn.textContent = state.alerts.length > 99 ? "99+" : state.alerts.length;
}

// ------------------------------------------------------------------ map
const map = {
  cv: null, g: null, W: 0, H: 0, dpr: 1,
  cam: { x: 500, y: 320, z: 1 }, tgt: { x: 500, y: 320, z: 1 },
  follow: false, drag: null, hover: null, mouse: null,
  terrain: null, cache: null, cacheKey: "",
  pings: [], tracks: new Map(), sweep: 0, last: 0,
};
function track(ip) {
  let t = map.tracks.get(ip);
  if (!t) {
    const lane = map.tracks.size, off = lane === 0 ? 0 : Math.ceil(lane / 2) * 24 * (lane % 2 ? 1 : -1);
    t = { pos: 0, off, hist: [], histAt: 0, sweptAt: 0, lockAt: 0, flareAt: 0, missileAt: 0 };
    map.tracks.set(ip, t);
  }
  return t;
}
function routeAt(f, off) {
  const i = clamp(Math.floor(f), 0, ROUTE.length - 2), u = clamp(f - i);
  const a = ROUTE[i], b = ROUTE[i + 1];
  const dx = b.x - a.x, dy = b.y - a.y, L = Math.hypot(dx, dy) || 1;
  return { x: lerp(a.x, b.x, u) - dy / L * off, y: lerp(a.y, b.y, u) + dx / L * off, ang: Math.atan2(dy, dx) };
}
function basePing(d, col) {
  if (RM) return; const now = performance.now(), last = map.pings.filter((p) => p.d === d).pop();
  if (last && now - last.t < 140) return;
  map.pings.push({ d, t: now, col }); if (map.pings.length > 40) map.pings.shift();
}

// terrain: contour lines from a smooth field, built once with marching squares
function buildTerrain() {
  const f = (x, y) => Math.sin(x * 0.0105 + 1.3) * Math.cos(y * 0.0128 - 0.7) + 0.6 * Math.sin((x + y) * 0.0068 + 2.1)
    + 0.45 * Math.cos(x * 0.019 - y * 0.016) + 0.28 * Math.sin(y * 0.024 + x * 0.004);
  const step = 11, x0 = -220, y0 = -200, nx = 132, ny = 96, vals = new Float32Array((nx + 1) * (ny + 1));
  for (let j = 0; j <= ny; j++) for (let i = 0; i <= nx; i++) vals[j * (nx + 1) + i] = f(x0 + i * step, y0 + j * step);
  const minor = [], major = [];
  const CASES = { 1: [[3, 2]], 2: [[2, 1]], 3: [[3, 1]], 4: [[0, 1]], 5: [[3, 0], [2, 1]], 6: [[0, 2]], 7: [[3, 0]], 8: [[3, 0]], 9: [[0, 2]], 10: [[0, 1], [3, 2]], 11: [[0, 1]], 12: [[3, 1]], 13: [[2, 1]], 14: [[3, 2]] };
  let li = 0;
  for (let lv = -1.8; lv <= 1.8; lv += 0.18, li++) {
    const out = li % 4 === 0 ? major : minor;
    for (let j = 0; j < ny; j++) for (let i = 0; i < nx; i++) {
      const a = vals[j * (nx + 1) + i], b = vals[j * (nx + 1) + i + 1], c = vals[(j + 1) * (nx + 1) + i + 1], d = vals[(j + 1) * (nx + 1) + i];
      const idx = (a > lv ? 8 : 0) | (b > lv ? 4 : 0) | (c > lv ? 2 : 0) | (d > lv ? 1 : 0);
      const segs = CASES[idx]; if (!segs) continue;
      const X = x0 + i * step, Y = y0 + j * step;
      const pt = (e) => e === 0 ? [X + step * (lv - a) / (b - a), Y] : e === 1 ? [X + step, Y + step * (lv - b) / (c - b)]
        : e === 2 ? [X + step * (lv - d) / (c - d), Y + step] : [X, Y + step * (lv - a) / (d - a)];
      for (const [e1, e2] of segs) { const p = pt(e1), q = pt(e2); out.push(p[0], p[1], q[0], q[1]); }
    }
  }
  map.terrain = { minor: new Float32Array(minor), major: new Float32Array(major) };
}
function scale() { return Math.min(map.W / 1000, map.H / 640) * 0.94 * map.cam.z; }
function toScreen(x, y) { const s = scale(); return [(x - map.cam.x) * s + map.W / 2, (y - map.cam.y) * s + map.H / 2]; }
function toWorld(sx, sy) { const s = scale(); return [(sx - map.W / 2) / s + map.cam.x, (sy - map.H / 2) / s + map.cam.y]; }
function sizeMap() {
  const wrap = $("map-wrap"), dpr = Math.min(devicePixelRatio || 1, 2);
  map.cv = $("map"); map.g = map.cv.getContext("2d"); map.dpr = dpr;
  map.W = wrap.clientWidth; map.H = wrap.clientHeight;
  map.cv.width = Math.round(map.W * dpr); map.cv.height = Math.round(map.H * dpr);
  map.cacheKey = "";
}

/** The parts of the map that only change with the camera, cached to an offscreen canvas. */
function drawStatic() {
  const key = `${map.W}x${map.H}:${map.cam.x.toFixed(1)}:${map.cam.y.toFixed(1)}:${map.cam.z.toFixed(3)}`;
  if (key === map.cacheKey && map.cache) return map.cache;
  map.cacheKey = key;
  const c = map.cache || document.createElement("canvas");
  c.width = map.cv.width; c.height = map.cv.height;
  const g = c.getContext("2d"); g.setTransform(map.dpr, 0, 0, map.dpr, 0, 0);
  const s = scale(), W = map.W, H = map.H;
  g.fillStyle = rgba(K.bg, 1); g.fillRect(0, 0, W, H);
  // terrain
  const strokeSegs = (arr, col, w) => {
    g.beginPath();
    for (let i = 0; i < arr.length; i += 4) { const [ax, ay] = toScreen(arr[i], arr[i + 1]); const [bx, by] = toScreen(arr[i + 2], arr[i + 3]); g.moveTo(ax, ay); g.lineTo(bx, by); }
    g.strokeStyle = col; g.lineWidth = w; g.stroke();
  };
  strokeSegs(map.terrain.minor, "rgba(255,255,255,.035)", 1);
  strokeSegs(map.terrain.major, "rgba(255,255,255,.075)", 1);
  // grid with map references along the edges (A, B, C … across, 1, 2, 3 … down)
  g.strokeStyle = "rgba(255,255,255,.045)"; g.lineWidth = 1; g.font = `10px ${MONO}`; g.fillStyle = rgba(K.faint, 1);
  for (let gx = -200; gx <= 1200; gx += 50) { const [x] = toScreen(gx, 0); if (x < 0 || x > W) continue; g.beginPath(); g.moveTo(x, 0); g.lineTo(x, H); g.stroke(); if (gx >= 0 && gx < 1000) { g.textAlign = "center"; g.fillText(String.fromCharCode(65 + gx / 50), x + 25 * s, 14); } }
  for (let gy = -200; gy <= 840; gy += 50) { const [, y] = toScreen(0, gy); if (y < 0 || y > H) continue; g.beginPath(); g.moveTo(0, y); g.lineTo(W, y); g.stroke(); if (gy >= 0 && gy < 640) { g.textAlign = "left"; g.fillText(String(gy / 50 + 1), 6, y + 25 * s + 3); } }
  // radar range rings and bearings around the station
  const [sx, sy] = toScreen(STATION.x, STATION.y);
  g.setLineDash([2, 6]);
  for (let r = 150; r <= 750; r += 150) { g.strokeStyle = rgba(K.lime, r % 300 ? .07 : .12); g.beginPath(); g.arc(sx, sy, r * s, 0, Math.PI * 2); g.stroke(); }
  g.setLineDash([]);
  for (let deg = 0; deg < 360; deg += 10) {
    const a = (deg - 90) * Math.PI / 180, r1 = 150 * s, r2 = r1 + (deg % 30 ? 4 : 9);
    g.strokeStyle = rgba(K.lime, deg % 30 ? .25 : .5); g.beginPath(); g.moveTo(sx + Math.cos(a) * r1, sy + Math.sin(a) * r1); g.lineTo(sx + Math.cos(a) * r2, sy + Math.sin(a) * r2); g.stroke();
    if (deg % 90 === 0) { g.fillStyle = rgba(K.lime, .7); g.textAlign = "center"; g.fillText(["N", "E", "S", "W"][deg / 90], sx + Math.cos(a) * (r2 + 10), sy + Math.sin(a) * (r2 + 10) + 3); }
  }
  // network links between the bases
  g.setLineDash([3, 5]); g.strokeStyle = "rgba(255,255,255,.12)"; g.lineWidth = 1;
  const link = (p, q) => { const [ax, ay] = toScreen(p.x, p.y), [bx, by] = toScreen(q.x, q.y); g.beginPath(); g.moveTo(ax, ay); g.lineTo(bx, by); g.stroke(); };
  link(BASES.admin, BASES.ssh); link(BASES.ssh, BASES.s3); link(BASES.s3, JEWEL); link(FRIEND, BASES.admin);
  g.setLineDash([]);
  // entry corridor
  g.font = `600 10px ${MONO}`; g.fillStyle = rgba(K.mute, .8); g.textAlign = "left";
  const [ex, ey] = toScreen(20, 92); g.fillText("ENTRY CORRIDOR ▸", Math.max(8, ex), ey);
  return c;
}
function hexPath(g, x, y, r) { g.beginPath(); for (let i = 0; i < 6; i++) { const a = Math.PI / 6 + i * Math.PI / 3; i ? g.lineTo(x + Math.cos(a) * r, y + Math.sin(a) * r) : g.moveTo(x + Math.cos(a) * r, y + Math.sin(a) * r); } g.closePath(); }
function label(g, text, x, y, col, size, weight, align) {
  g.font = `${weight || 500} ${size}px ${size < 12 ? MONO : SANS}`; g.textAlign = align || "center"; g.fillStyle = col; g.fillText(text, x, y);
}
function drawMap(now) {
  const g = map.g; if (!g) return;
  const dt = map.last ? Math.min(0.1, (now - map.last) / 1000) : 0; map.last = now;
  // camera eases toward its target
  const sel = current(), tsel = sel ? track(sel.ip) : null;
  if (map.follow && tsel && !map.drag) { const p = routeAt(tsel.pos, tsel.off); map.tgt.x = p.x; map.tgt.y = p.y; }
  const k = RM ? 1 : 1 - Math.exp(-dt * 7);
  map.cam.x = lerp(map.cam.x, map.tgt.x, k); map.cam.y = lerp(map.cam.y, map.tgt.y, k); map.cam.z = lerp(map.cam.z, map.tgt.z, k);
  if (Math.abs(map.cam.x - map.tgt.x) < 0.05) map.cam.x = map.tgt.x;
  if (Math.abs(map.cam.y - map.tgt.y) < 0.05) map.cam.y = map.tgt.y;
  if (Math.abs(map.cam.z - map.tgt.z) < 0.0005) map.cam.z = map.tgt.z;

  g.setTransform(1, 0, 0, 1, 0, 0); g.drawImage(drawStatic(), 0, 0);
  g.setTransform(map.dpr, 0, 0, map.dpr, 0, 0);
  const s = scale(), W = map.W, H = map.H;
  const [sx, sy] = toScreen(STATION.x, STATION.y);

  // radar sweep from the Mirage station
  const prevSweep = map.sweep;
  map.sweep = RM ? -Math.PI / 2 : (now * 0.0011) % (Math.PI * 2);
  if (layers.sweep && !RM && g.createConicGradient) {
    const cg = g.createConicGradient(map.sweep - 0.75, sx, sy);
    cg.addColorStop(0, "rgba(214,242,76,0)"); cg.addColorStop(0.118, "rgba(214,242,76,.09)"); cg.addColorStop(0.1194, "rgba(214,242,76,.45)"); cg.addColorStop(0.121, "rgba(214,242,76,0)"); cg.addColorStop(1, "rgba(214,242,76,0)");
    g.fillStyle = cg; g.beginPath(); g.arc(sx, sy, 760 * s, 0, Math.PI * 2); g.fill();
  }
  const swept = (x, y) => {
    if (!layers.sweep || RM) return true;
    const a = (Math.atan2(y - STATION.y, x - STATION.x) + Math.PI * 2) % (Math.PI * 2);
    return prevSweep <= map.sweep ? a > prevSweep && a <= map.sweep : a > prevSweep || a <= map.sweep;
  };

  const attackers = ranked();
  const hitBy = { admin: 0, ssh: 0, s3: 0 }, blocking = new Set();
  for (const a of attackers) {
    const st = a.max_stage || 0;
    hitBy.admin += 1; if (st >= 3) hitBy.ssh += 1; if (st >= 5) hitBy.s3 += 1;
    if (a.contained_at) DECOYS.forEach((d) => blocking.add(d));
  }

  // base sectors, pings, and the bases themselves
  for (const d of DECOYS) {
    const b = BASES[d], [bx, by] = toScreen(b.x, b.y), hot = hitBy[d] > 0, block = blocking.has(d);
    hexPath(g, bx, by, 74 * s);
    g.fillStyle = block ? "rgba(214,242,76,.045)" : hot ? "rgba(255,74,61,.05)" : "rgba(255,255,255,.018)"; g.fill();
    g.setLineDash([4, 6]); g.lineDashOffset = RM ? 0 : -now * 0.01; g.strokeStyle = block ? rgba(K.lime, .55) : hot ? rgba(K.red, .4) : "rgba(255,255,255,.14)"; g.lineWidth = 1; g.stroke(); g.setLineDash([]);
  }
  map.pings = map.pings.filter((p) => now - p.t < 900);
  for (const p of map.pings) {
    const b = BASES[p.d], [bx, by] = toScreen(b.x, b.y), u = (now - p.t) / 900;
    g.strokeStyle = rgba(p.col, (1 - u) * .8); g.lineWidth = 1.5; hexPath(g, bx, by, (16 + u * 40) * Math.max(.8, s)); g.stroke();
  }
  for (const d of DECOYS) {
    const b = BASES[d], [bx, by] = toScreen(b.x, b.y), hot = hitBy[d] > 0, block = blocking.has(d);
    const r = 11;
    g.fillStyle = rgba(K.bg, 1); g.strokeStyle = block ? rgba(K.lime, 1) : hot ? rgba(K.red, 1) : rgba(K.fg, .9); g.lineWidth = 1.8;
    g.beginPath(); g.roundRect(bx - r, by - r, r * 2, r * 2, 4); g.fill(); g.stroke();
    g.fillStyle = g.strokeStyle; g.beginPath(); g.roundRect(bx - 4, by - 4, 8, 8, 2); g.fill();
    label(g, b.name, bx, by + r + 18, rgba(K.fg, .95), 13, 500);
    label(g, `${b.ip} · ${block ? "BLOCKING" : hot ? "UNDER ATTACK" : "ARMED"}`, bx, by + r + 32, block ? rgba(K.lime, .9) : hot ? rgba(K.red, .9) : rgba(K.mute, .9), 10, 500);
  }
  // friendly site
  { const [fx, fy] = toScreen(FRIEND.x, FRIEND.y);
    g.fillStyle = rgba(K.lime, 1); g.beginPath(); g.arc(fx, fy, 7, 0, Math.PI * 2); g.fill();
    g.strokeStyle = rgba(K.lime, .35); g.beginPath(); g.arc(fx, fy, 13, 0, Math.PI * 2); g.stroke();
    label(g, FRIEND.name, fx, fy + 30, rgba(K.fg, .85), 13, 500); label(g, "FRIENDLY · REAL SITE", fx, fy + 44, rgba(K.lime, .75), 10, 500); }
  // crown jewel
  { const [jx, jy] = toScreen(JEWEL.x, JEWEL.y), breached = attackers.some((a) => (a.max_stage || 0) >= 6);
    const col = breached ? K.red : K.lime;
    g.save(); g.translate(jx, jy); g.rotate(Math.PI / 4 + (RM ? 0 : now * 0.0004));
    g.setLineDash([3, 3]); g.strokeStyle = rgba(col, .8); g.lineWidth = 1.5; g.strokeRect(-17, -17, 34, 34); g.setLineDash([]);
    g.rotate(-(RM ? 0 : now * 0.0004)); g.fillStyle = rgba(col, .9); g.fillRect(-6, -6, 12, 12); g.restore();
    label(g, JEWEL.name, jx, jy + 40, rgba(K.fg, .95), 13, 500); label(g, `${JEWEL.file} · ${breached ? "TAKEN" : "PROTECTED"}`, jx, jy + 54, rgba(col, .85), 10, 500); }
  // Mirage station
  { g.fillStyle = rgba(K.bg, 1); g.strokeStyle = rgba(K.lime, 1); g.lineWidth = 2;
    g.beginPath(); g.arc(sx, sy, 12, 0, Math.PI * 2); g.fill(); g.stroke();
    g.beginPath(); g.arc(sx, sy, 4, 0, Math.PI * 2); g.fillStyle = rgba(K.lime, 1); g.fill();
    g.beginPath(); g.moveTo(sx, sy); g.lineTo(sx + Math.cos(map.sweep) * 12, sy + Math.sin(map.sweep) * 12); g.stroke();
    label(g, STATION.name, sx, sy - 22, rgba(K.lime, 1), 13, 600); label(g, `${STATION.ip} · CONTROLLER`, sx, sy + 28, rgba(K.mute, .9), 10, 500); }

  // tracks
  const hits = [], blocks = [];
  for (const a of [...attackers].reverse()) {
    const t = track(a.ip), st = a.max_stage || 0, contained = !!a.contained_at, isSel = sel && sel.ip === a.ip;
    const target = st + 1;
    t.pos = RM ? target : t.pos + (target - t.pos) * (1 - Math.exp(-dt * 1.5));
    if (Math.abs(target - t.pos) < 0.002) t.pos = target;
    const p = routeAt(t.pos, t.off), [px, py] = toScreen(p.x, p.y);
    if (now - t.histAt > 160) { t.histAt = now; const lastH = t.hist[t.hist.length - 1]; if (!lastH || Math.hypot(lastH.x - p.x, lastH.y - p.y) > 2) { t.hist.push({ x: p.x, y: p.y }); if (t.hist.length > 46) t.hist.shift(); } }
    if (swept(p.x, p.y)) t.sweptAt = now;
    const glow = layers.sweep && !RM ? .5 + .5 * Math.exp(-(now - t.sweptAt) / 1900) : 1;
    const col = contained ? K.lime : bandOf(a) === "tarpit" ? K.amber : K.red;

    // route already flown, then the projected course still ahead
    if (layers.route) {
      g.lineWidth = isSel ? 2.2 : 1.4; g.strokeStyle = rgba(K.red, isSel ? .85 : .45);
      g.beginPath(); let first = true;
      for (let f = 0; f <= t.pos + 1e-6; f += 0.05) { const q = routeAt(Math.min(f, t.pos), t.off), [qx, qy] = toScreen(q.x, q.y); if (first) { g.moveTo(qx, qy); first = false; } else g.lineTo(qx, qy); }
      g.lineTo(px, py); g.stroke();
      if (!RM) { g.setLineDash([2, 14]); g.lineDashOffset = -now * 0.05; g.strokeStyle = rgba(K.fg, isSel ? .9 : .4); g.lineWidth = 2.2; g.stroke(); g.setLineDash([]); }
      if (!contained && t.pos < ROUTE.length - 1) {
        g.setLineDash([5, 7]); g.strokeStyle = rgba(K.red, isSel ? .35 : .15); g.lineWidth = 1.2; g.beginPath(); g.moveTo(px, py);
        for (let i = Math.ceil(t.pos + 1e-3); i < ROUTE.length; i++) { const q = routeAt(i, t.off), [qx, qy] = toScreen(q.x, q.y); g.lineTo(qx, qy); }
        g.stroke(); g.setLineDash([]);
      }
      // waypoints reached
      for (let i = 2; i <= Math.floor(t.pos + 1e-3); i++) {
        const q = routeAt(i, t.off), [qx, qy] = toScreen(q.x, q.y);
        g.fillStyle = rgba(K.bg, 1); g.strokeStyle = rgba(K.red, .9); g.lineWidth = 1.5; g.beginPath(); g.arc(qx, qy, 4.5, 0, Math.PI * 2); g.fill(); g.stroke();
        if (isSel) label(g, `S${i - 1}`, qx + 9, qy - 7, rgba(K.red, .9), 10, 600, "left");
      }
      if (t.flareAt && now - t.flareAt < 1400) {
        const u = (now - t.flareAt) / 1400, q = routeAt(target, t.off), [qx, qy] = toScreen(q.x, q.y);
        g.strokeStyle = rgba(K.red, 1 - u); g.lineWidth = 2; g.beginPath(); g.arc(qx, qy, 6 + u * 46, 0, Math.PI * 2); g.stroke();
        g.beginPath(); g.arc(qx, qy, 6 + easeOut(u) * 24, 0, Math.PI * 2); g.stroke();
      }
    }
    // history dots, evenly spaced in time: gaps show speed
    if (layers.history) {
      t.hist.forEach((h, i) => { const [hx, hy] = toScreen(h.x, h.y), u = i / t.hist.length; g.fillStyle = rgba(col, u * .7 * glow); g.beginPath(); g.arc(hx, hy, 1.4 + u * 1.4, 0, Math.PI * 2); g.fill(); });
    }
    // interceptor: fired from the station, curving onto the track, then a shield
    const mAge = t.missileAt ? now - t.missileAt : -1, flight = 1100;
    if (contained && mAge >= 0 && mAge < flight && !RM) {
      const u = easeOut(mAge / flight), cx = (sx + px) / 2 + (py - sy) * .35, cy = (sy + py) / 2 - (px - sx) * .35;
      const at = (v) => [(1 - v) * (1 - v) * sx + 2 * (1 - v) * v * cx + v * v * px, (1 - v) * (1 - v) * sy + 2 * (1 - v) * v * cy + v * v * py];
      g.strokeStyle = rgba(K.lime, .9); g.lineWidth = 2; g.beginPath();
      for (let v = Math.max(0, u - .35); v <= u; v += 0.02) { const [mx, my] = at(v); v === Math.max(0, u - .35) ? g.moveTo(mx, my) : g.lineTo(mx, my); }
      g.stroke(); const [mx, my] = at(u);
      g.fillStyle = "#fff"; g.beginPath(); g.arc(mx, my, 3.5, 0, Math.PI * 2); g.fill();
      g.fillStyle = rgba(K.lime, .3); g.beginPath(); g.arc(mx, my, 10, 0, Math.PI * 2); g.fill();
    }
    const impact = contained ? mAge - flight : -1;
    if (impact >= 0 && impact < 1200 && !RM) {
      const u = impact / 1200;
      g.fillStyle = rgba(K.lime, (1 - u) * .35); g.beginPath(); g.arc(px, py, 10 + u * 70, 0, Math.PI * 2); g.fill();
      g.strokeStyle = rgba(K.lime, 1 - u); g.lineWidth = 2; g.beginPath(); g.arc(px, py, 10 + easeOut(u) * 50, 0, Math.PI * 2); g.stroke();
    }
    const shieldOn = contained && (RM || mAge >= flight || t.missileAt < 0);
    if (shieldOn) {
      g.strokeStyle = rgba(K.lime, .9); g.lineWidth = 1.8; g.setLineDash([6, 4]); g.lineDashOffset = RM ? 0 : now * 0.02;
      g.beginPath(); g.arc(px, py, 22, 0, Math.PI * 2); g.stroke(); g.setLineDash([]);
    }
    // speed vector toward the next bait
    if (!contained && t.pos < ROUTE.length - 1) {
      const nx = routeAt(Math.min(ROUTE.length - 1, Math.floor(t.pos + 1e-3) + 1), t.off), ang = Math.atan2(nx.y - p.y, nx.x - p.x);
      g.strokeStyle = rgba(col, glow); g.lineWidth = 1.6; g.beginPath(); g.moveTo(px + Math.cos(ang) * 10, py + Math.sin(ang) * 10); g.lineTo(px + Math.cos(ang) * 34, py + Math.sin(ang) * 34); g.stroke();
    }
    // the hostile symbol: a diamond
    const R = isSel ? 9 : 7;
    if (!contained) { g.fillStyle = rgba(col, .18 * glow); g.beginPath(); g.arc(px, py, 22, 0, Math.PI * 2); g.fill(); }
    g.save(); g.translate(px, py); g.rotate(Math.PI / 4);
    g.fillStyle = contained ? rgba(K.bg, 1) : rgba(col, glow); g.strokeStyle = rgba(col, 1); g.lineWidth = 2;
    g.fillRect(-R, -R, R * 2, R * 2); g.strokeRect(-R, -R, R * 2, R * 2); g.restore();
    if (contained) { g.strokeStyle = rgba(K.red, .9); g.lineWidth = 2; g.beginPath(); g.moveTo(px - 5, py - 5); g.lineTo(px + 5, py + 5); g.moveTo(px + 5, py - 5); g.lineTo(px - 5, py + 5); g.stroke(); }
    // lock-on brackets close in on the selected track
    if (isSel) {
      const u = RM ? 1 : easeOut((now - t.lockAt) / 500), rr = lerp(46, 20, u), L = 7;
      g.strokeStyle = rgba(contained ? K.lime : K.fg, .95); g.lineWidth = 1.8; g.beginPath();
      for (const [dx, dy] of [[-1, -1], [1, -1], [1, 1], [-1, 1]]) { g.moveTo(px + dx * rr, py + dy * (rr - L)); g.lineTo(px + dx * rr, py + dy * rr); g.lineTo(px + dx * (rr - L), py + dy * rr); }
      g.stroke();
    }
    // data block with a leader line
    const right = px < W - 210, bx = px + (right ? 34 : -34), bw = 156, bh = 54, x0 = right ? bx : bx - bw;
    let by = py - 42;
    for (let guard = 0; guard < 8 && blocks.some((r) => x0 < r.x + r.w + 6 && x0 + bw + 6 > r.x && by < r.y + r.h + 6 && by + bh + 6 > r.y); guard++) by += bh + 8;
    blocks.push({ x: x0, y: by, w: bw, h: bh });
    g.strokeStyle = rgba(col, .7); g.lineWidth = 1; g.beginPath(); g.moveTo(px + (right ? 12 : -12), py - 10); g.lineTo(right ? x0 : x0 + bw, by + bh - 6); g.stroke();
    g.fillStyle = "rgba(10,11,10,.88)"; g.beginPath(); g.roundRect(x0, by, bw, bh, 8); g.fill();
    g.fillStyle = rgba(col, 1); g.fillRect(x0, by + 8, 2, bh - 16);
    label(g, trackId(a.ip), x0 + 12, by + 17, rgba(K.fg, 1), 13, 600, "left");
    label(g, contained ? "INTERCEPTED" : bandOf(a) === "tarpit" ? "HOSTILE · SLOWED" : "HOSTILE", x0 + 52, by + 17, rgba(col, 1), 10, 600, "left");
    label(g, a.ip, x0 + 12, by + 32, rgba(K.mute, 1), 10, 500, "left");
    label(g, `STAGE ${st}/6 · RISK ${a.risk_score || 0}`, x0 + 12, by + 46, rgba(K.fg, .85), 10, 500, "left");
    hits.push({ kind: "track", ip: a.ip, x: px, y: py, r: 18 });
  }
  map.hitTracks = hits;
  $("map-empty").hidden = attackers.length > 0;
}
function mapHit(mx, my) {
  for (const h of map.hitTracks || []) if (Math.hypot(h.x - mx, h.y - my) < h.r) return h;
  const near = (p) => { const [x, y] = toScreen(p.x, p.y); return Math.hypot(x - mx, y - my) < 22; };
  for (const d of DECOYS) if (near(BASES[d])) return { kind: "base", d };
  if (near(STATION)) return { kind: "station" };
  if (near(JEWEL)) return { kind: "jewel" };
  if (near(FRIEND)) return { kind: "friend" };
  return null;
}
function showHover(h, mx, my) {
  const card = $("hovercard");
  if (!h) { card.hidden = true; map.cv.classList.remove("over"); return; }
  map.cv.classList.add("over");
  const key = JSON.stringify(h);
  if (card.dataset.key !== key || card.hidden) {
    card.dataset.key = key; card.replaceChildren(); card.className = "hovercard";
    const rows = [];
    let k = "", title = "", act = "";
    if (h.kind === "track") {
      const a = state.attackers.get(h.ip); if (!a) { card.hidden = true; return; }
      card.classList.add("hostile");
      k = a.contained_at ? "Intercepted track" : "Hostile track"; title = `${trackId(a.ip)} · ${a.ip}`;
      rows.push(["Now at", PLACE[(a.max_stage || 0) + 1]], ["Baits taken", `${a.max_stage || 0} of 6`], ["Threat score", `${a.risk_score || 0} / 100`], ["First contact", fmtClock(a.first_seen)], ["Events", a.event_count || 0]);
      act = state.selected === a.ip ? "Locked · click a base or empty space to keep it" : "Click to lock this track";
    } else if (h.kind === "base") {
      const b = BASES[h.d], src = Object.keys(DECOY_OF_SOURCE).find((s) => DECOY_OF_SOURCE[s] === h.d);
      const evs = state.events.filter((e) => e.source === src), lastE = evs[evs.length - 1];
      k = `${b.role} · decoy`; title = b.name;
      rows.push(["Address", b.ip], ["Holds baits", b.holds], ["Hostile events", evs.length], ["Last contact", lastE ? fmtClock(lastE.ts) : "none"]);
      act = "Click to zoom to this base";
    } else if (h.kind === "station") { k = "Mirage"; title = "Radar station"; rows.push(["Address", STATION.ip], ["Watches", "3 decoy bases"], ["Auto-intercept", "at threat 75"]); act = "Fires the interceptor when a track crosses 75"; }
    else if (h.kind === "jewel") { k = "Protected objective"; title = "Crown jewel"; rows.push(["File", JEWEL.file], ["Lives on", "S3 bucket"], ["Status", ranked().some((a) => (a.max_stage || 0) >= 6) ? "Taken" : "Protected"]); }
    else { k = "Friendly"; title = "Staff portal"; rows.push(["Address", FRIEND.ip], ["What it is", "The real intranet"], ["Decoys touched", "none, ever"]); act = "Normal users only ever land here"; }
    card.append(el("span", "k", k), el("h3", null, title));
    const dl = el("dl"); for (const [dt, dd] of rows) dl.append(el("dt", null, dt), el("dd", null, dd)); card.append(dl);
    if (act) card.append(el("div", "act", act));
    card.hidden = false;
  }
  const w = card.offsetWidth, hh = card.offsetHeight;
  card.style.left = clamp(mx + 18, 8, map.W - w - 8) + "px";
  card.style.top = clamp(my + 18 + hh > map.H ? my - hh - 14 : my + 18, 8, map.H - hh - 8) + "px";
}
function selectTrack(ip, fly) {
  if (!ip) return;
  state.selected = ip; track(ip).lockAt = performance.now();
  if (fly) { const t = track(ip), p = routeAt(t.pos, t.off); map.tgt.x = p.x; map.tgt.y = p.y; map.tgt.z = Math.max(map.tgt.z, 1.5); }
  dirty.model = dirty.charts = dirty.queue = true;
}
function zoomBy(f, ax, ay) {
  const z = clamp(map.tgt.z * f, 0.7, 3.2);
  if (ax != null) { const [wx, wy] = toWorld(ax, ay); const k = 1 - map.tgt.z / z; map.tgt.x += (wx - map.tgt.x) * k; map.tgt.y += (wy - map.tgt.y) * k; }
  map.tgt.z = z;
}
function resetView() { map.tgt = { x: 500, y: 320, z: 1 }; setFollow(false); }
function setFollow(on) { map.follow = on; $("follow").setAttribute("aria-pressed", on); }
function bindMap() {
  const cv = $("map");
  cv.addEventListener("pointerdown", (e) => { cv.setPointerCapture(e.pointerId); map.drag = { x: e.offsetX, y: e.offsetY, cx: map.tgt.x, cy: map.tgt.y, moved: false }; });
  cv.addEventListener("pointermove", (e) => {
    const mx = e.offsetX, my = e.offsetY; map.mouse = [mx, my];
    if (map.drag) {
      const dx = mx - map.drag.x, dy = my - map.drag.y;
      if (Math.hypot(dx, dy) > 4) { map.drag.moved = true; cv.classList.add("drag"); setFollow(false); }
      if (map.drag.moved) { const s = scale(); map.tgt.x = map.cam.x = map.drag.cx - dx / s; map.tgt.y = map.cam.y = map.drag.cy - dy / s; }
    }
    const [wx, wy] = toWorld(mx, my);
    $("grid-ref").textContent = wx >= 0 && wx < 1000 && wy >= 0 && wy < 640 ? `GRID ${String.fromCharCode(65 + Math.floor(wx / 50))}${Math.floor(wy / 50) + 1} · ${Math.round(wx)}, ${Math.round(wy)}` : "OUTSIDE THE LAB";
    if (!map.drag || !map.drag.moved) showHover(mapHit(mx, my), mx, my); else showHover(null);
  });
  cv.addEventListener("pointerup", (e) => {
    const d = map.drag; map.drag = null; cv.classList.remove("drag");
    if (d && !d.moved) {
      const h = mapHit(e.offsetX, e.offsetY);
      if (h && h.kind === "track") selectTrack(h.ip, false);
      else if (h && h.kind === "base") { const b = BASES[h.d]; setFollow(false); map.tgt.x = b.x; map.tgt.y = b.y; map.tgt.z = 2; showHover(null); return; }
      showHover(h, e.offsetX, e.offsetY);
    }
  });
  cv.addEventListener("pointerleave", () => { showHover(null); $("grid-ref").textContent = "GRID —"; });
  // plain scroll keeps moving the page; Ctrl (or ⌘) + scroll zooms the map, like an embedded map
  let hintTimer = 0;
  cv.addEventListener("wheel", (e) => {
    if (!e.ctrlKey && !e.metaKey) {
      const h = $("zoom-hint"); h.hidden = false; h.classList.remove("show"); void h.offsetWidth; h.classList.add("show");
      clearTimeout(hintTimer); hintTimer = setTimeout(() => { h.hidden = true; }, 1400);
      return;
    }
    e.preventDefault(); setFollow(false); zoomBy(e.deltaY < 0 ? 1.15 : 1 / 1.15, e.offsetX, e.offsetY);
  }, { passive: false });
  $("zoom-in").onclick = () => zoomBy(1.3);
  $("zoom-out").onclick = () => zoomBy(1 / 1.3);
  $("recenter").onclick = resetView;
  $("follow").onclick = () => { const on = !map.follow; setFollow(on); if (on) { const a = current(); if (a) selectTrack(a.ip, false); map.tgt.z = Math.max(map.tgt.z, 1.6); } };
  document.querySelectorAll("[data-layer]").forEach((b) => b.addEventListener("click", () => {
    const k = b.dataset.layer; layers[k] = !layers[k]; b.classList.toggle("on", layers[k]); b.setAttribute("aria-pressed", layers[k]);
  }));
  document.addEventListener("keydown", (e) => {
    if (e.target.closest("input, textarea") || e.metaKey || e.ctrlKey) return;
    if (e.key === "+" || e.key === "=") zoomBy(1.3); else if (e.key === "-") zoomBy(1 / 1.3);
    else if (e.key === "0") resetView(); else if (e.key === "f" || e.key === "F") $("follow").click();
    else if (e.key === "g" || e.key === "G") $("guide").click();
    else if (e.key === "Escape") { showHover(null); setFollow(false); closeTakeover(); if (document.body.classList.contains("guide")) $("guide").click(); }
  });
}

// ------------------------------------------------------------------ target lock + track table
function buildDial() {
  const svg = $("dial-svg");
  S("circle", { cx: 100, cy: 100, r: 70, class: "dial-ring" }, svg);
  for (let i = 0; i < 60; i++) {
    const a = (i / 60) * Math.PI * 2 - Math.PI / 2, r1 = 82, r2 = i % 5 ? 92 : 96;
    const l = S("line", { x1: 100 + Math.cos(a) * r1, y1: 100 + Math.sin(a) * r1, x2: 100 + Math.cos(a) * r2, y2: 100 + Math.sin(a) * r2 }, svg);
    l.classList.add(i < 24 ? "w" : i < 45 ? "t" : "c");
  }
}
let dialShown = -1;
function renderLock() {
  const a = current(), band = bandOf(a);
  document.body.dataset.state = band;
  const risk = a ? a.risk_score || 0 : 0;
  if (risk !== dialShown) {
    const lines = $("dial-svg").querySelectorAll("line"), lit = Math.round(risk / 100 * 60);
    lines.forEach((l, i) => { l.style.transitionDelay = (RM ? 0 : Math.abs(i - (dialShown < 0 ? 0 : Math.round(dialShown / 100 * 60))) * 9) + "ms"; l.classList.toggle("on", i < lit); });
    countTo("dial-n", risk); dialShown = risk;
  }
  $("dial").classList.toggle("safe", !!(a && a.contained_at));
  const badge = $("lock-badge"), text = !a ? "Standby" : a.contained_at ? "Intercepted" : band === "tarpit" ? "Slowed" : "Hostile";
  if (badge.textContent !== text) { badge.textContent = text; badge.className = "badge " + (!a ? "" : a.contained_at ? "contained" : band === "tarpit" ? "tarpit" : "hostile"); if (state.booted) badge.classList.add("flip"); }
  $("lock-sub").textContent = a ? `${trackId(a.ip)} · ${state.selected ? "locked by you" : "highest threat, auto-locked"}` : "No track locked";
  const st = a ? a.max_stage || 0 : 0;
  $("lf-id").textContent = a ? trackId(a.ip) : "—";
  $("lf-ip").textContent = a ? a.ip : "—";
  const pos = $("lf-pos"); pos.textContent = a ? PLACE[st + 1].replace(/^the /, "").replace(/^./, (c) => c.toUpperCase()) : "—";
  const head = $("lf-head");
  head.textContent = !a ? "—" : a.contained_at ? "None · blocked" : st >= 6 ? "All baits taken" : STAGES[st].name;
  head.className = a && a.contained_at ? "ok" : a ? "hot" : "";
  $("lf-bait").textContent = a ? `${st} of 6` : "—";
  $("btn-contain").disabled = !a || !!a.contained_at;
  $("btn-release").disabled = !a || !a.contained_at;

  // track table
  const host = $("tracks"), list = ranked(); host.replaceChildren();
  for (const x of list) {
    const b = el("button", "trk" + (x.contained_at ? " done" : "") + (bandOf(x) === "tarpit" ? " tarpit" : "") + (a && a.ip === x.ip ? " sel" : ""));
    b.type = "button"; b.setAttribute("role", "listitem");
    const id = el("span", "id", trackId(x.ip)); id.append(el("span", null, x.ip));
    const bar = el("span", "bar"); for (let i = 1; i <= 6; i++) bar.append(el("i", i <= (x.max_stage || 0) ? "on" : null));
    b.append(el("span", "sym"), id, el("span", "st", x.contained_at ? "intercepted" : bandOf(x) === "tarpit" ? "slowed" : `risk ${x.risk_score || 0}`), bar);
    b.addEventListener("click", () => selectTrack(x.ip, true));
    host.append(b);
  }
  $("tracks-empty").hidden = list.length > 0;
  $("tracks-sub").textContent = `${list.length} track${list.length === 1 ? "" : "s"} · ${list.filter((x) => !x.contained_at).length} active`;
}
function tickLockClock() {
  const a = current(), n = $("lf-time");
  if (!a) { n.textContent = "—"; return; }
  const end = a.contained_at ? tms(a.contained_at) : Date.now();
  n.textContent = fmtDur(end - tms(a.first_seen));
}

// ------------------------------------------------------------------ engagement phases
function renderPhases() {
  const a = current(), host = $("phases"); host.replaceChildren();
  const t0 = a ? tms(a.first_seen) : 0, evs = a ? eventsOf(a.ip) : [], ft = stageTimes(evs);
  const al = a && firstAlert(a.ip), slow = a && [...state.responses].reverse().find((r) => r.src_ip === a.ip && r.action === "throttle_connection");
  const baitT = a ? Math.min(...Object.values(ft), Infinity) : Infinity;
  const P = [
    ["Contact", "First packet hit a decoy", a ? t0 : null],
    ["Detected", "Mirage raised the first alert", al ? tms(al.ts) : null],
    ["Took the bait", "Followed the planted breadcrumbs", isFinite(baitT) ? baitT : null],
    ["Slowed down", slow ? "Every request now waits" : "Tarpit at threat 40", slow ? tms(slow.ts) : null],
    ["Intercepted", "Blocked on every decoy", a && a.contained_at ? tms(a.contained_at) : null],
  ];
  const fill = el("i", "fill"); host.append(fill);
  let lastDone = -1;
  P.forEach(([name, desc, t], i) => {
    const li = el("li", "ph");
    const done = t != null, skipped = !done && i === 3 && a && a.contained_at;
    if (done) { li.classList.add(i === 4 ? "win" : "done"); lastDone = i; }
    if (skipped) li.classList.add("skip");
    li.append(el("span", "node", done && i === 4 ? "✓" : i + 1), el("b", null, name), el("span", null, skipped ? "Skipped · went straight to intercept" : desc), el("em", null, done ? fmtRel(t - t0) : skipped ? "—" : "waiting"));
    host.append(li);
  });
  const nowIdx = a && !a.contained_at ? Math.min(4, lastDone + 1) : -1;
  if (nowIdx >= 0) host.children[nowIdx + 1].classList.add("now");
  requestAnimationFrame(() => { fill.style.width = (lastDone <= 0 ? 0 : (lastDone / 4) * 80) + "%"; });
  const badge = $("engage-badge");
  badge.textContent = !a ? "No engagement" : a.contained_at ? `Intercepted in ${fmtDur(tms(a.contained_at) - t0)}` : "Engagement live";
  badge.className = "badge " + (!a ? "" : a.contained_at ? "contained" : "hostile");
  $("engage-sub").textContent = a ? `${trackId(a.ip)} · ${a.ip} · from first contact to intercept` : "From first contact to intercept";
}

// ------------------------------------------------------------------ charts
let lastChart = 0;
function tip(e, text, sub) {
  const t = $("tip"); t.replaceChildren(text, el("small", null, sub)); t.hidden = false;
  t.style.left = Math.min(e.clientX + 14, innerWidth - t.offsetWidth - 8) + "px"; t.style.top = (e.clientY - t.offsetHeight - 12) + "px";
}
const untip = () => { $("tip").hidden = true; };
function renderCharts(animate) {
  const a = current(), evs = a ? eventsOf(a.ip) : [];
  const t0 = a ? tms(a.first_seen) : 0;
  let t1 = evs.length ? evs[evs.length - 1]._t : t0; if (a && a.contained_at) t1 = Math.max(t1, tms(a.contained_at));
  const span = Math.max(t1 - t0, 1000);
  $("vol-total").textContent = evs.length.toLocaleString();

  // contact volume: bars with a bright cap, the busiest bin in lime
  { const host = $("vol"), W = host.clientWidth || 300, H = host.clientHeight || 210, N = 12, bins = new Array(N).fill(0);
    for (const e of evs) bins[Math.min(N - 1, Math.floor(((e._t - t0) / span) * N))]++;
    const max = Math.max(1, ...bins), peak = bins.indexOf(Math.max(...bins));
    const svg = S("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none" });
    const defs = S("defs", {}, svg), lg = S("linearGradient", { id: "barGrad", x1: 0, y1: 0, x2: 0, y2: 1 }, defs);
    S("stop", { offset: 0, "stop-color": "#f3f3ee", "stop-opacity": .16 }, lg); S("stop", { offset: 1, "stop-color": "#f3f3ee", "stop-opacity": 0 }, lg);
    const top = 30, bottom = H - 22, bw = (W / N) * 0.62, gap = W / N, gb = S("g", { class: animate ? "bars" : "" }, svg);
    bins.forEach((v, i) => {
      const h = Math.max(2, (v / max) * (bottom - top)), x = i * gap + (gap - bw) / 2, y = bottom - h;
      const r = S("rect", { x, y, width: bw, height: h, rx: 4, class: "bar-bg", style: `animation-delay:${i * 40}ms` }, gb);
      S("rect", { x, y, width: bw, height: 3, rx: 1.5, class: "bar-cap" + (i === peak && v ? " peak" : ""), style: `animation-delay:${i * 40}ms` }, gb);
      const hz = S("rect", { x: i * gap, y: 0, width: gap, height: H, class: "hit-zone" }, svg);
      const from = (span / N) * i, to = (span / N) * (i + 1);
      hz.addEventListener("mousemove", (e) => tip(e, `${v} event${v === 1 ? "" : "s"}`, `${fmtRel(from)} to ${fmtRel(to)}`)); hz.addEventListener("mouseleave", untip);
      void r;
    });
    if (bins[peak]) {
      const x = peak * gap + gap / 2, y = bottom - (bins[peak] / max) * (bottom - top) - 22, txt = `peak ${bins[peak]}`, w = txt.length * 7 + 14;
      const pl = S("g", { class: "pill-lbl" }, svg); S("rect", { x: clamp(x - w / 2, 0, W - w), y, width: w, height: 18, rx: 9 }, pl); S("text", { x: clamp(x, w / 2, W - w / 2), y: y + 12.5, "text-anchor": "middle" }, pl, txt);
    }
    S("text", { x: 0, y: H - 4, class: "ax" }, svg, "+0s"); S("text", { x: W, y: H - 4, class: "ax", "text-anchor": "end" }, svg, fmtRel(span));
    host.replaceChildren(svg);
  }

  // threat corridor: how deep (white) and how loud (lime alerts), with the intercept marked
  { const host = $("corridor"), W = host.clientWidth || 400, H = host.clientHeight || 210, top = 24, bottom = H - 24;
    const svg = S("svg", { viewBox: `0 0 ${W} ${H}` }), X = (t) => ((t - t0) / span) * (W - 8) + 4;
    for (let s = 0; s <= 6; s += 2) { const y = bottom - (s / 6) * (bottom - top); S("line", { x1: 0, x2: W, y1: y, y2: y, stroke: "#242522", "stroke-dasharray": "2 4" }, svg); S("text", { x: 0, y: y - 4, class: "ax" }, svg, s ? `stage ${s}` : ""); }
    const ft = stageTimes(evs), pts = [[X(t0), bottom]]; let prev = 0;
    for (let s = 1; s <= 6; s++) if (ft[s]) { const x = X(ft[s]); pts.push([x - 0.01, bottom - (prev / 6) * (bottom - top)], [x, bottom - (s / 6) * (bottom - top)]); prev = s; }
    pts.push([X(t1), bottom - (prev / 6) * (bottom - top)]);
    const smooth = (P) => P.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
    const als = state.alerts.filter((x) => x.src_ip === (a && a.ip)).map((x) => tms(x.ts)).sort((p, q) => p - q);
    const ap = [[X(t0), bottom]]; als.forEach((t, i) => ap.push([X(t), bottom - ((i + 1) / Math.max(1, als.length)) * (bottom - top) * .9]));
    if (als.length) ap.push([X(t1), ap[ap.length - 1][1]]);
    const l2 = S("path", { d: smooth(ap), class: "ln", stroke: "#d6f24c", opacity: .9 }, svg);
    const l1 = S("path", { d: smooth(pts), class: "ln", stroke: "#f3f3ee" }, svg);
    if (animate && !RM) for (const l of [l1, l2]) { requestAnimationFrame(() => { const len = l.getTotalLength(); l.style.setProperty("--len", len); l.classList.add("draw"); }); }
    for (let s = 1; s <= 6; s++) if (ft[s]) {
      const cx = X(ft[s]), cy = bottom - (s / 6) * (bottom - top);
      const c = S("circle", { cx, cy, r: 4.5, fill: "#060606", stroke: "#f3f3ee", "stroke-width": 2 }, svg);
      c.addEventListener("mousemove", (e) => tip(e, `Stage ${s} · ${STAGES[s - 1].name}`, fmtRel(ft[s] - t0))); c.addEventListener("mouseleave", untip);
    }
    if (a && a.contained_at) {
      const x = X(tms(a.contained_at));
      S("line", { x1: x, x2: x, y1: top - 6, y2: bottom, stroke: "#d6f24c", "stroke-width": 1.5, "stroke-dasharray": "3 3" }, svg);
      const txt = `intercept ${fmtRel(tms(a.contained_at) - t0)}`, w = txt.length * 6.6 + 14, px = clamp(x - w / 2, 0, W - w);
      const pl = S("g", { class: "pill-lbl" }, svg); S("rect", { x: px, y: top - 22, width: w, height: 18, rx: 9 }, pl); S("text", { x: px + w / 2, y: top - 9.5, "text-anchor": "middle" }, pl, txt);
    }
    const lg = S("g", {}, svg);
    S("circle", { cx: W - 150, cy: H - 6, r: 4, fill: "#f3f3ee" }, lg); S("text", { x: W - 142, y: H - 2, class: "ax" }, lg, "depth");
    S("circle", { cx: W - 88, cy: H - 6, r: 4, fill: "#d6f24c" }, lg); S("text", { x: W - 80, y: H - 2, class: "ax" }, lg, "alerts");
    host.replaceChildren(svg);
  }

  // bases under fire: a half gauge split by decoy
  { const host = $("gauge"), W = host.clientWidth || 300, H = host.clientHeight || 210;
    const counts = { admin: 0, ssh: 0, s3: 0 }; for (const e of evs) { const d = DECOY_OF_SOURCE[e.source]; if (d) counts[d]++; }
    const total = counts.admin + counts.ssh + counts.s3, cx = W / 2, cy = H - 44, r = Math.min(W / 2 - 16, H - 70);
    const svg = S("svg", { viewBox: `0 0 ${W} ${H}` });
    const arc = (a0, a1) => { const p = (a) => [cx + Math.cos(a) * r, cy + Math.sin(a) * r], [x0, y0] = p(a0), [x1, y1] = p(a1); return `M${x0} ${y0} A${r} ${r} 0 ${a1 - a0 > Math.PI ? 1 : 0} 1 ${x1} ${y1}`; };
    S("path", { d: arc(Math.PI, Math.PI * 2), fill: "none", stroke: "#242522", "stroke-width": 14, "stroke-linecap": "round" }, svg);
    const COL = { admin: "#f3f3ee", ssh: "#d6f24c", s3: "#8f908a" };
    let a0 = Math.PI;
    for (const d of DECOYS) {
      if (!counts[d]) continue;
      const a1 = a0 + (counts[d] / total) * Math.PI, seg = S("path", { d: arc(a0 + .015, Math.max(a0 + .03, a1 - .015)), fill: "none", stroke: COL[d], "stroke-width": 14, "stroke-linecap": "butt" }, svg);
      if (animate && !RM) { const len = r * (a1 - a0); seg.style.cssText = `stroke-dasharray:${len};stroke-dashoffset:${len};transition:stroke-dashoffset 1.1s cubic-bezier(.22,.9,.25,1)`; requestAnimationFrame(() => requestAnimationFrame(() => { seg.style.strokeDashoffset = 0; })); }
      seg.addEventListener("mousemove", (e) => tip(e, `${BASES[d].name}: ${counts[d]} events`, `${Math.round((counts[d] / total) * 100)}% of this track's activity`)); seg.addEventListener("mouseleave", untip);
      a0 = a1;
    }
    S("text", { x: cx, y: cy - 14, "text-anchor": "middle", fill: "#f3f3ee", style: "font: 500 40px Geist, sans-serif; letter-spacing:-.04em" }, svg, total.toLocaleString());
    S("text", { x: cx, y: cy + 8, "text-anchor": "middle", class: "ax" }, svg, "hostile events");
    host.replaceChildren(svg);
    const legend = el("div", "gauge-legend");
    for (const d of DECOYS) { const sp = el("span"); const i = el("i"); i.style.background = COL[d]; sp.append(i, `${BASES[d].name} ${counts[d]}`); legend.append(sp); }
    host.append(legend);
  }
}

// ------------------------------------------------------------------ alert queue
const counts = {};
function setCount(key, n, labelText) {
  $("n-" + key).textContent = labelText != null ? labelText : n;
  if (counts[key] != null && n > counts[key]) { const tab = $("tab-" + key); if (tab.getAttribute("aria-selected") !== "true") { tab.classList.remove("bump"); void tab.offsetWidth; tab.classList.add("bump"); } }
  counts[key] = n;
}
const seenRows = new Set();
function renderQueue() {
  // alerts
  { const host = $("alerts"), frag = document.createDocumentFragment();
    for (const al of state.alerts.slice(0, MAX_ROWS)) {
      const a = state.attackers.get(al.src_ip), sev = al.severity || "low", key = "a" + (al.id || al.ts + al.title);
      const row = el("div", "row" + (state.booted && !seenRows.has(key) ? " fresh" : "")); seenRows.add(key);
      const what = el("span", "what"); what.append(el("b", null, al.title || "Alert"));
      const v = el("button", "view", "View"); v.type = "button"; v.addEventListener("click", () => { selectTrack(al.src_ip, true); document.getElementById("airspace").scrollIntoView({ behavior: RM ? "auto" : "smooth" }); });
      row.append(el("span", "t", fmtTime(al.ts)), what, el("span", "trkid", trackId(al.src_ip)), el("span", "sev " + sev, sev), el("span", "stat" + (a && a.contained_at ? " ok" : ""), a && a.contained_at ? "Intercepted" : "Open"), v);
      frag.append(row);
    }
    host.replaceChildren(frag); $("alerts-empty").hidden = state.alerts.length > 0; setCount("alerts", state.alerts.length);
  }
  // live feed
  { const host = $("feed"), frag = document.createDocumentFragment(), ev = state.events, n = Math.min(ev.length, MAX_ROWS);
    for (let i = ev.length - 1; i >= ev.length - n; i--) {
      const e = ev[i], d = DECOY_OF_SOURCE[e.source], f = state.fresh.get(e.id);
      const row = el("div", "row feed-row" + (f && performance.now() - f < 1500 ? " fresh" : ""));
      row.append(el("span", "t", fmtTime(e.ts)), el("span", "src", SRC_TAG[d] || String(e.source || "").toUpperCase()), partsInto(el("span", "what"), [[`${trackId(e.src_ip)}  `, 3], ...describe(e)]), el("span", "stg", e.stage ? "S" + e.stage : ""));
      frag.append(row);
    }
    host.replaceChildren(frag); $("feed-empty").hidden = n > 0; setCount("feed", ev.length);
  }
  // stolen baits
  { const host = $("loot"), firstBy = {}; let taken = 0;
    for (const e of state.events) if (e.honeytoken_id && !firstBy[e.honeytoken_id]) firstBy[e.honeytoken_id] = e;
    host.replaceChildren(...STAGES.map((s) => {
      const e = firstBy[s.token], c = el("div", "tok" + (e ? " taken" : "")); if (e) taken++;
      c.append(el("span", "k", `Stage ${s.n} · ${e ? "taken" : "planted"}`), el("b", null, TOKEN_NAME[s.token]), el("span", null, e ? `${trackId(e.src_ip)} · ${e.src_ip} · ${fmtClock(e.ts)}` : `waiting on the ${BASES[s.decoy].name.toLowerCase()}`));
      return c;
    }));
    setCount("loot", taken, `${taken}/6`);
  }
  // ATT&CK
  { const techs = new Map(), tacs = new Map();
    for (const e of state.events) for (const t of e.techniques || []) { techs.set(t, (techs.get(t) || 0) + 1); const tc = TACTIC_OF[t]; if (tc) { if (!tacs.has(tc)) tacs.set(tc, new Set()); tacs.get(tc).add(t); } }
    $("matrix").replaceChildren(...TACTICS.map(([id, name]) => { const ids = tacs.get(id), c = el("div", "tac" + (ids ? " on" : "")); c.append(el("b", null, name), el("span", null, ids ? [...ids].join(" ") : "not seen")); return c; }));
    const list = [...techs.entries()].sort((p, q) => q[1] - p[1]);
    $("techs").replaceChildren(...list.map(([id, n]) => { const t = el("div", "tech"); t.append(el("span", "id", id), el("span", null, ATTACK[id] || "technique"), el("span", "n", "×" + n)); return t; }));
    setCount("attack", list.length);
  }
  // responses
  { const NAME = { containment_sequence: "Intercepted", throttle_connection: "Slowed down", release: "Released" };
    const host = $("resp");
    host.replaceChildren(...state.responses.slice(0, 100).map((r) => {
      const row = el("div", "row resp-row"), d = r.details || {}, acts = d.actions || {};
      const body = el("span", "what"); body.append(el("b", null, `${trackId(r.src_ip)} · ${r.src_ip}`), d.reason ? ` · ${d.reason}` : "");
      const steps = el("div", "steps"), add = (txt, real) => steps.append(el("span", real ? "real" : null, txt));
      if (acts.eviction) { const n = acts.eviction.terminated || 0; add(n ? `kicked ${n} SSH session${n > 1 ? "s" : ""}` : "no live session to kick", n > 0); }
      if (acts.enforcement) { const n = Array.isArray(acts.enforcement) ? acts.enforcement.length : (acts.enforcement.reached || []).length; add(`blocked on ${n} decoy${n === 1 ? "" : "s"}`, n > 0); }
      if (acts.firewall) { const be = acts.firewall.backend || ""; add(`firewall · ${be || "unknown"}`, be && be !== "simulated"); }
      if (acts.snapshot) { const be = acts.snapshot.backend || ""; add(`evidence snapshot · ${be || "unknown"}`, be && be !== "simulated"); }
      if (d.delay_seconds) add(`${d.delay_seconds} s delay per request`, true);
      if (steps.childElementCount) body.append(steps);
      row.append(el("span", "t", fmtTime(r.ts)), el("span", "sev " + (r.action === "containment_sequence" ? "info" : r.action === "release" ? "low" : "medium"), NAME[r.action] || r.action), body);
      return row;
    }));
    $("resp-empty").hidden = state.responses.length > 0; setCount("resp", state.responses.length);
  }
}
function selectTab(btn) {
  for (const t of document.querySelectorAll('#tabs [role="tab"]')) {
    const on = t === btn; t.setAttribute("aria-selected", on); t.tabIndex = on ? 0 : -1; $(t.getAttribute("aria-controls")).hidden = !on;
  }
  moveInk();
}
function moveInk() { const b = document.querySelector('#tabs [aria-selected="true"]'), ink = $("tab-ink"); if (!b) return; ink.style.left = b.offsetLeft + "px"; ink.style.width = b.offsetWidth + "px"; }

// ------------------------------------------------------------------ loop
let lastClock = "", lastQueue = 0, errs = 0;
function frame(now) {
  try {
    drawMap(now);
    for (const [id, t] of state.fresh) if (now - t > 2500) state.fresh.delete(id);
    if (dirty.model) { dirty.model = false; renderHero(); renderKpis(); renderChain(); renderLock(); renderPhases(); }
    if (dirty.queue && now - lastQueue > 300) { dirty.queue = false; lastQueue = now; renderQueue(); }
    if (dirty.charts && now - lastChart > 500) { dirty.charts = false; renderCharts(now - lastChart > 2500); lastChart = now; }
    const c = new Date().toLocaleTimeString([], { hour12: false });
    if (c !== lastClock) { lastClock = c; $("clock").textContent = c; tickLockClock(); }
  } catch (e) { if (errs++ < 5) console.error("render error", e); }
  requestAnimationFrame(frame);
}

// ------------------------------------------------------------------ io
async function control(kind, ip) { try { await fetch(`/api/${kind}/${encodeURIComponent(ip)}`, { method: "POST" }); } catch (e) { console.warn("control failed", e); } }
async function loadInitial() {
  const get = (u) => fetch(u).then((r) => r.json());
  const [events, alerts, responses, attackers] = await Promise.all([get("/api/events?limit=2000"), get("/api/alerts?limit=300"), get("/api/responses?limit=200"), get("/api/attackers")]);
  for (const e of [...events].reverse()) addEvent(e, false);
  for (const a of [...alerts].reverse()) addAlert(a);
  for (const r of [...responses].reverse()) addResponse(r);
  for (const a of [...attackers].sort((p, q) => tms(p.first_seen) - tms(q.first_seen))) upsertAttacker(a);
  for (const [, t] of map.tracks) t.pos = 0;   // tracks fly in from the entry corridor on first paint
}
function setLink(up, text) { $("link-dot").className = "link-dot " + (up ? "up" : "down"); $("link-text").textContent = text; }
let backoff = 500;
function connect() {
  const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/ws`);
  ws.onopen = () => { setLink(true, "Live"); backoff = 500; };
  ws.onclose = () => { setLink(false, "Reconnecting"); setTimeout(connect, backoff); backoff = Math.min(backoff * 2, 8000); };
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
// a controller reset empties the database; reloading is the cleanest way to clear the view
async function watchReset() {
  try { const list = await fetch("/api/attackers").then((r) => r.json()); if (state.attackers.size && !list.length) location.reload(); } catch { /* restarting */ }
}

// ------------------------------------------------------------------ boot
(function boot() {
  buildTerrain(); buildDial(); sizeMap(); bindMap();
  new ResizeObserver(() => { sizeMap(); dirty.charts = true; lastChart = 0; }).observe($("map-wrap"));
  addEventListener("resize", moveInk);
  $("btn-contain").addEventListener("click", () => { const a = current(); if (a) control("contain", a.ip); });
  $("btn-release").addEventListener("click", () => { const a = current(); if (a) control("uncontain", a.ip); });
  const toQueue = () => { selectTab($("tab-alerts")); $("queue").scrollIntoView({ behavior: RM ? "auto" : "smooth" }); };
  $("check-alerts").addEventListener("click", toQueue); $("bell").addEventListener("click", toQueue);
  const tabs = [...document.querySelectorAll('#tabs [role="tab"]')];
  tabs.forEach((t, i) => {
    t.tabIndex = t.getAttribute("aria-selected") === "true" ? 0 : -1;
    t.addEventListener("click", () => selectTab(t));
    t.addEventListener("keydown", (e) => { const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0; if (!d) return; const n = tabs[(i + d + tabs.length) % tabs.length]; selectTab(n); n.focus(); e.preventDefault(); });
  });
  // the rail follows the section in view
  const SECS = ["overview", "airspace", "engagement", "queue"];
  let spyLock = 0;
  const setRail = (id) => document.querySelectorAll(".rail-btn").forEach((b) => b.classList.toggle("on", b.dataset.sec === id));
  const spy = () => {
    if (performance.now() < spyLock) return;
    const root = document.documentElement;
    let cur = SECS[0];
    for (const id of SECS) if ($(id).getBoundingClientRect().top <= innerHeight * 0.35) cur = id;
    if (scrollY < 40) cur = SECS[0];
    else if (innerHeight + scrollY >= root.scrollHeight - 4) cur = SECS[SECS.length - 1];
    setRail(cur);
  };
  addEventListener("scroll", spy, { passive: true });
  document.querySelectorAll(".rail-btn, .rail-logo").forEach((a) => a.addEventListener("click", (e) => {
    e.preventDefault();
    const id = a.dataset.sec || "overview";
    if (id === "overview") scrollTo({ top: 0, behavior: RM ? "auto" : "smooth" });
    else $(id).scrollIntoView({ behavior: RM ? "auto" : "smooth", block: "start" });
    history.replaceState(null, "", "#" + id); setRail(id); spyLock = performance.now() + 900;
  }));
  spy();
  $("guide").addEventListener("click", () => { const on = document.body.classList.toggle("guide"); $("guide").setAttribute("aria-pressed", on); });
  $("takeover").addEventListener("click", closeTakeover);
  if (document.fonts) document.fonts.ready.then(() => { moveInk(); map.cacheKey = ""; dirty.charts = true; });
  setTimeout(moveInk, 300);
  requestAnimationFrame(frame);
  fetch("/api/mode").then((r) => r.json()).then((m) => {
    const observe = m && m.mode === "observe";
    $("mode-chip").textContent = observe ? "Observe only · no intercept" : "Auto-intercept on";
    $("mode-chip").classList.toggle("warn", observe);
  }).catch(() => {});
  loadInitial().catch((e) => console.warn("initial load failed", e)).finally(() => { state.booted = true; dirty.model = dirty.queue = dirty.charts = true; connect(); });
  setInterval(watchReset, 5000);
})();
