"use strict";

/* Mirage deception console.
 *
 * Reads the controller's REST API once for first paint, then applies live
 * deltas from /ws (event, alert, response, attacker). Four views share one
 * state: the narrative sentence, the radial "trap depth" HUD with the intruder
 * card, the campaign replay timeline, and the tabbed detail drawer.
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
  { n: 1, name: "robots.txt", short: "ROBOTS.TXT", decoy: "admin", token: "ht-robots-backup-link" },
  { n: 2, name: "Backup .env", short: "BACKUP .ENV", decoy: "admin", token: "ht-env-backup-file" },
  { n: 3, name: "SSH login", short: "SSH LOGIN", decoy: "ssh", token: "ht-ssh-password" },
  { n: 4, name: "AWS credentials", short: "AWS KEYS", decoy: "ssh", token: "ht-aws-credentials-file" },
  { n: 5, name: "S3 access", short: "S3 ACCESS", decoy: "s3", token: "ht-aws-access-key" },
  { n: 6, name: "passwords.xlsx", short: "PASSWORDS.XLSX", decoy: "s3", token: "ht-passwords-xlsx" },
];
const TOKEN_NAME = {
  "ht-robots-backup-link": "robots.txt breadcrumb", "ht-env-backup-file": "Backup .env file",
  "ht-ssh-password": "SSH password", "ht-aws-credentials-file": "AWS credentials file",
  "ht-aws-access-key": "AWS access key", "ht-passwords-xlsx": "passwords.xlsx",
};
const DECOYS = ["admin", "ssh", "s3"];
const DECOY_OF_SOURCE = { "admin-panel": "admin", ssh: "ssh", s3: "s3" };
const DECOY_IP = { admin: "10.66.0.20", ssh: "10.66.0.21", s3: "10.66.0.22" };
const DECOY_NAME = { admin: "Admin panel", ssh: "SSH server", s3: "S3 bucket" };
const SRC_TAG = { admin: "WEB", ssh: "SSH", s3: "S3" };
const BAND_WORD = { idle: "clear", watch: "watch", tarpit: "slow down", contain: "contained" };

// canvas colours (the CSS tokens, as rgb triples)
const C = {
  hud: [90, 215, 240], amber: [244, 179, 63], red: [255, 77, 69], green: [61, 220, 151],
  fg: [227, 237, 243], dim: [147, 168, 182], faint: [88, 112, 128], edge: [24, 48, 64], edgeHi: [42, 82, 102],
  admin: [183, 156, 255], ssh: [90, 215, 240], s3: [244, 179, 63], bg: [4, 7, 11],
};
const rgba = (c, a) => `rgba(${c[0]},${c[1]},${c[2]},${a})`;
const RM = matchMedia("(prefers-reduced-motion: reduce)").matches;
const FONT_MONO = '"JetBrains Mono", ui-monospace, monospace';
const FONT_DISPLAY = 'Oxanium, "Rajdhani", system-ui, sans-serif';
const FONT_BODY = '"IBM Plex Sans", system-ui, sans-serif';
const MAX_EVENTS = 5000, MAX_FEED = 300;

// ------------------------------------------------------------------ state
const state = {
  attackers: new Map(),   // ip -> attacker row from the controller
  events: [],             // ascending by time, each with a cached _t
  alerts: [], responses: [],
  selected: null,         // ip the operator picked; null = highest risk
  fresh: new Map(),       // event id -> arrival time, for live highlights
  booted: false,          // false while replaying the initial REST load
};
const dirty = { model: true, feed: true, alerts: true, resp: true, theft: true, attack: true, replay: true };
const counts = { feed: -1, theft: -1, attack: -1, alerts: -1, resp: -1 };

// ------------------------------------------------------------------ helpers
const $ = (id) => document.getElementById(id);
function el(tag, cls, text) { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = String(text); return n; }
function tms(ts) { const t = +new Date(ts); return isNaN(t) ? 0 : t; }
const clamp = (v, a = 0, b = 1) => Math.max(a, Math.min(b, v));
const easeOut = (k) => 1 - Math.pow(1 - clamp(k), 3);
function fmtTime(ts) { const d = new Date(ts); if (isNaN(d)) return String(ts || ""); return d.toLocaleTimeString([], { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0"); }
function fmtDur(ms) {
  if (ms == null || isNaN(ms)) return "—";
  if (ms < 1) return "<1 ms";
  if (ms < 1000) return Math.round(ms) + " ms";
  if (ms < 60000) return (ms / 1000).toFixed(2) + " s";
  const m = Math.floor(ms / 60000), s = Math.round((ms % 60000) / 1000);
  return m + "m " + String(s).padStart(2, "0") + "s";
}
function fmtRel(ms) { return "+" + (ms < 60000 ? (Math.max(0, ms) / 1000).toFixed(2) + " s" : fmtDur(ms)); }

function bandOf(a) {
  if (!a) return "idle";
  if (a.contained_at) return "contain";
  const p = a.playbook; if (p === "watch" || p === "tarpit" || p === "contain") return p;
  const r = a.risk_score || 0; return r >= 75 ? "contain" : r >= 40 ? "tarpit" : "watch";
}
function ranked() {
  return [...state.attackers.values()].sort((a, b) =>
    (b.risk_score || 0) - (a.risk_score || 0) || (b.max_stage || 0) - (a.max_stage || 0) || tms(a.first_seen) - tms(b.first_seen));
}
function current() {
  if (state.selected && state.attackers.has(state.selected)) return state.attackers.get(state.selected);
  return ranked()[0] || null;
}
const eventsOf = (ip) => state.events.filter((e) => e.src_ip === ip);
function stageTimes(evs) {
  const ft = {};
  for (const e of evs) { const s = e.stage || 0; if (s && !(s in ft)) ft[s] = e._t; }
  return ft;
}
function containmentOf(ip) { return state.responses.find((r) => r.src_ip === ip && r.action === "containment_sequence") || null; }
/** Which decoys acknowledged the block, read from the containment response. */
function blockedDecoys(a) {
  if (!a || !a.contained_at) return new Set();
  const r = containmentOf(a.ip), enf = r && r.details && r.details.actions && r.details.actions.enforcement;
  if (!enf) return new Set(DECOYS);
  const reached = Array.isArray(enf) ? enf : (enf.reached || []);
  const out = new Set();
  reached.forEach((u, i) => { const d = DECOYS.find((k) => String(u).includes(DECOY_IP[k])); out.add(d || DECOYS[i]); });
  return out;
}
function detectLag(a) {
  if (!a) return NaN;
  const al = state.alerts.filter((x) => x.src_ip === a.ip).sort((x, y) => tms(x.ts) - tms(y.ts))[0];
  if (!al) return NaN;
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
      if (d.user_agent) P.push([` · ${d.user_agent}`, 3]);
      break;
    case "login_attempt":
      t("login as "); b(d.username || e.asset || "?");
      if (d.password != null) t(` · password "${d.password}"`);
      P.push(d.success ? [" · accepted", 2] : [d.contained ? " · refused, contained" : " · failed", 3]);
      break;
    case "command": t("$ "); b(d.command || ""); break;
    case "session_start": t("SSH session opened"); if (d.mode) t(` · ${d.mode}`); break;
    case "session_end": t(`SSH session closed · ${d.commands ?? 0} commands · ${d.duration ?? 0} s`); break;
    case "honeytoken_used": t("used "); b(TOKEN_NAME[e.honeytoken_id] || e.honeytoken_id || "honeytoken"); if (e.asset) t(` on ${e.asset}`); break;
    default: t(String(e.event_type || "event").replace(/_/g, " ") + " "); if (e.asset) b(e.asset);
  }
  return P;
}
function partsInto(node, parts) {
  for (const [text, kind] of parts) {
    if (!kind) node.append(text);
    else node.append(el(kind === 1 ? "b" : "span", kind === 2 ? "ok" : kind === 3 ? "fail" : null, text));
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
    const now = performance.now();
    state.fresh.set(e.id, now);
    const d = DECOY_OF_SOURCE[e.source];
    if (d) { const chip = $("dc-" + d); chip.classList.remove("ping"); void chip.offsetWidth; chip.classList.add("ping"); }
    hudPulse(e.src_ip, e.stage ? C.red : C.hud, now);
  }
  dirty.model = dirty.feed = dirty.replay = dirty.attack = true;
  if (e.honeytoken_id) dirty.theft = true;
}
function addAlert(a) { state.alerts.unshift(a); if (state.alerts.length > 300) state.alerts.length = 300; dirty.alerts = dirty.model = dirty.replay = true; }
function addResponse(r) { state.responses.unshift(r); if (state.responses.length > 200) state.responses.length = 200; dirty.resp = dirty.model = dirty.replay = true; }
function upsertAttacker(a) {
  const prev = state.attackers.get(a.ip);
  state.attackers.set(a.ip, a);
  if (state.booted) {
    if (prev && (a.max_stage || 0) > (prev.max_stage || 0)) onStage(a, prev.max_stage || 0);
    if (a.contained_at && !(prev && prev.contained_at)) onContained(a);
  }
  dirty.model = dirty.replay = dirty.theft = true;
}

// One-off effects for live transitions. They never run during the initial load.
function onStage(a, from) {
  const now = performance.now();
  const b = hudBlip(a.ip);
  for (let k = from + 1; k <= (a.max_stage || 0); k++) b.ringAt[k] = now + (k - from - 1) * 180;
  const cur = current();
  if (cur && cur.ip === a.ip) ledgerFlash.set(a.max_stage || 0, now);
}
function onContained(a) {
  hudBlip(a.ip).shieldAt = performance.now();
  const cur = current();
  if (cur && cur.ip === a.ip) {
    const s = $("stamp"); s.classList.remove("slam"); void s.offsetWidth; s.classList.add("slam");
    if (!RM) { const f = $("flash"); f.classList.remove("go"); void f.offsetWidth; f.classList.add("go"); }
  }
}

// ------------------------------------------------------------------ 1 · the sentence
const say = { key: "", parts: [], start: 0, shown: -1 };
function sentence(a) {
  if (!a) return [["Decoys armed. Nothing has touched the trap yet.", 0]];
  const ip = [a.ip, "ip"], st = a.max_stage || 0;
  if (a.contained_at) {
    const ttc = tms(a.contained_at) - tms(a.first_seen);
    return [ip, [` got ${st} of 6 stages into the trap. `, 0], [`Mirage cut them off ${fmtDur(ttc)} after first contact.`, "ok"]];
  }
  const evs = eventsOf(a.ip), last = evs[evs.length - 1];
  const tail = bandOf(a) === "tarpit" ? [[" Mirage is slowing them down.", "hl"]] : [];
  if (last && last.event_type === "login_attempt" && !(last.details || {}).success && st < 3) {
    const n = evs.filter((e) => e.event_type === "login_attempt" && !(e.details || {}).success).length;
    return [ip, [" is guessing SSH passwords: ", 0], [`${n} failed so far.`, "hl"], ...tail];
  }
  const by = {
    0: [[" is probing the admin panel for hidden pages.", 0]],
    1: [[" took the first bait. ", 0], ["robots.txt pointed them to a hidden /backup/ folder.", "hl"]],
    2: [[" downloaded the fake backup file. ", 0], ["It leaks an SSH password.", "hl"]],
    3: [[" logged in to the SSH decoy ", 0], ["with the leaked password.", "hl"]],
    4: [[" stole the planted ", 0], ["AWS keys", "hl"], [" from ~/.aws/credentials.", 0]],
    5: [[" is using the stolen keys ", 0], ["against the S3 bucket.", "hl"]],
    6: [[" downloaded ", 0], ["passwords.xlsx", "hl"], [", the last bait in the trail.", 0]],
  };
  return [ip, ...(by[st] || by[0]), ...tail];
}
function updateSentence(now) {
  const a = current(), parts = sentence(a), key = parts.map((p) => p[0]).join("");
  if (key !== say.key) { say.key = key; say.parts = parts; say.start = now; say.shown = -1; }
  const total = key.length, n = RM || !state.booted ? total : Math.min(total, Math.floor((now - say.start) * 0.075));
  if (n === say.shown) return;
  say.shown = n;
  const h = $("say"); h.replaceChildren();
  let left = n;
  for (const [text, cls] of say.parts) {
    if (left <= 0) break;
    const piece = text.slice(0, left); left -= piece.length;
    if (cls) h.append(el("span", cls, piece)); else h.append(piece);
  }
  if (n < total) h.append(el("span", "caret"));
}

// ------------------------------------------------------------------ 2 · ledger + intruder card
const ledgerFlash = new Map();   // stage -> when it was reached, so a rebuild resumes the highlight
const riskShown = { v: 0 };
function renderModel() {
  const list = ranked(), a = current(), band = bandOf(a);
  document.body.dataset.band = band;

  // kicker
  const k = $("kicker"); k.replaceChildren();
  k.append(el("span", "live-tag", !a ? "Standby" : a.contained_at ? "Contained" : "Live intrusion"));
  if (a) {
    k.append(el("span", null, `First contact ${fmtTime(a.first_seen)}`), el("span", null, `${a.event_count || 0} events`),
      el("span", null, `${(a.tokens || []).length} of 6 honeytokens`));
    if (list.length > 1) k.append(el("span", null, `${list.length} intruders in the lab`));
  } else k.append(el("span", null, "3 decoys armed · 6-stage breadcrumb trail · watching 10.66.0.0/24"));

  // decoy chips in the bar
  const hits = { admin: 0, ssh: 0, s3: 0 };
  for (const e of state.events) { const d = DECOY_OF_SOURCE[e.source]; if (d) hits[d]++; }
  const anyBlocked = new Set(); for (const x of list) for (const d of blockedDecoys(x)) anyBlocked.add(d);
  for (const d of DECOYS) {
    const chip = $("dc-" + d), blocked = anyBlocked.has(d);
    chip.classList.toggle("hit", hits[d] > 0 && !blocked); chip.classList.toggle("blocked", blocked);
    $("dcs-" + d).textContent = blocked ? "blocking" : hits[d] ? `${hits[d]} events` : "armed";
  }

  // ledger
  const evs = a ? eventsOf(a.ip) : [], ft = stageTimes(evs), st = a ? (a.max_stage || 0) : 0, t0 = a ? tms(a.first_seen) : 0;
  const led = $("ledger"); led.replaceChildren();
  for (const s of STAGES) {
    const li = el("li");
    const reached = a && s.n <= st, cur = a && s.n === st && !a.contained_at;
    if (reached && !cur) li.classList.add("done"); if (cur) li.classList.add("cur");
    if (a && a.contained_at && s.n > st) li.classList.add("never");
    const lit = ledgerFlash.get(s.n), age = performance.now() - lit;
    if (lit && age < 1200) { li.classList.add("lit"); li.style.animationDelay = -age + "ms"; }
    const time = !a ? "waiting" : reached ? (ft[s.n] ? fmtRel(ft[s.n] - t0) : "reached") : a.contained_at ? "never" : "—";
    li.append(el("span", "n", s.n), el("span", "nm", s.name), el("span", "dc", `${DECOY_NAME[s.decoy]} · .${DECOY_IP[s.decoy].split(".")[3]}`), el("span", "tm", time));
    led.append(li);
    if (a && a.contained_at && s.n === st && st < 6) led.append(el("li", "gate", "BLOCKED HERE"));
  }
  $("hud-meta").textContent = !a ? "outer ring = first bait · centre = crown jewel" : `${a.ip} · stage ${st} of 6${a.contained_at ? " · contained" : ""}`;

  // picker
  const pk = $("picker"); pk.hidden = list.length < 2;
  if (a && list.length > 1) $("pick-n").textContent = `${list.findIndex((x) => x.ip === a.ip) + 1}/${list.length}`;

  // identity + stamp
  $("int-ip").textContent = a ? a.ip : "—.—.—.—";
  const stamp = $("stamp"), slam = stamp.classList.contains("slam");
  stamp.className = "stamp " + band + (slam ? " slam" : "");
  stamp.textContent = !a ? "No contact" : a.contained_at ? "Contained" : band === "tarpit" ? "Slowing down" : "Watching";
  $("int-seen").textContent = a ? `First seen ${fmtTime(a.first_seen)} · ${a.playbook || "watch"} playbook` : "Waiting for first contact";
  riskShown.target = a ? (a.risk_score || 0) : 0; riskShown.painted = false;
  $("risk-word").textContent = BAND_WORD[band];
  $("risk-word").style.color = band === "contain" ? "var(--green)" : band === "tarpit" ? "var(--amber)" : band === "watch" ? "var(--hud)" : "";

  // facts
  const ttc = a && a.contained_at ? tms(a.contained_at) - t0 : null;
  $("f-ttd").textContent = fmtDur(detectLag(a));
  $("f-ttc").textContent = ttc != null ? fmtDur(ttc) : a ? "not yet" : "—";
  $("f-ttc").classList.toggle("hot", ttc != null);
  $("f-events").textContent = a ? (a.event_count || evs.length) : 0;
  const ft2 = $("f-tokens"); ft2.replaceChildren(String(a ? (a.tokens || []).length : 0), el("small", null, "/6"));

  const blocked = blockedDecoys(a);
  for (const d of DECOYS) $("enf-" + d).classList.toggle("on", blocked.has(d));
  $("btn-contain").disabled = !a || !!a.contained_at;
  $("btn-release").disabled = !a || !a.contained_at;
}
function renderRisk() {
  const tgt = riskShown.target || 0;
  if (riskShown.v === tgt && riskShown.painted) return;
  const v = RM || Math.abs(tgt - riskShown.v) < 0.5 ? tgt : riskShown.v + (tgt - riskShown.v) * 0.12;
  riskShown.v = v; riskShown.painted = v === tgt;
  const r = Math.round(v);
  $("risk-n").textContent = r;
  $("risk-n").style.color = r >= 75 ? "var(--red)" : r >= 40 ? "var(--amber)" : r > 0 ? "var(--hud)" : "";
  const segs = $("risk-segs").children;
  for (let i = 0; i < 20; i++) segs[i].classList.toggle("on", r > i * 5);
}

// ------------------------------------------------------------------ 2 · HUD canvas
const hud = { cv: null, g: null, W: 0, H: 0, cx: 0, cy: 0, R: 100, blips: new Map(), last: 0 };
const RING = [0.965, 0.855, 0.735, 0.615, 0.495, 0.375, 0.255];   // stage 0 (perimeter) .. 6
const CORE = 0.13;
const ringR = (k) => hud.R * RING[clamp(k, 0, 6)];
function hashUnit(s) { let h = 2166136261; for (const ch of String(s)) { h ^= ch.charCodeAt(0); h = Math.imul(h, 16777619); } return (h >>> 0) / 4294967296; }
/** Each intruder enters from the left or right flank and spirals inward a little per stage. */
function hudBlip(ip) {
  let b = hud.blips.get(ip);
  if (!b) {
    const u = hashUnit(ip), deg = u < 0.5 ? 150 + u * 2 * 40 : 330 + (u - 0.5) * 2 * 40;
    b = { base: deg * Math.PI / 180, r: null, ang: null, pulses: [], ringAt: {}, shieldAt: 0 };
    hud.blips.set(ip, b);
  }
  return b;
}
const STEP_ANG = 0.21;
function hudPulse(ip, col, now) { if (RM || !ip) return; const b = hudBlip(ip); b.pulses.push({ born: now, col }); if (b.pulses.length > 8) b.pulses.shift(); }
function sizeHud() {
  const wrap = $("hud-wrap"), cv = $("hud"), dpr = Math.min(devicePixelRatio || 1, 2);
  hud.cv = cv; hud.g = cv.getContext("2d");
  hud.W = wrap.clientWidth; hud.H = wrap.clientHeight;
  cv.width = Math.round(hud.W * dpr); cv.height = Math.round(hud.H * dpr);
  hud.g.setTransform(dpr, 0, 0, dpr, 0, 0);
  hud.cx = hud.W / 2; hud.cy = hud.H / 2; hud.R = Math.max(60, Math.min(hud.W, hud.H) / 2 - 10);
}
function polar(ang, r) { return [hud.cx + Math.cos(ang) * r, hud.cy + Math.sin(ang) * r]; }
function textBox(g, text, x, y, col, align, size, font) {
  g.font = `${font || "600"} ${size}px ${FONT_MONO}`;
  const w = g.measureText(text).width;
  const x0 = clamp(align === "center" ? x - w / 2 : align === "right" ? x - w : x, 6, hud.W - w - 6);   // never off the canvas
  g.fillStyle = "rgba(4,7,11,.82)"; g.fillRect(x0 - 4, y - size * 0.75, w + 8, size * 1.35);
  g.fillStyle = col; g.textAlign = "left"; g.textBaseline = "alphabetic"; g.fillText(text, x0, y + size * 0.3);
}
function drawHud(now) {
  const g = hud.g; if (!g) return;
  const dt = hud.last ? Math.min(0.1, (now - hud.last) / 1000) : 0; hud.last = now;
  const { W, H, cx, cy, R } = hud, sel = current();
  const selStage = sel ? (sel.max_stage || 0) : -1;
  g.clearRect(0, 0, W, H);
  const fs = clamp(R * 0.04, 10, 13);

  // glow
  let gr = g.createRadialGradient(cx, cy, 0, cx, cy, R);
  gr.addColorStop(0, "rgba(90,215,240,.10)"); gr.addColorStop(0.6, "rgba(90,215,240,.03)"); gr.addColorStop(1, "rgba(90,215,240,0)");
  g.fillStyle = gr; g.fillRect(0, 0, W, H);

  // decoy bands: rings 1-2 live on the admin panel, 3-4 on SSH, 5-6 on S3
  const mid = (a, b) => (ringR(a) + ringR(b)) / 2;
  const bands = [["admin", mid(0, 1), mid(2, 3)], ["ssh", mid(2, 3), mid(4, 5)], ["s3", mid(4, 5), (ringR(6) + R * CORE) / 2]];
  for (const [d, ro, ri] of bands) {
    g.beginPath(); g.arc(cx, cy, ro, 0, Math.PI * 2); g.arc(cx, cy, ri, 0, Math.PI * 2, true);
    g.fillStyle = rgba(C[d], 0.035); g.fill();
    g.strokeStyle = rgba(C[d], 0.12); g.lineWidth = 1; g.beginPath(); g.arc(cx, cy, ro, 0, Math.PI * 2); g.stroke();
  }

  // crosshair with ticks
  g.strokeStyle = rgba(C.edgeHi, 0.55); g.lineWidth = 1;
  g.beginPath(); g.moveTo(cx - R, cy); g.lineTo(cx + R, cy); g.moveTo(cx, cy - R); g.lineTo(cx, cy + R); g.stroke();

  // perimeter: slowly turning tick ring
  const rot = RM ? 0 : now * 0.00004;
  const pr = ringR(0);
  for (let i = 0; i < 120; i++) {
    const a = rot + i * Math.PI / 60, long = i % 10 === 0, r1 = pr - (long ? 9 : 4);
    g.strokeStyle = rgba(C.hud, long ? 0.6 : 0.22); g.lineWidth = long ? 1.4 : 1;
    g.beginPath(); g.moveTo(...polar(a, r1)); g.lineTo(...polar(a, pr)); g.stroke();
  }
  g.strokeStyle = rgba(C.hud, 0.35); g.setLineDash([2, 7]); g.lineDashOffset = RM ? 0 : -now * 0.004;
  g.beginPath(); g.arc(cx, cy, pr + 6, 0, Math.PI * 2); g.stroke(); g.setLineDash([]);

  // radar sweep, clipped to the perimeter
  if (!RM && g.createConicGradient) {
    const sa = (now * 0.0009) % (Math.PI * 2);
    const cg = g.createConicGradient(sa - 0.9, cx, cy);
    cg.addColorStop(0, "rgba(90,215,240,0)"); cg.addColorStop(0.14, "rgba(90,215,240,.10)"); cg.addColorStop(0.1433, "rgba(90,215,240,.35)"); cg.addColorStop(0.145, "rgba(90,215,240,0)"); cg.addColorStop(1, "rgba(90,215,240,0)");
    g.fillStyle = cg; g.beginPath(); g.arc(cx, cy, pr - 10, 0, Math.PI * 2); g.fill();
  }

  // stage rings for the selected intruder: amber = walked, red = where they are now
  const pulse = RM ? 1 : 0.6 + 0.4 * Math.sin(now / 280);
  for (let k = 1; k <= 6; k++) {
    const r = ringR(k), reached = k <= selStage, cur = k === selStage && sel && !sel.contained_at;
    const b = sel ? hud.blips.get(sel.ip) : null, at = b && b.ringAt[k];
    const drawing = at && now - at < 1000 && !RM;
    g.lineWidth = cur ? 2.5 : reached ? 1.6 : 1;
    g.strokeStyle = cur ? rgba(C.red, 0.55 + 0.45 * pulse) : reached && !drawing ? rgba(C.amber, 0.75) : rgba(C.edgeHi, 0.9);
    g.beginPath(); g.arc(cx, cy, r, 0, Math.PI * 2); g.stroke();
    if (drawing && now >= at) {
      const p = easeOut((now - at) / 900), a0 = -Math.PI / 2;
      g.strokeStyle = rgba(C.amber, 1); g.lineWidth = 3; g.shadowColor = rgba(C.amber, 0.9); g.shadowBlur = 14;
      g.beginPath(); g.arc(cx, cy, r, a0, a0 + p * Math.PI * 2); g.stroke(); g.shadowBlur = 0;
      const [hx, hy] = polar(a0 + p * Math.PI * 2, r); g.fillStyle = "#fff"; g.beginPath(); g.arc(hx, hy, 3, 0, Math.PI * 2); g.fill();
    }
  }

  // crown jewel
  const jr = R * CORE * 0.62, breached = [...state.attackers.values()].some((x) => (x.max_stage || 0) >= 6);
  g.save(); g.translate(cx, cy); g.rotate(Math.PI / 4);
  g.fillStyle = breached ? rgba(C.red, 0.25 + 0.2 * pulse) : rgba(C.hud, 0.08); g.fillRect(-jr, -jr, jr * 2, jr * 2);
  g.strokeStyle = breached ? rgba(C.red, 1) : rgba(C.hud, 0.8); g.lineWidth = 1.5; g.strokeRect(-jr, -jr, jr * 2, jr * 2);
  g.strokeStyle = rgba(C.hud, 0.35); g.strokeRect(-jr * 0.55, -jr * 0.55, jr * 1.1, jr * 1.1);
  g.restore();
  g.textAlign = "center"; g.font = `600 ${fs - 1}px ${FONT_MONO}`; g.fillStyle = breached ? rgba(C.red, 1) : rgba(C.fg, 0.85);
  g.fillText("CROWN JEWEL", cx, cy + R * CORE + fs + 4);

  // paths, shields, blips
  const ips = ranked().map((x) => x.ip);
  for (const ip of [...ips].reverse()) {
    const a = state.attackers.get(ip), b = hudBlip(ip), isSel = sel && sel.ip === ip;
    const st = a.max_stage || 0, contained = !!a.contained_at;
    const tAng = b.base + st * STEP_ANG, tR = ringR(st);
    if (b.r == null || RM) { b.r = tR; b.ang = tAng; }
    const kk = 1 - Math.exp(-dt * 3.2); b.r += (tR - b.r) * kk; b.ang += (tAng - b.ang) * kk;
    const alpha = isSel ? 1 : 0.45;

    // walked path: a spiral through every stage reached so far
    g.strokeStyle = rgba(C.amber, 0.65 * alpha); g.lineWidth = isSel ? 2 : 1.2; g.setLineDash([5, 5]); g.lineDashOffset = RM ? 0 : -now * 0.01;
    g.beginPath();
    let first = true;
    for (let s = 0; s < st; s++) {
      for (let i = 0; i <= 14; i++) {
        const u = i / 14, ang = b.base + (s + u) * STEP_ANG, r = ringR(s) + (ringR(s + 1) - ringR(s)) * u;
        const [x, y] = polar(ang, r);
        if (r < b.r - 0.5) break;
        if (first) { g.moveTo(x, y); first = false; } else g.lineTo(x, y);
      }
    }
    if (!first) { g.lineTo(...polar(b.ang, b.r)); g.stroke(); }
    g.setLineDash([]);
    for (let s = 1; s <= st; s++) {
      const [x, y] = polar(b.base + s * STEP_ANG, ringR(s));
      if (ringR(s) < b.r - 0.5) continue;
      g.fillStyle = rgba(C.amber, alpha); g.save(); g.translate(x, y); g.rotate(Math.PI / 4); g.fillRect(-3, -3, 6, 6); g.restore();
    }

    // shield: a green ring closing just inside the intruder, between them and the next bait
    if (contained) {
      const sr = st >= 6 ? R * CORE * 1.15 : (ringR(st) + ringR(st + 1)) / 2;
      const p = RM || !b.shieldAt ? 1 : easeOut((now - b.shieldAt) / 1100);
      g.strokeStyle = rgba(C.green, 0.95 * alpha); g.lineWidth = isSel ? 4 : 2; g.shadowColor = rgba(C.green, 0.8); g.shadowBlur = isSel ? 16 : 6;
      g.beginPath(); g.arc(cx, cy, sr, b.ang - p * Math.PI, b.ang + p * Math.PI); g.stroke(); g.shadowBlur = 0;
      if (p >= 1) {
        g.strokeStyle = rgba(C.green, 0.4 * alpha); g.lineWidth = 1; g.setLineDash([3, 6]); g.lineDashOffset = RM ? 0 : now * 0.008;
        g.beginPath(); g.arc(cx, cy, sr - 7, 0, Math.PI * 2); g.stroke(); g.setLineDash([]);
      }
      if (isSel && p > 0.6) {
        const [lx, ly] = polar(b.ang + Math.PI, sr);
        textBox(g, "SHIELD UP", lx, ly, rgba(C.green, clamp((p - 0.6) * 2.5)), "center", fs);
      }
    }

    // event pulses
    const [bx, by] = polar(b.ang, b.r);
    b.pulses = b.pulses.filter((q) => now - q.born < 1000);
    for (const q of b.pulses) { const t = (now - q.born) / 1000; g.strokeStyle = rgba(q.col, (1 - t) * 0.9 * alpha); g.lineWidth = 2; g.beginPath(); g.arc(bx, by, 8 + t * 34, 0, Math.PI * 2); g.stroke(); }

    // tarpit halo
    if (!contained && bandOf(a) === "tarpit") {
      g.strokeStyle = rgba(C.amber, 0.85 * alpha); g.lineWidth = 1.5; g.setLineDash([4, 4]); g.lineDashOffset = RM ? 0 : now * 0.02;
      g.beginPath(); g.arc(bx, by, 17, 0, Math.PI * 2); g.stroke(); g.setLineDash([]);
    }

    // the blip itself
    if (contained) {
      g.fillStyle = rgba(C.bg, 1); g.strokeStyle = rgba(C.red, 0.9 * alpha); g.lineWidth = 2;
      g.beginPath(); g.arc(bx, by, isSel ? 8 : 6, 0, Math.PI * 2); g.fill(); g.stroke();
      g.strokeStyle = rgba(C.red, alpha); g.beginPath(); g.moveTo(bx - 4, by - 4); g.lineTo(bx + 4, by + 4); g.moveTo(bx + 4, by - 4); g.lineTo(bx - 4, by + 4); g.stroke();
    } else {
      gr = g.createRadialGradient(bx, by, 0, bx, by, 26); gr.addColorStop(0, rgba(C.red, 0.55 * alpha)); gr.addColorStop(1, rgba(C.red, 0));
      g.fillStyle = gr; g.beginPath(); g.arc(bx, by, 26, 0, Math.PI * 2); g.fill();
      g.fillStyle = rgba(C.red, alpha); g.beginPath(); g.arc(bx, by, isSel ? 7 : 5, 0, Math.PI * 2); g.fill();
      g.fillStyle = "#fff"; g.beginPath(); g.arc(bx, by, 2.2, 0, Math.PI * 2); g.fill();
    }
    // label on the outside of the blip, with a leader line
    const out = polar(b.ang, b.r + 26), right = Math.cos(b.ang) >= 0;
    g.strokeStyle = rgba(C.red, 0.6 * alpha); g.lineWidth = 1; g.beginPath(); g.moveTo(...polar(b.ang, b.r + 10)); g.lineTo(...out); g.lineTo(out[0] + (right ? 12 : -12), out[1]); g.stroke();
    textBox(g, ip, out[0] + (right ? 16 : -16), out[1], rgba(contained ? C.dim : C.red, alpha), right ? "left" : "right", fs + 1);
  }

  // ring labels along the top, decoy band labels along the bottom
  for (let k = 1; k <= 6; k++) {
    const reached = k <= selStage;
    textBox(g, `${k} ${STAGES[k - 1].short}`, cx, cy - ringR(k) + 1, reached ? rgba(C.amber, 1) : rgba(C.dim, 0.8), "center", fs - 1, reached ? "600" : "500");
  }
  for (const [d, ro, ri] of bands) textBox(g, `${DECOY_NAME[d].toUpperCase()} .${DECOY_IP[d].split(".")[3]}`, cx, cy + (ro + ri) / 2 + 2, rgba(C[d], 0.85), "center", fs - 1, "500");
  textBox(g, "PERIMETER", cx, cy + ringR(0) - 14, rgba(C.hud, 0.7), "center", fs - 1, "500");
}

// ------------------------------------------------------------------ 3 · campaign replay
const rp = { cv: null, g: null, W: 0, H: 0, span: 0, hits: [], lastDraw: 0 };
const LANES = [["admin", "Admin panel", "10.66.0.20"], ["ssh", "SSH server", "10.66.0.21"], ["s3", "S3 bucket", "10.66.0.22"], ["ctrl", "Mirage", "response"]];
function sizeReplay() {
  const wrap = $("replay-wrap"), cv = $("replay"), dpr = Math.min(devicePixelRatio || 1, 2);
  rp.cv = cv; rp.g = cv.getContext("2d"); rp.W = wrap.clientWidth; rp.H = wrap.clientHeight;
  cv.width = Math.round(rp.W * dpr); cv.height = Math.round(rp.H * dpr); rp.g.setTransform(dpr, 0, 0, dpr, 0, 0);
  dirty.replay = true;
}
function niceStep(spanMs, target) {
  const steps = [50, 100, 200, 500, 1000, 2000, 5000, 10000, 15000, 30000, 60000, 120000, 300000, 600000, 1800000, 3600000];
  return steps.find((s) => spanMs / s <= target) || steps[steps.length - 1];
}
function drawReplay(now) {
  const g = rp.g; if (!g) return;
  const { W, H } = rp, a = current();
  g.clearRect(0, 0, W, H); rp.hits = [];
  $("replay-empty").hidden = !!a;
  if (!a) return;
  const narrow = W < 640, L = narrow ? 92 : 150, Rm = 18, T = 40, laneH = narrow ? 40 : 46, depthH = narrow ? 52 : 62;
  const pw = W - L - Rm, lanesTop = T, depthTop = T + laneH * 4 + 10, axisY = depthTop + depthH + 16;
  const evs = eventsOf(a.ip), alerts = state.alerts.filter((x) => x.src_ip === a.ip), resps = state.responses.filter((x) => x.src_ip === a.ip);
  const t0 = Math.min(tms(a.first_seen) || Infinity, evs.length ? evs[0]._t : Infinity);
  let t1 = evs.length ? evs[evs.length - 1]._t : t0;
  if (a.contained_at) t1 = Math.max(t1, tms(a.contained_at));
  for (const x of alerts) t1 = Math.max(t1, tms(x.ts));
  for (const x of resps) t1 = Math.max(t1, tms(x.ts));
  const target = Math.max(t1 - t0, 1500) * 1.08;
  rp.span = !rp.span || RM ? target : rp.span + (target - rp.span) * 0.18;
  if (Math.abs(rp.span - target) > target * 0.002) dirty.replay = true;
  const span = rp.span, x = (t) => L + ((t - t0) / span) * pw;
  const laneY = (i) => lanesTop + laneH * i + laneH / 2;
  const fs = narrow ? 11 : 12;

  // lanes
  for (let i = 0; i < 4; i++) {
    g.fillStyle = i % 2 ? "rgba(11,24,35,.55)" : "rgba(8,18,27,.85)"; g.fillRect(0, lanesTop + laneH * i, W, laneH);
    const [key, name, sub] = LANES[i], col = key === "ctrl" ? C.green : C[key];
    g.fillStyle = rgba(col, 1); g.fillRect(0, lanesTop + laneH * i + 8, 2, laneH - 16);
    g.textAlign = "left"; g.textBaseline = "alphabetic";
    g.font = `600 ${narrow ? 12 : 14}px ${FONT_BODY}`; g.fillStyle = rgba(C.fg, 1); g.fillText(name, 12, laneY(i) - 1);
    g.font = `${fs - 1}px ${FONT_MONO}`; g.fillStyle = rgba(C.faint, 1); g.fillText(sub, 12, laneY(i) + 14);
    g.strokeStyle = rgba(C.edge, 1); g.beginPath(); g.moveTo(L, laneY(i)); g.lineTo(L + pw, laneY(i)); g.stroke();
  }
  // depth track
  g.fillStyle = "rgba(8,18,27,.85)"; g.fillRect(0, depthTop, W, depthH);
  g.font = `600 ${narrow ? 12 : 14}px ${FONT_BODY}`; g.fillStyle = rgba(C.fg, 1); g.fillText("Trail depth", 12, depthTop + depthH / 2 - 1);
  g.font = `${fs - 1}px ${FONT_MONO}`; g.fillStyle = rgba(C.faint, 1); g.fillText("stage 0–6", 12, depthTop + depthH / 2 + 14);
  const dy = (s) => depthTop + depthH - 6 - (s / 6) * (depthH - 12);
  for (let s = 0; s <= 6; s += 2) { g.strokeStyle = rgba(C.edge, s ? 0.8 : 1); g.beginPath(); g.moveTo(L, dy(s)); g.lineTo(L + pw, dy(s)); g.stroke(); }

  // time grid
  const step = niceStep(span, narrow ? 4 : 9);
  g.font = `${fs - 1}px ${FONT_MONO}`; g.textAlign = "center"; g.fillStyle = rgba(C.faint, 1);
  for (let t = 0; t <= span; t += step) {
    const xx = x(t0 + t);
    g.strokeStyle = "rgba(42,82,102,.22)"; g.beginPath(); g.moveTo(xx, lanesTop); g.lineTo(xx, depthTop + depthH); g.stroke();
    g.fillText(step < 1000 ? `+${(t / 1000).toFixed(1)}s` : step < 60000 ? `+${Math.round(t / 1000)}s` : `+${Math.round(t / 60000)}m`, xx, axisY);
  }

  // containment: hatch every decoy lane from the cut onward
  const cAt = a.contained_at ? tms(a.contained_at) : 0;
  if (cAt) {
    const xc = x(cAt);
    g.save(); g.beginPath(); g.rect(xc, lanesTop, L + pw - xc, laneH * 3); g.clip();
    g.fillStyle = "rgba(61,220,151,.05)"; g.fillRect(xc, lanesTop, L + pw - xc, laneH * 3);
    g.strokeStyle = "rgba(61,220,151,.22)"; g.lineWidth = 1.5;
    for (let k = -laneH * 3; k < L + pw - xc + laneH * 3; k += 9) { g.beginPath(); g.moveTo(xc + k, lanesTop + laneH * 3); g.lineTo(xc + k + laneH * 3, lanesTop); g.stroke(); }
    g.restore();
    if (L + pw - xc > 80) { g.textAlign = "center"; g.font = `700 ${fs}px ${FONT_DISPLAY}`; g.fillStyle = rgba(C.green, 0.9); g.fillText("B L O C K E D", (xc + L + pw) / 2, laneY(1) + 4); }
  }

  // events: one tick each, brighter while fresh; stage first-touches get a diamond and a label
  const lastLabel = {};
  const ft = stageTimes(evs);
  for (const e of evs) {
    const d = DECOY_OF_SOURCE[e.source]; if (!d) continue;
    const i = DECOYS.indexOf(d), xx = x(e._t), yy = laneY(i), fr = state.fresh.get(e.id), age = fr ? (now - fr) / 900 : 1;
    const hot = age < 1;
    g.strokeStyle = rgba(C[d], hot ? 1 : 0.5); g.lineWidth = hot ? 2 : 1.2;
    const hh = hot ? 10 + (1 - age) * 8 : 8;
    g.beginPath(); g.moveTo(xx, yy - hh); g.lineTo(xx, yy + hh); g.stroke();
    if (hot) { g.fillStyle = rgba(C[d], 0.25 * (1 - age)); g.fillRect(xx - 8, yy - hh, 16, hh * 2); dirty.replay = true; }
    rp.hits.push({ x: xx, y: yy, kind: "event", e });
  }
  for (const s of STAGES) {
    const t = ft[s.n]; if (!t) continue;
    const i = DECOYS.indexOf(s.decoy), xx = x(t), yy = laneY(i);
    g.fillStyle = rgba(C.amber, 1); g.save(); g.translate(xx, yy); g.rotate(Math.PI / 4); g.fillRect(-5, -5, 10, 10); g.restore();
    g.strokeStyle = rgba(C.bg, 1); g.lineWidth = 1; g.save(); g.translate(xx, yy); g.rotate(Math.PI / 4); g.strokeRect(-5, -5, 10, 10); g.restore();
    const se = evs.find((e) => e._t === t && e.stage === s.n);
    if (se) rp.hits.push({ x: xx, y: yy, kind: "event", e: se, prio: true });
    const label = narrow ? `S${s.n}` : `S${s.n} ${s.name}`;
    g.font = `600 ${fs}px ${FONT_BODY}`; const w = g.measureText(label).width;
    const lx = Math.min(xx - w / 2, L + pw - w);
    const row = lastLabel[i] != null && lx < lastLabel[i] + 6 ? 1 : 0;
    const ly = row ? yy + 22 : yy - 12;
    g.fillStyle = "rgba(4,7,11,.8)"; g.fillRect(lx - 3, ly - fs + 1, w + 6, fs + 4);
    g.fillStyle = rgba(C.amber, 1); g.textAlign = "left"; g.fillText(label, lx, ly + 1);
    if (!row) lastLabel[i] = lx + w;
  }

  // Mirage lane: alerts and responses
  const yM = laneY(3);
  for (const al of alerts) {
    const xx = x(tms(al.ts)), sev = al.severity, col = sev === "critical" || sev === "high" ? C.red : sev === "medium" ? C.amber : C.dim;
    g.fillStyle = rgba(col, 0.95); g.beginPath(); g.moveTo(xx, yM - 13); g.lineTo(xx + 5, yM - 4); g.lineTo(xx - 5, yM - 4); g.closePath(); g.fill();
    rp.hits.push({ x: xx, y: yM - 8, kind: "alert", al });
  }
  // a response label is drawn only where it fits before the next marker
  const marks = [...resps].reverse().map((r) => ({ r, xx: x(tms(r.ts)) }));
  let respLabelEnd = -Infinity;
  marks.forEach(({ r, xx }, i) => {
    const isC = r.action === "containment_sequence", isR = r.action === "release";
    g.fillStyle = rgba(isC ? C.green : isR ? C.hud : C.amber, 1); g.fillRect(xx - 5, yM + 2, 10, 10);
    const label = isC ? "CONTAIN" : isR ? "RELEASE" : "SLOW DOWN";
    g.font = `700 ${fs - 1}px ${FONT_DISPLAY}`; const w = g.measureText(label).width;
    const limit = Math.min(L + pw, i + 1 < marks.length ? marks[i + 1].xx - 8 : Infinity);
    if (xx + 9 > respLabelEnd && xx + 9 + w < limit) { g.textAlign = "left"; g.fillText(label, xx + 9, yM + 11); respLabelEnd = xx + 9 + w + 8; }
    rp.hits.push({ x: xx, y: yM + 7, kind: "resp", r });
  });

  // trail depth step line
  const pts = [[t0, 0]]; for (const s of STAGES) if (ft[s.n]) pts.push([ft[s.n], s.n]);
  const tEnd = cAt || (evs.length ? evs[evs.length - 1]._t : t0);
  g.beginPath(); g.moveTo(x(t0), dy(0));
  let prev = 0; for (const [t, s] of pts) { g.lineTo(x(t), dy(prev)); g.lineTo(x(t), dy(s)); prev = s; }
  g.lineTo(x(tEnd), dy(prev));
  g.strokeStyle = rgba(C.amber, 1); g.lineWidth = 2; g.stroke();
  g.lineTo(x(tEnd), dy(0)); g.closePath(); g.fillStyle = rgba(C.amber, 0.12); g.fill();
  if (cAt) { g.strokeStyle = rgba(C.green, 0.9); g.lineWidth = 2; g.setLineDash([4, 4]); g.beginPath(); g.moveTo(x(cAt), dy(prev)); g.lineTo(L + pw, dy(prev)); g.stroke(); g.setLineDash([]); }
  g.textAlign = "right"; g.font = `600 ${fs}px ${FONT_DISPLAY}`; g.fillStyle = rgba(C.amber, 1);
  g.fillText(`stage ${prev}`, L + pw - 4, dy(prev) - 5);

  // T0 and the containment cut
  g.strokeStyle = rgba(C.hud, 0.7); g.setLineDash([2, 3]); g.lineWidth = 1;
  g.beginPath(); g.moveTo(x(t0), 22); g.lineTo(x(t0), depthTop + depthH); g.stroke(); g.setLineDash([]);
  const lag = detectLag(a);
  g.textAlign = "left"; g.font = `600 ${fs}px ${FONT_MONO}`; g.fillStyle = rgba(C.hud, 1);
  g.fillText(narrow ? "T0" : `T0 first contact${isNaN(lag) ? "" : ` · detected in ${fmtDur(lag)}`}`, x(t0) + 6, 18);
  if (cAt) {
    const xc = x(cAt);
    g.strokeStyle = rgba(C.green, 1); g.lineWidth = 2; g.shadowColor = rgba(C.green, 0.8); g.shadowBlur = 10;
    g.beginPath(); g.moveTo(xc, 26); g.lineTo(xc, depthTop + depthH); g.stroke(); g.shadowBlur = 0;
    const label = `CONTAINED ${fmtRel(cAt - t0)}`;
    g.font = `700 ${fs + 1}px ${FONT_DISPLAY}`; const w = g.measureText(label).width;
    const right = xc + w + 8 > L + pw; g.textAlign = right ? "right" : "left"; g.fillStyle = rgba(C.green, 1);
    g.fillText(label, xc + (right ? -8 : 8), 34);
  }
}
function replayHover(ev) {
  const tip = $("tip"), r = rp.cv.getBoundingClientRect(), mx = ev.clientX - r.left, my = ev.clientY - r.top;
  let best = null, bd = 12;
  for (const h of rp.hits) { const d = Math.hypot(h.x - mx, (h.y - my) * 0.6) - (h.prio ? 6 : 0); if (d < bd) { bd = d; best = h; } }
  if (!best) { tip.hidden = true; return; }
  const a = current(), t0 = a ? tms(a.first_seen) : 0;
  tip.replaceChildren();
  if (best.kind === "event") {
    const e = best.e, d = DECOY_OF_SOURCE[e.source];
    tip.append(el("b", null, `${DECOY_NAME[d] || e.source}${e.stage ? ` · stage ${e.stage}` : ""}`), partsInto(el("span"), describe(e)), el("em", null, `${fmtTime(e.ts)} · ${fmtRel(e._t - t0)}`));
  } else if (best.kind === "alert") {
    const al = best.al;
    tip.append(el("b", null, `Alert · ${al.severity || "low"}`), el("span", null, al.title || "alert"), el("em", null, `${fmtTime(al.ts)} · ${fmtRel(tms(al.ts) - t0)}`));
  } else {
    const x = best.r, d = x.details || {};
    tip.append(el("b", null, x.action === "containment_sequence" ? "Mirage · contained" : x.action === "release" ? "Mirage · released" : "Mirage · slowing down"), el("span", null, d.reason || x.playbook || ""), el("em", null, `${fmtTime(x.ts)} · ${fmtRel(tms(x.ts) - t0)}`));
  }
  tip.hidden = false;
  const tw = tip.offsetWidth, th = tip.offsetHeight;
  tip.style.left = clamp(best.x - tw / 2, 4, rp.W - tw - 4) + "px";
  tip.style.top = (best.y - th - 14 < 0 ? best.y + 16 : best.y - th - 14) + "px";
}

// ------------------------------------------------------------------ 4 · drawer
function setCount(key, n, label) {
  const b = $("n-" + key); b.textContent = label != null ? label : n;
  if (counts[key] !== -1 && n > counts[key]) { const tab = $("tab-" + key); if (tab.getAttribute("aria-selected") !== "true") { tab.classList.remove("bump"); void tab.offsetWidth; tab.classList.add("bump"); } }
  counts[key] = n;
}
function renderFeed() {
  const host = $("feed"), frag = document.createDocumentFragment(), ev = state.events, n = Math.min(ev.length, MAX_FEED);
  for (let i = ev.length - 1; i >= ev.length - n; i--) {
    const e = ev[i], d = DECOY_OF_SOURCE[e.source], st = e.stage || 0;
    const row = el("div", "row" + (st ? " stage" : "") + (state.fresh.has(e.id) && performance.now() - state.fresh.get(e.id) < 1500 ? " fresh" : ""));
    row.append(el("span", "t", fmtTime(e.ts)), el("span", "src s-" + (d || "ctrl"), SRC_TAG[d] || String(e.source || "").toUpperCase()), partsInto(el("span", "what"), [[`${e.src_ip}  `, 3], ...describe(e)]), el("span", "sx", st ? "S" + st : ""));
    frag.append(row);
  }
  host.replaceChildren(frag);
  $("feed-empty").hidden = n > 0;
  setCount("feed", ev.length);
}
function renderTheft() {
  const host = $("theft"), frag = document.createDocumentFragment(), firstBy = {};
  for (const e of state.events) if (e.honeytoken_id && !firstBy[e.honeytoken_id]) firstBy[e.honeytoken_id] = e;
  let taken = 0;
  for (const s of STAGES) {
    const e = firstBy[s.token], card = el("div", "token" + (e ? " taken" : ""));
    if (e) taken++;
    card.append(el("span", "st", `Stage ${s.n} · ${e ? "taken" : "planted"}`), el("span", "nm", TOKEN_NAME[s.token]),
      el("span", "where", e ? `${e.src_ip} · ${fmtTime(e.ts)} · ${DECOY_NAME[s.decoy]}` : `waiting on the ${DECOY_NAME[s.decoy].toLowerCase()}`));
    frag.append(card);
  }
  host.replaceChildren(frag);
  $("theft-empty").hidden = true;
  setCount("theft", taken, `${taken}/6`);
}
function renderAttack() {
  const techs = new Map(), tacs = new Map();
  for (const e of state.events) for (const t of e.techniques || []) { techs.set(t, (techs.get(t) || 0) + 1); const tc = TACTIC_OF[t]; if (tc) (tacs.get(tc) || tacs.set(tc, new Set()).get(tc)).add(t); }
  const m = $("matrix"), frag = document.createDocumentFragment();
  for (const [id, name] of TACTICS) {
    const ids = tacs.get(id), c = el("div", "tac" + (ids ? " on" : ""));
    c.append(el("span", "tn", name), el("span", "ti", ids ? [...ids].join(" ") : "not seen"));
    frag.append(c);
  }
  m.replaceChildren(frag);
  const list = [...techs.entries()].sort((a, b) => b[1] - a[1]), max = list.length ? list[0][1] : 1, f2 = document.createDocumentFragment();
  for (const [id, n] of list) { const t = el("div", "tech"); t.style.setProperty("--w", Math.round((n / max) * 100) + "%"); t.append(el("span", "id", id), el("span", "nm", ATTACK[id] || "technique"), el("span", "n", "×" + n)); f2.append(t); }
  $("techs").replaceChildren(f2);
  setCount("attack", list.length);
}
function renderAlerts() {
  const host = $("alerts"), frag = document.createDocumentFragment();
  for (const a of state.alerts.slice(0, 150)) {
    const row = el("div", "row sev-" + (a.severity || "low"));
    const body = el("span", "what"); body.append(el("b", null, a.title || "alert"), ` · ${a.src_ip}${a.stage ? " · stage " + a.stage : ""}`);
    row.append(el("span", "t", fmtTime(a.ts)), el("span", "src", String(a.severity || "low").toUpperCase().slice(0, 4)), body, el("span", "sx", a.stage ? "S" + a.stage : ""));
    frag.append(row);
  }
  host.replaceChildren(frag);
  $("alerts-empty").hidden = state.alerts.length > 0;
  setCount("alerts", state.alerts.length);
}
const ACTION_NAME = { containment_sequence: "Contained", throttle_connection: "Slowing down", release: "Released" };
function renderResponses() {
  const host = $("resp"), frag = document.createDocumentFragment();
  for (const r of state.responses.slice(0, 100)) {
    const row = el("div", "row"), d = r.details || {}, acts = d.actions || {};
    const body = el("span", "what"); body.append(el("b", null, ACTION_NAME[r.action] || String(r.action || "").replace(/_/g, " ")), ` · ${r.src_ip}${d.reason ? " · " + d.reason : ""}`);
    const steps = el("div", "steps"), add = (txt, kind) => steps.append(el("span", kind, txt));
    if (acts.eviction) { const n = acts.eviction.terminated || 0; add(n ? `evicted ${n} SSH session${n > 1 ? "s" : ""}` : "no live session to evict", n ? "real" : ""); }
    if (acts.enforcement) { const n = Array.isArray(acts.enforcement) ? acts.enforcement.length : (acts.enforcement.reached || []).length; add(`blocked on ${n} decoy${n === 1 ? "" : "s"}`, n ? "real" : ""); }
    if (acts.firewall) { const be = acts.firewall.backend || (typeof acts.firewall === "string" ? acts.firewall : ""); add(`firewall · ${be || "unknown"}`, be && be !== "simulated" ? "real" : "sim"); }
    if (acts.snapshot) { const be = acts.snapshot.backend || ""; add(`evidence snapshot · ${be || "unknown"}`, be && be !== "simulated" ? "real" : "sim"); }
    if (d.delay_seconds) add(`${d.delay_seconds} s delay per request`, "real");
    if (steps.childElementCount) body.append(steps);
    const tag = r.action === "containment_sequence" ? "s-ctrl" : r.action === "release" ? "s-ssh" : "s-s3";
    row.append(el("span", "t", fmtTime(r.ts)), el("span", "src " + tag, r.action === "containment_sequence" ? "CUT" : r.action === "release" ? "FREE" : "SLOW"), body, el("span", "sx"));
    frag.append(row);
  }
  host.replaceChildren(frag);
  $("resp-empty").hidden = state.responses.length > 0;
  setCount("resp", state.responses.length);
}
function selectTab(btn) {
  for (const t of document.querySelectorAll('[role="tab"]')) {
    const on = t === btn; t.setAttribute("aria-selected", on); t.tabIndex = on ? 0 : -1;
    $(t.getAttribute("aria-controls")).hidden = !on;
  }
}

// ------------------------------------------------------------------ loop
let lastClock = "", errCount = 0, lastFeed = 0;
function flush(now) {
  for (const [id, t] of state.fresh) if (now - t > 2000) state.fresh.delete(id);
  if (dirty.model) { dirty.model = false; renderModel(); }
  // the feed can take thousands of rows during a scan; repaint it at most 4x a second
  if (dirty.feed && now - lastFeed > 250) { dirty.feed = false; lastFeed = now; renderFeed(); }
  if (dirty.alerts) { dirty.alerts = false; renderAlerts(); }
  if (dirty.resp) { dirty.resp = false; renderResponses(); }
  if (dirty.theft) { dirty.theft = false; renderTheft(); }
  if (dirty.attack) { dirty.attack = false; renderAttack(); }
  const c = new Date().toLocaleTimeString([], { hour12: false }); if (c !== lastClock) { lastClock = c; $("clock").textContent = c; }
}
function tick(now) {
  try {
    drawHud(now);
    if (dirty.replay && now - rp.lastDraw > 30) { dirty.replay = false; rp.lastDraw = now; drawReplay(now); }
    flush(now); updateSentence(now); renderRisk();
  } catch (e) { if (errCount++ < 5) console.error("render error", e); }
  requestAnimationFrame(tick);
}
// rAF pauses in a hidden tab; keep the DOM current so the page is right when it comes back
setInterval(() => { if (document.hidden) { try { flush(performance.now()); } catch (e) { if (errCount++ < 5) console.error("render error", e); } } }, 1000);

// ------------------------------------------------------------------ io
async function control(kind, ip) {
  try { await fetch(`/api/${kind}/${encodeURIComponent(ip)}`, { method: "POST" }); }
  catch (e) { console.warn("control failed", e); }
}
async function loadInitial() {
  const get = (u) => fetch(u).then((r) => r.json());
  const [events, alerts, responses, attackers] = await Promise.all([
    get("/api/events?limit=2000"), get("/api/alerts?limit=300"), get("/api/responses?limit=200"), get("/api/attackers"),
  ]);
  for (const e of [...events].reverse()) addEvent(e, false);
  for (const a of [...alerts].reverse()) addAlert(a);
  for (const r of [...responses].reverse()) addResponse(r);
  for (const a of attackers) upsertAttacker(a);
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
// A reset on the controller empties the database; a full reload is the simplest way to clear the view.
async function watchReset() {
  try {
    const list = await fetch("/api/attackers").then((r) => r.json());
    if (state.attackers.size && !list.length) location.reload();
  } catch { /* controller restarting; the socket handles it */ }
}

// ------------------------------------------------------------------ boot
(function boot() {
  const segs = $("risk-segs");
  for (let i = 0; i < 20; i++) { const s = el("i", i < 8 ? "w" : i < 15 ? "t" : "c"); segs.append(s); }
  $("btn-contain").addEventListener("click", () => { const a = current(); if (a) control("contain", a.ip); });
  $("btn-release").addEventListener("click", () => { const a = current(); if (a) control("uncontain", a.ip); });
  const step = (d) => { const list = ranked(); if (list.length < 2) return; const a = current(); const i = list.findIndex((x) => x.ip === a.ip); state.selected = list[(i + d + list.length) % list.length].ip; dirty.model = dirty.replay = true; };
  $("pick-prev").addEventListener("click", () => step(-1));
  $("pick-next").addEventListener("click", () => step(1));
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  tabs.forEach((t, i) => {
    t.tabIndex = t.getAttribute("aria-selected") === "true" ? 0 : -1;
    t.addEventListener("click", () => selectTab(t));
    t.addEventListener("keydown", (e) => {
      const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0; if (!d) return;
      const n = tabs[(i + d + tabs.length) % tabs.length]; selectTab(n); n.focus(); e.preventDefault();
    });
  });
  sizeHud(); sizeReplay();
  new ResizeObserver(sizeHud).observe($("hud-wrap"));
  new ResizeObserver(sizeReplay).observe($("replay-wrap"));
  $("replay").addEventListener("mousemove", replayHover);
  $("replay").addEventListener("mouseleave", () => { $("tip").hidden = true; });
  if (document.fonts) document.fonts.ready.then(() => { dirty.replay = true; });
  requestAnimationFrame(tick);
  loadInitial().catch((e) => console.warn("initial load failed", e)).finally(() => { state.booted = true; dirty.model = dirty.replay = true; connect(); });
  setInterval(watchReset, 5000);
})();
