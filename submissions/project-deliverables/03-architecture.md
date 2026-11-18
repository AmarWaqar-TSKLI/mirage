# Mirage: Project Architecture

**Group 5** · M Amar Waqar (23L-3035) · Hussain Nawaz (23L-3018) · Haseeb Ahmad (23L-3069)

## 1. Overview

Mirage is a cyber deception and active response platform. It fills a network with fake systems and fake secrets that no legitimate user has a reason to touch, so any touch is treated as an attacker. Every touch is reported to one controller, which raises an alert, labels it with MITRE ATT&CK techniques, keeps a threat score for each attacker and, past a threshold, contains the attacker automatically.

The system is one pipeline:

```
   Decoys  --events-->  Detection  --score-->  Response  --live-->  Dashboard
 (3 fake services)      (controller)          (playbooks)          (web page)
```

Everything runs as Docker containers on one isolated network. Nothing in the lab can reach the internet, and the only thing exposed on the host is the dashboard on `127.0.0.1:8000`.

## 2. Network layout

```
  host browser  --->  127.0.0.1:8000  (dashboard, host side only)
                            |
  ==================== lab network 10.66.0.0/24 : internal, no internet ====================

    ATTACKER                 DECOYS                            MIRAGE
  +----------------+       +-------------------------+       +------------------------+
  | attacker       |       | admin panel  .20  :80   |------>| controller  .10  :8000 |
  | 10.66.0.50     |------>| SSH server   .21  :22   |------>|   detect, score        |
  | (+ .52 to .58) | attack| S3 storage   .22  :9000 |------>|   respond, dashboard   |
  +----------------+       +-------------------------+ events+------------------------+
                                        ^                                |
                                        +------ block / tarpit / clear --+

    NORMAL USERS             REAL SERVICE
  +----------------+       +-------------------------+
  | benign  .51    |------>| legit  .30  :80         |   never a decoy: measures false alarms
  +----------------+       +-------------------------+
```

| Container | Address | Purpose |
|---|---|---|
| controller | 10.66.0.10 (+ mgmt) | Ingests events, stores state, scores, responds, serves the dashboard |
| admin-panel | 10.66.0.20 :80, control :8020 | Decoy fake admin website |
| ssh | 10.66.0.21 :22, control :8022 | Decoy fake deploy server |
| s3 | 10.66.0.22 :9000, control :8090 | Decoy fake S3-compatible storage |
| legit | 10.66.0.30 :80 | Real (non-decoy) staff website |
| attacker | 10.66.0.50 | Attack tools: nmap, gobuster, hydra, curl, ssh, AWS CLI, and `op` |
| benign | 10.66.0.51 | Generates normal-user traffic against the real site |

The controller is the only container on the `mgmt` network as well, which is how the host reaches the dashboard.

## 3. Components

### 3.1 Shared package: `common/mirage_common/`
Installed into every service, so all parts speak the same language.

| Module | Role |
|---|---|
| `events.py` | The single `Event` model every decoy sends: source, type, source IP, asset, honeytoken ID, suggested ATT&CK techniques, details |
| `client.py` | `EventClient`: sends events in a background thread pool and never raises, so a decoy keeps working if the controller is down |
| `trail.py` | The six breadcrumb trail stages, in order |
| `honeytokens.py` | The registry of planted items: ID, stage, where it was planted, and its generated value |
| `enforce.py` | Per-decoy containment state: which IPs are blocked or tarpitted, with expiry |
| `control.py` | A small token-protected control server each decoy runs, so the controller can push block / tarpit / clear |
| `reveal.py` | The screen a contained intruder is shown |

### 3.2 Decoys: `decoys/`

**Admin panel** (`admin-panel`, FastAPI). A fake "Halcyon Freight Operations Console" login page. Every login fails and is recorded. `robots.txt` lists `Disallow: /backup/` (bait 1), and `/backup/.env.bak` leaks the SSH deploy password (bait 2). It disguises itself as nginx, including nginx-style error pages.

**SSH server** (`ssh`, Paramiko). Announces itself as `OpenSSH_9.6p1 Ubuntu` and accepts only the leaked password (bait 3). Behind the login is a scripted shell of about 45 commands with pipes, redirects and variables over a realistic fake filesystem. That filesystem holds `~/.aws/credentials` (bait 4) and a `.bash_history` pointing at the storage server. Every command is classified to ATT&CK techniques and every session is recorded to disk as evidence. The shell takes an optional fallback hook for unknown commands, which is where the planned AI layer plugs in.

**S3 storage** (`s3`, FastAPI). A from-scratch S3-compatible service with real AWS Signature V4 checking, so the standard AWS CLI works against it. It accepts only the planted AWS keys (bait 5) and holds the bucket `corp-backups`, which contains filler archives and the bait spreadsheet `finance/passwords.xlsx` (bait 6).

### 3.3 Controller: `controller/app/`

| Module | Role |
|---|---|
| `main.py` | FastAPI app: event ingestion, REST reads, manual controls, the WebSocket, the lab lockdown middleware |
| `store.py` | SQLite storage for events, alerts, attackers and responses; every access is locked |
| `engine.py` | Processes each event: trail stage, labels, alerts, attacker profile, risk score, playbook |
| `labels.py` | Maps honeytoken kinds and event types to ATT&CK techniques and MITRE Engage activities |
| `risk.py` | The threat score and the playbook it selects |
| `response_engine.py` | Runs the tarpit and the containment sequence |
| `decoy_control.py` | Pushes block / tarpit / clear to every decoy's control server |
| `evict.py` | Asks the SSH decoy to end an attacker's live sessions |
| `firewall.py` | Host firewall ban through nftables or iptables, with a simulated fallback |
| `forensics.py` | Container snapshot as evidence through `docker commit`, with a simulated fallback |
| `playbooks.py` | Defender allowlist and policy timings |
| `broadcast.py` | Pushes live deltas to dashboard clients over the WebSocket |
| `static/` | The dashboard: one HTML page, one stylesheet, one script, no build step |

### 3.4 Evaluation and demo tools: `eval/`, `demo`

| Item | Role |
|---|---|
| `eval/Dockerfile.attacker` | The attacker and benign image with every tool baked in (the lab has no internet) |
| `eval/campaign.sh` | The scripted attack that walks the whole trail with real tools |
| `eval/benign.sh` | Normal-user traffic, aimed only at the real staff website |
| `eval/run.sh` | Runs N measured campaigns in `active` or `observe` mode |
| `eval/metrics.py` | Computes time to detect, time to contain, false-positive rate, ATT&CK coverage and stage reached from the controller's records |
| `eval/op.sh` | `op`: the narrated attack console used in live demos, plus `op watch`, an uplink monitor |
| `demo` | Stage helper: start, reset, switch modes, run several attackers, isolate them |

## 4. How an attack flows through the system

**Step 1: a decoy reports.** Any request, login, command or file read becomes an `Event` posted to `POST /api/events` with the shared `X-Mirage-Token` header. Decoys report *what happened*; they make no decisions.

**Step 2: the controller understands it.** For each event the engine:
1. stores it;
2. looks up its honeytoken, if any, and the trail stage that token belongs to;
3. labels it with ATT&CK techniques and Engage activities;
4. updates the attacker's profile: furthest stage reached (it only ever rises), techniques, honeytokens taken, event count;
5. raises an alert on first contact from an address and the first time that address touches each honeytoken (repeats are stored but not re-alerted, so a scanner cannot flood the screen);
6. recomputes the threat score and selects the playbook.

**Step 3: the threat score.** Scored 0–100 by `risk.py`:

| Part | Points |
|---|---|
| Furthest trail stage | 0, 10, 25, 45, 65, 85, 100 for stages 0–6 |
| Distinct ATT&CK techniques | 5 each, at most 25 |
| Distinct honeytokens taken | 5 each, at most 20 |
| Activity volume | 1 per 5 events, at most 10 |

The total is capped at 100.

**Step 4: the response.**

| Score | Playbook | What happens |
|---|---|---|
| 0–39 | Watch | Record everything, intervene in nothing |
| 40–74 | Tarpit | Every decoy delays each request or command from that address by 3 s |
| 75–100 | Contain | The containment sequence below runs once |

The containment sequence:
1. **Evict.** Live SSH sessions from the address are ended.
2. **Block on every decoy.** The controller pushes a block to all three decoys' control servers. From then on, the admin panel and S3 answer `403`, and the SSH server refuses even the correct password. Each decoy shows the intruder the reveal screen. This is the step that actually locks the attacker out.
3. **Firewall ban.** The address is banned with nftables or iptables for one hour where the controller can do so; otherwise the ban is recorded as simulated.
4. **Evidence snapshot.** The SSH decoy container is committed as an evidence image where Docker is reachable; otherwise the snapshot is recorded as simulated.
5. **Record and broadcast.** The response and every step's outcome are stored and pushed to the dashboard.

Addresses on the defender allowlist (the gateway and the controller itself) are never throttled or contained. An operator can also contain or release any address by hand from the dashboard.

**Step 5: the dashboard shows it.** The page loads the current state over REST, then applies live deltas (`event`, `alert`, `attacker`, `response`) from the WebSocket. It shows a plain-language headline, the six-bait attack chain, a tactical map where each attacker is a tracked target moving between decoys, a target panel with the threat score and the Contain and Release buttons, an engagement timeline, charts, and a tabbed evidence queue: alerts, live feed, stolen baits, ATT&CK matrix and responses.

## 5. The breadcrumb trail

| Stage | Bait | Where it lives | What it gives the attacker |
|---|---|---|---|
| 1 | `robots.txt` entry | Admin panel | A hint that `/backup/` exists |
| 2 | `/backup/.env.bak` | Admin panel | The SSH deploy password |
| 3 | SSH login | SSH server | A shell on the "deploy box" |
| 4 | `~/.aws/credentials` | SSH server | An AWS access key pair |
| 5 | Using the AWS keys | S3 storage | Access to bucket `corp-backups` |
| 6 | `finance/passwords.xlsx` | S3 storage | The bait spreadsheet: the crown jewel |

Every bait is unique to the deployment, generated by `tools/gen_honeytokens.py` into a git-ignored file. An alert therefore says exactly which item was taken and how deep the attacker got.

## 6. Security controls inside Mirage itself

| Control | Why it is needed |
|---|---|
| Shared ingest token on `POST /api/events` | The attacker shares the lab network with the controller and could otherwise forge or flood events |
| Lab lockdown | Requests from `10.66.0.0/24` may only reach `/health` and `POST /api/events`; everything else returns `404`, and the WebSocket closes. The attacker cannot read its own profile or release itself |
| Dashboard bound to `127.0.0.1` | Only the host can open the dashboard and the controls |
| Defender allowlist | Mirage can never lock out the gateway or itself |
| Safe rendering | Every attacker-controlled string (user agents, passwords, commands, paths) is drawn as text, never as HTML |
| No secrets in git | Fake keys are generated per deployment into an ignored file; GitHub push protection rejects even fake AWS-format keys |
| Isolated lab | `internal` Docker network with no internet route; Mirage never acts outside the decoys it owns |

## 7. Technology

| Layer | Technology |
|---|---|
| Lab | Docker, Docker Compose, one internal bridge network |
| Controller and API | Python 3.12, FastAPI, SQLite, WebSockets |
| Admin panel and S3 decoys | Python, FastAPI; S3 implements AWS Signature V4 |
| SSH decoy | Python, Paramiko, scripted shell over a virtual filesystem |
| Containment | Decoy-level enforcement, plus nftables/iptables where available |
| Dashboard | One HTML page, plain JavaScript, Canvas and SVG, no build step |
| Attack tools | nmap, gobuster, hydra, curl, OpenSSH, sshpass, AWS CLI |
| Tests | pytest, 86 tests |

## 8. Repository layout

```
common/mirage_common/   shared event model, client, trail, honeytokens, enforcement, reveal
config/                 honeytoken registry template (values generated locally)
controller/             FastAPI controller and the dashboard (controller/app/static)
decoys/admin-panel/     fake admin website (baits 1–2)
decoys/ssh/             fake SSH deploy server (baits 3–4)
decoys/s3/              fake S3 storage and bait spreadsheet (baits 5–6)
eval/                   attacker image, campaign, benign traffic, metrics, op console
tools/                  honeytoken generator
docs/                   progress, plan, requirements, event format, evaluation, demo playbook
demo                    stage helper for running the lab and live demos
docker-compose.yml      the lab
```
