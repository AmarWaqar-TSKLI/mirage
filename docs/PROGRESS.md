# Mirage: Progress and Remaining Work

Last updated: 4 November 2026. All work is on the `dev` branch.

The build is split into 8 steps that follow the pipeline **Decoys → Detection → Response → Dashboard**.
Steps 1–6 are done and tested. Steps 7–8 and the optional LLM layer are still to do.

| # | Step | Status |
|---|---|---|
| 1 | Skeleton: event format, controller, isolated lab network | ✅ Done |
| 2 | Controller core: storage, trail stages, ATT&CK/Engage labels, alerts | ✅ Done |
| 3 | Admin panel decoy and honeytokens (robots.txt → .env leak) | ✅ Done |
| 4 | SSH decoy: scripted shell, session recording | ✅ Done |
| 5 | Fake S3 endpoint and `passwords.xlsx` bait | ✅ Done |
| 6 | Risk score, response playbooks, nftables containment | ✅ Done (containment reach fixed in step 7) |
| 7 | Live dashboard | ✅ Done |
| 8 | Evaluation: attacker container, attack script, benign traffic, metrics | ✅ Done (needs a live `docker compose` run to execute) |
| + | LLM layer for the SSH shell (optional) | ⬜ Deferred |

---

## What is done

### Step 1: Skeleton
- **Shared package** `common/mirage_common/`, installed by every service:
  - `events.py`: the single `Event` model every decoy sends. See [event-format.md](event-format.md).
  - `trail.py`: the six breadcrumb trail stages, in order.
  - `honeytokens.py`: loads the registry of planted items and generates their fake secret values.
  - `client.py`: `EventClient`. `submit()` sends events in the background and never raises, so a decoy keeps working even if the controller is down.
- **Lab network** (`docker-compose.yml`):
  - `lab` (10.66.0.0/24) is `internal`, so no container on it can reach the internet.
  - `mgmt` is joined only by the controller, so its API is reachable from the host on `127.0.0.1:8000`.
- **Ingest authentication:** decoys must send the shared `X-Mirage-Token` header. The attacker shares the lab network with the controller, so unsigned events are rejected with 401.

| Container | Lab IP |
|---|---|
| controller | 10.66.0.10 |
| admin-panel | 10.66.0.20 |
| ssh | 10.66.0.21 |
| s3 (to do) | 10.66.0.22 |
| attacker (to do) | 10.66.0.50 |

### Step 2: Controller core (`controller/`)
- **Storage:** SQLite tables for `events`, `alerts` and `attackers` (`store.py`). The data lives on the `controller-data` volume.
- **Trail stage:** each event's `honeytoken_id` is looked up in the registry to get its stage. An attacker's `max_stage` only ever goes up.
- **Labels** (`labels.py`): a fixed mapping from honeytoken kind or event type to ATT&CK technique IDs and MITRE Engage activities. Techniques suggested by a decoy are merged in.
- **Alerts** (`engine.py`): one alert on first contact from an address, and one the first time an address touches each honeytoken. Repeats are stored as events only, so a scanner making thousands of requests does not flood the dashboard. Severity rises with the stage: medium → high → critical.
- **API:**
  - `POST /api/events` (needs the token)
  - `GET /api/events?limit=&ip=`
  - `GET /api/alerts?limit=&ip=`
  - `GET /api/attackers`
  - `GET /api/attackers/{ip}`
  - `GET /health`

### Step 3: Admin panel decoy (`decoys/admin-panel/`)
- A fake "Halcyon Freight Operations Console" login page. Every login fails, and the submitted username and password are recorded.
- `robots.txt` lists `Disallow: /backup/` (honeytoken, stage 1).
- `/backup/` shows an nginx-style directory listing with `.env.bak`.
- `/backup/.env.bak` leaks `DEPLOY_HOST`, `DEPLOY_USER` and `DEPLOY_PASSWORD` for the SSH decoy (honeytoken, stage 2).
- Every request is reported, with method, status code, query and user agent.
- The panel disguises itself as nginx: it sends an nginx `Server` header, all framework errors (404, 405, `/docs`) look like plain nginx 404 pages, and FastAPI's docs are disabled.
- `tools/gen_honeytokens.py` generates the fake SSH password and an AWS-format key pair. The committed `config/honeytokens.json` is only a template with IDs, stages and locations. The values go to `config/honeytokens.local.json`, which is git-ignored, so every deployment gets unique secrets. Re-run it to rotate them.

### Step 4: SSH decoy (`decoys/ssh/`)
- **Server** (`server.py`, Paramiko):
  - It announces itself as `OpenSSH_9.6p1 Ubuntu`, and its host key stays the same across restarts.
  - It accepts only the leaked password (honeytoken, stage 3). Every login attempt is reported, failed ones included, which catches hydra brute force.
  - Interactive shells and `ssh host 'cmd'` both work.
  - Port forwarding is refused.
  - Sessions close the way sshd does.
- **Fake filesystem** (`fs.py`): a realistic Ubuntu deploy box. It holds `~/.aws/credentials` (honeytoken, stage 4) and a `~/.bash_history` that points to the S3 bucket at `10.66.0.22:9000`. Each session gets its own copy, so files an attacker creates or deletes persist for that session only.
- **Scripted shell** (`shell.py`): about 45 commands (`ls`, `cd`, `cat`, `grep`, `ps`, `ip`, `ss`, `id`, `uname`, `history`, `sudo`, `wget`, `curl`, …). It supports pipes, `;`, `&&`, `||`, `>`/`>>` and `$VARS`. Network and sudo commands fail the way they would on a real box with no internet.
- **Command classifier** (`classify.py`): labels each command with ATT&CK techniques (discovery, credential access, tool transfer, persistence, defence evasion and others).
- **Evidence:** every session is saved as JSON lines in `/data/sessions/<session_id>.jsonl` on the `ssh-data` volume.
- **LLM-ready:** `Shell` takes an optional `fallback` hook for commands it does not know. Without one, unknown commands get bash's normal `command not found`. The whole pipeline works with no LLM.

### Step 5: Fake S3 endpoint (`decoys/s3/`, trail stages 5–6)
- **S3 service** (`main.py`, `storage.py`, `auth.py`):
  - Emulates an S3-compatible storage service listening at `10.66.0.22:9000` with bucket `corp-backups`.
  - Supports standard AWS SigV4 authentication (`Authorization: AWS4-HMAC-SHA256 ...`) and presigned query authentication.
  - Accepts the planted AWS key pair (`ht-aws-access-key`, stage 5) leaked in `~/.aws/credentials`.
  - Generates realistic XML responses for `ListBuckets` (`GET /`) and `ListObjectsV2` (`GET /corp-backups`).
  - Holds filler archives (`releases/ops-console-v3.8.2.tar.gz`, `db/staging-dump-20261101.sql.gz`) and the bait spreadsheet.
- **Bait spreadsheet** (`bait.py`):
  - `finance/passwords.xlsx` generated with realistic corporate finance & banking credentials (stage 6).
- **Telemetry reporting** (`reporting.py`):
  - Any successful request with the planted AWS key reports `honeytoken_used` (`ht-aws-access-key`, T1078.004).
  - Downloading `finance/passwords.xlsx` reports `file_access` (`ht-passwords-xlsx`, T1530).
  - Requests with wrong/missing credentials report `login_attempt` with `success: false`.

### Step 6: Risk scoring, playbooks, containment (`controller/app/`)
- **Dynamic risk scoring** (`risk.py`):
  - Normalized 0–100 score computed from trail stage progress, unique ATT&CK techniques, breached honeytokens, and event velocity.
  - Automatically classifies attackers into graded response tiers: **Watch** (0–39), **Tarpit** (40–74), and **Contain** (75–100).
- **Defender protection** (`playbooks.py`):
  - Configurable IP allowlist (`127.0.0.1`, `10.66.0.1`, `10.66.0.10`, subnet ranges) that protects defender/admin machines from ever being throttled or banned.
- **SSH decoy session control** (`decoys/ssh/app/control.py`, `evict.py`):
  - Authenticated HTTP control endpoint (`:8022`) on the SSH decoy for listing live sessions and immediately evicting intruders with a security banner notice.
- **Firewall containment driver** (`firewall.py`):
  - Adds real-time network drops via `nftables` or `iptables` with configurable ban durations and simulation fallback.
- **Forensic snapshot capture** (`forensics.py`):
  - Triggers automated container state preservation (`docker commit`) tagging forensic image captures before resets.
- **Active response orchestration** (`response_engine.py`, `main.py`):
  - Automated containment pipeline wired directly into event ingestion.
  - REST endpoints for response logging (`GET /api/responses`) and manual operator containment (`POST /api/contain/{ip}`, `POST /api/uncontain/{ip}`).

### Testing
- 63 automated tests, all passing:

  | Suite | Tests |
  |---|---|
  | controller | 17 (core engine, events, risk scoring & containment) |
  | admin-panel | 6 |
  | ssh | 31, including real SSH logins with a Paramiko client |
  | s3 | 9 |

- A manual end-to-end run in the live lab from an attacker container went: directory scan → login brute force → robots.txt → .env leak → SSH brute force → login with the leaked password → recon → reading the AWS keys. The controller tracked the attacker to **stage 4/6** with 10 ATT&CK techniques and 5 alerts, and the session recording was saved.

---

## Steps 7-8 (done)

Plan and requirements: [plan.md](plan.md), [requirements.md](requirements.md).

### Step 7: Dashboard (`controller/app/static/`, `broadcast.py`)
- Single page served at `/` by the controller: first paint from the REST reads, live updates over `/ws`. `ingest_event` and the response engine push `event`/`alert`/`attacker`/`response` deltas through a thread-safe `Publisher` (captured loop + `run_coroutine_threadsafe`), so the sync ingest path never blocks on the async fan-out.
- Shows the live event feed (sorted by timestamp), each attacker's 6-stage trail with risk and playbook, credential theft, alerts, the response log and the ATT&CK techniques seen (by name). Manual Contain / Release buttons.
- Every attacker-controlled field is rendered with `textContent`, never `innerHTML`.
- **Lab lockdown:** the attacker shares the lab subnet, so an HTTP middleware and a `/ws` guard 404 (or close) any lab-side request that is not token-gated `POST /api/events` or `/health`. The dashboard, reads and controls answer only on the mgmt side. Subnet is `MIRAGE_LAB_SUBNET` (default `10.66.0.0/24`).

### Step 6 fix: containment that reaches the decoys (`mirage_common/enforce.py`, `control.py`, `controller/app/decoy_control.py`)
- The old firewall ban only dropped traffic to the controller, not to the decoys the attacker uses. Now each decoy runs a token-gated control server (`/enforce` block|tarpit|clear) and keeps an `EnforcementState`. On containment the controller pushes a **block** to every decoy: the SSH decoy refuses the IP at auth (closing the login-time gap and the auth→session race) and kicks live sessions; the admin-panel and S3 decoys return 403. Tarpit is now a real per-request/per-command delay, not a no-op. Release clears it everywhere.

### Step 8: Evaluation (`eval/`)
- `eval/Dockerfile.attacker`: `debian:bookworm-slim` with nmap, gobuster, hydra, curl, sshpass, awscli baked in (lab is internal). Under the `eval` compose profile: `attacker` (10.66.0.50), `benign` (10.66.0.51), and a real non-decoy `legit` nginx site (10.66.0.30).
- `eval/campaign.sh` walks the whole trail with real tools, incl. `aws s3 ls/cp` against the S3 decoy. `eval/benign.sh` is normal-user traffic against the legit site only, so it never touches a decoy (false-positive rate stays ~0).
- `eval/metrics.py` computes, per run and aggregated (mean ± sd): time to detect, time to contain, false-positive rate, ATT&CK coverage, and trail stage reached, from the controller API.
- `eval/run.sh N [active|observe]` resets the controller, runs N campaigns + benign traffic, and writes `eval/results/`. `observe` turns off automatic response (`MIRAGE_RESPONSE_MODE`); `active` measures time-to-contain.

**Tested:** 85 automated tests pass (controller 27, admin-panel 7, ssh 32, s3 10, eval 9), and the whole lab was run end to end in Docker on 2026-11-06. Full results in [eval-results.md](eval-results.md). Headline: detection under 50 ms, containment ~1.3 s, 100% ATT&CK coverage in observe mode, 0 false positives, and a contained attacker is really locked out (admin/S3 return 403, SSH re-login refused, stage reached drops from 6.0 to 3.2).

### Optional: LLM layer
- Pass a `fallback` function to `Shell` in `decoys/ssh/app/server.py`. It is called only for commands the scripted shell does not know, and should return `None` on failure so the shell falls back to `command not found`.
- The SSH decoy has no internet, so send LLM requests through the controller, which is on the `mgmt` network. `.env.example` already has `LLM_BASE_URL`, `LLM_API_KEY` and `LLM_MODEL`.
- Keep a per-session record of state so answers stay consistent, and add a timeout so a slow API cannot freeze the shell.

---

## Known issues and notes
- Decoys send events from a background thread pool, so events from one burst can reach the controller slightly out of order. Stage tracking and alerts are unaffected because `max_stage` only increases, but the dashboard should sort by event `timestamp`.
- The admin panel's `Server` header is sent in lowercase (`server:`), a tiny fingerprinting tell. It is valid HTTP.
- MITRE Engage activities are labelled by name ("Lures", "Network Monitoring", "System Activity Monitoring"). Check the names and add the official IDs from engage.mitre.org before the final report.
- Fake secrets are never committed. GitHub push protection rejects AWS-format keys even when they are fake, so the values are generated locally into the git-ignored `config/honeytokens.local.json`. Never move them into a tracked file.

---

## Running it

```bash
cp .env.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(32))"   # paste into MIRAGE_INGEST_TOKEN in .env
pip install ./common && python3 tools/gen_honeytokens.py         # writes config/honeytokens.local.json
docker compose up -d --build
curl localhost:8000/api/alerts
```

Then open the **dashboard** at http://127.0.0.1:8000/ on the host (host-only; the attacker on the lab network gets 404s for everything but event ingest).

Run the **evaluation** (needs the lab up):

```bash
docker compose build                # builds the attacker/benign image too
eval/run.sh 10 active               # 10 campaigns, containment on -> time-to-contain
eval/run.sh 10 observe              # containment off -> full-trail detection + coverage
# results and a mean+/-sd summary land in eval/results/
```

The lab network has no internet, so a quick attacker shell has to install its tools first and then join the lab:

```bash
docker run -d --name probe alpine sleep 3600
docker exec probe apk add curl openssh-client sshpass
docker network disconnect bridge probe
docker network connect --ip 10.66.0.50 mirage_lab probe
docker exec -it probe sh       # then: curl http://10.66.0.20/robots.txt
```

## Running the tests

```bash
uv venv .venv --python 3.12
uv pip install --python .venv ./common -r controller/requirements-dev.txt \
    -r decoys/admin-panel/requirements-dev.txt -r decoys/ssh/requirements-dev.txt
(cd controller && ../.venv/bin/python -m pytest -q)
(cd decoys/admin-panel && ../../.venv/bin/python -m pytest -q)
(cd decoys/ssh && ../../.venv/bin/python -m pytest -q)
```

## Repository layout

```
common/mirage_common/   shared event format, trail stages, honeytoken registry, event client
config/honeytokens.json registry template of planted items (IDs, stages, locations)
controller/             FastAPI controller: ingest, storage, labelling, alerts
decoys/admin-panel/     fake admin web panel (stages 1-2)
decoys/ssh/             fake SSH deploy server with scripted shell (stages 3-4)
decoys/s3/              fake S3 endpoint and bait spreadsheet (stages 5-6)
controller/app/static/  the live dashboard (served at /)
eval/                   evaluation: attacker image, campaign, benign traffic, metrics
docs/                   event format, this progress file, plan.md, requirements.md
tools/                  honeytoken generator
docker-compose.yml      the lab (+ the `eval` profile)
```
