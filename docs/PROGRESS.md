# Mirage: Progress and Remaining Work

Last updated: 4 November 2026. All work is on the `dev` branch.

The build is split into 8 steps that follow the pipeline **Decoys → Detection → Response → Dashboard**.
Steps 1–4 are done and tested. Steps 5–8 and the optional LLM layer are still to do.

| # | Step | Status |
|---|---|---|
| 1 | Skeleton: event format, controller, isolated lab network | ✅ Done |
| 2 | Controller core: storage, trail stages, ATT&CK/Engage labels, alerts | ✅ Done |
| 3 | Admin panel decoy and honeytokens (robots.txt → .env leak) | ✅ Done |
| 4 | SSH decoy: scripted shell, session recording | ✅ Done |
| 5 | Fake S3 endpoint and `passwords.xlsx` bait | ⬜ To do |
| 6 | Risk score, response playbooks, nftables containment | ⬜ To do |
| 7 | Live dashboard | ⬜ To do |
| 8 | Evaluation: attacker container, attack script, benign traffic, metrics | ⬜ To do |
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

### Testing
- 49 automated tests, all passing:

  | Suite | Tests |
  |---|---|
  | controller | 12 |
  | admin-panel | 6 |
  | ssh | 31, including real SSH logins with a Paramiko client |

- A manual end-to-end run in the live lab from an attacker container went: directory scan → login brute force → robots.txt → .env leak → SSH brute force → login with the leaked password → recon → reading the AWS keys. The controller tracked the attacker to **stage 4/6** with 10 ATT&CK techniques and 5 alerts, and the session recording was saved.

---

## What is left

### Step 5: Fake S3 endpoint (trail stages 5–6)
- An S3-compatible service at `10.66.0.22:9000`, bucket `corp-backups`, holding `finance/passwords.xlsx` plus some filler objects (for example `releases/ops-console-v3.8.2.tar.gz`, which `deploy.sh` mentions).
- It must accept the planted key pair from the `ht-aws-access-key` value in `config/honeytokens.local.json`. A read-only, non-admin user is preferred.
- Report events in the common format:
  - any successful request with the planted key → `honeytoken_used`, `honeytoken_id: ht-aws-access-key`
  - downloading `finance/passwords.xlsx` → `file_access`, `honeytoken_id: ht-passwords-xlsx`
  - requests with a wrong key → `login_attempt` with `success: false`
- **Heads-up:** the official `minio/minio` Docker Hub image could not be pulled (MinIO stopped publishing community images in 2025). Options: build MinIO from source, use another registry mirror, or use a different S3-compatible server. For MinIO, the audit webhook (`MINIO_AUDIT_WEBHOOK_*`) plus a small adapter that converts audit logs into Mirage events is the cleanest way to report.

### Step 6: Risk scoring, playbooks, containment
- A per-attacker **risk score** built from trail stage, techniques seen and activity rate, stored on the `attackers` row.
- **Playbooks** chosen by thresholds: **Watch** (low) → **Slow down** (tarpit) → **Shut out** (contain).
- An **allow list** of defender IPs that are never acted on.
- **Containment sequence:**
  1. Freeze the session (throttle it with `tc`, or delay responses).
  2. Show the intruder a notice and end the session. `Connection.close()` in the SSH decoy already kicks a session, and `Decoy.sessions` lists the live ones, but the controller still needs a way to call it, for example a small authenticated control endpoint on the decoy.
  3. Ban the address with nftables for a set time. The controller (or a helper container) needs `NET_ADMIN` on the lab network.
  4. Save evidence: the session recording already exists, and a container snapshot still needs to be added (`docker commit`).
- Log every response action in a new `responses` table so the dashboard can show it.

### Step 7: Dashboard
- A single page served by the controller that updates live over WebSockets. Add a broadcast in `ingest_event` after `engine.process`.
- It should show the live event feed, each attacker's progress along the 6 trail stages, credential theft events, observed ATT&CK techniques and the response log.
- The REST endpoints above already return everything needed for the first page load.

### Step 8: Evaluation
- An attacker container (Kali, or Alpine with nmap, gobuster, hydra, curl, sshpass and awscli) at 10.66.0.50. The lab is internal, so the tools must be built into the image.
- A scripted campaign that walks the whole trail (the manual run above is a starting point).
- A benign traffic generator that acts like normal users. Normal users should never touch a decoy, which shows the false-positive rate is close to zero.
- Metrics computed from the controller database:
  - mean time to detect (first event → first alert)
  - mean time to contain (first event → containment)
  - false-positive rate
  - ATT&CK technique coverage

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
docs/                   event format and this progress file
tools/                  honeytoken generator
docker-compose.yml      the lab
```
