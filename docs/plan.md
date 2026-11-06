# Steps 7-8 plan: Dashboard and Evaluation

Owner: Hussain. Requirements in [requirements.md](requirements.md). Status in [PROGRESS.md](PROGRESS.md).

## Approach

Serve the dashboard straight from the existing FastAPI controller: a `/` route returns one
static HTML file, the first paint comes from the REST endpoints that already exist, and a
`/ws` WebSocket pushes every new event, alert, response and attacker update as it lands. The
broadcast hook goes in `ingest_event` right after `engine.process`, exactly where PROGRESS.md
says. No React, no build step, no second server, because the proposal calls for "a single web
page dashboard that updates live over WebSockets" and the controller already holds all the
state. The alternative, a separate Vite/React app, was rejected: it adds a build and a second
container for a one-page internal tool nobody logs into.

Evaluation is a `docker compose` profile, so the attacker and benign-traffic containers live in
the same file as the lab and join the same internal network, with no internet. Metrics come
straight from the controller's SQLite database, which already timestamps every event, alert and
response, so time-to-detect and time-to-contain are just queries. Scripts are plain bash and
Python so they run anywhere without new infra.

One hard dependency: step 6 containment does not actually stop the attacker in the live lab
(see "Broken nearby"). Phase 4 fixes that, and it is ordered before the active-mode evaluation
that depends on it.

## What exists (read these before touching them)
- `controller/app/main.py`: FastAPI app, REST endpoints, ingest. No `/`, no websocket, no static mount. Dashboard bolts on here.
- `controller/app/engine.py:27` `process()`: returns `(row, alert)`. The broadcast reads from here.
- `controller/app/store.py`: `recent("events"|"alerts"|"responses", limit, ip)`, `attackers()`. First-paint data. `recent` already sorts by `ts DESC`, which is the event timestamp, so stage/feed ordering is correct.
- `controller/app/response_engine.py`: containment and tarpit. Phase 4 edits this.
- `controller/app/labels.py`: ATT&CK IDs and Engage names. The dashboard needs ID to name, so a technique map is added here or in a new small module.
- `docker-compose.yml`: `lab` is `internal`, decoys on 10.66.0.20/.21/.22, attacker reserved 10.66.0.50. Only the controller has `NET_ADMIN`.
- `common/mirage_common/trail.py`: the 6 stages, for the progress bar.

## Phase 1: Dashboard served and live
**Goal:** The host page loads state over REST and updates live over a WebSocket.
**Files:** `controller/app/main.py`, `controller/app/broadcast.py` (new), `controller/app/static/index.html` (new), `controller/Dockerfile`
**Steps:**
1. Add `broadcast.py`: a `ConnectionManager` holding connected WebSockets, with `async broadcast(dict)` and connect/disconnect. One lock, drop a socket on send failure.
2. In `main.py`, add `GET /` returning the static HTML and a `/ws` WebSocket endpoint that registers with the manager and holds the connection open.
3. Make `ingest_event` push `{type: "event"|"alert"|"response"|"attacker", data: ...}` to the manager after `engine.process`. `ingest_event` is sync and the manager is async: use a thread-safe hand-off (an `asyncio.Queue` drained by a background task, or `run_coroutine_threadsafe` against the loop captured in `lifespan`). Decide this first, it is the one real unknown.
4. First paint: the page fetches `/api/events`, `/api/alerts`, `/api/responses`, `/api/attackers`, renders, then opens `/ws` and applies deltas.
5. `COPY controller/app/static ./app/static` in the Dockerfile.
**Done when:** `docker compose up -d`, open `http://127.0.0.1:8000/`, `curl` an event in, and a feed row appears with no refresh.

## Phase 2: Dashboard content and safety
**Goal:** The page shows everything the proposal lists, and attacker strings cannot run as code.
**Files:** `controller/app/static/index.html`, `controller/app/static/app.js` (new), `controller/app/static/style.css` (new), `controller/app/labels.py`
**Steps:**
1. Panels: live event feed, attacker cards (6-stage progress bar, risk score, playbook pill), credential-theft list (filter `honeytoken_used` and `file_access` on token stages), techniques seen (ID + name), response log.
2. Render every attacker-controlled field with `textContent`, never `innerHTML`. This is the one security rule of the dashboard: the data is literally attacker input.
3. Add a technique-ID to name map covering every ID the decoys emit (the classifier set is listed below), and label Engage activities with the names already in `labels.py`.
4. Add the Engage activity IDs (EAC00NN) next to the names, from engage.mitre.org, which PROGRESS.md flags for the report.
**Done when:** the full trail run shows all six stages advancing, techniques by name, and a `<script>`-laced user agent renders as visible text.

Techniques emitted today (map must cover all): T1003.008, T1016, T1021.004, T1033, T1046, T1049, T1053.003, T1057, T1059.004, T1070.002, T1070.003, T1078, T1078.004, T1082, T1083, T1087.001, T1098.004, T1105, T1110, T1136.001, T1222.002, T1530, T1546.004, T1548.003, T1552.001, T1552.003, T1580, T1595, T1595.003.

## Phase 3: Lock the dashboard away from the attacker
**Goal:** The attacker, who shares the lab network, cannot reach the dashboard, the API reads, or the manual controls.
**Files:** `controller/app/main.py`, `docker-compose.yml`
**Steps:**
1. The dashboard, `/ws`, the `/api/*` GET reads and the manual contain/uncontain must answer only on the `mgmt` side (host), never to a lab-network client. Only `POST /api/events` stays open to the lab (it already needs the ingest token).
2. Pick the mechanism and write down why: bind the dashboard/read routes to the mgmt interface only, or check `request.client.host` against the lab subnet and 404 it. Ingest must keep working from the lab.
3. Confirm `127.0.0.1:8000` on the host is unchanged.
**Done when:** from the attacker container `curl http://10.66.0.10:8000/` and `/api/attackers` return 404, while `POST /api/events` with the token still returns 202, and the host page still works.

## Phase 4: Make containment actually contain
**Goal:** A contained attacker is really cut off from the decoys, so step 8 can measure time to contain. Fixes gaps in step 6 (Haseeb's code, see open question 1).
**Files:** `controller/app/response_engine.py`, `controller/app/firewall.py`, `decoys/*/` (small), `docker-compose.yml`
**Steps:**
1. **Ban reaches the decoys.** Today only the controller has `NET_ADMIN`, and its nftables `input` hook drops packets to the controller only. The attacker talks to the decoys (10.66.0.20/.21/.22), so the ban does not stop it. Decide the fix: a tiny authenticated block endpoint on each decoy (like the SSH control server) that adds a local nft/iptables drop, with the decoys given `NET_ADMIN`; or a documented single-host limitation. Do not mount the Docker socket into the controller.
2. **Evict at login.** Containment can fire on the SSH `login_attempt` event, which is reported before the session is registered in `decoy.sessions`, so the kick finds nothing. Make the decoy refuse or immediately drop new sessions from a contained IP (controller tells it, or it asks on auth).
3. **Tarpit does something.** `execute_tarpit` only logs a record. Either enforce a real delay on a tarpitted IP at the decoys, or rename it to honest wording and note it in the report. The response log must not claim an action that did not happen.
4. **`simulated` is honest.** Where nft/iptables/docker are absent the drivers already return `"backend": "simulated"`; surface that word in the response log and the dashboard so a demo never looks like it blocked when it did not.
**Done when:** drive a full trail from the attacker container in active mode; after containment the attacker's next SSH, curl and AWS CLI calls fail, and the response log shows real backends (or an honest `simulated`).

## Phase 5: Evaluation harness
**Goal:** One command runs the attack and benign traffic and writes metrics.
**Files:** `eval/Dockerfile.attacker` (new), `eval/campaign.sh` (new), `eval/benign.py` (new), `eval/metrics.py` (new), `eval/run.sh` (new), `docker-compose.yml` (eval profile)
**Steps:**
1. Attacker image: `debian:bookworm-slim` + nmap, gobuster, hydra, curl, sshpass, awscli, built in (lab has no internet). Under an `eval` compose profile at 10.66.0.50.
2. `campaign.sh`: walk the whole trail. The AWS CLI must really work against the S3 decoy (`aws --endpoint-url http://10.66.0.22:9000 s3 ls`, then `s3 cp` the bait). Log each step's wall-clock start.
3. `benign.py`: normal-user traffic against a real internal service, never a decoy, so the false-positive rate is honest. Add one plain nginx/static container to the lab as the "legitimate" host for benign traffic to hit.
4. `metrics.py`: from the SQLite DB, per run and aggregated (mean, sd): time to detect (first event to first alert), time to contain (first event to containment response), false-positive rate (benign source IPs that raised any alert over total benign requests), ATT&CK coverage (distinct techniques seen over the campaign's planned set), and the stage the attacker reached.
5. `run.sh N`: reset controller data, run N campaigns + benign, in `observe` or `active` mode, write `eval/results/<mode>-<timestamp>.json` and a markdown table.
**Done when:** `docker compose --profile eval up` then `eval/run.sh 10 active` produces a results table; benign traffic raises zero alerts; observe mode shows the attacker reaching stage 6.

## Phase 6 (optional, only if time): LLM shell
**Goal:** Unknown SSH commands answered by an LLM, as the proposal abstract and objective 3 promise.
**Files:** `decoys/ssh/app/server.py`, `decoys/ssh/app/llm.py` (new), `controller/app/main.py` (proxy), `.env`
**Steps:**
1. Pass a `fallback` to `Shell`; return `None` on any failure so the shell falls back to `command not found`.
2. The SSH decoy has no internet, so proxy LLM calls through the controller (on `mgmt`). `.env.example` already has `LLM_BASE_URL/KEY/MODEL`.
3. Per-session state so answers stay consistent; a hard timeout so a slow API never freezes the shell.
**Done when:** a command the scripted shell does not know returns plausible output, the API key stays on the controller, and killing the LLM URL still leaves the shell usable.

## PR shape
Six phases, six PRs into `dev`, each green on its own and under 500 lines. Keep PR branches off
`dev`. Phase order resolves the two real unknowns first: the sync-to-async broadcast hand-off
(Phase 1) and whether containment can reach the decoys (Phase 4) before the evaluation that
needs it. Phase 6 only if steps 7-8 land with time to spare. Follow the `ship` skill, run
`local-ci` before any push, and do not push until a phase is actually done.

## Production checks
This is a self-contained Dockerized Python lab, not the 8x Next/Supabase/Vercel stack, so most
headings do not apply. The ones it hits:
- **Adds a route / endpoint (dashboard, `/ws`, manual controls):** auth is by network, not session. Phase 3 is exactly this: the reads and controls must not answer the lab-side attacker. Validate `/api/contain/{ip}` input (Phase 4).
- **Live updates / streaming:** the WebSocket lives in the long-running controller process (not serverless), so it can hold the socket. Phase 1 must drop dead sockets on send failure, or the manager leaks them. XSS on the feed is the headline risk and is Phase 2 step 2.
- **Shared state / concurrency:** `ingest_event` runs in a threadpool, the WS manager is async. The thread-safe hand-off (Phase 1 step 3) is the crux. The connection set needs a lock. `store.lock` already guards the DB.
- **Background / long-running (eval):** campaigns are idempotent per run because `run.sh` resets the DB first. No cron, no queue.
- **Secrets / auth:** the LLM API key (Phase 6) stays on the controller, never on the internet-less SSH decoy. Ingest token already gates `POST /api/events`.
- Not hit: RLS/Postgres, money/webhooks, caching/CDN, mobile/Expo, Stripe/RevenueCat, Vercel limits, email/DNS. No Supabase in this repo.

## Broken nearby (found while researching, do not fix inside a planning task)
- **Containment does not contain in the live lab.** `firewall.py` bans on the controller's own `input` chain, but the attacker's traffic goes to the decoys, which have no ban and (except SSH) no control channel. Promoted to Phase 4 because step 8 depends on it.
- **SSH eviction misses a login-time containment.** The `login_attempt` event is reported before the session is in `decoy.sessions`, so a kick triggered by that event finds no session. Phase 4 step 2.
- **Tarpit is a no-op.** `execute_tarpit` logs `throttle_connection` but nothing slows down. Phase 4 step 3. Honesty matters for the evaluation section.

## Risks
- **The sync-to-async broadcast hand-off.** Calling the async manager from the threadpool wrongly either silently drops messages or blocks ingest. Tell: events land in the DB and the REST reads show them, but `/ws` clients never get the live push. Resolve it in Phase 1 before building UI on top.
- **Containment cannot reach the decoys without widening privilege.** Giving decoys `NET_ADMIN` or a block endpoint grows the attack surface of containers the attacker is literally inside. Tell: if it feels like it needs the Docker socket or host firewall access, stop and document the single-host limitation in the report instead.
- **Benign traffic quietly hitting a decoy** would inflate the false-positive rate and sink the headline result. Tell: any alert with a benign source IP in `eval/results`. Benign traffic must target the plain service only.

## Needs Hussain
- Confirm with Amar and Haseeb who owns the step 6 containment fixes (Phase 4) and the LLM shell (Phase 6) before starting those phases.
- Deadline and demo date, to decide Phase 6 and the number of evaluation runs.
- Nothing else is external: no Supabase, Stripe, store or env config. The LLM key in Phase 6 is the only secret, and it goes in the local `.env` only.
