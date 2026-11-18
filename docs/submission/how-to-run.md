# Mirage: How to Run

**Group 5** · M Amar Waqar (23L-3035) · Hussain Nawaz (23L-3018) · Haseeb Ahmad (23L-3069)

Mirage runs entirely inside an isolated Docker lab on one machine. These steps take a fresh Linux machine from zero to a running lab, a live attack and a measured evaluation.

## 1. Requirements

| Need | Version used | Notes |
|---|---|---|
| Linux host | Arch Linux (kernel 7.x) | Any Linux with Docker works. macOS/Windows work through Docker Desktop. |
| Docker Engine + Compose plugin | Docker 29.9 | `docker compose` (v2), not the old `docker-compose`. |
| Python | 3.12 | Only for generating honeytokens and running the tests. |
| `uv` (optional) | 0.13 | Fast virtual-environment tool for the tests. Plain `pip` also works. |
| Free port | 127.0.0.1:8000 | The dashboard and API. Nothing else is exposed on the host. |
| Internet | first build only | Images download their packages once. The lab itself has no internet. |

## 2. First-time setup

```bash
git clone https://github.com/AmarWaqar-TSKLI/mirage.git
cd mirage

# 1. Secrets: each decoy's own token, and the operator key for the dashboard's controls
cp .env.example .env
python3 tools/gen_secrets.py        # fills them into .env with random values

# 2. Generate this deployment's fake secrets (SSH password, AWS key pair).
#    They go to config/honeytokens.local.json, which git ignores, so every
#    deployment gets its own unique bait and nothing secret-looking is committed.
python3 -m venv .venv && .venv/bin/pip install ./common
.venv/bin/python tools/gen_honeytokens.py

# 3. Build and start the lab, including the attacker and normal-user machines
sudo systemctl start docker          # if Docker is not already running
./demo up
```

`./demo up` builds every image, starts the lab, waits until the controller answers and prints a **sign-in link**. The first build takes a few minutes.

## 3. Open the dashboard

Open the sign-in link that `./demo up` printed (`./demo key` prints it again). It looks like `http://127.0.0.1:8000/#key=…` and carries the operator key. The dashboard keeps the key for that browser tab and removes it from the address bar. It should say **"Airspace clear"**, and the top bar should show **Operator**.

Opening plain **http://127.0.0.1:8000/** also works, in **Read-only** mode: you see everything, but **Intercept now** and **Release** ask for the key first.

The dashboard is only reachable from the host. Machines inside the lab, including the attacker, get `404` for everything except event ingestion.

## 4. See what is running

```bash
./demo show
```

| Container | IP | Role |
|---|---|---|
| mirage-controller-1 | 10.66.0.10 | Mirage: detection, scoring, response, dashboard |
| mirage-admin-panel-1 | 10.66.0.20 | Decoy: fake admin website (baits 1–2) |
| mirage-ssh-1 | 10.66.0.21 | Decoy: fake deploy server over SSH (baits 3–4) |
| mirage-s3-1 | 10.66.0.22 | Decoy: fake S3 cloud storage on port 9000 (baits 5–6) |
| mirage-legit-1 | 10.66.0.30 | A real staff website (not a decoy) |
| mirage-attacker-1 | 10.66.0.50 | Attacker machine with nmap, gobuster, hydra, ssh, AWS CLI |
| mirage-benign-1 | 10.66.0.51 | Normal-user traffic generator |

All of them share one internal Docker network, `10.66.0.0/24`, with no route to the internet.

## 5. Run an attack

The attacker's narrated console runs the whole breadcrumb trail by itself, with a countdown between phases:

```bash
./demo observe              # Mirage only watches: the attack gets all the way in
./demo attack --pause 8     # run it; watch the dashboard at the same time

./demo active               # Mirage responds on its own
./demo attack --pause 8     # this time it is intercepted at bait 4
```

Each mode switch also clears the dashboard. `./demo attack` prints **● OBSERVE** or **● ACTIVE** before starting, so the mode is always clear.

### Optional: several attackers and the isolation finale

```bash
./demo hackers 3            # three attacker machines: 10.66.0.50, .52, .53
./demo swarm 8              # launch the extra two in the background, 8 s apart
./demo watch                # on the attacker: live monitor of which doors are still open
./demo isolate              # cut every attacker machine off the network
./demo restore              # plug them back in
```

### Optional: the same intruder on a new address

```bash
./demo hackers 4            # a fresh attacker machine at 10.66.0.54
./demo reuse 4              # it logs in to SSH with the password hacker 1 stole
```

After hacker 1 has been contained, this login is linked to hacker 1 at once: a critical alert, a "same intruder, new address" banner, and immediate containment.

### Attacking by hand

```bash
./demo hacker               # a shell on the attacker machine (10.66.0.50)
curl http://10.66.0.20/robots.txt
curl http://10.66.0.20/backup/.env.bak            # leaks the SSH password
ssh deploy@10.66.0.21                              # use the leaked password
cat ~/.aws/credentials                             # inside the SSH session
```

## 6. Run the evaluation

```bash
eval/run.sh 5 active        # 5 measured attacks with automatic response
eval/run.sh 5 observe       # 5 measured attacks with response off
```

Each run resets the controller, fires one full attack campaign while the normal-user generator browses the real staff website, and computes the metrics from the controller's own records. Results and a mean ± standard deviation summary land in `eval/results/`. Allow about 5 minutes per mode, plus image builds on the first run.

## 7. Run the automated tests

```bash
uv venv .venv --python 3.12     # or: python3 -m venv .venv
uv pip install --python .venv ./common \
    -r controller/requirements-dev.txt -r decoys/admin-panel/requirements-dev.txt \
    -r decoys/ssh/requirements-dev.txt -r decoys/s3/requirements-dev.txt
(cd controller && ../.venv/bin/python -m pytest -q)
(cd decoys/admin-panel && ../../.venv/bin/python -m pytest -q)
(cd decoys/ssh && ../../.venv/bin/python -m pytest -q)
(cd decoys/s3 && ../../.venv/bin/python -m pytest -q)
.venv/bin/python -m pytest -q eval
```

Expected: 94 tests pass (controller 36, admin panel 7, SSH 32, S3 10, evaluation 9).

## 8. Stop everything

```bash
./demo down                                     # stops and removes the lab
sudo systemctl stop docker.socket docker.service  # optional: stop Docker itself
```

## Command reference

| Command | What it does |
|---|---|
| `./demo up` / `down` | Start / stop the whole lab |
| `./demo status` / `show` | What is running, which mode / every container with its role and IP |
| `./demo observe` / `active` | Switch response mode (and clear the board) |
| `./demo key` | Print the dashboard sign-in link (operator key) |
| `./demo reset` | Clear the dashboard, unblock and reconnect every attacker |
| `./demo attack [--pause N \| --step \| --fast]` | The narrated attack on attacker 1 |
| `./demo hackers N` / `swarm [SECS]` | Run N attacker machines / launch the extras in the background |
| `./demo watch` | Uplink monitor on attacker 1 |
| `./demo isolate [K]` / `restore` | Cut attackers off the network / reconnect them |
| `./demo hacker [K]` | Open a shell on attacker K |
| `./demo reuse [K]` | Attacker K logs in with the SSH password attacker 1 stole |

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Docker is not running` | `sudo systemctl start docker` |
| `run tools/gen_secrets.py` | Step 2.1 was skipped |
| "Operator key rejected" on the dashboard | Open the link from `./demo key` again |
| Controller exits at start: honeytokens file missing | Run `tools/gen_honeytokens.py` (step 2.2) |
| Attack ends at once with MISSION FAILED | The attacker is still blocked from a previous run: `./demo reset` |
| Every attack phase says no route | The attacker is still isolated: `./demo reset` |
| Dashboard shows old data after a reset | It reloads itself within 5 s, or press F5 |
| Port 8000 already in use | Stop whatever holds it, or change the host port in `docker-compose.yml` |
