# Mirage

**An Adaptive Cyber Deception and Active Response Platform**

Mirage is an Information Security project that turns a network into a trap. Instead of searching for attackers in a flood of legitimate traffic and logs, Mirage plants fake services, credentials and files that no legitimate user has any reason to touch. When something touches them, it's an attacker, so alerts are high-fidelity with near-zero false positives. Mirage then detects, profiles and automatically contains the attacker.

The project is based on the [MITRE Engage](https://engage.mitre.org) framework for adversary engagement, and every observed action is mapped to [MITRE ATT&CK](https://attack.mitre.org) techniques.

> **Status:** Complete. Three decoys, the breadcrumb trail, detection with ATT&CK labelling, risk scoring, automatic response, the live dashboard and the evaluation harness all run end to end in the Docker lab, with 94 automated tests passing. Each decoy has its own token, the dashboard controls need an operator key, and an intruder who switches address is linked back by the credentials it stole. Latest evaluation (19 Nov 2026): first alert within 16 ms, attacker contained in 2.4 s on average at bait 4 of 6, 0 false alarms from 400 normal-user requests.
>
> **Submission:** the graded deliverables (source zip, how to run, architecture, security analysis, slides) are in [`submissions/`](submissions/); their Markdown sources are in [`docs/submission/`](docs/submission/).

---

## How it works

Mirage is one working pipeline. A single attack path feeds a single flow of events:

```
Decoys → Detection → Response → Dashboard
```

An attacker who breaches the perimeter finds a deliberately planted **breadcrumb trail**:

```
robots.txt → exposed backup .env → SSH credentials → fake SSH server
          → ~/.aws/credentials → fake S3 bucket → passwords.xlsx
```

Each step is a decoy or a uniquely traceable honeytoken. Mirage knows exactly which asset was stolen, where it was planted, and how far along the trail the intruder has progressed. Once the attacker's risk crosses a threshold, Mirage contains them automatically.

## Components

### 1. Decoy Infrastructure
Docker containers hosting intentionally exposed, realistic-looking decoy services:
- **Fake admin panel**: an internal login page whose `robots.txt` points to an exposed backup `.env`. Records login attempts and directory enumeration.
- **Fake internal SSH server**: an interactive server with a believable filesystem holding planted secrets. Full sessions are recorded as evidence.
- **Fake AWS S3 endpoint**: our own S3-compatible service with AWS Signature V4 checking, so the real AWS CLI works against it. It accepts only the planted fake AWS keys, so stolen cloud credentials can be traced end to end.

### 2. Interactive Shell
The SSH decoy runs a scripted shell of about 45 commands (pipes, redirects, variables) over a believable virtual filesystem. Files the attacker creates persist for the session, and every command is classified to an ATT&CK technique and streamed live to the dashboard.

The AI layer from the proposal, where a language model answers commands the scripted shell does not know, is **designed but not built**: the shell has a fallback hook ready for it.

### 3. Honeytokens
Uniquely tagged fake secrets, each recorded where it was planted:
- A fake SSH password in the exposed `.env`
- Fake AWS keys in `~/.aws/credentials`
- A bait `passwords.xlsx` in the fake S3 bucket that alerts when downloaded
- A fake link in `robots.txt` that reveals scanning

### 4. Detection & Active Response Controller
- **Single event flow:** every decoy sends events to one controller in one common format, signed with that decoy's own token.
- **Instant alerting:** each alert carries the attacker's IP, the asset touched and the mapped ATT&CK/Engage technique.
- **Attacker profiling:** a per-attacker risk score built from trail progress and techniques used. An address that reuses a credential stolen by another is linked to it as the same intruder.
- **Graded response playbooks:**
  | Playbook | Action |
  |---|---|
  | Observe | Let low-risk activity continue to gather intelligence |
  | Tarpit | Slow the attacker's connections to a crawl |
  | Contain | Run the containment sequence below |

### 5. Containment and Disruption
When an attacker's risk score crosses the containment threshold, Mirage runs a disruption sequence. Every action targets only the attacker's own session and the decoy containers that Mirage controls, so the whole response stays inside the isolated lab.

- **Session freeze:** the active connection is throttled to a standstill, so the attacker's tools stall, hang and time out.
- **Lockout and notice:** the session is terminated, every decoy blocks the address (web and S3 return 403, SSH refuses even the right password) and shows the intruder that the system was a trap. A host firewall ban (nftables/iptables) is attempted too; in the lab it runs in simulated mode.
- **Forensic capture:** the full SSH session recording is saved, and a container snapshot is attempted (simulated in the lab).

### 6. Command & Telemetry Dashboard
A single real-time web page showing:
- the live event feed
- progress along the trail
- credential-theft events
- observed ATT&CK techniques
- a log of automated containment actions

## Evaluation

Tested in the lab with a scripted attack using real tools (nmap, gobuster, hydra, SSH, AWS CLI) while a generator plays normal users against a real staff website. Five measured runs per mode, 19 November 2026:

| Metric | Response off (observe) | Response on (active) |
|---|---|---|
| Time to detect | 3 ms mean, 7 ms worst | 4 ms mean, 16 ms worst |
| Time to contain | n/a | 2.38 s ± 0.30 |
| Furthest bait reached | 6 of 6 | 4 of 6 |
| ATT&CK coverage | 100% | 78% (attack stopped early) |
| False positives | 0 | 0 |

Full results: [docs/eval-results.md](docs/eval-results.md). Discussion: [the security analysis](docs/submission/security-analysis.md).

## Quick start

```bash
cp .env.example .env && python3 tools/gen_secrets.py   # per-decoy tokens and the operator key
python3 -m venv .venv && .venv/bin/pip install ./common && .venv/bin/python tools/gen_honeytokens.py
./demo up               # prints the dashboard sign-in link
./demo attack           # run the narrated attack
```

Full instructions: [How to run](docs/submission/how-to-run.md).

## Tech Stack

| Layer | Technology |
|---|---|
| Lab environment | Docker, Docker Compose |
| Controller / API | Python, FastAPI, SQLite |
| SSH decoy | Paramiko, scripted shell (LLM fallback planned) |
| Fake S3 | FastAPI, AWS Signature V4 |
| Containment | Decoy-level enforcement, nftables/iptables where available |
| Dashboard | Single web page, WebSockets |

## Scope & Ethics

Mirage runs **only inside an isolated lab network**. It does not use real credentials or real cloud accounts, and it performs no offensive "hack-back" actions.

## Team

| Name | Roll No |
|---|---|
| M Amar Waqar | 23L-3035 |
| Hussain Nawaz | 23L-3018 |
| Haseeb Ahmad | 23L-3069 |

National University of Computer and Emerging Sciences (FAST-NUCES), Department of Computer Science, Lahore, Pakistan
