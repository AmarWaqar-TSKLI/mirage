# Mirage

**An Adaptive Cyber Deception and Active Response Platform**

Mirage is an Information Security project that turns a network into a trap. Instead of searching for attackers in a flood of legitimate traffic and logs, Mirage plants fake services, credentials and files that no legitimate user has any reason to touch. When something touches them, it's an attacker, so alerts are high-fidelity with near-zero false positives. Mirage then detects, profiles and automatically contains the attacker.

The project is based on the [MITRE Engage](https://engage.mitre.org) framework for adversary engagement, and every observed action is mapped to [MITRE ATT&CK](https://attack.mitre.org) techniques.

> **Status:** Proposal stage. Implementation has not started yet.

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
- **Fake AWS S3 endpoint**: an S3-compatible service (MinIO) that accepts the planted fake AWS keys, so stolen cloud credentials can be traced end to end.

### 2. AI-Driven Interactive Shell
Traditional honeypots only emulate a fixed set of commands, so attackers quickly spot them. Mirage's SSH decoy uses a hybrid design:
- **Deterministic layer:** common commands and all planted bait come from a fixed virtual filesystem.
- **LLM layer:** every other command is answered by a large language model acting as the shell of one consistent fake server.
- **Session state:** files and directories the attacker creates persist for the whole session.
- **Command intelligence:** each command is classified to an ATT&CK technique and streamed live to the dashboard.

### 3. Honeytokens
Uniquely tagged fake secrets, each recorded where it was planted:
- A fake SSH password in the exposed `.env`
- Fake AWS keys in `~/.aws/credentials`
- A bait `passwords.xlsx` in the fake S3 bucket that alerts when downloaded
- A fake link in `robots.txt` that reveals scanning

### 4. Detection & Active Response Controller
- **Single event flow:** every decoy sends events to one controller in one common format.
- **Instant alerting:** each alert carries the attacker's IP, the asset touched and the mapped ATT&CK/Engage technique.
- **Attacker profiling:** a per-attacker risk score built from trail progress and techniques used.
- **Graded response playbooks:**
  | Playbook | Action |
  |---|---|
  | Observe | Let low-risk activity continue to gather intelligence |
  | Tarpit | Slow the attacker's connections to a crawl |
  | Contain | Run the containment sequence below |

### 5. Containment and Disruption
When an attacker's risk score crosses the containment threshold, Mirage runs a disruption sequence. Every action targets only the attacker's own session and the decoy containers that Mirage controls, so the whole response stays inside the isolated lab.

- **Session freeze:** the active connection is throttled to a standstill, so the attacker's tools stall, hang and time out.
- **Lockout and notice:** the session is terminated, a visible notice tells the intruder they have been detected and contained, and the source address is banned at the host firewall (nftables) with an expiry timer.
- **Forensic capture:** before the decoy resets, Mirage saves the full session recording and a snapshot of the container.

### 6. Command & Telemetry Dashboard
A single real-time web page showing:
- the live event feed
- progress along the trail
- credential-theft events
- observed ATT&CK techniques
- a log of automated containment actions

## Evaluation

Mirage will be tested in an isolated lab against a scripted attack campaign (nmap, gobuster, hydra, AWS CLI) while a benign traffic generator simulates normal users. We will measure:
- Mean **time-to-detect** and **time-to-contain**
- **False-positive rate** under benign traffic
- **ATT&CK technique coverage**

## Planned Tech Stack

| Layer | Technology |
|---|---|
| Lab environment | Docker, Docker Compose |
| Controller / API | Python, FastAPI, SQLite |
| SSH decoy | Paramiko + LLM-backed shell |
| Fake S3 | MinIO |
| Containment | nftables |
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
