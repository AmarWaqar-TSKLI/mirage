# Mirage

**An Adaptive Cyber Deception and Active Response Platform**

Mirage is an Information Security project that turns a network into a trap. Instead of searching for attackers in a flood of legitimate traffic and logs, Mirage plants fake services, credentials and documents that no legitimate user has any reason to touch. When something touches them, it's an attacker, so alerts are high-fidelity with near-zero false positives. Mirage then detects, profiles and automatically contains the attacker.

The project is based on the [MITRE Engage](https://engage.mitre.org) framework for adversary engagement, and every observed action is mapped to [MITRE ATT&CK](https://attack.mitre.org) techniques.

> **Status:** Proposal stage. Implementation has not started yet.

---

## How it works

An attacker who breaches the perimeter finds a deliberately planted **breadcrumb trail**:

```
robots.txt → exposed backup .env → SSH credentials → fake SSH server
          → ~/.aws/credentials → fake S3 bucket → passwords.xlsx
```

Each step is a decoy or a uniquely traceable honeytoken. Mirage knows exactly which asset was stolen, where it was planted, and how far along the attack chain the intruder has progressed. Once the attacker's risk crosses a threshold, Mirage contains them automatically.

## Components

### 1. Decoy Infrastructure
Docker containers hosting intentionally exposed, realistic-looking decoy services:
- **Fake admin panel**: an internal login/admin portal that records brute-force attempts, credential stuffing, directory enumeration and injection attempts.
- **Fake internal SSH server**: an interactive server with a believable filesystem full of planted secrets. Full sessions are recorded for replay.
- **Fake AWS S3/API endpoint**: an S3-compatible service (MinIO/LocalStack) that accepts the planted fake AWS keys, so stolen cloud credentials can be traced end to end.

### 2. AI-Driven Interactive Shell
Traditional honeypots only emulate a fixed set of commands, so attackers quickly spot them. Mirage's SSH decoy uses a hybrid design:
- **Deterministic layer:** common commands and all planted bait come from a fixed virtual filesystem.
- **LLM layer:** every other command is answered by a large language model acting as the shell of one consistent fake server.
- **Session state:** files and directories the attacker creates persist for the whole session.
- **Command intelligence:** each command is classified to an ATT&CK technique and streamed live to the dashboard.

### 3. Honeytoken Fabric
A generation engine that creates and tracks unique honeytokens:
- Fake API keys and AWS access keys in authentic formats (in `.env`, config files, git history)
- Fake database credentials and **honey records** (fake DB rows that alert when read)
- **Canary documents** (`passwords.xlsx`, `.docx`, `.pdf`) that call home when opened
- Honey URLs and DNS canaries for detecting reconnaissance

Because every token is unique, an attacker who rotates IP addresses but reuses a stolen credential is still linked to the **same attacker identity**.

### 4. Detection & Active Response Controller
- **Route validation:** a reverse proxy checks traffic against authentic service routes. Anything that hits a decoy route is hostile.
- **Instant alerting:** each alert carries the attacker's IP, client fingerprint (HASSH/JA3, scanner signatures), the asset touched and the mapped ATT&CK/Engage technique.
- **Attacker profiling:** a per-attacker risk score built from fingerprints, tools used and breadcrumb progress.
- **Graded response playbooks:**
  | Playbook | Action |
  |---|---|
  | Observe | Let low-risk activity continue to gather intelligence |
  | Tarpit | Slow the attacker's connections to a crawl |
  | Contain | Ban the IP at the host firewall (nftables/ipset, with expiry) and kill the session |
  | Preserve → Contain | Snapshot the decoy container for forensics, then contain |

### 5. Command & Telemetry Dashboard
A real-time web UI showing:
- a live incident map of attacker → decoy activity
- kill-chain timelines
- credential-theft and honeytoken events
- SSH session replay
- observed ATT&CK techniques
- a log of automated containment actions

## Evaluation

Mirage will be tested in an isolated lab against scripted attack campaigns (nmap, gobuster, hydra, AWS CLI) while a benign traffic generator simulates normal users. We will measure:
- Mean **time-to-detect** and **time-to-contain**
- **False-positive rate** under benign traffic
- **ATT&CK technique coverage**
- **Attacker dwell time** in the AI shell compared with a static-command honeypot

## Planned Tech Stack

| Layer | Technology |
|---|---|
| Lab environment | Docker, Docker Compose |
| Controller / API | Python, FastAPI |
| SSH decoy | Paramiko + LLM-backed shell |
| Fake S3 | MinIO / LocalStack |
| Containment | nftables, ipset |
| Event streaming | Redis |
| Dashboard | React, WebSockets |

## Scope & Ethics

Mirage runs **only inside an isolated lab network**. It does not use real credentials or real cloud accounts, and it performs no offensive "hack-back" actions.

## Team

| Name | Roll No |
|---|---|
| M Amar Waqar | 23L-3035 |
| Hussain Nawaz | 23L-3018 |
| Haseeb Ahmad | 23L-3069 |

National University of Computer and Emerging Sciences (FAST-NUCES), Department of Computer Science, Lahore, Pakistan
