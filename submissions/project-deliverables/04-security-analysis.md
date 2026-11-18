# Mirage: Security Analysis

**Group 5** · M Amar Waqar (23L-3035) · Hussain Nawaz (23L-3018) · Haseeb Ahmad (23L-3069)

Findings, measured results, performance and lessons from building and attacking Mirage.

## 1. Threat model

**Who we defend against.** An attacker who is already inside the internal network: for example through a phished laptop or an exposed service. They use common, freely available tools (nmap, gobuster, hydra, SSH, the AWS CLI). Their goal is to find credentials, move to more valuable systems and take data out.

**What Mirage assumes.** The attacker does not know which systems are decoys. Legitimate users and services have no reason to read robots.txt hints, open backup files or use the deploy box's password, so they never touch a bait.

**Out of scope.** Attackers outside the network; attackers who already know the deception layout; attacks on the host machine itself. Mirage never acts outside the lab and never attacks the attacker's own machine.

## 2. How we tested it

| Item | Setting |
|---|---|
| Environment | Docker lab, one isolated network `10.66.0.0/24`, no internet |
| Attack | `eval/campaign.sh` with real tools: port scan (nmap), directory brute force (gobuster), read robots.txt, download the backup `.env`, SSH brute force (hydra), SSH login with the leaked password, recon commands, read `~/.aws/credentials`, list the S3 bucket and download `passwords.xlsx` (AWS CLI) |
| Normal users | `eval/benign.sh`: 40 requests per run to the real staff website, running alongside every attack |
| Modes | **observe** (response off: how much does Mirage see?) and **active** (response on: how fast does it stop the attacker, and how far does the attacker get?) |
| Runs | 5 measured runs per mode, after one discarded warm-up run |
| Source of numbers | `eval/metrics.py`, computed from the controller's own records |

**Metric definitions**

| Metric | Measured as |
|---|---|
| Time to detect | First event from the attacker → first alert |
| Time to contain | First event from the attacker → containment recorded |
| Stage reached | Furthest of the 6 baits the attacker took |
| ATT&CK coverage | Share of the 9 techniques the campaign uses that Mirage labelled |
| False-positive rate | Alerts raised against the normal-user machine |

## 3. Results

Measured on 17 November 2026, on the current code.

| Metric | Observe mode | Active mode |
|---|---|---|
| Time to detect | 7 ms mean, 23 ms worst | under 1 ms in every run |
| Time to contain | not applicable (response off) | **2.63 s ± 0.69** |
| Stage reached | **6 of 6** in every run | **4 of 6** in every run |
| ATT&CK coverage | 100% | 78% |
| False positives | **0** (200 normal requests) | **0** (200 normal requests) |

Per-run values:

| Run | Observe: time to detect | Active: time to contain | Active: stage |
|---|---|---|---|
| 1 | 0.000 s | 2.00 s | 4 |
| 2 | 0.004 s | 2.87 s | 4 |
| 3 | 0.005 s | 2.65 s | 4 |
| 4 | 0.023 s | 3.77 s | 4 |
| 5 | 0.003 s | 1.85 s | 4 |

## 4. Findings

### 4.1 Detection is immediate and unambiguous
The first alert came within 25 ms of the attacker's first touch in every run, in both modes. Deception needs no baseline of normal behaviour and no training period. The signal is a fact ("someone read a file nobody should read"), not a statistical guess.

### 4.2 Zero false alarms, for a structural reason
Normal users made 400 requests across the ten runs and caused no alerts. This is the core advantage of deception: legitimate traffic never reaches a decoy, so it cannot trigger one. It should be read carefully, though: our normal-user generator only browses the real staff website, so this result shows the design works as intended rather than stress-testing it. In a real network, crawlers, inventory scanners or curious staff could touch a decoy, and would need to be allowlisted.

### 4.3 The attacker is stopped before the valuable data
With the response on, the attacker was contained at bait 4 (reading the planted AWS keys) in every run, 2.6 s on average after first contact, and never reached the cloud storage or the spreadsheet. With the response off, the attacker took all six baits in every run, which shows what the response prevents. Time to contain includes the attacker's own scanning time, so it measures the whole incident, not only Mirage's reaction.

An earlier evaluation stopped the attacker one bait sooner, at the SSH login; the cause of that change has not been investigated. In both cases the attacker never reached the cloud storage.

### 4.4 Coverage drops in active mode, as expected
Observe mode labelled all 9 techniques the campaign uses. Active mode labelled 78% because the attacker is stopped before it can use the cloud-storage techniques. This is a side effect of stopping the attack early, not a detection gap.

### 4.5 Containment has to reach the decoys, not only the controller
Our first containment design banned the attacker at the controller's firewall. Testing in the live lab showed this changed nothing: the ban only filtered traffic to the controller, not to the decoys the attacker was actually using. We redesigned containment so that every decoy runs a small token-protected control server and enforces blocks itself. After that, a contained attacker's web, S3 and SSH requests all fail immediately; even the correct SSH password is refused.

### 4.6 Containment can land mid-login
The threshold can be crossed by the SSH login event itself, before any shell session exists to kick. We closed this race in two places: blocked addresses are refused at authentication, and a session that starts after a block is ended straight away.

### 4.7 A concurrency bug corrupted attacker state
The controller originally shared one SQLite connection between threads with unlocked reads. Under the burst of events from a real attack, this could reset an attacker's record mid-attack. That added variance to when containment fired: 1.51 s ± 0.65 before the fix, 1.33 s ± 0.16 after. Every store access is now locked, and `controller/tests/test_concurrency.py` guards against a regression.

## 5. Performance

| Aspect | Observation |
|---|---|
| Event volume | About 300 to 330 events per attack campaign, mostly from directory brute forcing |
| Detection latency | Under 25 ms from event to alert in every run |
| Containment | Pushed to all three decoys in one sequence; each decoy acknowledges |
| Dashboard | Stays responsive under event bursts: the evidence tables redraw at most about three times a second, and live updates arrive over one WebSocket |
| Several attackers | Three attackers at once (live demo) are tracked, scored and contained independently |
| Tests | 86 automated tests pass |

## 6. Lessons learned

1. **Test containment from the attacker's side.** The first containment looked correct in the controller's logs and did nothing to the attacker. Only attacking the live lab exposed it.
2. **Bursts break assumptions.** Real tools fire hundreds of events in seconds. That exposed the database race and the login-time containment race, which unit tests had missed.
3. **Deception makes detection simple.** No baselines, no thresholds to tune for alert noise: a touch on a bait is the signal. The effort moves to making the decoys believable.
4. **Keep decoys simple.** Decoys only report what happened; the controller decides what it means. That kept three different decoys consistent and testable.
5. **Never commit secrets, even fake ones.** GitHub push protection rejected our fake AWS-format keys. Generating bait per deployment into a git-ignored file fixed it and gives every deployment unique tokens.
6. **Measure, then re-measure.** Re-running the evaluation after later changes showed containment had moved from stage 3 to stage 4. Results go stale as code changes, so the evaluation has to be re-run.

## 7. Ethics and scope

Mirage runs only inside an isolated lab. It uses no real credentials or cloud accounts and performs no offensive action against an attacker's own systems. Every response acts only on the decoys Mirage owns. The "host isolation" shown in the demo disconnects our own attacker container from the lab network, which models what defensive tools do to a compromised internal machine.
