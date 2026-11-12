# Mirage live demo playbook

About **12 minutes**, two people: the **Defender** narrates and drives the dashboard, the **Hacker** owns the attacker terminal. One laptop is enough.

**On stage, nobody copy-pastes anything.** Each act starts with one command, and then the attack runs by itself. Between phases it shows a countdown (`▸ next PHASE 3 … ▓▓▓▓░░░░ 6s`). That countdown is your cue to look at the dashboard and talk.

Every step uses real tools (nmap, gobuster, hydra, curl, ssh, aws) against the lab. Nothing on either screen is faked.

---

## The screens

| Where | What | Who |
|---|---|---|
| **Projector, left half** | Dashboard <http://127.0.0.1:8000/>, full screen | Defender |
| **Projector, right half** | Terminal **H**, big font (Ctrl + `+` three times) | Hacker |
| **Laptop only** | Terminal **S** (stage), for the `./demo …` commands | Defender |

Both terminals start in the repo: `cd ~/Projects/IS_Project`

---

## 30 minutes before

```bash
sudo systemctl start docker
./demo up            # starts the lab
./demo hackers 3     # three hacker machines: 10.66.0.50, .52, .53
./demo status        # everything "Up", all three hackers "connected"
```
- Open the dashboard, F11 for full screen.
- Do one full practice run of all acts, then reset.

## 1 minute before (in S)

```bash
./demo observe       # switches to watch-only and clears the board
```
Check that the dashboard says **"Airspace clear"** and the top chip says **"Observe only"**. When the Hacker starts the attack, the terminal first prints **● OBSERVE** or **● ACTIVE**. If it says the wrong one, press Ctrl+C and switch modes.

---

## Opening · The problem, and proof it's real (2:00)

| Time | Do | Say |
|---|---|---|
| 0:00 | Dashboard on screen, nothing happening | "Attackers who get into a company network usually go unnoticed for weeks. Normal tools look for known bad patterns and drown the team in false alarms. **Mirage turns that around: we fill the network with fake systems that no real employee ever touches.** The moment anyone touches one, it's an attacker, guaranteed." |
| 0:30 | In **S** (put it on the projector for a moment): `./demo show` | "This isn't a video or a mock-up. Every box here is its own container on one isolated network with no internet: three decoys, Mirage's controller, a real staff website, normal employee traffic, and three hacker machines, each with its own IP." |
| 1:00 | Point at the dashboard map | "These three bases look like a company website, a deploy server and cloud storage. **All three are fake.** We planted a trail of fake passwords and keys inside them, like breadcrumbs, leading to a fake spreadsheet of passwords: the crown jewel." |
| 1:20 | Press **G** | "Top line: what's happening, in one sentence. This strip: the six baits, in order. The map: where each attacker is right now. Red is them, green is us." |
| 1:45 | Press **G** again | "First, Mirage will only **watch**, so you can see how far a real attacker gets." |

### While the attack runs: lines to fill the countdowns

- **Point at the grey `$ …` lines in the hacker terminal:** "These are the real commands it's running: nmap, gobuster, hydra, ssh, the AWS command line. Real tools, real network traffic."
- "Every decoy reports to Mirage in under a millisecond. That's why the map moves the instant the terminal does."
- "The red diamond is how air-defence radars mark a hostile aircraft. Each attacker gets a track ID, a trail, and a heading toward its next target."
- "No real user ever has a reason to read robots.txt or open a backup file. Touching bait is proof of bad intent, so there are no false alarms."
- "The threat score rises with every bait: at 40 Mirage slows the attacker down, at 75 it blocks it everywhere."
- "Everything the attacker sees as a win is something we wrote for them."

---

## Act 1 · How far an attacker gets (observe mode, about 2:30)

**Hacker types in H:** `./demo attack --pause 12`, then hands off the keyboard.

| Time | Hacker screen (by itself) | Dashboard | Defender says during the countdown |
|---|---|---|---|
| 2:00 | **GHOSTLINE** banner, the objective, "operation starts" countdown | — | "This is the attacker's toolkit. Its goal is the finance spreadsheet." |
| 2:05 | **Phase 1 · Recon**: 3 machines, 3 open ports | nothing | "A port scan touches no decoy service, so Mirage stays quiet. No false alarms." |
| 2:20 | **Phase 2 · Enumerate**: `/backup`, `/login`, `/robots.txt` | **T-01 flies in**, "New hostile contact" | "The moment it touches a decoy it becomes a tracked target. Nobody legitimate touches these." |
| 2:35 | **Phase 3**: `Disallow: /backup/` | chain **1** red, banner "Stage 1 of 6" | "That hint was planted. Bait one." |
| 2:50 | **Phase 4**: **★ LOOT** SSH password | chain **2**, track turns **amber "Slowed"** | "It stole a password we wrote for it, and Mirage is already slowing it down." |
| 3:05 | **Phase 5**: hydra fails, then the leaked password works | track flies to the **SSH server**, chain **3** | "It's on a server now. Also fake." |
| 3:20 | **Phase 6**: **★ LOOT** AWS keys | chain **4** | "Cloud keys, planted." |
| 3:35 | **Phase 7**: **★ LOOT** passwords.xlsx, **MISSION COMPLETE** | all 6 red, crown jewel **TAKEN** | "Left alone, it takes everything. **Now we switch the defence on, and send three attackers at once.**" |

## Switch (0:20, in S)

```bash
./demo active        # switches to auto-intercept and clears the board
```
The chip turns **"Auto-intercept on"** and the dashboard goes back to "Airspace clear". The Hacker types `clear` in H.

---

## Act 2 · Three attackers, Mirage fights back (active mode, about 2:00)

Start both within a second or two of each other:

| Who | Type |
|---|---|
| Hacker (H) | `./demo attack --pause 6` |
| Defender (S) | `./demo swarm 8` (hackers 2 and 3 join, 8 s apart, running in the background) |

| Time | Hacker screen | Dashboard | Say |
|---|---|---|---|
| 4:00 | Phases tick by with 6 s countdowns | **T-01**, then **T-02**, **T-03** fly in on their own lanes. "Tracking 3 hostiles". | "Three attackers from three machines. Mirage tracks each one separately." |
| ~4:35 | ★ password, then Phase 5 logs in to the server and reads the AWS keys | T-01's threat dial passes **75** | "The first one crosses the line…" |
| ~4:40 | In the countdown to Phase 6: **■ CONNECTION SEVERED ■**, then the big **MIRAGE** screen: *"THIS SYSTEM WAS NEVER REAL"* | At the same moment: **interceptor** from the radar, then **"Threat neutralized"** | "…intercepted automatically. No human pressed anything. It never got the keys out." |
| ~4:50 | Lockout sweep: web, SSH, S3 all **✖ BLOCKED**, then **MISSION FAILED** | Track table: T-01 intercepted, T-02 and T-03 still red | "Everything it took was bait, and it's now blocked everywhere." |
| ~5:20 | (hacker 1 is done) | T-02, then T-03 are intercepted. The takeover reads **"T-01, T-02, T-03 intercepted"**. | "And the other two, the same way. Three for three." |

---

## Act 3 · Finale: cut them off (1:00)

| Time | Who | Type | What happens | Say |
|---|---|---|---|---|
| 5:40 | Hacker (H) | `./demo watch` | **Uplink monitor**: web, SSH and S3 all **BLOCKED**, ticking every second | "The attacking machines are still on our network, rattling the doors." |
| 6:00 | Defender (S) | `./demo isolate` | Every line turns **NO ROUTE**, then **■ HOST ISOLATED ■** | "So we do what real security tools do with a compromised machine: isolate it. All three are cut off. Game over." |

---

## Wrap-up on the dashboard (1:30)

| Click | Say |
|---|---|
| Rail → **Engagement** | "Contact, detected in under a millisecond, took the bait, intercepted. Every step timed." |
| **Threat corridor** chart | "How deep they got, and exactly when we reacted." |
| Rail → **Alerts**, then the **Stolen** and **ATT&CK** tabs | "Every alert, every bait taken, mapped to MITRE ATT&CK. That's the evidence for the security team." |
| Rail → **Overview** | "Fake systems, planted bait, automatic interception. That's Mirage." |

## After the demo (in S)

```bash
./demo restore
./demo down
```

---

## If something goes wrong

| Problem | Fix (in S) |
|---|---|
| The attack goes straight to MISSION FAILED | still blocked from the last run: `./demo reset` |
| Every phase says no route | still isolated: `./demo reset` (it reconnects them too) |
| Act 1 gets intercepted (the terminal said **● ACTIVE**) | wrong mode: `./demo observe`, then start the attack again |
| `swarm` says "no extra hackers" | `./demo hackers 3` |
| Dashboard says "Reconnecting" | the controller restarted after a mode switch; it reconnects within 3 s |
| Anything else | `./demo down`, `./demo up`, `./demo hackers 3`, `./demo reset` (about 40 s) |

## Cheat sheet

| Stage (S) | Hacker (H) | Dashboard keys |
|---|---|---|
| `./demo up` · `down` · `status` · `show` | `./demo attack --pause 12` (slow, to explain) | **G** guide labels |
| `./demo observe` · `active` (each also resets) | `./demo attack --pause 6` (normal) | **F** follow the track |
| `./demo reset` (clean slate, same mode) | `./demo attack --step` (Enter per phase) | **Esc** close overlays |
| `./demo hackers 3` · `swarm 8` | `./demo watch` (uplink monitor) | **Ctrl + scroll** zoom |
| `./demo isolate` · `restore` | | **Intercept now** / **Release** |
