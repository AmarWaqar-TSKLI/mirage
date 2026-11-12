# Mirage live demo playbook

About **12 minutes**. Two people: the **Defender**, who narrates and drives the dashboard, and the **Hacker**, who types on the attacker machine. One laptop is enough.

Every command here has been run against the lab. The hacker uses real tools (nmap, gobuster, hydra, curl, ssh, aws). Nothing on either screen is faked.

---

## The screens

| Where | What | Who |
|---|---|---|
| **Projector, left half** | Dashboard at <http://127.0.0.1:8000/> | Defender |
| **Projector, right half** | Terminal **H** (hacker), big font (Ctrl + `+` a few times) | Hacker |
| **Laptop only, off the projector** | Terminal **S** (stage), for the `./demo …` commands | Defender |

Both terminals start in the repo folder: `cd ~/Projects/IS_Project`

---

## 30 minutes before

```bash
sudo systemctl start docker
./demo up              # starts the lab, prints the dashboard address and the mode
./demo status          # all 7 containers "Up", attacker "connected"
```
- Open the dashboard in Chrome, full screen (F11), zoom 90 % if the map is cut off.
- Do one full practice run of Acts 1 to 3, then `./demo reset`.
- Close every notification on the laptop.

## 1 minute before

| Terminal | Type | Leave it waiting at |
|---|---|---|
| S | `./demo observe` then `./demo reset` | |
| H | `./demo hacker` | the hacker prompt `root@…:/#` |

The dashboard should say **"Airspace clear"**.

---

## Act 0 · What Mirage is (1:00)

| Time | Defender does | Screen shows | Say |
|---|---|---|---|
| 0:00 | Nothing | Dashboard: "Airspace clear", the radar sweeping | "This is a company network. These three boxes look like a website, a server and cloud storage. **All three are fake.** They are decoys, and we planted fake passwords and keys inside them like breadcrumbs." |
| 0:30 | Press **G** | Numbered labels on every panel | "The top tells you what is happening in one sentence. This strip is the six baits an attacker has to take, in order. The map shows them moving. Green is us, red is them." |
| 0:55 | Press **G** again | Labels gone | "Let's watch a real attacker walk in. First we let Mirage only **watch**, so you can see how far a real attacker would get." |

---

## Act 1 · How far an attacker gets (observe mode, 4:00)

The Hacker types `op` in **H** and presses **Enter** once to start. After that, press **Enter** only when the Defender has finished talking.

| Time | Hacker presses Enter for | Hacker screen | Dashboard | Defender says |
|---|---|---|---|---|
| 1:00 | *start* | Big **GHOSTLINE** banner, the objective | nothing yet | "This is the attacker's toolkit. The goal is the finance spreadsheet." |
| 1:15 | **Phase 1 · Recon** | 3 machines found, ports 80, 22, 9000 | nothing | "A port scan alone touches no decoy service, so Mirage stays quiet. No false alarms." |
| 1:35 | **Phase 2 · Enumerate** | gobuster finds `/backup`, `/login`, `/robots.txt` | **Red diamond T-01 flies in**, "New hostile contact" banner, Admin panel turns red | "The moment it touches a decoy, it becomes a tracked target. Nobody legitimate ever touches these." |
| 2:05 | **Phase 3 · Breadcrumb** | `Disallow: /backup/` | Chain step **1** red, banner "Stage 1 of 6" | "That hint was planted. Bait one." |
| 2:30 | **Phase 4 · Loot** | **★ LOOT +1** SSH password | Step **2** red, the track turns **amber "Slowed"** | "It just stole a password we wrote for it. Look, Mirage is already slowing it down." |
| 3:00 | **Phase 5 · Breach** | hydra fails, then `shell as deploy@ops-deploy-01` | Track flies to the **SSH server**, step **3** | "It's on a server now. Except the server isn't real either." |
| 3:30 | **Phase 6 · Pivot** | **★ LOOT +1** AWS keys | Step **4** | "Cloud keys, also planted." |
| 3:50 | **Phase 7 · Exfil** | bucket listing, **★ LOOT +1** passwords.xlsx, **MISSION COMPLETE** | All 6 steps red, track reaches the **crown jewel**, which turns **TAKEN** | "In observe mode it took everything, in under 10 seconds of tool time. Every step is on our screen. **Now let's turn the defence on.**" |

## Between acts (0:30)

| Terminal | Type |
|---|---|
| S | `./demo active` then `./demo reset` |
| H | `clear` |

The dashboard goes back to "Airspace clear" by itself and the top chip reads **"Auto-intercept on"**.

---

## Act 2 · Mirage fights back (active mode, 3:00)

To keep it tight, the Hacker runs it straight through: `op --auto`. Use `op` instead if you want to talk over each phase again.

| Time | Hacker screen | Dashboard | Defender says |
|---|---|---|---|
| 5:30 | The same phases start racing past | T-01 flies in, the chain lights up step by step | "Same attacker, same tools. This time Mirage is allowed to act." |
| ~5:35 | Loot ★ password, ★ AWS keys | Threat dial climbs past **75** | "The threat score crosses 75…" |
| ~5:37 | **■ CONNECTION SEVERED ■**, then the big **MIRAGE** screen: *"THIS SYSTEM WAS NEVER REAL"* | **Interceptor** flies from the radar to T-01, then full screen **"Threat neutralized"** | "…and Mirage intercepts it automatically, in a few seconds, with no human involved." |
| 5:45 | Lockout sweep: web, SSH and S3 all **✖ BLOCKED**, then **MISSION FAILED** | (click to close the takeover) Chain shows the lime **BLOCKED** wall, steps 5 and 6 crossed out | "Everything it stole was bait. It is now blocked on every decoy at once. It never reached the real data." |

---

## Act 3 · The finale: cut the machine off (1:30)

| Time | Who | Type | What happens | Say |
|---|---|---|---|---|
| 6:30 | Hacker | `op watch` | **Uplink monitor**: three lines, all **BLOCKED**, updating every second | "The attacker's machine is still on our network, trying the doors." |
| 6:50 | Defender (S) | `./demo isolate` | Within a second every line becomes **NO ROUTE**, then **■ HOST ISOLATED ■** | "So we do what real defence tools do with a compromised machine: isolate it. It's cut off from everything. The operation is over." |

---

## Wrap-up on the dashboard (1:30)

| Time | Click | Say |
|---|---|---|
| 8:00 | Rail → **Engagement** | "First contact, detected in under a millisecond, took the bait, intercepted. The full timeline, measured." |
| 8:30 | **Threat corridor** chart, hover the points | "How deep it got, and exactly when we reacted." |
| 9:00 | Rail → **Alerts**, then the **Stolen** and **ATT&CK** tabs | "Every alert, which baits were taken, and the attack techniques mapped to MITRE ATT&CK. This is the evidence for the security team." |
| 9:30 | Rail → **Overview** | "Fake systems, planted bait, automatic interception. That's Mirage." |

## After the demo
```bash
./demo restore     # plug the attacker back in
./demo down        # stop the lab
```

---

## If something goes wrong

| Problem | Fix |
|---|---|
| Dashboard stuck on old data | `./demo reset` (in S). The page clears itself within 5 s, or press F5. |
| `op` goes straight to MISSION FAILED | The attacker is still blocked from the last run: `./demo reset` |
| Every phase fails with no route | The attacker is still isolated: `./demo restore` |
| Act 1 gets intercepted | You are in active mode: `./demo observe`, then `./demo reset` |
| Dashboard says "Reconnecting" | The controller restarted (mode switch). Wait 3 s, it reconnects by itself. |
| Something is really broken | `./demo down`, then `./demo up`, then `./demo reset` (about 30 s) |

## Cheat sheet

| Stage (S) | Hacker (H) | Dashboard |
|---|---|---|
| `./demo up` start | `./demo hacker` open the hacker shell | **G** guide labels |
| `./demo reset` clean slate | `op` guided attack | **F** follow the track |
| `./demo observe` watch only | `op --auto` full speed | **Ctrl + scroll** zoom the map |
| `./demo active` auto-intercept | `op watch` uplink monitor | **Esc** close overlays |
| `./demo isolate` / `restore` | | **Intercept now** / **Release** buttons |
| `./demo status` / `down` | | |
