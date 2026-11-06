# Steps 7-8: Dashboard and Evaluation

Owner: Hussain. Steps 1-4 (Amar) and 5-6 (Haseeb) are in `dev`. This is the last 25%.
Status board stays in [PROGRESS.md](PROGRESS.md). The build plan is [plan.md](plan.md).

## Problem

The pipeline works up to the controller, but nobody can see it, and nothing proves it.
A defender has to `curl` JSON to know an attacker is on the trail. The proposal promises
two things we have not delivered yet:

- a live page where the trail, the techniques and each containment step light up as they happen (proposal 3.5, 3.6)
- numbers: time to detect, time to contain, false alarm rate, ATT&CK coverage, from a scripted attack next to normal users (proposal 3.7)

Research also found that step 6 containment does not actually stop the attacker in the live lab
(details in plan.md, "Broken nearby"). Time to contain is meaningless until it does.

## Must be true when done

### Dashboard (step 7)
- [ ] `http://127.0.0.1:8000/` on the host opens one page, served by the controller, no build step, no CDN.
- [ ] The page loads current state over REST, then updates live over a WebSocket with no refresh.
- [ ] It shows: live event feed, each attacker's progress over the 6 trail stages with risk score and playbook, credential theft events, ATT&CK techniques seen (ID and name), and the response log.
- [ ] When containment runs, each step (freeze, evict and notice, firewall ban, evidence) appears one after another in the response log as it happens.
- [ ] Events are ordered by event `timestamp`, not arrival order (decoys send out of order).
- [ ] Every attacker-controlled string (usernames, passwords, commands, paths, user agents) is rendered as text. Putting `<script>` in a user agent does nothing.
- [ ] From the attacker container (10.66.0.50), `/`, `/ws` and every `/api/*` path except `POST /api/events` return 404. The attacker cannot read its own profile or uncontain itself.
- [ ] Manual Contain and Release buttons work from the page and are refused without the operator header.

### Evaluation (step 8)
- [ ] `docker compose --profile eval up` adds an attacker container at 10.66.0.50 with nmap, gobuster, hydra, curl, sshpass and the AWS CLI built in. The lab stays internal.
- [ ] One command runs the scripted campaign that walks the full trail: scan, enumerate, brute force, robots.txt, .env, SSH login, recon, AWS keys, S3 listing, passwords.xlsx download.
- [ ] The AWS CLI really works against the S3 decoy (`aws s3 ls` and `aws s3 cp`), not only hand-built headers.
- [ ] A benign traffic generator runs at the same time, acting like normal users against a real (non-decoy) internal service.
- [ ] `eval/run.sh N` resets the controller, runs N campaigns plus benign traffic, and writes results to `eval/results/`.
- [ ] A metrics script reports, per run and as mean and standard deviation: time to detect, time to contain, false positive rate, ATT&CK technique coverage, and the trail stage where the attacker was stopped.
- [ ] Two modes: `observe` (containment off, measures full-trail detection and coverage) and `active` (containment on, measures time to contain and how far the attacker gets).
- [ ] In `active` mode, after containment the attacker's next SSH, HTTP and S3 requests fail. The campaign log shows where it got stopped.
- [ ] Results tables are ready to paste into the final report.

### Containment that contains (gap in step 6, needed by step 8)
- [ ] A ban drops the attacker's packets at the decoys with nftables, and expires on its own after the ban time.
- [ ] Tarpit actually slows the attacker, and the tarpit response is logged.
- [ ] Containment kicks the SSH session even when it fires at login, before the session is registered.
- [ ] The response log says `simulated` honestly anywhere an action did not really happen.

## Out of scope
- Any response that reaches outside the lab or touches the attacker's own machine (proposal 3.8).
- Mounting the Docker socket into the controller. It is reachable from the lab, so that would hand an attacker root on the host.
- Auth and user accounts on the dashboard. It is host-only by network.
- A React or Vite build. One HTML file, one JS file, one CSS file.
- New decoys or new trail stages.
- Real cloud accounts or real secrets, ever.

## Open questions
1. **Who fixes the step 6 containment gaps?** They are in Haseeb's code, but step 8 cannot measure time to contain without them. Recommendation: send Haseeb the list in plan.md today; if it is not fixed by the time Phase 1 is done, take it as Phase 4.
2. **Is the LLM shell on you too?** PROGRESS.md marks it optional, but the proposal's abstract and objective 3 promise it. Recommendation: do it last (Phase 6) only if steps 7-8 are done with time left, and ask the group who owns it now.
3. **Deadline and demo date?** Not in the repo. Sets whether Phase 6 happens and how many evaluation runs we do (recommend 10 per mode).
4. **Kali or Debian for the attacker image?** Proposal says "such as Kali". Recommendation: `debian:bookworm-slim`, all six tools are in its repos and the image is much smaller. Mention Kali-equivalent in the report.
