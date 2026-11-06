# Evaluation results

Run 2026-11-06 in the Docker lab (`eval/run.sh 5 <mode>`), 5 measured campaigns
per mode after one discarded warmup, 40 benign requests per run. Full scripted
campaign: nmap, gobuster, hydra, sshpass SSH login, recon, `aws s3 ls/cp`, bait
download. Benign traffic hits the non-decoy `legit` site only. Metrics are
computed from the controller's own records.

These numbers are from after the controller store fix (concurrent reads could
corrupt attacker state; see "Notes"). The controller logged 0 failed ingests
across both modes.

## Observe mode (automatic response off)

Measures how much of the attack Mirage sees when it never interferes.

| Metric | Result |
|---|---|
| Runs | 5 |
| Mean time to detect | 0.009 s ± 0.008 |
| Mean time to contain | n/a (containment off) |
| ATT&CK coverage | 1.00 ± 0.00 |
| Trail stage reached | 6.0 / 6 ± 0.0 |
| False-positive rate | 0.00 |
| Total false-positive alerts | 0 |

The attacker walks the whole trail every time (stage 6), Mirage raises the first
alert within about 10 ms of first contact, and sees 100% of the campaign's
reference ATT&CK techniques.

## Active mode (automatic response on)

Measures how fast Mirage contains, and how far the attacker gets before it does.

| Metric | Result |
|---|---|
| Runs | 5 |
| Mean time to detect | 0.020 s ± 0.026 |
| Mean time to contain | 1.33 s ± 0.16 |
| ATT&CK coverage | 0.73 ± 0.09 |
| Trail stage reached | 3.2 / 6 ± 0.4 |
| False-positive rate | 0.00 |
| Total false-positive alerts | 0 |

With response on, the attacker is contained in about 1.3 s and stopped around
stage 3 (SSH login), never reaching the S3 bucket or the bait (stage 6 in observe
vs 3.2 here). After containment, the attacker's next requests fail: admin panel
and S3 return 403, and SSH re-login with the leaked password is refused.

## Notes
- The first campaign after bring-up pays cold-start cost, so `run.sh` does one
  discarded warmup campaign before the measured runs.
- Time to contain is first event to containment, so it includes the attacker's
  own enumeration time. Detection (first event to first alert) is under 50 ms
  in every run.
- False-positive rate is 0 because benign users only touch the real `legit`
  site, never a decoy, which is the whole point of deception-based detection.
- An earlier run of this evaluation (before the store fix) reported containment
  at 1.51 s ± 0.65. The controller then shared one SQLite connection between
  threads with unlocked reads, which could reset an attacker's record mid-attack
  and add variance to when containment fired. Every store access is now locked;
  the regression test is `controller/tests/test_concurrency.py`.
