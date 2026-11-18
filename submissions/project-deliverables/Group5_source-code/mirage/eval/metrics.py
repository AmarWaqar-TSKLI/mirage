"""Compute Mirage's evaluation metrics from the controller's own records.

Reads events, alerts, responses and attacker state (from the controller API, or
a SQLite copy) and reports, for one run or aggregated across runs:

  time to detect     first event from the attacker  ->  first alert
  time to contain     first event from the attacker  ->  containment response
  false-positive rate  alerts raised against benign source IPs
  ATT&CK coverage      distinct techniques seen  /  the campaign's reference set
  stage reached        how far along the 6-stage trail the attacker got

Run with -I so a planted module on the path cannot shadow the stdlib.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import urllib.request
from datetime import datetime
from pathlib import Path

# Techniques the full scripted campaign is designed to exercise. Coverage is
# measured against this reference set, not against all of ATT&CK.
REFERENCE_TECHNIQUES = [
    "T1595.003",   # wordlist scanning (gobuster)
    "T1552.001",   # credentials in files (.env, ~/.aws/credentials)
    "T1110",       # brute force (hydra)
    "T1078",       # valid accounts (ssh login)
    "T1021.004",   # remote services: SSH
    "T1078.004",   # valid accounts: cloud (S3 keys)
    "T1530",       # data from cloud storage (passwords.xlsx)
    "T1083",       # file & directory discovery (recon)
    "T1552.003",   # bash history
]


def _parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def _seconds(a: str, b: str) -> float:
    return (_parse(b) - _parse(a)).total_seconds()


def time_to_detect(events: list[dict], alerts: list[dict]) -> float | None:
    if not events or not alerts:
        return None
    return _seconds(min(e["ts"] for e in events), min(a["ts"] for a in alerts))


def time_to_contain(events: list[dict], responses: list[dict]) -> float | None:
    contains = [r for r in responses if r.get("action") == "containment_sequence"]
    if not events or not contains:
        return None
    return _seconds(min(e["ts"] for e in events), min(r["ts"] for r in contains))


def techniques_seen(events: list[dict]) -> set[str]:
    seen: set[str] = set()
    for e in events:
        seen.update(e.get("techniques") or [])
    return seen


def coverage(events: list[dict], reference: list[str] = REFERENCE_TECHNIQUES) -> float:
    seen = techniques_seen(events)
    hit = sum(1 for t in reference if t in seen)
    return hit / len(reference) if reference else 0.0


def false_positives(alerts: list[dict], benign_ips: set[str]) -> int:
    return sum(1 for a in alerts if a.get("src_ip") in benign_ips)


def max_stage(events: list[dict]) -> int:
    return max((int(e.get("stage") or 0) for e in events), default=0)


def run_metrics(events, alerts, responses, attacker_ip, benign_ips, benign_requests) -> dict:
    a_events = [e for e in events if e.get("src_ip") == attacker_ip]
    a_alerts = [a for a in alerts if a.get("src_ip") == attacker_ip]
    a_resp = [r for r in responses if r.get("src_ip") == attacker_ip]
    fp = false_positives(alerts, benign_ips)
    return {
        "attacker_ip": attacker_ip,
        "time_to_detect_s": time_to_detect(a_events, a_alerts),
        "time_to_contain_s": time_to_contain(a_events, a_resp),
        "stage_reached": max_stage(a_events),
        "attack_coverage": round(coverage(a_events), 3),
        "techniques_seen": sorted(techniques_seen(a_events)),
        "false_positive_alerts": fp,
        "benign_requests": benign_requests,
        "false_positive_rate": round(fp / benign_requests, 4) if benign_requests else 0.0,
    }


# ----------------------------------------------------------------- fetching

def _get(api: str, path: str) -> list[dict]:
    with urllib.request.urlopen(f"{api.rstrip('/')}{path}", timeout=5) as r:
        return json.loads(r.read())


def from_api(api: str, attacker_ip: str, benign_ips: set[str], benign_requests: int) -> dict:
    events = _get(api, "/api/events?limit=100000")
    alerts = _get(api, "/api/alerts?limit=100000")
    responses = _get(api, "/api/responses?limit=100000")
    return run_metrics(events, alerts, responses, attacker_ip, benign_ips, benign_requests)


# -------------------------------------------------------------- aggregation

def _stat(values: list[float]) -> dict:
    vals = [v for v in values if v is not None]
    if not vals:
        return {"mean": None, "sd": None, "n": 0}
    return {
        "mean": round(statistics.mean(vals), 3),
        "sd": round(statistics.pstdev(vals), 3) if len(vals) > 1 else 0.0,
        "n": len(vals),
    }


def aggregate(runs: list[dict]) -> dict:
    return {
        "runs": len(runs),
        "time_to_detect_s": _stat([r["time_to_detect_s"] for r in runs]),
        "time_to_contain_s": _stat([r["time_to_contain_s"] for r in runs]),
        "attack_coverage": _stat([r["attack_coverage"] for r in runs]),
        "stage_reached": _stat([float(r["stage_reached"]) for r in runs]),
        "false_positive_rate": _stat([r["false_positive_rate"] for r in runs]),
        "total_false_positive_alerts": sum(r["false_positive_alerts"] for r in runs),
    }


def markdown(agg: dict) -> str:
    def fmt(s):
        return "n/a" if s["mean"] is None else f"{s['mean']} ± {s['sd']} (n={s['n']})"
    return (
        f"| Metric | Result |\n|---|---|\n"
        f"| Runs | {agg['runs']} |\n"
        f"| Mean time to detect (s) | {fmt(agg['time_to_detect_s'])} |\n"
        f"| Mean time to contain (s) | {fmt(agg['time_to_contain_s'])} |\n"
        f"| ATT&CK coverage | {fmt(agg['attack_coverage'])} |\n"
        f"| Trail stage reached | {fmt(agg['stage_reached'])} |\n"
        f"| False-positive rate | {fmt(agg['false_positive_rate'])} |\n"
        f"| Total false-positive alerts | {agg['total_false_positive_alerts']} |\n"
    )


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Mirage evaluation metrics")
    p.add_argument("--api", default="http://127.0.0.1:8000")
    p.add_argument("--attacker", default="10.66.0.50")
    p.add_argument("--benign", default="10.66.0.51", help="comma-separated benign source IPs")
    p.add_argument("--benign-requests", type=int, default=0)
    p.add_argument("--out", help="write this run's JSON here")
    p.add_argument("--aggregate", nargs="+", help="JSON result files to summarise instead")
    args = p.parse_args(argv)

    if args.aggregate:
        runs = [json.loads(Path(f).read_text()) for f in args.aggregate]
        agg = aggregate(runs)
        print(json.dumps(agg, indent=2))
        print("\n" + markdown(agg))
        return 0

    benign_ips = {ip.strip() for ip in args.benign.split(",") if ip.strip()}
    result = from_api(args.api, args.attacker, benign_ips, args.benign_requests)
    print(json.dumps(result, indent=2))
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
