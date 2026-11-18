"""Unit tests for the evaluation metric computations (no controller needed)."""

from __future__ import annotations

import metrics


def _events():
    return [
        {"src_ip": "10.66.0.50", "ts": "2026-11-06T12:00:00+00:00", "stage": 1, "techniques": ["T1595.003"]},
        {"src_ip": "10.66.0.50", "ts": "2026-11-06T12:00:04+00:00", "stage": 3, "techniques": ["T1078", "T1021.004"]},
        {"src_ip": "10.66.0.50", "ts": "2026-11-06T12:00:09+00:00", "stage": 6, "techniques": ["T1530"]},
        {"src_ip": "10.66.0.51", "ts": "2026-11-06T12:00:02+00:00", "stage": 0, "techniques": []},  # benign, never happens really
    ]


def _alerts():
    return [{"src_ip": "10.66.0.50", "ts": "2026-11-06T12:00:01+00:00"}]


def _responses():
    return [{"src_ip": "10.66.0.50", "ts": "2026-11-06T12:00:06+00:00", "action": "containment_sequence"}]


def test_time_to_detect():
    assert metrics.time_to_detect(_events(), _alerts()) == 1.0


def test_time_to_contain():
    # first event 12:00:00 -> containment 12:00:06
    a_events = [e for e in _events() if e["src_ip"] == "10.66.0.50"]
    assert metrics.time_to_contain(a_events, _responses()) == 6.0


def test_time_to_contain_none_when_not_contained():
    assert metrics.time_to_contain(_events(), []) is None


def test_coverage_counts_reference_hits():
    a_events = [e for e in _events() if e["src_ip"] == "10.66.0.50"]
    # seen: T1595.003, T1078, T1021.004, T1530  -> 4 of the reference set
    cov = metrics.coverage(a_events)
    assert abs(cov - 4 / len(metrics.REFERENCE_TECHNIQUES)) < 1e-9


def test_stage_reached():
    assert metrics.max_stage(_events()) == 6


def test_false_positives_zero_for_clean_benign():
    assert metrics.false_positives(_alerts(), {"10.66.0.51"}) == 0


def test_false_positives_counts_benign_alerts():
    alerts = _alerts() + [{"src_ip": "10.66.0.51", "ts": "2026-11-06T12:00:03+00:00"}]
    assert metrics.false_positives(alerts, {"10.66.0.51"}) == 1


def test_run_metrics_shape():
    r = metrics.run_metrics(_events(), _alerts(), _responses(), "10.66.0.50", {"10.66.0.51"}, 40)
    assert r["time_to_detect_s"] == 1.0
    assert r["time_to_contain_s"] == 6.0
    assert r["stage_reached"] == 6
    assert r["false_positive_alerts"] == 0
    assert r["false_positive_rate"] == 0.0


def test_aggregate_mean_and_sd():
    runs = [
        {"time_to_detect_s": 1.0, "time_to_contain_s": 6.0, "attack_coverage": 0.5,
         "stage_reached": 6, "false_positive_rate": 0.0, "false_positive_alerts": 0},
        {"time_to_detect_s": 3.0, "time_to_contain_s": 8.0, "attack_coverage": 0.5,
         "stage_reached": 6, "false_positive_rate": 0.0, "false_positive_alerts": 0},
    ]
    agg = metrics.aggregate(runs)
    assert agg["runs"] == 2
    assert agg["time_to_detect_s"]["mean"] == 2.0
    assert agg["time_to_contain_s"]["mean"] == 7.0
    assert agg["total_false_positive_alerts"] == 0
