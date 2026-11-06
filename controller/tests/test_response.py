import pytest

try:
    from app.playbooks import Allowlist, ResponsePolicy
    from app.response_engine import ResponseEngine
    from app.risk import (
        CONTAINMENT_THRESHOLD,
        TARPIT_THRESHOLD,
        Playbook,
        calculate_risk_score,
        evaluate_playbook,
    )
    from app.store import Store
except ImportError:
    from controller.app.playbooks import Allowlist, ResponsePolicy
    from controller.app.response_engine import ResponseEngine
    from controller.app.risk import (
        CONTAINMENT_THRESHOLD,
        TARPIT_THRESHOLD,
        Playbook,
        calculate_risk_score,
        evaluate_playbook,
    )
    from controller.app.store import Store


class MockEvictor:
    def __init__(self):
        self.kicked_ips = []

    def terminate_sessions(self, ip: str):
        self.kicked_ips.append(ip)
        return {"success": True, "terminated": 1}


class MockFirewall:
    def __init__(self):
        self.banned_ips = []

    def ban(self, ip: str, duration_seconds: int = 3600):
        self.banned_ips.append(ip)
        return {"backend": "mock", "success": True, "ip": ip}

    def unban(self, ip: str):
        if ip in self.banned_ips:
            self.banned_ips.remove(ip)
        return {"success": True, "ip": ip}

    def is_banned(self, ip: str):
        return ip in self.banned_ips


class MockSnapshots:
    def __init__(self):
        self.snapped = []

    def snapshot(self, container_name: str, src_ip: str):
        self.snapped.append((container_name, src_ip))
        return {"success": True, "image_tag": f"mock/{container_name}:{src_ip}"}


class MockEnforcer:
    def __init__(self):
        self.calls = []

    def block(self, ip, duration_seconds=0.0):
        self.calls.append(("block", ip))
        return {"mode": "block", "reached": ["ssh", "admin", "s3"], "failed": [], "decoys": 3}

    def tarpit(self, ip, delay_seconds):
        self.calls.append(("tarpit", ip))
        return {"mode": "tarpit", "reached": ["ssh", "admin", "s3"], "failed": [], "decoys": 3}

    def clear(self, ip):
        self.calls.append(("clear", ip))
        return {"mode": "clear", "reached": ["ssh", "admin", "s3"], "failed": [], "decoys": 3}


def _engine(store, **kw):
    kw.setdefault("evictor", MockEvictor())
    kw.setdefault("firewall", MockFirewall())
    kw.setdefault("snapshots", MockSnapshots())
    kw.setdefault("enforcer", MockEnforcer())
    return ResponseEngine(store=store, **kw)


def _attacker(ip="10.66.0.50", **over):
    base = {
        "ip": ip, "first_seen": "2026-11-06T12:00:00", "last_seen": "2026-11-06T12:05:00",
        "event_count": 10, "max_stage": 5, "risk_score": 90, "playbook": "watch",
        "contained_at": None, "techniques": ["T1078"], "tokens": ["ht-ssh-password"],
    }
    base.update(over)
    return base


def test_containment_blocks_every_decoy():
    store = Store(":memory:")
    enforcer = MockEnforcer()
    eng = _engine(store, enforcer=enforcer)
    store.upsert_attacker(_attacker(max_stage=5, risk_score=90))
    eng.execute_containment("10.66.0.50", reason="test")
    assert ("block", "10.66.0.50") in enforcer.calls
    saved = store.recent("responses", 10, "10.66.0.50")[0]
    assert saved["details"]["actions"]["enforcement"]["decoys"] == 3


def test_tarpit_pushes_tarpit_to_decoys():
    store = Store(":memory:")
    enforcer = MockEnforcer()
    eng = _engine(store, enforcer=enforcer)
    store.upsert_attacker(_attacker(max_stage=2, risk_score=50))
    eng.execute_tarpit("10.66.0.50", delay=2.0)
    assert ("tarpit", "10.66.0.50") in enforcer.calls


def test_uncontain_clears_block_and_state():
    store = Store(":memory:")
    enforcer = MockEnforcer()
    eng = _engine(store, enforcer=enforcer)
    store.upsert_attacker(_attacker(max_stage=6, risk_score=100))
    eng.execute_containment("10.66.0.50")
    assert store.get_attacker("10.66.0.50")["contained_at"] is not None
    eng.uncontain("10.66.0.50")
    assert ("clear", "10.66.0.50") in enforcer.calls
    assert store.get_attacker("10.66.0.50")["contained_at"] is None


def test_risk_score_calculation():
    # Stage 0, no tokens, no techniques
    assert calculate_risk_score(max_stage=0, techniques=[], tokens=[], event_count=1) == 0

    # Stage 1: robots.txt
    s1 = calculate_risk_score(max_stage=1, techniques=["T1595.003"], tokens=["ht-robots-backup-link"], event_count=1)
    assert s1 == 20  # 10 (stage) + 5 (technique) + 5 (token)

    # Stage 3: SSH login with multiple techniques
    s3 = calculate_risk_score(
        max_stage=3,
        techniques=["T1595.003", "T1552.001", "T1078", "T1021.004"],
        tokens=["ht-robots-backup-link", "ht-env-backup-file", "ht-ssh-password"],
        event_count=12,
    )
    # 45 (stage 3) + 20 (4 techniques) + 15 (3 tokens) + 2 (volume 12//5) = 82
    assert s3 == 82

    # Stage 6: Bait download caps at 100
    s6 = calculate_risk_score(
        max_stage=6,
        techniques=["T1595", "T1552", "T1078", "T1021", "T1059", "T1530"],
        tokens=["t1", "t2", "t3", "t4", "t5", "t6"],
        event_count=100,
    )
    assert s6 == 100


def test_playbook_thresholds():
    assert evaluate_playbook(15) == Playbook.WATCH
    assert evaluate_playbook(TARPIT_THRESHOLD) == Playbook.TARPIT
    assert evaluate_playbook(60) == Playbook.TARPIT
    assert evaluate_playbook(CONTAINMENT_THRESHOLD) == Playbook.CONTAIN
    assert evaluate_playbook(90) == Playbook.CONTAIN
    assert evaluate_playbook(10, previously_contained=True) == Playbook.CONTAIN


def test_defender_allowlist():
    allowlist = Allowlist({"10.66.0.1", "192.168.1.0/24"})
    assert allowlist.is_allowed("10.66.0.1") is True
    assert allowlist.is_allowed("192.168.1.50") is True
    assert allowlist.is_allowed("10.66.0.50") is False


def test_automated_containment_sequence():
    store = Store(":memory:")
    evictor = MockEvictor()
    firewall = MockFirewall()
    snapshots = MockSnapshots()
    response_engine = ResponseEngine(
        store=store,
        evictor=evictor,
        firewall=firewall,
        snapshots=snapshots,
    )

    attacker = {
        "ip": "10.66.0.50",
        "first_seen": "2026-11-05T12:00:00",
        "last_seen": "2026-11-05T12:05:00",
        "event_count": 10,
        "max_stage": 4,
        "risk_score": 80,
        "playbook": "watch",
        "contained_at": None,
        "techniques": ["T1078"],
        "tokens": ["ht-ssh-password"],
    }
    store.upsert_attacker(attacker)

    result = response_engine.handle(attacker, {"source": "ssh", "event_type": "command"})
    assert result is not None
    assert result["playbook"] == Playbook.CONTAIN

    # Verify actions triggered
    assert "10.66.0.50" in evictor.kicked_ips
    assert "10.66.0.50" in firewall.banned_ips
    assert len(snapshots.snapped) == 1

    # Verify database state
    updated_attacker = store.get_attacker("10.66.0.50")
    assert updated_attacker["contained_at"] is not None
    assert updated_attacker["playbook"] == Playbook.CONTAIN

    responses = store.recent("responses", limit=10, ip="10.66.0.50")
    assert len(responses) == 1
    assert responses[0]["action"] == "containment_sequence"
    assert responses[0]["status"] == "completed"


def test_allowlisted_attacker_is_never_contained():
    store = Store(":memory:")
    evictor = MockEvictor()
    firewall = MockFirewall()
    response_engine = ResponseEngine(
        store=store,
        allowlist=Allowlist({"10.66.0.1"}),
        evictor=evictor,
        firewall=firewall,
    )

    defender = {
        "ip": "10.66.0.1",
        "max_stage": 6,
        "risk_score": 100,
        "contained_at": None,
    }
    res = response_engine.handle(defender, {})
    assert res is None
    assert len(evictor.kicked_ips) == 0
    assert len(firewall.banned_ips) == 0
