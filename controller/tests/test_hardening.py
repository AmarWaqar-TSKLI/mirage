"""Operator key, per-decoy ingest tokens, and linking an intruder across addresses."""

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.store import Store
from mirage_common import TOKEN_HEADER

from .conftest import HONEYTOKENS, TOKEN
from .test_response import MockEnforcer, _attacker, _engine

OPERATOR = "operator-test-key"
THIEF, REUSER = "10.66.0.50", "10.66.0.77"


@pytest.fixture
def observe_client(monkeypatch, tmp_path):
    # Observe mode: nothing here may trigger a real containment (and a real docker commit).
    monkeypatch.setenv("MIRAGE_INGEST_TOKEN", TOKEN)
    monkeypatch.setenv("MIRAGE_OPERATOR_TOKEN", OPERATOR)
    monkeypatch.setenv("MIRAGE_RESPONSE_MODE", "observe")
    monkeypatch.setenv("MIRAGE_DB_PATH", str(tmp_path / "mirage.db"))
    monkeypatch.setenv("MIRAGE_HONEYTOKENS", str(HONEYTOKENS))
    with TestClient(app) as c:
        yield c


def _event(source, ip, **kw):
    return {"source": source, "event_type": kw.pop("event_type", "file_access"), "src_ip": ip, **kw}


# ------------------------------------------------------------- operator key

def test_controls_refuse_without_the_operator_key(observe_client):
    for path in ("/api/contain/10.66.0.50", "/api/uncontain/10.66.0.50", "/api/admin/reset"):
        assert observe_client.post(path).status_code == 401
        assert observe_client.post(path, headers={"X-Mirage-Operator": "wrong"}).status_code == 401


def test_reset_works_with_the_operator_key(observe_client):
    r = observe_client.post("/api/admin/reset", headers={"X-Mirage-Operator": OPERATOR})
    assert r.status_code == 200


def test_no_configured_key_means_no_control(observe_client, monkeypatch):
    monkeypatch.delenv("MIRAGE_OPERATOR_TOKEN")
    r = observe_client.post("/api/admin/reset", headers={"X-Mirage-Operator": ""})
    assert r.status_code == 401


# ------------------------------------------------------- per-decoy tokens

def test_a_decoy_token_only_speaks_for_its_own_decoy(observe_client, monkeypatch):
    monkeypatch.setenv("MIRAGE_TOKEN_SSH", "ssh-only")
    monkeypatch.setenv("MIRAGE_TOKEN_ADMIN_PANEL", "admin-only")
    post = lambda body, token: observe_client.post("/api/events", json=body, headers={TOKEN_HEADER: token})

    assert post(_event("ssh", THIEF, event_type="command"), "ssh-only").status_code == 202
    # The SSH decoy's token cannot forge an admin-panel event.
    assert post(_event("admin-panel", THIEF, asset="/"), "ssh-only").status_code == 403
    assert post(_event("admin-panel", THIEF, asset="/"), "admin-only").status_code == 202
    assert post(_event("admin-panel", THIEF, asset="/"), "nobody").status_code == 401


# -------------------------------------------- same intruder, new address

def test_reusing_a_stolen_credential_links_the_new_address(observe_client):
    send = lambda body: observe_client.post("/api/events", json=body, headers={TOKEN_HEADER: TOKEN})
    # The thief downloads the backup .env, which holds the SSH password ...
    send(_event("admin-panel", THIEF, asset="/backup/.env.bak", honeytoken_id="ht-env-backup-file"))
    # ... and a different address logs in with that password.
    send(_event("ssh", REUSER, event_type="login_attempt", asset="deploy",
                honeytoken_id="ht-ssh-password", details={"username": "deploy", "success": True}))

    reuser = observe_client.get(f"/api/attackers/{REUSER}").json()
    assert reuser["linked_to"] == THIEF
    assert reuser["max_stage"] == 3
    assert "ht-env-backup-file" in reuser["tokens"]          # inherits the thief's progress
    alerts = observe_client.get(f"/api/alerts?ip={REUSER}").json()
    assert alerts[0]["severity"] == "critical" and "reused" in alerts[0]["title"]
    assert observe_client.get(f"/api/attackers/{THIEF}").json()["linked_to"] is None


def test_the_thief_using_its_own_credential_is_not_a_link(observe_client):
    send = lambda body: observe_client.post("/api/events", json=body, headers={TOKEN_HEADER: TOKEN})
    send(_event("admin-panel", THIEF, asset="/backup/.env.bak", honeytoken_id="ht-env-backup-file"))
    send(_event("ssh", THIEF, event_type="login_attempt", honeytoken_id="ht-ssh-password"))
    assert observe_client.get(f"/api/attackers/{THIEF}").json()["linked_to"] is None


def test_containing_an_intruder_also_contains_its_other_addresses():
    store = Store(":memory:")
    store.upsert_attacker(_attacker(THIEF))
    store.upsert_attacker(_attacker(REUSER))
    store.add_link(REUSER, THIEF, "ht-ssh-password", "2026-11-18T12:00:00")
    enforcer = MockEnforcer()
    _engine(store, enforcer=enforcer).execute_containment(THIEF, reason="test")

    assert store.get_attacker(REUSER)["contained_at"] is not None
    assert ("block", REUSER) in enforcer.calls
