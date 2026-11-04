import os
import tempfile
from pathlib import Path

from mirage_common.honeytokens import generate

# The app loads the registry at import time, so generate fresh fake secrets first.
_TEMPLATE = Path(__file__).parents[3] / "config" / "honeytokens.json"
os.environ["MIRAGE_HONEYTOKENS"] = str(generate(_TEMPLATE, Path(tempfile.mkdtemp()) / "honeytokens.json"))

import pytest
from fastapi.testclient import TestClient

from app import main
from mirage_common import EventType


@pytest.fixture
def sent(monkeypatch):
    events = []
    monkeypatch.setattr(main, "emit", events.append)
    return events


@pytest.fixture
def client(sent):
    return TestClient(main.app, client=("10.66.0.50", 40000))


def test_every_request_is_reported_and_looks_like_nginx(client, sent):
    r = client.get("/wp-admin", headers={"User-Agent": "gobuster/3.6"})
    assert r.status_code == 404
    assert "nginx" in r.text and r.headers["server"].startswith("nginx")
    assert sent[0].event_type == EventType.HTTP_REQUEST
    assert sent[0].asset == "/wp-admin"
    assert sent[0].details["user_agent"] == "gobuster/3.6"
    assert sent[0].honeytoken_id is None


def test_framework_errors_do_not_leak(client, sent):
    for r in [client.post("/robots.txt"), client.get("/docs"), client.get("/openapi.json")]:
        assert r.status_code == 404
        assert "nginx" in r.text


def test_robots_points_to_backup_and_is_tagged(client, sent):
    r = client.get("/robots.txt")
    assert "Disallow: /backup/" in r.text
    assert sent[0].honeytoken_id == main.ROBOTS_TOKEN


def test_backup_listing_then_env_leaks_ssh_password(client, sent):
    assert ".env.bak" in client.get("/backup/").text
    assert sent[0].honeytoken_id is None

    body = client.get("/backup/.env.bak").text
    creds = main.registry.get(main.SSH_TOKEN).value
    assert f"DEPLOY_PASSWORD={creds['password']}" in body
    assert f"DEPLOY_HOST={creds['host']}" in body
    assert sent[1].event_type == EventType.FILE_ACCESS
    assert sent[1].honeytoken_id == main.ENV_TOKEN


def test_login_always_fails_and_records_credentials(client, sent):
    r = client.post("/login", data={"username": "admin", "password": "hunter2"})
    assert "Invalid username or password" in r.text
    assert sent[0].event_type == EventType.LOGIN_ATTEMPT
    assert sent[0].details == {**sent[0].details, "username": "admin", "password": "hunter2", "success": False}


def test_root_redirects_to_login(client, sent):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/login"
