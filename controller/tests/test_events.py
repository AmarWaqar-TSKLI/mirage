import pytest
from fastapi.testclient import TestClient

from app.main import EVENTS, app
from mirage_common import TOKEN_HEADER

TOKEN = "test-token"
EVENT = {"source": "admin-panel", "event_type": "http_request", "src_ip": "10.66.0.50", "asset": "/robots.txt"}


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("MIRAGE_INGEST_TOKEN", TOKEN)
    EVENTS.clear()
    return TestClient(app)


def test_ingest_valid_event(client):
    r = client.post("/api/events", json=EVENT, headers={TOKEN_HEADER: TOKEN})
    assert r.status_code == 202
    events = client.get("/api/events").json()
    assert len(events) == 1
    assert events[0]["asset"] == "/robots.txt"


def test_rejects_missing_or_wrong_token(client):
    assert client.post("/api/events", json=EVENT).status_code == 401
    assert client.post("/api/events", json=EVENT, headers={TOKEN_HEADER: "nope"}).status_code == 401
    assert EVENTS == []


@pytest.mark.parametrize("bad", [
    {**EVENT, "source": "ftp"},
    {**EVENT, "event_type": "explode"},
    {**EVENT, "src_ip": "not-an-ip"},
    {k: v for k, v in EVENT.items() if k != "src_ip"},
])
def test_rejects_malformed_event(client, bad):
    assert client.post("/api/events", json=bad, headers={TOKEN_HEADER: TOKEN}).status_code == 422
