from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from mirage_common import TOKEN_HEADER

TOKEN = "test-token"
HONEYTOKENS = Path(__file__).parents[2] / "config" / "honeytokens.json"


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("MIRAGE_INGEST_TOKEN", TOKEN)
    monkeypatch.setenv("MIRAGE_DB_PATH", str(tmp_path / "mirage.db"))
    monkeypatch.setenv("MIRAGE_HONEYTOKENS", str(HONEYTOKENS))
    with TestClient(app) as c:
        yield c


@pytest.fixture
def send(client):
    def _send(**event):
        r = client.post("/api/events", json=event, headers={TOKEN_HEADER: TOKEN})
        assert r.status_code == 202, r.text
        return r.json()
    return _send
