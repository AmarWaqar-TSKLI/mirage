"""The small read-only API endpoints."""

def test_mode_reports_active_by_default(client):
    assert client.get("/api/mode").json() == {"mode": "active"}
