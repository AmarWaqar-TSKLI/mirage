IP = "10.66.0.50"

TRAIL = [
    dict(source="admin-panel", event_type="http_request", asset="/robots.txt", honeytoken_id="ht-robots-backup-link"),
    dict(source="admin-panel", event_type="file_access", asset="/backup/.env.bak", honeytoken_id="ht-env-backup-file"),
    dict(source="ssh", event_type="login_attempt", asset="deploy", honeytoken_id="ht-ssh-password",
         details={"username": "deploy", "success": True}),
    dict(source="ssh", event_type="file_access", asset="/home/deploy/.aws/credentials",
         honeytoken_id="ht-aws-credentials-file"),
    dict(source="s3", event_type="honeytoken_used", asset="AKIA...", honeytoken_id="ht-aws-access-key"),
    dict(source="s3", event_type="file_access", asset="corp-backups/finance/passwords.xlsx",
         honeytoken_id="ht-passwords-xlsx"),
]


def test_full_trail_advances_stage_and_alerts_each_token(client, send):
    for expected_stage, event in enumerate(TRAIL, start=1):
        send(src_ip=IP, **event)
        assert client.get(f"/api/attackers/{IP}").json()["max_stage"] == expected_stage

    alerts = client.get("/api/alerts").json()
    assert len(alerts) == 6
    assert {a["severity"] for a in alerts} == {"medium", "high", "critical"}
    attacker = client.get(f"/api/attackers/{IP}").json()
    assert attacker["event_count"] == 6
    assert len(attacker["tokens"]) == 6
    assert {"T1595.003", "T1552.001", "T1078.004", "T1530"} <= set(attacker["techniques"])


def test_stage_never_goes_backwards(client, send):
    send(src_ip=IP, **TRAIL[3])
    send(src_ip=IP, **TRAIL[0])
    assert client.get(f"/api/attackers/{IP}").json()["max_stage"] == 4


def test_alerts_are_deduplicated(client, send):
    first = send(src_ip=IP, source="admin-panel", event_type="http_request", asset="/admin")
    assert first["alert_id"] is not None  # first contact
    for path in ["/login", "/wp-admin", "/.git"]:
        assert send(src_ip=IP, source="admin-panel", event_type="http_request", asset=path)["alert_id"] is None

    assert send(src_ip=IP, **TRAIL[0])["alert_id"] is not None
    assert send(src_ip=IP, **TRAIL[0])["alert_id"] is None
    assert len(client.get("/api/alerts").json()) == 2


def test_labels(client, send):
    send(src_ip=IP, source="ssh", event_type="command", details={"command": "id"}, attack_techniques=["T1033"])
    event = client.get("/api/events").json()[0]
    assert event["techniques"] == ["T1033", "T1059.004"]
    assert event["engage"] == ["System Activity Monitoring"]

    send(src_ip=IP, **TRAIL[1])
    event = client.get("/api/events", params={"limit": 1}).json()[0]
    assert event["techniques"] == ["T1552.001"]
    assert event["engage"] == ["Network Monitoring", "Lures"]


def test_unknown_honeytoken_is_stored_without_stage(client, send):
    send(src_ip=IP, source="s3", event_type="file_access", honeytoken_id="ht-made-up")
    assert client.get("/api/events").json()[0]["stage"] == 0


def test_attackers_are_tracked_separately(client, send):
    send(src_ip=IP, **TRAIL[2])
    send(src_ip="10.66.0.51", **TRAIL[0])
    stages = {a["ip"]: a["max_stage"] for a in client.get("/api/attackers").json()}
    assert stages == {IP: 3, "10.66.0.51": 1}
    assert len(client.get("/api/events", params={"ip": IP}).json()) == 1
    assert client.get("/api/attackers/10.66.0.99").status_code == 404
