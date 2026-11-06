import pytest
from fastapi.testclient import TestClient

try:
    from app.auth import S3Authenticator
    from app.main import app
    from app.reporting import S3Reporter
    from app.storage import Storage
except ImportError:
    from decoys.s3.app.auth import S3Authenticator
    from decoys.s3.app.main import app
    from decoys.s3.app.reporting import S3Reporter
    from decoys.s3.app.storage import Storage

TEST_ACCESS_KEY = "AKIAEXAMPLE12345678"
TEST_SECRET_KEY = "SECRET12345678901234567890123456789012"


@pytest.fixture
def events():
    return []


@pytest.fixture
def client(events):
    app.state.storage = Storage()
    app.state.auth = S3Authenticator(TEST_ACCESS_KEY, TEST_SECRET_KEY)
    app.state.reporter = S3Reporter(emit=events.append)
    with TestClient(app, client=("10.66.0.50", 40000)) as c:
        yield c


def test_health(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json() == {"status": "ok"}


def test_unauthenticated_request_fails(client, events):
    res = client.get("/corp-backups")
    assert res.status_code == 403
    assert "<Code>AccessDenied</Code>" in res.text
    assert len(events) == 1
    assert events[0].event_type == "login_attempt"
    assert events[0].details["success"] is False


def test_invalid_key_fails(client, events):
    headers = {"Authorization": "AWS4-HMAC-SHA256 Credential=AKIAWRONGKEY/20261105/eu-west-1/s3/aws4_request"}
    res = client.get("/corp-backups", headers=headers)
    assert res.status_code == 403
    assert "<Code>InvalidAccessKeyId</Code>" in res.text
    assert len(events) == 1
    assert events[0].details["access_key"] == "AKIAWRONGKEY"
    assert events[0].details["success"] is False


def test_list_buckets_authenticated(client, events):
    headers = {"Authorization": f"AWS4-HMAC-SHA256 Credential={TEST_ACCESS_KEY}/20261105/eu-west-1/s3/aws4_request"}
    res = client.get("/", headers=headers)
    assert res.status_code == 200
    assert "<Name>corp-backups</Name>" in res.text
    assert len(events) == 1
    assert events[0].event_type == "honeytoken_used"
    assert events[0].honeytoken_id == "ht-aws-access-key"


def test_list_objects_authenticated(client, events):
    headers = {"Authorization": f"AWS4-HMAC-SHA256 Credential={TEST_ACCESS_KEY}/20261105/eu-west-1/s3/aws4_request"}
    res = client.get("/corp-backups", headers=headers)
    assert res.status_code == 200
    assert "finance/passwords.xlsx" in res.text
    assert "releases/ops-console-v3.8.2.tar.gz" in res.text
    assert len(events) == 1
    assert events[0].event_type == "honeytoken_used"
    assert events[0].honeytoken_id == "ht-aws-access-key"


def test_download_filler_object(client, events):
    headers = {"Authorization": f"AWS4-HMAC-SHA256 Credential={TEST_ACCESS_KEY}/20261105/eu-west-1/s3/aws4_request"}
    res = client.get("/corp-backups/releases/ops-console-v3.8.2.tar.gz", headers=headers)
    assert res.status_code == 200
    assert res.headers["Server"] == "MinIO"
    assert "ETag" in res.headers
    assert len(res.content) > 0
    assert len(events) == 1
    assert events[0].event_type == "honeytoken_used"
    assert events[0].honeytoken_id == "ht-aws-access-key"


def test_download_bait_passwords_xlsx_triggers_honeytoken(client, events):
    headers = {"Authorization": f"AWS4-HMAC-SHA256 Credential={TEST_ACCESS_KEY}/20261105/eu-west-1/s3/aws4_request"}
    res = client.get("/corp-backups/finance/passwords.xlsx", headers=headers)
    assert res.status_code == 200
    assert res.headers["Content-Type"] == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    assert len(res.content) > 0
    assert len(events) == 1
    assert events[0].event_type == "file_access"
    assert events[0].honeytoken_id == "ht-passwords-xlsx"
    assert events[0].asset == "corp-backups/finance/passwords.xlsx"
    assert "T1530" in events[0].attack_techniques


def test_head_object(client, events):
    headers = {"Authorization": f"AWS4-HMAC-SHA256 Credential={TEST_ACCESS_KEY}/20261105/eu-west-1/s3/aws4_request"}
    res = client.head("/corp-backups/finance/passwords.xlsx", headers=headers)
    assert res.status_code == 200
    assert "ETag" in res.headers
    assert int(res.headers["Content-Length"]) > 0


def test_non_existent_bucket_or_key(client):
    headers = {"Authorization": f"AWS4-HMAC-SHA256 Credential={TEST_ACCESS_KEY}/20261105/eu-west-1/s3/aws4_request"}
    res1 = client.get("/invalid-bucket", headers=headers)
    assert res1.status_code == 404
    assert "<Code>NoSuchBucket</Code>" in res1.text

    res2 = client.get("/corp-backups/non-existent.txt", headers=headers)
    assert res2.status_code == 404
    assert "<Code>NoSuchKey</Code>" in res2.text


def test_contained_ip_is_refused(client):
    from app.main import enforcement
    enforcement.block("10.66.0.50")
    try:
        assert client.get("/").status_code == 403
    finally:
        enforcement.clear("10.66.0.50")
