"""End-to-end tests: a real paramiko client against the decoy on a local port."""

import json
import socket
import tempfile
import threading
import time
from pathlib import Path

import paramiko
import pytest

from app.server import AWS_FILE_TOKEN, BANNER, SSH_TOKEN, Decoy
from mirage_common import EventType, Registry
from mirage_common.honeytokens import generate

# Fresh fake secrets for this test run, generated from the committed template.
_TEMPLATE = Path(__file__).parents[3] / "config" / "honeytokens.json"
REGISTRY = Registry.load(generate(_TEMPLATE, Path(tempfile.mkdtemp()) / "honeytokens.json"))
CREDS = REGISTRY.get(SSH_TOKEN).value


@pytest.fixture
def decoy(tmp_path):
    events = []
    d = Decoy(REGISTRY, events.append, tmp_path)
    d.events = events
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    threading.Thread(target=d.serve, args=(sock,), daemon=True).start()
    d.port = sock.getsockname()[1]
    yield d
    sock.close()


def connect(decoy, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect("127.0.0.1", decoy.port, username=CREDS["username"], password=password,
                   allow_agent=False, look_for_keys=False, timeout=5)
    return client


def wait_for(events, event_type, timeout=3):
    end = time.time() + timeout
    while time.time() < end:
        found = [e for e in events if e.event_type == event_type]
        if found:
            return found
        time.sleep(0.05)
    raise AssertionError(f"no {event_type} event")


def test_wrong_password_is_rejected_and_reported(decoy):
    with pytest.raises(paramiko.AuthenticationException):
        connect(decoy, "wrong")
    attempt = wait_for(decoy.events, EventType.LOGIN_ATTEMPT)[0]
    assert attempt.details["success"] is False
    assert attempt.details["password"] == "wrong"
    assert attempt.honeytoken_id is None


def test_banner_looks_like_openssh(decoy):
    with socket.create_connection(("127.0.0.1", decoy.port)) as s:
        assert s.recv(256).decode().strip() == BANNER


def test_exec_session_reads_bait_and_is_reported(decoy):
    client = connect(decoy, CREDS["password"])
    _, stdout, _ = client.exec_command("cat ~/.aws/credentials")
    out = stdout.read().decode()
    assert "aws_access_key_id" in out
    assert stdout.channel.recv_exit_status() == 0
    client.close()

    wait_for(decoy.events, EventType.SESSION_END)
    by_type = {e.event_type: e for e in decoy.events}
    assert by_type[EventType.LOGIN_ATTEMPT].honeytoken_id == SSH_TOKEN
    assert by_type[EventType.COMMAND].details["command"] == "cat ~/.aws/credentials"
    assert "T1552.001" in by_type[EventType.COMMAND].attack_techniques
    assert by_type[EventType.FILE_ACCESS].honeytoken_id == AWS_FILE_TOKEN
    # All events from one session share a session id.
    assert len({e.session_id for e in decoy.events}) == 1


def test_interactive_session_is_recorded(decoy):
    client = connect(decoy, CREDS["password"])
    chan = client.invoke_shell()
    chan.send("whoami\rexit\r")
    chan.settimeout(5)
    out = b""
    while chunk := chan.recv(4096):  # read until the server closes the channel
        out += chunk
    client.close()
    text = out.decode()
    assert "Welcome to Ubuntu" in text and "deploy@ops-deploy-01:~$ " in text and "\r\ndeploy\r\n" in text

    end = wait_for(decoy.events, EventType.SESSION_END)[0]
    assert end.details["commands"] == 2
    recording = list((decoy.data_dir / "sessions").glob("*.jsonl"))[0].read_text().splitlines()
    records = [json.loads(l) for l in recording]
    assert records[0]["type"] == "header" and records[0]["username"] == "deploy"
    assert [r["data"] for r in records if r["type"] == "input"] == ["whoami", "exit"]


def test_port_forwarding_is_refused(decoy):
    client = connect(decoy, CREDS["password"])
    with pytest.raises(paramiko.ChannelException):
        client.get_transport().open_channel("direct-tcpip", ("10.66.0.31", 5432), ("127.0.0.1", 0))
    client.close()
