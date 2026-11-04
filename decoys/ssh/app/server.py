"""SSH front end of the fake deploy server (trail stages 3 and 4).

Accepts only the password leaked in the admin panel's .env backup, then drops
the intruder into the scripted shell. Every login attempt, command and read of
the planted AWS credentials is reported to the controller, and each session is
recorded to disk as evidence.
"""

import json
import logging
import os
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import paramiko

from mirage_common import Event, EventClient, EventType, Registry, Source

from .classify import classify
from .fs import AWS_CREDENTIALS, FileSystem
from .shell import Shell

log = logging.getLogger("mirage.ssh")

SSH_TOKEN = "ht-ssh-password"
AWS_FILE_TOKEN = "ht-aws-credentials-file"
AWS_KEY_TOKEN = "ht-aws-access-key"

# Identify as the stock OpenSSH build of the Ubuntu release the fake box claims to run.
BANNER = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
MOTD = (
    "Welcome to Ubuntu 24.04.1 LTS (GNU/Linux 6.8.0-45-generic x86_64)\r\n\r\n"
    " * Documentation:  https://help.ubuntu.com\r\n"
    " * Management:     https://landscape.canonical.com\r\n"
    " * Support:        https://ubuntu.com/pro\r\n\r\n"
    " System information as of Wed Nov  4 15:02:41 UTC 2026\r\n\r\n"
    "  System load:  0.08              Processes:             131\r\n"
    "  Usage of /:   36.2% of 47.39GB  Users logged in:       0\r\n"
    "  Memory usage: 29%               IPv4 address for eth0: 10.66.0.21\r\n\r\n"
    "Last login: Tue Nov  3 18:21:07 2026 from 10.66.0.5\r\n"
)
IDLE_TIMEOUT = 600  # seconds without input before the session is dropped


def load_host_key(path: Path) -> paramiko.PKey:
    """Reuse one host key across restarts so the attacker's known_hosts never complains."""
    if path.exists():
        return paramiko.RSAKey(filename=str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    key = paramiko.RSAKey.generate(3072)
    key.write_private_key_file(str(path))
    return key


class Recorder:
    """Writes a session transcript as JSON lines: one header, then input/output records."""

    def __init__(self, path: Path, meta: dict):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.file = path.open("a", encoding="utf-8")
        self.start = time.monotonic()
        self._write({"type": "header", **meta})

    def _write(self, record: dict) -> None:
        self.file.write(json.dumps(record) + "\n")
        self.file.flush()

    def record(self, kind: str, data: str) -> None:
        self._write({"type": kind, "t": round(time.monotonic() - self.start, 3), "data": data})

    def close(self) -> None:
        self.file.close()


class Decoy:
    """Shared state for all connections: planted credentials, base filesystem, live sessions."""

    def __init__(self, registry: Registry, emit, data_dir: Path):
        creds = registry.get(SSH_TOKEN).value
        self.username, self.password = creds["username"], creds["password"]
        self.base_fs = FileSystem.build(registry.get(AWS_KEY_TOKEN).value)
        self.emit = emit
        self.data_dir = data_dir
        self.host_key = load_host_key(data_dir / "ssh_host_rsa_key")
        self.sessions: dict[str, "Connection"] = {}
        self.lock = threading.Lock()

    def serve(self, sock: socket.socket) -> None:
        """Accept connections forever, one thread per connection."""
        while True:
            client, addr = sock.accept()
            threading.Thread(target=Connection(self, client, addr).handle, daemon=True).start()


class Connection(paramiko.ServerInterface):
    """One TCP connection: SSH authentication, then an interactive shell or a single exec."""

    def __init__(self, decoy: Decoy, sock: socket.socket, addr: tuple[str, int]):
        self.decoy = decoy
        self.sock = sock
        self.ip, self.port = addr[0], addr[1]
        self.session_id = uuid.uuid4().hex[:12]
        self.username: str | None = None
        self.exec_command: str | None = None
        self.ready = threading.Event()   # set once the client asks for a shell or exec
        self.transport: paramiko.Transport | None = None
        self.recorder: Recorder | None = None

    # ------------------------------------------------------------- reporting

    def report(self, event_type: EventType, **fields) -> None:
        try:
            self.decoy.emit(Event(source=Source.SSH, event_type=event_type, src_ip=self.ip,
                                  src_port=self.port, session_id=self.session_id, **fields))
        except Exception:
            # Reporting must never break the decoy in front of the attacker.
            log.exception("failed to report %s", event_type)

    # ------------------------------------------------------- paramiko hooks

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_password(self, username, password):
        ok = username == self.decoy.username and password == self.decoy.password
        # Only a successful login with the planted password touches the honeytoken.
        self.report(EventType.LOGIN_ATTEMPT, asset=username, honeytoken_id=SSH_TOKEN if ok else None,
                    attack_techniques=["T1078", "T1021.004"] if ok else ["T1110"],
                    details={"username": username, "password": password, "success": ok, "method": "password"})
        if ok:
            self.username = username
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        self.report(EventType.LOGIN_ATTEMPT, asset=username, attack_techniques=["T1110"],
                    details={"username": username, "success": False, "method": "publickey",
                             "key_type": key.get_name(), "fingerprint": key.fingerprint})
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        # No port forwarding or tunnelling through the decoy.
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        return True

    def check_channel_shell_request(self, channel):
        self.ready.set()
        return True

    def check_channel_exec_request(self, channel, command):
        self.exec_command = command.decode(errors="replace")
        self.ready.set()
        return True

    # ------------------------------------------------------------- session

    def handle(self) -> None:
        try:
            self.transport = paramiko.Transport(self.sock)
            self.transport.local_version = BANNER
            self.transport.add_server_key(self.decoy.host_key)
            self.transport.start_server(server=self)
            channel = self.transport.accept(timeout=30)
            if channel is None or not self.ready.wait(timeout=10):
                return
            self._session(channel)
        except (paramiko.SSHException, EOFError, OSError) as e:
            # Scanners and brute-forcers drop connections constantly; that is not an error.
            log.debug("connection from %s ended: %s", self.ip, e)
        finally:
            self.close(graceful=True)

    def _session(self, channel: paramiko.Channel) -> None:
        started = time.monotonic()
        shell = Shell(self.decoy.base_fs.copy(), peer=(self.ip, self.port))
        self.recorder = Recorder(
            self.decoy.data_dir / "sessions" / f"{self.session_id}.jsonl",
            {"session_id": self.session_id, "src_ip": self.ip, "src_port": self.port, "username": self.username,
             "started": datetime.now(timezone.utc).isoformat()})
        with self.decoy.lock:
            self.decoy.sessions[self.session_id] = self
        self.report(EventType.SESSION_START, asset=self.username,
                    details={"mode": "exec" if self.exec_command else "shell"})

        commands = 0
        try:
            if self.exec_command is not None:
                # `ssh host 'cmd'`: run once, return the exit status, done.
                channel.sendall(self._run(shell, self.exec_command))
                commands = 1
                channel.send_exit_status(shell.status)
            else:
                commands = self._interactive(channel, shell)
                channel.send_exit_status(0)
        finally:
            with self.decoy.lock:
                self.decoy.sessions.pop(self.session_id, None)
            self.report(EventType.SESSION_END, asset=self.username,
                        details={"duration": round(time.monotonic() - started, 1), "commands": commands})
            # Like sshd: signal EOF and close the channel, then let the client hang up.
            channel.shutdown_write()
            channel.close()

    def _interactive(self, channel: paramiko.Channel, shell: Shell) -> int:
        """Minimal line editor: echo, backspace, Ctrl-C, Ctrl-D. Returns the number of commands run."""
        channel.settimeout(IDLE_TIMEOUT)
        channel.sendall(MOTD + shell.prompt())
        buf, prev, in_escape, commands = "", "", False, 0

        while not shell.exited:
            data = channel.recv(1024)
            if not data:
                break
            for ch in data.decode(errors="ignore"):
                if in_escape:
                    # Swallow arrow keys and other ANSI escape sequences (ESC [ ... letter).
                    in_escape = not (ch.isalpha() or ch == "~")
                elif ch == "\x1b":
                    in_escape = True
                elif ch in "\r\n":
                    if ch == "\n" and prev == "\r":
                        pass  # \r\n counts as one Enter
                    else:
                        channel.sendall("\r\n")
                        if buf.strip():
                            commands += 1
                        channel.sendall(self._run(shell, buf))
                        buf = ""
                        if shell.exited:
                            return commands
                        channel.sendall(shell.prompt())
                elif ch in "\x7f\x08":
                    if buf:
                        buf = buf[:-1]
                        channel.sendall("\b \b")
                elif ch == "\x03":
                    buf = ""
                    channel.sendall("^C\r\n" + shell.prompt())
                elif ch == "\x04":
                    if not buf:
                        channel.sendall("logout\r\n")
                        return commands
                elif ch.isprintable():
                    buf += ch
                    channel.sendall(ch)
                prev = ch
        return commands

    def _run(self, shell: Shell, line: str) -> str:
        """Run one command line, record it, report it, and return terminal-ready output."""
        output = shell.run(line)
        if line.strip():
            if self.recorder:  # may already be closed if containment kicked the session
                self.recorder.record("input", line)
                self.recorder.record("output", output)
            self.report(EventType.COMMAND, asset=shell.cwd, attack_techniques=classify(line),
                        details={"command": line, "exit_status": shell.status, "fallback": shell.used_fallback})
            if AWS_CREDENTIALS in shell.files_read:
                self.report(EventType.FILE_ACCESS, asset=AWS_CREDENTIALS, honeytoken_id=AWS_FILE_TOKEN,
                            details={"command": line})
        return output.replace("\n", "\r\n")

    def close(self, graceful: bool = False) -> None:
        """Tear the connection down (also used by containment to kick the attacker).

        A graceful close waits briefly for the client to disconnect first, as a real
        sshd does; dropping TCP immediately makes the client print "Connection reset".
        """
        if self.recorder:
            self.recorder.close()
            self.recorder = None
        if self.transport:
            deadline = time.monotonic() + 2
            while graceful and self.transport.is_active() and time.monotonic() < deadline:
                time.sleep(0.05)
            self.transport.close()
        else:
            self.sock.close()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)  # brute-force noise
    registry = Registry.load(os.environ.get("MIRAGE_HONEYTOKENS", "/etc/mirage/honeytokens.json"))
    client = EventClient()
    decoy = Decoy(registry, client.submit, Path(os.environ.get("MIRAGE_DATA_DIR", "/data")))

    port = int(os.environ.get("SSH_PORT", "22"))
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(100)
    log.info("ssh decoy listening on %d", port)
    decoy.serve(sock)


if __name__ == "__main__":
    main()
