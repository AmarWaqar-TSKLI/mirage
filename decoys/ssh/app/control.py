"""Authenticated HTTP control server for remote SSH session management and containment."""

import json
import logging
import os
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
import threading
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

if TYPE_CHECKING:
    from .server import Decoy

log = logging.getLogger("mirage.ssh.control")


class ControlHandler(BaseHTTPRequestHandler):
    decoy: "Decoy"

    def log_message(self, format, *args):
        # Suppress noisy standard HTTP access logs
        pass

    def _send_json(self, status_code: int, data: dict) -> None:
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _check_auth(self) -> bool:
        expected = os.environ.get("MIRAGE_INGEST_TOKEN", "")
        token = self.headers.get("X-Mirage-Token", "")
        if not expected or not secrets.compare_digest(token, expected):
            self._send_json(401, {"error": "unauthorized"})
            return False
        return True

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self._send_json(200, {"status": "ok"})
            return

        if not self._check_auth():
            return

        if parsed.path == "/sessions":
            with self.decoy.lock:
                sessions = [
                    {
                        "session_id": s.session_id,
                        "src_ip": s.ip,
                        "src_port": s.port,
                        "username": s.username,
                    }
                    for s in self.decoy.sessions.values()
                ]
            self._send_json(200, {"sessions": sessions, "count": len(sessions)})
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self):
        if not self._check_auth():
            return

        parsed = urlparse(self.path)
        if parsed.path == "/sessions/terminate":
            content_length = int(self.headers.get("Content-Length", 0))
            payload = {}
            if content_length > 0:
                try:
                    payload = json.loads(self.rfile.read(content_length))
                except Exception:
                    pass

            query = parse_qs(parsed.query)
            target_ip = payload.get("ip") or query.get("ip", [None])[0]
            target_sid = payload.get("session_id") or query.get("session_id", [None])[0]

            kicked = []
            with self.decoy.lock:
                to_terminate = []
                for sid, conn in list(self.decoy.sessions.items()):
                    if (target_ip and conn.ip == target_ip) or (target_sid and sid == target_sid) or (not target_ip and not target_sid):
                        to_terminate.append(conn)

            for conn in to_terminate:
                try:
                    conn.notify_and_kick()
                    kicked.append({"session_id": conn.session_id, "src_ip": conn.ip})
                except Exception:
                    log.exception("failed to kick session %s", conn.session_id)

            self._send_json(200, {"terminated": len(kicked), "sessions": kicked})
        else:
            self._send_json(404, {"error": "not found"})


def start_control_server(decoy: "Decoy", port: int = 8022) -> HTTPServer:
    handler = type("ConfiguredControlHandler", (ControlHandler,), {"decoy": decoy})
    server = HTTPServer(("0.0.0.0", port), handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    log.info("ssh control server listening on port %d", port)
    return server
