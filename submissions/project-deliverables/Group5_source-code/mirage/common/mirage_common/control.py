"""Shared, token-gated control server every decoy runs on a dedicated port.

The controller reaches this to enforce containment on a decoy: block or tarpit
a source IP, release it, or (SSH only) list and terminate live sessions. It
runs on a separate port from the decoy's public service so probing it is not a
fingerprinting tell on the decoy itself, and it rejects anything without the
shared ingest token.

Endpoints:
  GET  /health                      -> {"status": "ok"}  (no auth)
  GET  /enforcement                 -> current blocked/tarpit snapshot
  POST /enforce {ip, mode, delay?, duration?}   mode: block | tarpit | clear
  GET  /sessions                    -> live sessions        (if a lister is given)
  POST /sessions/terminate {ip|session_id}  -> kick sessions (if a terminator is given)
"""

import json
import logging
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Callable, Optional

from .enforce import EnforcementState

log = logging.getLogger("mirage.control")


def start_control_server(
    state: EnforcementState,
    port: int,
    token: Optional[str] = None,
    session_lister: Optional[Callable[[], list]] = None,
    session_terminator: Optional[Callable[[Optional[str], Optional[str]], int]] = None,
    on_block: Optional[Callable[[str], None]] = None,
) -> HTTPServer:
    """Start the control server in a daemon thread and return it."""
    expected = token if token is not None else os.environ.get("MIRAGE_INGEST_TOKEN", "")

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass  # no stdout access logs

        def _json(self, code: int, data: dict) -> None:
            body = json.dumps(data).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _auth(self) -> bool:
            got = self.headers.get("X-Mirage-Token", "")
            if not expected or not secrets.compare_digest(got, expected):
                self._json(401, {"error": "unauthorized"})
                return False
            return True

        def _body(self) -> dict:
            n = int(self.headers.get("Content-Length", 0) or 0)
            if not n:
                return {}
            try:
                return json.loads(self.rfile.read(n))
            except Exception:
                return {}

        def do_GET(self):
            if self.path == "/health":
                return self._json(200, {"status": "ok"})
            if not self._auth():
                return
            if self.path == "/enforcement":
                return self._json(200, state.snapshot())
            if self.path == "/sessions" and session_lister is not None:
                sessions = session_lister()
                return self._json(200, {"sessions": sessions, "count": len(sessions)})
            self._json(404, {"error": "not found"})

        def do_POST(self):
            if not self._auth():
                return
            payload = self._body()
            if self.path == "/enforce":
                ip = payload.get("ip")
                mode = payload.get("mode", "")
                if not ip:
                    return self._json(400, {"error": "missing ip"})
                try:
                    state.apply(ip, mode, float(payload.get("delay", 0) or 0), float(payload.get("duration", 0) or 0))
                except ValueError as e:
                    return self._json(400, {"error": str(e)})
                terminated = 0
                if mode == "block":
                    if session_terminator is not None:
                        terminated = session_terminator(ip, None)
                    if on_block is not None:
                        on_block(ip)
                return self._json(200, {"ok": True, "ip": ip, "mode": mode, "terminated": terminated})
            if self.path == "/sessions/terminate" and session_terminator is not None:
                ip = payload.get("ip")
                sid = payload.get("session_id")
                n = session_terminator(ip, sid)
                return self._json(200, {"terminated": n})
            self._json(404, {"error": "not found"})

    server = HTTPServer(("0.0.0.0", port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log.info("control server listening on port %d", port)
    return server
