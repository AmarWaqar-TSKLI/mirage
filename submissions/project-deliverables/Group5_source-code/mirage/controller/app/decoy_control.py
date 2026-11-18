"""Pushes containment decisions from the controller to each decoy's control server.

A firewall ban on the controller only drops traffic to the controller, not to
the decoys the attacker is actually using. So real containment in the lab is
enforced at each decoy: the controller tells every decoy to block (or tarpit,
or release) a source IP, and the decoy refuses that IP locally. Unreachable
decoys never raise, so containment of the others still completes.

Each decoy's control server accepts only that decoy's own token, so entries in
MIRAGE_DECOY_CONTROL_URLS are written `source=url` and each is sent its token.
"""

import logging
import os
from typing import Any, Dict, List, Optional, Tuple

import httpx

log = logging.getLogger("mirage.controller.decoy_control")


# The environment variable that holds each decoy's own token.
DECOY_TOKEN_ENV = {"admin-panel": "MIRAGE_TOKEN_ADMIN_PANEL", "ssh": "MIRAGE_TOKEN_SSH", "s3": "MIRAGE_TOKEN_S3"}


def token_for(source: str) -> str:
    """A decoy's own token, or the shared MIRAGE_INGEST_TOKEN when it has none."""
    return os.environ.get(DECOY_TOKEN_ENV.get(source, ""), "") or os.environ.get("MIRAGE_INGEST_TOKEN", "")


def _default_targets() -> List[Tuple[str, str]]:
    targets = []
    for entry in os.environ.get("MIRAGE_DECOY_CONTROL_URLS", "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        source, _, url = entry.rpartition("=") if "=" in entry else ("", "", entry)
        targets.append((url.strip().rstrip("/"), token_for(source.strip())))
    return targets


class DecoyControl:
    def __init__(self, urls: Optional[List[str]] = None, token: Optional[str] = None, timeout: float = 2.0):
        if urls is not None:   # explicit URLs (tests): one token for all of them
            shared = token or os.environ.get("MIRAGE_INGEST_TOKEN", "")
            self.targets = [(u, shared) for u in urls]
        else:
            self.targets = _default_targets()
        self.timeout = timeout

    @property
    def urls(self) -> List[str]:
        return [url for url, _ in self.targets]

    def _enforce(self, ip: str, mode: str, delay: float = 0.0, duration: float = 0.0) -> Dict[str, Any]:
        reached, failed = [], []
        payload = {"ip": ip, "mode": mode, "delay": delay, "duration": duration}
        for url, token in self.targets:
            try:
                with httpx.Client(timeout=self.timeout) as c:
                    r = c.post(f"{url}/enforce", json=payload, headers={"X-Mirage-Token": token})
                    (reached if r.status_code == 200 else failed).append(url)
            except Exception as e:
                log.warning("could not enforce %s on %s: %s", mode, url, e)
                failed.append(url)
        return {"mode": mode, "reached": reached, "failed": failed, "decoys": len(self.urls)}

    def block(self, ip: str, duration_seconds: float = 0.0) -> Dict[str, Any]:
        return self._enforce(ip, "block", duration=duration_seconds)

    def tarpit(self, ip: str, delay_seconds: float) -> Dict[str, Any]:
        return self._enforce(ip, "tarpit", delay=delay_seconds)

    def clear(self, ip: str) -> Dict[str, Any]:
        return self._enforce(ip, "clear")
