"""Pushes containment decisions from the controller to each decoy's control server.

A firewall ban on the controller only drops traffic to the controller, not to
the decoys the attacker is actually using. So real containment in the lab is
enforced at each decoy: the controller tells every decoy to block (or tarpit,
or release) a source IP, and the decoy refuses that IP locally. Unreachable
decoys never raise, so containment of the others still completes.
"""

import logging
import os
from typing import Any, Dict, List, Optional

import httpx

log = logging.getLogger("mirage.controller.decoy_control")


def _default_urls() -> List[str]:
    raw = os.environ.get("MIRAGE_DECOY_CONTROL_URLS", "")
    return [u.strip().rstrip("/") for u in raw.split(",") if u.strip()]


class DecoyControl:
    def __init__(self, urls: Optional[List[str]] = None, token: Optional[str] = None, timeout: float = 2.0):
        self.urls = urls if urls is not None else _default_urls()
        self.token = token or os.environ.get("MIRAGE_INGEST_TOKEN", "")
        self.timeout = timeout

    def _enforce(self, ip: str, mode: str, delay: float = 0.0, duration: float = 0.0) -> Dict[str, Any]:
        reached, failed = [], []
        headers = {"X-Mirage-Token": self.token}
        payload = {"ip": ip, "mode": mode, "delay": delay, "duration": duration}
        for url in self.urls:
            try:
                with httpx.Client(timeout=self.timeout) as c:
                    r = c.post(f"{url}/enforce", json=payload, headers=headers)
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
