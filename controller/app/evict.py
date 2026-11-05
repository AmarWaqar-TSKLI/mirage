"""Client for terminating active attacker sessions on decoys."""

import logging
import os
from typing import Any, Dict, List, Optional
import httpx

log = logging.getLogger("mirage.controller.evict")

DEFAULT_SSH_CONTROL_URL = os.environ.get("MIRAGE_SSH_CONTROL_URL", "http://10.66.0.21:8022")


class SessionEvictor:
    def __init__(self, base_url: str = DEFAULT_SSH_CONTROL_URL, token: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.token = token or os.environ.get("MIRAGE_INGEST_TOKEN", "")

    def terminate_sessions(self, ip: str) -> Dict[str, Any]:
        """Instructs the SSH decoy to notify and immediately kick any active sessions from `ip`."""
        endpoint = f"{self.base_url}/sessions/terminate"
        headers = {"X-Mirage-Token": self.token}
        payload = {"ip": ip}

        try:
            with httpx.Client(timeout=2.0) as client:
                res = client.post(endpoint, json=payload, headers=headers)
                if res.status_code == 200:
                    data = res.json()
                    log.info("evicted %d sessions for ip %s", data.get("terminated", 0), ip)
                    return {"success": True, "terminated": data.get("terminated", 0), "details": data}
                log.warning("evict endpoint returned HTTP %d: %s", res.status_code, res.text)
                return {"success": False, "terminated": 0, "error": f"HTTP {res.status_code}"}
        except Exception as e:
            log.warning("could not reach decoy session control at %s: %s", endpoint, e)
            return {"success": False, "terminated": 0, "error": str(e)}

    def list_sessions(self) -> List[Dict[str, Any]]:
        endpoint = f"{self.base_url}/sessions"
        headers = {"X-Mirage-Token": self.token}
        try:
            with httpx.Client(timeout=2.0) as client:
                res = client.get(endpoint, headers=headers)
                if res.status_code == 200:
                    return res.json().get("sessions", [])
        except Exception:
            pass
        return []
