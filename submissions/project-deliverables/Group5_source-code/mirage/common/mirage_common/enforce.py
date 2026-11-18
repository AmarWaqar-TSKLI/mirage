"""Per-decoy enforcement state: which source IPs are blocked or tarpitted.

The controller pushes enforcement decisions to each decoy's control server
(see ``control.py``). The decoy consults this state on every connection or
request: a blocked IP is refused, a tarpitted IP is delayed. Kept in the decoy
so enforcement survives a controller hiccup and adds no per-request round trip.
"""

import threading
import time


class EnforcementState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._blocked: dict[str, float] = {}      # ip -> unix expiry (0 = no expiry)
        self._tarpit: dict[str, float] = {}       # ip -> delay seconds

    def block(self, ip: str, duration_seconds: float = 0.0) -> None:
        expiry = time.time() + duration_seconds if duration_seconds else 0.0
        with self._lock:
            self._blocked[ip] = expiry
            self._tarpit.pop(ip, None)

    def tarpit(self, ip: str, delay_seconds: float) -> None:
        with self._lock:
            # A blocked IP stays blocked; tarpit never downgrades a block.
            if ip not in self._blocked:
                self._tarpit[ip] = max(0.0, delay_seconds)

    def clear(self, ip: str) -> None:
        with self._lock:
            self._blocked.pop(ip, None)
            self._tarpit.pop(ip, None)

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            expiry = self._blocked.get(ip)
            if expiry is None:
                return False
            if expiry and time.time() > expiry:
                del self._blocked[ip]
                return False
            return True

    def tarpit_delay(self, ip: str) -> float:
        with self._lock:
            return self._tarpit.get(ip, 0.0)

    def apply(self, ip: str, mode: str, delay: float = 0.0, duration: float = 0.0) -> None:
        if mode == "block":
            self.block(ip, duration)
        elif mode == "tarpit":
            self.tarpit(ip, delay)
        elif mode == "clear":
            self.clear(ip)
        else:
            raise ValueError(f"unknown enforcement mode: {mode}")

    def snapshot(self) -> dict:
        with self._lock:
            return {"blocked": sorted(self._blocked), "tarpit": dict(self._tarpit)}
