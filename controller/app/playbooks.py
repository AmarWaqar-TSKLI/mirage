"""Response playbooks, containment policies, and defender allowlist."""

import os
from ipaddress import ip_address, ip_network
from typing import List, Set
from .risk import Playbook

# Default defender networks and IP addresses that must NEVER be contained or throttled
DEFAULT_ALLOWLIST = {
    "127.0.0.1",
    "::1",
    "10.66.0.1",       # Lab Docker bridge gateway
    "10.66.0.10",      # Mirage Controller IP
}


class Allowlist:
    def __init__(self, entries: Set[str] = None):
        self.entries = set(entries or DEFAULT_ALLOWLIST)
        env_allow = os.environ.get("MIRAGE_DEFENDER_ALLOWLIST", "")
        if env_allow:
            for item in env_allow.split(","):
                item = item.strip()
                if item:
                    self.entries.add(item)

    def is_allowed(self, ip_str: str) -> bool:
        if not ip_str:
            return False
        if ip_str in self.entries:
            return True
        try:
            target = ip_address(ip_str)
            for entry in self.entries:
                try:
                    if "/" in entry and target in ip_network(entry, strict=False):
                        return True
                    if target == ip_address(entry):
                        return True
                except ValueError:
                    continue
        except ValueError:
            pass
        return False


class ResponsePolicy:
    """Configurable containment policy timings and flags."""
    def __init__(
        self,
        ban_duration_seconds: int = 3600,
        tarpit_delay_seconds: float = 3.0,
        enable_snapshot: bool = True,
        enable_firewall: bool = True,
    ):
        self.ban_duration_seconds = ban_duration_seconds
        self.tarpit_delay_seconds = tarpit_delay_seconds
        self.enable_snapshot = enable_snapshot
        self.enable_firewall = enable_firewall
