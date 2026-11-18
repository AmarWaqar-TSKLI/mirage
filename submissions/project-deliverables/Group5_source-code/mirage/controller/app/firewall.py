"""Firewall containment driver supporting nftables and iptables rules."""

import logging
import shutil
import subprocess
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional

log = logging.getLogger("mirage.controller.firewall")


class FirewallManager:
    def __init__(self, table_name: str = "mirage_containment"):
        self.table_name = table_name
        self.banned: Dict[str, datetime] = {}
        self._nft_path = shutil.which("nft")
        self._iptables_path = shutil.which("iptables")
        self._initialized = False

    def _init_nftables(self) -> bool:
        if not self._nft_path or self._initialized:
            return self._initialized
        try:
            # Create inet table and drop chain if not existing
            subprocess.run(
                [self._nft_path, "add", "table", "inet", self.table_name],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                [
                    self._nft_path,
                    "add",
                    "chain",
                    "inet",
                    self.table_name,
                    "input",
                    "{ type filter hook input priority -10; policy accept; }",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            self._initialized = True
            log.info("initialized nftables table '%s'", self.table_name)
            return True
        except Exception as e:
            log.warning("could not initialize nftables (needs NET_ADMIN): %s", e)
            return False

    def ban(self, ip: str, duration_seconds: int = 3600) -> Dict[str, any]:
        """Enforces a network drop rule on attacker `ip`."""
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)
        self.banned[ip] = expires_at

        # Attempt nftables execution
        if self._nft_path and self._init_nftables():
            try:
                cmd = [
                    self._nft_path,
                    "add",
                    "rule",
                    "inet",
                    self.table_name,
                    "input",
                    "ip",
                    "saddr",
                    ip,
                    "drop",
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=3.0)
                if res.returncode == 0:
                    log.info("nftables banned %s for %d seconds", ip, duration_seconds)
                    return {"backend": "nftables", "success": True, "ip": ip, "expires_at": expires_at.isoformat()}
            except Exception as e:
                log.warning("nftables ban execution failed for %s: %s", ip, e)

        # Fallback to iptables if available
        if self._iptables_path:
            try:
                cmd = [self._iptables_path, "-I", "INPUT", "-s", ip, "-j", "DROP"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=3.0)
                if res.returncode == 0:
                    log.info("iptables banned %s for %d seconds", ip, duration_seconds)
                    return {"backend": "iptables", "success": True, "ip": ip, "expires_at": expires_at.isoformat()}
            except Exception as e:
                log.warning("iptables ban execution failed for %s: %s", ip, e)

        # In environments without raw socket/NET_ADMIN privileges (e.g. Windows dev host)
        log.info("simulated firewall ban for %s (expires %s)", ip, expires_at.isoformat())
        return {"backend": "simulated", "success": True, "ip": ip, "expires_at": expires_at.isoformat()}

    def unban(self, ip: str) -> Dict[str, any]:
        self.banned.pop(ip, None)
        if self._iptables_path:
            try:
                subprocess.run([self._iptables_path, "-D", "INPUT", "-s", ip, "-j", "DROP"], capture_output=True, timeout=3.0)
            except Exception:
                pass
        return {"success": True, "ip": ip}

    def is_banned(self, ip: str) -> bool:
        if ip not in self.banned:
            return False
        if datetime.now(timezone.utc) > self.banned[ip]:
            self.banned.pop(ip, None)
            return False
        return True
