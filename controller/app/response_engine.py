"""Orchestrates active response playbooks, containment execution, and forensic capture."""

import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .decoy_control import DecoyControl
from .evict import SessionEvictor
from .firewall import FirewallManager
from .forensics import SnapshotManager
from .playbooks import Allowlist, ResponsePolicy
from .risk import Playbook, evaluate_playbook
from .store import Store

log = logging.getLogger("mirage.controller.response")


class ResponseEngine:
    def __init__(
        self,
        store: Store,
        allowlist: Optional[Allowlist] = None,
        policy: Optional[ResponsePolicy] = None,
        evictor: Optional[SessionEvictor] = None,
        firewall: Optional[FirewallManager] = None,
        snapshots: Optional[SnapshotManager] = None,
        enforcer: Optional[DecoyControl] = None,
        publisher: Optional[Any] = None,
    ):
        self.store = store
        self.allowlist = allowlist or Allowlist()
        self.policy = policy or ResponsePolicy()
        self.evictor = evictor or SessionEvictor()
        self.firewall = firewall or FirewallManager()
        self.snapshots = snapshots or SnapshotManager()
        # Pushes block/tarpit/clear to the decoys. Default reads decoy control
        # URLs from env (empty in tests, so no network calls there).
        self.enforcer = enforcer or DecoyControl()
        # "observe" turns off automatic response (for the evaluation's observe
        # mode, which measures full-trail detection and coverage). Manual
        # contain/uncontain still work. "active" (default) responds on risk.
        self.mode = os.environ.get("MIRAGE_RESPONSE_MODE", "active").lower()
        # Optional live fan-out to the dashboard (broadcast.Publisher). None in tests.
        self.publisher = publisher

    def _publish(self, message: dict) -> None:
        if self.publisher is not None:
            self.publisher.publish(message)

    def handle(self, attacker: Dict[str, Any], event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Evaluates attacker risk and dispatches the appropriate response playbook."""
        ip = attacker["ip"]

        # Observe mode: watch only, take no automatic action.
        if self.mode == "observe":
            return None

        # Defender protection: allowlisted IPs are never acted against
        if self.allowlist.is_allowed(ip):
            log.debug("ip %s is allowlisted; bypassing automated response", ip)
            return None

        risk_score = attacker.get("risk_score", 0)
        previously_contained = attacker.get("contained_at") is not None
        playbook = evaluate_playbook(risk_score, previously_contained)

        if playbook == Playbook.CONTAIN and not previously_contained:
            return self.execute_containment(ip, reason=f"risk score reached {risk_score}")

        if playbook == Playbook.TARPIT and attacker.get("playbook") != Playbook.TARPIT:
            return self.execute_tarpit(ip, delay=self.policy.tarpit_delay_seconds)

        return None

    def execute_containment(self, ip: str, reason: str = "automated threshold") -> Dict[str, Any]:
        """Runs the four-stage containment and evidence collection sequence.

        Idempotent: the attacker's tools fire many events at once, so several can
        cross the threshold before the first containment commits contained_at.
        Only the first call does the work; the rest return the existing record.
        """
        ts = datetime.now(timezone.utc).isoformat()
        auto = reason.startswith("risk score")
        # Atomically CLAIM containment under the lock before doing any work, so
        # concurrent threshold-crossing events don't each run the sequence.
        with self.store.lock:
            existing = self.store.get_attacker(ip)
            if existing and existing.get("contained_at") is not None and auto:
                prior = self.store.recent("responses", 1, ip)
                return prior[0] if prior else {"status": "already_contained", "src_ip": ip}
            if existing:
                existing["contained_at"] = ts
                existing["playbook"] = Playbook.CONTAIN
                self.store.upsert_attacker(existing)
                self.store.commit()

        log.warning("CONTAINING ATTACKER %s (reason: %s)", ip, reason)
        actions = {}

        # 1. Lockout & Session Eviction
        evict_res = self.evictor.terminate_sessions(ip)
        actions["eviction"] = evict_res

        # 2. Decoy-level block: the real lockout. Every decoy refuses this IP, so
        # re-login and further HTTP/S3 use fail. Also kicks live sessions.
        actions["enforcement"] = self.enforcer.block(ip, duration_seconds=self.policy.ban_duration_seconds)

        # 3. Host firewall ban (controller nftables/iptables; simulated off-lab).
        if self.policy.enable_firewall:
            fw_res = self.firewall.ban(ip, duration_seconds=self.policy.ban_duration_seconds)
            actions["firewall"] = fw_res

        # 3. Forensic Evidence Snapshot
        if self.policy.enable_snapshot:
            snap_res = self.snapshots.snapshot("mirage-ssh-1", ip)
            actions["snapshot"] = snap_res

        # 4. Record Response in Database
        response_record = {
            "ts": ts,
            "src_ip": ip,
            "playbook": Playbook.CONTAIN,
            "action": "containment_sequence",
            "status": "completed",
            "details": {"reason": reason, "actions": actions},
        }

        with self.store.lock:
            saved = self.store.insert_response(response_record)
            # contained_at was already claimed atomically above; just read it back.
            attacker = self.store.get_attacker(ip)
            self.store.commit()

        self._publish({"type": "response", "data": saved})
        if attacker:
            self._publish({"type": "attacker", "data": attacker})
        log.warning("containment sequence completed for %s", ip)
        return saved

    def execute_tarpit(self, ip: str, delay: float = 3.0) -> Dict[str, Any]:
        """Applies tarpit throttling to slow down attacker enumeration."""
        ts = datetime.now(timezone.utc).isoformat()
        enforce_res = self.enforcer.tarpit(ip, delay)
        response_record = {
            "ts": ts,
            "src_ip": ip,
            "playbook": Playbook.TARPIT,
            "action": "throttle_connection",
            "status": "active",
            "details": {"delay_seconds": delay, "enforcement": enforce_res},
        }
        with self.store.lock:
            saved = self.store.insert_response(response_record)
            attacker = self.store.get_attacker(ip)
            if attacker:
                attacker["playbook"] = Playbook.TARPIT
                self.store.upsert_attacker(attacker)
            self.store.commit()
        self._publish({"type": "response", "data": saved})
        if attacker:
            self._publish({"type": "attacker", "data": attacker})
        log.info("tarpit throttling enabled for %s (%0.1fs delay)", ip, delay)
        return saved

    def uncontain(self, ip: str) -> Dict[str, Any]:
        """Operator release: lift the firewall ban, clear decoy enforcement, and reset state."""
        fw = self.firewall.unban(ip)
        enforce_res = self.enforcer.clear(ip)
        ts = datetime.now(timezone.utc).isoformat()
        response_record = {
            "ts": ts,
            "src_ip": ip,
            "playbook": Playbook.WATCH,
            "action": "release",
            "status": "completed",
            "details": {"firewall": fw, "enforcement": enforce_res},
        }
        with self.store.lock:
            saved = self.store.insert_response(response_record)
            self.store.clear_containment(ip)
            attacker = self.store.get_attacker(ip)
            self.store.commit()
        self._publish({"type": "response", "data": saved})
        if attacker:
            self._publish({"type": "attacker", "data": attacker})
        log.warning("released %s", ip)
        return saved
