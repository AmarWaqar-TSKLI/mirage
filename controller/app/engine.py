"""Turns raw decoy events into labelled, stored events, attacker state, alerts, and active responses."""

from typing import Optional
from mirage_common import Event, Registry, TrailStage

from .labels import label
from .response_engine import ResponseEngine
from .risk import calculate_risk_score, evaluate_playbook
from .store import Store

STAGE_SEVERITY = {
    TrailStage.ROBOTS_TXT: "medium",
    TrailStage.ENV_BACKUP: "medium",
    TrailStage.SSH_LOGIN: "high",
    TrailStage.AWS_CREDS_READ: "high",
    TrailStage.S3_ACCESS: "critical",
    TrailStage.BAIT_DOWNLOAD: "critical",
}


class Engine:
    def __init__(self, store: Store, registry: Registry, response_engine: Optional[ResponseEngine] = None):
        self.store = store
        self.registry = registry
        self.response_engine = response_engine

    def process(self, event: Event) -> tuple[dict, dict | None]:
        """Store the event, update the attacker, trigger responses, and return (event, alert or None)."""
        token = self.registry.get(event.honeytoken_id)
        stage = token.stage if token else TrailStage.NONE
        techniques, engage = label(event, token)
        ip, ts = str(event.src_ip), event.timestamp.isoformat()

        row = {
            "id": str(event.event_id), "ts": ts, "source": str(event.source),
            "event_type": str(event.event_type), "src_ip": ip, "src_port": event.src_port,
            "session_id": event.session_id, "asset": event.asset, "honeytoken_id": event.honeytoken_id,
            "stage": int(stage), "techniques": techniques, "engage": engage, "details": event.details,
        }

        with self.store.lock:
            attacker = self.store.get_attacker(ip)
            first_contact = attacker is None
            attacker = attacker or {
                "ip": ip,
                "first_seen": ts,
                "event_count": 0,
                "max_stage": 0,
                "risk_score": 0,
                "playbook": "watch",
                "contained_at": None,
                "techniques": [],
                "tokens": [],
            }
            new_token = token is not None and token.id not in attacker["tokens"]

            new_event_count = attacker["event_count"] + 1
            new_max_stage = max(attacker["max_stage"], int(stage))
            new_techniques = list(dict.fromkeys(attacker["techniques"] + techniques))
            new_tokens = attacker["tokens"] + [token.id] if new_token else attacker["tokens"]

            # Dynamic risk score calculation and active response playbook selection
            risk_score = calculate_risk_score(new_max_stage, new_techniques, new_tokens, new_event_count)
            playbook = evaluate_playbook(risk_score, attacker.get("contained_at") is not None)

            attacker.update(
                last_seen=ts,
                event_count=new_event_count,
                max_stage=new_max_stage,
                risk_score=risk_score,
                playbook=playbook,
                techniques=new_techniques,
                tokens=new_tokens,
            )

            alert = None
            if new_token:
                alert = {"severity": STAGE_SEVERITY.get(stage, "medium"),
                         "title": f"Honeytoken touched: {token.description or token.id} (stage {int(stage)})"}
            elif first_contact:
                alert = {"severity": "low", "title": f"First contact with {event.source} decoy"}
            if alert:
                alert.update(ts=ts, event_id=row["id"], src_ip=ip, honeytoken_id=event.honeytoken_id,
                             stage=int(stage), techniques=techniques, engage=engage)

            self.store.insert_event(row)
            self.store.upsert_attacker(attacker)
            if alert:
                alert = self.store.insert_alert(alert)
            self.store.commit()

        # Orchestrate active response if configured
        if self.response_engine:
            self.response_engine.handle(attacker, row)

        return row, alert
