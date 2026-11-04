"""Mirage controller: receives every decoy event.

Step 1 skeleton: validates and keeps events in memory. SQLite storage,
alerting, ATT&CK labelling, risk scoring and playbooks come next.
"""

import logging
import os
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, status

from mirage_common import Event

log = logging.getLogger("mirage.controller")
logging.basicConfig(level=logging.INFO)

app = FastAPI(title="Mirage Controller")
EVENTS: list[Event] = []


def require_ingest_token(x_mirage_token: str = Header(default="")) -> None:
    # The attacker shares the lab network with the controller, so only decoys
    # holding the shared token may submit events.
    expected = os.environ.get("MIRAGE_INGEST_TOKEN", "")
    if not expected or not secrets.compare_digest(x_mirage_token, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid ingest token")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/api/events", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(require_ingest_token)])
def ingest_event(event: Event) -> dict:
    EVENTS.append(event)
    log.info("event %s %s from %s asset=%s", event.source, event.event_type, event.src_ip, event.asset)
    return {"event_id": str(event.event_id)}


@app.get("/api/events")
def list_events(limit: int = 100) -> list[Event]:
    return EVENTS[-limit:]
