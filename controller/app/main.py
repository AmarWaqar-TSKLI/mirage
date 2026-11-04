"""Mirage controller: receives every decoy event, labels it, tracks attackers and raises alerts."""

import logging
import os
import secrets
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status

from mirage_common import Event, Registry

from .engine import Engine
from .store import Store

log = logging.getLogger("mirage.controller")
logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    store = Store(os.environ.get("MIRAGE_DB_PATH", "/data/mirage.db"))
    registry = Registry.load(os.environ.get("MIRAGE_HONEYTOKENS", "/etc/mirage/honeytokens.json"))
    app.state.store = store
    app.state.engine = Engine(store, registry)
    yield
    store.db.close()


app = FastAPI(title="Mirage Controller", lifespan=lifespan)


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
def ingest_event(event: Event, request: Request) -> dict:
    row, alert = request.app.state.engine.process(event)
    log.info("event %s %s from %s asset=%s stage=%s", row["source"], row["event_type"], row["src_ip"],
             row["asset"], row["stage"])
    if alert:
        log.warning("ALERT [%s] %s from %s", alert["severity"], alert["title"], alert["src_ip"])
    return {"event_id": row["id"], "alert_id": alert["id"] if alert else None}


@app.get("/api/events")
def list_events(request: Request, limit: int = 100, ip: str | None = None) -> list[dict]:
    return request.app.state.store.recent("events", limit, ip)


@app.get("/api/alerts")
def list_alerts(request: Request, limit: int = 100, ip: str | None = None) -> list[dict]:
    return request.app.state.store.recent("alerts", limit, ip)


@app.get("/api/attackers")
def list_attackers(request: Request) -> list[dict]:
    return request.app.state.store.attackers()


@app.get("/api/attackers/{ip}")
def get_attacker(ip: str, request: Request) -> dict:
    attacker = request.app.state.store.get_attacker(ip)
    if not attacker:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown attacker")
    return attacker
