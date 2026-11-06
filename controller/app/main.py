"""Mirage controller: receives every decoy event, labels it, tracks attackers, raises alerts, executes active containment, and serves the live dashboard."""

import asyncio
import logging
import os
import secrets
from contextlib import asynccontextmanager
from ipaddress import ip_address, ip_network
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from mirage_common import Event, Registry

from .broadcast import ConnectionManager, Publisher
from .engine import Engine
from .response_engine import ResponseEngine
from .store import Store

log = logging.getLogger("mirage.controller")
logging.basicConfig(level=logging.INFO)

STATIC_DIR = Path(__file__).parent / "static"

# The attacker shares the lab network with the controller. Everything except
# event ingest (token-gated) and the health check must be invisible to a
# lab-side client, so the dashboard, the API reads and the manual controls
# answer only on the mgmt side (the host). Decoys sit in the lab too but only
# ever POST events, so they are unaffected.
LAB_SUBNET = os.environ.get("MIRAGE_LAB_SUBNET", "10.66.0.0/24")
try:
    _LAB_NET = ip_network(LAB_SUBNET, strict=False)
except ValueError:
    _LAB_NET = ip_network("10.66.0.0/24")


def _from_lab(host: str | None) -> bool:
    if not host:
        return False
    try:
        return ip_address(host) in _LAB_NET
    except ValueError:
        # Non-IP peers (e.g. the TestClient) are not lab clients.
        return False


def _lab_allowed(method: str, path: str) -> bool:
    # The only things a lab-side client may reach.
    return path == "/health" or (method == "POST" and path == "/api/events")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Captured so synchronous ingest handlers (run in a worker thread) can push
    # to async WebSocket clients via Publisher.
    manager = ConnectionManager()
    publisher = Publisher(manager, asyncio.get_running_loop())

    store = Store(os.environ.get("MIRAGE_DB_PATH", "/data/mirage.db"))
    registry = Registry.load(os.environ.get("MIRAGE_HONEYTOKENS", "/etc/mirage/honeytokens.json"))
    response_engine = ResponseEngine(store, publisher=publisher)

    app.state.manager = manager
    app.state.publisher = publisher
    app.state.store = store
    app.state.response_engine = response_engine
    app.state.engine = Engine(store, registry, response_engine=response_engine)
    yield
    store.db.close()


app = FastAPI(title="Mirage Controller", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.middleware("http")
async def restrict_to_mgmt(request: Request, call_next):
    """404 any lab-side request that is not token-gated ingest or the health check."""
    host = request.client.host if request.client else None
    if _from_lab(host) and not _lab_allowed(request.method, request.url.path):
        return JSONResponse({"detail": "Not Found"}, status_code=status.HTTP_404_NOT_FOUND)
    return await call_next(request)


def require_ingest_token(x_mirage_token: str = Header(default="")) -> None:
    # The attacker shares the lab network with the controller, so only decoys
    # holding the shared token may submit events.
    expected = os.environ.get("MIRAGE_INGEST_TOKEN", "")
    if not expected or not secrets.compare_digest(x_mirage_token, expected):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid ingest token")


@app.get("/health", include_in_schema=False)
def health() -> dict:
    return {"status": "ok"}


# ----------------------------------------------------------------- dashboard


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    index = STATIC_DIR / "index.html"
    if not index.is_file():
        raise HTTPException(status.HTTP_404_NOT_FOUND, "dashboard not built")
    return FileResponse(index)


@app.websocket("/ws")
async def dashboard_ws(ws: WebSocket) -> None:
    # HTTP middleware does not see the WebSocket scope, so guard it here too.
    if _from_lab(ws.client.host if ws.client else None):
        await ws.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    manager: ConnectionManager = ws.app.state.manager
    await manager.connect(ws)
    try:
        # The dashboard is read-only; we only need the socket open to push to it.
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(ws)


# --------------------------------------------------------------------- ingest


@app.post("/api/events", status_code=status.HTTP_202_ACCEPTED, dependencies=[Depends(require_ingest_token)])
def ingest_event(event: Event, request: Request) -> dict:
    row, alert = request.app.state.engine.process(event)
    log.info("event %s %s from %s asset=%s stage=%s", row["source"], row["event_type"], row["src_ip"],
             row["asset"], row["stage"])
    if alert:
        log.warning("ALERT [%s] %s from %s", alert["severity"], alert["title"], alert["src_ip"])

    # Push the live deltas to every connected dashboard. Never fail ingest on this.
    publisher: Publisher = request.app.state.publisher
    publisher.publish({"type": "event", "data": row})
    if alert:
        publisher.publish({"type": "alert", "data": alert})
    attacker = request.app.state.store.get_attacker(row["src_ip"])
    if attacker:
        publisher.publish({"type": "attacker", "data": attacker})

    return {"event_id": row["id"], "alert_id": alert["id"] if alert else None}


# ----------------------------------------------------------------------- reads


@app.get("/api/events")
def list_events(request: Request, limit: int = 100, ip: str | None = None) -> list[dict]:
    return request.app.state.store.recent("events", limit, ip)


@app.get("/api/alerts")
def list_alerts(request: Request, limit: int = 100, ip: str | None = None) -> list[dict]:
    return request.app.state.store.recent("alerts", limit, ip)


@app.get("/api/responses")
def list_responses(request: Request, limit: int = 100, ip: str | None = None) -> list[dict]:
    return request.app.state.store.recent("responses", limit, ip)


@app.get("/api/attackers")
def list_attackers(request: Request) -> list[dict]:
    return request.app.state.store.attackers()


@app.get("/api/attackers/{ip}")
def get_attacker(ip: str, request: Request) -> dict:
    attacker = request.app.state.store.get_attacker(ip)
    if not attacker:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown attacker")
    return attacker


# ------------------------------------------------------------- manual controls


@app.post("/api/contain/{ip}")
def manual_contain(ip: str, request: Request) -> dict:
    return request.app.state.response_engine.execute_containment(ip, reason="manual_operator_trigger")


@app.post("/api/uncontain/{ip}")
def manual_uncontain(ip: str, request: Request) -> dict:
    return request.app.state.response_engine.uncontain(ip)


@app.post("/api/admin/reset")
def admin_reset(request: Request) -> dict:
    """Wipe all records and clear decoy enforcement. Mgmt-only (the lab guard
    404s this for attacker IPs). Used by the evaluation harness to start each
    run from a clean slate: decoy block/tarpit state is in-memory on each decoy,
    so it must be lifted here or a contained IP stays blocked into the next run."""
    store = request.app.state.store
    enforcer = request.app.state.response_engine.enforcer
    cleared = [a["ip"] for a in store.attackers()]
    for ip in cleared:
        enforcer.clear(ip)
    store.reset()
    return {"status": "reset", "cleared": cleared}
