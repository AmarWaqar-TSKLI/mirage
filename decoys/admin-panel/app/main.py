"""Fake internal admin panel: the first decoy on the breadcrumb trail.

robots.txt points at /backup/, which lists an exposed .env backup holding
the SSH password for the next decoy. Every request is reported to the controller.
"""

import logging
import os
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from starlette.exceptions import HTTPException as StarletteHTTPException

from mirage_common import Event, EventClient, EventType, Registry, Source

from . import pages

log = logging.getLogger("mirage.admin-panel")

ROBOTS_TOKEN = "ht-robots-backup-link"
ENV_TOKEN = "ht-env-backup-file"
SSH_TOKEN = "ht-ssh-password"
SERVER_HEADER = "nginx/1.24.0 (Ubuntu)"

registry = Registry.load(os.environ.get("MIRAGE_HONEYTOKENS", "/etc/mirage/honeytokens.json"))
ENV_BACKUP = pages.ENV_BACKUP.format(**registry.get(SSH_TOKEN).value)

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

_client: EventClient | None = None


def emit(event: Event) -> None:
    """Send an event without delaying the response to the attacker."""
    global _client
    _client = _client or EventClient()
    _client.submit(event)


def mark(request: Request, **fields) -> None:
    """Let a handler refine the event the middleware will send for this request."""
    request.state.event = fields


@app.middleware("http")
async def report(request: Request, call_next):
    request.state.event = {}
    response = await call_next(request)
    response.headers["Server"] = SERVER_HEADER

    fields = {"event_type": EventType.HTTP_REQUEST, "asset": request.url.path, **request.state.event}
    details = {"method": request.method, "status": response.status_code,
               "query": request.url.query, "user_agent": request.headers.get("user-agent", ""),
               **fields.pop("details", {})}
    try:
        emit(Event(source=Source.ADMIN_PANEL, src_ip=request.client.host, src_port=request.client.port,
                   details=details, **fields))
    except Exception:
        # Reporting must never break the decoy in front of the attacker.
        log.exception("failed to build event for %s", request.url.path)
    return response


@app.exception_handler(StarletteHTTPException)
async def not_found(request: Request, exc: StarletteHTTPException):
    # Any framework error (404, 405...) must look like plain nginx, never like FastAPI.
    return HTMLResponse(pages.NOT_FOUND, status_code=404)


@app.get("/")
def index():
    return RedirectResponse("/login", status_code=302)


@app.get("/login")
def login_page():
    return HTMLResponse(pages.LOGIN.format(error=""))


@app.post("/login")
async def login(request: Request):
    form = parse_qs((await request.body()).decode(errors="replace"))
    username = form.get("username", [""])[0]
    password = form.get("password", [""])[0]
    mark(request, event_type=EventType.LOGIN_ATTEMPT, asset=username,
         details={"username": username, "password": password, "success": False})
    return HTMLResponse(pages.LOGIN.format(error=pages.LOGIN_ERROR))


@app.get("/robots.txt")
def robots(request: Request):
    mark(request, event_type=EventType.FILE_ACCESS, honeytoken_id=ROBOTS_TOKEN)
    return PlainTextResponse(pages.ROBOTS)


@app.get("/backup/")
def backup_index():
    return HTMLResponse(pages.BACKUP_INDEX.format(size=len(ENV_BACKUP)))


@app.get("/backup/.env.bak")
def env_backup(request: Request):
    mark(request, event_type=EventType.FILE_ACCESS, honeytoken_id=ENV_TOKEN)
    return Response(ENV_BACKUP, media_type="application/octet-stream")
