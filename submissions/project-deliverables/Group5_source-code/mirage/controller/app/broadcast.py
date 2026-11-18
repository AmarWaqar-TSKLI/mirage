"""Live fan-out of controller events to connected dashboard WebSockets.

The ingest path is synchronous (FastAPI runs ``def`` handlers in a worker
thread) while the WebSocket connections are async. ``Publisher.publish`` is the
thread-safe bridge: any thread can call it, and it schedules the async broadcast
onto the event loop captured at startup. Broadcasting must never raise into the
ingest path, so every failure here is swallowed and logged.
"""

import asyncio
import logging
from typing import Any

from starlette.websockets import WebSocket

log = logging.getLogger("mirage.controller.broadcast")


class ConnectionManager:
    """Holds the set of live dashboard sockets and fans messages out to them."""

    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)
        log.info("dashboard connected (%d live)", len(self._connections))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(ws)
        log.info("dashboard disconnected (%d live)", len(self._connections))

    async def broadcast(self, message: dict[str, Any]) -> None:
        async with self._lock:
            targets = list(self._connections)
        dead: list[WebSocket] = []
        for ws in targets:
            try:
                await ws.send_json(message)
            except Exception:
                # A client that hung up mid-send: drop it, never fail the burst.
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections.discard(ws)

    @property
    def count(self) -> int:
        return len(self._connections)


class Publisher:
    """Thread-safe entry point: schedule a broadcast from any thread."""

    def __init__(self, manager: ConnectionManager, loop: asyncio.AbstractEventLoop) -> None:
        self.manager = manager
        self.loop = loop

    def publish(self, message: dict[str, Any]) -> None:
        try:
            asyncio.run_coroutine_threadsafe(self.manager.broadcast(message), self.loop)
        except Exception:
            log.exception("failed to schedule broadcast for %s", message.get("type"))
