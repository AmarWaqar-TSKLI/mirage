"""Helper decoys use to send events to the controller."""

import logging
import os

import httpx

from .events import Event

log = logging.getLogger(__name__)

TOKEN_HEADER = "X-Mirage-Token"


class EventClient:
    def __init__(self, controller_url: str | None = None, token: str | None = None):
        self.url = (controller_url or os.environ["MIRAGE_CONTROLLER_URL"]).rstrip("/") + "/api/events"
        self.headers = {TOKEN_HEADER: token or os.environ["MIRAGE_INGEST_TOKEN"]}

    def send(self, event: Event) -> bool:
        """Send one event. Never raises: a decoy must keep looking real even if
        the controller is down, so failures are only logged."""
        try:
            r = httpx.post(self.url, content=event.model_dump_json(), headers={
                **self.headers, "Content-Type": "application/json"}, timeout=2.0)
            r.raise_for_status()
            return True
        except httpx.HTTPError as e:
            log.warning("failed to send event %s: %s", event.event_id, e)
            return False
