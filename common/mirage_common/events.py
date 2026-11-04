"""The single event format every decoy sends to the controller.

Decoys report *what happened*. The controller decides what it means:
trail stage, ATT&CK/Engage labels, risk score and response.
"""

from datetime import datetime, timezone
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Source(StrEnum):
    ADMIN_PANEL = "admin-panel"
    SSH = "ssh"
    S3 = "s3"


class EventType(StrEnum):
    HTTP_REQUEST = "http_request"        # any request to a decoy web service
    LOGIN_ATTEMPT = "login_attempt"      # credentials submitted (success in details)
    FILE_ACCESS = "file_access"          # a decoy file was read/downloaded
    HONEYTOKEN_USED = "honeytoken_used"  # a planted secret was presented back to us
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    COMMAND = "command"                  # a shell command run in the SSH decoy


class Event(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: Source
    event_type: EventType
    src_ip: IPv4Address | IPv6Address
    src_port: int | None = Field(default=None, ge=0, le=65535)
    session_id: str | None = None
    # What was touched: a URL path, a file path, a username, a bucket/key...
    asset: str | None = None
    # Set when the event involves a planted honeytoken (see mirage_common.trail).
    honeytoken_id: str | None = None
    # Optional ATT&CK technique IDs suggested by the decoy (e.g. the SSH command
    # classifier). The controller may add its own.
    attack_techniques: list[str] = Field(default_factory=list)
    # Source-specific extras (user agent, command text, status code, ...).
    details: dict[str, Any] = Field(default_factory=dict)
