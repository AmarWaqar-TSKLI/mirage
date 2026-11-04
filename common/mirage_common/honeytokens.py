"""Registry of planted honeytokens.

Every item on the breadcrumb trail is a honeytoken with a unique ID. Decoys tag
events with that ID; the controller looks it up to learn the trail stage and
where the token was planted.
"""

import json
import os
from pathlib import Path

from pydantic import BaseModel

from .trail import TrailStage

DEFAULT_PATH = Path(os.environ.get("MIRAGE_HONEYTOKENS", "/etc/mirage/honeytokens.json"))


class Honeytoken(BaseModel):
    id: str
    kind: str              # robots_link, env_file, ssh_password, aws_key, bait_file, ...
    stage: TrailStage
    planted_at: str        # human-readable location, e.g. "admin-panel:/backup/.env.bak"
    description: str = ""
    # Secret material (fake). Filled in by the honeytoken generator.
    value: dict[str, str] = {}


class Registry:
    def __init__(self, tokens: list[Honeytoken]):
        self._by_id = {t.id: t for t in tokens}

    @classmethod
    def load(cls, path: Path | str = DEFAULT_PATH) -> "Registry":
        data = json.loads(Path(path).read_text())
        return cls([Honeytoken.model_validate(t) for t in data["honeytokens"]])

    def get(self, token_id: str | None) -> Honeytoken | None:
        return self._by_id.get(token_id) if token_id else None

    def __iter__(self):
        return iter(self._by_id.values())
