"""Registry of planted honeytokens.

Every item on the breadcrumb trail is a honeytoken with a unique ID. Decoys tag
events with that ID; the controller looks it up to learn the trail stage and
where the token was planted.

The committed template (config/honeytokens.json) holds no secret values.
`generate()` fills them in and writes config/honeytokens.local.json, which is
git-ignored: every deployment gets its own unique fake secrets, and secret
scanners never see AWS-format keys in the repository.
"""

import json
import os
import secrets
import string
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


# ---------------------------------------------------------------- generation

WORDS = ["Halcyon", "Freight", "Harbor", "Summit", "Atlas", "Cobalt", "Granite", "Meridian"]


def _ssh_password() -> str:
    # Looks like a human-chosen password, e.g. "Harbor#2025Cobalt".
    return f"{secrets.choice(WORDS)}{secrets.choice('#!@$')}{secrets.randbelow(9000) + 1000}{secrets.choice(WORDS)}"


def _aws_key() -> dict[str, str]:
    # Same shape as a real IAM key pair: "AKIA" + 16 base32 chars, 40-char secret.
    upper = string.ascii_uppercase + "234567"
    return {
        "access_key_id": "AKIA" + "".join(secrets.choice(upper) for _ in range(16)),
        "secret_access_key": "".join(secrets.choice(string.ascii_letters + string.digits + "+/") for _ in range(40)),
    }


GENERATORS = {
    "ssh_password": lambda: {"host": "10.66.0.21", "username": "deploy", "password": _ssh_password()},
    "aws_key": _aws_key,
}


def generate(template: Path | str, out: Path | str) -> Path:
    """Copy the template registry to `out`, filling in fresh fake secret values."""
    data = json.loads(Path(template).read_text())
    for token in data["honeytokens"]:
        if gen := GENERATORS.get(token["kind"]):
            token["value"] = gen()
    out = Path(out)
    out.write_text(json.dumps(data, indent=2) + "\n")
    return out
