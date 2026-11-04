"""Fill config/honeytokens.json with fresh, realistic-looking fake secrets.

Run once per deployment (or to rotate everything):
    python3 tools/gen_honeytokens.py
The values are fake. They only work against Mirage's own decoys.
"""

import json
import secrets
import string
import sys
from pathlib import Path

PATH = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parents[1] / "config" / "honeytokens.json"

WORDS = ["Halcyon", "Freight", "Harbor", "Summit", "Atlas", "Cobalt", "Granite", "Meridian"]


def ssh_password() -> str:
    # Looks like a human-chosen password, e.g. "Harbor#2025Cobalt"
    return f"{secrets.choice(WORDS)}{secrets.choice('#!@$')}{secrets.randbelow(9000) + 1000}{secrets.choice(WORDS)}"


def aws_key() -> dict[str, str]:
    upper = string.ascii_uppercase + "234567"
    return {
        "access_key_id": "AKIA" + "".join(secrets.choice(upper) for _ in range(16)),
        "secret_access_key": "".join(secrets.choice(string.ascii_letters + string.digits + "+/") for _ in range(40)),
    }


GENERATORS = {
    "ssh_password": lambda: {"host": "10.66.0.21", "username": "deploy", "password": ssh_password()},
    "aws_key": aws_key,
}

data = json.loads(PATH.read_text())
for token in data["honeytokens"]:
    if gen := GENERATORS.get(token["kind"]):
        token["value"] = gen()
PATH.write_text(json.dumps(data, indent=2) + "\n")
print(f"wrote {PATH}")
