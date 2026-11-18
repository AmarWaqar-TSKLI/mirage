"""Generate this deployment's real secrets into .env.

Each decoy gets its own token (so a token taken from one decoy cannot forge
events for another), and the operator gets a key for the dashboard's Contain,
Release and Reset controls. Other settings already in .env are kept.

    python3 tools/gen_secrets.py            # fill in any missing secret
    python3 tools/gen_secrets.py --rotate   # replace all of them

Standard library only, so it runs before anything is installed.
"""

import secrets
import sys
from pathlib import Path

ENV = Path(__file__).parents[1] / ".env"
KEYS = ["MIRAGE_TOKEN_ADMIN_PANEL", "MIRAGE_TOKEN_SSH", "MIRAGE_TOKEN_S3", "MIRAGE_OPERATOR_TOKEN"]

rotate = "--rotate" in sys.argv[1:]
lines = ENV.read_text().splitlines() if ENV.exists() else []
present = {line.split("=", 1)[0] for line in lines if "=" in line and not line.lstrip().startswith("#")}

out, written = [], []
for line in lines:
    key = line.split("=", 1)[0] if "=" in line else ""
    if key in KEYS and (rotate or not line.split("=", 1)[1].strip()):
        line = f"{key}={secrets.token_urlsafe(32)}"
        written.append(key)
    out.append(line)
for key in KEYS:
    if key not in present:
        out.append(f"{key}={secrets.token_urlsafe(32)}")
        written.append(key)

ENV.write_text("\n".join(out) + "\n")
ENV.chmod(0o600)
print(f"{ENV}: " + (f"wrote {', '.join(written)}" if written else "all secrets already set (use --rotate to replace)"))
