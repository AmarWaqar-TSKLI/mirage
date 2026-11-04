"""Generate this deployment's fake secrets.

Reads the committed template config/honeytokens.json and writes
config/honeytokens.local.json (git-ignored) with a fresh SSH password and
AWS-format key pair. Run once after cloning, or again to rotate everything:

    python3 tools/gen_honeytokens.py

Needs the shared package installed (pip install ./common).
The values are fake. They only work against Mirage's own decoys.
"""

from pathlib import Path

from mirage_common.honeytokens import generate

CONFIG = Path(__file__).parents[1] / "config"

print(f"wrote {generate(CONFIG / 'honeytokens.json', CONFIG / 'honeytokens.local.json')}")
