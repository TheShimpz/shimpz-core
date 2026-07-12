"""The local, single-scope bearer token `shimpz-brain` uses to call this driver.

Generated once on first boot, on a volume shared only between `shimpz-brain` and this sidecar; never stored in .env.
"""

from __future__ import annotations

import grp
import os
import secrets
from pathlib import Path

TOKEN_PATH = Path(os.environ.get("SHIMPZ_DRIVER_TOKEN_FILE", "/run/shimpz-driver/token"))
# Group the agent user (`abc`, UID 1000 — not driver's own UID 10001) is a member of, so it can
# read the token without owning it (a 0400 owner-only token was unreadable by `abc`).
TOKEN_GROUP = os.environ.get("SHIMPZ_DRIVER_TOKEN_GROUP", "shimpzdriver-token")


def _group_readable(path: Path) -> None:
    """Enforce 0440 + TOKEN_GROUP on `path`, every time — idempotent and self-healing."""
    gid = grp.getgrnam(TOKEN_GROUP).gr_gid
    os.chown(path, -1, gid)
    path.chmod(0o440)


def ensure_token() -> str:
    if TOKEN_PATH.exists():
        token = TOKEN_PATH.read_text().strip()
        if token:
            _group_readable(TOKEN_PATH)
            return token
    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(32)
    TOKEN_PATH.write_text(token)
    _group_readable(TOKEN_PATH)
    return token
