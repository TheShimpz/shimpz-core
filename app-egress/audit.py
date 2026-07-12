"""Structured audit log for every app-egress CONNECT decision (allowed / denied / error).

Matches the repo-wide structlog JSON schema `logq` expects (ts/level/service/trace_id/msg/…extra).
Mirrors drivers/egress/audit.py — this is the per-app record of which host an app was allowed to
reach (or refused), the security-relevant trail for the deny-by-default app-egress lock. The `app` field
(the token prefix) ties a line to the app that made the request.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import time
import uuid
from pathlib import Path

AUDIT_PATH = Path(os.environ.get("SHIMPZ_APP_EGRESS_AUDIT_LOG", "/var/log/app-egress-proxy/audit.jsonl"))
MAX_BYTES = 10 * 1024 * 1024
BACKUPS = 3


def _rotate() -> None:
    if not AUDIT_PATH.exists() or AUDIT_PATH.stat().st_size <= MAX_BYTES:
        return
    for i in range(BACKUPS - 1, 0, -1):
        src = AUDIT_PATH.with_name(f"{AUDIT_PATH.name}.{i}")
        dst = AUDIT_PATH.with_name(f"{AUDIT_PATH.name}.{i + 1}")
        if src.exists():
            src.replace(dst)
    AUDIT_PATH.replace(AUDIT_PATH.with_name(f"{AUDIT_PATH.name}.1"))


def log(op: str, subject: str, *, result: str, level: str | None = None, **extra: object) -> str:
    """Emit one audit line for a CONNECT decision. `subject` is the `host:port` targeted."""
    trace_id = uuid.uuid4().hex
    event = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": level or ("info" if result == "ok" else "warn"),
        "service": "app-egress-proxy",
        "trace_id": trace_id,
        "msg": f"{op} {subject}: {result}",
        "op": op,
        "subject": subject,
        "result": result,
        **extra,
    }
    line = json.dumps(event, sort_keys=True)
    print(line, file=sys.stdout, flush=True)
    with contextlib.suppress(OSError):
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        _rotate()
        with AUDIT_PATH.open("a") as fh:
            fh.write(line + "\n")
    return trace_id
