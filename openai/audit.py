"""Structured audit log for every openai-driver operation.

Matches the repo-wide structlog JSON schema `logq` expects (ts/level/service/trace_id/msg/…extra).

Redaction: call sites pass only model names, sizes, counts and durations — NEVER the prompt text,
the transcribed/synthesized text, the audio/image bytes, or the API key.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path

AUDIT_PATH = Path(os.environ.get("SHIMPZ_OPENAIDRIVER_AUDIT_LOG", "/var/log/openai-driver/audit.jsonl"))
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


def log(
    op: str, subject: str, *, result: str, trace_id: str | None = None, level: str | None = None, **extra: object
) -> str:
    """Emit one audit line; returns the trace_id (generated if not given) to echo in the HTTP response."""
    trace_id = trace_id or uuid.uuid4().hex
    event = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": level or ("info" if result == "ok" else "warn"),
        "service": "openai-driver",
        "trace_id": trace_id,
        "msg": f"{op} {subject}: {result}",
        "op": op,
        "subject": subject,
        "result": result,
        **extra,
    }
    line = json.dumps(event, sort_keys=True)
    print(line, file=sys.stdout, flush=True)
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _rotate()
    with AUDIT_PATH.open("a") as fh:
        fh.write(line + "\n")
    return trace_id
