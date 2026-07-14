"""Structured audit log for every r2-driver operation.

Matches the repo-wide structlog JSON schema `logq` expects (ts/level/service/trace_id/msg/…extra).

Redaction: every call site passes only keys, prefixes, sizes and counts — never file bytes, never a
presigned link (a live download credential), never the R2 secret.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
import uuid
from pathlib import Path

AUDIT_PATH = Path(os.environ.get("SHIMPZ_R2DRIVER_AUDIT_LOG", "/var/log/r2-driver/audit.jsonl"))
MAX_BYTES = 10 * 1024 * 1024
BACKUPS = 3
_WRITE_LOCK = threading.Lock()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _rotate() -> bool:
    if not AUDIT_PATH.exists() or AUDIT_PATH.stat().st_size <= MAX_BYTES:
        return False
    for i in range(BACKUPS - 1, 0, -1):
        src = AUDIT_PATH.with_name(f"{AUDIT_PATH.name}.{i}")
        dst = AUDIT_PATH.with_name(f"{AUDIT_PATH.name}.{i + 1}")
        if src.exists():
            src.replace(dst)
    AUDIT_PATH.replace(AUDIT_PATH.with_name(f"{AUDIT_PATH.name}.1"))
    return True


def log(
    op: str, subject: str, *, result: str, trace_id: str | None = None, level: str | None = None, **extra: object
) -> str:
    """Emit one audit line; returns the trace_id (generated if not given) to echo in the HTTP response."""
    trace_id = trace_id or uuid.uuid4().hex
    event = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": level or ("info" if result == "ok" else "warn"),
        "service": "r2-driver",
        "trace_id": trace_id,
        "msg": f"{op} {subject}: {result}",
        "op": op,
        "subject": subject,
        "result": result,
        **extra,
    }
    line = json.dumps(event, sort_keys=True)
    payload = f"{line}\n".encode()
    with _WRITE_LOCK:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        if _rotate():
            _fsync_directory(AUDIT_PATH.parent)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(AUDIT_PATH, flags, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("audit append made no progress")
                remaining = remaining[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        _fsync_directory(AUDIT_PATH.parent)
    print(line, file=sys.stdout, flush=True)
    return trace_id
