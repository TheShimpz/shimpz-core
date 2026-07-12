"""The ONLY place the Cloudflare R2 credentials (RCLONE_CONFIG_R2_*) are ever read or used.

A thin wrapper over the `rclone` binary, called ONLY by app.py's already-allowlisted (validate.py)
endpoint handlers. Never exposes a generic "run any rclone command" call — every function here is
one SPECIFIC operation (copy up, presigned link, list, copy down) with a FIXED argv list (never a
shell string, so a bucket key can't inject a command). Same shape as cf-driver's cf_client.py:
the credential lives here, the brain only ever asks for one of these named operations.

The creds reach rclone the same way they reached the brain before this split: RCLONE_CONFIG_R2_*
env vars naming an rclone remote "R2" — moved verbatim from `shimpz-brain`'s compose env to this sidecar's
(SECURITY_ENGINEERING_PLAN.md item 7). The brain no longer holds them at all.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

BUCKET = os.environ.get("R2_BUCKET", "")
# Absolute path (not bare "rclone") — the executable location is fixed by this image's Dockerfile,
# so there is no PATH-hijack surface even in principle.
RCLONE = "/usr/local/bin/rclone"
# rclone retries a couple of R2 quirks itself (a 501 on the first PUT that completes on the second);
# we bound the whole call so a hung transfer can't wedge a worker thread forever.
_TIMEOUT = 600


class R2Error(Exception):
    """An rclone call failed (auth/network/nonexistent) — its stderr IS the message."""


class R2NotFoundError(R2Error):
    """rclone reported the object/prefix does not exist (exit 3), distinct from a real failure."""


def _remote(key: str) -> str:
    return f"R2:{BUCKET}/{key}"


def _run(args: list[str]) -> subprocess.CompletedProcess:
    # Fixed argv, never a shell string — a key/prefix can never inject a command (same guarantee
    # cf_client relies on for its fixed https://api.cloudflare.com calls).
    return subprocess.run(  # noqa: S603 — argv list, no shell; every element is validated or a literal
        [RCLONE, *args],
        capture_output=True,
        text=True,
        timeout=_TIMEOUT,
        check=False,
    )


def upload(local_path: str, key: str) -> int:
    """Copy a local file up to R2 at `key`. Returns the uploaded size in bytes."""
    proc = _run(["copyto", local_path, _remote(key)])
    if proc.returncode != 0:
        raise R2Error(f"upload failed: {proc.stderr.strip() or proc.returncode}")
    return Path(local_path).stat().st_size


def link(key: str, expire: str) -> str:
    """A presigned download URL for `key`, valid for `expire` (e.g. '168h')."""
    proc = _run(["link", "--expire", expire, _remote(key)])
    if proc.returncode != 0:
        raise R2Error(f"link failed: {proc.stderr.strip() or proc.returncode}")
    return proc.stdout.strip()


def list_prefix(prefix: str) -> list[dict]:
    """`rclone lsl` under `prefix` → [{size, modtime, path}]. Empty existing prefix = [] (not an error)."""
    proc = _run(["lsl", _remote(prefix)])
    if proc.returncode == 3:
        raise R2NotFoundError(f"nonexistent prefix: {prefix!r}")
    if proc.returncode != 0:
        raise R2Error(f"list failed: {proc.stderr.strip() or proc.returncode}")
    entries = []
    for line in proc.stdout.splitlines():
        # rclone lsl: "  <size> <YYYY-MM-DD> <HH:MM:SS.fffffffff> <path>"
        parts = line.strip().split(None, 3)
        if len(parts) == 4 and parts[0].isdigit():
            entries.append({"size": int(parts[0]), "modtime": f"{parts[1]} {parts[2]}", "path": parts[3]})
    return entries


# rclone's several "this object isn't there" phrasings (copyto of a missing source is exit 1 with
# "Source doesn't exist...", not the exit 3 that `lsl` of a missing prefix gives) — matched so a
# genuinely-missing key is a 404, not a 502 that would wrongly read as a sidecar/upstream failure.
# NB: NOT a bare "not found" — rclone prints a harmless "Config file ... not found - using defaults"
# NOTICE on every call (config comes from RCLONE_CONFIG_R2_* env), which would misclassify a present
# object as missing. Each marker below is specific to a genuinely-absent source.
_NOT_FOUND_MARKERS = ("directory not found", "object not found", "source doesn't exist")


def download(key: str, local_path: str) -> int:
    """Copy `key` down from R2 to `local_path`. Returns the downloaded size in bytes."""
    proc = _run(["copyto", _remote(key), local_path])
    stderr = proc.stderr.lower()
    if proc.returncode == 3 or any(m in stderr for m in _NOT_FOUND_MARKERS):
        raise R2NotFoundError(f"no such object: {key!r}")
    if proc.returncode != 0:
        raise R2Error(f"download failed: {proc.stderr.strip() or proc.returncode}")
    return Path(local_path).stat().st_size
