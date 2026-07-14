"""The ONLY place the Cloudflare R2 credentials (RCLONE_CONFIG_R2_*) are ever read or used.

A thin wrapper over the `rclone` binary, called ONLY by app.py's already-allowlisted (validate.py)
endpoint handlers. Never exposes a generic "run any rclone command" call — every function here is
one SPECIFIC operation (copy up, presigned link, list, copy down, immutable backup upload, or bounded
backup range read) with a FIXED argv list (never a shell string, so a bucket key can't inject a
command). Same shape as cf-driver's cf_client.py:
the credential lives here, the brain only ever asks for one of these named operations.

The creds reach rclone the same way they reached the brain before this split: RCLONE_CONFIG_R2_*
env vars naming an rclone remote "R2" — moved verbatim from `shimpz-brain`'s compose env to this sidecar's
(SECURITY_ENGINEERING_PLAN.md item 7). The brain no longer holds them at all.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import stat
import subprocess
import time
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import BinaryIO

BUCKET = os.environ.get("R2_BUCKET", "")
# Absolute path (not bare "rclone") — the executable location is fixed by this image's Dockerfile,
# so there is no PATH-hijack surface even in principle.
RCLONE = "/usr/local/bin/rclone"
# Brain-facing transfers keep their existing ten-minute bound. Private recovery has separate hard
# ceilings: one total deadline covers the complete upload/remote-hash/stat transaction, while metadata
# and one bounded range have short individual ceilings. Environment values may only reduce these maxima.
_TIMEOUT = 600


def _reduced_timeout(name: str, default: int, hard_maximum: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer number of seconds") from exc
    if not 1 <= value <= hard_maximum:
        raise RuntimeError(f"{name} must be between 1 and {hard_maximum} seconds")
    return value


_BACKUP_UPLOAD_TOTAL_TIMEOUT = _reduced_timeout(
    "SHIMPZ_R2DRIVER_BACKUP_UPLOAD_TOTAL_TIMEOUT_SECONDS",
    48 * 60 * 60,
    48 * 60 * 60,
)
_BACKUP_STAT_TIMEOUT = _reduced_timeout(
    "SHIMPZ_R2DRIVER_BACKUP_STAT_TIMEOUT_SECONDS",
    10 * 60,
    10 * 60,
)
_BACKUP_RANGE_TIMEOUT = _reduced_timeout(
    "SHIMPZ_R2DRIVER_BACKUP_RANGE_TIMEOUT_SECONDS",
    2 * 60 * 60,
    2 * 60 * 60,
)


class R2Error(Exception):
    """An rclone call failed (auth/network/nonexistent) — its stderr IS the message."""


class R2NotFoundError(R2Error):
    """rclone reported the object/prefix does not exist (exit 3), distinct from a real failure."""


class R2AlreadyExistsError(R2Error):
    """An immutable backup key already exists and was not overwritten."""


class R2CancelledError(R2Error):
    """The private HTTP caller disconnected and its rclone work was killed and reaped."""


def peer_disconnected(connection: socket.socket) -> bool:
    """Peek for FIN/RST immediately while preserving the handler's prior socket timeout."""
    previous_timeout = connection.gettimeout()
    try:
        # MSG_DONTWAIT alone is insufficient after http.server has assigned a positive socket
        # timeout: CPython polls for that timeout before recv(). Temporarily changing the socket
        # mode keeps cancellation checks genuinely nonblocking even after a long upload deadline.
        connection.setblocking(False)
        return connection.recv(1, socket.MSG_PEEK) == b""
    except BlockingIOError:
        return False
    except OSError:
        return True
    finally:
        with suppress(OSError):
            connection.settimeout(previous_timeout)


def remaining_deadline_seconds(deadline: float, now: float, description: str) -> float:
    """Return a caller-supplied deadline's remainder without ever resetting its budget."""
    remaining = deadline - now
    if remaining <= 0:
        raise R2Error(f"{description} exceeded its total timeout")
    return remaining


def _remote(key: str) -> str:
    return f"R2:{BUCKET}/{key}"


def _run(
    args: list[str],
    *,
    timeout: int | float = _TIMEOUT,
    stdout=subprocess.PIPE,
    text: bool = True,
    pass_fds: tuple[int, ...] = (),
    cancel_check: Callable[[], bool] | None = None,
) -> subprocess.CompletedProcess:
    # Fixed argv, never a shell string — a key/prefix can never inject a command (same guarantee
    # cf_client relies on for its fixed https://api.cloudflare.com calls).
    command = [RCLONE, *args]
    try:
        process = subprocess.Popen(
            command,
            stdout=stdout,
            stderr=subprocess.PIPE,
            text=text,
            pass_fds=pass_fds,
            start_new_session=True,
        )
    except OSError as exc:
        raise R2Error(f"could not execute the fixed rclone binary: {exc}") from exc
    try:
        stdout_data, stderr_data = _communicate_cancellable(process, timeout, cancel_check)
    except subprocess.TimeoutExpired as exc:
        _terminate_process_group(process)
        raise R2Error(f"rclone operation exceeded its {timeout}-second timeout") from exc
    except R2CancelledError:
        _terminate_process_group(process)
        raise
    return subprocess.CompletedProcess(command, process.returncode, stdout_data, stderr_data)


def _terminate_process_group(process: subprocess.Popen) -> None:
    """Terminate, then kill if necessary, and always reap the complete rclone process group."""
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    try:
        process.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
        process.communicate()


def _communicate_cancellable(
    process: subprocess.Popen,
    timeout: int | float,
    cancel_check: Callable[[], bool] | None,
) -> tuple[object, object]:
    """Drain a real subprocess while polling one peer-liveness predicate and one total deadline."""
    deadline = time.monotonic() + timeout
    while True:
        if cancel_check is not None and cancel_check():
            raise R2CancelledError("private backup caller disconnected; rclone was cancelled")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(process.args, timeout)
        try:
            return process.communicate(timeout=min(0.25, remaining))
        except subprocess.TimeoutExpired:
            continue


def upload(local_path: str, key: str) -> int:
    """Copy a local file up to R2 at `key`. Returns the uploaded size in bytes."""
    proc = _run(["copyto", local_path, _remote(key)])
    if proc.returncode != 0:
        raise R2Error(f"upload failed: {proc.stderr.strip() or proc.returncode}")
    return Path(local_path).stat().st_size


def backup_upload(
    source: BinaryIO,
    key: str,
    expected_sha256: str,
    expected_size: int,
    *,
    deadline: float | None = None,
    cancel_check: Callable[[], bool] | None = None,
) -> int:
    """Upload one retained verified inode and bind the remote bytes to its caller-recorded identity."""
    if len(expected_sha256) != 64 or any(character not in "0123456789abcdef" for character in expected_sha256):
        raise R2Error("backup upload expected SHA-256 is invalid")
    source_fd = source.fileno()
    before = os.fstat(source_fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size or expected_size <= 0:
        raise R2Error("backup upload source is not the expected regular inode")
    started = time.monotonic()
    if deadline is None:
        deadline = started + _BACKUP_UPLOAD_TOTAL_TIMEOUT
    if deadline <= started or deadline - started > _BACKUP_UPLOAD_TOTAL_TIMEOUT:
        raise R2Error("backup upload deadline is expired or exceeds the hard total timeout")

    def remaining_timeout() -> float:
        return remaining_deadline_seconds(deadline, time.monotonic(), "backup upload transaction")

    # `--ignore-existing` makes a pre-existing key a skip, never a replacement. `--copy-links` is
    # intentionally narrow here: rclone's local backend otherwise treats /proc/self/fd/N as a
    # directory symlink. Following this one inherited descriptor preserves the already-validated
    # inode and never reopens the mutable spool pathname. The key is derived from the body SHA-256,
    # and we verify the remote bytes after either create or skip. Concurrent valid writers can
    # therefore race only with identical content.
    proc = _run(
        [
            "copyto",
            "--copy-links",
            "--ignore-existing",
            "--no-update-modtime",
            f"/proc/self/fd/{source_fd}",
            _remote(key),
        ],
        timeout=remaining_timeout(),
        pass_fds=(source_fd,),
        cancel_check=cancel_check,
    )
    if proc.returncode != 0:
        raise R2Error(f"backup upload failed: {proc.stderr.strip() or proc.returncode}")
    after = os.fstat(source_fd)
    stable_source = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    verify = _run(
        ["hashsum", "SHA-256", "--download", _remote(key)],
        timeout=remaining_timeout(),
        cancel_check=cancel_check,
    )
    remote_digest = verify.stdout.strip().split(None, 1)[0] if verify.returncode == 0 else ""
    if verify.returncode != 0 or remote_digest != expected_sha256:
        if remote_digest and remote_digest != expected_sha256:
            raise R2AlreadyExistsError(f"backup key already exists with different bytes: {key}")
        raise R2Error(f"could not verify backup upload: {verify.stderr.strip() or verify.returncode}")
    if (
        backup_size(
            key,
            timeout=min(_BACKUP_STAT_TIMEOUT, remaining_timeout()),
            cancel_check=cancel_check,
        )
        != expected_size
    ):
        raise R2Error("remote backup size does not match the verified upload source")
    if not stable_source:
        raise R2Error("backup upload source inode changed during rclone transfer")
    return expected_size


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


def _stderr_text(proc: subprocess.CompletedProcess) -> str:
    if isinstance(proc.stderr, bytes):
        return proc.stderr.decode(errors="replace")
    return proc.stderr or ""


def _missing(proc: subprocess.CompletedProcess) -> bool:
    return proc.returncode == 3 or any(marker in _stderr_text(proc).lower() for marker in _NOT_FOUND_MARKERS)


def _object_size(
    key: str,
    *,
    timeout: int | float,
    operation: str,
    cancel_check: Callable[[], bool] | None = None,
) -> int:
    proc = _run(["lsjson", "--stat", _remote(key)], timeout=timeout, cancel_check=cancel_check)
    if _missing(proc):
        raise R2NotFoundError(f"no such {operation} object: {key!r}")
    if proc.returncode != 0:
        raise R2Error(f"{operation} stat failed: {_stderr_text(proc).strip() or proc.returncode}")
    try:
        payload = json.loads(proc.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        raise R2Error(f"{operation} stat returned malformed metadata") from exc
    if not isinstance(payload, dict) or payload.get("IsDir") is not False or type(payload.get("Size")) is not int:
        raise R2Error(f"{operation} stat did not identify exactly one regular object")
    return payload["Size"]


def object_size(key: str) -> int:
    """Stat one generic object before the bounded transfer starts."""
    return _object_size(key, timeout=_TIMEOUT, operation="object")


def backup_size(
    key: str,
    *,
    timeout: int | float = _BACKUP_STAT_TIMEOUT,
    cancel_check: Callable[[], bool] | None = None,
) -> int:
    """Return the exact size of one approved backup object without downloading its body."""
    return _object_size(key, timeout=timeout, operation="backup", cancel_check=cancel_check)


def backup_download_range(
    key: str,
    offset: int,
    count: int,
    destination: BinaryIO,
    *,
    cancel_check: Callable[[], bool] | None = None,
) -> int:
    """Download one fixed byte range to an already-open private file and rewind it."""
    if offset < 0 or count <= 0:
        raise R2Error("backup range must have a nonnegative offset and positive count")
    destination.seek(0)
    destination.truncate(0)
    proc = _run(
        ["cat", "--offset", str(offset), "--count", str(count), _remote(key)],
        timeout=_BACKUP_RANGE_TIMEOUT,
        stdout=destination,
        text=False,
        cancel_check=cancel_check,
    )
    if _missing(proc):
        raise R2NotFoundError(f"no such backup object: {key!r}")
    if proc.returncode != 0:
        raise R2Error(f"backup range download failed: {_stderr_text(proc).strip() or proc.returncode}")
    actual = os.fstat(destination.fileno()).st_size
    if actual != count:
        raise R2Error(f"backup range download returned {actual} bytes instead of {count}")
    destination.seek(0)
    return actual


def download(key: str, local_path: str, max_bytes: int) -> int:
    """Copy at most `max_bytes + 1` bytes so a changing object cannot exhaust generic staging."""
    if max_bytes <= 0:
        raise R2Error("generic download bound must be positive")
    destination = Path(local_path)
    with destination.open("wb") as stream:
        proc = _run(
            ["cat", "--count", str(max_bytes + 1), _remote(key)],
            stdout=stream,
            text=False,
        )
    if _missing(proc):
        raise R2NotFoundError(f"no such object: {key!r}")
    if proc.returncode != 0:
        raise R2Error(f"download failed: {_stderr_text(proc).strip() or proc.returncode}")
    return destination.stat().st_size
