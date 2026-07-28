"""Durable, bounded authorization state for retrying an incomplete Team destroy.

The Brain container is normally the ownership anchor. Named volumes cannot be removed until that
container is gone, so a failed volume removal needs a smaller non-runnable anchor that survives a
driver/container restart. Records live in a driver-only volume, contain no credential, and are removed
only after every runtime/database artifact has been removed.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
import stat
import threading
from dataclasses import asdict, dataclass
from pathlib import Path

STATE_DIR = Path(os.environ.get("SHIMPZ_TEAM_CLEANUP_DIR", "/var/lib/team-driver/cleanup"))
MAX_RECORDS = int(os.environ.get("SHIMPZ_TEAM_CLEANUP_MAX_RECORDS", "128"))
MAX_RECORD_BYTES = 4096
VERSION = 1

_TEAM_ID_RE = re.compile(r"^[a-z0-9_]{1,40}$")
_BRAIN_ID_RE = re.compile(r"^(?:[a-f0-9]{12,64})?$")
_NONCE_RE = re.compile(r"^[a-f0-9]{32}$")
_guard = threading.RLock()

if MAX_RECORDS < 1:
    raise ValueError("SHIMPZ_TEAM_CLEANUP_MAX_RECORDS must be positive")


class CleanupStateError(Exception):
    """Durable cleanup authorization could not be safely read or committed."""


@dataclass(frozen=True)
class Record:
    version: int
    team_id: str
    owner: str
    brain_id: str
    nonce: str
    db_dropped: bool = False


def _validate_record(record: Record) -> Record:
    if (
        not isinstance(record.version, int)
        or isinstance(record.version, bool)
        or record.version != VERSION
        or not isinstance(record.team_id, str)
        or _TEAM_ID_RE.fullmatch(record.team_id) is None
    ):
        raise CleanupStateError("cleanup record has an invalid identity")
    if not isinstance(record.owner, str) or len(record.owner) > 256 or any(ord(char) < 32 for char in record.owner):
        raise CleanupStateError("cleanup record has an invalid owner")
    try:
        record.owner.encode()
    except UnicodeEncodeError as exc:
        raise CleanupStateError("cleanup record has an invalid owner") from exc
    if (
        not isinstance(record.brain_id, str)
        or not isinstance(record.nonce, str)
        or _BRAIN_ID_RE.fullmatch(record.brain_id) is None
        or _NONCE_RE.fullmatch(record.nonce) is None
    ):
        raise CleanupStateError("cleanup record has invalid immutable metadata")
    if not isinstance(record.db_dropped, bool):
        raise CleanupStateError("cleanup record has an invalid database phase")
    return record


def _path(team_id: str) -> Path:
    if _TEAM_ID_RE.fullmatch(team_id) is None:
        raise CleanupStateError("invalid Team id for cleanup state")
    return STATE_DIR / f"{team_id}.json"


def _ensure_directory() -> None:
    try:
        STATE_DIR.mkdir(parents=True, mode=0o700, exist_ok=True)
        metadata = STATE_DIR.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise CleanupStateError("cleanup state path is not a private directory")
        STATE_DIR.chmod(0o700)
    except OSError as exc:
        raise CleanupStateError("cleanup state directory is unavailable") from exc


def _fsync_directory() -> None:
    try:
        descriptor = os.open(STATE_DIR, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise CleanupStateError("cleanup state directory could not be committed") from exc


def _load_unlocked(team_id: str) -> Record | None:
    path = _path(team_id)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CleanupStateError("cleanup record could not be opened") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_RECORD_BYTES or metadata.st_mode & 0o077:
            raise CleanupStateError("cleanup record has unsafe filesystem metadata")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_RECORD_BYTES + 1)
    except OSError as exc:
        raise CleanupStateError("cleanup record could not be read") from exc
    finally:
        os.close(descriptor)
    try:
        payload = json.loads(raw)
        if not isinstance(payload, dict) or set(payload) != set(Record.__dataclass_fields__):
            raise ValueError("unexpected cleanup record fields")
        record = Record(**payload)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise CleanupStateError("cleanup record is malformed") from exc
    return _validate_record(record)


def load(team_id: str) -> Record | None:
    with _guard:
        _ensure_directory()
        return _load_unlocked(team_id)


def _write_unlocked(record: Record) -> None:
    record = _validate_record(record)
    _ensure_directory()
    payload = json.dumps(asdict(record), sort_keys=True, separators=(",", ":")).encode()
    temporary = STATE_DIR / f".{record.team_id}.{secrets.token_hex(8)}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
        )
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written < 1:
                raise OSError("short cleanup record write")
            remaining = remaining[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        temporary.replace(_path(record.team_id))
        _fsync_directory()
    except OSError as exc:
        raise CleanupStateError("cleanup record could not be committed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with contextlib.suppress(OSError):
            temporary.unlink(missing_ok=True)


def begin(team_id: str, owner: str, brain_id: str) -> Record:
    """Create one immutable ownership anchor, or return the exact matching pending anchor."""
    candidate = _validate_record(
        Record(
            version=VERSION,
            team_id=team_id,
            owner=owner,
            brain_id=brain_id,
            nonce=secrets.token_hex(16),
        )
    )
    with _guard:
        _ensure_directory()
        existing = _load_unlocked(team_id)
        if existing is not None:
            if (existing.owner, existing.brain_id) != (owner, brain_id):
                raise CleanupStateError("cleanup record identity does not match this Team")
            return existing
        try:
            count = sum(1 for path in STATE_DIR.glob("*.json") if path.is_file() and not path.is_symlink())
        except OSError as exc:
            raise CleanupStateError("cleanup record inventory is unavailable") from exc
        if count >= MAX_RECORDS:
            raise CleanupStateError("cleanup record capacity is exhausted")
        _write_unlocked(candidate)
        return candidate


def mark_db_dropped(record: Record) -> Record:
    """Durably record the last irreversible phase before the retry anchor may be removed."""
    with _guard:
        current = _load_unlocked(record.team_id)
        if current is None or current.nonce != record.nonce or current != record:
            raise CleanupStateError("cleanup record changed during teardown")
        completed = Record(
            version=record.version,
            team_id=record.team_id,
            owner=record.owner,
            brain_id=record.brain_id,
            nonce=record.nonce,
            db_dropped=True,
        )
        _write_unlocked(completed)
        return completed


def finish(record: Record) -> None:
    """Remove only the exact record whose complete cleanup has just been proved."""
    with _guard:
        current = _load_unlocked(record.team_id)
        if current is None:
            return
        if current != record:
            raise CleanupStateError("cleanup record changed during teardown")
        try:
            _path(record.team_id).unlink()
            _fsync_directory()
        except OSError as exc:
            raise CleanupStateError("cleanup record could not be removed") from exc


def principal_authorized(record: Record, principal: tuple[str, str | None]) -> bool:
    kind, account_id = principal
    return kind == "operator" or (kind == "account" and account_id == record.owner)
