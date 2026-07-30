"""Hashed postgresql-service principals scoped to one Hosted Team database."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
from pathlib import Path

STATE_PATH = Path(
    os.environ.get(
        "SHIMPZ_POSTGRESQL_SERVICE_PRINCIPALS_FILE",
        "/var/lib/postgresql-service/principals.json",
    )
)
_lock = threading.RLock()
_DATABASE_RE = re.compile(r"proj_[a-z0-9_]{1,58}\Z")


class PrincipalError(Exception):
    """A tenant principal is unknown or outside its registered database scope."""


class PrincipalStoreError(Exception):
    """The durable principal registry could not be read or committed."""


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _read() -> dict[str, dict[str, object]]:
    try:
        if not STATE_PATH.exists():
            return {}
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PrincipalStoreError("principal registry could not be read") from exc
    if not isinstance(data, dict):
        raise PrincipalStoreError("principal registry is not a JSON object")
    for digest, record in data.items():
        if not isinstance(digest, str) or not isinstance(record, dict):
            raise PrincipalStoreError("principal registry contains an invalid record")
        team_id = record.get("team_id")
        database = record.get("database")
        if not isinstance(team_id, str) or not isinstance(database, str) or _DATABASE_RE.fullmatch(database) is None:
            raise PrincipalStoreError("principal registry contains an invalid record")
        if not isinstance(record.get("retired", False), bool):
            raise PrincipalStoreError("principal registry contains an invalid retirement state")
    databases = [record["database"] for record in data.values()]
    if len(databases) != len(set(databases)):
        raise PrincipalStoreError("principal registry contains a duplicate Team database")
    return data


def _write(data: dict[str, dict[str, object]]) -> None:
    try:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        temporary = STATE_PATH.with_suffix(".tmp")
        temporary.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(STATE_PATH)
    except OSError as exc:
        raise PrincipalStoreError("principal registry could not be committed") from exc


def register(team_id: str, token: str, database: str) -> None:
    """Register or rotate exactly one principal for `team_id`; cleartext is never stored."""
    with _lock:
        if not isinstance(database, str) or _DATABASE_RE.fullmatch(database) is None:
            raise PrincipalStoreError("cannot register an invalid Team database")
        data = _read()
        existing = [record for record in data.values() if record.get("team_id") == team_id]
        if len(existing) > 1:
            raise PrincipalStoreError("principal registry contains duplicate Team identities")
        if existing and existing[0].get("retired", False):
            raise PrincipalError("Team principal must be finalized before reprovisioning")
        if any(record.get("database") == database and record.get("team_id") != team_id for record in data.values()):
            raise PrincipalStoreError("Team database is already assigned to another principal")
        for digest, record in list(data.items()):
            if record.get("team_id") == team_id:
                del data[digest]
        data[_digest(token)] = {
            "team_id": team_id,
            "database": database,
            "retired": False,
        }
        _write(data)


def owns_database(team_id: str, database: str) -> bool:
    """Whether the durable registry assigns one exact database to this Team."""
    with _lock:
        matches = [record for record in _read().values() if record.get("team_id") == team_id]
        if len(matches) > 1:
            raise PrincipalStoreError("principal registry contains duplicate Team identities")
        if not matches:
            return False
        if matches[0].get("retired", False):
            raise PrincipalError("Team principal must be finalized before reprovisioning")
        return matches[0].get("database") == database


def database(token: str, team_id: str, *, allow_retired: bool = False) -> str:
    with _lock:
        record = _read().get(_digest(token))
        if record is None or record.get("team_id") != team_id:
            raise PrincipalError("unknown principal or team scope mismatch")
        if record.get("retired", False) and not allow_retired:
            raise PrincipalError("Team principal is retired")
        value = record.get("database")
        if not isinstance(value, str) or _DATABASE_RE.fullmatch(value) is None:
            raise PrincipalError("principal registry contains an invalid database")
        return value


def retire(token: str, team_id: str) -> None:
    """Keep the exact dropped database as an idempotent proof until runtime cleanup finalizes."""
    with _lock:
        data = _read()
        digest = _digest(token)
        record = data.get(digest)
        if record is None or record.get("team_id") != team_id:
            raise PrincipalError("unknown principal or team scope mismatch")
        record["retired"] = True
        _write(data)


def finalize(team_id: str) -> None:
    """Provisioner-authorized, retry-safe removal of this Team's retired principal proof."""
    with _lock:
        data = _read()
        matched = [digest for digest, record in data.items() if record.get("team_id") == team_id]
        for digest in matched:
            record = data[digest]
            if not record.get("retired", False):
                raise PrincipalError("Team principal is still active")
        if matched:
            for digest in matched:
                del data[digest]
            _write(data)
