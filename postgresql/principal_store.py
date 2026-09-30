"""Hashed postgresql-service principals scoped to one Hosted Team database.

Each Team has at most one record, keyed by its principal digest, whose `state` is:
- `pending`: a durable provisioning intent committed after proving the database and role absent and before any DDL,
  so resources under its names belong to that interrupted attempt and may be reclaimed or dropped;
- `active`: the committed principal for its database;
- `retired`: the idempotent proof of a dropped database until runtime cleanup finalizes it.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
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
PENDING = "pending"
ACTIVE = "active"
RETIRED = "retired"
_STATES = (PENDING, ACTIVE, RETIRED)


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
        state = record.get("state")
        if not isinstance(state, str) or state not in _STATES:
            raise PrincipalStoreError("principal registry contains an invalid principal state")
    databases = [record["database"] for record in data.values()]
    if len(databases) != len(set(databases)):
        raise PrincipalStoreError("principal registry contains a duplicate Team database")
    team_ids = [record["team_id"] for record in data.values()]
    if len(team_ids) != len(set(team_ids)):
        raise PrincipalStoreError("principal registry contains duplicate Team identities")
    return data


def _fsync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write(data: dict[str, dict[str, object]]) -> None:
    """Durably replace the registry: a committed ownership record must survive power loss like the DDL it guards."""
    payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    try:
        STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        # mkstemp creates a unique 0600 file with O_EXCL, so no reader ever sees a broader mode or a shared name.
        descriptor, name = tempfile.mkstemp(prefix=f".{STATE_PATH.name}.", suffix=".tmp", dir=STATE_PATH.parent)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.replace(STATE_PATH)
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
        _fsync_directory(STATE_PATH.parent)
    except OSError as exc:
        raise PrincipalStoreError("principal registry could not be committed") from exc


def _provisionable(data: dict[str, dict[str, object]], team_id: str) -> dict[str, object] | None:
    """The Team's record, if any; a retired proof blocks reprovisioning until it is finalized."""
    record = next((record for record in data.values() if record["team_id"] == team_id), None)
    if record is not None and record["state"] == RETIRED:
        raise PrincipalError("Team principal must be finalized before reprovisioning")
    return record


def _assign(team_id: str, token: str, database: str, state: str, *, prior: tuple[str | None, ...]) -> None:
    """Durably move this Team's one record to `state`; cleartext is never stored."""
    with _lock:
        if not isinstance(database, str) or _DATABASE_RE.fullmatch(database) is None:
            raise PrincipalStoreError("cannot register an invalid Team database")
        data = _read()
        record = _provisionable(data, team_id)
        current = None if record is None else record["state"]
        if current not in prior:
            raise PrincipalError(f"Team principal cannot become {state} while {current or 'absent'}")
        digest = _digest(token)
        others = {other: record for other, record in data.items() if record["team_id"] != team_id}
        if digest in others or any(record["database"] == database for record in others.values()):
            raise PrincipalStoreError("Team database or principal is already assigned to another Team")
        data = others
        data[digest] = {"team_id": team_id, "database": database, "state": state}
        _write(data)


def provision_state(team_id: str, database: str) -> str | None:
    """This Team's `pending` or `active` state for its exact database, or None when it has no record."""
    with _lock:
        record = _provisionable(_read(), team_id)
        if record is None:
            return None
        if record["database"] != database:
            raise PrincipalStoreError("principal registry assigns another database to this Team")
        return record["state"]


def record_pending(team_id: str, token: str, database: str) -> None:
    """Commit the provisioning intent that makes this Team own `database` before any DDL can create it."""
    _assign(team_id, token, database, PENDING, prior=(None, PENDING))


def register(team_id: str, token: str, database: str) -> None:
    """Complete a recorded provisioning intent, or rotate an active principal, for exactly `database`."""
    _assign(team_id, token, database, ACTIVE, prior=(PENDING, ACTIVE))


def database(token: str, team_id: str, *, allow_retired: bool = False) -> str:
    with _lock:
        record = _read().get(_digest(token))
        if record is None or record["team_id"] != team_id:
            raise PrincipalError("unknown principal or team scope mismatch")
        if record["state"] == RETIRED and not allow_retired:
            raise PrincipalError("Team principal is retired")
        return record["database"]


def require_unregistered(team_id: str) -> None:
    """Refuse when this Team has a record in any state: only its own principal may then drop its database."""
    with _lock:
        if any(record["team_id"] == team_id for record in _read().values()):
            raise PrincipalError("Team principal is registered; only that principal may drop its database")


def retire(token: str, team_id: str) -> None:
    """Keep the exact dropped database as an idempotent proof until runtime cleanup finalizes."""
    with _lock:
        data = _read()
        record = data.get(_digest(token))
        if record is None or record["team_id"] != team_id:
            raise PrincipalError("unknown principal or team scope mismatch")
        record["state"] = RETIRED
        _write(data)


def finalize(team_id: str) -> None:
    """Provisioner-authorized, retry-safe removal of this Team's retired principal proof."""
    with _lock:
        data = _read()
        digest = next((digest for digest, record in data.items() if record["team_id"] == team_id), None)
        if digest is None:
            return
        if data[digest]["state"] != RETIRED:
            raise PrincipalError("Team principal must be dropped before finalization")
        del data[digest]
        _write(data)
