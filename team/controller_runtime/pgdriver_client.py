"""Tenant-scoped pg-driver client: one persistent principal token per Team."""

from __future__ import annotations

import http.client
import json
import os
import re
import secrets
from pathlib import Path
from urllib.parse import urlparse

PGDRIVER_URL = os.environ.get("SHIMPZ_PGDRIVER_URL", "http://pg-driver:7072")
PROVISIONER_TOKEN_FILE = Path(os.environ.get("SHIMPZ_PGDRIVER_PROVISIONER_TOKEN_FILE", "/run/shimpz-pgdriver/token"))
PRINCIPAL_DIR = Path(os.environ.get("SHIMPZ_PG_PRINCIPAL_DIR", "/var/lib/team-driver/pg-principals"))
SAFE_TEAM_ID = re.compile(r"^[a-z0-9_]{1,40}$")


class PgDriverError(Exception):
    """pg-driver refused or was unreachable; lifecycle rollback must surface this."""


def _call(path: str, payload: dict, bearer: str) -> dict:
    parsed = urlparse(PGDRIVER_URL)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 7072, timeout=30)
    try:
        conn.request(
            "POST",
            path,
            json.dumps(payload),
            {"Authorization": f"Bearer {bearer}", "Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        raw = resp.read()
        if resp.status != 200:
            # The upstream body is intentionally not reflected into Team create errors. Even a
            # regressed/misconfigured pg-driver must not smuggle SQL or a role password through it.
            raise PgDriverError(f"pg-driver {path} failed with status {resp.status}")
        result = json.loads(raw or b"{}")
        if not isinstance(result, dict):
            raise PgDriverError(f"pg-driver {path} returned a non-object response")
        return result
    finally:
        conn.close()


def _principal_path(team_id: str) -> Path:
    if not SAFE_TEAM_ID.fullmatch(team_id):
        raise PgDriverError("invalid team id for principal path")
    return PRINCIPAL_DIR / f"{team_id}.token"


def _principal(team_id: str, *, create: bool) -> str:
    path = _principal_path(team_id)
    if path.exists():
        token = path.read_text(encoding="utf-8").strip()
        if re.fullmatch(r"[a-f0-9]{64}", token):
            path.chmod(0o600)
            return token
        raise PgDriverError("stored Team database principal is malformed")
    if not create:
        raise PgDriverError("Team database principal is missing")
    PRINCIPAL_DIR.mkdir(parents=True, exist_ok=True)
    PRINCIPAL_DIR.chmod(0o700)
    token = secrets.token_hex(32)
    path.write_text(token, encoding="utf-8")
    path.chmod(0o600)
    return token


def provision_team(team_id: str) -> dict:
    principal = _principal(team_id, create=True)
    provisioner = PROVISIONER_TOKEN_FILE.read_text(encoding="utf-8").strip()
    return _call(
        "/v1/teams/provision",
        {"team_id": team_id, "principal_token": principal},
        provisioner,
    )


def create_app_db(team_id: str, app_id: str) -> dict:
    return _call(
        "/v1/teams/apps/create",
        {"team_id": team_id, "app_id": app_id},
        _principal(team_id, create=False),
    )


def drop_app_db(team_id: str, app_id: str) -> dict:
    return _call(
        "/v1/teams/apps/drop",
        {"team_id": team_id, "app_id": app_id},
        _principal(team_id, create=False),
    )


def drop_team(team_id: str) -> dict:
    # The tenant endpoint retires (rather than deletes) its hashed principal, making an ambiguous
    # response safely retryable until Team runtime/volume cleanup is durably complete.
    return _call(
        "/v1/teams/drop",
        {"team_id": team_id},
        _principal(team_id, create=False),
    )


def finalize_team_drop(team_id: str) -> dict:
    """Finalize the retired pg principal, then remove the controller's cleartext copy; retry-safe."""
    result = _call(
        "/v1/teams/finalize",
        {"team_id": team_id},
        PROVISIONER_TOKEN_FILE.read_text(encoding="utf-8").strip(),
    )
    _principal_path(team_id).unlink(missing_ok=True)
    return result
