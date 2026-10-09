"""Allowlist validation for postgresql-service — runs BEFORE any psql/createdb/dropdb call.

Nothing here touches Postgres; it only decides yes/no and returns a validated project name the
caller (app.py) turns into postgresql_client.py calls. This validator is the actual security boundary,
not the client that acts on its output.
"""

import re

TEAM_ID_RE = re.compile(r"^[a-z0-9_]{1,40}$")
PRINCIPAL_TOKEN_RE = re.compile(r"^[a-f0-9]{64}$")
MAX_NOT_AFTER = 2**53


class ValidationError(Exception):
    """A postgresql-service request failed the allowlist — nothing was touched."""


def validate_team_id(value: object) -> str:
    if not isinstance(value, str) or not TEAM_ID_RE.fullmatch(value):
        raise ValidationError("team_id must match [a-z0-9_]{1,40}")
    return value


def validate_principal_token(value: object) -> str:
    if not isinstance(value, str) or not PRINCIPAL_TOKEN_RE.fullmatch(value):
        raise ValidationError("principal_token must be a 256-bit lowercase hex token")
    return value


def team_project(team_id: str) -> str:
    return f"team_{validate_team_id(team_id)}"


def validate_not_after(value: object) -> int:
    """A provisioning fence in whole Unix seconds; 0 means no provisioning request can be in flight."""
    if type(value) is not int or not 0 <= value <= MAX_NOT_AFTER:
        raise ValidationError("not_after must be a non-negative integer Unix time")
    return value
