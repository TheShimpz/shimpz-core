"""Allowlist validation for pg-driver — runs BEFORE any psql/createdb/dropdb call.

Nothing here touches Postgres; it only decides yes/no and returns a validated project name the
caller (app.py) turns into pg_client.py calls. Same shape as cf-driver/driver's own
validate.py modules — the actual security boundary, not the client that acts on its output.
"""

from __future__ import annotations

import re

# Postgres identifier limit is 63 bytes; dbname/role are "proj_" + this, so leave room for the prefix.
PROJECT_NAME_RE = re.compile(r"^[a-z0-9_]{1,58}$")


class ValidationError(Exception):
    """A pg-driver request failed the allowlist — nothing was touched."""


def sanitize_proj(name: str) -> str:
    """Port of shimpzdetect.sh's _sanitize_proj / drivers/apps/validate.py's sanitize_proj.

    MUST match both exactly — shimpz-db, shimpz-app, and the driver all independently derive the
    same proj_<name> identity from a raw project name.
    """
    lowered = re.sub(r"[^a-z0-9_]+", "_", str(name).lower())
    return lowered.strip("_")


def validate_project(name: object) -> str:
    if not isinstance(name, str) or not name:
        raise ValidationError(f"project name must be a non-empty string: {name!r}")
    sanitized = sanitize_proj(name)
    if not sanitized or not PROJECT_NAME_RE.match(sanitized):
        raise ValidationError(f"project name sanitizes to empty or invalid: {name!r} -> {sanitized!r}")
    return sanitized


MAX_SQL_LEN = 20000


def validate_sql(sql: object) -> str:
    """Shape-check a read-only query — bound its type + size only.

    Read-only is ENFORCED by the RO role's privileges (it has no write grant), NOT by parsing this string,
    so the SQL itself is passed through as-is.
    """
    if not isinstance(sql, str):
        raise ValidationError(f"sql must be a string: {sql!r}")
    sql = sql.strip()
    if not sql:
        raise ValidationError("sql must be non-empty")
    if len(sql) > MAX_SQL_LEN:
        raise ValidationError(f"sql too long (> {MAX_SQL_LEN} chars)")
    return sql
