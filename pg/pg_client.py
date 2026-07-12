"""The ONLY place SHIMPZ_PG_DSN is ever read or sent.

Shells out to the same psql/createdb/dropdb CLI invocations shimpz-db used to run directly against
the Postgres superuser — moved server-side, unchanged SQL and derivation logic, so this is a
credential relocation (SECURITY_ENGINEERING_PLAN.md item 2), not a rewrite of already-correct
logic. Every argument passed to SQL comes from validate.py's sanitize_proj first (`[a-z0-9_]` only)
before it ever reaches here, same injection-safety argument the original bash version relied on.
"""

from __future__ import annotations

import hmac
import os
import subprocess
from hashlib import sha256
from urllib.parse import urlsplit

_dsn = urlsplit(os.environ.get("SHIMPZ_PG_DSN", ""))
PGHOST = _dsn.hostname or "postgres"
PGPORT = _dsn.port or 5432
PGUSER = _dsn.username or ""
PGPASSWORD = _dsn.password or ""

_PG_ARGS = ["-h", PGHOST, "-p", str(PGPORT), "-U", PGUSER]
_ENV = {**os.environ, "PGPASSWORD": PGPASSWORD}

# The brain's read-only lead-query identity (item 8 keeps it OFF the direct postgres route; it reads via
# this driver instead). A privilege-enforced read-only login role — SELECT anything, WRITE nothing.
RO_ROLE = "shimpz_ro"
QUERY_TIMEOUT_MS = int(os.environ.get("SHIMPZ_PGDRIVER_QUERY_TIMEOUT_MS", "15000"))
MAX_QUERY_ROWS = int(os.environ.get("SHIMPZ_PGDRIVER_MAX_ROWS", "2000"))


class PgError(Exception):
    """A psql/createdb/dropdb invocation failed."""


def _run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, env=_ENV, capture_output=True, text=True, timeout=20, check=False)  # noqa: S603 — fixed argv, no shell, every element either a literal or a validate.py-sanitized name
    if result.returncode != 0:
        raise PgError(f"{' '.join(cmd)} -> rc={result.returncode}: {result.stderr.strip()}")
    return result.stdout


def dbname(project: str) -> str:
    return f"proj_{project}"


def role_password(project: str) -> str:
    """Deterministic per-project password, no state file to keep in sync.

    HMAC-SHA256 keyed by the superuser secret, message = dbname — `database_url` recomputes exactly
    what `create_db_and_role` set, same as shimpz-db's old `rolepw`.
    """
    return hmac.new(PGPASSWORD.encode(), dbname(project).encode(), sha256).hexdigest()[:32]


def database_url(project: str) -> str:
    db = dbname(project)
    return f"postgresql://{db}:{role_password(project)}@{PGHOST}:{PGPORT}/{db}"


def _psql(db: str, sql: str) -> str:
    return _run(["psql", *_PG_ARGS, "-d", db, "-tAc", sql])


def _ensure_ro_role() -> str:
    """A privilege-enforced READ-ONLY login role (pg_read_all_data): SELECT anything, WRITE nothing.

    Unlike `default_transaction_read_only` (which a query could `SET … off`), this role simply LACKS write
    privileges — no query can grant itself one. Idempotent; deterministic password (like the project
    roles), so there is no state file to keep in sync.
    """
    pw = hmac.new(PGPASSWORD.encode(), b"role:shimpz_ro", sha256).hexdigest()[:32]
    if not _role_exists(RO_ROLE):
        _psql("postgres", f"CREATE ROLE {RO_ROLE} LOGIN PASSWORD '{pw}'")
    _psql("postgres", f"GRANT pg_read_all_data TO {RO_ROLE}")  # idempotent
    return pw


def query(project: str, sql: str) -> dict:
    """Run a READ-ONLY query against proj_<project> as the read-only role; return rows as CSV (capped).

    The brain reaches this via the driver (bearer-gated, audited) and NEVER touches postgres
    directly — datastore isolation for WRITES stays intact (the RO role has no write privilege at all). A
    statement timeout bounds runtime; the output is capped at MAX_QUERY_ROWS.
    """
    db = dbname(project)
    pw = _ensure_ro_role()
    _psql("postgres", f'GRANT CONNECT ON DATABASE "{db}" TO {RO_ROLE}')  # proj DBs revoke PUBLIC connect
    url = f"postgresql://{RO_ROLE}:{pw}@{PGHOST}:{PGPORT}/{db}"
    script = f"SET statement_timeout = {QUERY_TIMEOUT_MS};\n{sql}\n"
    result = subprocess.run(  # noqa: S603 — fixed argv; SQL via stdin; the RO role cannot write
        ["psql", url, "-v", "ON_ERROR_STOP=1", "--csv", "-q"],  # noqa: S607 — psql on PATH, same as _run
        env=_ENV, input=script, capture_output=True, text=True, timeout=(QUERY_TIMEOUT_MS // 1000) + 15, check=False,
    )
    if result.returncode != 0:
        raise PgError(result.stderr.strip()[:600] or "query failed")
    lines = result.stdout.splitlines()
    truncated = len(lines) > MAX_QUERY_ROWS + 1  # +1 for the header row
    return {"csv": "\n".join(lines[: MAX_QUERY_ROWS + 1]), "rows": max(0, len(lines) - 1), "truncated": truncated}


def _role_exists(role: str) -> bool:
    # `role` only ever reaches here via validate.py's sanitize_proj ([a-z0-9_] only) — psql has no
    # parameterized-identifier syntax for a bare -tAc query, so string interpolation is the only way.
    return _psql("postgres", f"SELECT 1 FROM pg_roles WHERE rolname='{role}'").strip() == "1"  # noqa: S608


def _db_exists(db: str) -> bool:
    # same sanitize_proj-only-input guarantee as _role_exists above.
    return _psql("postgres", f"SELECT 1 FROM pg_database WHERE datname='{db}'").strip() == "1"  # noqa: S608


def create_db_and_role(project: str) -> dict:
    db = dbname(project)
    role = db
    pw = role_password(project)
    # 1) least-privilege LOGIN role (idempotent: create it, or re-sync the derived password)
    if _role_exists(role):
        _psql("postgres", f"ALTER ROLE \"{role}\" LOGIN PASSWORD '{pw}'")
    else:
        _psql("postgres", f"CREATE ROLE \"{role}\" LOGIN PASSWORD '{pw}'")
    # 2) database OWNED by that role — the project is never the superuser
    already_existed = _db_exists(db)
    if not already_existed:
        _run(["createdb", *_PG_ARGS, "-O", role, db])
    # 3) lock it down: ONLY this role may connect; it owns the public schema so it can create tables.
    _psql("postgres", f'REVOKE CONNECT ON DATABASE "{db}" FROM PUBLIC')
    _psql("postgres", f'GRANT ALL ON DATABASE "{db}" TO "{role}"')
    _psql(db, f'ALTER SCHEMA public OWNER TO "{role}"')
    return {"database_url": database_url(project), "created": not already_existed}


def list_project_dbs() -> list[str]:
    out = _psql("postgres", "SELECT datname FROM pg_database WHERE datname LIKE 'proj_%' ORDER BY 1")
    return [line for line in out.splitlines() if line]


def drop_db_and_role(project: str) -> dict:
    db = dbname(project)
    role = db
    _run(["dropdb", *_PG_ARGS, "--if-exists", db])
    _psql("postgres", f'DROP ROLE IF EXISTS "{role}"')
    return {"dropped": db}
