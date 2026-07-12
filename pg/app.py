#!/opt/venv/bin/python
"""pg-driver — the ONLY container that holds SHIMPZ_PG_DSN (the Postgres superuser DSN).

SECURITY_ENGINEERING_PLAN.md item 2: `shimpz-brain` never sees the Postgres superuser credential; it calls
this restricted, allowlisted, audited HTTP API instead — the same pattern cf-driver already
proved for Cloudflare. Every endpoint is one SPECIFIC operation with a fixed request shape
(validate.py), mirroring shimpz-db's own existing subcommands exactly (create/url/list/drop) — this
is a credential relocation, not a new capability. `shimpz-db psql <name>` no longer needs this sidecar
at all: it derives the project's own least-privilege DATABASE_URL via GET /v1/db/url and connects
with THAT, never the superuser.

Endpoints (all require `Authorization: Bearer <token>` — see token_store.py):
  POST   /v1/db/create        {name} -> {database_url, created}
  GET    /v1/db/url?name=<n>  -> {database_url}
  GET    /v1/db/list          -> {databases: [...]}
  POST   /v1/db/drop          {name} -> {dropped}
  POST   /v1/db/query         {name, sql} -> {csv, rows, truncated}   READ-ONLY (RO role; the brain's lead-read path)
"""

from __future__ import annotations

import json
import os
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import audit
import pg_client
import token_store
import validate

LISTEN_PORT = int(os.environ.get("SHIMPZ_PGDRIVER_PORT", "7072"))

_token = token_store.ensure_token()


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _db_create(body: dict) -> dict:
    project = validate.validate_project(body.get("name"))
    return pg_client.create_db_and_role(project)


def _db_url(name: str) -> dict:
    project = validate.validate_project(name)
    return {"database_url": pg_client.database_url(project)}


def _db_list() -> dict:
    return {"databases": pg_client.list_project_dbs()}


def _db_drop(body: dict) -> dict:
    project = validate.validate_project(body.get("name"))
    return pg_client.drop_db_and_role(project)


def _db_query(body: dict) -> dict:
    project = validate.validate_project(body.get("name"))
    sql = validate.validate_sql(body.get("sql"))
    return pg_client.query(project, sql)


class Handler(BaseHTTPRequestHandler):
    server_version = "pg-driver/1.0"

    def _authed(self) -> bool:
        return self.headers.get("Authorization", "") == f"Bearer {_token}"

    def _send_json(self, status: HTTPStatus, payload: object) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, f"invalid JSON body: {exc}") from exc

    def _dispatch(self, method: str) -> None:
        if not self._authed():
            # 127.0.0.1 = this container's own Docker HEALTHCHECK proving the 403 gate is live
            # (an unauthenticated probe every 30s BY DESIGN) — keep the audit line but at info,
            # so warn/error carries only real denials, never a heartbeat.
            if self.client_address[0] == "127.0.0.1":
                audit.log("auth", self.path, result="denied", level="info", source="loopback-probe")
            else:
                audit.log("auth", self.path, result="denied")
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "invalid or missing bearer token"})
            return
        try:
            self._route(method)
        except ApiError as exc:
            audit.log(method.lower(), self.path, result="denied", reason=exc.message)
            self._send_json(exc.status, {"error": exc.message})
        except validate.ValidationError as exc:
            audit.log(method.lower(), self.path, result="denied", reason=str(exc))
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
        except pg_client.PgError as exc:
            audit.log(method.lower(), self.path, result="error", reason=str(exc))
            self._send_json(HTTPStatus.BAD_GATEWAY, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001 — top-level HTTP handler: log + surface, never crash the server
            audit.log(method.lower(), self.path, result="error", reason=str(exc))
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

    def _route(self, method: str) -> None:
        split = urlsplit(self.path)
        path, query = split.path, parse_qs(split.query)

        if method == "POST" and path == "/v1/db/create":
            body = self._body()
            result = _db_create(body)
            trace = audit.log("db.create", body.get("name", "?"), result="ok", created=result["created"])
            self._send_json(HTTPStatus.OK, {**result, "trace_id": trace})
            return
        if method == "POST" and path == "/v1/db/query":
            body = self._body()
            result = _db_query(body)  # READ-ONLY query as the RO role — the brain's lead-read path (item 8)
            trace = audit.log(
                "db.query", body.get("name", "?"), result="ok", rows=result["rows"], truncated=result["truncated"]
            )
            self._send_json(HTTPStatus.OK, {**result, "trace_id": trace})
            return
        if method == "GET" and path == "/v1/db/url":
            name = query.get("name", [""])[0]
            result = _db_url(name)
            # never log the derived DATABASE_URL itself (it embeds the project's own role password)
            trace = audit.log("db.url", name, result="ok")
            self._send_json(HTTPStatus.OK, {**result, "trace_id": trace})
            return
        if method == "GET" and path == "/v1/db/list":
            result = _db_list()
            self._send_json(HTTPStatus.OK, result)
            return
        if method == "POST" and path == "/v1/db/drop":
            body = self._body()
            result = _db_drop(body)
            trace = audit.log("db.drop", body.get("name", "?"), result="ok", **result)
            self._send_json(HTTPStatus.OK, {**result, "trace_id": trace})
            return
        raise ApiError(HTTPStatus.NOT_FOUND, f"no route for {method} {path}")

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def log_message(self, fmt: str, *args: object) -> None:
        # Suppress BaseHTTPRequestHandler's default stderr access log — audit.log() is the
        # single source of truth for what happened, in the schema logq expects.
        pass


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler)  # noqa: S104 — pgdriver_net-only by design
    print(f"pg-driver listening on :{LISTEN_PORT}", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
