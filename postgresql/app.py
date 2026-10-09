#!/usr/local/bin/python3
"""Tenant-scoped postgresql-service: one hashed principal and exact DB set per Team."""

import io
import os
import re
import subprocess
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import audit
import deadline
import postgresql_client
import principal_store
import service_manifest
import stdlib_http
import token_store
import validate

SERVICE = service_manifest.load()
LISTEN_HOST = os.environ.get("SHIMPZ_POSTGRESQL_SERVICE_HOST", "")
LISTEN_PORT = SERVICE.port
MAX_BODY_BYTES = int(os.environ.get("SHIMPZ_POSTGRESQL_SERVICE_MAX_BODY_BYTES", str(64 * 1024)))
MAX_HTTP_CONCURRENCY = 32
HTTP_CONNECTION_TIMEOUT_SECONDS = 10
REQUEST_DEADLINE_SECONDS = 10
_provisioner_token = token_store.ensure_token()


ApiError = stdlib_http.HttpError

_ROUTES = (
    stdlib_http.Route("GET", re.compile(r"^/healthz$"), "health"),
    stdlib_http.Route("GET", re.compile(r"^/v1/service$"), "metadata"),
    stdlib_http.Route("POST", re.compile(r"^/v1/teams/provision$"), "team.provision"),
    stdlib_http.Route("POST", re.compile(r"^/v1/teams/finalize$"), "team.finalize"),
    stdlib_http.Route("POST", re.compile(r"^/v1/teams/drop$"), "team.drop"),
)


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Bound thread creation and expire slow database-control connections."""

    daemon_threads = True
    request_queue_size = 32

    def __init__(
        self,
        *args,
        max_concurrency: int = MAX_HTTP_CONCURRENCY,
        connection_timeout: int = HTTP_CONNECTION_TIMEOUT_SECONDS,
        **kwargs,
    ) -> None:
        self._request_slots = threading.BoundedSemaphore(max_concurrency)
        self._connection_timeout = connection_timeout
        super().__init__(*args, **kwargs)

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(self._connection_timeout)
        return request, client_address

    def process_request(self, request, client_address) -> None:
        if not self._request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()


class _FenceClock:
    """Wall-clock seconds that never run backward in this process; read only under the mutation lock.

    A provision is admitted only at or before its `not_after`, and a Team is proven absent only after it, both on this
    one clock. A wall-clock step backward therefore cannot reopen a fence the Service has already passed, and a
    delayed request never outlives this process because its socket closes with it.
    """

    def __init__(self) -> None:
        self._floor = 0.0

    def now(self) -> float:
        self._floor = max(self._floor, time.time())
        return self._floor


_fence_clock = _FenceClock()


def _require_fence_passed(not_after: int) -> None:
    """Refuse while a provisioning request fenced by `not_after` could still be admitted; hold the mutation lock."""
    if _fence_clock.now() <= not_after:
        raise ApiError(HTTPStatus.CONFLICT, "a provisioning request may still be in flight")


def _claim_resources(team_id: str, principal_token: str, project: str, database: str) -> bool:
    """Reconcile a recorded interrupted provisioning, then durably record this one before any DDL runs.

    Returns whether the Team's resources already exist under an active principal. Names without a registry record
    stay refused; names under a pending intent were proven absent before it was committed, so they belong to that
    interrupted attempt, never reached a Team, and are reclaimed before this attempt recreates them.
    """
    state = principal_store.provision_state(team_id, database)
    if state == principal_store.PENDING:
        postgresql_client.drop_db_and_role(project)
    existing = state == principal_store.ACTIVE
    postgresql_client.require_resources(project, registered=existing)
    if not existing:
        principal_store.record_pending(team_id, principal_token, database)
    return existing


def _provision_team(body: dict) -> dict:
    team_id = validate.validate_team_id(body.get("team_id"))
    principal_token = validate.validate_principal_token(body.get("principal_token"))
    not_after = validate.validate_not_after(body.get("not_after"))
    project = validate.team_project(team_id)
    database = postgresql_client.dbname(project)
    with postgresql_client.mutation_lock():
        # A delayed request must never land after Team may have proven this Team absent: once its fence has passed it
        # is refused before any registry change or DDL.
        if _fence_clock.now() > not_after:
            raise ApiError(HTTPStatus.CONFLICT, "provisioning request expired")
        existing = _claim_resources(team_id, principal_token, project, database)
        result = postgresql_client.create_db_and_role(project, existing=existing)
        # A failed registration keeps the resources: its commit may have landed before the failure surfaced, and
        # otherwise the pending intent still owns them, so a retry or Team drop reconciles them.
        principal_store.register(team_id, principal_token, database)
        return result.public()


def _drop_team(body: dict, token: str) -> dict:
    team_id = validate.validate_team_id(body.get("team_id"))
    with postgresql_client.mutation_lock():
        database = principal_store.database(token, team_id, allow_retired=True)
        postgresql_client.drop_db_and_role(database.removeprefix("proj_"))
        principal_store.retire(token, team_id)
        return {"dropped": [database]}


def _confirm_team_absent(body: dict) -> dict:
    """The provisioner's `team.drop`: prove, without any DDL, that nothing of this Team exists or can still appear.

    Provisioning can fail before its pending intent is recorded, leaving Team holding a principal this registry never
    admitted. `not_after` is the latest fence of every provisioning request Team may still have in flight. Absence is
    terminal only once that fence has passed, because every later provision is refused, so this succeeds only then
    and only when the Team has no registry record in any state and neither its database nor its role exists. Every
    real drop still requires the Team's own principal.
    """
    team_id = validate.validate_team_id(body.get("team_id"))
    not_after = validate.validate_not_after(body.get("not_after"))
    with postgresql_client.mutation_lock():
        _require_fence_passed(not_after)
        principal_store.require_unregistered(team_id)
        postgresql_client.require_resources(validate.team_project(team_id), registered=False)
        return {"dropped": []}


def _finalize_team(body: dict) -> dict:
    """Remove the Team's retired proof only once no fenced provisioning request can still be admitted.

    A retired or pending record refuses a delayed provision for its Team; removing it earlier would let that request
    recreate a database after Team discarded its principal and cleanup record.
    """
    team_id = validate.validate_team_id(body.get("team_id"))
    not_after = validate.validate_not_after(body.get("not_after"))
    with postgresql_client.mutation_lock():
        _require_fence_passed(not_after)
        principal_store.finalize(team_id)
    return {"finalized": True}


def _http_failure(exc: Exception) -> stdlib_http.HttpFailure | None:
    if isinstance(exc, ApiError):
        failure = stdlib_http.HttpFailure(exc.status, exc.message, exc.message, "denied")
    elif isinstance(exc, validate.ValidationError):
        message = str(exc)
        failure = stdlib_http.HttpFailure(HTTPStatus.BAD_REQUEST, message, message, "denied")
    elif isinstance(exc, principal_store.PrincipalError):
        failure = stdlib_http.HttpFailure(HTTPStatus.FORBIDDEN, "principal scope denied", str(exc), "denied")
    elif isinstance(exc, principal_store.PrincipalStoreError):
        failure = stdlib_http.HttpFailure(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            "principal registry unavailable",
            str(exc),
            "error",
        )
    elif isinstance(exc, postgresql_client.PostgreSQLError):
        failure = stdlib_http.HttpFailure(
            HTTPStatus.BAD_GATEWAY,
            "database operation failed",
            "database operation failed",
            "error",
        )
    elif isinstance(exc, (OSError, RuntimeError, ValueError, subprocess.SubprocessError)):
        failure = stdlib_http.HttpFailure(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            "internal service error",
            type(exc).__name__,
            "error",
        )
    else:
        failure = None
    return failure


def _run_operation(operation: str, body: dict, token: str) -> dict:
    if operation == "team.provision":
        return _provision_team(body)
    if operation == "team.finalize":
        return _finalize_team(body)
    if operation == "team.drop":
        return _drop_team(body, token) if token else _confirm_team_absent(body)
    raise ApiError(HTTPStatus.NOT_FOUND, f"unsupported operation: {operation}")


class Handler(BaseHTTPRequestHandler):
    """Serve one HTTP/1.0 request per connection; its request line, headers, and body share one absolute deadline."""

    server_version = f"{SERVICE.id}-service/{SERVICE.version}"
    request_deadline_seconds: float = REQUEST_DEADLINE_SECONDS

    def setup(self) -> None:
        super().setup()
        self.rfile.close()
        self._expires = time.monotonic() + self.request_deadline_seconds
        self.rfile = io.BufferedReader(deadline.DeadlineReader(self.connection, self._expires))
        self._request_body = deadline.ExactBody(self.rfile)

    def finish(self) -> None:
        super().finish()
        if self._body_unread():
            deadline.linger_close(self.connection, self._expires)

    def _body_unread(self) -> bool:
        """Whether parsed headers declared a body that a refusal or failure left unread on the socket."""
        headers = getattr(self, "headers", None)
        if headers is None or self._request_body.complete:
            return False
        return headers.get("Content-Length", "0") not in {"", "0"} or "Transfer-Encoding" in headers

    def _bearer(self) -> str:
        return stdlib_http.bearer_token(self.headers)

    def _is_provisioner(self) -> bool:
        return stdlib_http.bearer_authorized(self.headers, _provisioner_token)

    def _send_json(self, status: HTTPStatus, payload: object) -> None:
        stdlib_http.send_json(self, status, payload)

    def _body(self) -> dict:
        return stdlib_http.read_json_body(self.headers, self._request_body, max_bytes=MAX_BODY_BYTES)

    def _dispatch(self, method: str) -> None:
        stdlib_http.dispatch(
            lambda: self._route(method),
            classify=_http_failure,
            emit=lambda failure: self._emit_failure(method, failure),
            unexpected_message="internal service error",
        )

    def _emit_failure(self, method: str, failure: stdlib_http.HttpFailure) -> None:
        audit.log(method.lower(), self.path, result=failure.result, reason=failure.audit_reason)
        self._send_json(failure.status, {"error": failure.public_message})

    def _route(self, method: str) -> None:
        route = stdlib_http.resolve_route(_ROUTES, method, self.path)
        if route.operation == "health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return
        if route.operation == "metadata":
            self._send_json(HTTPStatus.OK, SERVICE.public())
            return
        # Authenticate before reading any body, so an unknown caller can never hold a worker with one.
        token = self._bearer()
        if not token:
            raise ApiError(HTTPStatus.FORBIDDEN, "bearer required")
        provisioner = self._is_provisioner()
        if route.operation in {"team.provision", "team.finalize"} and not provisioner:
            raise ApiError(HTTPStatus.FORBIDDEN, "provisioner bearer required")
        if not provisioner and not principal_store.is_principal(token):
            raise principal_store.PrincipalError("unknown principal")
        body = self._body()
        # The provisioner can never drop a Team database; its `team.drop` only proves the Team absent.
        result = _run_operation(route.operation, body, "" if provisioner else token)
        trace = audit.log(route.operation, body.get("team_id", "?"), result="ok")
        self._send_json(HTTPStatus.OK, {**result, "trace_id": trace})

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def log_message(self, fmt: str, *args: object) -> None:
        pass


def main() -> None:
    server = BoundedThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    print(f"postgresql-service listening on :{LISTEN_PORT}; tenant principals only", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
