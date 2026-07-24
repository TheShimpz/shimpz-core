"""Bounded HTTP transport and route dispatch for the hosted Team controller."""

from __future__ import annotations

import contextlib
import functools
import json
import threading
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import accounts_client
import audit
import brain_runtime_token_store
import docker
import marketplace
import runtime_state
import validate
from assistant_human import approval_flow as assistant_approval_flow
from assistant_human import hosted_assistants, hosted_chat_api, hosted_chat_segment
from assistant_human import input_flow as assistant_input_flow
from container_policy import hosted_apps, hosted_lifecycle, hosted_resources

from http_boundary import hosted, stdlib
from http_boundary import strict as strict_http


@dataclass(frozen=True, slots=True)
class _AuthorizedRequest:
    params: dict[str, str]
    team_id: str
    principal: tuple[str, str | None]
    lease: hosted_resources._AuthorizationLease
    query: dict[str, str]


class _BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Thread-per-request server with hard admission and slow-client expiry."""

    daemon_threads = True

    def __init__(self, *args, max_concurrency: int | None = None, **kwargs) -> None:
        concurrency = runtime_state.MAX_HTTP_CONCURRENCY if max_concurrency is None else max_concurrency
        self._request_slots = threading.BoundedSemaphore(concurrency)
        super().__init__(*args, **kwargs)

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(runtime_state.HTTP_CONNECTION_TIMEOUT_SECONDS)
        return request, client_address

    def process_request(self, request, client_address) -> None:
        # Backpressure happens before a thread exists. At the ceiling, at most the kernel's bounded
        # listen backlog plus this accepted socket waits; Python thread count cannot grow unbounded.
        self._request_slots.acquire()
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


class Handler(BaseHTTPRequestHandler):
    server_version = "team-driver/1.0"

    def log_message(self, *_args) -> None:  # audit.log is the ONLY log source
        pass

    def _principal(self) -> tuple[str, str | None] | None:
        """('operator', None) for the admin bearer; ('account', <id>) for a valid account token; else None.

        The operator token (the admin panel) has full access. A store-forwarded account token is verified
        against the accounts service and scopes every op to that account's OWN teams — the store holds
        no privileged secret, this driver is the enforcer.
        """
        if strict_http.bearer_matches(self.headers, runtime_state._token):
            return ("operator", None)
        account_token = self.headers.get("X-Shimpz-Account", "")
        if account_token:
            account_id = accounts_client.verify(account_token)
            if account_id:
                return ("account", account_id)
        return None

    def _send_json(self, status: HTTPStatus, payload: dict, *, no_store: bool = False) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if no_store:
            self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _stream_chat(
        self,
        team_id: str,
        message: str,
        file_ids: object,
        assistant_ids: tuple[str, ...],
        lease: hosted_resources._AuthorizationLease,
    ) -> None:
        """Preserve the NDJSON transport while exposing only the validated terminal reply."""
        terminal: dict[str, object]
        stream_error = None
        with hosted_chat_api._exclusive_chat_turn(team_id, lease) as (token, container):
            pending = hosted_chat_api._pending_hosted_chat(team_id)
            if pending is not None:
                self._send_json(
                    HTTPStatus.PRECONDITION_REQUIRED,
                    pending,
                    no_store=True,
                )
                return
                # The durable token is claimed before a 200 or any response byte reaches the client.
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/x-ndjson")
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

            def emit(obj: dict) -> None:
                line = (json.dumps(obj, ensure_ascii=False) + "\n").encode()
                self.wfile.write(f"{len(line):X}\r\n".encode() + line + b"\r\n")
                self.wfile.flush()

            try:
                result = hosted_chat_segment._chat_in_turn(
                    team_id,
                    message,
                    file_ids,
                    assistant_ids,
                    token,
                    container,
                    lease.owner,
                )
                paused = result.get("status") in hosted_assistants.CHAT_PAUSED_STATUSES
                terminal = (
                    {"type": str(result["status"]), **result}
                    if paused
                    else {
                        "type": "done",
                        "reply": result["reply"],
                        "team_id": result["team_id"],
                        "team_name": result["team_name"],
                    }
                )
                emit(terminal)
            except runtime_state.ApiError as exc:
                terminal = (
                    {"type": "stopped"}
                    if exc.status == HTTPStatus.CONFLICT and exc.message == "brain turn stopped"
                    else {"type": "error", "status": int(exc.status), "detail": exc.message}
                )
                with contextlib.suppress(OSError):
                    emit(terminal)
            except (docker.errors.DockerException, OSError) as exc:
                stream_error = type(exc).__name__
                terminal = {"type": "error", "status": 500, "detail": "brain stream failed"}
                with contextlib.suppress(OSError):
                    emit(terminal)
            finally:
                with contextlib.suppress(OSError):
                    self.wfile.write(b"0\r\n\r\n")
                    self.wfile.flush()
        audit.log(
            "chat",
            team_id,
            result="ok" if terminal["type"] in {"done", "accounts-required", "secrets-required"} else "error",
            streamed=True,
            status=terminal.get("status"),
            reason=stream_error,
        )

    def _read_body(self, *, max_bytes: int | None = None) -> dict:
        try:
            return strict_http.read_json_object(
                self.headers,
                self.rfile,
                max_bytes=runtime_state.MAX_JSON_BODY_BYTES if max_bytes is None else max_bytes,
            )
        except strict_http.HttpContractError as exc:
            raise runtime_state.ApiError(exc.status, exc.message) from exc

    def _read_file_body(self) -> tuple[str, bytes, str]:
        try:
            return strict_http.read_file_upload(
                self.headers,
                self.rfile,
                max_bytes=hosted_assistants.MAX_FILE_BODY_BYTES,
            )
        except strict_http.HttpContractError as exc:
            raise runtime_state.ApiError(exc.status, exc.message) from exc

    def _read_driver_body(self, keys: set[str]) -> dict[str, object]:
        """Read one closed Driver mutation document; arbitrary scripts/shapes never cross the bridge."""
        body = self._read_body(max_bytes=runtime_state.MAX_DRIVER_JSON_BODY_BYTES)
        if not isinstance(body, dict) or set(body) != keys:
            raise runtime_state.ApiError(HTTPStatus.BAD_REQUEST, "request body does not match the Driver operation")
        return body

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def _dispatch(self, method: str) -> None:
        principal = self._principal()
        if principal is None:
            if self.client_address[0] == "127.0.0.1":
                audit.log("auth", self.path, result="denied", level="info", source="loopback-probe")
            else:
                audit.log("auth", self.path, result="denied")
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "invalid or missing credentials"})
            return
        stdlib.dispatch(
            lambda: self._route(method, principal),
            classify=lambda exc: hosted.classify_failure(
                exc,
                runtime_state.ApiError,
                validate.ValidationError,
                marketplace.MarketplaceError,
            ),
            emit=lambda failure: self._emit_failure(method, failure),
            unexpected_message="internal driver error",
        )

    def _emit_failure(self, method: str, failure: stdlib.HttpFailure) -> None:
        audit.log(method.lower(), self.path, result=failure.result, reason=failure.audit_reason)
        self._send_json(failure.status, {"error": failure.public_message})

    def _route(self, method: str, principal: tuple[str, str | None]) -> None:
        target, route = hosted.route_target(self.headers, self.path, method, runtime_state.ApiError)
        global_handler = _GLOBAL_ROUTES.get(route.operation)
        if global_handler is not None:
            global_handler(self, principal)
            return

        team_id = validate.validate_team_id(route.params["team_id"])
        preauthorized_handler = _PREAUTHORIZED_ROUTES.get(route.operation)
        if preauthorized_handler is not None:
            preauthorized_handler(self, team_id, principal)
            return

        lease = hosted_resources._authorize(team_id, principal)
        request = _AuthorizedRequest(route.params, team_id, principal, lease, target.query)
        _AUTHORIZED_ROUTES[route.operation](self, request)

    def _route_team_list(self, principal: tuple[str, str | None]) -> None:
        kind, account_id = principal
        self._send_json(
            HTTPStatus.OK,
            hosted_lifecycle._list(owner=account_id if kind == "account" else None),
        )

    def _route_assistant_account_complete(self, principal: tuple[str, str | None]) -> None:
        result = hosted_chat_api._complete_oauth_account(self._read_body(), principal)
        audit.log(
            "assistant_account_complete",
            result["team_id"],
            result="ok",
            assistant=result["assistant_id"],
            account=result["account_id"],
            provider=result["provider"],
        )
        self._send_json(HTTPStatus.OK, result, no_store=True)

    def _route_team_create(self, team_id: str, principal: tuple[str, str | None]) -> None:
        runtime_state._enforce_rate("create", principal)
        body = self._read_body()
        _kind, account_id = principal
        owner = account_id or str(body.get("owner", "")).strip()
        result = hosted_lifecycle._create(team_id, body, owner)
        trace = audit.log("create", team_id, result="ok", created=result.get("created"), owner=owner)
        self._send_json(HTTPStatus.OK, {**result, "trace_id": trace})

    def _route_team_destroy(self, team_id: str, principal: tuple[str, str | None]) -> None:
        # Destroy may authorize against a bounded non-runnable cleanup successor.
        lease = hosted_resources._authorize_destroy(team_id, principal)
        result = hosted_lifecycle._destroy(team_id, lease)
        trace = audit.log("destroy", team_id, result="ok", db_dropped=result["db_dropped"])
        self._send_json(HTTPStatus.OK, {**result, "trace_id": trace})

    def _route_assistant_account_list(self, request: _AuthorizedRequest) -> None:
        self._send_json(
            HTTPStatus.OK,
            hosted_assistants._assistant_account_inventory(request.team_id, request.lease),
            no_store=True,
        )

    def _route_assistant_account_authorize(self, request: _AuthorizedRequest) -> None:
        body = self._read_body()
        if not isinstance(body, dict) or set(body) != {"session_binding"}:
            raise runtime_state.ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "OAuth authorization request is invalid")
        result = hosted_chat_api._start_oauth_account(
            request.team_id,
            request.params["challenge_id"],
            body["session_binding"],
            request.lease,
        )
        audit.log("assistant_account_start", request.team_id, result="ok")
        self._send_json(HTTPStatus.OK, result, no_store=True)

    def _route_assistant_account_disconnect(self, request: _AuthorizedRequest) -> None:
        assistant_id = request.params["assistant_id"]
        account_id = request.params["account_id"]
        result = hosted_chat_api._disconnect_oauth_account(
            request.team_id,
            assistant_id,
            account_id,
            request.lease,
        )
        audit.log(
            "assistant_account_disconnect",
            request.team_id,
            result="ok",
            assistant=assistant_id,
            account=account_id,
            disconnected=result["disconnected"],
        )
        self._send_json(HTTPStatus.OK, result, no_store=True)

    def _route_assistant_secret_list(self, request: _AuthorizedRequest) -> None:
        self._send_json(
            HTTPStatus.OK,
            hosted_assistants._assistant_secret_inventory(request.team_id, request.lease),
            no_store=True,
        )

    def _route_assistant_secret_replace(self, request: _AuthorizedRequest) -> None:
        runtime_state._enforce_rate("secret", request.principal)
        body = self._read_body(max_bytes=runtime_state.MAX_ASSISTANT_SECRET_BODY_BYTES)
        result = hosted_assistants._replace_assistant_secrets(request.team_id, body, request.lease)
        audit.log(
            "assistant_secret_replace",
            request.team_id,
            result="ok",
            assistant=body.get("assistant_id") if isinstance(body, dict) else None,
        )
        self._send_json(HTTPStatus.OK, result, no_store=True)

    def _route_team_status(self, request: _AuthorizedRequest) -> None:
        self._send_json(HTTPStatus.OK, hosted_lifecycle._status(request.team_id, request.lease))

    def _route_team_logs(self, request: _AuthorizedRequest) -> None:
        lines = int(request.query.get("lines", "200"))
        self._send_json(
            HTTPStatus.OK,
            hosted_lifecycle._logs(request.team_id, lines, request.lease),
        )

    def _route_team_lifecycle(self, request: _AuthorizedRequest, *, operation: str) -> None:
        result = hosted_lifecycle._lifecycle(request.team_id, operation, request.lease)
        audit.log(operation, request.team_id, result="ok")
        self._send_json(HTTPStatus.OK, result)

    def _route_file_list(self, request: _AuthorizedRequest) -> None:
        self._send_json(
            HTTPStatus.OK,
            hosted_lifecycle._list_team_files(request.team_id, request.lease),
        )

    def _route_file_upload(self, request: _AuthorizedRequest) -> None:
        runtime_state._enforce_rate("file_upload", request.principal)
        if not runtime_state._file_upload_slots.acquire(blocking=False):
            raise runtime_state.ApiError(
                HTTPStatus.TOO_MANY_REQUESTS,
                "another Team file upload is in progress",
            )
        try:
            filename, content, media_type = self._read_file_body()
            result = hosted_lifecycle._put_inbox_file(
                request.team_id,
                filename,
                content,
                media_type,
                request.lease,
            )
        finally:
            runtime_state._file_upload_slots.release()
        trace = audit.log(
            "team_file_upload",
            request.team_id,
            result="ok",
            file_id=result["file"]["id"],
            bytes=result["file"]["size"],
        )
        self._send_json(HTTPStatus.OK, {**result, "trace_id": trace})

    def _route_file_delete(self, request: _AuthorizedRequest) -> None:
        result = hosted_lifecycle._delete_team_file(
            request.team_id,
            request.params["file_id"],
            request.lease,
        )
        trace = audit.log(
            "team_file_delete",
            request.team_id,
            result="ok",
            file_id=result["id"],
            deleted=result["deleted"],
        )
        self._send_json(HTTPStatus.OK, {**result, "trace_id": trace})

    def _route_inference_status(self, request: _AuthorizedRequest) -> None:
        self._send_json(
            HTTPStatus.OK,
            hosted_lifecycle._inference_status(request.team_id, request.lease),
        )

    def _route_inference_configure(self, request: _AuthorizedRequest) -> None:
        self._send_json(
            HTTPStatus.OK,
            hosted_lifecycle._configure_inference(
                request.team_id,
                self._read_body(),
                request.lease,
            ),
        )

    def _route_human_chat(
        self,
        request: _AuthorizedRequest,
        kind: str,
        *,
        submit: bool,
    ) -> None:
        if kind == "input":
            challenge = runtime_state._assistant_input_challenges.current(request.team_id)
            payload = assistant_input_flow.challenge_payload
            submit_challenge = hosted_chat_api._submit_chat_input
        else:
            challenge = runtime_state._assistant_approval_challenges.current(request.team_id)
            payload = assistant_approval_flow.challenge_payload
            submit_challenge = hosted_chat_api._submit_chat_approval
        if not submit:
            self._send_json(
                HTTPStatus.OK,
                (payload(challenge) if challenge is not None else {"team_id": request.team_id, "status": "none"}),
                no_store=True,
            )
            return
        runtime_state._enforce_rate("chat", request.principal)
        result = submit_challenge(request.team_id, self._read_body(), request.lease)
        paused = result.get("status") in hosted_assistants.CHAT_PAUSED_STATUSES
        self._send_json(
            HTTPStatus.PRECONDITION_REQUIRED if paused else HTTPStatus.OK,
            result,
            no_store=True,
        )

    def _route_chat_turn(
        self,
        request: _AuthorizedRequest,
        *,
        stream: bool,
    ) -> None:
        body = self._read_body()
        if not isinstance(body, dict) or set(body) != {"message", "files", "assistant_ids"}:
            raise runtime_state.ApiError(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                "Team chat requires message, files, and assistant_ids",
            )
        message = validate.validate_chat_message(body["message"])
        file_ids = body["files"]
        assistant_ids = hosted_assistants._chat_assistant_ids(body["assistant_ids"])
        if stream:
            runtime_state._enforce_rate("stream", request.principal)
            pending = hosted_chat_api._pending_hosted_chat(request.team_id)
            if pending is not None:
                self._send_json(
                    HTTPStatus.PRECONDITION_REQUIRED,
                    pending,
                    no_store=True,
                )
                return
            self._stream_chat(request.team_id, message, file_ids, assistant_ids, request.lease)
            return
        runtime_state._enforce_rate("chat", request.principal)
        result = hosted_chat_api._chat(
            request.team_id,
            message,
            file_ids,
            assistant_ids,
            request.lease,
        )
        audit.log(
            "chat",
            request.team_id,
            result="ok",
            chars_in=len(message),
            chars_out=len(str(result.get("reply", ""))),
            paused=result.get("status") in hosted_assistants.CHAT_PAUSED_STATUSES,
        )
        paused = result.get("status") in hosted_assistants.CHAT_PAUSED_STATUSES
        self._send_json(
            HTTPStatus.PRECONDITION_REQUIRED if paused else HTTPStatus.OK,
            result,
            no_store=paused,
        )

    def _route_chat_accounts(
        self,
        request: _AuthorizedRequest,
        *,
        submit: bool,
    ) -> None:
        if not submit:
            pending = runtime_state._assistant_account_challenges.current(request.team_id)
            self._send_json(
                HTTPStatus.OK,
                (
                    hosted_chat_segment._hosted_account_challenge_payload(pending)
                    if pending is not None
                    else {"team_id": request.team_id, "status": "none"}
                ),
                no_store=True,
            )
            return
        runtime_state._enforce_rate("chat", request.principal)
        body = self._read_body()
        if not isinstance(body, dict) or set(body) != {"challenge_id"}:
            raise runtime_state.ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "account continuation is invalid")
        result = hosted_chat_api._resume_chat_accounts(
            request.team_id,
            body["challenge_id"],
            request.lease,
        )
        paused = result.get("status") in hosted_assistants.CHAT_PAUSED_STATUSES
        self._send_json(
            HTTPStatus.PRECONDITION_REQUIRED if paused else HTTPStatus.OK,
            result,
            no_store=True,
        )

    def _route_chat_secrets(
        self,
        request: _AuthorizedRequest,
        *,
        submit: bool,
    ) -> None:
        if not submit:
            self._send_json(
                HTTPStatus.OK,
                hosted_assistants._pending_chat_secrets(request.team_id, request.lease),
                no_store=True,
            )
            return
        runtime_state._enforce_rate("chat", request.principal)
        result = hosted_chat_api._submit_chat_secrets(
            request.team_id,
            self._read_body(max_bytes=runtime_state.MAX_ASSISTANT_SECRET_BODY_BYTES),
            request.lease,
        )
        paused = result.get("status") in hosted_assistants.CHAT_PAUSED_STATUSES
        self._send_json(
            HTTPStatus.PRECONDITION_REQUIRED if paused else HTTPStatus.OK,
            result,
            no_store=True,
        )

    def _route_chat_stop(self, request: _AuthorizedRequest) -> None:
        runtime_state._enforce_rate("stop", request.principal)
        self._send_json(
            HTTPStatus.OK,
            hosted_chat_api._stop_chat(request.team_id, request.lease),
        )

    def _route_app_install(self, request: _AuthorizedRequest) -> None:
        kind, account_id = request.principal
        runtime_state._enforce_rate("install", request.principal)
        app_id, spec = marketplace.resolve(self._read_body().get("app"))
        # A non-first-party app requires a verified Shimpz account.
        if not spec.first_party and kind != "account":
            raise runtime_state.ApiError(
                HTTPStatus.UNAUTHORIZED,
                f"installing {app_id!r} requires a valid Shimpz account",
            )
        owner = account_id or request.lease.owner
        result = hosted_apps._install_app(
            request.team_id,
            app_id,
            spec,
            owner,
            request.lease,
        )
        trace = audit.log(
            "install",
            request.team_id,
            result="ok",
            app=app_id,
            installed=result["installed"],
        )
        self._send_json(HTTPStatus.OK, {**result, "trace_id": trace})

    def _route_app_list(self, request: _AuthorizedRequest) -> None:
        self._send_json(
            HTTPStatus.OK,
            hosted_apps._list_apps(request.team_id, request.lease),
        )

    def _route_app_uninstall(self, request: _AuthorizedRequest) -> None:
        # Shape-validated only: a delisted app must remain uninstallable.
        app_id = marketplace.validate_app_id(request.params["app_id"])
        result = hosted_apps._uninstall_app(request.team_id, app_id, request.lease)
        trace = audit.log(
            "uninstall",
            request.team_id,
            result="ok",
            app=app_id,
            db_dropped=result["db_dropped"],
        )
        self._send_json(HTTPStatus.OK, {**result, "trace_id": trace})

    def _route_assistant_help(self, request: _AuthorizedRequest) -> None:
        if request.query:
            raise runtime_state.ApiError(HTTPStatus.BAD_REQUEST, "query and encoded paths are not accepted")
        assistant_id = marketplace.validate_app_id(request.params["assistant_id"])
        help_payload = hosted_assistants._assistant_help(
            request.team_id,
            assistant_id,
            request.lease,
            request.params.get("locale", "en"),
        )
        trace = audit.log(
            "assistant_help",
            request.team_id,
            result="ok",
            assistant=help_payload["assistant"],
        )
        self._send_json(
            HTTPStatus.OK,
            {**help_payload, "trace_id": trace},
            no_store=True,
        )


_GLOBAL_ROUTES = {
    "team-list": Handler._route_team_list,
    "assistant-account-complete": Handler._route_assistant_account_complete,
}
_PREAUTHORIZED_ROUTES = {
    "team-create": Handler._route_team_create,
    "team-destroy": Handler._route_team_destroy,
}
_AUTHORIZED_ROUTES = {
    "file-list": Handler._route_file_list,
    "file-upload": Handler._route_file_upload,
    "file-delete": Handler._route_file_delete,
    "inference-status": Handler._route_inference_status,
    "inference-configure": Handler._route_inference_configure,
    "chat": functools.partial(Handler._route_chat_turn, stream=False),
    "chat-stream": functools.partial(Handler._route_chat_turn, stream=True),
    "chat-account-pending": functools.partial(Handler._route_chat_accounts, submit=False),
    "chat-account-submit": functools.partial(Handler._route_chat_accounts, submit=True),
    "chat-secret-pending": functools.partial(Handler._route_chat_secrets, submit=False),
    "chat-secret-submit": functools.partial(Handler._route_chat_secrets, submit=True),
    "chat-input-pending": functools.partial(Handler._route_human_chat, kind="input", submit=False),
    "chat-input-submit": functools.partial(Handler._route_human_chat, kind="input", submit=True),
    "chat-approval-pending": functools.partial(Handler._route_human_chat, kind="approval", submit=False),
    "chat-approval-submit": functools.partial(Handler._route_human_chat, kind="approval", submit=True),
    "chat-stop": Handler._route_chat_stop,
    "assistant-secret-list": Handler._route_assistant_secret_list,
    "assistant-secret-replace": Handler._route_assistant_secret_replace,
    "assistant-account-list": Handler._route_assistant_account_list,
    "assistant-account-authorize": Handler._route_assistant_account_authorize,
    "assistant-account-disconnect": Handler._route_assistant_account_disconnect,
    "assistant-help": Handler._route_assistant_help,
    "app-list": Handler._route_app_list,
    "app-install": Handler._route_app_install,
    "app-uninstall": Handler._route_app_uninstall,
    "team-status": Handler._route_team_status,
    "team-logs": Handler._route_team_logs,
    "team-stop": functools.partial(Handler._route_team_lifecycle, operation="stop"),
    "team-start": functools.partial(Handler._route_team_lifecycle, operation="start"),
    "team-restart": functools.partial(Handler._route_team_lifecycle, operation="restart"),
}


def main() -> None:
    # The Controller owns this bearer. The runtime receives the same named volume read-only and
    # cannot rotate or replace its authority.
    brain_runtime_token_store.ensure()
    _BoundedThreadingHTTPServer((runtime_state.ALL_INTERFACES, runtime_state.LISTEN_PORT), Handler).serve_forever()
