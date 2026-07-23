"""Local Team-controller HTTP dispatch and stable failure projection."""

from __future__ import annotations

from http import HTTPStatus

import stdlib_http


def dispatch_route(route, record, send, problem_type: type[Exception], docker_error_type: type[Exception]) -> None:
    operation = "request"
    team_id = None
    assistant_id = None

    def action() -> None:
        nonlocal operation, team_id, assistant_id
        status, payload, operation, team_id, assistant_id = route()
        trace_id = record(operation, result="ok", team_id=team_id, assistant=assistant_id)
        payload["trace_id"] = trace_id
        send(status, payload)

    def classify(exc: Exception) -> stdlib_http.HttpFailure:
        if isinstance(exc, problem_type):
            return stdlib_http.HttpFailure(
                exc.status,
                exc.message,
                exc.code,
                "denied" if exc.status < 500 else "error",
                exc.code,
            )
        if isinstance(exc, docker_error_type):
            return stdlib_http.HttpFailure(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "Docker is unavailable",
                "docker-error",
                "error",
            )
        return stdlib_http.HttpFailure(
            HTTPStatus.INTERNAL_SERVER_ERROR,
            "internal error",
            "internal-error",
            "error",
        )

    def emit(failure: stdlib_http.HttpFailure) -> None:
        trace_id = record(
            operation,
            result=failure.result,
            team_id=team_id,
            assistant=assistant_id,
            detail=failure.audit_reason,
        )
        payload = {"error": failure.public_message, "trace_id": trace_id}
        if failure.public_code is not None:
            payload["code"] = failure.public_code
        send(failure.status, payload)

    stdlib_http.dispatch(
        action,
        classify=classify,
        emit=emit,
        unexpected_message="internal error",
    )
