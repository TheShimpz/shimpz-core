"""Hosted Team-controller HTTP parsing and error projection."""

from __future__ import annotations

from http import HTTPStatus

from . import stdlib, strict


def route_target(headers: object, path: str, method: str, error_type: type[Exception]):
    try:
        target = strict.parse_routed_request(
            headers,
            path,
            method,
            body_methods=frozenset({"POST", "PUT"}),
            allow_query=True,
        )
    except strict.HttpContractError as exc:
        raise error_type(exc.status, exc.message) from exc
    route = strict.resolve_controller_route(strict.HOSTED_CONTROLLER, method, target.parts)
    if route is None:
        raise error_type(HTTPStatus.NOT_FOUND, f"no such operation: {method} {target.path}")
    return target, route


def classify_failure(
    exc: Exception,
    api_error_type: type[Exception],
    validation_error_type: type[Exception],
    marketplace_error_type: type[Exception],
) -> stdlib.HttpFailure | None:
    if isinstance(exc, api_error_type):
        return stdlib.HttpFailure(exc.status, exc.message, exc.message, "denied")
    if isinstance(exc, validation_error_type):
        message = str(exc)
        return stdlib.HttpFailure(HTTPStatus.BAD_REQUEST, message, message, "denied")
    if isinstance(exc, marketplace_error_type):
        message = str(exc)
        return stdlib.HttpFailure(HTTPStatus.NOT_FOUND, message, message, "denied")
    return None
