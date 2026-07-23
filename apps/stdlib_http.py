"""Small fail-closed primitives for stdlib HTTP control-plane services."""

from __future__ import annotations

import hmac
import json
from http import HTTPStatus
from typing import BinaryIO


class HttpError(ValueError):
    def __init__(self, status: HTTPStatus, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def bearer_authorized(headers: object, token: str) -> bool:
    """Accept one exact bearer header and compare it in constant time."""
    get_all = getattr(headers, "get_all", None)
    values = get_all("Authorization", failobj=[]) if get_all is not None else []
    return len(values) == 1 and hmac.compare_digest(values[0], f"Bearer {token}")


def send_json(handler: object, status: HTTPStatus, payload: object) -> None:
    body = json.dumps(payload).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def read_json_body(headers: object, stream: BinaryIO, *, max_bytes: int) -> dict[str, object]:
    raw_length = headers.get("Content-Length", "0") or "0"
    try:
        length = int(raw_length)
    except ValueError as exc:
        raise HttpError(HTTPStatus.BAD_REQUEST, "invalid Content-Length") from exc
    if length < 0 or length > max_bytes:
        raise HttpError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "request body is too large")
    if length == 0:
        return {}
    try:
        body = json.loads(stream.read(length))
    except json.JSONDecodeError as exc:
        raise HttpError(HTTPStatus.BAD_REQUEST, "invalid JSON body") from exc
    if not isinstance(body, dict):
        raise HttpError(HTTPStatus.BAD_REQUEST, "JSON body must be an object")
    return body
