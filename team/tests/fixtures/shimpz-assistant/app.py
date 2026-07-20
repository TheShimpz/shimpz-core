"""Deterministic Shimpz Assistant used only by the Docker integration contract."""

from __future__ import annotations

import json
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer

MAX_BODY = 16 * 1024
HELP_PATHS = {"/v1/help", *(f"/v1/help/{locale}" for locale in ("en", "pt", "es", "zh", "fr", "de", "ja", "ar"))}
X_POWERS = {"public-user-lookup", "identity-me", "create-post", "delete-post"}
MUX_API_POWERS = {"list-direct-uploads", "create-test-direct-upload", "cancel-direct-upload"}
MUX_WEBHOOK_POWERS = {"verify-mux-webhook"}
POWERS = X_POWERS | MUX_API_POWERS | MUX_WEBHOOK_POWERS
USERNAME_RE = re.compile(r"[A-Za-z0-9_]{1,15}\Z")
POST_ID_RE = re.compile(r"[0-9]{1,19}\Z")
MUX_UPLOAD_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")


def _power_input(payload: object, power: str) -> dict[str, object]:
    if not isinstance(payload, dict) or set(payload) != {"input", "secrets", "accounts"}:
        raise ValueError
    power_input = payload["input"]
    secrets = payload["secrets"]
    accounts = payload["accounts"]
    if not isinstance(power_input, dict) or not isinstance(secrets, dict) or not isinstance(accounts, dict):
        raise ValueError
    if power in MUX_API_POWERS | MUX_WEBHOOK_POWERS:
        expected = {"mux-token-id", "mux-token-secret"} if power in MUX_API_POWERS else {"mux-webhook-signing-secret"}
        if (
            accounts
            or set(secrets) != expected
            or not all(isinstance(value, str) and value for value in secrets.values())
        ):
            raise ValueError
        return power_input
    if secrets or power not in X_POWERS:
        raise ValueError
    if set(accounts) != {"x"}:
        raise ValueError
    account = accounts["x"]
    if not isinstance(account, dict) or set(account) != {"type", "access_token"}:
        raise ValueError
    token = account["access_token"]
    if account["type"] != "oauth2-bearer" or not isinstance(token, str):
        raise ValueError
    try:
        encoded_token = token.encode("ascii")
    except UnicodeError as exc:
        raise ValueError from exc
    if not 16 <= len(encoded_token) <= 16 * 1024 or any(byte <= 32 or byte >= 127 for byte in encoded_token):
        raise ValueError
    return power_input


def _x_power_result(power: str, power_input: dict[str, object]) -> dict[str, object]:
    if power == "public-user-lookup":
        if set(power_input) != {"username"} or not isinstance(power_input["username"], str):
            raise ValueError
        username = power_input["username"]
        if USERNAME_RE.fullmatch(username) is None:
            raise ValueError
        return {"id": "123456789", "name": "X fixture user", "username": username}
    if power == "identity-me":
        if power_input:
            raise ValueError
        return {
            "id": "987654321",
            "name": "Connected fixture account",
            "username": "fixture_account",
        }
    if power == "create-post":
        if set(power_input) != {"text"} or not isinstance(power_input["text"], str):
            raise ValueError
        text = power_input["text"]
        if not 1 <= len(text) <= 8192 or text != text.strip():
            raise ValueError
        return {"id": "246813579", "text": text}
    if power == "delete-post":
        if set(power_input) != {"id"} or not isinstance(power_input["id"], str):
            raise ValueError
        if POST_ID_RE.fullmatch(power_input["id"]) is None:
            raise ValueError
        return {"deleted": True}
    raise ValueError


def _mux_power_result(power: str, power_input: dict[str, object]) -> dict[str, object]:
    if power == "list-direct-uploads":
        limit = power_input.get("limit")
        if (
            set(power_input) != {"limit"}
            or isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 25
        ):
            raise ValueError
        return {"uploads": []}
    if power == "create-test-direct-upload":
        if power_input:
            raise ValueError
        return {"id": "fixture_upload", "status": "waiting", "timeout": 60}
    if power == "cancel-direct-upload":
        upload_id = power_input.get("id")
        if (
            set(power_input) != {"id"}
            or not isinstance(upload_id, str)
            or MUX_UPLOAD_ID_RE.fullmatch(upload_id) is None
        ):
            raise ValueError
        return {"id": upload_id, "status": "cancelled", "timeout": 60}
    raise ValueError


def _power_result(power: str, power_input: dict[str, object]) -> dict[str, object]:
    if power in X_POWERS:
        return _x_power_result(power, power_input)
    if power in MUX_API_POWERS:
        return _mux_power_result(power, power_input)
    if set(power_input) != {"body", "signature"}:
        raise ValueError
    if not all(isinstance(power_input[key], str) and power_input[key] for key in ("body", "signature")):
        raise ValueError
    return {"valid": True, "timestamp": 0, "event_type": "video.upload.asset_created"}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args) -> None:
        return

    def _send(self, status: HTTPStatus, payload: dict[str, object]) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(HTTPStatus.OK, {"status": "ok"})
            return
        if self.path in HELP_PATHS:
            self._send(
                HTTPStatus.OK,
                {"markdown": "# Shimpz Assistant\n\nRead public X profiles or manage approved Posts."},
            )
            return
        self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:
        power = self.path.removeprefix("/v1/powers/")
        if power not in POWERS or self.path != f"/v1/powers/{power}":
            self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            if not 2 <= length <= MAX_BODY or self.headers.get("Content-Type") != "application/json":
                raise ValueError
            payload = json.loads(self.rfile.read(length))
            result = _power_result(power, _power_input(payload, power))
        except ValueError, UnicodeError, json.JSONDecodeError:
            self._send(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": "invalid input"})
            return
        self._send(HTTPStatus.OK, result)


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8080), Handler).serve_forever()
