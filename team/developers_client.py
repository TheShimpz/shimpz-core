"""Fixed internal client for Controller-to-Developers install decisions."""

from __future__ import annotations

import http.client
import json
from pathlib import Path
from typing import Any

from developers_controller_contract import ContractValidationError, ContractValidator

_HOST = "developers-api"
_PORT = 8080
_TIMEOUT_SECONDS = 10
_MAX_RESPONSE_BYTES = 1024 * 1024
_CONTRACTS = ContractValidator()


class DevelopersClientError(RuntimeError):
    """Developers could not provide a trustworthy installation decision."""


class AssistantNotInstallableError(DevelopersClientError):
    """The publication is not currently installable."""


class InstallAuthorizationDeniedError(DevelopersClientError):
    """The final, request-bound installation authorization was denied."""


class DevelopersClient:
    def __init__(self, service_token_file: Path) -> None:
        self._service_token = _read_service_token(service_token_file)

    def resolve(self, source_digest: str) -> dict[str, Any]:
        status, value = self._request(
            "GET",
            f"/internal/v1/assistants/{source_digest}",
            None,
        )
        if status == 404:
            raise AssistantNotInstallableError("Assistant is not installable")
        if status != 200:
            raise DevelopersClientError("Developers resolution is unavailable")
        resolution = _validated("resolve-response.schema.json", value)
        if resolution["source_digest"] != source_digest:
            raise DevelopersClientError("Developers resolution does not match the requested digest")
        return resolution

    def authorize_install(self, request: dict[str, object]) -> dict[str, Any]:
        try:
            _CONTRACTS.validate("install-authorization-request.schema.json", request)
        except ContractValidationError as exc:
            raise DevelopersClientError("install authorization request is invalid") from exc
        status, value = self._request(
            "POST",
            "/internal/v1/install-authorizations",
            request,
        )
        if status in {403, 404, 409}:
            raise InstallAuthorizationDeniedError("installation authorization was denied")
        if status != 200:
            raise DevelopersClientError("installation authorization is unavailable")
        return _validated("install-authorization-receipt.schema.json", value)

    def _request(
        self,
        method: str,
        path: str,
        body: dict[str, object] | None,
    ) -> tuple[int, object]:
        encoded = (
            b""
            if body is None
            else json.dumps(
                body,
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode()
        )
        headers = {
            "Authorization": f"Bearer {self._service_token}",
            "Accept": "application/json",
            "Content-Length": str(len(encoded)),
            **({"Content-Type": "application/json"} if body is not None else {}),
        }
        connection = http.client.HTTPConnection(_HOST, _PORT, timeout=_TIMEOUT_SECONDS)
        try:
            connection.request(method, path, body=encoded, headers=headers)
            response = connection.getresponse()
            raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except (OSError, http.client.HTTPException) as exc:
            raise DevelopersClientError("Developers is unavailable") from exc
        finally:
            connection.close()
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise DevelopersClientError("Developers response is too large")
        if response.status == 204:
            return response.status, None
        try:
            value = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise DevelopersClientError("Developers response is invalid") from exc
        return response.status, value


def _read_service_token(path: Path) -> str:
    try:
        value = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise RuntimeError("Controller-to-Developers service token is unavailable") from exc
    if not 32 <= len(value) <= 256 or not value.isascii() or any(character.isspace() for character in value):
        raise RuntimeError("Controller-to-Developers service token is invalid")
    return value


def _validated(schema: str, value: object) -> dict[str, Any]:
    try:
        _CONTRACTS.validate(schema, value)
    except ContractValidationError as exc:
        raise DevelopersClientError("Developers response violates its contract") from exc
    if not isinstance(value, dict):
        raise DevelopersClientError("Developers response violates its contract")
    return value
