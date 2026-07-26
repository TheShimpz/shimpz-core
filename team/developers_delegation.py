"""Verify short-lived Developers service delegations at the hosted Controller boundary."""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import threading
import time
from email.message import Message
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from developers_controller_contract import ContractValidationError, ContractValidator

_MAX_TOKEN_BYTES = 8192
_CLOCK_SKEW_SECONDS = 5
_HEADER = {"alg": "EdDSA", "kid": "developers-v1", "typ": "JWT"}
_CONTRACTS = ContractValidator()


class DevelopersDelegationError(RuntimeError):
    """Developers service authentication or delegated authority is invalid."""


class ReplayGuard:
    """Process-local one-use guard; short token lifetime bounds restart exposure."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seen: dict[str, int] = {}

    def consume(self, jti: str, expires_at: int, *, now: int) -> None:
        with self._lock:
            self._seen = {
                stored_jti: stored_expiry for stored_jti, stored_expiry in self._seen.items() if stored_expiry >= now
            }
            if jti in self._seen:
                raise DevelopersDelegationError("delegation replayed")
            self._seen[jti] = expires_at


class DevelopersDelegationVerifier:
    def __init__(
        self,
        service_token_file: Path,
        public_key_file: Path,
        *,
        replay_guard: ReplayGuard | None = None,
    ) -> None:
        self._service_token = _read_service_token(service_token_file)
        self._public_key = _read_public_key(public_key_file)
        self._replay_guard = replay_guard or ReplayGuard()

    def verify(
        self,
        headers: Message,
        *,
        action: str,
        request: dict[str, object] | None = None,
        now: int | None = None,
    ) -> dict[str, Any]:
        _verify_service_bearer(headers, self._service_token)
        encoded = _one_bearer(headers, "X-Shimpz-Delegation")
        claims = _verify_jwt(encoded, self._public_key)
        try:
            _CONTRACTS.validate("delegation-claims.schema.json", claims)
        except ContractValidationError as exc:
            raise DevelopersDelegationError("delegation contract is invalid") from exc
        current = int(time.time()) if now is None else now
        _verify_time(claims, current)
        if claims["action"] != action:
            raise DevelopersDelegationError("delegation action does not match")
        _verify_request_binding(claims, request)
        self._replay_guard.consume(claims["jti"], claims["exp"], now=current)
        return claims


def _read_service_token(path: Path) -> str:
    try:
        value = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise RuntimeError("Developers Controller service token is unavailable") from exc
    if not 32 <= len(value) <= 256 or not value.isascii() or any(character.isspace() for character in value):
        raise RuntimeError("Developers Controller service token is invalid")
    return value


def _read_public_key(path: Path) -> Ed25519PublicKey:
    try:
        value = load_pem_public_key(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise RuntimeError("Developers delegation public key is unavailable") from exc
    if not isinstance(value, Ed25519PublicKey):
        raise RuntimeError("Developers delegation public key must use Ed25519")
    return value


def _verify_service_bearer(headers: Message, expected: str) -> None:
    supplied = _one_bearer(headers, "Authorization")
    if not hmac.compare_digest(supplied, expected):
        raise DevelopersDelegationError("Developers service identity is invalid")


def _one_bearer(headers: Message, name: str) -> str:
    values = headers.get_all(name, failobj=[])
    if len(values) != 1 or not values[0].startswith("Bearer "):
        raise DevelopersDelegationError(f"{name} bearer is required")
    value = values[0].removeprefix("Bearer ")
    if (
        not value
        or len(value.encode("ascii", "ignore")) != len(value)
        or len(value) > _MAX_TOKEN_BYTES
        or any(character.isspace() for character in value)
    ):
        raise DevelopersDelegationError(f"{name} bearer is invalid")
    return value


def _verify_jwt(encoded: str, public_key: Ed25519PublicKey) -> dict[str, Any]:
    parts = encoded.split(".")
    if len(parts) != 3 or any(not part for part in parts):
        raise DevelopersDelegationError("delegation token is malformed")
    header = _json_segment(parts[0])
    claims = _json_segment(parts[1])
    if header != _HEADER or not isinstance(claims, dict):
        raise DevelopersDelegationError("delegation token is malformed")
    signature = _decode_segment(parts[2])
    try:
        public_key.verify(signature, f"{parts[0]}.{parts[1]}".encode("ascii"))
    except InvalidSignature as exc:
        raise DevelopersDelegationError("delegation signature is invalid") from exc
    return claims


def _json_segment(encoded: str) -> object:
    raw = _decode_segment(encoded)
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise DevelopersDelegationError("delegation token is malformed") from exc
    if _encode_segment(json.dumps(value, separators=(",", ":"), sort_keys=True).encode()) != encoded:
        raise DevelopersDelegationError("delegation token is not canonical")
    return value


def _decode_segment(encoded: str) -> bytes:
    if not encoded.isascii() or "=" in encoded:
        raise DevelopersDelegationError("delegation token is malformed")
    try:
        raw = base64.b64decode(
            encoded + "=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise DevelopersDelegationError("delegation token is malformed") from exc
    if _encode_segment(raw) != encoded:
        raise DevelopersDelegationError("delegation token is not canonical")
    return raw


def _encode_segment(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _verify_time(claims: dict[str, Any], now: int) -> None:
    issued_at = claims["iat"]
    expires_at = claims["exp"]
    if issued_at > now + _CLOCK_SKEW_SECONDS or expires_at < now:
        raise DevelopersDelegationError("delegation token is outside its valid time")


def _verify_request_binding(
    claims: dict[str, Any],
    request: dict[str, object] | None,
) -> None:
    if claims["action"] == "teams:list":
        if request is not None:
            raise DevelopersDelegationError("team list delegation cannot bind a request body")
        return
    if request is None:
        raise DevelopersDelegationError("install delegation requires a request body")
    bindings = {
        "team_id": "team_id",
        "source_digest": "source_digest",
        "request_id": "request_id",
        "idempotency_key": "idempotency_key",
    }
    if any(claims[claim_key] != request.get(body_key) for claim_key, body_key in bindings.items()):
        raise DevelopersDelegationError("delegation does not match the install request")
