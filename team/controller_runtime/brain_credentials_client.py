"""Deliver one account model API key to the LangGraph runtime in memory.

The Team controller receives neither the encryption key nor the seal token. It first obtains only
an opaque envelope from accounts, then presents that envelope plus a one-use X25519 public key to the
separately authorized delivery API. The endpoint returns only AES-GCM ciphertext. Plaintext exists
transiently in this process so it can be sent to the private Brain runtime for one turn; it is never
written to a Team volume, HTTP response, Docker metadata, argv, labels, or logs.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import stat
import threading
from contextlib import suppress
from pathlib import Path
from urllib.parse import urlparse

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from controller_runtime.inference_config import PROVIDERS as MODEL_PROVIDERS

ACCOUNTS_URL = os.environ.get("SHIMPZ_ACCOUNTS_URL", "http://accounts:7079")
RESOLVE_TOKEN_FILE = Path(
    os.environ.get(
        "SHIMPZ_ACCOUNTS_BRAIN_RESOLVE_TOKEN_FILE",
        "/run/shimpz-accounts-brain-resolve/token",
    )
)
BRAINCRED_URL = os.environ.get("SHIMPZ_BRAINCRED_URL", "http://brain-credential-driver:7080")
UNSEAL_TOKEN_FILE = Path(
    os.environ.get(
        "SHIMPZ_BRAINCRED_UNSEAL_TOKEN_FILE",
        "/run/shimpz-braincred-unseal/token",
    )
)
MAX_RESPONSE_BYTES = 96 * 1024
DELIVERY_VERSION = 1
DELIVERY_ALGORITHM = "X25519-HKDF-SHA256+A256GCM"
DELIVERY_SALT_BYTES = 16
DELIVERY_NONCE_BYTES = 12
DELIVERY_KEY_BYTES = 32
MAX_SECRET_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 16 * 1024
SUPPORTED_PROVIDERS = frozenset(MODEL_PROVIDERS)
SUPPORTED_AUTH_TYPE = "api_key"
_token_cache: dict[Path, tuple[tuple[int, int, int, int, int], str]] = {}
_token_cache_lock = threading.Lock()


class BrainCredentialError(Exception):
    """Credential control plane failed without exposing secret-bearing response material."""


def _require_provider(provider: str) -> None:
    if provider not in SUPPORTED_PROVIDERS:
        raise BrainCredentialError("Brain credential provider is unsupported")


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode()


def _b64decode(value: object) -> bytes:
    if not isinstance(value, str):
        raise BrainCredentialError("Brain credential delivery returned invalid ciphertext")
    try:
        return base64.b64decode(value, altchars=b"-_", validate=True)
    except ValueError as exc:
        raise BrainCredentialError("Brain credential delivery returned invalid ciphertext") from exc


def _delivery_aad(
    account_id: str,
    provider: str,
    auth_type: str,
    recipient_public_key: bytes,
    sender_public_key: bytes,
) -> bytes:
    return json.dumps(
        {
            "account_id": account_id,
            "alg": DELIVERY_ALGORITHM,
            "auth_type": auth_type,
            "provider": provider,
            "purpose": "shimpz-brain-credential-delivery",
            "recipient_public_key": _b64encode(recipient_public_key),
            "sender_public_key": _b64encode(sender_public_key),
            "v": DELIVERY_VERSION,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _open_delivery(
    private_key: x25519.X25519PrivateKey,
    account_id: str,
    provider: str,
    auth_type: str,
    delivery: object,
) -> str:
    if not isinstance(delivery, dict):
        raise BrainCredentialError("Brain credential delivery returned invalid ciphertext")
    if delivery.get("v") != DELIVERY_VERSION or delivery.get("alg") != DELIVERY_ALGORITHM:
        raise BrainCredentialError("Brain credential delivery returned invalid ciphertext")
    sender_public_key = _b64decode(delivery.get("sender_public_key"))
    salt = _b64decode(delivery.get("salt"))
    nonce = _b64decode(delivery.get("nonce"))
    ciphertext = _b64decode(delivery.get("ciphertext"))
    if (
        len(sender_public_key) != 32
        or len(salt) != DELIVERY_SALT_BYTES
        or len(nonce) != DELIVERY_NONCE_BYTES
        or not 16 < len(ciphertext) <= MAX_SECRET_BYTES + 16
    ):
        raise BrainCredentialError("Brain credential delivery returned invalid ciphertext")
    recipient_public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    aad = _delivery_aad(
        account_id,
        provider,
        auth_type,
        recipient_public_key,
        sender_public_key,
    )
    try:
        shared_key = private_key.exchange(x25519.X25519PublicKey.from_public_bytes(sender_public_key))
        delivery_key = HKDF(
            algorithm=hashes.SHA256(),
            length=DELIVERY_KEY_BYTES,
            salt=salt,
            info=aad,
        ).derive(shared_key)
        plaintext = AESGCM(delivery_key).decrypt(nonce, ciphertext, aad)
        secret = plaintext.decode()
    except (InvalidTag, UnicodeDecodeError, ValueError) as exc:
        raise BrainCredentialError("Brain credential delivery authentication failed") from exc
    if not secret or "\0" in secret:
        raise BrainCredentialError("Brain credential delivery returned invalid plaintext")
    return secret


def _file_identity(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _token(path: Path) -> str:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0))
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 1 <= before.st_size <= MAX_TOKEN_BYTES:
            raise BrainCredentialError("Brain credential service is unavailable")
        identity = _file_identity(before)
        with _token_cache_lock:
            cached = _token_cache.get(path)
            if cached is not None and cached[0] == identity:
                return cached[1]
        raw = bytearray()
        while len(raw) < before.st_size:
            chunk = os.read(descriptor, min(4096, before.st_size - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise BrainCredentialError("Brain credential service is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) != before.st_size or identity != _file_identity(after):
        raise BrainCredentialError("Brain credential service is unavailable")
    try:
        token = bytes(raw).decode("utf-8").strip()
    except UnicodeError as exc:
        raise BrainCredentialError("Brain credential service is unavailable") from exc
    if not token or any(character in token for character in "\0\r\n"):
        raise BrainCredentialError("Brain credential service is unavailable")
    with _token_cache_lock:
        _token_cache[path] = (identity, token)
    return token


class BrainCredentialSession:
    """Keep credential-service transports alive for one hosted chat turn."""

    def __init__(self) -> None:
        self._connections: dict[tuple[object, str, int], http.client.HTTPConnection] = {}

    def connection(
        self,
        connection_cls,
        host: str,
        port: int,
    ) -> tuple[tuple[object, str, int], object, bool]:
        key = (connection_cls, host, port)
        connection = self._connections.get(key)
        reused = connection is not None
        if connection is None:
            connection = connection_cls(host, port, timeout=10)
            self._connections[key] = connection
        return key, connection, reused

    def discard(self, key: tuple[object, str, int]) -> None:
        connection = self._connections.pop(key, None)
        if connection is not None:
            with suppress(OSError):
                connection.close()

    def close(self) -> None:
        connections = tuple(self._connections.values())
        self._connections.clear()
        for connection in connections:
            with suppress(OSError):
                connection.close()

    def __enter__(self) -> BrainCredentialSession:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _post(
    base_url: str,
    path: str,
    payload: dict,
    token_file: Path,
    session: BrainCredentialSession | None = None,
) -> tuple[int, dict]:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise BrainCredentialError("Brain credential service is unavailable")
    connection_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    current_session = session or BrainCredentialSession()
    owned_session = session is None
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    request_path = f"{parsed.path.rstrip('/')}{path}"
    body = json.dumps(payload, separators=(",", ":")).encode()
    try:
        for attempt in range(2):
            key, connection, reused = current_session.connection(connection_cls, host, port)
            try:
                connection.request(
                    "POST",
                    request_path,
                    body,
                    {
                        "Authorization": f"Bearer {_token(token_file)}",
                        "Content-Type": "application/json",
                    },
                )
                response = connection.getresponse()
                raw = response.read(MAX_RESPONSE_BYTES + 1)
            except (OSError, http.client.HTTPException) as exc:
                current_session.discard(key)
                # Resolve, generation-check, and encrypted delivery are idempotent reads. Retry
                # only a previously healthy transport that the bounded server closed while idle.
                if attempt == 0 and reused:
                    continue
                raise BrainCredentialError("Brain credential service is unavailable") from exc
            if len(raw) > MAX_RESPONSE_BYTES or getattr(response, "will_close", False):
                current_session.discard(key)
            break
    finally:
        if owned_session:
            current_session.close()
    if len(raw) > MAX_RESPONSE_BYTES:
        raise BrainCredentialError("Brain credential service returned an invalid response")
    try:
        result = json.loads(raw or b"{}")
    except json.JSONDecodeError as exc:
        raise BrainCredentialError("Brain credential service returned an invalid response") from exc
    if not isinstance(result, dict):
        raise BrainCredentialError("Brain credential service returned an invalid response")
    return response.status, result


def resolve(
    account_id: str,
    provider: str,
    session: BrainCredentialSession | None = None,
) -> tuple[str, str, int] | None:
    """Return ``('api_key', plaintext, generation)`` via one encrypted delivery."""
    _require_provider(provider)
    status, resolved = _post(
        ACCOUNTS_URL,
        "/v1/internal/brains/resolve",
        {"account_id": account_id, "provider": provider},
        RESOLVE_TOKEN_FILE,
        session,
    )
    if status == 404:
        return None
    if status != 200:
        raise BrainCredentialError("Brain credential lookup failed")
    auth_type = resolved.get("auth_type")
    envelope = resolved.get("secret_ref")
    generation = resolved.get("generation")
    if (
        auth_type != SUPPORTED_AUTH_TYPE
        or not isinstance(envelope, dict)
        or not isinstance(generation, int)
        or isinstance(generation, bool)
        or generation < 1
    ):
        raise BrainCredentialError("Brain credential lookup returned invalid metadata")
    private_key = x25519.X25519PrivateKey.generate()
    recipient_public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    status, delivered = _post(
        BRAINCRED_URL,
        "/v1/deliver",
        {
            "account_id": account_id,
            "provider": provider,
            "auth_type": auth_type,
            "envelope": envelope,
            "recipient_public_key": _b64encode(recipient_public_key),
        },
        UNSEAL_TOKEN_FILE,
        session,
    )
    if status != 200 or "secret" in delivered:
        raise BrainCredentialError("Brain credential delivery failed")
    secret = _open_delivery(private_key, account_id, provider, auth_type, delivered.get("delivery"))
    return auth_type, secret, generation


def generation_is_current(
    account_id: str,
    provider: str,
    generation: int,
    session: BrainCredentialSession | None = None,
) -> bool:
    """Check the in-memory key lease; False means revoke/replace won the race."""
    _require_provider(provider)
    if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
        raise BrainCredentialError("Brain credential generation is invalid")
    status, result = _post(
        ACCOUNTS_URL,
        "/v1/internal/brains/generation-check",
        {
            "account_id": account_id,
            "provider": provider,
            "generation": generation,
        },
        RESOLVE_TOKEN_FILE,
        session,
    )
    valid = result.get("valid")
    if status == 200 and valid is True:
        return True
    if status == 409 and valid is False:
        return False
    raise BrainCredentialError("Brain credential generation check failed")
