"""Private registry credentials kept out of process arguments and logs."""

from __future__ import annotations

import base64
import json
import os
import re
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

_USERNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_MAX_TOKEN_BYTES = 1024


class RegistryAuthError(RuntimeError):
    """Private registry authentication is unavailable or malformed."""


class RegistryAuth:
    __slots__ = ("_token", "_username")

    def __init__(self, username: str, token: str) -> None:
        if _USERNAME_RE.fullmatch(username) is None:
            raise RegistryAuthError("registry username is invalid")
        if (
            not 20 <= len(token) <= _MAX_TOKEN_BYTES
            or not token.isascii()
            or not token.isprintable()
            or any(character.isspace() for character in token)
        ):
            raise RegistryAuthError("registry token is invalid")
        self._username = username
        self._token = token

    @classmethod
    def from_files(cls, username_path: Path, token_path: Path) -> RegistryAuth:
        return cls(
            _read_secret(username_path, "username"),
            _read_secret(token_path, "token"),
        )

    def __repr__(self) -> str:
        return "RegistryAuth(<redacted>)"

    def docker_auth_config(self) -> dict[str, str]:
        return {"username": self._username, "password": self._token}

    @contextmanager
    def docker_config(self) -> Iterator[str]:
        with tempfile.TemporaryDirectory(prefix="shimpz-registry-") as directory:
            encoded = base64.b64encode(
                f"{self._username}:{self._token}".encode("ascii")
            ).decode("ascii")
            document = json.dumps(
                {"auths": {"ghcr.io": {"auth": encoded}}},
                separators=(",", ":"),
            ).encode("ascii")
            path = Path(directory, "config.json")
            descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(document)
            yield directory


def _read_secret(path: Path, label: str) -> str:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise RegistryAuthError(f"registry {label} is unavailable") from exc
    if not raw or len(raw) > _MAX_TOKEN_BYTES:
        raise RegistryAuthError(f"registry {label} is invalid")
    try:
        value = raw.decode("ascii")
    except UnicodeError as exc:
        raise RegistryAuthError(f"registry {label} is invalid") from exc
    value = value.removesuffix("\n")
    if not value or "\n" in value or "\r" in value:
        raise RegistryAuthError(f"registry {label} is invalid")
    return value
