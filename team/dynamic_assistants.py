"""Durable, fail-closed bindings for dynamically published hosted Assistants."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import assistant_manifest
import assistant_registry
import marketplace
from developers_controller_contract import ContractValidationError, ContractValidator

_FORMAT_VERSION = 1
_MAX_BINDINGS = 4096
_MAX_FILE_BYTES = 8 * 1024 * 1024
_TEAM_ID_RE = re.compile(r"^[a-z0-9_]{1,40}$")
_ASSISTANT_ID_RE = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
_CONTRACTS = ContractValidator()


class DynamicAssistantError(RuntimeError):
    """The dynamic Assistant registry is unavailable or violates its contract."""


class DynamicAssistantConflictError(DynamicAssistantError):
    """A Team already binds this Assistant id to a different artifact."""


@dataclass(frozen=True, slots=True)
class DynamicAssistantBinding:
    team_id: str
    binding_digest: str
    resolution: dict[str, Any]

    @property
    def assistant_id(self) -> str:
        return str(self.resolution["assistant_id"])


class DynamicAssistantStore:
    """One controller-private, atomic registry shared by hosted request threads."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock_path = path.with_suffix(f"{path.suffix}.lock")
        self._thread_lock = threading.RLock()

    def put(self, team_id: str, resolution: dict[str, Any]) -> DynamicAssistantBinding:
        binding = _binding(team_id, resolution)
        with self._exclusive_lock():
            bindings = self._read()
            existing = _find(bindings, team_id, binding.assistant_id)
            if existing is not None:
                if existing == binding:
                    return existing
                raise DynamicAssistantConflictError(
                    "the Team already binds this Assistant id to another artifact"
                )
            if len(bindings) >= _MAX_BINDINGS:
                raise DynamicAssistantError("the dynamic Assistant registry is full")
            bindings.append(binding)
            self._write(bindings)
        return binding

    def get(self, team_id: str, assistant_id: str) -> DynamicAssistantBinding | None:
        _validate_identity(team_id, assistant_id)
        with self._exclusive_lock():
            return _find(self._read(), team_id, assistant_id)

    def list(self, team_id: str) -> tuple[DynamicAssistantBinding, ...]:
        _validate_team_id(team_id)
        with self._exclusive_lock():
            bindings = tuple(binding for binding in self._read() if binding.team_id == team_id)
        return tuple(sorted(bindings, key=lambda binding: binding.assistant_id))

    def delete(self, team_id: str, assistant_id: str) -> bool:
        _validate_identity(team_id, assistant_id)
        with self._exclusive_lock():
            bindings = self._read()
            retained = [
                binding
                for binding in bindings
                if (binding.team_id, binding.assistant_id) != (team_id, assistant_id)
            ]
            if len(retained) == len(bindings):
                return False
            self._write(retained)
        return True

    def _exclusive_lock(self):
        return _FileLock(self._thread_lock, self._lock_path)

    def _read(self) -> list[DynamicAssistantBinding]:
        try:
            raw = self._path.read_bytes()
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise DynamicAssistantError("the dynamic Assistant registry cannot be read") from exc
        if len(raw) > _MAX_FILE_BYTES:
            raise DynamicAssistantError("the dynamic Assistant registry is too large")
        try:
            document = json.loads(raw)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise DynamicAssistantError("the dynamic Assistant registry is malformed") from exc
        if (
            not isinstance(document, dict)
            or set(document) != {"version", "bindings"}
            or document["version"] != _FORMAT_VERSION
            or not isinstance(document["bindings"], list)
            or len(document["bindings"]) > _MAX_BINDINGS
        ):
            raise DynamicAssistantError("the dynamic Assistant registry is malformed")
        bindings = [_decode_binding(value) for value in document["bindings"]]
        identities = [(binding.team_id, binding.assistant_id) for binding in bindings]
        if len(identities) != len(set(identities)):
            raise DynamicAssistantError("the dynamic Assistant registry contains duplicate bindings")
        return bindings

    def _write(self, bindings: list[DynamicAssistantBinding]) -> None:
        document = {
            "version": _FORMAT_VERSION,
            "bindings": [_encode_binding(binding) for binding in sorted(bindings, key=_binding_key)],
        }
        encoded = _canonical_bytes(document)
        if len(encoded) > _MAX_FILE_BYTES:
            raise DynamicAssistantError("the dynamic Assistant registry is too large")
        temporary: Path | None = None
        try:
            self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=self._path.parent,
                prefix=f".{self._path.name}.",
                delete=False,
            ) as stream:
                temporary = Path(stream.name)
                temporary.chmod(0o600)
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            temporary.replace(self._path)
            temporary = None
            directory_fd = os.open(self._path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError as exc:
            raise DynamicAssistantError("the dynamic Assistant registry cannot be written") from exc
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def app_spec(binding: DynamicAssistantBinding) -> marketplace.AppSpec:
    """Convert one validated binding into the existing hosted Assistant contract."""
    resolution = binding.resolution
    try:
        account_declarations = tuple(
            assistant_manifest.AccountDeclaration(
                id=account["id"],
                provider=account["provider"],
                scopes=tuple(account["scopes"]),
            )
            for account in resolution["accounts"]
        )
        canonical_contract = assistant_manifest.canonical_machine_contract(
            resolution["machine_contract"],
            account_declarations,
        )
        if canonical_contract != resolution["machine_contract"]:
            raise assistant_manifest.ManifestError("machine contract is not canonical")
        accounts = {
            account.id: assistant_registry.AccountSpec(
                provider=account.provider,
                scopes=account.scopes,
            )
            for account in account_declarations
        }
        reviewed_manifest = assistant_manifest.reviewed_manifest_contract(
            allowed_hosts=resolution["allowed_hosts"],
            accounts=accounts,
        )
        powers = {
            power["id"]: assistant_registry.PowerSpec(
                summary=assistant_registry.power_summary(power["id"]),
                input_schema=power["input_schema"],
                output_schema=power["output_schema"],
                accounts=tuple(power["accounts"]),
            )
            for power in canonical_contract["powers"]
        }
        platforms = tuple(platform.removeprefix("linux/") for platform in resolution["platforms"])
    except (KeyError, TypeError, assistant_manifest.ManifestError) as exc:
        raise DynamicAssistantError("the dynamic Assistant runtime contract is invalid") from exc
    return marketplace.AppSpec(
        image=resolution["image_reference"],
        port=1,
        db=False,
        allowed_hosts=reviewed_manifest.allowed_hosts,
        first_party=False,
        archs=platforms,
        required_image_labels=(
            ("org.shimpz.assistant.id", binding.assistant_id),
            ("org.shimpz.source.digest", resolution["source_digest"]),
        ),
        assistant=marketplace.AssistantContract(
            powers=powers,
            accounts=accounts,
            machine_contract=canonical_contract,
        ),
    )


class _FileLock:
    def __init__(self, thread_lock: threading.RLock, path: Path) -> None:
        self._thread_lock = thread_lock
        self._path = path
        self._stream = None

    def __enter__(self) -> None:
        self._thread_lock.acquire()
        try:
            self._path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            descriptor = os.open(
                self._path,
                os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            self._stream = os.fdopen(descriptor, "rb+")
            fcntl.flock(self._stream, fcntl.LOCK_EX)
        except Exception:
            self._thread_lock.release()
            raise

    def __exit__(self, *_args: object) -> None:
        stream = self._stream
        if stream is None:
            self._thread_lock.release()
            raise DynamicAssistantError("the dynamic Assistant registry lock is unavailable")
        try:
            fcntl.flock(stream, fcntl.LOCK_UN)
            stream.close()
        finally:
            self._thread_lock.release()


def _binding(team_id: str, resolution: dict[str, Any]) -> DynamicAssistantBinding:
    _validate_team_id(team_id)
    try:
        _CONTRACTS.validate("resolve-response.schema.json", resolution)
    except ContractValidationError as exc:
        raise DynamicAssistantError("the dynamic Assistant resolution is invalid") from exc
    digest_value = {
        "version": _FORMAT_VERSION,
        "team_id": team_id,
        "resolution": resolution,
    }
    digest = f"sha256:{hashlib.sha256(_canonical_bytes(digest_value)).hexdigest()}"
    return DynamicAssistantBinding(
        team_id=team_id,
        binding_digest=digest,
        resolution=resolution,
    )


def _decode_binding(value: object) -> DynamicAssistantBinding:
    if not isinstance(value, dict) or set(value) != {"team_id", "binding_digest", "resolution"}:
        raise DynamicAssistantError("the dynamic Assistant registry binding is malformed")
    resolution = value["resolution"]
    if not isinstance(resolution, dict):
        raise DynamicAssistantError("the dynamic Assistant registry binding is malformed")
    expected = _binding(value["team_id"], resolution)
    if value["binding_digest"] != expected.binding_digest:
        raise DynamicAssistantError("the dynamic Assistant registry binding digest is invalid")
    return expected


def _encode_binding(binding: DynamicAssistantBinding) -> dict[str, object]:
    return {
        "team_id": binding.team_id,
        "binding_digest": binding.binding_digest,
        "resolution": binding.resolution,
    }


def _binding_key(binding: DynamicAssistantBinding) -> tuple[str, str]:
    return binding.team_id, binding.assistant_id


def _find(
    bindings: list[DynamicAssistantBinding],
    team_id: str,
    assistant_id: str,
) -> DynamicAssistantBinding | None:
    return next(
        (
            binding
            for binding in bindings
            if binding.team_id == team_id and binding.assistant_id == assistant_id
        ),
        None,
    )


def _validate_team_id(team_id: object) -> None:
    if not isinstance(team_id, str) or _TEAM_ID_RE.fullmatch(team_id) is None:
        raise DynamicAssistantError("the Team id is invalid")


def _validate_identity(team_id: object, assistant_id: object) -> None:
    _validate_team_id(team_id)
    if (
        not isinstance(assistant_id, str)
        or len(assistant_id) > 40
        or _ASSISTANT_ID_RE.fullmatch(assistant_id) is None
    ):
        raise DynamicAssistantError("the Assistant id is invalid")


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
