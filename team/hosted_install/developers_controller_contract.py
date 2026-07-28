"""Closed Developers-to-Controller v1 contract validation."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

CONTRACT_ROOT = Path(__file__).resolve().parent.parent / "contracts" / "developers-controller" / "v1"
DEFINITIONS = "definitions.schema.json"
ENTRY_POINTS = {
    "controller-install-request.schema.json": "controllerInstallRequest",
    "controller-install-response.schema.json": "controllerInstallResponse",
    "delegation-claims.schema.json": "delegationClaims",
    "install-authorization-receipt.schema.json": "installAuthorizationReceipt",
    "install-authorization-request.schema.json": "installAuthorizationRequest",
    "resolve-response.schema.json": "resolveResponse",
    "team-list-response.schema.json": "teamListResponse",
}


class ContractValidationError(ValueError):
    """A Developers-to-Controller value is malformed or inconsistent."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class ContractValidator:
    """Load the pinned schemas once and validate closed wire values."""

    def __init__(self, root: Path = CONTRACT_ROOT) -> None:
        definitions = _load_json(root / DEFINITIONS)
        shared = definitions.get("$defs")
        if not isinstance(shared, dict):
            raise RuntimeError("Developers Controller definitions are invalid")
        self._validators = {
            filename: _build_validator(root, filename, definition, shared)
            for filename, definition in ENTRY_POINTS.items()
        }

    def validate(self, schema_name: str, value: object) -> None:
        validator = self._validators.get(schema_name)
        if validator is None:
            raise ContractValidationError("unknown_contract")
        try:
            validator.validate(value)
        except ValidationError:
            raise ContractValidationError("schema_violation") from None
        _validate_semantics(schema_name, value)


def _load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Developers Controller schema cannot be loaded") from exc
    if not isinstance(value, dict):
        raise RuntimeError("Developers Controller schema must be an object")
    return value


def _build_validator(
    root: Path,
    filename: str,
    definition: str,
    shared: dict[str, object],
) -> Draft202012Validator:
    entry = _load_json(root / filename)
    if entry.get("$ref") != f"{DEFINITIONS}#/$defs/{definition}":
        raise RuntimeError("Developers Controller schema entry point is invalid")
    local = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": shared,
        "$ref": f"#/$defs/{definition}",
    }
    try:
        Draft202012Validator.check_schema(local)
    except SchemaError as exc:
        raise RuntimeError("Developers Controller schema is invalid") from exc
    return Draft202012Validator(local)


def _validate_semantics(schema_name: str, value: object) -> None:
    if not isinstance(value, dict):
        return
    if schema_name == "delegation-claims.schema.json":
        _validate_lifetime(value, "iat", "exp", 60, "delegation_lifetime")
    elif schema_name == "install-authorization-receipt.schema.json":
        _validate_lifetime(value, "issued_at", "expires_at", 120, "authorization_lifetime")
    elif schema_name == "resolve-response.schema.json":
        _validate_resolve(value)


def _validate_lifetime(
    value: dict[str, object],
    issued_key: str,
    expires_key: str,
    maximum: int,
    code: str,
) -> None:
    issued = value.get(issued_key)
    expires = value.get(expires_key)
    if not isinstance(issued, int) or isinstance(issued, bool):
        return
    if not isinstance(expires, int) or isinstance(expires, bool):
        return
    if expires <= issued or expires - issued > maximum:
        raise ContractValidationError(code)


def _validate_resolve(value: dict[str, object]) -> None:
    expected = f"ghcr.io/theshimpz/shimpz-assistants@{value.get('oci_digest')}"
    if value.get("image_reference") != expected:
        raise ContractValidationError("resolve_digest_mismatch")
    intents = value.get("accounts")
    contract = value.get("machine_contract")
    if not isinstance(intents, list) or not isinstance(contract, dict):
        return
    intent_ids = _intent_ids(intents)
    required_ids = _required_account_ids(contract)
    if len(intent_ids) != len(intents) or len(set(intent_ids)) != len(intent_ids):
        raise ContractValidationError("resolve_account_mismatch")
    if set(intent_ids) != required_ids:
        raise ContractValidationError("resolve_account_mismatch")


def _intent_ids(intents: list[object]) -> list[str]:
    return [intent["id"] for intent in intents if isinstance(intent, dict) and isinstance(intent.get("id"), str)]


def _required_account_ids(contract: dict[str, object]) -> set[str]:
    powers = contract.get("powers")
    if not isinstance(powers, list):
        return set()
    return {
        account
        for power in powers
        if isinstance(power, dict) and isinstance(power.get("accounts"), list)
        for account in power["accounts"]
        if isinstance(account, str)
    }
