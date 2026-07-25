#!/usr/bin/env python3
"""Validate and copy the frozen Developers-to-Controller v1 authority."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import shutil
from pathlib import Path

from schema_validator import SchemaViolationError, check_schema, validate

HERE = Path(__file__).resolve().parent
MANIFEST = "contract-files.sha256"
SCHEMAS = (
    "controller-install-request.schema.json",
    "controller-install-response.schema.json",
    "definitions.schema.json",
    "delegation-claims.schema.json",
    "install-authorization-receipt.schema.json",
    "install-authorization-request.schema.json",
    "resolve-response.schema.json",
    "team-list-response.schema.json",
)
AUTHORITY_FILES = (*SCHEMAS, "README.md", "schema_validator.py", "vectors.json", "verify.py")
SCHEMA_ORIGIN = "https://schemas.shimpz.com/developers-controller/v1/"


class ContractViolationError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def fail(message: str) -> None:
    raise SystemExit(message)


def load_object(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"{path.name} is not valid JSON: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.name} must contain a JSON object")
    return value


def schema_documents() -> dict[str, dict[str, object]]:
    documents = {}
    for name in SCHEMAS:
        document = load_object(HERE / name)
        identifier = document.get("$id")
        expected = f"{SCHEMA_ORIGIN}{name}"
        if document.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            fail(f"{name} must use JSON Schema draft 2020-12")
        if identifier != expected:
            fail(f"{name} has unexpected $id")
        documents[expected] = document
    for identifier, document in documents.items():
        try:
            check_schema(document, documents, identifier)
        except SchemaViolationError as exc:
            fail(f"{identifier.removeprefix(SCHEMA_ORIGIN)} is invalid: {exc}")
    return documents


def apply_mutation(value: object, mutation: object, label: str) -> object:
    result = copy.deepcopy(value)
    if mutation is None:
        return result
    if not isinstance(mutation, dict) or set(mutation) not in ({"op", "path"}, {"op", "path", "value"}):
        fail(f"{label}.mutation has an invalid shape")
    operation = mutation.get("op")
    path = mutation.get("path")
    if operation not in {"set", "remove"} or not isinstance(path, list) or not path:
        fail(f"{label}.mutation has an invalid operation or path")
    parent = mutation_parent(result, path, label)
    key = path[-1]
    if not isinstance(parent, dict) or not isinstance(key, str):
        fail(f"{label}.mutation may address only object properties")
    if operation == "remove":
        if set(mutation) != {"op", "path"} or key not in parent:
            fail(f"{label}.mutation cannot remove its target")
        del parent[key]
    else:
        if set(mutation) != {"op", "path", "value"}:
            fail(f"{label}.mutation set requires value")
        parent[key] = copy.deepcopy(mutation["value"])
    return result


def mutation_parent(value: object, path: list[object], label: str) -> object:
    current = value
    for key in path[:-1]:
        if not isinstance(current, dict) or not isinstance(key, str) or key not in current:
            fail(f"{label}.mutation path does not exist")
        current = current[key]
    return current


def semantic_validation(schema: str, value: object) -> None:
    if not isinstance(value, dict):
        return
    if schema == "delegation-claims.schema.json":
        validate_lifetime(value, "iat", "exp", 60, "delegation_lifetime")
    elif schema == "install-authorization-receipt.schema.json":
        validate_lifetime(value, "issued_at", "expires_at", 120, "authorization_lifetime")
    elif schema == "resolve-response.schema.json":
        validate_resolve(value)


def validate_resolve(value: dict[str, object]) -> None:
    expected = f"ghcr.io/theshimpz/shimpz-assistants@{value.get('oci_digest')}"
    if value.get("image_reference") != expected:
        raise ContractViolationError("resolve_digest_mismatch")
    intents = value.get("accounts")
    contract = value.get("machine_contract")
    if not isinstance(intents, list) or not isinstance(contract, dict):
        return
    intent_ids = [
        intent.get("id") for intent in intents if isinstance(intent, dict) and isinstance(intent.get("id"), str)
    ]
    powers = contract.get("powers")
    if not isinstance(powers, list):
        return
    required_ids = {
        account
        for power in powers
        if isinstance(power, dict) and isinstance(power.get("accounts"), list)
        for account in power["accounts"]
        if isinstance(account, str)
    }
    if len(intent_ids) != len(intents) or len(set(intent_ids)) != len(intent_ids):
        raise ContractViolationError("resolve_account_mismatch")
    if set(intent_ids) != required_ids:
        raise ContractViolationError("resolve_account_mismatch")


def validate_lifetime(
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
        raise ContractViolationError(code)


def validate_case(
    case: dict[str, object],
    fixtures: dict[str, dict[str, object]],
    documents: dict[str, dict[str, object]],
) -> str | None:
    fixture_name = case.get("fixture")
    fixture = fixtures.get(fixture_name) if isinstance(fixture_name, str) else None
    if fixture is None:
        fail(f"{case.get('name')} references an unknown fixture")
    schema_name = fixture.get("schema")
    if not isinstance(schema_name, str) or schema_name not in SCHEMAS or schema_name == "definitions.schema.json":
        fail(f"{case.get('name')} fixture has an invalid schema")
    value = apply_mutation(fixture.get("value"), case.get("mutation"), str(case.get("name")))
    try:
        validate(
            documents[f"{SCHEMA_ORIGIN}{schema_name}"],
            value,
            documents,
            f"{SCHEMA_ORIGIN}{schema_name}",
        )
        semantic_validation(schema_name, value)
    except SchemaViolationError:
        return "schema_violation"
    except ContractViolationError as exc:
        return exc.code
    return None


def verify_vectors(documents: dict[str, dict[str, object]]) -> None:
    vectors = load_object(HERE / "vectors.json")
    if set(vectors) != {"version", "fixtures", "cases"} or vectors.get("version") != 1:
        fail("vectors.json has an invalid root")
    raw_fixtures = vectors.get("fixtures")
    raw_cases = vectors.get("cases")
    if not isinstance(raw_fixtures, dict) or not isinstance(raw_cases, list):
        fail("vectors.json fixtures/cases have invalid types")
    fixtures = {
        name: value for name, value in raw_fixtures.items() if isinstance(name, str) and isinstance(value, dict)
    }
    if len(fixtures) != len(raw_fixtures):
        fail("vectors.json has an invalid fixture")
    verify_cases(raw_cases, fixtures, documents)


def verify_cases(
    cases: list[object],
    fixtures: dict[str, dict[str, object]],
    documents: dict[str, dict[str, object]],
) -> None:
    names: set[str] = set()
    for index, raw_case in enumerate(cases):
        if not isinstance(raw_case, dict):
            fail(f"vectors.cases[{index}] must be an object")
        expected_keys = {"name", "fixture", "valid"} | ({"error"} if raw_case.get("valid") is False else set())
        if "mutation" in raw_case:
            expected_keys.add("mutation")
        name = raw_case.get("name")
        if set(raw_case) != expected_keys or not isinstance(name, str) or not name or name in names:
            fail(f"vectors.cases[{index}] has an invalid shape or duplicate name")
        names.add(name)
        actual = validate_case(raw_case, fixtures, documents)
        expected = None if raw_case.get("valid") is True else raw_case.get("error")
        if not isinstance(raw_case.get("valid"), bool) or actual != expected:
            fail(f"{name} returned {actual!r}, expected {expected!r}")


def manifest_rows() -> list[tuple[str, str]]:
    try:
        lines = (HERE / MANIFEST).read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as exc:
        fail(f"{MANIFEST} cannot be read: {exc}")
    rows = []
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)", line)
        if match is None:
            fail(f"{MANIFEST} contains an invalid row")
        rows.append((match[2], match[1]))
    if [name for name, _ in rows] != sorted(AUTHORITY_FILES):
        fail(f"{MANIFEST} must list every authority file in sorted order")
    return rows


def verify_authority() -> None:
    for name, expected in manifest_rows():
        path = HERE / name
        if path.is_symlink() or not path.is_file():
            fail(f"{name} is missing, special, or symlinked")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            fail(f"{name} SHA-256 is {actual}, expected {expected}")


def sync_authority(target: Path) -> None:
    if target.resolve() == HERE or target.is_symlink():
        fail("sync target must be a different non-symlink directory")
    target.mkdir(parents=True, exist_ok=True)
    allowed = {*AUTHORITY_FILES, MANIFEST}
    for child in target.iterdir():
        if child.name not in allowed or child.is_symlink() or not child.is_file():
            fail(f"sync target contains unknown or special entry: {child.name}")
    for name in sorted(allowed):
        destination = target / name
        if destination.is_symlink():
            fail(f"sync destination may not be a symlink: {name}")
        shutil.copyfile(HERE / name, destination)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sync", type=Path, metavar="DIRECTORY")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    verify_authority()
    documents = schema_documents()
    verify_vectors(documents)
    if args.sync is not None:
        sync_authority(args.sync)
        print(f"Developers-to-Controller v1 authority synchronized to {args.sync}")
        return
    print("Developers-to-Controller v1 authority and golden vectors are valid")


if __name__ == "__main__":
    main()
