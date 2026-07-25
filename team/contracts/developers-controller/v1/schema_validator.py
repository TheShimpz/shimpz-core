"""Dependency-free JSON Schema subset used by the v1 golden vectors."""

from __future__ import annotations

import json
import re
from urllib.parse import urldefrag, urljoin

SUPPORTED_KEYWORDS = {
    "$defs",
    "$id",
    "$ref",
    "$schema",
    "additionalProperties",
    "allOf",
    "const",
    "enum",
    "items",
    "maxItems",
    "maxLength",
    "minItems",
    "minLength",
    "minimum",
    "not",
    "oneOf",
    "pattern",
    "prefixItems",
    "properties",
    "required",
    "title",
    "type",
    "uniqueItems",
}


class SchemaViolationError(ValueError):
    """A value does not satisfy the frozen contract schema."""


def check_schema(
    schema: object,
    documents: dict[str, dict[str, object]],
    current_id: str,
    path: str = "$",
) -> None:
    if isinstance(schema, bool):
        return
    if not isinstance(schema, dict):
        raise SchemaViolationError(f"{path}: schema node must be an object or boolean")
    unknown = set(schema).difference(SUPPORTED_KEYWORDS)
    if unknown:
        raise SchemaViolationError(f"{path}: unsupported schema keyword")
    reference = schema.get("$ref")
    if isinstance(reference, str):
        _resolve(reference, documents, current_id)
    for keyword in ("allOf", "oneOf", "prefixItems"):
        _check_schema_list(schema.get(keyword), documents, current_id, f"{path}.{keyword}")
    for keyword in ("$defs", "properties"):
        _check_schema_map(schema.get(keyword), documents, current_id, f"{path}.{keyword}")
    for keyword in ("additionalProperties", "items", "not"):
        child = schema.get(keyword)
        if child is not None:
            check_schema(child, documents, current_id, f"{path}.{keyword}")


def _check_schema_list(
    value: object,
    documents: dict[str, dict[str, object]],
    current_id: str,
    path: str,
) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        raise SchemaViolationError(f"{path}: expected an array")
    for index, child in enumerate(value):
        check_schema(child, documents, current_id, f"{path}[{index}]")


def _check_schema_map(
    value: object,
    documents: dict[str, dict[str, object]],
    current_id: str,
    path: str,
) -> None:
    if value is None:
        return
    if not isinstance(value, dict):
        raise SchemaViolationError(f"{path}: expected an object")
    for name, child in value.items():
        check_schema(child, documents, current_id, f"{path}.{name}")


def validate(
    schema: object,
    value: object,
    documents: dict[str, dict[str, object]],
    current_id: str,
    path: str = "$",
) -> None:
    if isinstance(schema, bool):
        if not schema:
            raise SchemaViolationError(f"{path}: false schema")
        return
    if not isinstance(schema, dict):
        raise SchemaViolationError(f"{path}: invalid schema node")
    reference = schema.get("$ref")
    if isinstance(reference, str):
        target, target_id = _resolve(reference, documents, current_id)
        validate(target, value, documents, target_id, path)
    _validate_combinators(schema, value, documents, current_id, path)
    _validate_literals(schema, value, path)
    expected_type = schema.get("type")
    if expected_type is not None and not _matches_type(expected_type, value):
        raise SchemaViolationError(f"{path}: expected {expected_type}")
    if isinstance(value, dict):
        _validate_object(schema, value, documents, current_id, path)
    elif isinstance(value, list):
        _validate_array(schema, value, documents, current_id, path)
    elif isinstance(value, str):
        _validate_string(schema, value, path)
    elif isinstance(value, int) and not isinstance(value, bool):
        _validate_integer(schema, value, path)


def _resolve(
    reference: str,
    documents: dict[str, dict[str, object]],
    current_id: str,
) -> tuple[object, str]:
    absolute = urljoin(current_id, reference)
    document_id, fragment = urldefrag(absolute)
    document = documents.get(document_id)
    if document is None:
        raise SchemaViolationError(f"unresolved schema document: {document_id}")
    target: object = document
    if fragment:
        if not fragment.startswith("/"):
            raise SchemaViolationError(f"unsupported schema fragment: {fragment}")
        for encoded in fragment[1:].split("/"):
            key = encoded.replace("~1", "/").replace("~0", "~")
            if not isinstance(target, dict) or key not in target:
                raise SchemaViolationError(f"unresolved schema fragment: {fragment}")
            target = target[key]
    return target, document_id


def _validate_combinators(
    schema: dict[str, object],
    value: object,
    documents: dict[str, dict[str, object]],
    current_id: str,
    path: str,
) -> None:
    all_of = schema.get("allOf", [])
    if isinstance(all_of, list):
        for candidate in all_of:
            validate(candidate, value, documents, current_id, path)
    one_of = schema.get("oneOf")
    if isinstance(one_of, list):
        matches = sum(_accepts(candidate, value, documents, current_id, path) for candidate in one_of)
        if matches != 1:
            raise SchemaViolationError(f"{path}: expected exactly one matching schema")
    rejected = schema.get("not")
    if rejected is not None and _accepts(rejected, value, documents, current_id, path):
        raise SchemaViolationError(f"{path}: matched rejected schema")


def _accepts(
    schema: object,
    value: object,
    documents: dict[str, dict[str, object]],
    current_id: str,
    path: str,
) -> bool:
    try:
        validate(schema, value, documents, current_id, path)
    except SchemaViolationError:
        return False
    return True


def _validate_literals(schema: dict[str, object], value: object, path: str) -> None:
    if "const" in schema and not _json_equal(schema["const"], value):
        raise SchemaViolationError(f"{path}: unexpected constant")
    enum = schema.get("enum")
    if isinstance(enum, list) and not any(_json_equal(item, value) for item in enum):
        raise SchemaViolationError(f"{path}: value is outside the enum")


def _matches_type(expected: object, value: object) -> bool:
    checks = {
        "array": lambda: isinstance(value, list),
        "integer": lambda: isinstance(value, int) and not isinstance(value, bool),
        "object": lambda: isinstance(value, dict),
        "string": lambda: isinstance(value, str),
    }
    check = checks.get(expected)
    return check is not None and check()


def _validate_object(
    schema: dict[str, object],
    value: object,
    documents: dict[str, dict[str, object]],
    current_id: str,
    path: str,
) -> None:
    if not isinstance(value, dict):
        return
    required = schema.get("required", [])
    if isinstance(required, list) and any(key not in value for key in required):
        raise SchemaViolationError(f"{path}: missing required property")
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        raise SchemaViolationError(f"{path}: invalid properties schema")
    additional = schema.get("additionalProperties", True)
    for key, item in value.items():
        child = properties.get(key)
        if child is not None:
            validate(child, item, documents, current_id, f"{path}.{key}")
        elif additional is False:
            raise SchemaViolationError(f"{path}: unknown property {key}")
        elif isinstance(additional, dict):
            validate(additional, item, documents, current_id, f"{path}.{key}")


def _validate_array(
    schema: dict[str, object],
    value: object,
    documents: dict[str, dict[str, object]],
    current_id: str,
    path: str,
) -> None:
    if not isinstance(value, list):
        return
    minimum = schema.get("minItems")
    maximum = schema.get("maxItems")
    if isinstance(minimum, int) and len(value) < minimum:
        raise SchemaViolationError(f"{path}: too few items")
    if isinstance(maximum, int) and len(value) > maximum:
        raise SchemaViolationError(f"{path}: too many items")
    if schema.get("uniqueItems") is True and len({_canonical(item) for item in value}) != len(value):
        raise SchemaViolationError(f"{path}: duplicate items")
    prefix = schema.get("prefixItems", [])
    items = schema.get("items", {})
    for index, item in enumerate(value):
        item_schema = prefix[index] if isinstance(prefix, list) and index < len(prefix) else items
        validate(item_schema, item, documents, current_id, f"{path}[{index}]")


def _validate_string(schema: dict[str, object], value: object, path: str) -> None:
    if not isinstance(value, str):
        return
    minimum = schema.get("minLength")
    maximum = schema.get("maxLength")
    if isinstance(minimum, int) and len(value) < minimum:
        raise SchemaViolationError(f"{path}: string is too short")
    if isinstance(maximum, int) and len(value) > maximum:
        raise SchemaViolationError(f"{path}: string is too long")
    pattern = schema.get("pattern")
    if isinstance(pattern, str) and re.search(pattern, value) is None:
        raise SchemaViolationError(f"{path}: string does not match pattern")


def _validate_integer(schema: dict[str, object], value: object, path: str) -> None:
    minimum = schema.get("minimum")
    if isinstance(value, int) and not isinstance(value, bool) and isinstance(minimum, int) and value < minimum:
        raise SchemaViolationError(f"{path}: integer is too small")


def _json_equal(left: object, right: object) -> bool:
    return _canonical(left) == _canonical(right)


def _canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
