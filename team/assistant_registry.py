"""Shared reviewed Assistant registry primitives for both Controllers."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

import assistant_manifest

ALL_ZERO_SHA256 = "0" * 64
REVIEWED_ASSISTANTS = assistant_manifest.load_reviewed_catalog()


@dataclass(frozen=True, slots=True)
class PowerSpec:
    summary: str
    input_schema: Mapping[str, object]
    output_schema: Mapping[str, object]
    accounts: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AccountSpec:
    provider: str
    scopes: tuple[str, ...]


def power_summary(power_id: str) -> str:
    return power_id.replace("-", " ").capitalize()


def validate_power_input(assistant_id: str, power: str, payload: object) -> dict[str, object]:
    try:
        validator = REVIEWED_ASSISTANTS[assistant_id].power_validators[power]["input"]
    except KeyError as exc:
        raise ValueError("the Power has no declared input contract") from exc
    return assistant_manifest.validate_schema_payload(validator, payload)


def validate_power_output(assistant_id: str, power: str, payload: object) -> dict[str, object]:
    try:
        validator = REVIEWED_ASSISTANTS[assistant_id].power_validators[power]["output"]
    except KeyError as exc:
        raise ValueError("the Power has no declared output contract") from exc
    return assistant_manifest.validate_schema_payload(validator, payload)


def digest_is_bound(ref: object) -> bool:
    return isinstance(ref, str) and not ref.endswith(f"sha256:{ALL_ZERO_SHA256}")
