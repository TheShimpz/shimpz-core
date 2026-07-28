"""Immutable first-party Assistant registry for the single-owner local controller.

Only the image reference is release data.  The executable contract stays in reviewed
source so a registry document cannot turn the Docker socket into an arbitrary runner.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from assistant_human import assistant_registry
from assistant_human.assistant_registry import AccountSpec, PowerSpec, validate_power_input, validate_power_output

__all__ = ("AccountSpec", "PowerSpec", "validate_power_input", "validate_power_output")

REGISTRY_PATH = Path("/etc/shimpz/local-assistants.json")
_DIGEST_REF = re.compile(
    r"(?:[a-z0-9.-]+(?::[0-9]{1,5})?/)?"
    r"[a-z0-9]+(?:[._/-][a-z0-9]+)*@sha256:[0-9a-f]{64}"
)
_REVIEWED_ASSISTANTS = assistant_registry.REVIEWED_ASSISTANTS


class RegistryError(RuntimeError):
    """The baked registry is missing or is not safe to execute."""


@dataclass(frozen=True, slots=True)
class AssistantSpec:
    assistant_id: str
    name: str
    summary: str
    image: str
    powers: dict[str, PowerSpec]
    allowed_hosts: tuple[str, ...]
    accounts: dict[str, AccountSpec] = field(default_factory=dict)
    machine_contract: dict[str, object] = field(default_factory=dict)


def is_digest_ref(value: object) -> bool:
    return (
        isinstance(value, str)
        and _DIGEST_REF.fullmatch(value) is not None
        and assistant_registry.digest_is_bound(value)
    )


def _digest_ref(value: object) -> str:
    if not isinstance(value, str) or _DIGEST_REF.fullmatch(value) is None:
        raise RegistryError("an Assistant image must be an OCI sha256 digest reference")
    if not is_digest_ref(value):
        raise RegistryError("an Assistant release digest has not been bound")
    return value


def load_registry(path: Path = REGISTRY_PATH) -> dict[str, AssistantSpec]:
    """Load the closed, build-baked local registry schema v2.

    There is deliberately no environment override: changing the allowlist requires a
    new controller image and therefore leaves a normal release/audit trail.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RegistryError("the baked Assistant registry is unreadable") from exc
    expected_ids = set(_REVIEWED_ASSISTANTS)
    if (
        not isinstance(raw, dict)
        or set(raw) != {"schema", "images"}
        or raw["schema"] != 2
        or not isinstance(raw["images"], dict)
        or set(raw["images"]) != expected_ids
    ):
        raise RegistryError("the baked Assistant registry has an unsupported shape")
    registry: dict[str, AssistantSpec] = {}
    for assistant_id, contract in _REVIEWED_ASSISTANTS.items():
        spec = AssistantSpec(
            assistant_id=assistant_id,
            name=contract.name,
            summary=contract.summary,
            image=_digest_ref(raw["images"][assistant_id]),
            powers={
                power_id: PowerSpec(
                    summary=assistant_registry.power_summary(power_id),
                    input_schema=power["input_schema"],
                    output_schema=power["output_schema"],
                    accounts=tuple(power["accounts"]),
                )
                for power_id, power in contract.powers.items()
            },
            allowed_hosts=contract.allowed_hosts,
            accounts={
                account.id: AccountSpec(provider=account.provider, scopes=account.scopes)
                for account in contract.accounts
            },
            machine_contract=contract.machine_contract,
        )
        registry[spec.assistant_id] = spec
    return registry
