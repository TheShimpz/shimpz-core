"""Closed public metadata and exact submissions for local Power approval."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Protocol

import assistant_approval_challenges
import brain_runtime_client
from local_registry import AssistantSpec

MAX_APPROVAL_REQUESTS = 64


class ApprovalFlowError(RuntimeError):
    """An approval request or submission violated its closed contract."""


class _ActiveBinding(Protocol):
    spec: AssistantSpec


def requirements_for_batch(
    bindings: Mapping[str, _ActiveBinding],
    requests: Sequence[brain_runtime_client.PowerRequest],
) -> tuple[assistant_approval_challenges.ApprovalRequirement, ...]:
    """Project only public metadata while retaining exact interrupt bindings internally."""
    if not requests or len(requests) > MAX_APPROVAL_REQUESTS:
        raise ApprovalFlowError("approval batch size is invalid")
    requirements: list[assistant_approval_challenges.ApprovalRequirement] = []
    seen: set[str] = set()
    for request in requests:
        active = bindings.get(request.assistant_id)
        power = active.spec.powers.get(request.power) if active is not None else None
        if power is None or request.approval == "none" or request.approval != power.approval:
            raise ApprovalFlowError("Power approval contract is unavailable")
        if request.interrupt_id in seen:
            raise ApprovalFlowError("approval batch repeats an interrupt")
        seen.add(request.interrupt_id)
        requirements.append(
            assistant_approval_challenges.ApprovalRequirement(
                interrupt_id=request.interrupt_id,
                assistant_id=request.assistant_id,
                assistant_name=active.spec.name,
                power_id=request.power,
                power_summary=power.summary,
            )
        )
    return tuple(requirements)


def challenge_payload(challenge: assistant_approval_challenges.PendingApprovalChallenge) -> dict[str, object]:
    """Expose no Power input, interrupt id, or provider credential."""
    return {
        "team_id": challenge.team_id,
        "status": "approval-required",
        "turn_id": challenge.id,
        "challenge_id": challenge.id,
        "requirements": [
            {
                "assistant_id": requirement.assistant_id,
                "assistant_name": requirement.assistant_name,
                "power_id": requirement.power_id,
                "power_summary": requirement.power_summary,
            }
            for requirement in challenge.requirements
        ],
    }


def approved_interrupts(
    challenge: assistant_approval_challenges.PendingApprovalChallenge,
    body: object,
) -> frozenset[str]:
    """Accept exactly one explicit affirmative decision for the complete paused batch."""
    if (
        not isinstance(body, dict)
        or set(body) != {"challenge_id", "approved"}
        or body.get("challenge_id") != challenge.id
        or body.get("approved") is not True
    ):
        raise ApprovalFlowError("approval submission does not match its challenge")
    identifiers = frozenset(requirement.interrupt_id for requirement in challenge.requirements)
    if len(identifiers) != len(challenge.requirements):
        raise ApprovalFlowError("approval challenge repeats an interrupt")
    return identifiers
