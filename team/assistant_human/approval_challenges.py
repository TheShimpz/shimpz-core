"""One-use, Team-bound continuations for explicit Assistant Power approval."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from assistant_human import challenge_store

MAX_PENDING_CHALLENGES = challenge_store.MAX_PENDING_CHALLENGES
DEFAULT_TTL_SECONDS = challenge_store.DEFAULT_TTL_SECONDS


class ApprovalChallengeError(RuntimeError):
    """A pending approval continuation is unavailable or conflicts."""


class ApprovalChallengeNotFoundError(ApprovalChallengeError):
    """The opaque challenge is unknown, expired, consumed, or belongs to another Team."""


@dataclass(frozen=True, slots=True)
class ApprovalRequirement:
    interrupt_id: str
    assistant_id: str
    assistant_name: str
    power_id: str
    assistant_image: str
    ordinal: int
    title: str
    summary: str
    docs: str | None
    runs: str


@dataclass(frozen=True, slots=True)
class PendingApprovalChallenge:
    id: str
    team_id: str
    expires_at: float
    requirements: tuple[ApprovalRequirement, ...]
    payload: Any


_CONTRACT = challenge_store.ChallengeContract(
    PendingApprovalChallenge,
    bool,
    ApprovalChallengeError,
    ApprovalChallengeNotFoundError,
    "approval",
)


class ApprovalChallengeStore(challenge_store.ChallengeStore[PendingApprovalChallenge]):
    """Keep approval grants memory-only and consume them before continuation."""

    def __init__(
        self,
        *,
        capacity: int = MAX_PENDING_CHALLENGES,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        super().__init__(
            _CONTRACT,
            capacity=capacity,
            ttl_seconds=ttl_seconds,
            clock=lambda: time.monotonic(),
        )
