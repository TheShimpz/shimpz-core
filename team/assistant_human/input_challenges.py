"""Bounded, one-use continuations for Assistant human input."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from assistant_human import challenge_store

MAX_PENDING_CHALLENGES = challenge_store.MAX_PENDING_CHALLENGES
DEFAULT_TTL_SECONDS = challenge_store.DEFAULT_TTL_SECONDS


class InputChallengeError(RuntimeError):
    """A pending input continuation is unavailable or conflicts."""


class InputChallengeNotFoundError(InputChallengeError):
    """The challenge is unknown, expired, consumed, or owned by another Team."""


@dataclass(frozen=True, slots=True)
class InputRequirement:
    interrupt_id: str
    assistant_id: str
    power_id: str
    assistant_image: str
    ordinal: int
    request_type: str
    title: str
    summary: str
    docs: str | None
    options: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PendingInputChallenge:
    id: str
    team_id: str
    expires_at: float
    requirement: InputRequirement
    payload: Any


def _valid_requirement(value: object) -> bool:
    return isinstance(value, InputRequirement)


_CONTRACT = challenge_store.ChallengeContract(
    PendingInputChallenge,
    _valid_requirement,
    InputChallengeError,
    InputChallengeNotFoundError,
    "input",
)


class InputChallengeStore(challenge_store.ChallengeStore[PendingInputChallenge]):
    """Keep one process-local human-input continuation per Team."""

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
