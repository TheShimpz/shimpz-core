"""Bounded, process-local continuations for just-in-time Assistant secrets."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import challenge_store

MAX_PENDING_CHALLENGES = challenge_store.MAX_PENDING_CHALLENGES
DEFAULT_TTL_SECONDS = challenge_store.DEFAULT_TTL_SECONDS


class SecretChallengeError(RuntimeError):
    """A pending secret continuation is unavailable or conflicts."""


class SecretChallengeNotFoundError(SecretChallengeError):
    """The opaque challenge is unknown, expired, or belongs to another Team."""


@dataclass(frozen=True, slots=True)
class SecretRequirement:
    assistant_id: str
    assistant_name: str
    power_ids: tuple[str, ...]
    secrets: tuple[tuple[str, str, str], ...]


@dataclass(frozen=True, slots=True)
class PendingSecretChallenge:
    id: str
    team_id: str
    expires_at: float
    requirements: tuple[SecretRequirement, ...]
    payload: Any


_CONTRACT = challenge_store.ChallengeContract(
    PendingSecretChallenge,
    bool,
    SecretChallengeError,
    SecretChallengeNotFoundError,
    "secret",
)


class SecretChallengeStore(challenge_store.ChallengeStore[PendingSecretChallenge]):
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
