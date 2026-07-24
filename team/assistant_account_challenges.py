"""Bounded, process-local continuations for just-in-time OAuth accounts."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import challenge_store

MAX_PENDING_CHALLENGES = challenge_store.MAX_PENDING_CHALLENGES
DEFAULT_TTL_SECONDS = challenge_store.DEFAULT_TTL_SECONDS


class AccountChallengeError(RuntimeError):
    """A pending account continuation is unavailable or conflicts."""


class AccountChallengeNotFoundError(AccountChallengeError):
    """The opaque challenge expired, was consumed, or belongs to another Team."""


@dataclass(frozen=True, slots=True)
class AccountRequirement:
    assistant_id: str
    assistant_name: str
    power_ids: tuple[str, ...]
    accounts: tuple[tuple[str, str, tuple[str, ...]], ...]


@dataclass(frozen=True, slots=True)
class PendingAccountChallenge:
    id: str
    team_id: str
    expires_at: float
    requirements: tuple[AccountRequirement, ...]
    payload: Any


_CONTRACT = challenge_store.ChallengeContract(
    PendingAccountChallenge,
    bool,
    AccountChallengeError,
    AccountChallengeNotFoundError,
    "account",
)


class AccountChallengeStore(challenge_store.ChallengeStore[PendingAccountChallenge]):
    """Keep one short-lived, one-use paused account turn per Team."""

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
