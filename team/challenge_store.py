"""Generic bounded, Team-bound, one-use TTL challenge storage."""

from __future__ import annotations

import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, TypeVar

MAX_PENDING_CHALLENGES = 32
DEFAULT_TTL_SECONDS = 300
_CHALLENGE_ID = re.compile(r"[0-9a-f]{32}\Z")
_TEAM_ID = re.compile(r"[a-z0-9_]{1,40}\Z")


class PendingChallenge(Protocol):
    id: str
    team_id: str
    expires_at: float
    payload: Any


PendingT = TypeVar("PendingT", bound=PendingChallenge)


@dataclass(frozen=True, slots=True)
class ChallengeContract[PendingT]:
    pending_type: Callable[[str, str, float, object, Any], PendingT]
    payload_validator: Callable[[object], bool]
    error_class: type[RuntimeError]
    not_found_class: type[RuntimeError]
    label: str


class ChallengeStore[PendingT]:
    def __init__(
        self,
        contract: ChallengeContract[PendingT],
        *,
        capacity: int = MAX_PENDING_CHALLENGES,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if type(capacity) is not int or not 1 <= capacity <= 1024:
            raise ValueError(f"{contract.label} challenge capacity is invalid")
        if type(ttl_seconds) is not int or not 30 <= ttl_seconds <= 900:
            raise ValueError(f"{contract.label} challenge TTL is invalid")
        if not callable(contract.pending_type) or not callable(contract.payload_validator) or not callable(clock):
            raise ValueError(f"{contract.label} challenge configuration is invalid")
        self._contract = contract
        self._capacity = capacity
        self._ttl = ttl_seconds
        self._clock = clock
        self._pending: dict[str, PendingT] = {}
        self._by_team: dict[str, str] = {}
        self._lock = threading.Lock()

    def create(self, team_id: object, challenge_payload: object, payload: Any) -> PendingT:
        team = self._team_id(team_id)
        if not self._contract.payload_validator(challenge_payload):
            raise self._contract.error_class(f"{self._contract.label} challenge requires metadata")
        now = self._clock()
        with self._lock:
            self._expire(now)
            if team in self._by_team:
                raise self._contract.error_class(f"Team already has a pending {self._contract.label} challenge")
            if len(self._pending) >= self._capacity:
                raise self._contract.error_class(f"{self._contract.label} challenge capacity reached")
            identifier = secrets.token_hex(16)
            while identifier in self._pending:
                identifier = secrets.token_hex(16)
            challenge = self._contract.pending_type(
                identifier,
                team,
                now + self._ttl,
                challenge_payload,
                payload,
            )
            self._pending[identifier] = challenge
            self._by_team[team] = identifier
            return challenge

    def get(self, team_id: object, challenge_id: object) -> PendingT:
        team = self._team_id(team_id)
        identifier = self._challenge_id(challenge_id)
        with self._lock:
            self._expire(self._clock())
            return self._available(team, identifier)

    def restore(
        self,
        team_id: object,
        challenge_id: object,
        remaining_seconds: object,
        challenge_payload: object,
        payload: Any,
    ) -> PendingT:
        """Rehydrate one authenticated durable challenge without extending its TTL."""
        team = self._team_id(team_id)
        identifier = self._challenge_id(challenge_id)
        if (
            type(remaining_seconds) is not int
            or not 1 <= remaining_seconds <= self._ttl
            or not self._contract.payload_validator(challenge_payload)
        ):
            raise self._contract.error_class(f"{self._contract.label} challenge restore is invalid")
        now = self._clock()
        with self._lock:
            self._expire(now)
            if team in self._by_team or identifier in self._pending:
                raise self._contract.error_class(f"Team already has a pending {self._contract.label} challenge")
            if len(self._pending) >= self._capacity:
                raise self._contract.error_class(f"{self._contract.label} challenge capacity reached")
            challenge = self._contract.pending_type(
                identifier,
                team,
                now + remaining_seconds,
                challenge_payload,
                payload,
            )
            self._pending[identifier] = challenge
            self._by_team[team] = identifier
            return challenge

    def current(self, team_id: object) -> PendingT | None:
        team = self._team_id(team_id)
        with self._lock:
            self._expire(self._clock())
            identifier = self._by_team.get(team)
            return self._pending.get(identifier) if identifier is not None else None

    def claim(self, team_id: object, challenge_id: object) -> PendingT:
        return self.claim_after(team_id, challenge_id, lambda _challenge: None)

    def claim_after(
        self,
        team_id: object,
        challenge_id: object,
        commit: Callable[[PendingT], None],
    ) -> PendingT:
        """Consume one challenge only after its bounded controller transaction commits."""
        team = self._team_id(team_id)
        identifier = self._challenge_id(challenge_id)
        if not callable(commit):
            raise self._contract.error_class(f"{self._contract.label} challenge commit is invalid")
        with self._lock:
            self._expire(self._clock())
            challenge = self._available(team, identifier)
            commit(challenge)
            self._pending.pop(identifier)
            if self._by_team.get(team) == identifier:
                self._by_team.pop(team, None)
            return challenge

    def cancel_team(self, team_id: object) -> bool:
        team = self._team_id(team_id)
        with self._lock:
            identifier = self._by_team.pop(team, None)
            return self._pending.pop(identifier, None) is not None if identifier is not None else False

    def cancel_all(self) -> int:
        with self._lock:
            removed = len(self._pending)
            self._pending.clear()
            self._by_team.clear()
            return removed

    def _available(self, team_id: str, challenge_id: str) -> PendingT:
        challenge = self._pending.get(challenge_id)
        if challenge is None or challenge.team_id != team_id:
            raise self._contract.not_found_class(f"{self._contract.label} challenge is unavailable")
        return challenge

    def _expire(self, now: float) -> None:
        expired = [identifier for identifier, item in self._pending.items() if item.expires_at <= now]
        for identifier in expired:
            challenge = self._pending.pop(identifier)
            if self._by_team.get(challenge.team_id) == identifier:
                self._by_team.pop(challenge.team_id, None)

    def _team_id(self, value: object) -> str:
        if not isinstance(value, str) or _TEAM_ID.fullmatch(value) is None:
            raise self._contract.error_class("Team id is invalid")
        return value

    def _challenge_id(self, value: object) -> str:
        if not isinstance(value, str) or _CHALLENGE_ID.fullmatch(value) is None:
            raise self._contract.not_found_class(f"{self._contract.label} challenge is unavailable")
        return value
