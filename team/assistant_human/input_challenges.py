"""Bounded, one-use continuations for Assistant human input."""

from __future__ import annotations

import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any

MAX_PENDING_CHALLENGES = 32
DEFAULT_TTL_SECONDS = 300
_CHALLENGE_ID = re.compile(r"[0-9a-f]{32}")
_TEAM_ID = re.compile(r"[a-z0-9_]{1,40}")


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


def _team_id(value: object) -> str:
    if not isinstance(value, str) or _TEAM_ID.fullmatch(value) is None:
        raise InputChallengeError("Team id is invalid")
    return value


def _challenge_id(value: object) -> str:
    if not isinstance(value, str) or _CHALLENGE_ID.fullmatch(value) is None:
        raise InputChallengeNotFoundError("input challenge is unavailable")
    return value


class InputChallengeStore:
    """Keep one process-local human-input continuation per Team."""

    def __init__(self, *, capacity: int = MAX_PENDING_CHALLENGES, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        if type(capacity) is not int or not 1 <= capacity <= 1024:
            raise ValueError("input challenge capacity is invalid")
        if type(ttl_seconds) is not int or not 30 <= ttl_seconds <= 900:
            raise ValueError("input challenge TTL is invalid")
        self._capacity = capacity
        self._ttl = ttl_seconds
        self._pending: dict[str, PendingInputChallenge] = {}
        self._by_team: dict[str, str] = {}
        self._lock = threading.Lock()

    def _expire(self, now: float) -> None:
        expired = [identifier for identifier, item in self._pending.items() if item.expires_at <= now]
        for identifier in expired:
            challenge = self._pending.pop(identifier)
            if self._by_team.get(challenge.team_id) == identifier:
                self._by_team.pop(challenge.team_id, None)

    def create(
        self,
        team_id: object,
        requirement: InputRequirement,
        payload: Any,
    ) -> PendingInputChallenge:
        team = _team_id(team_id)
        if not isinstance(requirement, InputRequirement):
            raise InputChallengeError("input challenge requires metadata")
        now = time.monotonic()
        with self._lock:
            self._expire(now)
            if team in self._by_team:
                raise InputChallengeError("Team already has a pending input challenge")
            if len(self._pending) >= self._capacity:
                raise InputChallengeError("input challenge capacity reached")
            identifier = secrets.token_hex(16)
            while identifier in self._pending:
                identifier = secrets.token_hex(16)
            challenge = PendingInputChallenge(
                id=identifier,
                team_id=team,
                expires_at=now + self._ttl,
                requirement=requirement,
                payload=payload,
            )
            self._pending[identifier] = challenge
            self._by_team[team] = identifier
            return challenge

    def get(self, team_id: object, challenge_id: object) -> PendingInputChallenge:
        team = _team_id(team_id)
        identifier = _challenge_id(challenge_id)
        now = time.monotonic()
        with self._lock:
            self._expire(now)
            challenge = self._pending.get(identifier)
            if challenge is None or challenge.team_id != team:
                raise InputChallengeNotFoundError("input challenge is unavailable")
            return challenge

    def restore(
        self,
        team_id: object,
        challenge_id: object,
        remaining_seconds: object,
        requirement: InputRequirement,
        payload: Any,
    ) -> PendingInputChallenge:
        """Rehydrate one authenticated durable challenge without extending its TTL."""
        team = _team_id(team_id)
        identifier = _challenge_id(challenge_id)
        if (
            type(remaining_seconds) is not int
            or not 1 <= remaining_seconds <= self._ttl
            or not isinstance(requirement, InputRequirement)
        ):
            raise InputChallengeError("input challenge restore is invalid")
        now = time.monotonic()
        with self._lock:
            self._expire(now)
            if team in self._by_team or identifier in self._pending:
                raise InputChallengeError("Team already has a pending input challenge")
            if len(self._pending) >= self._capacity:
                raise InputChallengeError("input challenge capacity reached")
            challenge = PendingInputChallenge(
                identifier,
                team,
                now + remaining_seconds,
                requirement,
                payload,
            )
            self._pending[identifier] = challenge
            self._by_team[team] = identifier
            return challenge

    def current(self, team_id: object) -> PendingInputChallenge | None:
        team = _team_id(team_id)
        now = time.monotonic()
        with self._lock:
            self._expire(now)
            identifier = self._by_team.get(team)
            return self._pending.get(identifier) if identifier is not None else None

    def claim(self, team_id: object, challenge_id: object) -> PendingInputChallenge:
        team = _team_id(team_id)
        identifier = _challenge_id(challenge_id)
        now = time.monotonic()
        with self._lock:
            self._expire(now)
            challenge = self._pending.get(identifier)
            if challenge is None or challenge.team_id != team:
                raise InputChallengeNotFoundError("input challenge is unavailable")
            self._pending.pop(identifier)
            if self._by_team.get(team) == identifier:
                self._by_team.pop(team, None)
            return challenge

    def cancel_team(self, team_id: object) -> bool:
        team = _team_id(team_id)
        with self._lock:
            identifier = self._by_team.pop(team, None)
            return self._pending.pop(identifier, None) is not None if identifier is not None else False

    def cancel_all(self) -> int:
        with self._lock:
            removed = len(self._pending)
            self._pending.clear()
            self._by_team.clear()
            return removed
