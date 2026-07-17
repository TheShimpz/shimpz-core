"""Deterministic Controller-owned loop between LangGraph suspensions and Assistant Powers."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

import brain_runtime_client

MAX_POWER_ROUNDS = 8


class ChatOrchestrationError(RuntimeError):
    """The Brain runtime violated the turn contract or could not finish safely."""


class ApprovalRequiredError(ChatOrchestrationError):
    """A declared Power requires a Captain approval that has not been granted."""

    def __init__(self, request: brain_runtime_client.PowerRequest) -> None:
        super().__init__(f"Power {request.power!r} requires {request.approval} approval")
        self.request = request


class ChatStoppedError(ChatOrchestrationError):
    """The Controller cancelled the active turn between two bounded operations."""


@dataclass(frozen=True, slots=True)
class ChatOutcome:
    reply: str
    powers: tuple[str, ...]


PowerInvoker = Callable[[str, Mapping[str, Any]], object]
CancellationCheck = Callable[[], bool]


def run(
    runtime: brain_runtime_client.BrainRuntimeClient,
    context: brain_runtime_client.RuntimeContext,
    message: str,
    invoke_power: PowerInvoker,
    *,
    cancelled: CancellationCheck = lambda: False,
) -> ChatOutcome:
    """Run a bounded turn; every model-requested Power returns through Controller validation."""
    if cancelled():
        raise ChatStoppedError("chat turn stopped")
    turn = runtime.start(context, message)
    invoked: list[str] = []
    declared = {power.id: power for power in context.powers}

    for _round in range(MAX_POWER_ROUNDS + 1):
        if cancelled():
            raise ChatStoppedError("chat turn stopped")
        if turn.status == "completed":
            return ChatOutcome(reply=turn.reply, powers=tuple(invoked))
        if _round == MAX_POWER_ROUNDS:
            raise ChatOrchestrationError("Brain exceeded the Power round limit")

        results: dict[str, object] = {}
        for request in turn.powers:
            if cancelled():
                raise ChatStoppedError("chat turn stopped")
            power = declared.get(request.power)
            if power is None or request.approval != power.approval:
                raise ChatOrchestrationError("Brain requested an undeclared Power contract")
            if request.interrupt_id in results:
                raise ChatOrchestrationError("Brain repeated a Power interrupt id")
            if power.approval != "none":
                raise ApprovalRequiredError(request)
            results[request.interrupt_id] = invoke_power(power.id, request.input)
            invoked.append(power.id)

        if not results:
            raise ChatOrchestrationError("Brain suspended without a Power request")
        turn = runtime.resume(context, results)

    raise ChatOrchestrationError("Brain did not complete the chat turn")
