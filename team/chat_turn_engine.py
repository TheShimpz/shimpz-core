"""Shared Controller-owned chat turn drive and suspension dispatch."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

import assistant_chat
import brain_runtime_client
import chat_orchestrator
import power_journal


@dataclass(slots=True)
class SegmentRequirements:
    """Mutable suspension gates populated while one shared segment is driven."""

    accounts: tuple[object, ...] = ()
    secrets: tuple[object, ...] = ()
    approvals: tuple[object, ...] = ()

    def groups(self, *, approvals: bool) -> tuple[tuple[object, ...], ...]:
        groups = (self.accounts, self.secrets)
        return (*groups, self.approvals) if approvals else groups


@dataclass(frozen=True, slots=True)
class PreparedSegment:
    """Controller-specific resources consumed by the shared segment state machine."""

    team_name: str
    identity: tuple[object, ...]
    context: object
    files: list[dict[str, object]]
    durable_batch: object


@dataclass(frozen=True, slots=True)
class SegmentStrategy:
    """Hosted/local adapters for state and errors that intentionally differ."""

    runtime: object
    prepare: Callable[[], PreparedSegment]
    validate_power: Callable
    pause_for_private_inputs: Callable[[tuple[object, ...], SegmentRequirements], bool]
    cancelled: Callable[[], bool]
    validate_context: Callable[[], None]
    raise_problem: Callable[[str, BaseException | None], None]
    finalize: Callable[[], None] = lambda: None
    pause_for_approval: Callable[[tuple[object, ...], SegmentRequirements], bool] | None = None
    approval_granted: Callable | None = None


_DRIVE_ERRORS = (
    power_journal.PowerJournalError,
    chat_orchestrator.ChatStoppedError,
    chat_orchestrator.ApprovalRequiredError,
    chat_orchestrator.ChatOrchestrationError,
    brain_runtime_client.BrainRuntimeError,
)


def run_segment(
    strategy: SegmentStrategy,
    *,
    message: str | None,
    continuation: chat_orchestrator.ChatContinuation | None,
    expected_identity: tuple[object, ...] | None,
) -> tuple[
    str,
    tuple[object, ...],
    chat_orchestrator.ChatOutcome | chat_orchestrator.ChatSuspension,
    SegmentRequirements,
]:
    """Apply the same continuation, identity and suspension decisions on both Controllers."""
    if (message is None) == (continuation is None):
        strategy.raise_problem("invalid-continuation", None)
    segment = strategy.prepare()
    if expected_identity is not None and segment.identity != expected_identity:
        strategy.raise_problem("context-changed", None)
    requirements = SegmentRequirements()
    try:
        outcome = drive(
            strategy=strategy,
            segment=segment,
            message=message,
            continuation=continuation,
            requirements=requirements,
        )
    except _DRIVE_ERRORS as exc:
        strategy.raise_problem("drive-error", exc)
        raise AssertionError("chat error adapter returned") from exc
    strategy.finalize()
    groups = requirements.groups(approvals=strategy.pause_for_approval is not None)
    if isinstance(outcome, chat_orchestrator.ChatSuspension) and suspension_gate_count(*groups) != 1:
        strategy.raise_problem("invalid-suspension", None)
    return segment.team_name, segment.identity, outcome, requirements


def drive(
    runtime: object | None = None,
    context: object | None = None,
    message: str | None = None,
    files: list[dict[str, object]] | None = None,
    continuation: chat_orchestrator.ChatContinuation | None = None,
    validate_power: Callable | None = None,
    durable_batch: object | None = None,
    pause_before_batch: Callable | None = None,
    cancelled: Callable[[], bool] | None = None,
    validate_context: Callable[[], None] | None = None,
    *,
    pause_for_approval: Callable | None = None,
    approval_granted: Callable | None = None,
    strategy: SegmentStrategy | None = None,
    segment: PreparedSegment | None = None,
    requirements: SegmentRequirements | None = None,
) -> chat_orchestrator.ChatOutcome | chat_orchestrator.ChatSuspension:
    """Run or resume one turn with the same durable Power hooks on both Controllers."""
    if strategy is not None:
        if segment is None or requirements is None:
            raise TypeError("shared segment drive requires prepared state")
        runtime = strategy.runtime
        context = segment.context
        files = segment.files
        validate_power = strategy.validate_power
        durable_batch = segment.durable_batch

        def pause_before_batch(requests: tuple[object, ...]) -> bool:
            return strategy.pause_for_private_inputs(requests, requirements)

        cancelled = strategy.cancelled
        validate_context = strategy.validate_context
        if strategy.pause_for_approval is not None:

            def pause_for_approval(requests: tuple[object, ...]) -> bool:
                if strategy.pause_for_approval is None:
                    raise AssertionError("approval strategy changed")
                return strategy.pause_for_approval(requests, requirements)

        approval_granted = strategy.approval_granted
    if (
        runtime is None
        or context is None
        or files is None
        or validate_power is None
        or durable_batch is None
        or pause_before_batch is None
        or cancelled is None
        or validate_context is None
    ):
        raise TypeError("chat drive is missing required state")
    hooks = {
        "prepare_batch": durable_batch.prepare,
        "batch_delivered": durable_batch.delivered,
        "pause_before_batch": pause_before_batch,
        "cancelled": cancelled,
        "validate_context": validate_context,
    }
    if pause_for_approval is not None:
        hooks["pause_for_approval"] = pause_for_approval
    if approval_granted is not None:
        hooks["approval_granted"] = approval_granted
    if continuation is None:
        return chat_orchestrator.run_until_pause(
            runtime,
            context,
            assistant_chat.build_prompt(message, files),
            validate_power,
            durable_batch.invoke,
            **hooks,
        )
    return chat_orchestrator.continue_after_pause(
        runtime,
        context,
        continuation,
        validate_power,
        durable_batch.invoke,
        **hooks,
    )


def suspension_gate_count(*requirements: tuple[object, ...]) -> int:
    return sum(bool(group) for group in requirements)


def dispatch(
    outcome: chat_orchestrator.ChatOutcome | chat_orchestrator.ChatSuspension,
    requirements: tuple[tuple[object, ...], ...],
    pending: Callable[[chat_orchestrator.ChatSuspension], object],
    pause: tuple[Callable[[chat_orchestrator.ChatSuspension, tuple[object, ...], object], object], ...],
    complete: Callable[[chat_orchestrator.ChatOutcome], object],
) -> object:
    """Send exactly one suspension kind to its handler, or finish a terminal turn."""
    if not isinstance(outcome, chat_orchestrator.ChatSuspension):
        return complete(outcome)
    if len(requirements) != len(pause) or suspension_gate_count(*requirements) != 1:
        raise ValueError("invalid chat suspension")
    state = pending(outcome)
    for group, handler in zip(requirements, pause, strict=True):
        if group:
            return handler(outcome, group, state)
    raise AssertionError("unreachable")
