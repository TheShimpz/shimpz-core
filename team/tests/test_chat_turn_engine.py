"""Characterize the shared hosted/local chat-segment decision engine."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

TEAM = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TEAM))

import brain_runtime_client
import chat_orchestrator
import chat_turn_engine


def _context() -> brain_runtime_client.RuntimeContext:
    return brain_runtime_client.RuntimeContext(
        thread_id="thread-1",
        team_name="Team",
        assistants=(
            brain_runtime_client.RuntimeAssistant(
                id="assistant",
                genesis="Use the declared Power.",
                powers=(
                    brain_runtime_client.RuntimePower(
                        id="lookup",
                        summary="Look up one value.",
                        input_schema={"type": "object"},
                        approval="none",
                    ),
                ),
            ),
        ),
        provider="openai",
        model="gpt-test",
        api_key="test-key",
    )


class _Runtime:
    @staticmethod
    def start(_context, _message):
        return brain_runtime_client.RuntimeTurn(
            status="power-required",
            reply="",
            powers=(
                brain_runtime_client.PowerRequest(
                    interrupt_id="interrupt-1",
                    assistant_id="assistant",
                    power="lookup",
                    input={"query": "Ada"},
                    approval="none",
                ),
            ),
        )


class _Batch:
    @staticmethod
    def prepare(_requests) -> None:
        raise AssertionError("a suspended batch must not be prepared")

    @staticmethod
    def invoke(_request):
        raise AssertionError("a suspended Power must not be invoked")

    @staticmethod
    def delivered(_requests) -> None:
        raise AssertionError("a suspended batch must not be delivered")


class SharedChatTurnEngineTest(unittest.TestCase):
    def _strategy(self, *, local: bool, decisions: list[str]) -> chat_turn_engine.SegmentStrategy:
        def private_inputs(_requests, requirements) -> bool:
            requirements.accounts = ("account-required",)
            decisions.append("accounts")
            return True

        def approval(_requests, _requirements) -> bool:
            decisions.append("approval")
            return False

        def raise_problem(reason: str, _exc: BaseException | None) -> None:
            raise AssertionError(reason)

        return chat_turn_engine.SegmentStrategy(
            runtime=_Runtime(),
            prepare=lambda: chat_turn_engine.PreparedSegment(
                "Team",
                ("identity",),
                _context(),
                [],
                _Batch(),
            ),
            validate_power=lambda _assistant, _power, payload: payload,
            pause_for_private_inputs=private_inputs,
            cancelled=lambda: False,
            validate_context=lambda: None,
            raise_problem=raise_problem,
            pause_for_approval=approval if local else None,
            approval_granted=(lambda _request: False) if local else None,
        )

    def test_hosted_and_local_strategies_make_the_same_real_suspension_decision(self) -> None:
        decisions: dict[str, list[str]] = {"hosted": [], "local": []}

        hosted = chat_turn_engine.run_segment(
            self._strategy(local=False, decisions=decisions["hosted"]),
            message="look this up",
            continuation=None,
            expected_identity=("identity",),
        )
        local = chat_turn_engine.run_segment(
            self._strategy(local=True, decisions=decisions["local"]),
            message="look this up",
            continuation=None,
            expected_identity=("identity",),
        )

        self.assertIsInstance(hosted[2], chat_orchestrator.ChatSuspension)
        self.assertIsInstance(local[2], chat_orchestrator.ChatSuspension)
        self.assertEqual(hosted[2], local[2])
        self.assertEqual(hosted[3].accounts, local[3].accounts)
        self.assertEqual(decisions, {"hosted": ["accounts"], "local": ["accounts"]})


if __name__ == "__main__":
    unittest.main()
