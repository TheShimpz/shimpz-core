from __future__ import annotations

import unittest

import brain_runtime_client
import chat_orchestrator


def context(*powers: brain_runtime_client.RuntimePower) -> brain_runtime_client.RuntimeContext:
    return brain_runtime_client.RuntimeContext(
        thread_id="capsule:assistant:conversation",
        assistant_id="hello-pulse",
        rules="Use only declared Powers.",
        powers=powers
        or (
            brain_runtime_client.RuntimePower(
                id="hello",
                summary="Return a greeting.",
                input_schema={"type": "object", "additionalProperties": False},
                approval="none",
            ),
        ),
        provider="openai",
        model="gpt-test",
        api_key="not-a-real-key",
    )


def completed(reply: str = "Done") -> brain_runtime_client.RuntimeTurn:
    return brain_runtime_client.RuntimeTurn(status="completed", reply=reply, powers=())


def suspended(
    power: str = "hello",
    *,
    interrupt_id: str = "interrupt-1",
    approval: str = "none",
) -> brain_runtime_client.RuntimeTurn:
    return brain_runtime_client.RuntimeTurn(
        status="power-required",
        reply="",
        powers=(
            brain_runtime_client.PowerRequest(
                interrupt_id=interrupt_id,
                power=power,
                input={"name": "Ada"},
                approval=approval,
            ),
        ),
    )


class FakeRuntime:
    def __init__(self, turns):
        self.turns = iter(turns)
        self.resumes = []

    def start(self, _context, _message):
        return next(self.turns)

    def resume(self, _context, results):
        self.resumes.append(results)
        return next(self.turns)


class ChatOrchestratorTests(unittest.TestCase):
    def test_direct_reply_never_invokes_a_power(self):
        invoked = []

        outcome = chat_orchestrator.run(
            FakeRuntime([completed("Hello")]),
            context(),
            "Hello",
            lambda power, payload: invoked.append((power, payload)),
        )

        self.assertEqual(outcome.reply, "Hello")
        self.assertEqual(outcome.powers, ())
        self.assertEqual(invoked, [])

    def test_power_result_is_returned_to_the_model_before_the_final_reply(self):
        runtime = FakeRuntime([suspended(), completed("Hello, Ada.")])
        invoked = []

        outcome = chat_orchestrator.run(
            runtime,
            context(),
            "Greet Ada",
            lambda power, payload: invoked.append((power, payload)) or {"message": "Hello, Ada."},
        )

        self.assertEqual(invoked, [("hello", {"name": "Ada"})])
        self.assertEqual(runtime.resumes, [{"interrupt-1": {"message": "Hello, Ada."}}])
        self.assertEqual(outcome.reply, "Hello, Ada.")
        self.assertEqual(outcome.powers, ("hello",))

    def test_multiple_power_rounds_remain_bounded_and_controller_brokered(self):
        runtime = FakeRuntime(
            [
                suspended(interrupt_id="one"),
                suspended(interrupt_id="two"),
                completed(),
            ]
        )

        outcome = chat_orchestrator.run(
            runtime,
            context(),
            "Run twice",
            lambda _power, _payload: {"message": "ok"},
        )

        self.assertEqual(outcome.powers, ("hello", "hello"))
        self.assertEqual(len(runtime.resumes), 2)

    def test_undeclared_power_or_changed_approval_fails_before_invocation(self):
        invoked = []
        for turn in (suspended("shell"), suspended(approval="each-run")):
            with self.subTest(turn=turn), self.assertRaises(chat_orchestrator.ChatOrchestrationError):
                chat_orchestrator.run(
                    FakeRuntime([turn]),
                    context(),
                    "Do it",
                    lambda power, payload: invoked.append((power, payload)),
                )
        self.assertEqual(invoked, [])

    def test_approval_policy_fails_closed_until_the_controller_has_a_grant(self):
        protected = brain_runtime_client.RuntimePower(
            id="hello",
            summary="Return a greeting.",
            input_schema={"type": "object"},
            approval="each-run",
        )
        invoked = []

        with self.assertRaises(chat_orchestrator.ApprovalRequiredError) as raised:
            chat_orchestrator.run(
                FakeRuntime([suspended(approval="each-run")]),
                context(protected),
                "Do it",
                lambda power, payload: invoked.append((power, payload)),
            )

        self.assertEqual(raised.exception.request.power, "hello")
        self.assertEqual(invoked, [])

    def test_cancelled_turn_never_starts_or_resumes_work(self):
        runtime = FakeRuntime([completed()])

        with self.assertRaises(chat_orchestrator.ChatStoppedError):
            chat_orchestrator.run(runtime, context(), "Stop", lambda _power, _payload: {}, cancelled=lambda: True)
        self.assertEqual(runtime.resumes, [])

    def test_power_round_limit_stops_an_unbounded_model_loop(self):
        turns = [
            suspended(interrupt_id=f"interrupt-{index}") for index in range(chat_orchestrator.MAX_POWER_ROUNDS + 1)
        ]

        with self.assertRaisesRegex(chat_orchestrator.ChatOrchestrationError, "round limit"):
            chat_orchestrator.run(
                FakeRuntime(turns),
                context(),
                "Loop",
                lambda _power, _payload: {"message": "ok"},
            )


if __name__ == "__main__":
    unittest.main()
