from __future__ import annotations

import sys
import tempfile
import threading
from pathlib import Path
from unittest import mock

TEAM = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TEAM))
import brain_runtime_client
import local_app
from assistant_human import approval_grants as assistant_approval_grants
from local_controller_harness import LocalContractCase

LOOKUP_INPUT = {"page": 1, "per_page": 25}
LOOKUP_RESULT = {
    "zones": [],
    "pagination": {"page": 1, "per_page": 25, "count": 0, "total_count": 0, "total_pages": 0},
}
DNS_INPUT = {"zone_id": "a" * 32, "page": 1, "per_page": 25}
DNS_RESULT = {
    "records": [],
    "pagination": {"page": 1, "per_page": 25, "count": 0, "total_count": 0, "total_pages": 0},
}
TEST_SECRET_VALUES = {
    "service-token": "service-test-credential-123456789",
    "client-key": "client-key-test-credential-123456789",
    "client-secret": "client-secret-test-credential-123456789",
    "session-token": "session-token-test-credential-123456789",
    "session-secret": "session-secret-test-credential-123456789",
}
TEST_ACCOUNT_ACCESS_TOKEN = "-".join(("oauth", "access", "test", "token", "123456789"))
TEST_ACCOUNT_REFRESH_TOKEN = "-".join(("oauth", "refresh", "test", "token", "123456789"))
CURRENT_ASSISTANT_IMAGE = "ghcr.io/theshimpz/shimpz-space@sha256:" + "b" * 64
OUTDATED_ASSISTANT_IMAGE = "ghcr.io/theshimpz/shimpz-space@sha256:" + "a" * 64


class LocalChatControlTests(LocalContractCase):
    def test_once_approval_is_remembered_for_one_team_assistant_power_release_and_can_be_revoked(self) -> None:
        class Runtime:
            def __init__(self) -> None:
                self.turn = 0

            def start(self, _context, _message):
                self.turn += 1
                request = brain_runtime_client.PowerRequest(
                    interrupt_id=f"power-{self.turn}",
                    assistant_id="shimpz-cloudflare",
                    power="list-zones",
                    input=LOOKUP_INPUT,
                )
                return brain_runtime_client.RuntimeTurn(status="power-required", reply="", powers=(request,))

            def resume(self, _context, _results):
                return brain_runtime_client.RuntimeTurn(status="completed", reply="Published.", powers=())

        with tempfile.TemporaryDirectory() as directory:
            controller = self._chat_controller(directory, Runtime())
            answers: list[list[object]] = []

            def rpc(_container, _spec, _method, _path, envelope):
                answers.append(envelope["answers"])
                if not envelope["answers"]:
                    return local_app.power_execution.RpcSuspension(
                        {
                            "ordinal": 0,
                            "kind": "approval",
                            "request_type": "bool",
                            "title": "Publish zones",
                            "summary": "Publish the current zones?",
                            "docs": None,
                            "options": [],
                            "runs": "once",
                        }
                    )
                return LOOKUP_RESULT

            controller.assistant_lifecycle._rpc = rpc
            audit = mock.patch.object(local_app.local_audit, "record", return_value="trace")
            audit.start()
            self.addCleanup(audit.stop)

            first = controller.chat_turn_service.chat(
                "team_1",
                {"message": "First", "files": [], "assistant_ids": ["shimpz-cloudflare"]},
                "openai",
                "sk-test-0123456789",
            )
            self.assertEqual(first["requirements"][0]["approval"], "once")
            controller.chat_turn_service.submit_chat_approval(
                "team_1",
                {"challenge_id": first["challenge_id"], "approved": True},
                "openai",
                "sk-test-0123456789",
            )
            second = controller.chat_turn_service.chat(
                "team_1",
                {"message": "Second", "files": [], "assistant_ids": ["shimpz-cloudflare"]},
                "openai",
                "sk-test-0123456789",
            )
            controller.approval_grants.grant_many(
                (
                    assistant_approval_grants.Grant(
                        "team_1",
                        "shimpz-cloudflare",
                        "list-zones",
                        CURRENT_ASSISTANT_IMAGE,
                        1,
                    ),
                )
            )
            inventory = controller.chat_turn_service.list_assistant_approval_grants("team_1")
            revoked = controller.chat_turn_service.revoke_assistant_approval_grants("team_1")
            third = controller.chat_turn_service.chat(
                "team_1",
                {"message": "Third", "files": [], "assistant_ids": ["shimpz-cloudflare"]},
                "openai",
                "sk-test-0123456789",
            )

        self.assertEqual(second["reply"], "Published.")
        self.assertEqual(answers, [[], [True], [], [True], []])
        self.assertEqual(
            inventory,
            {
                "team_id": "team_1",
                "grants": [{"assistant_id": "shimpz-cloudflare", "power_id": "list-zones"}],
            },
        )
        self.assertEqual(revoked, {"team_id": "team_1", "revoked": 2})
        self.assertEqual(third["status"], "approval-required")

    def test_secret_continuation_can_pause_for_approval_before_any_power_runs(self) -> None:
        request = brain_runtime_client.PowerRequest(
            interrupt_id="create-1",
            assistant_id="shimpz-cloudflare",
            power="list-zones",
            input=LOOKUP_INPUT,
        )

        class Runtime:
            def start(self, _context, _message):
                return brain_runtime_client.RuntimeTurn(status="power-required", reply="", powers=(request,))

            def resume(self, _context, results):
                self.results = dict(results)
                return brain_runtime_client.RuntimeTurn(status="completed", reply="Published.", powers=())

        runtime = Runtime()
        with tempfile.TemporaryDirectory() as directory:
            controller = self._chat_controller(directory, runtime, configure_secrets=False)
            answers: list[list[object]] = []

            def rpc(_container, _spec, _method, _path, envelope):
                answers.append(envelope["answers"])
                if not envelope["answers"]:
                    return local_app.power_execution.RpcSuspension(
                        {
                            "ordinal": 0,
                            "kind": "approval",
                            "request_type": "bool",
                            "title": "Publish zones",
                            "summary": "Publish the current zones?",
                            "docs": None,
                            "options": [],
                            "runs": "always",
                        }
                    )
                return LOOKUP_RESULT

            controller.assistant_lifecycle._rpc = rpc
            audit = mock.patch.object(local_app.local_audit, "record", return_value="trace")
            audit.start()
            self.addCleanup(audit.stop)
            secret_challenge = controller.chat_turn_service.chat(
                "team_1",
                {"message": "Publish", "files": [], "assistant_ids": ["shimpz-cloudflare"]},
                "openai",
                "sk-test-0123456789",
            )
            approval_challenge = controller.chat_turn_service.submit_chat_secrets(
                "team_1",
                self._secret_submission(secret_challenge),
                "openai",
                "sk-test-0123456789",
            )
            self.assertEqual(approval_challenge["status"], "approval-required")
            self.assertEqual(approval_challenge["requirements"][0]["title"], "Publish zones")
            response = controller.chat_turn_service.submit_chat_approval(
                "team_1",
                {"challenge_id": approval_challenge["challenge_id"], "approved": True},
                "openai",
                "sk-test-0123456789",
            )

        self.assertEqual(response["reply"], "Published.")
        self.assertEqual(answers, [[], [True]])
        self.assertEqual(runtime.results, {"create-1": LOOKUP_RESULT})

    def test_approval_challenge_transfers_to_a_cancellable_active_turn_without_a_gap(self) -> None:
        request = brain_runtime_client.PowerRequest(
            interrupt_id="power-1",
            assistant_id="shimpz-cloudflare",
            power="list-zones",
            input=LOOKUP_INPUT,
        )

        class Runtime:
            def start(self, _context, _message):
                return brain_runtime_client.RuntimeTurn(status="power-required", reply="", powers=(request,))

            def resume(self, _context, _results):
                raise AssertionError("a cancelled approval must never resume")

        with tempfile.TemporaryDirectory() as directory:
            controller = self._chat_controller(directory, Runtime())
            controller.assistant_lifecycle._rpc = lambda *_args: local_app.power_execution.RpcSuspension(
                {
                    "ordinal": 0,
                    "kind": "approval",
                    "request_type": "bool",
                    "title": "Publish zones",
                    "summary": "Publish the current zones?",
                    "docs": None,
                    "options": [],
                    "runs": "always",
                }
            )
            audit = mock.patch.object(local_app.local_audit, "record", return_value="trace")
            audit.start()
            self.addCleanup(audit.stop)
            challenge = controller.chat_turn_service.chat(
                "team_1",
                {"message": "Publish", "files": [], "assistant_ids": ["shimpz-cloudflare"]},
                "openai",
                "sk-test-0123456789",
            )
            claiming = threading.Event()
            release = threading.Event()
            original_claim = controller.approval_challenges.claim

            def blocked_claim(team_id, challenge_id):
                claiming.set()
                if not release.wait(timeout=2):
                    raise AssertionError("test did not release approval claim")
                return original_claim(team_id, challenge_id)

            failures: list[BaseException] = []

            def submit() -> None:
                try:
                    controller.chat_turn_service.submit_chat_approval(
                        "team_1",
                        {"challenge_id": challenge["challenge_id"], "approved": True},
                        "openai",
                        "sk-test-0123456789",
                    )
                except local_app.ApiProblem as exc:
                    failures.append(exc)

            with mock.patch.object(controller.approval_challenges, "claim", side_effect=blocked_claim):
                thread = threading.Thread(target=submit)
                thread.start()
                self.assertTrue(claiming.wait(timeout=2))
                repeated = controller.chat_turn_service.chat(
                    "team_1",
                    {"message": "Different turn", "files": [], "assistant_ids": ["shimpz-cloudflare"]},
                    "openai",
                    "sk-test-0123456789",
                )
                self.assertEqual(repeated["challenge_id"], challenge["challenge_id"])
                stopped = controller.chat_turn_service.stop_chat("team_1")
                release.set()
                thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertTrue(stopped["accepted"])
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], local_app.ApiProblem)
        self.assertIn(failures[0].code, {"assistant-approval-challenge-expired", "chat-stopped"})

    def test_stop_discards_a_runtime_reply_that_finishes_late(self) -> None:
        started = threading.Event()
        release = threading.Event()

        class Runtime:
            def start(self, _context, _message):
                started.set()
                if not release.wait(timeout=2):
                    raise AssertionError("test did not release runtime")
                return brain_runtime_client.RuntimeTurn(status="completed", reply="must be discarded", powers=())

        with tempfile.TemporaryDirectory() as directory:
            controller = self._chat_controller(directory, Runtime())
            failures: list[BaseException] = []

            def turn() -> None:
                try:
                    controller.chat_turn_service.chat(
                        "team_1",
                        {"message": "Wait", "files": [], "assistant_ids": ["shimpz-cloudflare"]},
                        "openai",
                        "sk-test-0123456789",
                    )
                except local_app.ApiProblem as exc:
                    failures.append(exc)

            worker = threading.Thread(target=turn)
            worker.start()
            self.assertTrue(started.wait(timeout=1))
            stopped = controller.chat_turn_service.stop_chat("team_1")
            release.set()
            worker.join(timeout=2)

        self.assertFalse(worker.is_alive())
        self.assertTrue(stopped["accepted"])
        self.assertFalse(stopped["confirmed"])
        self.assertEqual(len(failures), 1)
        self.assertIsInstance(failures[0], local_app.ApiProblem)
        self.assertEqual(failures[0].code, "chat-stopped")
