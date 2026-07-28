from __future__ import annotations

import sys
import unittest
from pathlib import Path

TEAM = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TEAM))

from assistant_human import assistant_account_challenges
from controller_runtime import (
    brain_runtime_client,
    chat_orchestrator,
    inference_config,
    local_chat_continuation_store,
    local_chat_continuations,
)

IMAGE = "registry.example/assistant@sha256:" + "b" * 64
TURN = brain_runtime_client.RuntimeTurn(
    status="power-required",
    reply="",
    powers=(
        brain_runtime_client.PowerRequest(
            interrupt_id="power-1",
            assistant_id="demo-assistant",
            power="publish",
            input={"message": "private Power input"},
        ),
    ),
)


def pending() -> local_chat_continuations.PendingLocalChat:
    return local_chat_continuations.PendingLocalChat(
        continuation=chat_orchestrator.ChatContinuation(
            turn=TURN,
            seen_interrupts=("older-power",),
            invoked=(chat_orchestrator.InvokedPower("demo-assistant", "lookup"),),
            round_index=1,
        ),
        assistant_ids=("demo-assistant",),
        file_ids=("a" * 32,),
        provider="openai",
        identity=(
            "Demo Team",
            "network-id",
            (("demo-assistant", IMAGE, "container-id"),),
            [
                {
                    "id": "a" * 32,
                    "name": "brief.txt",
                    "media_type": "text/plain",
                    "size": 42,
                }
            ],
            inference_config.normalize("openai", "gpt-5.5"),
        ),
    )


class LocalChatContinuationCodecTests(unittest.TestCase):
    def _round_trip(self, kind: str, requirements: tuple[object, ...]) -> None:
        bindings, payload = local_chat_continuations.encode(kind, requirements, pending())
        stored = local_chat_continuation_store.StoredContinuation(
            "team_1",
            kind,
            "c" * 32,
            1_300,
            1,
            bindings,
            payload,
        )
        decoded = local_chat_continuations.decode(stored)
        self.assertEqual(decoded.kind, kind)
        self.assertEqual(decoded.requirements, requirements)
        self.assertEqual(decoded.pending, pending())

    def test_round_trips_the_account_suspension(self) -> None:
        requirements = (
            assistant_account_challenges.AccountRequirement(
                "demo-assistant",
                "Demo Assistant",
                ("publish",),
                (("cloudflare", "cloudflare", ("dns.read", "zone.read")),),
            ),
        )
        self._round_trip("accounts", requirements)

    def test_rejects_release_binding_and_decrypted_shape_drift(self) -> None:
        requirement = (
            assistant_account_challenges.AccountRequirement(
                "demo-assistant",
                "Demo Assistant",
                ("publish",),
                (("cloudflare", "cloudflare", ("dns.read", "zone.read")),),
            ),
        )
        bindings, payload = local_chat_continuations.encode("accounts", requirement, pending())
        drifted = local_chat_continuation_store.StoredContinuation(
            "team_1",
            "accounts",
            "c" * 32,
            1_300,
            1,
            ("demo-assistant/publish/" + IMAGE + "/changed",),
            payload,
        )
        with self.assertRaisesRegex(
            local_chat_continuations.ContinuationCodecError,
            "binding changed",
        ):
            local_chat_continuations.decode(drifted)

        malformed = local_chat_continuation_store.StoredContinuation(
            "team_1",
            "accounts",
            "c" * 32,
            1_300,
            1,
            bindings,
            b'{"schema":1,"kind":"accounts","requirements":[],"pending":{}}',
        )
        with self.assertRaises(local_chat_continuations.ContinuationCodecError):
            local_chat_continuations.decode(malformed)


if __name__ == "__main__":
    unittest.main()
