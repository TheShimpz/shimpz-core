from __future__ import annotations

import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

TEAM = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TEAM))

import assistant_secret_challenges
import assistant_secret_flow
import assistant_secret_store
import brain_runtime_client
from local_registry import AssistantSpec, PowerSpec, SecretSpec


def _spec() -> AssistantSpec:
    return AssistantSpec(
        assistant_id="x-assistant",
        name="X Assistant",
        summary="test",
        image="example.invalid/x@sha256:" + ("a" * 64),
        rpc_command="/app/rpc",
        health_path="/healthz",
        powers={
            "read": PowerSpec("POST", "/read", "read", {}, {}, "none", ("bearer",)),
            "write": PowerSpec("POST", "/write", "write", {}, {}, "none", ("key", "secret")),
        },
        secrets={
            "bearer": SecretSpec("Bearer", "Read access"),
            "key": SecretSpec("Key", "Write key"),
            "secret": SecretSpec("Secret", "Write secret"),
        },
        allowed_hosts=("api.x.com",),
    )


@dataclass(frozen=True)
class _Active:
    spec: AssistantSpec


class AssistantSecretFlowTests(unittest.TestCase):
    def _store(self, root: Path) -> assistant_secret_store.AssistantSecretStore:
        return assistant_secret_store.AssistantSecretStore(
            root / "state" / "secrets.json",
            root / "key" / "aes256.key",
        )

    @staticmethod
    def _request(power: str, interrupt_id: str) -> brain_runtime_client.PowerRequest:
        return brain_runtime_client.PowerRequest(interrupt_id, "x-assistant", power, {}, "none")

    def test_batch_collects_all_missing_secrets_before_any_power(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(Path(directory))
            store.put_many("team_1", "x-assistant", {"bearer": "already-set"})
            requirements = assistant_secret_flow.requirements_for_batch(
                "team_1",
                {"x-assistant": _Active(_spec())},
                (self._request("read", "one"), self._request("write", "two")),
                store,
            )
            self.assertEqual(len(requirements), 1)
            self.assertEqual(requirements[0].power_ids, ("write",))
            self.assertEqual(
                requirements[0].secrets,
                (("key", "Key", "Write key"), ("secret", "Secret", "Write secret")),
            )

    def test_submission_rejects_partial_extra_and_duplicate_values(self) -> None:
        requirement = assistant_secret_challenges.SecretRequirement(
            "x-assistant",
            "X Assistant",
            ("write",),
            (("key", "Key", "Write key"), ("secret", "Secret", "Write secret")),
        )
        challenge = assistant_secret_challenges.PendingSecretChallenge(
            "a" * 32,
            "team_1",
            1.0,
            (requirement,),
            object(),
        )
        valid = {
            "challenge_id": "a" * 32,
            "values": [
                {"assistant_id": "x-assistant", "secret_id": "key", "value": "alpha"},
                {"assistant_id": "x-assistant", "secret_id": "secret", "value": "bravo"},
            ],
        }
        self.assertEqual(
            assistant_secret_flow.submission_values(challenge, valid),
            {"x-assistant": {"key": "alpha", "secret": "bravo"}},
        )
        for invalid in (
            {**valid, "values": valid["values"][:1]},
            {
                **valid,
                "values": valid["values"]
                + [{"assistant_id": "x-assistant", "secret_id": "extra", "value": "charlie"}],
            },
            {**valid, "values": [valid["values"][0], valid["values"][0]]},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(assistant_secret_flow.SecretFlowError):
                assistant_secret_flow.submission_values(challenge, invalid)

    def test_inventory_never_returns_secret_values_or_generations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(Path(directory))
            raw = "private-material-123456789"
            store.put_many("team_1", "x-assistant", {"bearer": raw})
            payload = assistant_secret_flow.inventory_payload("team_1", [_spec()], store)
            encoded = repr(payload)
            self.assertNotIn(raw, encoded)
            self.assertNotIn("generation", encoded)
            self.assertEqual(payload["assistants"][0]["secrets"][0]["mask"], "pr…89")


if __name__ == "__main__":
    unittest.main()
