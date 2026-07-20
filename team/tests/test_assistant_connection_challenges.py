from __future__ import annotations

import unittest
from unittest import mock

import assistant_connection_challenges


def requirement() -> assistant_connection_challenges.ConnectionRequirement:
    return assistant_connection_challenges.ConnectionRequirement(
        assistant_id="shimpz-assistant",
        assistant_name="Shimpz Assistant",
        power_ids=("create-post", "identity-me"),
        connections=(
            (
                "x",
                "x",
                ("offline.access", "tweet.read", "tweet.write", "users.read"),
            ),
        ),
    )


class AssistantConnectionChallengeTests(unittest.TestCase):
    def test_challenge_is_team_bound_single_use_and_keeps_payload_private(self) -> None:
        store = assistant_connection_challenges.ConnectionChallengeStore()
        private = {"continuation": "private user input"}
        challenge = store.create("team_1", (requirement(),), private)

        self.assertNotIn("private user input", repr(store._by_team))
        with self.assertRaises(assistant_connection_challenges.ConnectionChallengeNotFoundError):
            store.get("team_2", challenge.id)
        claimed = store.claim("team_1", challenge.id)
        self.assertIs(claimed.payload, private)
        with self.assertRaises(assistant_connection_challenges.ConnectionChallengeNotFoundError):
            store.claim("team_1", challenge.id)

    def test_one_pending_turn_per_team_and_global_capacity_fail_closed(self) -> None:
        store = assistant_connection_challenges.ConnectionChallengeStore(capacity=2)
        store.create("team_1", (requirement(),), object())
        with self.assertRaisesRegex(
            assistant_connection_challenges.ConnectionChallengeError,
            "already",
        ):
            store.create("team_1", (requirement(),), object())
        store.create("team_2", (requirement(),), object())
        with self.assertRaisesRegex(
            assistant_connection_challenges.ConnectionChallengeError,
            "capacity",
        ):
            store.create("team_3", (requirement(),), object())

    def test_expiry_cancel_and_invalid_identifiers_remove_no_other_team(self) -> None:
        store = assistant_connection_challenges.ConnectionChallengeStore(ttl_seconds=30)
        with mock.patch.object(assistant_connection_challenges.time, "monotonic", return_value=1.0):
            expired = store.create("team_1", (requirement(),), object())
        with (
            mock.patch.object(assistant_connection_challenges.time, "monotonic", return_value=31.0),
            self.assertRaises(assistant_connection_challenges.ConnectionChallengeNotFoundError),
        ):
            store.get("team_1", expired.id)

        active = store.create("team_2", (requirement(),), object())
        for team, identifier in (("../team", active.id), ("team_2", "not-a-challenge")):
            with self.subTest(team=team, identifier=identifier), self.assertRaises(RuntimeError):
                store.get(team, identifier)
        self.assertTrue(store.cancel_team("team_2"))
        self.assertFalse(store.cancel_team("team_2"))
        self.assertEqual(store.cancel_all(), 0)

    def test_empty_requirements_and_invalid_limits_are_rejected(self) -> None:
        with self.assertRaises(assistant_connection_challenges.ConnectionChallengeError):
            assistant_connection_challenges.ConnectionChallengeStore().create("team_1", (), object())
        for options in (
            {"capacity": 0},
            {"capacity": True},
            {"ttl_seconds": 29},
            {"ttl_seconds": 901},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                assistant_connection_challenges.ConnectionChallengeStore(**options)


if __name__ == "__main__":
    unittest.main()
