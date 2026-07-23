from __future__ import annotations

import json
import stat
import sys
import tempfile
import unittest
from pathlib import Path

TEAM = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TEAM))

import local_chat_continuation_store


class EncryptedContinuationStoreTests(unittest.TestCase):
    @staticmethod
    def _paths(directory: str) -> tuple[Path, Path]:
        root = Path(directory)
        return (
            root / "continuations" / "state" / "continuations.json",
            root / "continuations" / "key" / "aes256.key",
        )

    def test_round_trip_survives_reopen_without_plaintext_answers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_path, key_path = self._paths(directory)
            payload = b'{"answers":["private human answer"],"turn":"paused"}'
            store = local_chat_continuation_store.EncryptedContinuationStore(
                state_path,
                key_path,
                now=lambda: 1_000,
            )
            saved = store.put(
                "team_1",
                "input",
                "a" * 32,
                1_300,
                ("assistant/power/image@sha256:" + "b" * 64 + "/0",),
                payload,
            )
            reopened = local_chat_continuation_store.EncryptedContinuationStore(
                state_path,
                key_path,
                now=lambda: 1_001,
            )

            self.assertEqual(reopened.current("team_1"), saved)
            self.assertNotIn(b"private human answer", state_path.read_bytes())
            self.assertEqual(stat.S_IMODE(state_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(state_path.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(key_path.parent.stat().st_mode), 0o700)

    def test_generation_and_aad_bind_every_routing_dimension(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_path, key_path = self._paths(directory)
            store = local_chat_continuation_store.EncryptedContinuationStore(
                state_path,
                key_path,
                now=lambda: 2_000,
            )
            first = store.put(
                "team_1",
                "approval",
                "b" * 32,
                2_300,
                ("assistant/power/release/0",),
                b'{"answer":true}',
            )
            second = store.put(
                "team_1",
                "approval",
                "c" * 32,
                2_300,
                ("assistant/power/release/1",),
                b'{"answer":true}',
            )
            self.assertEqual((first.generation, second.generation), (1, 2))

            state = json.loads(state_path.read_text(encoding="ascii"))
            state["records"]["team_1"]["challenge_id"] = "d" * 32
            state_path.write_text(
                json.dumps(state, sort_keys=True, separators=(",", ":")),
                encoding="ascii",
            )
            state_path.chmod(0o600)
            with self.assertRaisesRegex(
                local_chat_continuation_store.ContinuationStoreError,
                "authentication failed",
            ):
                store.current("team_1")

    def test_expiry_and_exact_delete_are_fail_closed(self) -> None:
        clock = [3_000]
        with tempfile.TemporaryDirectory() as directory:
            state_path, key_path = self._paths(directory)
            store = local_chat_continuation_store.EncryptedContinuationStore(
                state_path,
                key_path,
                now=lambda: clock[0],
            )
            store.put(
                "team_1",
                "secrets",
                "e" * 32,
                3_001,
                ("assistant/power/release/0",),
                b"{}",
            )
            with self.assertRaises(local_chat_continuation_store.ContinuationNotFoundError):
                store.delete("team_1", "f" * 32)
            clock[0] = 3_001
            self.assertIsNone(store.current("team_1"))
            self.assertFalse(store.delete("team_1"))

    def test_rejects_unsafe_paths_capacity_and_oversized_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            state_path, key_path = self._paths(directory)
            with self.assertRaises(local_chat_continuation_store.ContinuationStoreError):
                local_chat_continuation_store.EncryptedContinuationStore(
                    Path("relative-state"),
                    key_path,
                )
            with self.assertRaises(local_chat_continuation_store.ContinuationStoreError):
                local_chat_continuation_store.EncryptedContinuationStore(
                    state_path,
                    state_path.with_name("key"),
                )
            store = local_chat_continuation_store.EncryptedContinuationStore(
                state_path,
                key_path,
                now=lambda: 4_000,
                capacity=1,
            )
            store.put(
                "team_1",
                "accounts",
                "1" * 32,
                4_300,
                ("assistant/power/release/0",),
                b"{}",
            )
            with self.assertRaisesRegex(
                local_chat_continuation_store.ContinuationStoreError,
                "capacity",
            ):
                store.put(
                    "team_2",
                    "accounts",
                    "2" * 32,
                    4_300,
                    ("assistant/power/release/0",),
                    b"{}",
                )
            with self.assertRaises(local_chat_continuation_store.ContinuationStoreError):
                store.put(
                    "team_1",
                    "input",
                    "3" * 32,
                    4_300,
                    ("assistant/power/release/0",),
                    b"x" * (local_chat_continuation_store.MAX_PLAINTEXT_BYTES + 1),
                )


if __name__ == "__main__":
    unittest.main()
