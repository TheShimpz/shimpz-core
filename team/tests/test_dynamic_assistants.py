"""Contract tests for durable dynamic Assistant bindings."""

from __future__ import annotations

import copy
import json
import stat
import tempfile
import unittest
from pathlib import Path

from developers_controller_contract import CONTRACT_ROOT
from dynamic_assistants import (
    DynamicAssistantConflictError,
    DynamicAssistantError,
    DynamicAssistantStore,
)

VECTORS = json.loads((CONTRACT_ROOT / "vectors.json").read_bytes())
RESOLUTION = VECTORS["fixtures"]["resolve_response"]["value"]


class DynamicAssistantStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "bindings.json"
        self.store = DynamicAssistantStore(self.path)

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_binding_is_durable_scoped_and_digest_stable(self) -> None:
        first = self.store.put("team_1", copy.deepcopy(RESOLUTION))
        repeated = self.store.put("team_1", copy.deepcopy(RESOLUTION))
        other_team = self.store.put("team_2", copy.deepcopy(RESOLUTION))

        self.assertEqual(first, repeated)
        self.assertEqual(first.binding_digest, repeated.binding_digest)
        self.assertNotEqual(first.binding_digest, other_team.binding_digest)
        self.assertEqual(DynamicAssistantStore(self.path).get("team_1", "hello-world"), first)
        self.assertEqual(self.store.list("team_1"), (first,))
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_different_artifact_for_same_identity_requires_removal(self) -> None:
        self.store.put("team_1", copy.deepcopy(RESOLUTION))
        replacement = copy.deepcopy(RESOLUTION)
        replacement["source_digest"] = f"sha256:{'9' * 64}"

        with self.assertRaises(DynamicAssistantConflictError):
            self.store.put("team_1", replacement)

        self.assertTrue(self.store.delete("team_1", "hello-world"))
        self.assertFalse(self.store.delete("team_1", "hello-world"))
        self.assertEqual(self.store.list("team_1"), ())

    def test_rejects_invalid_resolution_before_writing(self) -> None:
        invalid = copy.deepcopy(RESOLUTION)
        invalid["image_reference"] = "ghcr.io/attacker/assistant@sha256:" + "b" * 64

        with self.assertRaises(DynamicAssistantError):
            self.store.put("team_1", invalid)

        self.assertFalse(self.path.exists())

    def test_corruption_and_digest_tampering_fail_closed(self) -> None:
        self.path.write_text("{", encoding="ascii")
        with self.assertRaises(DynamicAssistantError):
            self.store.list("team_1")

        self.path.unlink()
        self.store.put("team_1", copy.deepcopy(RESOLUTION))
        document = json.loads(self.path.read_bytes())
        document["bindings"][0]["binding_digest"] = f"sha256:{'0' * 64}"
        self.path.write_text(json.dumps(document), encoding="ascii")
        with self.assertRaises(DynamicAssistantError):
            self.store.list("team_1")

    def test_identifiers_are_closed_ascii_contracts(self) -> None:
        for team_id in ("../team", "téam", ""):
            with self.subTest(team_id=team_id), self.assertRaises(DynamicAssistantError):
                self.store.list(team_id)
        for assistant_id in ("Hello", "../hello", "héllo"):
            with self.subTest(assistant_id=assistant_id), self.assertRaises(DynamicAssistantError):
                self.store.get("team_1", assistant_id)


if __name__ == "__main__":
    unittest.main()
