"""Contract tests for durable dynamic Assistant bindings."""

from __future__ import annotations

import copy
import json
import stat
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

import dynamic_assistants
from developers_controller_contract import CONTRACT_ROOT
from dynamic_assistants import (
    DynamicAssistantConflictError,
    DynamicAssistantError,
    DynamicAssistantStore,
    app_spec,
)

VECTORS = json.loads((CONTRACT_ROOT / "vectors.json").read_bytes())
RESOLUTION = VECTORS["fixtures"]["resolve_response"]["value"]


def runtime_resolution() -> dict[str, object]:
    resolution = copy.deepcopy(RESOLUTION)
    power = resolution["machine_contract"]["powers"][0]
    power["input_schema"]["additionalProperties"] = False
    power["output_schema"]["additionalProperties"] = False
    return resolution


class DynamicAssistantStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "bindings.json"
        self.store = DynamicAssistantStore(self.path)
        dynamic_assistants._cached_app_spec.cache_clear()

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
        self.assertEqual(self.store.snapshot(), (first, other_team))
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

    def test_resolution_builds_a_digest_bound_assistant_spec(self) -> None:
        binding = self.store.put("team_1", runtime_resolution())

        spec = app_spec(binding)

        self.assertEqual(spec.image, RESOLUTION["image_reference"])
        self.assertFalse(spec.db)
        self.assertFalse(spec.first_party)
        self.assertEqual(spec.archs, ("amd64", "arm64"))
        self.assertEqual(spec.allowed_hosts, ("api.cloudflare.com",))
        self.assertEqual(tuple(spec.assistant.powers), ("hello",))
        self.assertEqual(
            spec.required_image_labels,
            (
                ("org.shimpz.assistant.id", "hello-world"),
                ("org.shimpz.source.digest", RESOLUTION["source_digest"]),
            ),
        )

    def test_unchanged_digest_reuses_validation_without_aliasing_results(self) -> None:
        binding = self.store.put("team_1", runtime_resolution())
        validator = dynamic_assistants.assistant_manifest.canonical_machine_contract

        with mock.patch.object(
            dynamic_assistants.assistant_manifest,
            "canonical_machine_contract",
            wraps=validator,
        ) as canonical:
            first = app_spec(binding)
            second = app_spec(binding)

        self.assertEqual(canonical.call_count, 1)
        self.assertEqual(first, second)
        self.assertIsNot(first, second)
        first.assistant.powers.pop("hello")
        self.assertIn("hello", app_spec(binding).assistant.powers)

    def test_registry_readers_share_the_file_lock(self) -> None:
        expected = self.store.put("team_1", runtime_resolution())
        original_read = self.store._read
        readers_entered = threading.Barrier(2)

        def overlapping_read():
            readers_entered.wait(timeout=2)
            return original_read()

        with (
            mock.patch.object(self.store, "_read", side_effect=overlapping_read),
            ThreadPoolExecutor(max_workers=2) as executor,
        ):
            results = tuple(executor.map(lambda _index: self.store.get("team_1", "hello-world"), range(2)))

        self.assertEqual(results, (expected, expected))

    def test_registry_writer_waits_for_shared_reader(self) -> None:
        self.store.put("team_1", runtime_resolution())
        reader_entered = threading.Event()
        release_reader = threading.Event()
        writer_read = threading.Event()
        original_read = self.store._read

        def hold_reader() -> None:
            with self.store._shared_lock():
                reader_entered.set()
                release_reader.wait(timeout=2)

        def observe_writer_read():
            writer_read.set()
            return original_read()

        with ThreadPoolExecutor(max_workers=2) as executor:
            reader = executor.submit(hold_reader)
            self.assertTrue(reader_entered.wait(timeout=1))
            with mock.patch.object(self.store, "_read", side_effect=observe_writer_read):
                writer = executor.submit(self.store.delete, "team_1", "hello-world")
                self.assertFalse(writer_read.wait(timeout=0.1))
                release_reader.set()
                reader.result(timeout=1)
                self.assertTrue(writer.result(timeout=1))

    def test_noncanonical_machine_contract_fails_closed(self) -> None:
        binding = self.store.put("team_1", copy.deepcopy(RESOLUTION))

        with self.assertRaises(DynamicAssistantError):
            app_spec(binding)


if __name__ == "__main__":
    unittest.main()
