"""Durability and metadata contracts for the local audit journal."""

from __future__ import annotations

import json
import multiprocessing
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from local_support import audit


def _crash_after_acknowledged_audit(path: str, sync_marker: str) -> None:
    audit.AUDIT_PATH = Path(path)
    real_fsync = os.fsync

    def mark_sync(descriptor: int) -> None:
        real_fsync(descriptor)
        Path(sync_marker).write_text("synced", encoding="ascii")

    audit.os.fsync = mark_sync
    audit.record("assistant-power", result="ok", team_id="team_1")
    os._exit(0)


class LocalAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "audit" / "audit.jsonl"

    def test_acknowledged_event_is_fsynced_before_process_crash(self) -> None:
        marker = Path(self.temporary.name) / "sync-marker"
        process = multiprocessing.get_context("spawn").Process(
            target=_crash_after_acknowledged_audit,
            args=(str(self.path), str(marker)),
        )

        process.start()
        process.join(timeout=10)

        self.assertEqual(process.exitcode, 0)
        self.assertEqual(marker.read_text(encoding="ascii"), "synced")
        event = json.loads(self.path.read_bytes())
        self.assertEqual(event["operation"], "assistant-power")
        self.assertEqual(event["team_id"], "team_1")

    def test_each_event_has_its_own_durability_sync(self) -> None:
        with (
            mock.patch.object(audit, "AUDIT_PATH", self.path),
            mock.patch.object(audit.os, "fsync", wraps=os.fsync) as sync,
        ):
            audit.record("first", result="ok")
            audit.record("second", result="ok")

        self.assertEqual(sync.call_count, 2)


if __name__ == "__main__":
    unittest.main()
