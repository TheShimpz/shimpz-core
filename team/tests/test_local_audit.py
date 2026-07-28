"""Durability and metadata contracts for the local audit journal."""

from __future__ import annotations

import json
import multiprocessing
import os
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from local_support import audit


def _crash_after_acknowledged_audit(path: str, sync_marker: str) -> None:
    audit.AUDIT_PATH = Path(path)
    audit.GROUP_COMMIT_MAX_SECONDS = 60
    real_fsync = os.fsync

    def mark_sync(descriptor: int) -> None:
        real_fsync(descriptor)
        Path(sync_marker).write_text("synced", encoding="ascii")

    audit.os.fsync = mark_sync
    audit.record("assistant-power", result="ok", team_id="team_1")
    os._exit(0)


class LocalAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        audit.close()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.addCleanup(audit.close)
        self.path = Path(self.temporary.name) / "audit" / "audit.jsonl"

    def test_acknowledged_event_survives_process_crash_before_group_sync(self) -> None:
        marker = Path(self.temporary.name) / "sync-marker"
        process = multiprocessing.get_context("spawn").Process(
            target=_crash_after_acknowledged_audit,
            args=(str(self.path), str(marker)),
        )

        process.start()
        process.join(timeout=10)

        self.assertEqual(process.exitcode, 0)
        self.assertFalse(marker.exists())
        event = json.loads(self.path.read_bytes())
        self.assertEqual(event["operation"], "assistant-power")
        self.assertEqual(event["team_id"], "team_1")

    def test_multiple_events_share_one_durability_sync(self) -> None:
        with (
            mock.patch.object(audit, "AUDIT_PATH", self.path),
            mock.patch.object(audit, "GROUP_COMMIT_MAX_SECONDS", 60),
            mock.patch.object(audit.os, "fsync", wraps=os.fsync) as sync,
        ):
            audit.record("first", result="ok")
            audit.record("second", result="ok")
            self.assertEqual(sync.call_count, 0)
            audit.flush()

        self.assertEqual(sync.call_count, 1)

    def test_background_sync_bounds_the_acknowledged_loss_window(self) -> None:
        synchronized = threading.Event()
        real_fsync = os.fsync
        synchronized_at: list[float] = []

        def observe(descriptor: int) -> None:
            real_fsync(descriptor)
            synchronized_at.append(time.monotonic())
            synchronized.set()

        window = 0.02
        with (
            mock.patch.object(audit, "AUDIT_PATH", self.path),
            mock.patch.object(audit, "GROUP_COMMIT_MAX_SECONDS", window),
            mock.patch.object(audit.os, "fsync", side_effect=observe) as sync,
        ):
            started = time.monotonic()
            audit.record("first", result="ok")
            audit.record("second", result="ok")
            self.assertTrue(synchronized.wait(timeout=1))
            elapsed = time.monotonic() - started

        self.assertLess(elapsed, window * 5)
        self.assertLess(synchronized_at[0] - started, window * 5)
        self.assertEqual(sync.call_count, 1)

    def test_power_loss_model_limits_loss_to_the_current_unsynced_group(self) -> None:
        durable_snapshot = b""
        real_fsync = os.fsync

        def checkpoint(descriptor: int) -> None:
            nonlocal durable_snapshot
            real_fsync(descriptor)
            durable_snapshot = self.path.read_bytes()

        with (
            mock.patch.object(audit, "AUDIT_PATH", self.path),
            mock.patch.object(audit, "GROUP_COMMIT_MAX_SECONDS", 60),
            mock.patch.object(audit.os, "fsync", side_effect=checkpoint),
        ):
            for index in range(8):
                audit.record("burst", result="ok", detail=str(index))
            self.assertEqual(durable_snapshot, b"")
            audit.flush()
            self.assertEqual(len(durable_snapshot.splitlines()), 8)
            audit.record("next-group", result="ok")
            simulated_recovery = durable_snapshot

        self.assertEqual(len(simulated_recovery.splitlines()), 8)

    def test_concurrent_records_are_complete_and_share_the_writer(self) -> None:
        with (
            mock.patch.object(audit, "AUDIT_PATH", self.path),
            mock.patch.object(audit, "GROUP_COMMIT_MAX_SECONDS", 60),
            ThreadPoolExecutor(max_workers=8) as executor,
        ):
            trace_ids = tuple(
                executor.map(
                    lambda index: audit.record("concurrent", result="ok", detail=str(index)),
                    range(64),
                )
            )
            audit.flush()

        events = tuple(json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines())
        self.assertEqual(len(events), 64)
        self.assertEqual({event["trace_id"] for event in events}, set(trace_ids))


if __name__ == "__main__":
    unittest.main()
