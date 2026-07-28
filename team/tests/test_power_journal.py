from __future__ import annotations

import hashlib
import multiprocessing
import os
import shutil
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from controller_runtime import power_journal


def operation(interrupt_id: str, value: str) -> power_journal.Operation:
    return power_journal.Operation(interrupt_id, hashlib.sha256(value.encode()).hexdigest())


def _crash_after_acknowledged_transition(path: str, phase: str) -> None:
    journal = power_journal.PowerJournal(Path(path))
    selected = operation("interrupt-1", "validated-input-1")
    batch = journal.prepare_batch("generation-1", "thread-1", [selected])
    if phase in {"executing", "completed", "delivered"}:
        journal.begin(batch, selected)
    if phase in {"completed", "delivered"}:
        journal.complete(batch, selected, {"answer": 1})
    if phase == "delivered":
        journal.delivered(batch)
    os._exit(0)


class PowerJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "private" / "journal.sqlite3"
        self.first = operation("interrupt-1", "validated-input-1")
        self.second = operation("interrupt-2", "validated-input-2")

    def journal(self, **limits: int) -> power_journal.PowerJournal:
        journal = power_journal.PowerJournal(self.path, **limits)
        self.addCleanup(journal.close)
        return journal

    def test_reopen_returns_canonical_cached_result_without_reexecution(self) -> None:
        journal = self.journal()
        batch = journal.prepare_batch("generation-1", "thread-1", [self.first])
        self.assertEqual(journal.begin(batch, self.first), power_journal.Execution(True, None))
        journal.complete(batch, self.first, {"z": [2, 1], "a": "ok"})
        journal.close()

        reopened = self.journal()
        same = reopened.prepare_batch("generation-1", "thread-1", [self.first])

        self.assertEqual(same, batch)
        self.assertEqual(
            reopened.begin(same, self.first),
            power_journal.Execution(False, {"a": "ok", "z": [2, 1]}),
        )
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_executing_operation_is_uncertain_after_reopen(self) -> None:
        journal = self.journal()
        batch = journal.prepare_batch("generation-1", "thread-1", [self.first])
        self.assertTrue(journal.begin(batch, self.first).execute)
        journal.close()

        reopened = self.journal()
        same = reopened.prepare_batch("generation-1", "thread-1", [self.first])
        with self.assertRaises(power_journal.PowerJournalUncertainError):
            reopened.begin(same, self.first)

    def test_process_crash_loses_no_acknowledged_transition(self) -> None:
        expected = {
            "prepared": ("prepared", None),
            "executing": ("executing", None),
            "completed": ("completed", b'{"answer":1}'),
            "delivered": None,
        }
        context = multiprocessing.get_context("spawn")
        for phase, persisted in expected.items():
            with self.subTest(phase=phase):
                path = Path(self.temporary.name) / phase / "journal.sqlite3"
                process = context.Process(
                    target=_crash_after_acknowledged_transition,
                    args=(str(path), phase),
                )
                process.start()
                process.join(timeout=10)
                self.assertEqual(process.exitcode, 0)

                reopened = power_journal.PowerJournal(path)
                self.addCleanup(reopened.close)
                row = reopened._connection.execute(
                    "SELECT state, result FROM operations WHERE generation = 'generation-1'"
                ).fetchone()
                self.assertEqual(row, persisted)

    def test_uses_bounded_wal_normal_durability_policy(self) -> None:
        journal = self.journal()

        self.assertEqual(journal._connection.execute("PRAGMA journal_mode").fetchone(), ("wal",))
        self.assertEqual(journal._connection.execute("PRAGMA synchronous").fetchone(), (1,))
        self.assertEqual(
            journal._connection.execute("PRAGMA wal_autocheckpoint").fetchone(),
            (power_journal.WAL_AUTOCHECKPOINT_PAGES,),
        )

    def test_power_loss_model_bounds_acknowledged_state_loss(self) -> None:
        journal = self.journal()
        operations = tuple(operation(f"interrupt-{index}", f"validated-input-{index}") for index in range(16))
        batch = journal.prepare_batch("generation-1", "thread-1", operations)
        self.assertEqual(
            journal._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone(),
            (0, 0, 0),
        )
        stable_checkpoint = Path(self.temporary.name) / "stable-checkpoint.sqlite3"
        shutil.copy2(self.path, stable_checkpoint)

        transitions = 0
        for selected in operations[:-1]:
            journal.begin(batch, selected)
            journal.complete(batch, selected, {"interrupt": selected.interrupt_id})
            transitions += 2
        final = operations[-1]
        journal.begin(batch, final)
        transitions += 1

        page_size = journal._connection.execute("PRAGMA page_size").fetchone()[0]
        wal_size = self.path.with_name(f"{self.path.name}-wal").stat().st_size
        frames = (wal_size - 32) // (page_size + 24)
        self.assertEqual(transitions, power_journal.MAX_ACKNOWLEDGED_TRANSITIONS_AT_RISK)
        self.assertEqual(frames, transitions)

        simulated_loss = Path(self.temporary.name) / "loss" / "journal.sqlite3"
        simulated_loss.parent.mkdir(mode=0o700)
        shutil.copy2(stable_checkpoint, simulated_loss)
        recovered_before_checkpoint = power_journal.PowerJournal(simulated_loss)
        self.addCleanup(recovered_before_checkpoint.close)
        states = recovered_before_checkpoint._connection.execute(
            "SELECT state FROM operations ORDER BY ordinal"
        ).fetchall()
        self.assertEqual(states, [("prepared",)] * len(operations))

        journal.complete(batch, final, {"interrupt": final.interrupt_id})
        after_checkpoint = Path(self.temporary.name) / "checkpointed" / "journal.sqlite3"
        after_checkpoint.parent.mkdir(mode=0o700)
        shutil.copy2(self.path, after_checkpoint)
        recovered_after_checkpoint = power_journal.PowerJournal(after_checkpoint)
        self.addCleanup(recovered_after_checkpoint.close)
        states = recovered_after_checkpoint._connection.execute(
            "SELECT state FROM operations ORDER BY ordinal"
        ).fetchall()
        self.assertEqual(states, [("completed",)] * len(operations))

    def test_changed_pending_batch_and_changed_completed_result_fail_closed(self) -> None:
        journal = self.journal()
        batch = journal.prepare_batch("generation-1", "thread-1", [self.first])

        with self.assertRaises(power_journal.PowerJournalConflictError):
            journal.prepare_batch("generation-1", "thread-1", [self.second])
        with self.assertRaises(power_journal.PowerJournalConflictError):
            journal.prepare_batch("generation-1", "other-thread", [self.first])

        journal.begin(batch, self.first)
        journal.complete(batch, self.first, {"answer": 1})
        journal.complete(batch, self.first, {"answer": 1})
        with self.assertRaises(power_journal.PowerJournalConflictError):
            journal.complete(batch, self.first, {"answer": 2})

    def test_batch_identity_is_scanned_once_before_point_transitions(self) -> None:
        journal = self.journal()
        operations = (
            self.first,
            self.second,
            operation("interrupt-3", "validated-input-3"),
        )
        batch = journal.prepare_batch("generation-1", "thread-1", operations)

        with mock.patch.object(journal, "_load_batch", wraps=journal._load_batch) as full_scan:
            for selected in operations:
                journal.begin(batch, selected)
                journal.complete(batch, selected, {"interrupt": selected.interrupt_id})
            self.assertEqual(full_scan.call_count, 1)
            journal.delivered(batch)

        self.assertEqual(full_scan.call_count, 2)
        self.assertEqual(journal._validated_batches, {})

    def test_point_transition_revalidates_persisted_batch_header(self) -> None:
        journal = self.journal()
        batch = journal.prepare_batch("generation-1", "thread-1", [self.first])
        journal.begin(batch, self.first)
        journal._connection.execute(
            "UPDATE batches SET fingerprint = ? WHERE generation = ?",
            ("f" * 64, batch.generation),
        )

        with self.assertRaises(power_journal.PowerJournalConflictError):
            journal.complete(batch, self.first, {"answer": 1})

    def test_delivery_requires_all_results_then_allows_the_next_batch(self) -> None:
        journal = self.journal(max_generations=1)
        batch = journal.prepare_batch("generation-1", "thread-1", [self.first, self.second])
        journal.begin(batch, self.first)
        journal.complete(batch, self.first, {"first": True})
        with self.assertRaises(power_journal.PowerJournalConflictError):
            journal.delivered(batch)

        journal.begin(batch, self.second)
        journal.complete(batch, self.second, {"second": True})
        journal.delivered(batch)
        journal.delivered(batch)

        next_batch = journal.prepare_batch("generation-1", "thread-1", [operation("interrupt-3", "input-3")])
        self.assertNotEqual(next_batch.fingerprint, batch.fingerprint)
        with self.assertRaises(power_journal.PowerJournalConflictError):
            journal.delivered(batch)
        with self.assertRaises(power_journal.PowerJournalConflictError):
            journal.begin(batch, self.first)

        next_operation = next_batch.operations[0]
        journal.begin(next_batch, next_operation)
        journal.complete(next_batch, next_operation, {"third": True})
        journal.delivered(next_batch)
        journal.prepare_batch("generation-2", "thread-2", [self.first])

    def test_delivery_reuses_confirmed_canonical_result_digests(self) -> None:
        journal = self.journal()
        operations = (self.first, self.second)
        batch = journal.prepare_batch("generation-1", "thread-1", operations)
        for selected in operations:
            journal.begin(batch, selected)
            journal.complete(batch, selected, {"interrupt": selected.interrupt_id})

        with mock.patch.object(journal, "_decode_result", wraps=journal._decode_result) as decode:
            journal.delivered(batch)

        decode.assert_not_called()
        self.assertEqual(journal._validated_results, {})

    def test_reopen_canonically_validates_results_before_delivery(self) -> None:
        journal = self.journal()
        batch = journal.prepare_batch("generation-1", "thread-1", [self.first])
        journal.begin(batch, self.first)
        journal.complete(batch, self.first, {"answer": 1})
        journal.close()

        reopened = self.journal()
        with mock.patch.object(reopened, "_decode_result", wraps=reopened._decode_result) as decode:
            reopened.delivered(batch)

        decode.assert_called_once_with(b'{"answer":1}')

    def test_corrupt_database_and_noncanonical_cache_fail_closed(self) -> None:
        journal = self.journal()
        batch = journal.prepare_batch("generation-1", "thread-1", [self.first])
        journal.begin(batch, self.first)
        journal.complete(batch, self.first, {"answer": 1})
        journal.close()

        connection = sqlite3.connect(self.path)
        connection.execute(
            "UPDATE operations SET result = ? WHERE interrupt_id = ?",
            (b'{"answer": 1}', self.first.interrupt_id),
        )
        connection.commit()
        connection.close()

        reopened = self.journal()
        with self.assertRaises(power_journal.PowerJournalCorruptionError):
            reopened.begin(batch, self.first)
        reopened.close()

        self.path.write_bytes(b"not-a-sqlite-database")
        self.path.chmod(0o600)
        with self.assertRaises(power_journal.PowerJournalCorruptionError):
            power_journal.PowerJournal(self.path)

    def test_capacity_and_json_limits_are_enforced_without_raw_inputs(self) -> None:
        journal = self.journal(max_generations=1, max_operations=1, max_result_bytes=16)
        batch = journal.prepare_batch("generation-1", "thread-secret", [self.first])
        with self.assertRaises(power_journal.PowerJournalConflictError):
            journal.prepare_batch("generation-2", "thread-2", [self.second])
        with self.assertRaises(power_journal.PowerJournalConflictError):
            journal.prepare_batch("generation-1", "thread-secret", [self.first, self.second])

        journal.begin(batch, self.first)
        with self.assertRaises(power_journal.PowerJournalConflictError):
            journal.complete(batch, self.first, {"secret": "raw-input-must-not-fit"})

        raw = self.path.read_bytes()
        self.assertNotIn(b"thread-secret", raw)
        self.assertNotIn(b"validated-input-1", raw)

    def test_purge_removes_even_uncertain_generation_and_frees_capacity(self) -> None:
        journal = self.journal(max_generations=1)
        batch = journal.prepare_batch("generation-1", "thread-1", [self.first])
        journal.begin(batch, self.first)

        journal.purge("generation-1")
        journal.purge("generation-1")
        replacement = journal.prepare_batch("generation-2", "thread-2", [self.second])

        self.assertTrue(journal.begin(replacement, self.second).execute)
        with self.assertRaises(power_journal.PowerJournalConflictError):
            journal.begin(batch, self.first)

    def test_unsafe_file_and_symlink_paths_are_rejected(self) -> None:
        self.path.parent.mkdir(mode=0o700)
        self.path.write_bytes(b"")
        self.path.chmod(0o644)
        with self.assertRaises(power_journal.PowerJournalCorruptionError):
            power_journal.PowerJournal(self.path)

        self.path.unlink()
        victim = Path(self.temporary.name) / "victim"
        victim.write_bytes(b"unchanged")
        self.path.symlink_to(victim)
        with self.assertRaises(power_journal.PowerJournalCorruptionError):
            power_journal.PowerJournal(self.path)
        self.assertEqual(victim.read_bytes(), b"unchanged")

    def test_new_database_file_and_parent_entry_are_fsynced(self) -> None:
        synced_modes: list[int] = []
        real_fsync = power_journal.os.fsync

        def observe(descriptor: int) -> None:
            synced_modes.append(power_journal.os.fstat(descriptor).st_mode)
            real_fsync(descriptor)

        with mock.patch.object(power_journal.os, "fsync", side_effect=observe):
            journal = self.journal()

        self.assertIsNotNone(journal)
        self.assertEqual(len(synced_modes), 2)
        self.assertTrue(stat.S_ISREG(synced_modes[0]))
        self.assertTrue(stat.S_ISDIR(synced_modes[1]))

    def test_hardlinked_database_fails_closed(self) -> None:
        journal = self.journal()
        journal.close()
        linked = self.path.parent / "journal-copy.sqlite3"
        linked.hardlink_to(self.path)

        with self.assertRaises(power_journal.PowerJournalCorruptionError):
            power_journal.PowerJournal(self.path)

    def test_foreign_parent_or_database_owner_fails_closed(self) -> None:
        journal = self.journal()
        journal.close()

        effective_uid = power_journal.os.geteuid()
        with (
            mock.patch.object(power_journal.os, "geteuid", return_value=effective_uid + 1),
            self.assertRaises(power_journal.PowerJournalCorruptionError),
        ):
            power_journal.PowerJournal(self.path)

        real_lstat = Path.lstat

        def foreign_database(path: Path) -> power_journal.os.stat_result:
            metadata = real_lstat(path)
            if path == self.path:
                fields = list(metadata)
                fields[4] = metadata.st_uid + 1
                return power_journal.os.stat_result(fields)
            return metadata

        with (
            mock.patch.object(Path, "lstat", autospec=True, side_effect=foreign_database),
            self.assertRaises(power_journal.PowerJournalCorruptionError),
        ):
            power_journal.PowerJournal(self.path)


if __name__ == "__main__":
    unittest.main()
