from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

import brain_runtime_token_store


class BrainRuntimeTokenStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name) / "runtime-token"
        self.path = self.root / "token"
        self.group_id = os.getgid()

    def test_create_uses_a_strong_token_and_exact_shared_group_permissions(self) -> None:
        token = brain_runtime_token_store.ensure(self.path, group_id=self.group_id)

        self.assertEqual(len(bytes.fromhex(token)), 32)
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o750)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o440)
        self.assertEqual(self.root.stat().st_gid, self.group_id)
        self.assertEqual(self.path.stat().st_gid, self.group_id)
        self.assertEqual(list(self.root.glob(".*.tmp")), [])

    def test_existing_safe_token_is_reused_without_replacement(self) -> None:
        first = brain_runtime_token_store.ensure(self.path, group_id=self.group_id)
        inode = self.path.stat().st_ino

        second = brain_runtime_token_store.ensure(self.path, group_id=self.group_id)

        self.assertEqual(second, first)
        self.assertEqual(self.path.stat().st_ino, inode)

    def test_symlink_and_insecure_existing_file_fail_closed(self) -> None:
        self.root.mkdir(mode=0o750)
        victim = Path(self.directory.name) / "victim"
        victim.write_text("do-not-read", encoding="ascii")
        self.path.symlink_to(victim)
        with self.assertRaises(brain_runtime_token_store.RuntimeTokenError):
            brain_runtime_token_store.ensure(self.path, group_id=self.group_id)
        self.assertEqual(victim.read_text(encoding="ascii"), "do-not-read")

        self.path.unlink()
        self.path.write_text("a" * 64, encoding="ascii")
        self.path.chmod(0o640)
        with self.assertRaises(brain_runtime_token_store.RuntimeTokenError):
            brain_runtime_token_store.ensure(self.path, group_id=self.group_id)


if __name__ == "__main__":
    unittest.main()
