"""Reviewed Assistant catalog capacity contracts."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from assistant_human import assistant_manifest as am


class AssistantCatalogCapTests(unittest.TestCase):
    def test_catalog_cap_covers_every_individually_legal_contract(self):
        self.assertEqual(am.MAX_CATALOG_ASSISTANTS, 32)
        self.assertGreaterEqual(
            am.MAX_CATALOG_BYTES,
            am.MAX_CATALOG_ASSISTANTS * am.MAX_CONTRACT_BYTES,
        )
