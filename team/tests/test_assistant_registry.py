"""Shared Assistant registry contracts."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import assistant_registry
import local_registry
import marketplace


class SharedRegistry(unittest.TestCase):
    def test_both_reject_all_zero_digest(self):
        zero = "ghcr.io/theshimpz/shimpz-space@sha256:" + "0" * 64
        self.assertFalse(marketplace.is_digest_image(zero))
        self.assertFalse(local_registry.is_digest_ref(zero))

    def test_real_digest_still_accepted(self):
        self.assertTrue(marketplace.is_digest_image(marketplace.SHIMPZ_CLOUDFLARE_ASSISTANT_IMAGE))

    def test_single_dataclass_and_validators(self):
        self.assertIs(marketplace.PowerSpec, assistant_registry.PowerSpec)
        self.assertIs(local_registry.PowerSpec, assistant_registry.PowerSpec)
        self.assertIs(marketplace.AccountSpec, assistant_registry.AccountSpec)
        self.assertIs(local_registry.AccountSpec, assistant_registry.AccountSpec)
