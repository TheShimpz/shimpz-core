"""Strict JSON decoder contracts."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import strict_json


class StrictJsonTests(unittest.TestCase):
    def test_rejects_non_finite_numbers_and_duplicate_fields(self):
        for payload in (
            "NaN",
            '{"a": Infinity}',
            '{"a": -Infinity}',
            '{"a": 1, "a": 2}',
        ):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                strict_json.loads(payload)

    def test_accepts_finite_unique_object(self):
        self.assertEqual(strict_json.loads('{"a": 1}'), {"a": 1})
