#!/usr/bin/env python3
"""Tests for action-download-budget.py: an archive over its budget fails, one at or under passes.

Run with: python3 scripts/action-download-budget-test.py
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("action_download_budget", HERE / "action-download-budget.py")
assert _spec and _spec.loader
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


class Verdict(unittest.TestCase):
    def test_over_budget_fails(self) -> None:
        ok, line = gate.verdict(135_806_433, gate.BUDGET_BYTES)
        self.assertFalse(ok)
        self.assertIn("over by", line)

    def test_at_budget_passes(self) -> None:
        self.assertTrue(gate.verdict(gate.BUDGET_BYTES, gate.BUDGET_BYTES)[0])

    def test_this_checkout_measures_a_real_archive(self) -> None:
        self.assertGreater(gate.archive_size("HEAD"), 1_000_000)


if __name__ == "__main__":
    unittest.main()
