#!/usr/bin/env python3
"""Tests for scripts/regen.py: a row declares exactly one of a repair or why none exists.

    python3 scripts/regen-test.py
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("regen", HERE / "regen.py")
assert SPEC and SPEC.loader
regen: Any = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(regen)

GATE = 'ident = "g"\nargv = ["python3", "x.py", "--check"]\n'


def registry(body: str) -> Path:
    path = Path(tempfile.mkdtemp()) / "repairs.toml"
    path.write_text(body, encoding="utf-8")
    return path


class RowShape(unittest.TestCase):
    def load(self, body: str):
        old = regen.REGISTRY
        regen.REGISTRY = registry(body)
        try:
            return regen.load()
        finally:
            regen.REGISTRY = old

    def test_a_row_with_a_reason_and_no_repair_loads(self) -> None:
        gates = self.load("[[gate]]\n" + GATE + 'not_regenerable = "hand-authored answers"\n')
        self.assertEqual(gates[0]["ident"], "g")

    def test_a_row_with_neither_is_refused(self) -> None:
        with self.assertRaises(regen.Refused):
            self.load("[[gate]]\n" + GATE)

    def test_a_row_with_both_is_refused(self) -> None:
        with self.assertRaises(regen.Refused):
            self.load("[[gate]]\n" + GATE + 'fix = ["python3", "x.py"]\nnot_regenerable = "why"\n')

    def test_a_reasoned_row_is_reported_and_never_run(self) -> None:
        gates = [{"ident": "g", "argv": ["python3", "x.py", "--check"],
                  "not_regenerable": "hand-authored answers"}]
        ran = []
        old = regen.run_one
        regen.run_one = lambda g: ran.append(g) or (False, "ok")
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                rc = regen.regenerate(gates)
        finally:
            regen.run_one = old
        self.assertEqual(rc, 0)
        self.assertEqual(ran, [])
        self.assertIn("NOT REGENERABLE g: hand-authored answers", out.getvalue())


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
