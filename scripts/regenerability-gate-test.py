#!/usr/bin/env python3
"""Tests for regenerability-gate.py's comparison: the committed side is what git
tracks, never whatever sits in the working tree.

Run with: python3 scripts/regenerability-gate-test.py
"""

from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location(
    "regenerability_gate", HERE / "regenerability-gate.py"
)
assert _spec and _spec.loader
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


class CompareTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        base = Path(self._tmp.name)
        self.root = base / "root"
        self.dest = base / "dest"
        for tree in (self.root, self.dest):
            (tree / "corpus").mkdir(parents=True)
        _git(self.root, "init", "-q")
        (self.root / "corpus" / "a.json").write_text("{}\n")
        _git(self.root, "add", "corpus/a.json")
        (self.dest / "corpus" / "a.json").write_text("{}\n")
        patcher = mock.patch.object(gate, "OWNED", [("corpus", "*.json")])
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_clean_tree_passes(self) -> None:
        self.assertEqual(gate.compare(self.root, self.dest), [])

    def test_untracked_file_is_not_committed(self) -> None:
        # The defect: a stray working-tree file was reported as committed.
        (self.root / "corpus" / "stray.json").write_text("{}\n")
        self.assertEqual(gate.compare(self.root, self.dest), [])

    def test_tracked_file_no_generator_wrote_still_fails(self) -> None:
        # Control: the absence direction the gate exists for still refuses.
        (self.root / "corpus" / "b.json").write_text("{}\n")
        _git(self.root, "add", "corpus/b.json")
        failures = gate.compare(self.root, self.dest)
        self.assertEqual(len(failures), 1)
        self.assertIn("corpus/b.json is committed and no generator produced it", failures[0])

    def test_generated_but_untracked_still_fails(self) -> None:
        # An untracked file the generators DO produce is still a missing commit.
        (self.root / "corpus" / "c.json").write_text("{}\n")
        (self.dest / "corpus" / "c.json").write_text("{}\n")
        failures = gate.compare(self.root, self.dest)
        self.assertEqual(len(failures), 1)
        self.assertIn("corpus/c.json is produced by a generator and is not committed", failures[0])


if __name__ == "__main__":
    unittest.main()
