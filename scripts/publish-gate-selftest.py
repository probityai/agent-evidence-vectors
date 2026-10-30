#!/usr/bin/env python3
"""Mutations of the workflows that publish-gate-test.py must refuse."""

from __future__ import annotations

import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("gate", HERE / "publish-gate-test.py")
assert spec and spec.loader
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class Mutations(unittest.TestCase):
    def mutate(self, name: str, old: str, new: str) -> list[str]:
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copytree(gate.WORKFLOWS, tmp, dirs_exist_ok=True)
            path = Path(tmp) / name
            text = path.read_text(encoding="utf-8")
            self.assertIn(old, text)
            path.write_text(text.replace(old, new, 1), encoding="utf-8")
            return gate.check_all(Path(tmp))

    def test_clean_tree_passes(self) -> None:
        self.assertEqual(gate.check_all(gate.WORKFLOWS), [])

    def test_manual_trigger_on_hf_refused(self) -> None:
        out = self.mutate("publish-hf-dataset.yml", "  release:\n", "  workflow_dispatch:\n  release:\n")
        self.assertTrue(out)

    def test_hf_job_without_environment_refused(self) -> None:
        out = self.mutate("publish-hf-dataset.yml", "    environment: public-release\n", "")
        self.assertTrue(out)

    def test_hf_job_on_push_refused(self) -> None:
        out = self.mutate("publish-hf-dataset.yml", "github.event_name == 'release'", "github.event_name != 'x'")
        self.assertTrue(out)

    def test_release_dispatch_refused(self) -> None:
        out = self.mutate("release.yml", "  release:\n    types: [published]\n", "  release:\n    types: [published]\n  workflow_dispatch:\n")
        self.assertTrue(out)

    def test_corpus_publish_without_environment_refused(self) -> None:
        out = self.mutate("release.yml", "    environment: public-release\n", "")
        self.assertTrue(out)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
