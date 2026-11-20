#!/usr/bin/env python3
"""Tests for changed-cases.py, over a throwaway repository with real tags."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from typing import Any


def load() -> ModuleType:
    path = Path(__file__).with_name("changed-cases.py")
    spec = importlib.util.spec_from_file_location("changed_cases", path)
    if spec is None or spec.loader is None:
        raise ImportError("changed-cases.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


cc = load()


class Repo:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "t@example.invalid")
        self.git("config", "user.name", "t")
        self.git("config", "commit.gpgsign", "false")
        self.git("config", "tag.gpgsign", "false")

    def git(self, *args: str) -> None:
        subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True)

    def write(self, rel: str, value: object) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value), encoding="utf-8")

    def commit(self, tag: str) -> None:
        self.git("add", "-A")
        self.git("commit", "-q", "-m", tag)
        self.git("tag", tag)


def manifest(*ids: str, suite: str = "demo/v1", contract: str = "c1") -> dict[str, object]:
    return {"suite": suite, "verifierContract": contract, "corpusDigest": "x",
            "vectors": [{"id": i, "expected": "accept", "path": f"cases/{i}"} for i in ids]}


class ChangedCases(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repo(Path(self.tmp.name))
        self.repo.write("corpora/vectors-demo/MANIFEST.json", manifest("a", "b"))
        self.repo.write("corpora/vectors-demo/cases/a/record.json", {"v": 1})
        self.repo.write("corpora/vectors-demo/cases/b/record.json", {"v": 2})
        self.repo.write("packaging/agent_evidence_vectors/tb/corpus/manifest.json",
                        {"schema": "s", "members": {"cases.json": "sha256:1"}})
        self.repo.write("packaging/agent_evidence_vectors/tb/corpus/cases.json",
                        {"cases": [{"id": "p", "expected": "x"}]})
        self.repo.commit("v1.2.0")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_diff(self, old: str = "v1.2.0", new: str = "HEAD") -> dict[str, Any]:
        return cc.diff(self.repo.root, old, new)

    def test_nothing_changed_reads_every_manifest(self) -> None:
        self.repo.write("README.md", "docs only")
        self.repo.commit("v1.2.1")
        result = self.run_diff()
        self.assertEqual(result["corpora"], [])
        self.assertEqual(result["corporaRead"], {"from": 2, "to": 2})
        self.assertEqual(cc.semver(self.repo.root, "1.2.1", "HEAD", None), 0)

    def test_added_case_is_listed_and_refuses_a_patch(self) -> None:
        self.repo.write("corpora/vectors-demo/MANIFEST.json", manifest("a", "b", "c"))
        self.repo.write("corpora/vectors-demo/cases/c/record.json", {"v": 3})
        self.repo.commit("v1.2.1")
        result = self.run_diff()
        self.assertEqual(result["corpora"][0]["added"], ["c"])
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cc.semver(self.repo.root, "1.2.1", "HEAD", None), 1)
        self.assertIn("bump to v1.3.0", out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cc.semver(self.repo.root, "1.3.0", "HEAD", None), 0)

    def test_case_bytes_changed_under_an_unchanged_entry(self) -> None:
        self.repo.write("corpora/vectors-demo/cases/a/record.json", {"v": 9})
        self.repo.commit("v1.2.1")
        self.assertEqual(self.run_diff()["corpora"][0]["changed"], ["a"])

    def test_removed_case_and_contract_change(self) -> None:
        self.repo.write("corpora/vectors-demo/MANIFEST.json", manifest("a", contract="c2"))
        self.repo.commit("v1.2.1")
        row = self.run_diff()["corpora"][0]
        self.assertEqual(row["removed"], ["b"])
        self.assertTrue(row["contractChanged"])

    def test_contract_change_alone_refuses_a_patch(self) -> None:
        self.repo.write("corpora/vectors-demo/MANIFEST.json", manifest("a", "b", contract="c2"))
        self.repo.commit("v1.2.1")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cc.semver(self.repo.root, "1.2.1", "HEAD", None), 1)

    def test_packaged_member_cases(self) -> None:
        self.repo.write("packaging/agent_evidence_vectors/tb/corpus/cases.json",
                        {"cases": [{"id": "p", "expected": "y"}, {"id": "q", "expected": "x"}]})
        self.repo.commit("v1.2.1")
        row = self.run_diff()["corpora"][0]
        self.assertEqual(row["added"], ["cases.json#q"])
        self.assertEqual(row["changed"], ["cases.json#p"])

    def test_new_corpus_counts_every_case_as_added(self) -> None:
        self.repo.write("corpora/vectors-new/MANIFEST.json", manifest("n1", "n2", suite="new/v1"))
        self.repo.commit("v1.2.1")
        row = self.run_diff()["corpora"][0]
        self.assertEqual((row["status"], row["added"]), ("added", ["n1", "n2"]))

    def test_unreadable_manifest_is_an_error_not_an_empty_corpus(self) -> None:
        self.repo.write("corpora/vectors-demo/MANIFEST.json", {"suite": "demo/v1"})
        self.repo.commit("v1.2.1")
        with self.assertRaises(cc.ReadError):
            self.run_diff()
        with contextlib.redirect_stderr(io.StringIO()):
            argv = ["--repo", str(self.repo.root), "diff", "--from", "v1.2.0"]
            self.assertEqual(cc.main(argv), 2)

    def test_version_not_above_previous_is_refused(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cc.semver(self.repo.root, "1.2.0", "HEAD", "v1.2.0"), 1)

    def test_notes_list_each_case(self) -> None:
        self.repo.write("corpora/vectors-demo/MANIFEST.json", manifest("a", "b", "c"))
        self.repo.commit("v1.3.0")
        notes = cc.render_notes(self.run_diff())
        self.assertIn("## Cases that changed", notes)
        self.assertIn("- added: `c`", notes)
        self.assertIn("1 added, 0 changed, 0 removed", notes)


if __name__ == "__main__":
    unittest.main()
