#!/usr/bin/env python3
"""Tests for scripts/sync-install-pins.py, against a throwaway git repository."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location("sync_install_pins", HERE / "sync-install-pins.py")
assert spec is not None and spec.loader is not None
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

README = (
    "uv add agent-evidence-vectors==0.26.0 and pip install probityai==0.1.0\n"
    "go install x/cmd/aee-verify@v0.26.0\n"
    "[r](https://github.com/o/agent-evidence-vectors/releases/tag/v0.26.0)\n"
    "uses: probityai/agent-evidence-vectors@v0.22.0\n"
)
CITATION = """version: 0.26.0
date-released: "2026-10-01"
preferred-citation:
  type: software
  url: https://github.com/probityai/agent-evidence-vectors/releases/tag/v0.26.0
  version: 0.26.0
  commit: 0000000000000000000000000000000000000000
  date-released: "2026-10-01"
  identifiers:
    - type: url
      value: https://api.github.com/repos/probityai/agent-evidence-vectors/git/tags/1111111111111111111111111111111111111111
"""


def git(root: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-C", str(root), "-c", "user.email=t@example.invalid", "-c", "user.name=t",
         "-c", "commit.gpgSign=false", "-c", "tag.gpgSign=false", *args],
        capture_output=True, text=True, check=True,
    )  # fmt: skip
    return done.stdout.strip()


class SyncTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "docs" / "guides").mkdir(parents=True)
        for rel, text in {
            "README.md": README,
            "DISTRIBUTION.md": "git checkout v0.26.0\n",
            "docs/guides/runner.md": "uses: p/agent-evidence-vectors@v0.26.0\n",
            "docs/reference/release-verification.md": "git checkout v0.26.0\n",
            "docs/reference/citing.md": "version = {0.26.0}\n",
            "CITATION.cff": CITATION,
        }.items():
            path = self.root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        git(self.root, "init", "-q")
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "release 0.30.0 source")
        git(self.root, "tag", "-a", "v0.9.0", "-m", "older")
        git(self.root, "tag", "-a", "v0.30.0", "-m", "newest")
        git(self.root, "commit", "-q", "--allow-empty", "-m", "after the release")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_newest_tag_is_numeric_not_lexical(self) -> None:
        self.assertEqual(mod.published_version(self.root), "0.30.0")

    def test_check_reports_stale_files_without_writing(self) -> None:
        stale = mod.sync(self.root, "0.30.0", apply=False)
        self.assertIn("README.md", stale)
        self.assertIn("CITATION.cff", stale)
        self.assertEqual((self.root / "README.md").read_text(), README)

    def test_apply_moves_pins_and_citation_to_the_tag(self) -> None:
        mod.sync(self.root, "0.30.0", apply=True)
        text = (self.root / "README.md").read_text()
        self.assertIn("agent-evidence-vectors==0.30.0", text)
        self.assertIn("aee-verify@v0.30.0", text)
        self.assertIn("probityai==0.1.0", text)
        self.assertIn("agent-evidence-vectors@v0.22.0", text)
        citing = self.root / "docs/reference/citing.md"
        self.assertEqual(citing.read_text(), "version = {0.30.0}\n")
        cff = (self.root / "CITATION.cff").read_text()
        commit = git(self.root, "rev-parse", "v0.30.0^{commit}")
        tag_object = git(self.root, "rev-parse", "v0.30.0")
        self.assertIn(f"  commit: {commit}", cff)
        self.assertIn(f"git/tags/{tag_object}", cff)
        self.assertIn("  version: 0.30.0", cff)

    def test_second_run_is_clean(self) -> None:
        mod.sync(self.root, "0.30.0", apply=True)
        self.assertEqual(mod.sync(self.root, "0.30.0", apply=False), [])

    def test_a_descendant_of_the_tag_is_refused_while_the_citation_lags(self) -> None:
        import _release_source

        self.assertIsNotNone(_release_source.lagging(self.root, "0.26.0"))
        self.assertIsNone(_release_source.lagging(self.root, "0.30.0"))

    def test_the_tagged_commit_itself_is_exempt(self) -> None:
        import _release_source

        git(self.root, "checkout", "-q", "v0.30.0")
        self.assertIsNone(_release_source.lagging(self.root, "0.26.0"))

    def test_repo_pins_follow_the_newest_tag(self) -> None:
        version = mod.published_version(mod.ROOT)
        import _release_source

        if _release_source.head_is_tag_commit(mod.ROOT, version):
            return  # the tagged commit cannot name its own tag
        self.assertEqual(mod.sync(mod.ROOT, version, apply=False), [])


if __name__ == "__main__":
    unittest.main()
