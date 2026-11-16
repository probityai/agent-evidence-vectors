#!/usr/bin/env python3
"""Tests for tools/mutation_sweep.py's --check-anchors mode.

The crate workflow runs `mutation_sweep.py --check-anchors` on every change. Until
this file existed the sweep had no such mode: it read the flag as its log
directory, made a directory called `--check-anchors` in the crate and ran all of
its rows, one compiler build each, inside the test job. These tests hold the
mode to what the workflow asks of it: it builds nothing, writes nothing, passes
on the shipped sources, and names a row whose anchor or test filter has moved.

    python3 tools/mutation_sweep_test.py

Standard library only.
"""

import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

CRATE = pathlib.Path(__file__).resolve().parents[1]
SWEEP = CRATE / "tools" / "mutation_sweep.py"


def copy_crate(into: pathlib.Path) -> pathlib.Path:
    """A copy of the parts of the crate the sweep reads, so a test can break it."""
    root = into / "crate"
    for part in ("src", "tests", "tools"):
        shutil.copytree(CRATE / part, root / part)
    return root


class CheckAnchors(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="sweep-anchors-test-"))
        self.addCleanup(shutil.rmtree, self.tmp)
        # A compiler stand-in that records any call and fails it, so a mode that
        # builds anything is caught whether or not the build would have passed.
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        self.calls = self.tmp / "calls.log"
        stub = bin_dir / "cargo"
        stub.write_text(f'#!/bin/sh\necho "$@" >> "{self.calls}"\nexit 1\n')
        stub.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{bin_dir}{os.pathsep}{os.environ['PATH']}")

    def run_sweep(self, root: pathlib.Path, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(root / "tools" / "mutation_sweep.py"), *args],
            cwd=root,
            env=self.env,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def assert_built_and_wrote_nothing(self, root: pathlib.Path, before: set) -> None:
        self.assertFalse(self.calls.exists(), "the anchor check invoked the compiler")
        self.assertEqual(set(os.listdir(root)), before, "the anchor check wrote into the crate")

    def test_the_shipped_sources_pass_without_a_build(self):
        root = copy_crate(self.tmp)
        before = set(os.listdir(root))
        result = self.run_sweep(root, "--check-anchors")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("0 problems", result.stdout)
        self.assert_built_and_wrote_nothing(root, before)

    def test_an_anchor_that_moved_is_named(self):
        root = copy_crate(self.tmp)
        parse = root / "src" / "parse.rs"
        text = parse.read_text()
        anchor = "            if !seen.insert(name.clone()) {"
        self.assertEqual(text.count(anchor), 1)
        parse.write_text(text.replace(anchor, "            if !seen.insert(name.to_owned()) {"))
        before = set(os.listdir(root))
        result = self.run_sweep(root, "--check-anchors")
        self.assertEqual(result.returncode, 1)
        self.assertIn("R1: anchor matches 0 times in src/parse.rs", result.stderr)
        self.assertIn("M1: anchor matches 0 times in src/parse.rs", result.stderr)
        self.assert_built_and_wrote_nothing(root, before)

    def test_a_filter_that_names_no_test_is_named(self):
        # cargo runs zero tests for such a filter and passes, so every mutation
        # in the row would read as a test that does not discriminate.
        root = copy_crate(self.tmp)
        target = root / "tests" / "refusal_messages.rs"
        text = target.read_text()
        name = "fn invalid_utf8_is_reported_at_its_own_first_byte"
        self.assertEqual(text.count(name), 1)
        target.write_text(text.replace(name, "fn renamed_offset_test"))
        result = self.run_sweep(root, "--check-anchors")
        self.assertEqual(result.returncode, 1)
        self.assertIn("M4d: filter 'invalid_utf8_is_reported_at_its_own_first_byte'", result.stderr)

    def test_an_unknown_flag_is_refused_not_used_as_a_directory(self):
        root = copy_crate(self.tmp)
        before = set(os.listdir(root))
        result = self.run_sweep(root, "--anchors-only")
        self.assertEqual(result.returncode, 2)
        self.assert_built_and_wrote_nothing(root, before)

    def test_the_check_takes_no_log_directory(self):
        root = copy_crate(self.tmp)
        before = set(os.listdir(root))
        result = self.run_sweep(root, "--check-anchors", "logs")
        self.assertEqual(result.returncode, 2)
        self.assert_built_and_wrote_nothing(root, before)


if __name__ == "__main__":
    unittest.main()
