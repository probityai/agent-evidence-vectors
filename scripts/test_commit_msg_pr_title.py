#!/usr/bin/env python3
"""Squash-merge title length control for the commit-msg gate.

A squash merge writes the pull request title plus ` (#N)` as the subject on
main. These tests run the real hook file, in process and as the CLI that CI
calls, so a title that is 72 characters alone and over 72 with the suffix
cannot pass on the pull request and fail on main again.
"""
from __future__ import annotations

import subprocess
import sys
import unittest
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path

HOOK = Path(__file__).resolve().parents[1] / ".githooks" / "commit-msg"


def load_hook():
    loader = SourceFileLoader("commit_msg_hook", str(HOOK))
    spec = spec_from_loader(loader.name, loader)
    assert spec is not None
    module = module_from_spec(spec)
    loader.exec_module(module)
    return module


def cli(title: str, number: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(HOOK), "--check-title", title, number],
        capture_output=True,
        text=True,
        check=False,
    )


class SquashTitleLength(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.hook = load_hook()

    def test_title_of_72_fails_once_the_suffix_is_appended(self) -> None:
        title = "feat(trace): " + "x" * 59
        self.assertEqual(len(title), 72)
        errors = self.hook.lint_pr_title(title, 12)
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("title is 72 chars", errors[0])
        self.assertIn("' (#12)'", errors[0])
        self.assertIn("giving 78", errors[0])

    def test_title_that_fits_with_the_suffix_passes(self) -> None:
        title = "feat(trace): " + "x" * 53
        self.assertEqual(len(title) + len(" (#12)"), 72)
        self.assertEqual(self.hook.lint_pr_title(title, 12), [])

    def test_one_over_the_limit_fails(self) -> None:
        title = "feat(trace): " + "x" * 54
        self.assertTrue(self.hook.lint_pr_title(title, 12))

    def test_suffix_grows_with_the_number(self) -> None:
        title = "feat(trace): " + "x" * 53
        self.assertEqual(self.hook.lint_pr_title(title, 99), [])
        self.assertTrue(self.hook.lint_pr_title(title, 100))

    def test_other_rules_still_apply_to_the_title(self) -> None:
        errors = self.hook.lint_pr_title("fix(api): drop the — dash", 3)
        self.assertTrue(any("non-ASCII" in e for e in errors), errors)

    def test_cli_exit_codes(self) -> None:
        long_title = "feat(trace): " + "x" * 59
        refused = cli(long_title, "12")
        self.assertEqual(refused.returncode, 1, refused.stderr)
        self.assertIn("giving 78", refused.stderr)
        self.assertEqual(cli("feat(trace): " + "x" * 53, "12").returncode, 0)
        self.assertEqual(cli("feat: ok", "not-a-number").returncode, 2)


if __name__ == "__main__":
    unittest.main()
