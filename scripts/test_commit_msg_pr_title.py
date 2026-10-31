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
from typing import Any

HOOK = Path(__file__).resolve().parents[1] / ".githooks" / "commit-msg"


def load_hook() -> Any:
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


class ImportedTips(unittest.TestCase):
    """`--check-range` exempts only commits reachable from a listed tip."""

    def test_only_the_imported_ancestry_is_exempt(self) -> None:
        import contextlib
        import io
        import os
        import tempfile

        hook = load_hook()
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull}
        too_long = "feat: " + "x" * 80

        def git(repo: str, *args: str) -> str:
            done = subprocess.run(["git", *args], cwd=repo, env=env, check=True,
                                  capture_output=True, text=True)
            return done.stdout.strip()

        with tempfile.TemporaryDirectory() as repo:
            git(repo, "init", "-q")
            git(repo, "config", "user.email", "t@invalid")
            git(repo, "config", "user.name", "T")
            git(repo, "config", "commit.gpgsign", "false")
            git(repo, "commit", "-q", "--allow-empty", "-m", "feat: base")
            base = git(repo, "rev-parse", "HEAD")
            git(repo, "commit", "-q", "--allow-empty", "-m", too_long)
            imported = git(repo, "rev-parse", "HEAD")
            git(repo, "commit", "-q", "--allow-empty", "-m", too_long)
            hook.load_baseline = lambda: None
            cwd = os.getcwd()
            os.chdir(repo)
            try:
                out = io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                    hook.load_imported_tips = lambda: [imported]
                    exempt_status = hook.check_range(f"{base}..HEAD")
                    hook.load_imported_tips = lambda: []
                    plain_status = hook.check_range(f"{base}..HEAD")
            finally:
                os.chdir(cwd)
        self.assertEqual(exempt_status, 1, "the new long subject must still be refused")
        self.assertIn("1 imported commit(s)", out.getvalue())
        self.assertIn("checked 1 commit message(s)", out.getvalue())
        self.assertEqual(plain_status, 1)
        self.assertIn("checked 2 commit message(s)", out.getvalue())


if __name__ == "__main__":
    unittest.main()
