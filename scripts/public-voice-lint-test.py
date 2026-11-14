#!/usr/bin/env python3
"""Tests for public-voice-lint.py: each rule refuses its pattern and passes plain prose.

Run with: python3 scripts/public-voice-lint-test.py
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("public_voice_lint", HERE / "public-voice-lint.py")
assert _spec and _spec.loader
lint = importlib.util.module_from_spec(_spec)
sys.modules["public_voice_lint"] = lint
_spec.loader.exec_module(lint)

# rule -> (text the rule refuses, nearby text it must pass)
CASES = {
    "status-note": (
        "| probity-verify | 10,003 (fixed) |",
        "| probity-verify | 10,003 (total to 8 November 2026) |",
    ),
    "marker": ("TODO: say what the flag does.", "Open work is listed in TODO.md."),
    "process": (
        "This page and the badge are written by the same scheduled run.",
        "The badge refreshes every day.",
    ),
    "decision-id": ("Pins stay exact (ruling P-48).", "The key is an ECDSA P-256 key."),
    "tracker-id": (
        "The bump is tracked at PIN-BUMP-BOTS.",
        "Read NUMBER-FAMILY-BALANCE.md; signatures use SLH-DSA-SHA2-128S.",
    ),
    "timestamp": (
        "Read from the API at 2026-11-08 17:36 UTC.",
        "Read from the API on 8 November 2026.",
    ),
    "correction": (
        "This page previously said 10,003; that was wrong.",
        "The total is 10,003.",
    ),
    "agent": (
        "Change it only through the main session.",
        "A sub-agent delegates a task to another agent.",
    ),
    "company": ("Our company maintains this list.", "The maintainers keep this list."),
}


def rules(text: str, digests: frozenset[str] = lint.PRIVATE_DIGESTS) -> set[str]:
    return {f.rule for f in lint.lint_text("README.md", text, digests)}


class RuleTest(unittest.TestCase):
    def test_every_rule_has_a_case(self) -> None:
        self.assertEqual(set(CASES), {rule for rule, _, _ in lint.RULES})

    def test_each_rule_refuses_its_pattern(self) -> None:
        for rule, (bad, _) in CASES.items():
            with self.subTest(rule=rule):
                self.assertIn(rule, rules(bad))

    def test_each_rule_passes_plain_prose(self) -> None:
        for rule, (_, good) in CASES.items():
            with self.subTest(rule=rule):
                self.assertEqual(rules(good), set())

    def test_code_is_not_prose(self) -> None:
        fenced = "```\n# TODO: fill in\nread at 2026-11-08 17:36 UTC\n```\n"
        self.assertEqual(rules(fenced), set())
        self.assertEqual(rules("Run `grep TODO` to list them."), set())

    def test_link_targets_are_not_prose(self) -> None:
        self.assertEqual(rules("See [the guide](docs/PIN-BUMP-BOTS-12.md)."), set())

    def test_html_comments_are_not_prose(self) -> None:
        self.assertEqual(rules("<!-- TODO regenerate -->\nPlain text.\n"), set())

    def test_ruling_number_as_a_policy_name_passes(self) -> None:
        self.assertEqual(rules("The gate rules follow ruling 2."), set())
        self.assertIn("process", rules("The operator's ruling of 2026-09-09 applies."))


class PrivateNameTest(unittest.TestCase):
    DIGESTS = frozenset({hashlib.sha256(b"examplecorp").hexdigest()})

    def test_private_name_is_refused_in_every_spelling(self) -> None:
        for text in (
            "See examplecorp.dev for details.",
            "https://www.examplecorp.dev/deck",
            "Clone github.com/someone/examplecorp-tools.",
            "`examplecorp` in code is still a leak.",
        ):
            with self.subTest(text=text):
                self.assertIn("private-name", rules(text, self.DIGESTS))

    def test_unrelated_name_passes(self) -> None:
        self.assertEqual(rules("See example.org for details.", self.DIGESTS), set())

    def test_shipped_digests_are_sha256(self) -> None:
        for value in lint.PRIVATE_DIGESTS:
            self.assertRegex(value, r"^[0-9a-f]{64}$")

    def test_private_name_cannot_be_allowlisted(self) -> None:
        finding = lint.Finding("README.md", 1, "private-name", "x", "x")
        self.assertFalse(lint.allowed(finding, {("*", "private-name", "*")}))


class CliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / "docs").mkdir()
        self.allow = self.root / "allow.txt"
        self.allow.write_text("")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_lint(self, text: str) -> int:
        page = self.root / "docs" / "page.md"
        page.write_text(text)
        status: int = lint.main(
            [str(page), "--root", str(self.root), "--allowlist", str(self.allow)]
        )
        return status

    def test_clean_page_passes(self) -> None:
        self.assertEqual(self.run_lint("The badge refreshes every day.\n"), 0)

    def test_finding_fails(self) -> None:
        self.assertEqual(self.run_lint("Counts are fixed at the old total.\n"), 1)

    def test_allowlist_entry_passes_exact_text_in_matching_path(self) -> None:
        self.allow.write_text("# a spec term\ndocs/*.md\tprocess\tfixed at\n")
        self.assertEqual(self.run_lint("The length is fixed at 32 bytes.\n"), 0)

    def test_allowlist_entry_for_another_path_does_not_apply(self) -> None:
        self.allow.write_text("other/*.md\tprocess\tfixed at\n")
        self.assertEqual(self.run_lint("The length is fixed at 32 bytes.\n"), 1)

    def test_allowlist_star_covers_every_match_of_the_rule(self) -> None:
        self.allow.write_text("docs/page.md\ttimestamp\t*\n")
        self.assertEqual(self.run_lint("Window 2026-10-11 19:29 UTC to 19:33 UTC.\n"), 0)

    def test_malformed_allowlist_is_refused(self) -> None:
        self.allow.write_text("docs/page.md process fixed at\n")
        with self.assertRaises(SystemExit):
            self.run_lint("text\n")


if __name__ == "__main__":
    unittest.main()
