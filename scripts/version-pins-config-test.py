#!/usr/bin/env python3
"""Hold version-pins.toml's historical exclusions to a planted stale pin.

Each exclusion in version-pins.toml names pages that record a past release as a fact. A
stale pin planted in one of them must pass `version-pins.py check`, and the same pin in a
live page must fail it; otherwise the exclusion guards nothing or the check is blind.

The checker is the single copy in probityai/.github. Set VERSION_PINS_SCRIPT to its path
(CI checks it out at the commit the workflow pins); the default is a sibling checkout.
Standard library only; run with `python3 scripts/version-pins-config-test.py`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SCRIPT = Path(os.environ.get("VERSION_PINS_SCRIPT") or REPO.parent / ".github" / "scripts" / "version-pins.py")
STALE = "pip install agent-evidence-vectors==0.12.0"
CURRENT_MANIFEST = '[project]\nname = "agent-evidence-vectors"\nversion = "0.32.1"\n'

# (path, text) for every page the config declares historical, with one stale pin inside.
HISTORICAL = [
    ("interop/x-2026-10-01/source-lock.json", '{"note": "%s"}\n' % STALE),
    ("interop/w3c-v01-appendix/main.tex", "\\providecommand{\\aevreadrelease}{%s}\n" % STALE),
    ("interop/x-2026-10-01/README.md", "Tested with `%s`.\n" % STALE),
    ("docs/paper/w3c-v01/README.md", "| Producer | `%s` |\n" % STALE),
    ("docs/USED-BY.md", "| adopter | Pins `agent-evidence-vectors==0.20.0` |\n"),
    ("docs/W3C-V01-CONFORMANCE-APPENDIX.md", "written by `uvx agent-evidence-vectors==0.12.0 --emit`\n"),
]
LIVE = [
    ("README.md", "Install with `%s`.\n" % STALE),
    ("docs/guides/install.md", "Install with `%s`.\n" % STALE),
]


def check(files: dict[str, str]) -> subprocess.CompletedProcess[str]:
    root = Path(tempfile.mkdtemp(prefix="vectors-pins-"))
    try:
        shutil.copy(REPO / "version-pins.toml", root / "version-pins.toml")
        files = {"pyproject.toml": CURRENT_MANIFEST, **files}
        for rel, text in files.items():
            (root / rel).parent.mkdir(parents=True, exist_ok=True)
            (root / rel).write_text(text, encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
        return subprocess.run([sys.executable, "-B", str(SCRIPT), "check", "--root", str(root)],
                              capture_output=True, text=True, check=False)
    finally:
        shutil.rmtree(root)


class HistoricalExclusions(unittest.TestCase):
    def test_the_checker_is_present(self):
        self.assertTrue(SCRIPT.is_file(), f"set VERSION_PINS_SCRIPT; {SCRIPT} is missing")

    def test_each_historical_page_may_name_an_old_release(self):
        for rel, text in HISTORICAL:
            with self.subTest(page=rel):
                done = check({rel: text})
                self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_a_live_page_may_not(self):
        for rel, text in LIVE:
            with self.subTest(page=rel):
                done = check({rel: text})
                self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
                self.assertIn(rel, done.stdout + done.stderr)

    def test_a_historical_page_keeps_its_pin_when_the_live_one_is_wrong(self):
        done = check({HISTORICAL[0][0]: HISTORICAL[0][1], LIVE[0][0]: LIVE[0][1]})
        self.assertEqual(done.returncode, 1)
        self.assertNotIn("source-lock.json", done.stdout + done.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
