#!/usr/bin/env python3
"""Tests for scripts/regenerate-derived.py and the layout it relies on.

Each case fails on the layout this repository had before the script existed:
a hand-kept corpus list in the ruff step, a shared-source lock nothing refreshed
during regeneration, and generated records resolved by hand at every merge.

Usage: python3 scripts/regenerate-derived-test.py
"""

from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "regenerate-derived.py"
LOCK_DIR = "interop/agentavow-signed-map-v1"


def load():
    spec = importlib.util.spec_from_file_location("regenerate_derived", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(root: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    done = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)
    if check and done.returncode != 0:
        raise AssertionError(f"git {' '.join(args)}: {done.stderr}")
    return done


def ci_text() -> str:
    return (REPO / ".github/workflows/ci.yml").read_text(encoding="utf-8")


class Layout(unittest.TestCase):
    def test_every_derived_file_carries_the_attribute(self) -> None:
        tracked = git(REPO, "ls-files", "release", LOCK_DIR + "/source-lock.json").stdout.split()
        derived = [p for p in tracked if p.startswith("release/intake/")
                   or p in ("release/CORPUS-DIGESTS.txt", LOCK_DIR + "/source-lock.json")]
        self.assertGreater(len(derived), 100)
        module = load()
        missing = [p for p in derived if not module.is_derived(REPO, p)]
        self.assertEqual(missing, [])

    def test_hand_written_files_do_not_carry_it(self) -> None:
        module = load()
        for path in ("scripts/gen-intake-records.py", "pyproject.toml", "release/cosign.pub"):
            self.assertFalse(module.is_derived(REPO, path), path)

    def test_the_ruff_step_names_no_corpus(self) -> None:
        step = re.search(r"- name: ruff\n\s+run: (uv run ruff check [^\n]*)", ci_text())
        assert step, "the ruff step is missing"
        self.assertNotRegex(step.group(1), r"vectors-[a-z]", "a corpus is listed by name")
        self.assertIn("corpora/vectors-*", step.group(1))

    def test_ruff_excludes_name_existing_paths(self) -> None:
        text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
        config = tomllib.loads(text)["tool"]["ruff"]
        self.assertTrue(config["force-exclude"])
        stale = [p for p in config["extend-exclude"] if not (REPO / p).exists()]
        self.assertEqual(stale, [], "an exclusion names a path that is gone; delete it")

    def test_ci_checks_every_derived_file_in_one_step(self) -> None:
        text = ci_text()
        self.assertIn("scripts/regenerate-derived.py --check", text)
        self.assertNotIn("scripts/gen-intake-records.py --check", text)

    def test_the_lock_is_a_regeneration_step(self) -> None:
        scripts = [script for _, script in load().STEPS]
        self.assertIn(LOCK_DIR + "/lock_sources.py", scripts)
        for script in scripts:
            self.assertTrue((REPO / script).is_file(), script)

    def test_the_jcsvectors_copies_are_a_regeneration_step(self) -> None:
        scripts = [script for _, script in load().STEPS]
        self.assertIn("scripts/gen-jcsvectors-data.py", scripts)
        module = load()
        for path in ("jcsvectors/digests.go", "crates/jcsvectors/src/files.rs",
                     "crates/jcsvectors/npm/digests.mjs",
                     "jcsvectors/jcs-byte-vectors/cases.json",
                     "crates/jcsvectors/data/jcs-byte-vectors/cases.json",
                     "crates/jcsvectors/npm/data/jcs-byte-vectors/cases.json"):
            self.assertTrue(module.is_derived(REPO, path), path)
        for path in ("jcsvectors/jcsvectors.go", "crates/jcsvectors/src/lib.rs"):
            self.assertFalse(module.is_derived(REPO, path), path)

    def test_a_stale_lock_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in (
                LOCK_DIR + "/lock_sources.py",
                LOCK_DIR + "/source-lock.json",
                LOCK_DIR + "/selection.json",
                "interop/agentavow-live-mcp/definition_pin.py",
                "packaging/run_vectors.py",
            ):
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy(REPO / rel, root / rel)
            lock = root / LOCK_DIR / "lock_sources.py"
            ran = subprocess.run([sys.executable, str(lock), "--check"], capture_output=True)
            self.assertEqual(ran.returncode, 0, ran.stdout)
            with (root / "packaging/run_vectors.py").open("a", encoding="utf-8") as handle:
                handle.write("# changed\n")
            ran = subprocess.run([sys.executable, str(lock), "--check"], capture_output=True)
            self.assertEqual(ran.returncode, 1)
            subprocess.run([sys.executable, str(lock)], check=True)
            ran = subprocess.run([sys.executable, str(lock), "--check"], capture_output=True)
            self.assertEqual(ran.returncode, 0)


class RunSteps(unittest.TestCase):
    def fake_repo(self, root: Path, exits: list[int]) -> list[tuple[str, str]]:
        """One script per exit status; each records that it ran."""
        steps = []
        for index, code in enumerate(exits):
            script = root / f"step{index}.py"
            script.write_text(
                "import pathlib, sys\n"
                "ran = pathlib.Path(sys.argv[0]).with_suffix('.ran')\n"
                "ran.write_text(' '.join(sys.argv[1:]))\n"
                f"raise SystemExit({code})\n",
                encoding="utf-8",
            )
            steps.append((f"step {index}", script.name))
        return steps

    def test_a_check_runs_every_step_after_a_failure(self) -> None:
        module = load()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            module.STEPS = self.fake_repo(root, [0, 1, 1])
            self.assertEqual(module.run_steps(root, True), 1)
            for index in range(3):
                ran = root / f"step{index}.ran"
                self.assertTrue(ran.exists(), f"step {index} did not run")
                self.assertEqual(ran.read_text(encoding="utf-8"), "--check")

    def test_a_write_stops_at_the_first_failure(self) -> None:
        module = load()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            module.STEPS = self.fake_repo(root, [0, 1, 0])
            self.assertEqual(module.run_steps(root, False), 1)
            self.assertTrue((root / "step1.ran").exists())
            self.assertFalse((root / "step2.ran").exists())

    def test_a_clean_check_passes(self) -> None:
        module = load()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            module.STEPS = self.fake_repo(root, [0, 0])
            self.assertEqual(module.run_steps(root, True), 0)

class ResolveMerge(unittest.TestCase):
    def repo_with_two_branches(self, root: Path, extra: bool) -> None:
        git(root, "init", "-q", "-b", "main")
        git(root, "config", "user.email", "t@example.org")
        git(root, "config", "user.name", "t")
        (root / ".gitattributes").write_text("gen/** derived\n", encoding="utf-8")
        (root / "gen").mkdir()
        (root / "gen/a.json").write_text('{"pin": "base"}\n', encoding="utf-8")
        (root / "hand.txt").write_text("base\n", encoding="utf-8")
        git(root, "add", "-A")
        git(root, "commit", "-q", "-m", "base")
        git(root, "switch", "-q", "-c", "side")
        (root / "gen/a.json").write_text('{"pin": "side"}\n', encoding="utf-8")
        if extra:
            (root / "hand.txt").write_text("side\n", encoding="utf-8")
        git(root, "commit", "-qam", "side")
        git(root, "switch", "-q", "main")
        (root / "gen/a.json").write_text('{"pin": "main"}\n', encoding="utf-8")
        if extra:
            (root / "hand.txt").write_text("main\n", encoding="utf-8")
        git(root, "commit", "-qam", "main")
        self.assertNotEqual(git(root, "merge", "side", check=False).returncode, 0)

    def test_derived_only_conflicts_are_regenerated_and_staged(self) -> None:
        module = load()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.repo_with_two_branches(root, extra=False)
            calls: list[int] = []

            def regenerate() -> int:
                calls.append(1)
                (root / "gen/a.json").write_text('{"pin": "derived"}\n', encoding="utf-8")
                return 0

            self.assertEqual(module.resolve_merge(root, regenerate), 0)
            self.assertEqual(calls, [1])
            self.assertEqual(module.unmerged(root), [])
            self.assertEqual(git(root, "show", ":gen/a.json").stdout, '{"pin": "derived"}\n')

    def test_a_conflict_in_a_hand_written_file_is_refused_untouched(self) -> None:
        module = load()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.repo_with_two_branches(root, extra=True)
            before = sorted(module.unmerged(root))

            def regenerate() -> int:
                raise AssertionError("must not regenerate over a hand conflict")

            self.assertEqual(module.resolve_merge(root, regenerate), 1)
            self.assertEqual(sorted(module.unmerged(root)), before)

    def test_a_failed_regeneration_is_reported(self) -> None:
        module = load()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.repo_with_two_branches(root, extra=False)
            self.assertEqual(module.resolve_merge(root, lambda: 1), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
