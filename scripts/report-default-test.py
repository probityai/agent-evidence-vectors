#!/usr/bin/env python3
"""A harness run never overwrites the committed conformance report.

Why this file exists
--------------------
``packaging/conformance-report.json`` is a committed record, and until this test
existed the harness wrote its default report beside itself, which in a checkout
is that very file. Any run that named no ``--report`` replaced it: a corpus smoke
run lost 12,415 lines of the record on a branch and a person restored it by hand,
and the replay tests under ``scripts/`` replace it with the report of a mutated
corpus every time they run. A run is an observation. It writes where its caller
looks, which is the working directory, and a caller who wants the committed
record replaced says so by naming that path.

Each case reads the fact it is about, from the report bytes themselves. The
mutation case restores the old default in a copy of the harness and requires this
file to go red against the copy.

Usage: python3 scripts/report-default-test.py
Exit 0 when every case behaves as described; 1 otherwise.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REAL_PACKAGING = REPO_ROOT / "packaging"
TRACKED = REAL_PACKAGING / "conformance-report.json"
CORPUS = REPO_ROOT / "vectors"
HARNESS_UNDER_TEST_ENV = "AEV_HARNESS_UNDER_TEST"

# The one line that sends a defaulted report beside the harness again.
MUTATION_OLD = "    return str(args.report) if args.report else REPORT_NAME\n"
MUTATION_NEW = (
    "    return str(args.report) if args.report else os.path.join(\n"
    '        os.path.dirname(os.path.abspath(__file__)), "conformance-report.json"\n'
    "    )\n"
)


def harness_path(packaging: Path) -> Path:
    override = os.environ.get(HARNESS_UNDER_TEST_ENV)
    return Path(override) if override else packaging / "run_vectors.py"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def copy_of_packaging(work: Path) -> Path:
    """A private copy of packaging/ so a broken harness cannot touch the real record."""
    target = work / "packaging"
    shutil.copytree(REAL_PACKAGING, target, ignore=shutil.ignore_patterns("__pycache__"))
    return target


def run(argv: list[str], cwd: Path, harness: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(harness), *argv],
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
    )


def case_default_report_goes_to_the_working_directory(work: Path) -> None:
    packaging = copy_of_packaging(work)
    before = digest(packaging / "conformance-report.json")
    cwd = work / "elsewhere"
    cwd.mkdir()
    proc = run(["--vectors", str(CORPUS)], cwd, harness_path(packaging))
    assert proc.returncode == 0, f"corpus run exited {proc.returncode}: {proc.stderr[-400:]}"
    assert digest(packaging / "conformance-report.json") == before, (
        "a corpus run with no --report replaced the committed report"
    )
    written = cwd / "conformance-report.json"
    assert written.is_file(), "the run wrote no report in its working directory"
    report = json.loads(written.read_text(encoding="utf-8"))
    assert report["totals"]["vectors"] > 0, "the working-directory report holds no vectors"
    assert "verifierResult" in report, "the working-directory report was never stamped"


def case_default_inside_packaging_is_refused(work: Path) -> None:
    packaging = copy_of_packaging(work)
    tracked = packaging / "conformance-report.json"
    before = digest(tracked)
    proc = run(["--vectors", str(CORPUS)], packaging, harness_path(packaging))
    assert proc.returncode == 2, (
        f"a defaulted report aimed at the committed file exited {proc.returncode}, not 2"
    )
    assert "--report" in proc.stderr, f"the refusal does not name --report: {proc.stderr!r}"
    assert digest(tracked) == before, "the refused run still replaced the committed report"


def case_naming_the_committed_report_asks_for_it(work: Path) -> None:
    packaging = copy_of_packaging(work)
    tracked = packaging / "conformance-report.json"
    tracked.write_text('{"stale": "record"}\n', encoding="utf-8")
    proc = run(
        ["--vectors", str(CORPUS), "--report", str(tracked)], packaging, harness_path(packaging)
    )
    assert proc.returncode == 0, (
        f"an explicit report path exited {proc.returncode}: {proc.stderr[-400:]}"
    )
    report = json.loads(tracked.read_text(encoding="utf-8"))
    assert report.get("totals", {}).get("vectors", 0) > 0, (
        "naming the committed report did not write it"
    )


def case_runtime_mode_obeys_the_same_rule(work: Path) -> None:
    packaging = copy_of_packaging(work)
    tracked = packaging / "conformance-report.json"
    before = digest(tracked)
    proc = run(
        ["runtime", "--runtime", "true", "--vectors", str(CORPUS)],
        packaging,
        harness_path(packaging),
    )
    assert proc.returncode == 2, (
        f"runtime mode aimed at the committed file exited {proc.returncode}"
    )
    assert "--report" in proc.stderr, (
        f"runtime mode refused for another reason than the committed report: {proc.stderr!r}"
    )
    assert digest(tracked) == before, "runtime mode replaced the committed report"


def case_the_real_record_is_untouched(work: Path) -> None:
    """The run above used copies; the checked-in file itself must still read as committed."""
    del work
    committed = subprocess.run(
        ["git", "show", "HEAD:packaging/conformance-report.json"],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
    )
    if committed.returncode != 0:
        return  # not a git checkout: nothing to compare against
    assert hashlib.sha256(committed.stdout).hexdigest() == digest(TRACKED), (
        "packaging/conformance-report.json differs from HEAD: a run of this "
        "repository's own tests replaced it"
    )


def case_old_default_goes_red(work: Path) -> None:
    """With the default restored beside the harness, this file must fail."""
    if os.environ.get(HARNESS_UNDER_TEST_ENV):
        return
    text = (REAL_PACKAGING / "run_vectors.py").read_text(encoding="utf-8")
    assert MUTATION_OLD in text, "the default-report line moved; update this test"
    copy_dir = copy_of_packaging(work / "mutant")
    mutant = copy_dir / "run_vectors.py"
    mutant.write_text(text.replace(MUTATION_OLD, MUTATION_NEW), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, __file__],
        env={**os.environ, HARNESS_UNDER_TEST_ENV: str(mutant)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0, (
        "this test stayed green against a harness that writes beside itself"
    )


CASES: list[Callable[[Path], None]] = [
    case_default_report_goes_to_the_working_directory,
    case_default_inside_packaging_is_refused,
    case_naming_the_committed_report_asks_for_it,
    case_runtime_mode_obeys_the_same_rule,
    case_the_real_record_is_untouched,
    case_old_default_goes_red,
]


def main() -> int:
    failed = 0
    for case in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                case(Path(tmp))
            except AssertionError as exc:
                failed += 1
                print(f"FAIL {case.__name__}: {exc}")
            else:
                print(f"ok   {case.__name__}")
    print(f"{len(CASES) - failed}/{len(CASES)} cases behave as described")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
