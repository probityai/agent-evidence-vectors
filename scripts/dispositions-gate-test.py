#!/usr/bin/env python3
"""The disposition gate's own tests, which are mostly refusals.

This repository has shipped a verifier that scored zero against its own corpus
while its unit test passed, and it has shipped several checks that ran green
while enforcing nothing. So a gate evidenced only by a green run is a known
failure shape here, and every case below drives the gate to a NON-ZERO exit and
asserts the reason it gave — not merely that it refused, but that it refused for
the fault the case introduced. A test asserting only the exit status passes when
the gate refuses everything, which is the other way to enforce nothing.

Each case stages a copy of the files the gate reads, breaks exactly one thing in
the copy, and runs the gate against it with --root. Nothing here writes to the
repository it is testing.

The first case is the control and it is not optional: it stages the copy
unmutated and requires a PASS. Without it, every refusal below would also be
produced by a staging bug, and the suite would report a working gate over a tree
it had failed to assemble.

Usage:
    python3 scripts/dispositions-gate-test.py
Exit 0 when every case behaves as declared; 1 on the first that does not.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "dispositions-gate.py"
LEDGER = "docs/DISPOSITIONS.json"
PUBLISHED = "DISPOSITIONS.md"

# Everything the gate reads. The recordedIn anchors reach outside the ledger, so
# the staged tree has to carry those files too or the control case would fail for
# a reason no test introduced.
STAGED = (
    LEDGER,
    PUBLISHED,
    "vectors/CHANGES.md",
    "vectors/MANIFEST.json",
    "docs/ADOPTION.md",
    "docs/interpretation-decisions-open.md",
)

Mutate = Callable[[Path], None]


def stage(root: Path) -> None:
    for rel in STAGED:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPO_ROOT / rel, target)


def run(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 -- running this repository's own gate is the point
        [sys.executable, str(GATE), "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )


def edit_ledger(root: Path, change: Callable[[dict[str, Any]], None]) -> None:
    path = root / LEDGER
    ledger = json.loads(path.read_text(encoding="utf-8"))
    change(ledger)
    path.write_text(json.dumps(ledger, indent=2), encoding="utf-8")


def unknown_revision(root: Path) -> None:
    edit_ledger(root, lambda led: led["entries"][0].__setitem__("landedAtRevision", 9999))


def unknown_vector(root: Path) -> None:
    edit_ledger(root, lambda led: led["entries"][0].__setitem__("vectors", ["bad-000-invented"]))


def broken_anchor(root: Path) -> None:
    edit_ledger(
        root,
        lambda led: led["entries"][0]["recordedIn"][0].__setitem__(
            "anchor", "a sentence no file in this repository contains"
        ),
    )


def unknown_resolution(root: Path) -> None:
    edit_ledger(root, lambda led: led["entries"][0].__setitem__("resolution", "noted"))


def residual_missing(root: Path) -> None:
    def change(ledger: dict[str, Any]) -> None:
        ledger["entries"][0]["resolution"] = "open"
        ledger["entries"][0]["residual"] = None

    edit_ledger(root, change)


def empty_reason(root: Path) -> None:
    edit_ledger(root, lambda led: led["entries"][0].__setitem__("reason", "   "))


def duplicate_id(root: Path) -> None:
    edit_ledger(root, lambda led: led["entries"][1].__setitem__("id", led["entries"][0]["id"]))


def empty_ledger(root: Path) -> None:
    edit_ledger(root, lambda led: led.__setitem__("entries", []))


def table_edited(root: Path) -> None:
    """The row a reader sees is changed and the ledger is not.

    This is the failure the render exists to catch: a resolution word rewritten
    in the published table alone changes what a committee reads and leaves every
    other check passing.
    """
    path = root / PUBLISHED
    path.write_text(
        path.read_text(encoding="utf-8").replace("**declined**", "**adopted**", 1),
        encoding="utf-8",
    )


def appeal_heading_deleted(root: Path) -> None:
    path = root / PUBLISHED
    path.write_text(
        path.read_text(encoding="utf-8").replace(
            "## If you disagree with a disposition", "## Notes", 1
        ),
        encoding="utf-8",
    )


# Each case: what it breaks, and the phrase the refusal has to carry. The phrase
# is asserted so that a gate refusing for some other reason fails the case.
CASES: tuple[tuple[str, Mutate, str], ...] = (
    ("a landing revision the changelog does not carry", unknown_revision, "owns revision"),
    ("a forcing vector the corpus does not contain", unknown_vector, "is not in vectors/MANIFEST"),
    ("a cited record that no longer carries its phrase", broken_anchor, "no longer carries"),
    ("a resolution outside the declared vocabulary", unknown_resolution, "is not one of"),
    ("an unresolved row with no residual", residual_missing, "absorbing a gap"),
    ("a row whose reason is blank", empty_reason, "says nothing"),
    ("two rows sharing an identifier", duplicate_id, "more than once"),
    ("a ledger with no entries at all", empty_ledger, "enforcing nothing"),
    ("the published table edited and the ledger left alone", table_edited, "is not the one"),
    ("the appeal route's heading deleted", appeal_heading_deleted, "has lost the heading"),
)


def check_control(root: Path) -> str | None:
    stage(root)
    result = run(root)
    if result.returncode != 0:
        return (
            "CONTROL: the unmutated staged copy was refused, so every refusal below "
            f"could be a staging bug rather than a check.\n{result.stdout}{result.stderr}"
        )
    return None


def check_case(root: Path, label: str, mutate: Mutate, expected: str) -> str | None:
    stage(root)
    mutate(root)
    result = run(root)
    if result.returncode == 0:
        return f"{label}: the gate PASSED a tree carrying this fault."
    if expected not in result.stderr:
        return (
            f"{label}: the gate refused, but not for this fault. Expected a message "
            f"carrying {expected!r}.\n{result.stderr}"
        )
    return None


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "control"
        if failure := check_control(root):
            print(failure, file=sys.stderr)
            return 1
        print("  OK  control: the unmutated staged copy passes")
        for index, (label, mutate, expected) in enumerate(CASES):
            case_root = Path(tmp) / f"case{index}"
            if failure := check_case(case_root, label, mutate, expected):
                failures.append(failure)
            else:
                print(f"  OK  refused: {label}")
    if failures:
        print(f"\nFAIL: {len(failures)} case(s) did not behave as declared:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    print(f"\nOK: the control passes and all {len(CASES)} declared faults are refused.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
