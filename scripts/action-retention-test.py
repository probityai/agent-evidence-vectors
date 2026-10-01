#!/usr/bin/env python3
"""The action's report retention is an input, and the upload step reads it.

Why this file exists
--------------------
The upload step kept the report for a fixed thirty days. A consumer who needed
the report longer, or wanted it gone sooner, had to fork the action. The
`retention-days` input now carries that number, with the old value as its
default so a consumer who sets nothing sees no change.

The cases read action.yml as YAML rather than grepping it, so a value moved to
a comment or a different step does not pass. The last case writes the fixed
number back into a copy and requires this file to go red against the copy.

Usage: python3 scripts/action-retention-test.py
Exit 0 when every case behaves as described; 1 otherwise.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
ACTION = Path(os.environ.get("AEV_ACTION_UNDER_TEST", REPO_ROOT / "action.yml"))
README = REPO_ROOT / "README.md"
EXPRESSION = "${{ inputs.retention-days }}"
UPLOAD = "actions/upload-artifact@"
# The fixed period every release before the input used.
OLD_DEFAULT = "30"


def action() -> dict[str, Any]:
    loaded: dict[str, Any] = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    return loaded


def upload_step() -> dict[str, Any]:
    steps = [s for s in action()["runs"]["steps"] if str(s.get("uses", "")).startswith(UPLOAD)]
    assert len(steps) == 1, f"expected one upload step, found {len(steps)}"
    step: dict[str, Any] = steps[0]
    return step


def case_input_declared_with_old_default(work: Path) -> None:
    del work
    spec = action()["inputs"].get("retention-days")
    assert isinstance(spec, dict), "action.yml declares no retention-days input"
    assert spec.get("required") is False, "retention-days must be optional"
    got = str(spec.get("default"))
    assert got == OLD_DEFAULT, f"default is {got!r}, not the old {OLD_DEFAULT}"


def case_upload_reads_the_input(work: Path) -> None:
    del work
    got = upload_step()["with"].get("retention-days")
    assert got == EXPRESSION, f"upload step retention-days is {got!r}, not {EXPRESSION}"


def case_readme_documents_it(work: Path) -> None:
    del work
    text = README.read_text(encoding="utf-8")
    assert "| `retention-days` |" in text, "README's input table has no retention-days row"


def case_mutation_goes_red(work: Path) -> None:
    """With the fixed number restored, this file must fail."""
    if os.environ.get("AEV_ACTION_UNDER_TEST"):
        return
    text = ACTION.read_text(encoding="utf-8")
    anchor = f"        retention-days: {EXPRESSION}\n"
    assert anchor in text, "mutation anchor moved; update this test"
    copy = work / "action.yml"
    fixed = f"        retention-days: {OLD_DEFAULT}\n"
    copy.write_text(text.replace(anchor, fixed), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, __file__],
        env={**os.environ, "AEV_ACTION_UNDER_TEST": str(copy)},
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0, "this test stayed green against a fixed retention period"


CASES: list[Callable[[Path], None]] = [
    case_input_declared_with_old_default,
    case_upload_reads_the_input,
    case_readme_documents_it,
    case_mutation_goes_red,
]


def main() -> int:
    failed = 0
    for case in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                case(Path(tmp))
                print(f"ok   {case.__name__}")
            except AssertionError as exc:
                failed += 1
                print(f"FAIL {case.__name__}: {exc}")
    print(f"{len(CASES) - failed}/{len(CASES)} cases passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
