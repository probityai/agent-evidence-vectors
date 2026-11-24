#!/usr/bin/env python3
"""The freshness gate fails on a stale record and ignores only the stamped header.

Each case writes a pair of reports into a temporary directory and runs
``scripts/report-fresh-gate.py --fresh`` against a copy of the gate that reads
that pair as the committed record.

Usage: python3 scripts/report-fresh-gate-test.py
Exit 0 when every case behaves as described; 1 otherwise.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "report-fresh-gate.py"


def load_gate() -> Any:
    spec = importlib.util.spec_from_file_location("report_fresh_gate", GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def judge(work: Path, committed: dict[str, object], fresh: dict[str, object]) -> int:
    gate = load_gate()
    (work / "committed.json").write_text(json.dumps(committed), encoding="utf-8")
    (work / "fresh.json").write_text(json.dumps(fresh), encoding="utf-8")
    gate.COMMITTED = work / "committed.json"
    argv = sys.argv
    sys.argv = [str(GATE), "--fresh", str(work / "fresh.json")]
    try:
        return int(gate.main())
    finally:
        sys.argv = argv


BASE: dict[str, object] = {"suite": "s", "totals": {"vectors": 2}, "vectors": [{"id": "a"}]}


def case_an_equal_report_passes(work: Path) -> None:
    assert judge(work, BASE, dict(BASE)) == 0


def case_only_the_header_may_differ(work: Path) -> None:
    fresh = {**BASE, "verifierResult": {"corpus": "new"}}
    committed = {**BASE, "verifierResult": {"corpus": "old"}}
    assert judge(work, committed, fresh) == 0, "a different header failed the gate"
    assert judge(work, BASE, fresh) == 0, "a record with no header failed the gate"


def case_a_changed_vector_row_fails(work: Path) -> None:
    fresh = {**BASE, "vectors": [{"id": "a", "verdict": "changed"}]}
    assert judge(work, BASE, fresh) == 1, "a stale vector row passed the gate"


def case_a_changed_total_fails(work: Path) -> None:
    fresh = {**BASE, "totals": {"vectors": 3}}
    assert judge(work, BASE, fresh) == 1, "a stale total passed the gate"


def case_an_unreadable_report_is_not_a_pass(work: Path) -> None:
    gate = load_gate()
    (work / "fresh.json").write_text("[1]", encoding="utf-8")
    (work / "committed.json").write_text(json.dumps(BASE), encoding="utf-8")
    gate.COMMITTED = work / "committed.json"
    argv = sys.argv
    sys.argv = [str(GATE), "--fresh", str(work / "fresh.json")]
    try:
        assert gate.main() == 2, "a report that is not an object passed the gate"
    finally:
        sys.argv = argv


CASES: list[Callable[[Path], None]] = [
    case_an_equal_report_passes,
    case_only_the_header_may_differ,
    case_a_changed_vector_row_fails,
    case_a_changed_total_fails,
    case_an_unreadable_report_is_not_a_pass,
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
