#!/usr/bin/env python3
"""The committed conformance report is the report the harness writes today.

``packaging/conformance-report.json`` is a committed record. A run of the harness
never replaces it unless asked, so nothing refreshes it, and a corpus change
leaves it describing a corpus that no longer exists. This gate runs the harness
into ``.build/fresh-report.json`` and fails when that report differs from the
committed one anywhere except the ``verifierResult`` header, which names the
corpus release and digest the run was stamped against.

On a difference it prints the command that regenerates the record:

    python3 packaging/run_vectors.py --report packaging/conformance-report.json --replace-record

Usage: python3 scripts/report-fresh-gate.py [--fresh PATH]
``--fresh`` compares an already written report instead of running the harness
(for the gate's own test). Exit 0 when the record is current; 1 when it differs;
2 when a report could not be read or the harness failed to run.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
COMMITTED = REPO_ROOT / "packaging" / "conformance-report.json"
HARNESS = REPO_ROOT / "packaging" / "run_vectors.py"
FRESH = REPO_ROOT / ".build" / "fresh-report.json"
HEADER = "verifierResult"
REGENERATE = (
    "python3 packaging/run_vectors.py --report packaging/conformance-report.json --replace-record"
)


def load(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError(f"{path} is not a JSON object")
    return document


def differences(fresh: dict[str, Any], committed: dict[str, Any]) -> list[str]:
    """The top-level members that differ, ignoring the stamped header."""
    keys = sorted((set(fresh) | set(committed)) - {HEADER})
    return [key for key in keys if fresh.get(key) != committed.get(key)]


def vector_differences(fresh: dict[str, Any], committed: dict[str, Any]) -> list[str]:
    """The ids of vector rows that differ, when both reports carry a vectors list."""
    fresh_rows, committed_rows = fresh.get("vectors"), committed.get("vectors")
    if not (isinstance(fresh_rows, list) and isinstance(committed_rows, list)):
        return []
    mine = {str(v.get("id")): v for v in fresh_rows if isinstance(v, dict)}
    theirs = {str(v.get("id")): v for v in committed_rows if isinstance(v, dict)}
    return [i for i in sorted(set(mine) | set(theirs)) if mine.get(i) != theirs.get(i)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fresh", default=None)
    ns = ap.parse_args()
    fresh_path = Path(ns.fresh) if ns.fresh else FRESH
    if ns.fresh is None:
        fresh_path.parent.mkdir(exist_ok=True)
        run = subprocess.run(
            [sys.executable, str(HARNESS), "--report", str(fresh_path)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        if run.returncode != 0 or not fresh_path.is_file():
            print(f"FAIL: the harness exited {run.returncode} and wrote no fresh report")
            print((run.stdout + run.stderr)[-600:])
            return 2
    try:
        fresh, committed = load(fresh_path), load(COMMITTED)
    except (OSError, ValueError) as exc:
        print(f"FAIL: a report could not be read: {exc}")
        return 2
    members = differences(fresh, committed)
    if not members:
        print("ok   packaging/conformance-report.json is the report the harness writes today")
        return 0
    rows = vector_differences(fresh, committed)
    print(f"FAIL packaging/conformance-report.json is stale: {len(members)} member(s) differ")
    print(f"  members: {', '.join(members)}")
    if rows:
        print(f"  vector rows: {len(rows)} differ, first: {', '.join(rows[:5])}")
    print(f"  regenerate it with: {REGENERATE}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
