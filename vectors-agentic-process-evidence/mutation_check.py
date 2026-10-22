#!/usr/bin/env python3
"""Prove every rule in the reference reader is load-bearing.

    uv run python vectors-agentic-process-evidence/mutation_check.py

check_vectors.py answers "does the corpus behave as the manifest claims". This
answers the question a green suite cannot answer about itself: would any member
still get the same answer if the rule were not there?

For each rule in agenticprocess.RULES, this switches that rule off alone,
re-reads every member, and requires that at least one member now gets a
different answer. A rule whose removal changes nothing measures nothing.

Exit 0 when every rule is load-bearing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packaging"))

import run_vectors  # noqa: E402, F401  (the reader borrows its Ed25519)
from agent_evidence_vectors import agenticprocess  # noqa: E402

ROOT = Path(__file__).resolve().parent


def sweep(root: Path = ROOT) -> list[str]:
    """Return every defect the sweep finds; empty when every rule is load-bearing."""
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    defects: list[str] = []
    for rule in agenticprocess.RULES:
        moved = []
        for entry in manifest["vectors"]:
            answer = agenticprocess.verify(root / entry["path"] / "case.json", frozenset({rule}))
            if answer != entry["expected"]:
                moved.append(f"{entry['id']} -> {answer['decision']}/{answer['reason']}")
        if moved:
            print(f"{rule}: load-bearing on {', '.join(moved)}")
        else:
            defects.append(f"{rule}: switching it off changes no member")
    return defects


def main() -> int:
    defects = sweep()
    for defect in defects:
        print(defect, file=sys.stderr)
    print(f"{len(agenticprocess.RULES)} rules swept, {len(defects)} defects")
    return 1 if defects else 0


if __name__ == "__main__":
    raise SystemExit(main())
