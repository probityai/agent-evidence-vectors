#!/usr/bin/env python3
"""Prove every rule in the reference reader is load-bearing.

    uv run python vectors-grade-floor/mutation_check.py

check_vectors.py answers "does the corpus behave as the manifest claims". This
answers the question a green suite cannot answer about itself: would any member
still be refused, for the same reason, if the rule were not there?

For each rule in gradefloor.RULES, this switches that rule off alone, re-reads
every member, and requires that at least one rejected member now gets a
different answer (accepted, or refused for another reason). A rule whose
removal changes nothing measures nothing. In the other direction, switching a
rule off must never turn an accepted member into a refusal.

Exit 0 when every rule is load-bearing and no accepted member depends on a rule
being absent.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packaging"))

from agent_evidence_vectors import gradefloor  # noqa: E402

ROOT = Path(__file__).resolve().parent


def sweep(root: Path = ROOT) -> list[str]:
    """Return every defect the sweep finds; empty when every rule is load-bearing."""
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    defects: list[str] = []
    for rule in gradefloor.RULES:
        moved: list[str] = []
        for entry in entries:
            answer = gradefloor.verify(root / entry["path"] / "case.json", frozenset({rule}))
            expected = entry["expected"]
            if expected["decision"] == gradefloor.ACCEPTED:
                if answer["decision"] != gradefloor.ACCEPTED:
                    defects.append(f"{rule}: switching it off refuses accepted {entry['id']}")
            elif answer != expected:
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
    print(f"{len(gradefloor.RULES)} rules swept, {len(defects)} defects")
    return 1 if defects else 0


if __name__ == "__main__":
    raise SystemExit(main())
