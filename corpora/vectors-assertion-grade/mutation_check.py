#!/usr/bin/env python3
"""Prove every rule in the assertion-grade reader is load-bearing.

uv run python corpora/vectors-assertion-grade/mutation_check.py

For each rule in assertiongrade.RULES, this switches that rule off alone, re-reads every member,
and requires that at least one rejected member now gets a different answer (another grade,
accepted, or refused for another reason). A rule whose removal changes nothing measures nothing.
In the other direction, switching a rule off must never turn an accepted member into a refusal.

Exit 0 when every rule is load-bearing and no accepted member depends on a rule being absent.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "packaging"))

import run_vectors  # noqa: E402, F401
from agent_evidence_vectors import assertiongrade  # noqa: E402

ROOT = Path(__file__).resolve().parent


def sweep(root: Path = ROOT) -> list[str]:
    """Return every defect the sweep finds; empty when every rule is load-bearing."""
    entries = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"]
    defects: list[str] = []
    for rule in assertiongrade.RULES:
        moved: list[str] = []
        for entry in entries:
            answer = assertiongrade.verify(root / entry["path"] / "case.json", frozenset({rule}))
            expected = entry["expected"]
            if expected["decision"] == assertiongrade.ACCEPTED:
                if answer["decision"] != assertiongrade.ACCEPTED:
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
    print(f"{len(assertiongrade.RULES)} rules swept, {len(defects)} defects")
    return 1 if defects else 0


if __name__ == "__main__":
    raise SystemExit(main())
