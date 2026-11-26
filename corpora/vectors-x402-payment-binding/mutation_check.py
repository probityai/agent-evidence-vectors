#!/usr/bin/env python3
"""Prove every rule in the reference reader is load-bearing.

    uv run python corpora/vectors-x402-payment-binding/mutation_check.py

For each rule in x402binding.RULES (both verdict tables), this switches that rule
off alone, re-reads every member, and requires that at least one member not
verified twice now gets a different answer. A verifier with that rule removed is a
mutant the corpus must catch. In the other direction, switching a rule off must
never move a member that is verified twice.

Exit 0 when every rule is load-bearing and no accepted member depends on a rule
being absent.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "packaging"))

from agent_evidence_vectors import x402binding  # noqa: E402

ROOT = Path(__file__).resolve().parent


def _accepted(expected: dict[str, dict[str, str]]) -> bool:
    return all(expected[v]["state"] == x402binding.VERIFIED for v in x402binding.VERDICTS)


def sweep(root: Path = ROOT) -> list[str]:
    """Return every defect the sweep finds; empty when every rule is load-bearing."""
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    defects: list[str] = []
    for rule in x402binding.RULES:
        moved: list[str] = []
        for entry in entries:
            answer = x402binding.verify(root / entry["path"] / "case.json", frozenset({rule}))
            expected = entry["expected"]
            if _accepted(expected):
                if answer != expected:
                    defects.append(f"{rule}: switching it off moves accepted {entry['id']}")
            elif answer != expected:
                moved.append(entry["id"])
        if moved:
            print(f"{rule}: load-bearing on {', '.join(moved)}")
        else:
            defects.append(f"{rule}: switching it off changes no member")
    return defects


def main() -> int:
    defects = sweep()
    for defect in defects:
        print(defect, file=sys.stderr)
    print(f"{len(x402binding.RULES)} rules swept, {len(defects)} defects")
    return 1 if defects else 0


if __name__ == "__main__":
    raise SystemExit(main())
