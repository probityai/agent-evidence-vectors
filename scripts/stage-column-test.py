#!/usr/bin/env python3
"""The stage columns of a reject vector, held against first-refusal verifiers.

Why this file exists
--------------------
A reject vector may name codes at more than one stage. Vectors
``vf35474dd75d6b14a`` and ``v87a339f53f689d9f`` name ``result-vocabulary``
(gate0) and ``result-recompute-mismatch`` (recompute). A verifier that stops at
its first refusal reports only the gate0 code, which is a correct refusal: the
row's status is PASS. The harness nevertheless printed FAIL in the recompute
column, because it marked every stage whose expected code was not observed as
FAIL, including a stage the verifier never reached. A reviewer running the
suite against such a component read a FAIL beside a passing vector and could
not interpret the table.

The harness now prints ``unreached`` for a stage after the verifier's refusal,
when that refusal used a code the vector names. Every other case keeps its
FAIL: a stage before the refusal that was skipped, and any stage when the rail
refused only for reasons the vector does not name.

Usage: python3 scripts/stage-column-test.py
Exit 0 when every case behaves as described; 1 otherwise.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "vectors" / "MANIFEST.json"

sys.path.insert(0, str(REPO_ROOT / "packaging"))

import run_vectors  # noqa: E402

TWO_STAGE_VECTORS = ("vf35474dd75d6b14a", "v87a339f53f689d9f")
EARLY = "result-vocabulary"
LATE = "result-recompute-mismatch"


def manifest_entry(vector_id: str) -> dict[str, Any]:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    for entry in manifest["vectors"]:
        if entry["id"] == vector_id:
            typed: dict[str, Any] = entry
            return typed
    raise SystemExit(f"the MANIFEST carries no vector {vector_id}, which this test reads.")


def score(entry: dict[str, Any], codes: list[str]) -> tuple[bool, dict[str, str]]:
    observed = {"verdict": "invalid", "codes": codes}
    ev = run_vectors.evaluate_vector_detailed(entry["kind"], entry, observed, None)
    return ev.ok, ev.gates


def check(label: str, got: dict[str, str], want: dict[str, str]) -> list[str]:
    return [
        f"{label}: {stage} reads {got[stage]!r}, expected {value!r} (gates {got})"
        for stage, value in want.items()
        if got[stage] != value
    ]


def cases(vector_id: str) -> list[str]:
    entry = manifest_entry(vector_id)
    expected = set(entry["expected"]["codes"])
    if expected != {EARLY, LATE}:
        return [
            f"{vector_id}: expected codes are {sorted(expected)}, "
            f"this test reads {EARLY} and {LATE}"
        ]
    errors: list[str] = []

    # The defect: a first-refusal verifier stops at gate0.
    ok, gates = score(entry, [EARLY])
    if not ok:
        errors.append(f"{vector_id} first-refusal: status is not PASS")
    errors += check(
        f"{vector_id} first-refusal",
        gates,
        {"gate0": "PASS", "recompute": run_vectors.STAGE_NOT_REACHED},
    )

    # Control: a verifier reporting both codes passes both stages.
    _ok, gates = score(entry, [EARLY, LATE])
    errors += check(f"{vector_id} both-codes", gates, {"gate0": "PASS", "recompute": "PASS"})

    # Control: a stage BEFORE the refusal that was skipped is still a failure.
    _ok, gates = score(entry, [LATE])
    errors += check(f"{vector_id} skipped-earlier", gates, {"gate0": "FAIL", "recompute": "PASS"})

    # Control: a refusal for a reason the vector does not name proves nothing
    # about how far the verifier got, so the expected stages stay FAIL.
    _ok, gates = score(entry, ["batch-root-mismatch"])
    errors += check(f"{vector_id} unnamed-reason", gates, {"gate0": "FAIL", "recompute": "FAIL"})
    return errors


def main() -> int:
    errors: list[str] = []
    for vector_id in TWO_STAGE_VECTORS:
        errors += cases(vector_id)
    for error in errors:
        print(f"FAIL {error}")
    if errors:
        return 1
    print(f"stage-column-test: {4 * len(TWO_STAGE_VECTORS)} cases pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
