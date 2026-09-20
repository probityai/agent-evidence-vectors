#!/usr/bin/env python3
"""The rail-parity gate can fail, on each axis it claims to guard.

A gate nobody has seen refuse is a gate nobody has seen work. This exercises
``check()`` directly against synthetic measurements rather than re-running the
replay: the replay is what the gate itself runs in CI, over the real corpus and
the real binary, and repeating it here would cost five minutes to re-measure
something already measured while proving nothing about the comparison. What
needs proving is the comparison, and the comparison is pure.

Five refusals and one acceptance:

- a verdict split refuses even when the code-set baseline is otherwise perfect,
  which is the claim that a verdict split can never be recorded as expected;
- a code-set divergence no baseline row records refuses;
- a recorded divergence the rails no longer have refuses, so the baseline
  cannot go stale in the quiet direction;
- a recorded divergence whose sets have moved refuses;
- an absent baseline refuses rather than passing an unguarded corpus;
- and the matching case passes, so the refusals above are not a gate that
  refuses everything.

Usage: python3 scripts/rail-parity-gate-test.py
Exit 0 when every case behaves as declared; 1 otherwise.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent


def load_gate() -> Any:
    path = REPO_ROOT / "scripts" / "rail-parity-gate.py"
    spec = importlib.util.spec_from_file_location("aee_rail_parity_gate", str(path))
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot import the gate at {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DIVERGENCE = {
    "id": "vaaaaaaaaaaaaaaaa",
    "kind": "reject",
    "goOnly": [],
    "pythonOnly": ["caught-row-uncovered"],
    "cause": "the Go pipeline stopped at an earlier gate and never reached "
    "the check that produced these",
}


def run_case(
    gate: Any,
    name: str,
    baseline: dict[str, Any] | None,
    divergences: list[dict[str, Any]],
    verdict_splits: list[str],
    want: int,
    must_say: str,
) -> list[str]:
    """Run one case and return its findings (empty when it behaved)."""
    with tempfile.TemporaryDirectory() as work:
        path = Path(work) / "BASELINE.json"
        if baseline is not None:
            path.write_text(json.dumps(baseline), encoding="utf-8")
        gate.BASELINE = path
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            got = gate.check(divergences, verdict_splits)
        said = err.getvalue()
    findings = []
    if got != want:
        findings.append(f"{name}: gate returned {got}, expected {want}")
    if want == 1 and must_say not in said:
        findings.append(
            f"{name}: the refusal does not name what it refused. Expected the "
            f"text {must_say!r} in:\n{said}"
        )
    return findings


def main() -> int:
    gate = load_gate()
    # The real corpus is walked by _manifest_rows, which check() calls only to
    # print a count. Stub it so the cases below do not depend on the corpus.
    gate._manifest_rows = lambda: [{"id": "x", "kind": "reject", "file": "x"}]

    base_one = {"members": 1, "divergences": [DIVERGENCE]}
    moved = dict(DIVERGENCE, pythonOnly=["some-other-code"])

    cases = [
        (
            "matching baseline passes",
            base_one,
            [DIVERGENCE],
            [],
            0,
            "",
        ),
        (
            "a verdict split refuses under a perfect code baseline",
            base_one,
            [DIVERGENCE],
            ["vbbbb: the Go rail answers 'invalid' and this rail answers 'valid'"],
            1,
            "the Go rail answers",
        ),
        (
            "an unrecorded code-set divergence refuses",
            {"members": 1, "divergences": []},
            [DIVERGENCE],
            [],
            1,
            "no baseline row records it",
        ),
        (
            "a recorded divergence the rails no longer have refuses",
            base_one,
            [],
            [],
            1,
            "a divergence the rails no longer have",
        ),
        (
            "a recorded divergence whose sets moved refuses",
            base_one,
            [moved],
            [],
            1,
            "has moved",
        ),
        (
            "an absent baseline refuses",
            None,
            [],
            [],
            1,
            "no baseline at",
        ),
    ]

    findings: list[str] = []
    for name, baseline, divergences, splits, want, must_say in cases:
        findings.extend(
            run_case(gate, name, baseline, divergences, splits, want, must_say)
        )

    if findings:
        print("FAIL: the rail-parity gate does not refuse as declared:", file=sys.stderr)
        for line in findings:
            print(f"  - {line}", file=sys.stderr)
        return 1
    refusals = sum(1 for c in cases if c[4] == 1)
    print(
        f"OK: {len(cases)} case(s), of which {refusals} assert a refusal the gate "
        "makes and name the axis it makes it about."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
