#!/usr/bin/env python3
"""Cross-rail parity: the two first-party rails, replayed over every member.

WHY THIS EXISTS, AS WHAT HAPPENED RATHER THAN AS A PRINCIPLE.

The Python rail declined to run the result recompute when the predicate carried
no readable observation vocabulary or no rows, guarding on
``labels is not None and caught is not None and rows``. The Go rail built empty
carried sets and proceeded. On a statement carrying ``attackResults: []``, a
coverage map accounting for every manifested attack, and a declared ``result``
the recompute does not derive, the Go rail answered INVALID
(``result-recompute-mismatch``) and the Python rail answered VALID -- and
published a result token the predicate's own definition never produces. Two
first-party rails, one corpus, opposite verdicts on identical bytes.

Nothing in this repository could see it. ``aee/vectors_test.go`` asserts that
the Go rail's PRIMARY code is a member of the vector's declared set.
``scripts/observed-code-closure-gate.py`` pins what the PYTHON rail emits, in
the manifest, and says so in its own words: it is "a check over the REFERENCE
rail", singular, and it imports ``run_vectors``. Each rail was measured against
the corpus and neither was ever measured against the other. The defect lived in
the gap between two gates that each looked complete.

WHAT THIS GATE COMPARES, AND WHAT IT REFUSES.

For every member of ``vectors/`` -- the Adversarial Execution Evidence corpus,
the one corpus both rails judge with the same predicate evaluator -- it runs the
Python ``ReferenceVerifier`` and the shipped ``cmd/aee-verify`` over identical
bytes under identical key policy, and compares two things:

- **the verdict**, where any difference is an UNCONDITIONAL refusal. A verdict
  split is the class the defect above belonged to: one rail admits a statement
  the other refuses, which is the only disagreement that reaches a consumer as
  a different decision. It can never be baselined away.
- **the code set**, where a difference must be recorded, per member, in
  ``docs/RAIL-PARITY-BASELINE.json`` with its cause. An unrecorded difference is
  a refusal; so is a recorded one that no longer holds, or whose recorded sets
  have moved.

WHY THE CODE SETS ARE A RATCHET AND NOT AN EQUALITY.

Because the two rails report on different principles, and both are conformant.
The Go pipeline stops at the first failing gate -- ``Evaluate`` returns Gate 0's
codes and never reaches Gate 1 -- so it reports the earliest independent fault
and nothing after it. The Python rail runs every check and accumulates, so it
reports every independent fault it can see. ``vectors/MANIFEST.json`` declares
which of the two surfaces is normative: the verdict, and an accepted statement's
result token. It calls the codes on a reject entry "the reference verifier's own
vocabulary, not the specification's", and README says a strict single-code
implementation and a superset-emitting one certify against one manifest.

So an equality assertion over the code sets would be red on arrival -- thirty of
the two hundred and seventy four members differ today -- and making it green
would mean rewriting one rail's reporting architecture to match the other's,
which would promote this repository's private reporting style into an obligation
the manifest promises not to impose. A ratchet keeps the real guarantee (no NEW
divergence, and none at all on the verdict) without inventing that obligation.

WHAT THE BASELINE CANNOT DO, STATED SO NOBODY READS IT AS MORE.

It compares the rails on the shapes the CORPUS carries. The defect above was
reachable only on a shape no vector carried, so this gate, run the day before
the fix, would have passed. The vector is what puts the shape into the
membership; the gate is what stops the next one drifting once it is there.
``ve3c7f7a8d918c70c`` is that vector and the two are one change on purpose.

Usage:
    python3 scripts/rail-parity-gate.py            # write the baseline
    python3 scripts/rail-parity-gate.py --check    # compare against it (CI)

Exit 0 when the verdicts agree everywhere and every code-set difference is the
recorded one; 1 otherwise.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
SUITE = REPO_ROOT / "vectors"
BASELINE = REPO_ROOT / "docs" / "RAIL-PARITY-BASELINE.json"

sys.path.insert(0, str(REPO_ROOT / "packaging"))
import run_vectors  # noqa: E402


def _baseline_name() -> str:
    """The baseline's path as a reader should see it.

    Repository-relative in the ordinary case, absolute when the gate is driven
    over a baseline outside the tree -- which its own test does. A message that
    raises while explaining a refusal turns a finding into a crash and loses
    the finding.
    """
    try:
        return str(BASELINE.relative_to(REPO_ROOT))
    except ValueError:
        return str(BASELINE)


def _load_external_rail_gate() -> Any:
    """Import ``scripts/external-rail-gate.py`` for its CLI builder.

    There is ONE place in this repository that turns ``cmd/aee-verify`` into a
    binary and refuses rather than skips when the Go toolchain is absent, and
    it is that gate's ``build_cli``. A second copy here would be a second thing
    to keep in step with the module path, the build flags and the refusal
    wording, and the two would drift the first time either moved.
    """
    import importlib.util

    path = REPO_ROOT / "scripts" / "external-rail-gate.py"
    spec = importlib.util.spec_from_file_location("aee_external_rail_gate", str(path))
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot import the external-rail gate at {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _manifest_rows() -> list[dict[str, Any]]:
    manifest = json.loads((SUITE / "MANIFEST.json").read_text(encoding="utf-8"))
    rows = manifest.get("vectors") or manifest.get("index") or []
    if not rows:
        raise SystemExit(
            f"FAIL: {SUITE / 'MANIFEST.json'} carries no vectors; this gate has "
            "nothing to replay and must not report a pass for an empty walk"
        )
    return [dict(r) for r in rows]


def _python_answer(
    verifier: Any, raw: bytes
) -> tuple[str, list[str]]:
    stmt, _faithful = run_vectors._load_statement(raw)
    out = verifier.verify(stmt, raw)
    codes = sorted(set(out.codes))
    return ("invalid" if out.codes else "valid"), codes


def _go_answer(binary: str, policy: str, path: Path) -> tuple[str, list[str]]:
    proc = subprocess.run(
        [binary, "-keys", policy, "-json", str(path)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    line = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else ""
    try:
        report = json.loads(line)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"FAIL: aee-verify wrote no readable report for {path.name}: {exc}. "
            f"stdout={proc.stdout[:400]!r} stderr={proc.stderr[:400]!r}. This is "
            "the gate failing to RUN, never a finding about the rails."
        ) from exc
    return str(report.get("verdict")), sorted(set(report.get("codes") or []))


def _classify(go_only: list[str], py_only: list[str]) -> str:
    """Name the shape of one divergence. Descriptive, never exculpatory."""
    if go_only and py_only:
        return "each rail reports a code the other does not"
    if py_only:
        return (
            "the Go pipeline stopped at an earlier gate and never reached the "
            "check that produced these"
        )
    return (
        "the Go rail reports a code this rail does not derive at all on these "
        "bytes"
    )


def measure() -> tuple[list[dict[str, Any]], list[str]]:
    """Replay both rails. Returns (divergences, verdict-split refusals)."""
    gate = _load_external_rail_gate()
    keys = run_vectors.derive_test_keys()
    verifier = run_vectors.ReferenceVerifier([keys[run_vectors.PINNED_ROLE]["public"]])

    divergences: list[dict[str, Any]] = []
    verdict_splits: list[str] = []

    with tempfile.TemporaryDirectory() as work:
        binary = gate.build_cli(work)
        policy = run_vectors.write_pinned_key_policy(keys, work)
        for row in _manifest_rows():
            path = SUITE / row["file"]
            raw = path.read_bytes()
            py_verdict, py_codes = _python_answer(verifier, raw)
            go_verdict, go_codes = _go_answer(binary, policy, path)
            if py_verdict != go_verdict:
                verdict_splits.append(
                    f"{row['id']} ({row['kind']}): the Go rail answers "
                    f"{go_verdict!r} with {go_codes} and this rail answers "
                    f"{py_verdict!r} with {py_codes}. A verdict split is one "
                    "rail admitting a statement the other refuses, which is "
                    "the only disagreement a consumer sees as a different "
                    "decision, and it is never recorded as expected."
                )
                continue
            if py_codes != go_codes:
                go_only = sorted(set(go_codes) - set(py_codes))
                py_only = sorted(set(py_codes) - set(go_codes))
                divergences.append(
                    {
                        "id": row["id"],
                        "kind": row["kind"],
                        "goOnly": go_only,
                        "pythonOnly": py_only,
                        "cause": _classify(go_only, py_only),
                    }
                )
    divergences.sort(key=lambda d: str(d["id"]))
    return divergences, verdict_splits


def write_baseline(divergences: list[dict[str, Any]]) -> None:
    body = {
        "note": (
            "Per-member code-set divergence between the two first-party rails. "
            "The verdict is NOT recorded here and never can be: a verdict split "
            "is an unconditional refusal in scripts/rail-parity-gate.py. These "
            "rows exist because the Go pipeline stops at the first failing gate "
            "and the Python rail accumulates every independent fault, which "
            "vectors/MANIFEST.json already declares measured rather than "
            "normative. The list is a ratchet: a new row is a refusal until "
            "somebody writes it down, and a row that has stopped describing the "
            "corpus is a refusal too."
        ),
        "members": len(_manifest_rows()),
        "divergences": divergences,
    }
    BASELINE.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    print(
        f"wrote {_baseline_name()}: {len(divergences)} code-set "
        f"divergence(s) over {body['members']} members"
    )


def check(divergences: list[dict[str, Any]], verdict_splits: list[str]) -> int:
    failures: list[str] = list(verdict_splits)
    if not BASELINE.exists():
        print(
            f"FAIL: no baseline at {_baseline_name()}. Write one "
            "with `python3 scripts/rail-parity-gate.py` and read it before "
            "committing it.",
            file=sys.stderr,
        )
        return 1
    recorded = json.loads(BASELINE.read_text(encoding="utf-8"))
    by_id = {str(d["id"]): d for d in recorded.get("divergences", [])}
    seen = {str(d["id"]): d for d in divergences}

    for vid, observed in seen.items():
        expected = by_id.get(vid)
        if expected is None:
            failures.append(
                f"{vid} ({observed['kind']}): the rails now disagree on the code "
                f"set and no baseline row records it. Go alone reports "
                f"{observed['goOnly']}, this rail alone reports "
                f"{observed['pythonOnly']}. Either the change that caused it is "
                "wrong, or it is right and the row belongs in "
                f"{_baseline_name()} with its cause."
            )
        elif (
            sorted(expected.get("goOnly", [])) != observed["goOnly"]
            or sorted(expected.get("pythonOnly", [])) != observed["pythonOnly"]
        ):
            failures.append(
                f"{vid}: the recorded divergence has moved. Recorded goOnly="
                f"{sorted(expected.get('goOnly', []))} pythonOnly="
                f"{sorted(expected.get('pythonOnly', []))}; observed goOnly="
                f"{observed['goOnly']} pythonOnly={observed['pythonOnly']}."
            )
    for vid in by_id:
        if vid not in seen:
            failures.append(
                f"{vid}: a baseline row records a divergence the rails no longer "
                "have. A pin that has stopped describing the corpus is what "
                "hides the next change to it; delete the row in the same commit "
                "that closed the divergence."
            )

    if failures:
        print("FAIL: the two first-party rails do not agree as recorded:", file=sys.stderr)
        for line in failures:
            print(f"  - {line}", file=sys.stderr)
        return 1
    print(
        f"OK: {len(_manifest_rows())} vectors replayed on both rails — every "
        f"verdict agrees and all {len(divergences)} code-set divergence(s) are "
        "the recorded ones."
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare against the committed baseline and write nothing",
    )
    args = parser.parse_args(argv)
    divergences, verdict_splits = measure()
    if args.check:
        return check(divergences, verdict_splits)
    if verdict_splits:
        print(
            "REFUSED: the rails disagree on a VERDICT, which this baseline "
            "cannot record. Fix the rails; there is nothing to write.",
            file=sys.stderr,
        )
        for line in verdict_splits:
            print(f"  - {line}", file=sys.stderr)
        return 1
    write_baseline(divergences)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
