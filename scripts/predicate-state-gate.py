#!/usr/bin/env python3
"""Predicate-state equivalence gate: the three empty states are ONE input.

WHAT IT CHECKS. `spec/v1/statement.md` says a verifier treats an absent
`predicate` member, `"predicate": null` and `"predicate": {}` as one input and
emits the identical verdict and the identical reason codes for all three. This
gate runs both rails this repository ships over the three vectors that carry
condition `aee-c-109` and refuses unless every outcome is identical: across the
three states within each rail, and between the two rails.

WHY IT IS A SEPARATE GATE RATHER THAN A CORPUS EXPECTATION. The corpus harness
cannot express this rule. `vectors/MANIFEST.json` declares its own comparison
surface -- verdict, and for an accepted statement its result -- and says of a
reject vector's codes that "a differing code is a reason-parity datum rather
than a failure". The scoring matches that: `_eval_reject_stages` fails only when
the INTERSECTION of the declared and observed code sets is empty. So two rails
that reject the same statement for entirely different reasons both pass, and
adding the three vectors alone would not have caught the divergence they exist
to catch. That contract is correct for a THIRD-PARTY rail, whose vocabulary is
its own; it is wrong for the two rails in this repository, which share one code
vocabulary, so a divergence between them is a defect rather than a datum.

WHY THE RULE IS CHECKED WITHIN A RAIL AND NOT ONLY ACROSS THEM. The three states
are all invalid for this predicate -- the empty predicate is missing every
required member -- so the verdict is `invalid` whichever way a rail reads them.
The whole observable content of the equivalence rule is therefore the REASON, and
a check on verdicts alone would have passed every version of both rails,
including the ones that answered `statement-malformed`, the six-code set, and
`predicate-type-unsupported` for the three spellings of one input.

WHY IT DOES NOT TRUST THE VECTOR IDS. Ids are digests of vector bytes, so they
move whenever the corpus is regenerated. The three are found by their condition
id in the MANIFEST, and the gate refuses if it does not find exactly three.

WHY IT CHECKS THE VECTORS AGAINST EACH OTHER FIRST. Three statements that differ
in more than the `predicate` member would make an equivalence comparison
meaningless -- any difference in the answer could come from the other edit. The
gate therefore proves the fixtures are a controlled triple before it compares
any rail's answers, and that check is the positive control for the rest: if the
three files ever stop being one statement in three spellings, this fails here
rather than reporting a clean sweep of a comparison that measured nothing.

Usage: python3 scripts/predicate-state-gate.py
Exit 0 when every outcome is identical; 1 on any divergence or on any read that
could not be performed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
CONDITION = "aee-c-109"
STATES = 3

sys.path.insert(0, str(REPO_ROOT / "packaging"))

import run_vectors  # noqa: E402


def manifest() -> dict[str, Any]:
    with open(REPO_ROOT / "vectors" / "MANIFEST.json", encoding="utf-8") as handle:
        loaded: dict[str, Any] = json.load(handle)
    return loaded


def triple(man: dict[str, Any]) -> list[dict[str, Any]]:
    """The vectors carrying the equivalence condition, or a refusal.

    Found by condition rather than by id: an id is a digest of the vector's own
    bytes and moves on every regeneration, so a gate holding three literal ids
    would start reading nothing the first time the corpus was rebuilt, and a
    lookup that finds nothing reads exactly like a corpus with nothing to find.
    """
    rows = [v for v in man["vectors"] if CONDITION in (v.get("conditions") or [])]
    if len(rows) != STATES:
        print(
            f"FAIL: {len(rows)} vector(s) cite {CONDITION}; this gate requires "
            f"exactly {STATES}, one per empty predicate state. The equivalence "
            "rule is unforced without all three, and a missing state is how the "
            "two rails came to disagree about this member with every gate green.",
            file=sys.stderr,
        )
        return []
    return sorted(rows, key=lambda v: str(v["id"]))


def statement_of(row: dict[str, Any]) -> tuple[bytes, Any]:
    path = REPO_ROOT / "vectors" / str(row["file"])
    raw = path.read_bytes()
    return raw, json.loads(raw.decode("utf-8"))


def controlled_triple(rows: list[dict[str, Any]]) -> list[str]:
    """Refuse unless the three differ in the `predicate` member and nothing else.

    This is the gate's own positive control. Every comparison below asks whether
    three inputs that should be one produce one answer; that question is empty if
    the three inputs differ in some other member, because then a differing answer
    has an innocent cause and an identical answer proves nothing about the rule.
    """
    findings: list[str] = []
    spellings: list[str] = []
    others: list[tuple[str, str]] = []
    for row in rows:
        _, value = statement_of(row)
        if not isinstance(value, dict):
            findings.append(f"{row['id']}: the vector is not a JSON object")
            continue
        rest = {k: v for k, v in value.items() if k != "predicate"}
        others.append((str(row["id"]), json.dumps(rest, sort_keys=True)))
        if "predicate" not in value:
            spellings.append("absent")
        elif value["predicate"] is None:
            spellings.append("null")
        elif value["predicate"] == {}:
            spellings.append("empty-object")
        else:
            findings.append(
                f"{row['id']}: `predicate` is neither absent, null nor the empty "
                "object, so it is not one of the three states this condition is "
                "about"
            )
    if len(set(spellings)) != len(spellings) or (
        spellings and set(spellings) != {"absent", "null", "empty-object"}
    ):
        findings.append(
            "the three vectors do not spell the three distinct states: found "
            f"{sorted(spellings)}. One state covered twice leaves another covered "
            "not at all"
        )
    distinct = {body for _, body in others}
    if len(distinct) > 1:
        findings.append(
            "the three vectors differ somewhere other than the `predicate` "
            "member, so nothing below would be measuring the equivalence rule: "
            + ", ".join(vid for vid, _ in others)
        )
    return findings


def build_cli(dest_dir: str) -> str:
    """Build cmd/aee-verify, or fail. Never returns without a binary."""
    binary = os.path.join(dest_dir, "aee-verify")
    try:
        proc = subprocess.run(
            ["go", "build", "-o", binary, "./cmd/aee-verify"],
            cwd=REPO_ROOT,
            capture_output=True,
            timeout=600,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(
            f"FAIL: cmd/aee-verify could not be built ({exc}). This gate needs a "
            "Go toolchain and does not skip: half a differential check reports a "
            "clean sweep of one rail as agreement between two.",
            file=sys.stderr,
        )
        sys.exit(1)
    if proc.returncode != 0:
        print(
            "FAIL: cmd/aee-verify did not build:\n"
            + proc.stderr.decode("utf-8", "replace"),
            file=sys.stderr,
        )
        sys.exit(1)
    return binary


def go_outcomes(rows: list[dict[str, Any]], binary: str) -> dict[str, tuple[str, tuple[str, ...]]]:
    out: dict[str, tuple[str, tuple[str, ...]]] = {}
    for row in rows:
        path = str(REPO_ROOT / "vectors" / str(row["file"]))
        parsed = run_vectors.run_external([binary, "-json"], path, None, "predicate-state")
        errors = parsed.get("errors") or []
        verdict = parsed.get("verdict")
        if errors or not verdict:
            print(
                f"FAIL: the Go rail returned no readable outcome for {row['id']}: "
                f"{parsed!r}. A rail that did not answer is not a rail that "
                "agreed.",
                file=sys.stderr,
            )
            sys.exit(1)
        out[str(row["id"])] = (str(verdict), tuple(sorted(parsed.get("codes") or [])))
    return out


def python_outcomes(rows: list[dict[str, Any]]) -> dict[str, tuple[str, tuple[str, ...]]]:
    ref = run_vectors.ReferenceVerifier([])
    out: dict[str, tuple[str, tuple[str, ...]]] = {}
    for row in rows:
        raw, value = statement_of(row)
        outcome = ref.verify(value, raw)
        out[str(row["id"])] = (outcome.verdict, tuple(sorted(outcome.codes)))
    return out


def equivalence_findings(
    label: str, outcomes: dict[str, tuple[str, tuple[str, ...]]]
) -> list[str]:
    answers = set(outcomes.values())
    if len(answers) == 1:
        return []
    detail = "; ".join(
        f"{vid}: {verdict} {list(codes)}" for vid, (verdict, codes) in sorted(outcomes.items())
    )
    return [
        f"{label} answers the three empty predicate states differently, so the "
        f"spelling the producer chose is observable in its output: {detail}"
    ]


def cross_rail_findings(
    go: dict[str, tuple[str, tuple[str, ...]]],
    py: dict[str, tuple[str, tuple[str, ...]]],
) -> list[str]:
    findings: list[str] = []
    for vid in sorted(go):
        if go[vid] != py.get(vid):
            findings.append(
                f"{vid}: the Go rail says {go[vid][0]} {list(go[vid][1])} and the "
                f"Python rail says {py[vid][0]} {list(py[vid][1])}. Both rails "
                "here share one code vocabulary, so this is a defect and not the "
                "reason-parity datum the MANIFEST's comparison surface permits a "
                "third-party rail."
            )
    return findings


def main() -> int:
    rows = triple(manifest())
    if not rows:
        return 1

    findings = controlled_triple(rows)
    if findings:
        for finding in findings:
            print(f"FAIL: {finding}", file=sys.stderr)
        return 1

    py = python_outcomes(rows)
    with tempfile.TemporaryDirectory() as tmp:
        go = go_outcomes(rows, build_cli(tmp))

    findings = (
        equivalence_findings("the Python rail", py)
        + equivalence_findings("the Go rail", go)
        + cross_rail_findings(go, py)
    )
    if findings:
        for finding in findings:
            print(f"FAIL: {finding}", file=sys.stderr)
        return 1

    verdict, codes = next(iter(py.values()))
    print(
        f"OK: both rails answer all {STATES} empty predicate states identically: "
        f"{verdict}, {list(codes)}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
