#!/usr/bin/env python3
"""Replay the done corpora through probity-verify and compare every verdict.

probity-verify (``packages/probity-verify`` of probityai/probity) is the implementation
the done rules come from; this repository's readers restate them. A member whose every
declared verdict probity-verify reaches too is a member whose verdict does not rest on
one implementation. For each member and each check it declares, the script runs the
member's case and policy through ``probity_verify.adjudicate`` and compares the check's
place on an axis (``done_receipt.entry``); for a member that declares the five checks it
compares the outcome and integrity verdicts ``done_receipt.combine_*`` give; for the
done-contract corpus it compares which contracts ``done_records.contract`` refuses. A
refusal is compared as a refusal: the codes are this repository's own.

Given ``--examples <dir>`` it also runs this repository's reader over probity-verify's
own done-receipt examples (``packages/probity-verify/examples/done-receipt``) and
compares each verdict with probity-verify's.

    uv run --group crosscheck python vectors-done-receipt/crosscheck_probity_verify.py \\
        vectors-done-contract vectors-done-receipt vectors-spoofed-tool-output \\
        vectors-test-tampering vectors-grader-isolation

Exit 0 when every verdict agrees but those listed in ``KNOWN``, 1 on a disagreement,
2 when nothing was compared.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from probity_verify import adjudicate  # pyright: ignore[reportMissingImports]
from probity_verify.adapters import (  # pyright: ignore[reportMissingImports]
    done_receipt,
    done_records,
)
from probity_verify.common import (  # pyright: ignore[reportMissingImports]
    MAX_ARTIFACT_BYTES,
    CaseError,
)
from probity_verify.json_input import parse_json  # pyright: ignore[reportMissingImports]

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packaging"))

from agent_evidence_vectors import donechecks, donerecords  # noqa: E402

RECEIPT_KEYS = ("decision", "reason", "vantage", "witness_scope", "unwitnessed_scope_claims",
                "receipt_valid", "accepted")
# Members where the readers refuse what probity-verify decides, by design: a protected
# file the verifier judges by its Python syntax tree (spec/predicates/done-records.md).
KNOWN = {("equivalence-with-sources", "protected_paths/v1"),
         ("equivalence-with-sources", "done_receipt/v2")}


def _load(path: Path) -> Any:
    """Read a control file the way probity-verify's command line does."""
    return parse_json(path.read_bytes(), max_bytes=MAX_ARTIFACT_BYTES, max_depth=32,
                      max_nodes=32768)


def verifier_verdict(member: Path, claim_type: str) -> dict[str, Any]:
    """probity-verify's verdict on one check of a member, as a corpus declares it."""
    name = donechecks.FILES[claim_type]
    try:
        result = adjudicate(_load(member / f"{name}.case.json"),
                            _load(member / f"{name}.policy.json"), member)
    except (OSError, ValueError, CaseError) as exc:
        return {"refused": type(exc).__name__}
    if claim_type == donechecks.RECEIPT:
        return {key: result[key] for key in RECEIPT_KEYS if key in result}
    found = done_receipt.entry(result)
    del found["claim_type"]
    return found


def _same(want: dict[str, Any], got: dict[str, Any]) -> bool:
    return ("refused" in want and "refused" in got) or want == got


def compare_member(entry: dict[str, Any], member: Path) -> tuple[int, list[str]]:
    expected = entry["expected"]
    compared, problems = 0, []
    entries = []
    for claim_type, want in expected.get("checks", {}).items():
        compared += 1
        got = verifier_verdict(member, claim_type)
        entries.append({"claim_type": claim_type, **got})
        if not _same(want, got) and (entry["id"], claim_type) not in KNOWN:
            problems.append(f"{entry['id']} {claim_type}: declared {want}, probity-verify {got}")
    if "integrity" in expected:
        compared += 1
        found = {item["claim_type"]: item for item in entries}
        outcome = done_receipt.combine_outcome([found[ct] for ct in donechecks.OUTCOME_TYPES])
        integrity = done_receipt.combine_integrity(
            [found[ct] for ct in donechecks.INTEGRITY_TYPES])
        got_axes = {"outcome": donechecks.axis_projection(outcome),
                    "integrity": donechecks.axis_projection(integrity),
                    "accepted": done_receipt.accepted(outcome, integrity)}
        want_axes = {key: expected[key] for key in ("outcome", "integrity", "accepted")}
        if got_axes != want_axes:
            problems.append(f"{entry['id']} axes: declared {want_axes}, probity-verify {got_axes}")
    return compared, problems


def compare_contract(entry: dict[str, Any], member: Path) -> tuple[int, list[str]]:
    """Which contract records probity-verify refuses; the statement rules are ours alone."""
    verdict = entry["expected"]["contract"]
    if verdict["verdict"] == "invalid" and not verdict["code"].startswith("contract_"):
        return 0, []
    try:
        done_records.contract((member / "contract.json").read_bytes())
        refused = False
    except CaseError:
        refused = True
    if refused != (verdict["verdict"] == "invalid"):
        return 1, [f"{entry['id']}: declared {verdict}, probity-verify refused={refused}"]
    return 1, []


def compare_corpus(root: Path) -> tuple[int, list[str]]:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    compared, problems = 0, []
    for entry in manifest["vectors"]:
        member = root / entry["path"]
        if "contract" in entry["expected"]:
            count, found = compare_contract(entry, member)
        else:
            count, found = compare_member(entry, member)
        compared += count
        problems += found
    return compared, problems


def compare_examples(root: Path) -> tuple[int, list[str]]:
    """This repository's reader against probity-verify on probity-verify's own examples."""
    compared, problems = 0, []
    for run in sorted(path for path in root.iterdir() if path.is_dir()):
        for claim_type, name in donechecks.FILES.items():
            if not (run / f"{name}.case.json").exists():
                continue
            compared += 1
            try:
                ours = donechecks.projection(donechecks.run_check(claim_type, run))
            except donerecords.RecordError as exc:
                ours = {"refused": exc.code}
            theirs = verifier_verdict(run, claim_type)
            if not _same(ours, theirs):
                problems.append(f"example {run.name} {claim_type}: reader {ours}, "
                                f"probity-verify {theirs}")
    return compared, problems


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("corpora", nargs="*", type=Path)
    parser.add_argument("--examples", type=Path,
                        help="probity-verify's examples/done-receipt directory")
    args = parser.parse_args(argv)
    compared, problems = 0, []
    for root in args.corpora:
        count, found = compare_corpus(root)
        print(f"{root}: compared {count}, {len(found)} disagreements")
        compared, problems = compared + count, problems + found
    if args.examples is not None:
        count, found = compare_examples(args.examples)
        print(f"{args.examples}: compared {count}, {len(found)} disagreements")
        compared, problems = compared + count, problems + found
    for line in problems:
        print(line)
    if not compared:
        return 2
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
