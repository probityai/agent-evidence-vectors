"""The axis cases the Go done reader is held to, judged by the Python reader.

The receipt's two verdicts combine the five checks' verdicts: the outcome axis is the
acceptance check's own, and the integrity axis takes the worst hard contradiction (tamper,
then gaming, then deception, then check order), else the first open check that is not
excused, else support with the narrower witness scope. The corpora reach a few of these
combinations. This file builds every combination of a small set of verdicts per check and
keeps what the Python reader derives for each (the two axes without their check lists,
``accepted`` and the receipt's decision) in ``corpora/testdata/done-axes.json.gz``. The Go
test ``TestDoneAxesAgreeWithPython`` combines the same verdicts and requires the same
answers. Regenerate with:

    AEV_WRITE_DONE_AXES=1 uv run --extra dev pytest \\
        vectors-done-receipt/tests/test_done_axis_cases.py
"""

from __future__ import annotations

import gzip
import itertools
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packaging"))

from agent_evidence_vectors import donechecks as chk  # noqa: E402

FIXTURE = ROOT / "corpora" / "testdata" / "done-axes.json.gz"


def contradicted(reason: str, scope: str) -> dict[str, Any]:
    return {"decision": "contradicted", "reason": reason, "vantage": "independent",
            "witness_scope": scope}


# The verdicts each integrity check takes in turn. "excused" is replaced per check by the
# reason the receipt excuses for that check, where it has one.
INTEGRITY_OPTIONS: tuple[dict[str, Any], ...] = (
    {"decision": "supported", "reason": "ok", "vantage": "independent"},
    {"decision": "supported", "reason": "ok", "vantage": "independent",
     "witness_scope": "EXTERNAL", "unwitnessed_scope_claims": ["c1"]},
    {"decision": "supported", "reason": "ok", "vantage": "independent",
     "witness_scope": "EXTERNAL"},
    {"decision": "not_established", "reason": "open", "vantage": "unestablished"},
    {"decision": "not_established", "reason": "excused", "vantage": "unestablished"},
    contradicted("probe_determinism_failed", "PEER"),
    contradicted("protected_path_mutated", "EXTERNAL"),
    contradicted("tool_claim_unmatched", "PEER"),
    contradicted("tool_claim_precedes_last_edit", "EXTERNAL"),
)
OUTCOME_OPTIONS: tuple[dict[str, Any], ...] = (
    {"decision": "supported", "reason": "acceptance_passed_in_verifier",
     "vantage": "independent", "witness_scope": "EXTERNAL", "unwitnessed_scope_claims": ["c2"]},
    {"decision": "supported", "reason": "acceptance_passed_in_verifier",
     "vantage": "independent"},
    contradicted("acceptance_failed_in_verifier", "PEER"),
    {"decision": "not_established", "reason": "grade_unavailable", "vantage": "unestablished"},
)
EXCUSED = {chk.PROBES: "no_probes", chk.TOOLS: "no_tool_claims"}


def verdict(claim_type: str, option: dict[str, Any]) -> dict[str, Any]:
    out = {**option, "claim_type": claim_type}
    if out["reason"] == "excused":
        out["reason"] = EXCUSED.get(claim_type, "excused")
    return out


def without_checks(axis: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in axis.items() if key != "checks"}


def answer(pick: tuple[int, ...]) -> dict[str, Any]:
    verdicts = {chk.ACCEPTANCE: verdict(chk.ACCEPTANCE, OUTCOME_OPTIONS[pick[0]])}
    for claim_type, index in zip(chk.INTEGRITY_TYPES, pick[1:], strict=True):
        verdicts[claim_type] = verdict(claim_type, INTEGRITY_OPTIONS[index])
    derived = chk.axes(verdicts)
    decision, reason, extra = chk._receipt_decision(derived["outcome"], derived["integrity"])
    return {"outcome": without_checks(derived["outcome"]),
            "integrity": without_checks(derived["integrity"]),
            "accepted": derived["accepted"], "receipt": [decision, reason, without_checks(extra)]}


def picks() -> list[tuple[int, ...]]:
    return list(itertools.product(range(len(OUTCOME_OPTIONS)),
                                  *[range(len(INTEGRITY_OPTIONS))] * len(chk.INTEGRITY_TYPES)))


def encoded() -> bytes:
    lines = [json.dumps({"pick": list(pick), "want": answer(pick)}, sort_keys=True,
                        separators=(",", ":"), ensure_ascii=True) for pick in picks()]
    head = json.dumps({"outcome_options": OUTCOME_OPTIONS, "integrity_options": INTEGRITY_OPTIONS,
                       "integrity_types": chk.INTEGRITY_TYPES, "excused": EXCUSED},
                      sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    body = '{"head":' + head + ',\n"cases":[\n' + ",\n".join(lines) + "\n]}\n"
    return gzip.compress(body.encode(), compresslevel=9, mtime=0)


def test_the_go_axis_cases_are_what_python_answers() -> None:
    if os.environ.get("AEV_WRITE_DONE_AXES") == "1":
        FIXTURE.write_bytes(encoded())
    assert gzip.decompress(FIXTURE.read_bytes()) == gzip.decompress(encoded()), (
        "corpora/testdata/done-axes.json.gz is not what the Python reader answers; "
        "regenerate it with AEV_WRITE_DONE_AXES=1")


def test_the_axis_cases_reach_every_answer() -> None:
    found = [json.loads(line.rstrip(",")) for line in
             gzip.decompress(FIXTURE.read_bytes()).decode().splitlines()[2:-1]]
    assert {item["want"]["integrity"]["decision"] for item in found} == set(chk.DECISIONS)
    assert {item["want"]["integrity"].get("class") for item in found} >= {
        "tamper", "gaming", "deception", "hygiene"}
    assert {item["want"]["receipt"][0] for item in found} == set(chk.DECISIONS)
    assert {item["want"]["integrity"].get("witness_scope") for item in found} >= {
        "PEER", "EXTERNAL"}
