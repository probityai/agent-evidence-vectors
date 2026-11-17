#!/usr/bin/env python3
"""Each dating rule revision 01 adds is pinned by its own retained member.

Rows R10 to R16 of draft-gilda-audit-agent-audit-record-01 add the
opentimestamps anchor (its proof checked against block headers the manifest
pins, its time compared with a 7200-second tolerance) and the delegation-root
result. R17 and R18 pin that tolerance on the late (anchorWithin) bound, and
R19 to R22 sit exactly on the bounds R3, R6, R7 and R11 are one second past:
with every tolerance one second shorter each on-bound member turns malformed
under its pair's code, and with every tolerance one second longer each
past-bound member turns well-formed, so a reader whose comparison is off by
one at any bound is caught. The dating sweep in check_vectors.py asks only that each rule move some
member. This test asks that each rule move the member whose row names it, that
R14 never report the root as a pass, and that each malformed entry (R11, R15)
returns to its parent's result once its one mutation is restored, so it fails
for its stated reason and no other.

Usage: uv run --extra generators python scripts/audit-record-dating-rows-test.py
Exit 0 when every case holds; 1 with a summary of the failures.
"""

from __future__ import annotations

import datetime
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "corpora" / "vectors-agent-audit-record"
sys.path.insert(0, str(REPO_ROOT / "packaging"))

import run_vectors  # noqa: E402,F401  (the reader resolves the rail's Ed25519 through it)
from agent_evidence_vectors import auditrecord  # noqa: E402

CASES = (
    ("R10", "opentimestamps-tolerance"),
    ("R11", "entry-received-after-anchor"),
    ("R12", "anchor-validation"),
    ("R13", "entry-delegation-root"),
    ("R15", "entry-delegation-root"),
    ("R16", "anchor-validation"),
    ("R17", "opentimestamps-tolerance"),
    ("R18", "entry-anchor-late"),
    ("R22", "opentimestamps-tolerance"),
)

#: Each dating bound as a pair of members: the first sits exactly on the bound,
#: the second one second past it, with the code the second is refused under.
BOUND_PAIRS = (
    ("R19", "R3", "entry-received-after-anchor"),
    ("R20", "R6", "entry-received-before-issued"),
    ("R21", "R7", "entry-anchor-late"),
    ("R22", "R11", "entry-received-after-anchor"),
    ("R17", "R18", "entry-anchor-late"),
)


def main() -> int:
    manifest = json.loads((CORPUS / "MANIFEST.json").read_text())
    policy = auditrecord.policy_for(manifest)
    trust = auditrecord.tree_heads(manifest)
    members = {v["draftId"]: v for v in manifest["vectors"] if "dating" in v["expected"]}
    raw = {k: (CORPUS / v["file"]).read_bytes() for k, v in members.items()}
    want = {k: v["expected"]["dating"] for k, v in members.items()}
    failures: list[str] = []

    def date(body: bytes, disabled: str | None = None) -> tuple[str, dict[str, Any]]:
        report, dated = auditrecord.verify_retained(body, policy, trust, disabled=disabled)
        return report.verdict, auditrecord.dating_dict(dated)

    for row, rule in CASES:
        verdict, got = date(raw[row])
        if verdict != "valid" or got != want[row]:
            failures.append(f"{row}: got {verdict} and {got}, want valid and {want[row]}")
        if date(raw[row], rule)[1] == want[row]:
            failures.append(f"{row}: disabling {rule} leaves its dating result unmoved")
    if want["R14"]["delegationRoot"] != {"result": "not-established"}:
        failures.append("R14 must report the root not established, never a pass")

    def restored(row: str, parent: str, field: str, index: int | None = None) -> None:
        child, source = json.loads(raw[row]), json.loads(raw[parent])
        if index is None:
            child["retention"][field] = source["retention"][field]
        else:
            child["retention"][field][index] = source["retention"][field][index]
        got = date(json.dumps(child).encode())[1]
        if got != want[parent]:
            failures.append(f"{row} with its mutation restored dates {got}, want {parent}'s")

    restored("R11", "R10", "anchors", 1)
    restored("R15", "R13", "validationData")
    restored("R18", "R17", "anchors", 1)

    failures.extend(bound_pair_failures(raw, want, date))
    for line in failures:
        print("FAIL", line)
    total = len(CASES) + 4 + 3 * len(BOUND_PAIRS)
    print(f"{total - len(failures)} of {total} checks hold")
    return 1 if failures else 0


def bound_pair_failures(
    raw: dict[str, bytes],
    want: dict[str, dict[str, Any]],
    date: Callable[[bytes], tuple[str, dict[str, Any]]],
) -> list[str]:
    """Each pair straddles its bound: one second less tolerance refuses the
    on-bound member under its pair's code, one second more admits the other."""

    def shifted(seconds: int) -> dict[str, dict[str, Any]]:
        saved = auditrecord.SKEW_TOLERANCE, auditrecord.OTS_TOLERANCE
        step = datetime.timedelta(seconds=seconds)
        auditrecord.SKEW_TOLERANCE, auditrecord.OTS_TOLERANCE = saved[0] + step, saved[1] + step
        try:
            rows = {row for pair in BOUND_PAIRS for row in pair[:2]}
            return {row: date(raw[row])[1] for row in rows}
        finally:
            auditrecord.SKEW_TOLERANCE, auditrecord.OTS_TOLERANCE = saved

    failures: list[str] = []
    shorter, longer = shifted(-1), shifted(1)
    for on, past, code in BOUND_PAIRS:
        if want[on]["entry"] != "well-formed" or want[past]["codes"] != [code]:
            failures.append(f"{on} and {past} do not straddle the bound {code} names")
        if shorter[on].get("codes") != [code]:
            failures.append(f"{on} with every tolerance one second shorter: {shorter[on]}")
        if longer[past].get("entry") != "well-formed":
            failures.append(f"{past} with every tolerance one second longer: {longer[past]}")
    return failures


if __name__ == "__main__":
    sys.exit(main())
