#!/usr/bin/env python3
"""Each dating rule revision 01 adds is pinned by its own retained member.

Rows R10 to R16 of draft-gilda-audit-agent-audit-record-01 add the
opentimestamps anchor (its proof checked against block headers the manifest
pins, its time compared with a 7200-second tolerance) and the delegation-root
result. The dating sweep in check_vectors.py asks only that each rule move some
member. This test asks that each rule move the member whose row names it, that
R14 never report the root as a pass, and that each malformed entry (R11, R15)
returns to its parent's result once its one mutation is restored, so it fails
for its stated reason and no other.

Usage: uv run --extra generators python scripts/audit-record-dating-rows-test.py
Exit 0 when every case holds; 1 with a summary of the failures.
"""

from __future__ import annotations

import json
import sys
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
    for line in failures:
        print("FAIL", line)
    print(f"{len(CASES) + 3 - len(failures)} of {len(CASES) + 3} checks hold")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
