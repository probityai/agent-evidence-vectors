#!/usr/bin/env python3
"""Each dating rule revision 01 adds is pinned by its own retained member.

Rows R10 to R16 of draft-gilda-audit-agent-audit-record-01 add the
opentimestamps anchor (its proof checked against block headers the manifest
pins, its time compared with a 7200-second tolerance) and the delegation-root
result. R23 and R24 pin that tolerance on the late (anchorWithin) bound, and
R19 to R22 sit exactly on the bounds R3, R6, R7 and R11 are one second past:
with every tolerance one second shorter each on-bound member turns malformed
under its pair's code, and with every tolerance one second longer each
past-bound member turns well-formed, so a reader whose comparison is off by
one at any bound is caught. R25 holds the root's key set to what a key set can show: it
records the key the chain verifier held and its algorithm family, and it never binds that key to a
party, so R13 and R25 report the binding not established, and an answer reporting it established
is scored as a disagreement. The dating sweep in check_vectors.py asks only that each rule move some
member. This test asks that each rule move the member whose row names it, that
R14 never report the root as a pass, and that each malformed entry (R11, R15)
returns to its parent's result once its one mutation is restored, so it fails
for its stated reason and no other.

Usage: uv run --extra generators python scripts/audit-record-dating-rows-test.py
Exit 0 when every case holds; 1 with a summary of the failures.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
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
    ("R23", "opentimestamps-tolerance"),
    ("R24", "entry-anchor-late"),
    ("R22", "opentimestamps-tolerance"),
    ("R25", "entry-delegation-root"),
)

#: The members whose delegation-root element is a key set, each with the
#: algorithm family its one key names.
KEY_SET_ROOTS = (("R13", "Ed25519"), ("R25", "P-256"))

#: Each dating bound as a pair of members: the first sits exactly on the bound,
#: the second one second past it, with the code the second is refused under.
BOUND_PAIRS = (
    ("R19", "R3", "entry-received-after-anchor"),
    ("R20", "R6", "entry-received-before-issued"),
    ("R21", "R7", "entry-anchor-late"),
    ("R22", "R11", "entry-received-after-anchor"),
    ("R23", "R24", "entry-anchor-late"),
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
    restored("R24", "R23", "anchors", 1)

    failures.extend(bound_pair_failures(raw, want, date))
    failures.extend(key_set_binding_failures(raw, want))
    for line in failures:
        print("FAIL", line)
    total = len(CASES) + 4 + 3 * len(BOUND_PAIRS) + 6 * len(KEY_SET_ROOTS)
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


def thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638: SHA-256 over the required members in lexicographic order, base64url."""
    required = ("crv", "kty", "x", "y") if jwk["kty"] == "EC" else ("crv", "kty", "x")
    text = json.dumps({k: jwk[k] for k in required}, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(text.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def key_set_binding_failures(raw: dict[str, bytes], want: dict[str, dict[str, Any]]) -> list[str]:
    """A key set records a held key and names no party, so the binding of that key
    to a party is never established, and the scoring refuses an answer that says it is."""
    failures: list[str] = []
    for row, family in KEY_SET_ROOTS:
        root = want[row]["delegationRoot"]
        element = next(
            v for v in json.loads(raw[row])["retention"]["validationData"]
            if v["for"] == "delegation-root"
        )
        keys = json.loads(base64.b64decode(element["value"]))["keys"]
        if element["mediaType"] != "application/jwk-set+json" or len(keys) != 1:
            failures.append(f"{row}: the root element is not a key set holding one key")
            continue
        if any("x5c" in k or "x5u" in k for k in keys):
            failures.append(f"{row}: the root key carries a certificate")
        if root.get("result") != "established" or root.get("algorithm") != family:
            failures.append(f"{row}: want the root established under {family}, got {root}")
        if root.get("binding") != "not-established":
            failures.append(f"{row}: a key set must leave the binding not established, got {root}")
        if root.get("keyThumbprint") != thumbprint(keys[0]):
            failures.append(f"{row}: keyThumbprint is not the RFC 7638 thumbprint of the held key")
        forged = {**want[row], "delegationRoot": {**root, "binding": "established"}}
        if not auditrecord._dating_mismatch(want[row], forged)[0]:
            failures.append(f"{row}: an answer reporting the binding established is scored a pass")
        silent = {**want[row], "delegationRoot": {k: v for k, v in root.items() if k != "binding"}}
        if auditrecord._dating_mismatch(want[row], silent)[0]:
            failures.append(f"{row}: an answer that leaves the binding out is scored a failure")
    return failures


if __name__ == "__main__":
    sys.exit(main())
