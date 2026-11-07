"""Build the refusal-reason-priority cases byte-identically.

Every case is one attestation response and the facts it answered over. The
records come from the Aicent Stack families aicent-grant-ref and
aicent-lease-boundary (issue 453 on this repository), each anchored to a sentence
of draft-li-rttp-iqa-addressing-02. Each nonconformant case changes an accepting
control so the check it names is the first that fails and every earlier check
passes; each conformant case is a control that keeps a verifier from refusing
everything; each ambiguous case is open by design and lists its readings.
Every member is synthetic.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import refusalreason as reader  # noqa: E402

SUITE = reader.SUITE
ABSENT = object()
SOURCE = {
    "author": "ShaoBao Li (Lee), Aicent Stack",
    "families": [
        "https://github.com/Aicent-Stack/conformance/tree/main/candidates/aicent-grant-ref",
        "https://github.com/Aicent-Stack/conformance/tree/main/candidates/aicent-lease-boundary",
    ],
    "issue": "https://github.com/probityai/agent-evidence-vectors/issues/453",
    "note": (
        "The two families are cited, not copied: each member here was written for this "
        "corpus from the facts and the response the family states, and carries the "
        "family's case id in source. Where the draft's sentence does not settle the "
        "author's expected value the member says so and is marked open."
    ),
    "source": "Aicent Stack, issue 453",
}
SPEC = {
    "draft": "draft-li-rttp-iqa-addressing-02",
    "posted": "2026-11-01",
    "sections": ["6.1", "7.2", "8.1", "8.2"],
    "sha256": "02491c5a59d1e7471be04e8e0d4933dfc22ce19f9b054ead0aa449d6b4485044",
    "status": (
        "Informational Internet-Draft published for the public record; not the agreed "
        "text of any working group, and a later revision can change it."
    ),
    "url": "https://www.ietf.org/archive/id/draft-li-rttp-iqa-addressing-02.txt",
}

#: Single sentences of the retrieved text (whitespace normalised), one per rule.
ANCHORS = {
    "order": (
        "8.1",
        "For a refusal, the reason is exactly one value from the following closed set, "
        "and it is the first value in the list whose condition applies (the priority "
        "order is part of this definition)",
    ),
    "operation": (
        "8.1",
        "The requested operation is not permitted for this subject or grant, for reasons "
        "other than the four above.",
    ),
    "not-determined": (
        "8.1",
        "An unreachable source is refused under this value, never read as assent.",
    ),
    "permit": (
        "8.1",
        "A null refusal reason is the only representation of \"permitted\"; there is no "
        "affirmative \"granted\" value.",
    ),
    "closed": (
        "8.1",
        "The set is closed: implementations MUST NOT emit values outside it, and MUST "
        "NOT reinterpret an emitted value to mean something else.",
    ),
    "reason-required": (
        "8.1",
        "A response that reports an outcome without its reason is not conformant: the "
        "reason is what makes a refusal auditable.",
    ),
    "null-rule": (
        "8.2",
        "observation_as_of_ms is null whenever the observation the answer relied on is "
        "absent or not fresh, even if a later, successful observation is available at "
        "answer time.",
    ),
    "diagnostic": (
        "8.2",
        "A diagnostic or opportunistic read performed after the relied-on evidence "
        "expired does not backfill the member: diagnostic reads do not participate in "
        "authorisation and do not renew evidence.",
    ),
    "boundary": (
        "6.1",
        "Whether the lease instant itself counts as fresh or as expired is a deployment "
        "convention; implementations SHOULD declare which boundary they use, and "
        "conformance material MAY test both.",
    ),
    "frame": (
        "7.2",
        "rejects the frame if lease_expiry is earlier than the current time, checked against "
        "the receiver's own clock (Section 6.1)",
    ),
    "envelope": (
        "n/a",
        "The record names the contract it is written against, as every record of this "
        "repository's decision corpora does.",
    ),
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def build(
    name: str,
    *,
    reason: Any = None,
    facts: dict[str, Any] | None = None,
    grant: dict[str, Any] | None = None,
    **top: Any,
) -> dict[str, Any]:
    """One response and the facts it answered over."""
    base_facts: dict[str, Any] = {
        "authority": "determined",
        "bindingMismatch": False,
        "evidenceExpired": False,
        "operationPermitted": True,
    }
    base_facts.update(facts or {})
    grant_ref: dict[str, Any] = {
        "evidenceId": "ev-0042",
        "expiresAtMs": 9000,
        "grant": "grant-7f3a",
        "issuedAtMs": 1000,
        "observationAsOfMs": 1100,
    }
    grant_ref.update(grant or {})
    response: dict[str, Any] = {"grantRef": grant_ref}
    if reason is not ABSENT:
        response["reason"] = reason
    record: dict[str, Any] = {
        "contractId": reader.CONTRACT_ID,
        "facts": base_facts,
        "recordId": f"record-{name}",
        "response": response,
    }
    record.update(top)
    return {key: value for key, value in record.items() if value is not None}


#: Facts whose first applicable value lies earlier or later in the draft's list.
EXPIRED = {"evidenceExpired": True}
MISMATCH = {"bindingMismatch": True}
REVOKED = {"authority": "revoked"}
STALE = {
    "authority": "staleObservation",
    "diagnosticRead": {"asOfMs": 1150, "successful": True},
    "grantExpiresAtMs": 900,
    "reliedOnObservation": {"asOfMs": 500, "fresh": False, "present": True},
}
LAPSED = {"expiresAtMs": 900, "observationAsOfMs": 800}


def lease(declared: str | None, frame: bool = False) -> dict[str, Any]:
    """Facts for a read exactly at the lease instant."""
    instant: dict[str, Any] = {"atInstant": True, "declaredBoundary": declared}
    if frame:
        instant["frameAccepted"] = True
    return {"leaseInstant": instant}


Case = tuple[str, dict[str, Any], str, str, str, dict[str, Any]]


def meta(source: str, rule: str, anchor: str, **extra: Any) -> dict[str, Any]:
    """The family case, the rule that decides and the sentence it rests on."""
    section, quote = ANCHORS[anchor]
    row: dict[str, Any] = {
        "anchor": {"quote": quote, "section": section},
        "rule": rule,
        "source": source,
    }
    row.update(extra)
    return row


def _order() -> list[Case]:
    ok = reader.CONFORMANT_REASON
    return [
        ("conformant-mismatch-over-expiry",
         build("conformant-mismatch-over-expiry", reason="evidence_binding_mismatch",
               facts={**MISMATCH, **EXPIRED}, grant=LAPSED),
         "conformant", ok, "control: binding mismatch and expiry both apply and the first value "
         "in the list is emitted", meta("GR-P01", "R-ORDER", "order")),
        ("nonconformant-expiry-over-mismatch",
         build("nonconformant-expiry-over-mismatch", reason="evidence_expired",
               facts={**MISMATCH, **EXPIRED}, grant=LAPSED),
         "nonconformant", "later_value_emitted", "the same facts, answered with the second value "
         "in the list", meta("GR-P02", "R-ORDER", "order")),
        ("conformant-expiry-over-revocation",
         build("conformant-expiry-over-revocation", reason="evidence_expired",
               facts={**EXPIRED, **REVOKED}, grant=LAPSED),
         "conformant", ok, "control: expiry and revocation both apply and evidence_expired, "
         "which comes first, is emitted", meta("GR-P03", "R-ORDER", "order",
                                                 pair="expiry-over-revocation")),
        ("nonconformant-revocation-over-expiry",
         build("nonconformant-revocation-over-expiry", reason="authority_revoked",
               facts={**EXPIRED, **REVOKED}, grant=LAPSED),
         "nonconformant", "later_value_emitted", "the same facts, answered with the later "
         "value authority_revoked; a checker that accepts any applicable value passes this "
         "member and fails only this one of the pair", meta("GR-P04", "R-ORDER", "order",
                                                             pair="expiry-over-revocation")),
        ("conformant-mismatch-over-revocation",
         build("conformant-mismatch-over-revocation", reason="evidence_binding_mismatch",
               facts={**MISMATCH, **REVOKED}),
         "conformant", ok, "control: mismatch and revocation both apply and the mismatch is "
         "emitted", meta("GR-P05", "R-ORDER", "order")),
        ("conformant-mismatch-first-of-three",
         build("conformant-mismatch-first-of-three", reason="evidence_binding_mismatch",
               facts={**MISMATCH, **EXPIRED, **REVOKED}, grant=LAPSED),
         "conformant", ok, "control: mismatch, expiry and revocation all apply and the first "
         "is emitted", meta("GR-P06", "R-ORDER", "order")),
        ("nonconformant-revocation-of-three",
         build("nonconformant-revocation-of-three", reason="authority_revoked",
               facts={**MISMATCH, **EXPIRED, **REVOKED}, grant=LAPSED),
         "nonconformant", "later_value_emitted", "the three-condition facts answered with the "
         "last applicable value instead of the first",
         meta("derived from GR-P06", "R-ORDER", "order")),
        ("conformant-not-determined-unreachable",
         build("conformant-not-determined-unreachable", reason="authority_not_determined",
               facts={"authority": "unreachable"}, grant={"observationAsOfMs": None}),
         "conformant", ok, "control: the authority source could not be reached and the refusal "
         "is authority_not_determined, never an assent",
         meta("GR-P07", "R-NOTDET", "not-determined")),
        ("conformant-operation-not-permitted-alone",
         build("conformant-operation-not-permitted-alone", reason="operation_not_permitted",
               facts={"operationPermitted": False}),
         "conformant", ok, "control: no earlier condition applies and the operation is not "
         "permitted", meta("GR-P08", "R-ORDER", "operation")),
        ("nonconformant-refusal-without-condition",
         build("nonconformant-refusal-without-condition", reason="operation_not_permitted"),
         "nonconformant", "refusal_without_condition", "every condition is absent and the "
         "operation is permitted on the face of the record, yet operation_not_permitted is "
         "emitted: when no condition applies the reason is null",
         meta("GR-P09", "R-ORDER", "operation",
              note="The draft states the no-condition case through the definitions: each value "
                   "is emitted only where its condition applies, and the condition of "
                   "operation_not_permitted is that the operation is not permitted. The author "
                   "expects nonconformant and so does this corpus.")),
        ("conformant-revocation-over-operation-not-permitted",
         build("conformant-revocation-over-operation-not-permitted", reason="authority_revoked",
               facts={**REVOKED, "operationPermitted": False}),
         "conformant", ok, "control: revocation and a refused operation both apply and "
         "authority_revoked, which comes first, is emitted",
         meta("derived from GR-P08", "R-ORDER", "operation", pair="revocation-over-operation")),
        ("nonconformant-operation-not-permitted-over-revocation",
         build("nonconformant-operation-not-permitted-over-revocation",
               reason="operation_not_permitted", facts={**REVOKED, "operationPermitted": False}),
         "nonconformant", "later_value_emitted", "the same facts answered with the last value of "
         "the list, which the draft reserves for reasons other than the four before it",
         meta("derived from GR-P08", "R-ORDER", "operation", pair="revocation-over-operation")),
        ("conformant-expiry-over-not-determined",
         build("conformant-expiry-over-not-determined", reason="evidence_expired",
               facts={**EXPIRED, "authority": "unreachable"}, grant={**LAPSED,
                                                                      "observationAsOfMs": None}),
         "conformant", ok, "control: the evidence has expired and the authority source is "
         "unreachable, and evidence_expired comes first in the list",
         meta("derived from GR-P07", "R-ORDER", "order", pair="expiry-over-not-determined")),
        ("nonconformant-not-determined-over-expiry",
         build("nonconformant-not-determined-over-expiry", reason="authority_not_determined",
               facts={**EXPIRED, "authority": "unreachable"}, grant={**LAPSED,
                                                                      "observationAsOfMs": None}),
         "nonconformant", "later_value_emitted", "the same facts answered with the third value "
         "of the list instead of the second",
         meta("derived from GR-P07", "R-ORDER", "order", pair="expiry-over-not-determined")),
    ]


def _null_rule() -> list[Case]:
    ok = reader.CONFORMANT_REASON
    fresh = {"reliedOnObservation": {"asOfMs": 1100, "fresh": True, "present": True}}
    gone = {"reliedOnObservation": {"present": False}}
    return [
        ("conformant-observation-fresh",
         build("conformant-observation-fresh", facts=fresh),
         "conformant", ok, "control: the answer relied on a fresh observation and the member "
         "carries its as-of instant", meta("GR-N01", "R-NULLOBS", "null-rule")),
        ("conformant-observation-absent-null",
         build("conformant-observation-absent-null", facts=gone,
               grant={"observationAsOfMs": None}),
         "conformant", ok, "control: the relied-on observation is absent and the member is null",
         meta("GR-N02", "R-NULLOBS", "null-rule")),
        ("nonconformant-diagnostic-backfills-observation",
         build("nonconformant-diagnostic-backfills-observation", reason="authority_not_determined",
               facts=STALE, grant={"expiresAtMs": 900, "observationAsOfMs": 1150}),
         "nonconformant", "observation_backfilled", "the relied-on observation is stale and the "
         "member is filled from a later diagnostic read",
         meta("GR-N03", "R-NULLOBS", "diagnostic")),
        ("nonconformant-permit-over-diagnostic-read",
         build("nonconformant-permit-over-diagnostic-read", reason=None, facts=STALE,
               grant={"expiresAtMs": 900, "observationAsOfMs": 1150}),
         "nonconformant", "condition_ignored", "the relied-on evidence was stale and a permit "
         "is computed over the later diagnostic read, with its instant 1150 as the observation; "
         "a diagnostic read does not participate in authorisation, so the only conformant "
         "answer is authority_not_determined with the member null",
         meta("GR-N04", "R-NOTDET", "diagnostic", basis=["8.1", "8.2"])),
        ("conformant-stale-diagnostic-keeps-null",
         build("conformant-stale-diagnostic-keeps-null", reason="authority_not_determined",
               facts=STALE, grant={"expiresAtMs": 900, "observationAsOfMs": None}),
         "conformant", ok, "control: the stale facts answered correctly: not determined, the "
         "member null and the expiry unchanged", meta("GR-N05", "R-NULLOBS", "diagnostic")),
        ("nonconformant-diagnostic-renews-expiry",
         build("nonconformant-diagnostic-renews-expiry", reason="authority_not_determined",
               facts=STALE, grant={"expiresAtMs": 1150, "observationAsOfMs": None}),
         "nonconformant", "evidence_renewed_by_diagnostic_read", "the expiry is pushed to the "
         "diagnostic instant as if the read had renewed the evidence",
         meta("GR-N06", "R-NULLOBS", "diagnostic")),
    ]


def _closed() -> list[Case]:
    ok = reader.CONFORMANT_REASON
    return [
        ("conformant-null-is-the-only-permit",
         build("conformant-null-is-the-only-permit", reason=None),
         "conformant", ok, "control: a permit recorded as a null reason over the closed set, "
         "the only representation of permitted", meta("GR-C04", "R-CLOSED", "permit")),
        ("nonconformant-granted-value",
         build("nonconformant-granted-value", reason="granted"),
         "nonconformant", "reason_outside_closed_set", "an affirmative granted value is "
         "emitted; there is none in the set", meta("GR-C01", "R-CLOSED", "permit")),
        ("nonconformant-reason-member-absent",
         build("nonconformant-reason-member-absent", reason=ABSENT, facts=EXPIRED, grant=LAPSED),
         "nonconformant", "reason_member_absent", "the response reports a refusal and carries no "
         "reason member at all", meta("GR-C02", "R-CLOSED", "reason-required")),
        ("nonconformant-sixth-value",
         build("nonconformant-sixth-value", reason="authority_suspended",
               facts={"authority": "unreachable"}, grant={"observationAsOfMs": None}),
         "nonconformant", "reason_outside_closed_set", "a sixth value outside the closed set is "
         "emitted", meta("GR-C03", "R-CLOSED", "closed")),
    ]


def _boundary() -> list[Case]:
    ok = reader.CONFORMANT_REASON
    both = [
        "inclusive: the lease instant counts as fresh, so the answer is a permit",
        "exclusive: the lease instant counts as expired, so the answer is evidence_expired",
    ]
    contradicted = [
        "nonconformant (the author's strict reading): a declaration that contradicts use tells "
        "the caller the opposite of the behaviour and defeats the function the clause gives "
        "declarations",
        "conformant: the clause says implementations SHOULD declare and attaches no consequence "
        "to a declaration that contradicts use, and the answer sits inside a licensed convention",
    ]
    return [
        ("conformant-inclusive-permit-at-instant",
         build("conformant-inclusive-permit-at-instant", facts=lease("inclusive")),
         "conformant", ok, "control: the read is exactly at the lease instant under a declared "
         "inclusive boundary and the answer is a permit", meta("LB-D01", "R-DECLARED", "boundary")),
        ("conformant-exclusive-expired-at-instant",
         build("conformant-exclusive-expired-at-instant", reason="evidence_expired",
               facts=lease("exclusive")),
         "conformant", ok, "control: the same instant under a declared exclusive boundary and the "
         "answer is evidence_expired", meta("LB-D02", "R-DECLARED", "boundary")),
        ("open-inclusive-declared-expired-at-instant",
         build("open-inclusive-declared-expired-at-instant", reason="evidence_expired",
               facts=lease("inclusive")),
         "ambiguous", "declaration_contradicts_use", "the deployment declared the inclusive "
         "boundary and answers evidence_expired at the instant",
         meta("LB-D03", "R-DECLARED", "boundary", authorExpected="nonconformant",
              readings=contradicted,
              note="The author scores this nonconformant and discloses the reading as strict: "
                   "the sentence asks for a declaration with SHOULD and states no consequence "
                   "for a declaration that contradicts use. Open here until a revision says.")),
        ("open-exclusive-declared-permit-at-instant",
         build("open-exclusive-declared-permit-at-instant", facts=lease("exclusive")),
         "ambiguous", "declaration_contradicts_use", "the mirror of the previous member: the "
         "exclusive boundary is declared and the answer at the instant is a permit",
         meta("derived from LB-D03", "R-DECLARED", "boundary", readings=contradicted,
              note="Same open question as the previous member, in the other direction.")),
        ("open-boundary-undeclared",
         build("open-boundary-undeclared", facts=lease(None)),
         "ambiguous", "boundary_undeclared", "the read is at the lease instant, no boundary is "
         "declared and the answer is a permit; it sits inside one licensed reading and cannot "
         "be settled until the implementation declares",
         meta("LB-D04", "R-DECLARED", "boundary", authorExpected="ambiguous", readings=both)),
        ("nonconformant-undeclared-answer-outside-both-readings",
         build("nonconformant-undeclared-answer-outside-both-readings",
               reason="authority_revoked", facts=lease(None)),
         "nonconformant", "answer_outside_both_boundary_readings", "no boundary is declared and "
         "the answer at the instant is neither a permit nor evidence_expired, so it sits inside "
         "neither licensed reading", meta("derived from LB-D04", "R-DECLARED", "boundary")),
        ("conformant-frame-accepted-reliance-refused",
         build("conformant-frame-accepted-reliance-refused", reason="evidence_expired",
               facts=lease("exclusive", frame=True)),
         "conformant", ok, "control: the envelope frame is accepted at the instant, as the "
         "verification procedure requires, and the answer is still evidence_expired under the "
         "declared exclusive boundary; frame validity and reliance are different layers",
         meta("LB-D05", "R-DECLARED", "frame", basis=["6.1", "7.2"])),
    ]


def _envelope() -> list[Case]:
    unknown = reader.CONTRACT_ID.replace("/predicate/v1/", "/contract/v0/")
    return [
        ("nonconformant-contract-id-missing",
         build("nonconformant-contract-id-missing", contractId=None),
         "nonconformant", "contract_id_missing", "the record names no contract",
         meta("envelope", "envelope", "envelope")),
        ("nonconformant-contract-id-unknown",
         build("nonconformant-contract-id-unknown", contractId=unknown),
         "nonconformant", "contract_id_unknown", "the record names a contract version that does "
         "not exist", meta("envelope", "envelope", "envelope")),
    ]


def cases() -> list[Case]:
    """Every case: id, record, decision, reason, what it shows and its provenance."""
    return [*_order(), *_null_rule(), *_closed(), *_boundary(), *_envelope()]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base_dir = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base_dir / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    if (root / "cases").exists():
        shutil.rmtree(root / "cases")
    entries = []
    for name, body, decision, reason, edit, provenance in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True)
        data = _json(body)
        (directory / "record.json").write_bytes(data)
        expected = {"decision": decision, "reason": reason}
        observed = reader.verify(directory / "record.json")
        if observed != expected:
            raise SystemExit(f"{name}: the reader says {observed}, the case {expected}")
        entries.append({
            "basis": provenance.pop("basis", [provenance["anchor"]["section"]]),
            **provenance,
            "edit": edit,
            "expected": expected,
            "files": {"record.json": _sha(data)},
            "id": name,
            "path": f"cases/{name}",
            "retained": reader.retained(copy.deepcopy(body)),
        })
    words = [entry["expected"]["decision"] for entry in entries]
    manifest = {
        "contractId": reader.CONTRACT_ID,
        "corpusDigest": _sha(_json(entries)),
        "counts": {word: words.count(word) for word in sorted(set(words))},
        "provenance": SOURCE,
        "spec": SPEC,
        "suite": SUITE,
        "synthetic": True,
        "verifierContract": "verifier record.json --json; exit 0 conformant, 1 nonconformant, "
        "2 ambiguous",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
