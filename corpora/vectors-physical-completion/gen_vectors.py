"""Build the physical-completion cases byte-identically.

Every case is one presentation a verifier was given and the result it reported
for the PHYSICAL_COMPLETION intent, judged against
draft-noa-scitt-ai-agent-receipt-01. Each nonconformant case changes an
accepting control so the check it names is the first that fails and every
earlier check passes; each conformant case is a control that keeps a verifier
from refusing everything; each ambiguous case is a result -01 cannot decide,
because Section 1.5 leaves the observation and controller artifacts undefined,
and it lists the profile's reading and the reading of the rule this corpus puts
forward. The claim boundary and the seven starting cases were proposed by
hippoley (Noah Ellis) in issue 80 on this repository, with the FlyThink
physical-completion probes. Every member is synthetic.
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

from agent_evidence_vectors import physicalcompletion as reader  # noqa: E402

SUITE = reader.SUITE
SOURCE = {
    "author": "hippoley (Noah Ellis)",
    "issue": "https://github.com/probityai/agent-evidence-vectors/issues/80",
    "note": (
        "The claim boundary and seven starting cases come from the proposal in issue 80. "
        "The FlyThink probes are cited, not copied: each member here was written for this "
        "corpus from the draft's text, and where a probe's expected answer rests on an "
        "artifact the draft leaves undefined the member is marked open and says so."
    ),
    "probes": [
        "https://github.com/hippoley/FlyThink-Anatomy-Demo/commit/1be4ff7d63e166842d67fe04ecd10bb3054fca3a",
        "https://github.com/hippoley/FlyThink-Anatomy-Demo/commit/01297c1dbca49be19f6af6c90dda58bb08c03f9d",
    ],
    "source": "hippoley, issue 80",
}
SPEC = {
    "author": "T. Toraman",
    "draft": reader.PROFILE,
    "posted": "2026-08-15",
    "sections": ["1.5", "2", "8.1", "8.2", "8.3", "8.4", "12"],
    "sha256": "246b5da4c6ab0045e20d50f7f60ba41db03d49518255b360d8bf39b6ac0560a4",
    "status": (
        "Individual Internet-Draft, intended status Standards Track; not the agreed text "
        "of the SCITT working group, and a later revision can change it."
    ),
    "url": "https://www.ietf.org/archive/id/draft-noa-scitt-ai-agent-receipt-01.txt",
}
PROPOSAL = {
    "rules": list(reader.PROPOSAL),
    "status": (
        "Proposed by this corpus for the physical-observation and controller-outcome "
        "artifacts that Section 1.5 of the draft leaves undefined, from the failure model "
        "the draft fixes for them in Section 2 and Sections 8.2 to 8.4. Not the draft's "
        "text: every member that rests on one of these rules is ambiguous under -01."
    ),
    "vocabulary": SUITE,
}

#: Single sentences of the retrieved text (whitespace normalised), one per rule.
ANCHORS = {
    "definition": (
        "2",
        "Physical completion: whether the intended real-world effect actually occurred, as "
        "observed by an identified witness under a criterion fixed before execution.",
    ),
    "receipt": (
        "8.1",
        "A verifier evaluating a receipt -- alone or as part of a chain -- MUST NOT return "
        "a result whose named fields assert any of them on that basis, and where a consumer "
        "asked for one it MUST report that the receipt does not establish it.",
    ),
    "report": (
        "8.1",
        'A controller reporting "succeeded" attests success under its own semantics; that '
        "is a report, and a report is not an effect.",
    ),
    "executed": (
        "8.1",
        "In particular, governance.verdict == EXECUTED records that the action was "
        "dispatched, or attempted, at the governed boundary.",
    ),
    "unqualified": (
        "8.2",
        'A verifier MUST NOT report an unqualified "physical completion proven".',
    ),
    "policy": (
        "8.2",
        "The strongest defensible result is proven to the stated policy, naming the trust "
        "configuration that made it so, and a receipt never supplies it (Section 8.1).",
    ),
    "witness": (
        "8.2 Table 6",
        "an authenticated physical-observation artifact bound to this action, from a "
        "witness the verifier trusts for that purpose.",
    ),
    "conflict": (
        "8.2",
        "Where two authenticated claims conflict -- a controller reporting success and a "
        "witness reporting that the effect did not occur -- the conflict is its own result, "
        "carrying both claims, with neither erased in favour of the other; this document "
        "defines no token for it (Section 1.5).",
    ),
    "untokenised": (
        "1.5",
        "An implementation MAY report the two untokenised results under a name of its own; "
        "what it MUST NOT do is present that name as this profile's vocabulary, since a "
        "second implementation reading this document will not have chosen the same one.",
    ),
    "collapse": (
        "8.3",
        "A verifier MUST keep the following distinct, and MUST NOT collapse them:",
    ),
    "negative": (
        "8.3",
        "A verifier MUST NOT define a result code that asserts a negative fact about the "
        "world it did not observe;",
    ),
    "gap": (
        "8.3",
        '"The verifier did not receive acceptable evidence" is not "no evidence exists", and '
        "rendering the first as the second turns a gap in a presentation into a negative "
        "finding about the world.",
    ),
    "artifact": (
        "8.4",
        "a physical-observation artifact says what a witness observed, under a named "
        "method, in a named window, against a criterion digest fixed before execution.",
    ),
    "undefined": (
        "1.5",
        "Where such an object is absent, the corresponding requirement is not a requirement "
        "a conforming implementation can fail: it has nothing to evaluate, and Section 8 "
        "states what a bare receipt cannot establish.",
    ),
    "unwritten": (
        "12",
        "The rest -- a controller success with no physical evidence, a controller success "
        "against a witness reporting non-completion, same-party evidence presented as "
        "independent, a missing signer relationship, a stale or replayed observation, and "
        "the positive baselines mirroring each -- remain committed and unwritten, as does "
        "a cross-implementation negative for the alg pin.",
    ),
    "envelope": (
        "n/a",
        "The record names the contract it is written against, as every record of this "
        "repository's decision corpora does.",
    ),
}

TRUST = "sha256:5d1f0c7a9e2b4b3c8a6f1e0d2c4b6a8e9f1d3c5b7a9e0f2d4c6b8a0e1f3d5c7b"
DISPATCHED = 1000


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def observation(**changes: Any) -> dict[str, Any]:
    """A physical-observation artifact that satisfies every proposal rule, then the changes."""
    body: dict[str, Any] = {
        "authenticated": True,
        "boundToAction": True,
        "criterionDigest": "sha256:" + _sha(b"window opening within 1 pct of 5 pct"),
        "criterionFixedAtMs": 900,
        "criterionMet": True,
        "method": "state-readback",
        "observedAtMs": 1400,
        "windowEndMs": 2000,
        "witness": "witness-window-sensor-7",
    }
    body.update(changes)
    return body


def build(
    name: str,
    result: dict[str, Any] | None,
    *,
    observed: dict[str, Any] | None = None,
    controller: str | None = None,
    ack: str | None = None,
    **top: Any,
) -> dict[str, Any]:
    """One presentation and the result a verifier reported for it."""
    presented: dict[str, Any] = {
        "receipt": {
            "dispatchedAtMs": DISPATCHED,
            "profile": "noa.receipt/0.1",
            "valid": True,
            "verdict": "EXECUTED",
        },
        "trust": {"configuration": TRUST, "witnessesTrustedForPurpose": ["witness-window-sensor-7"]},
    }
    if controller is not None:
        presented["controllerOutcome"] = {"authenticated": True, "status": controller}
    if ack is not None:
        presented["transport"] = {"ack": ack}
    if observed is not None:
        presented["observation"] = observed
    record: dict[str, Any] = {
        "contractId": reader.CONTRACT_ID,
        "intent": "PHYSICAL_COMPLETION",
        "presented": presented,
        "recordId": f"record-{name}",
        "result": result if result is not None else {},
    }
    record.update(top)
    return {key: value for key, value in record.items() if value is not None}


def proven(**extra: Any) -> dict[str, Any]:
    return {"physicalCompletion": "PROVEN_TO_POLICY", "trustConfiguration": TRUST, **extra}


def said(token: str, **extra: Any) -> dict[str, Any]:
    return {"physicalCompletion": token, **extra}


CLAIMS = [
    {"source": "controller", "says": "see controllerOutcome.status"},
    {"source": "witness", "says": "see observation.criterionMet"},
]

Case = tuple[str, dict[str, Any], str, str, str, dict[str, Any]]


def meta(source: str, rule: str, anchor: str, **extra: Any) -> dict[str, Any]:
    """The proposal case, the rule that decides and the sentence it rests on."""
    section, quote = ANCHORS[anchor]
    row: dict[str, Any] = {
        "anchor": {"quote": quote, "section": section},
        "rule": rule,
        "source": source,
    }
    row.update(extra)
    return row


def readings(rule: str, owed: str) -> list[dict[str, str]]:
    """The two readings of an open member: the profile's, and this corpus's proposal."""
    section, quote = ANCHORS["undefined"]
    return [
        {
            "basis": f"{reader.PROFILE} Section {section}: {quote}",
            "decision": reader.CONFORMANT,
            "reading": "profile",
        },
        {
            "basis": f"proposal rule {rule} of {SUITE}; owes {owed}",
            "decision": reader.NONCONFORMANT,
            "reading": "proposal",
        },
    ]


def _case(
    name: str,
    decision: str,
    reason: str,
    edit: str,
    provenance: dict[str, Any],
    result: dict[str, Any] | None,
    **presentation: Any,
) -> Case:
    return (name, build(name, result, **presentation), decision, reason, edit, provenance)


def _controls() -> list[Case]:
    ok, c = reader.CONFORMANT_REASON, reader.CONFORMANT
    return [
        _case("conformant-receipt-alone-not-provided", c, ok,
              "control: a valid receipt with verdict EXECUTED and nothing else; the verifier "
              "reports NOT_PROVIDED", meta("issue 80 case 1", "R-RECEIPT", "receipt"),
              said("NOT_PROVIDED")),
        _case("conformant-controller-success-not-provided", c, ok,
              "control: a controller reports success and no observation is presented; the "
              "verifier reports NOT_PROVIDED", meta("issue 80 case 1", "R-REPORT", "report"),
              said("NOT_PROVIDED"), controller="succeeded"),
        _case("conformant-witness-proven-to-policy", c, ok,
              "control: an authenticated, bound, trusted, identified witness observed the "
              "criterion met inside the window; the verifier reports PROVEN_TO_POLICY and "
              "names its trust configuration", meta("issue 80 case 2", "R-POLICY", "policy"),
              proven(), observed=observation()),
        _case("conformant-witness-not-satisfied", c, ok,
              "control: the same witness observed the criterion not met; the verifier "
              "reports NOT_SATISFIED", meta("issue 80 case 3", "R-NEGATIVE", "negative"),
              said("NOT_SATISFIED"), observed=observation(criterionMet=False)),
        _case("conformant-stale-witness-indeterminate", c, ok,
              "control: the observation was made after its window closed; the verifier "
              "reports INDETERMINATE", meta("issue 80 case 4", "P-WINDOW", "artifact"),
              said("INDETERMINATE"), observed=observation(observedAtMs=2500)),
        _case("conformant-replayed-observation-indeterminate", c, ok,
              "control: the observation predates dispatch, so it cannot be of this action's "
              "effect; the verifier reports INDETERMINATE",
              meta("draft Section 12 stale or replayed", "P-WINDOW", "unwritten"),
              said("INDETERMINATE"), observed=observation(observedAtMs=950)),
        _case("conformant-criterion-after-dispatch-indeterminate", c, ok,
              "control: the criterion was fixed after dispatch; the verifier reports "
              "INDETERMINATE", meta("issue 80 case 5", "P-PREFIXED", "definition"),
              said("INDETERMINATE"), observed=observation(criterionFixedAtMs=1200)),
        _case("conformant-unidentified-witness-indeterminate", c, ok,
              "control: the observation names no witness; the verifier reports INDETERMINATE",
              meta("derived from issue 80 case 2", "P-IDENTIFIED", "definition"),
              said("INDETERMINATE"), observed=observation(witness=None)),
        _case("conformant-untrusted-witness-indeterminate", c, ok,
              "control: the witness is not one the trust configuration trusts for this "
              "purpose; the verifier reports INDETERMINATE",
              meta("derived from issue 80 case 2", "P-TRUSTED", "witness"),
              said("INDETERMINATE"), observed=observation(witness="witness-hallway-camera-2")),
        _case("conformant-unauthenticated-observation-not-provided", c, ok,
              "control: the observation artifact does not authenticate, so the verifier was "
              "not given acceptable evidence and reports NOT_PROVIDED",
              meta("derived from issue 80 case 2", "P-AUTHENTICATED", "witness"),
              said("NOT_PROVIDED"), observed=observation(authenticated=False)),
        _case("conformant-unbound-observation-not-provided", c, ok,
              "control: the observation is not bound to this action; the verifier reports "
              "NOT_PROVIDED", meta("derived from issue 80 case 2", "P-BOUND", "witness"),
              said("NOT_PROVIDED"), observed=observation(boundToAction=False)),
        _case("conformant-ack-lost-witness-proven", c, ok,
              "control: the transport acknowledgement was lost and a fresh trusted witness "
              "observed the criterion met; the verifier reports PROVEN_TO_POLICY",
              meta("issue 80 case 6", "R-NEGATIVE", "gap"),
              proven(), observed=observation(), ack="lost"),
        _case("conformant-ack-lost-not-provided", c, ok,
              "control: the acknowledgement was lost and no observation is presented; the "
              "verifier reports NOT_PROVIDED", meta("issue 80 case 6", "R-ABSENCE", "gap"),
              said("NOT_PROVIDED"), ack="lost"),
        _case("conformant-conflict-success-against-unmet", c, ok,
              "control: the controller reports success, the witness reports the criterion "
              "not met, and the verifier reports CONFLICT carrying both claims",
              meta("issue 80 case 7", "P-CONFLICT", "conflict"),
              said("CONFLICT", claims=CLAIMS, vocabulary=SUITE),
              observed=observation(criterionMet=False), controller="succeeded"),
        _case("conformant-conflict-failure-against-met", c, ok,
              "control: the mirror: the controller reports failure, the witness reports the "
              "criterion met, and the verifier reports CONFLICT carrying both claims",
              meta("issue 80 case 7", "P-CONFLICT", "conflict"),
              said("CONFLICT", claims=CLAIMS),
              observed=observation(), controller="failed"),
    ]


def _refusals() -> list[Case]:
    n = reader.NONCONFORMANT
    unknown = reader.CONTRACT_ID.replace("/predicate/v1/", "/contract/v0/")
    return [
        ("nonconformant-contract-id-missing",
         build("nonconformant-contract-id-missing", proven(), observed=observation(),
               contractId=None),
         n, "contract_id_missing", "the record names no contract",
         meta("envelope", "envelope", "envelope")),
        ("nonconformant-contract-id-unknown",
         build("nonconformant-contract-id-unknown", proven(), observed=observation(),
               contractId=unknown),
         n, "contract_id_unknown", "the record names a contract version that does not exist",
         meta("envelope", "envelope", "envelope")),
        _case("nonconformant-result-member-absent", n, "result_member_absent",
              "the consumer asked for PHYSICAL_COMPLETION and the result carries no answer",
              meta("derived from issue 80 case 1", "R-RECEIPT", "receipt"),
              {}, observed=observation()),
        _case("nonconformant-unqualified-proven", n, "proven_without_policy",
              "the witness control, reported as an unqualified PROVEN",
              meta("issue 80 case 2", "R-UNQUALIFIED", "unqualified"),
              said("PROVEN"), observed=observation()),
        _case("nonconformant-physical-completion-proven-token", n, "proven_without_policy",
              "the witness control, reported as PHYSICAL_COMPLETION_PROVEN, the spelling "
              "the FlyThink probe emits, which names no policy",
              meta("FlyThink probe 1be4ff7", "R-UNQUALIFIED", "unqualified"),
              said("PHYSICAL_COMPLETION_PROVEN"), observed=observation()),
        _case("nonconformant-proven-without-trust-configuration", n, "proven_without_policy",
              "PROVEN_TO_POLICY over the witness control with no trust configuration named",
              meta("derived from issue 80 case 2", "R-UNQUALIFIED", "policy"),
              said("PROVEN_TO_POLICY"), observed=observation()),
        _case("nonconformant-result-outside-vocabulary", n, "result_outside_vocabulary",
              "the witness control, reported as COMPLETED, which is in neither vocabulary",
              meta("derived from issue 80 case 2", "R-ABSENCE", "collapse"),
              said("COMPLETED"), observed=observation()),
        _case("nonconformant-conflict-as-profile-token", n, "untokenised_result_as_profile_token",
              "the conflict control, with CONFLICT presented as the draft's own vocabulary",
              meta("issue 80 case 7", "R-UNTOKENISED", "untokenised"),
              said("CONFLICT", claims=CLAIMS, vocabulary=reader.PROFILE),
              observed=observation(criterionMet=False), controller="succeeded"),
        _case("nonconformant-receipt-executed-read-as-completion", n, "completion_from_receipt",
              "a receipt with verdict EXECUTED and nothing else, reported as PROVEN_TO_POLICY",
              meta("issue 80 case 1", "R-RECEIPT", "executed", basis=["8.1"]),
              proven()),
        _case("nonconformant-controller-success-read-as-completion", n,
              "completion_from_controller_report",
              "a controller's success and no observation, reported as PROVEN_TO_POLICY",
              meta("issue 80 case 1", "R-REPORT", "report"),
              proven(), controller="succeeded"),
        _case("nonconformant-absence-read-as-not-satisfied", n, "negative_without_observation",
              "nothing but the receipt, reported as NOT_SATISFIED",
              meta("derived from issue 80 case 6", "R-NEGATIVE", "negative"),
              said("NOT_SATISFIED")),
        _case("nonconformant-lost-ack-read-as-not-executed", n, "negative_without_observation",
              "a lost acknowledgement and no observation, reported as NOT_SATISFIED",
              meta("issue 80 case 6", "R-NEGATIVE", "gap"),
              said("NOT_SATISFIED"), ack="lost"),
        _case("nonconformant-lost-ack-over-met-witness", n, "negative_without_observation",
              "a lost acknowledgement and a trusted witness that observed the criterion met, "
              "reported as NOT_SATISFIED", meta("issue 80 case 6", "R-NEGATIVE", "negative"),
              said("NOT_SATISFIED"), observed=observation(), ack="lost"),
        _case("nonconformant-controller-failure-read-as-not-satisfied", n,
              "negative_without_observation",
              "a controller's failure and no observation, reported as NOT_SATISFIED; a report "
              "is not an effect in either direction",
              meta("derived from issue 80 case 1", "R-NEGATIVE", "report", basis=["8.1", "8.3"]),
              said("NOT_SATISFIED"), controller="failed"),
        _case("nonconformant-absence-read-as-indeterminate", n,
              "absence_not_reported_as_not_provided",
              "nothing but the receipt, reported as INDETERMINATE, which says evidence was "
              "presented", meta("derived from issue 80 case 1", "R-ABSENCE", "collapse"),
              said("INDETERMINATE")),
        _case("nonconformant-absence-read-as-not-applicable", n,
              "absence_not_reported_as_not_provided",
              "nothing but the receipt, reported as NOT_APPLICABLE, which says the question "
              "does not arise", meta("derived from issue 80 case 1", "R-ABSENCE", "collapse"),
              said("NOT_APPLICABLE")),
    ]


def _open(name: str, rule: str, owed: str, edit: str, source: str, anchor: str,
          result: dict[str, Any], **presentation: Any) -> Case:
    provenance = meta(source, f"P-{rule}", anchor, readings=readings(rule, owed),
                      basis=["1.5", ANCHORS[anchor][0]])
    return _case(name, reader.AMBIGUOUS, rule, edit, provenance, result, **presentation)


def _open_cases() -> list[Case]:
    return [
        _open("open-bare-receipt-not-claimed", "absence_reported_as_not_claimed", "NOT_PROVIDED",
              "nothing but the receipt, reported as NOT_CLAIMED: the receipt makes no claim "
              "of physical completion, and a claim may still exist elsewhere",
              "derived from issue 80 case 1", "collapse", said("NOT_CLAIMED")),
        _open("open-stale-witness-proven", "observation_outside_window", "INDETERMINATE",
              "the stale-witness control, reported as PROVEN_TO_POLICY",
              "issue 80 case 4", "artifact", proven(), observed=observation(observedAtMs=2500)),
        _open("open-replayed-observation-proven", "observation_outside_window", "INDETERMINATE",
              "the replayed-observation control, reported as PROVEN_TO_POLICY",
              "draft Section 12 stale or replayed", "unwritten", proven(),
              observed=observation(observedAtMs=950)),
        _open("open-criterion-after-dispatch-proven", "criterion_not_prefixed", "INDETERMINATE",
              "the late-criterion control, reported as PROVEN_TO_POLICY",
              "issue 80 case 5", "definition", proven(),
              observed=observation(criterionFixedAtMs=1200)),
        _open("open-unidentified-witness-proven", "witness_unidentified", "INDETERMINATE",
              "the unidentified-witness control, reported as PROVEN_TO_POLICY",
              "derived from issue 80 case 2", "definition", proven(),
              observed=observation(witness=None)),
        _open("open-untrusted-witness-proven", "witness_untrusted", "INDETERMINATE",
              "the untrusted-witness control, reported as PROVEN_TO_POLICY",
              "derived from issue 80 case 2", "witness", proven(),
              observed=observation(witness="witness-hallway-camera-2")),
        _open("open-unauthenticated-observation-proven", "observation_unauthenticated",
              "NOT_PROVIDED", "the unauthenticated-observation control, reported as "
              "PROVEN_TO_POLICY", "derived from issue 80 case 2", "witness", proven(),
              observed=observation(authenticated=False)),
        _open("open-unbound-observation-proven", "observation_unbound", "NOT_PROVIDED",
              "the unbound-observation control, reported as PROVEN_TO_POLICY",
              "derived from issue 80 case 2", "witness", proven(),
              observed=observation(boundToAction=False)),
        _open("open-unmet-witness-proven", "observation_outcome_not_reported", "NOT_SATISFIED",
              "the not-satisfied control, reported as PROVEN_TO_POLICY",
              "issue 80 case 3", "definition", proven(),
              observed=observation(criterionMet=False)),
        _open("open-settled-witness-indeterminate", "observation_outcome_not_reported",
              "PROVEN_TO_POLICY", "the witness control, reported as INDETERMINATE although "
              "every rule of the proposal holds", "issue 80 case 2", "policy",
              said("INDETERMINATE"), observed=observation()),
        _open("open-conflict-erased-to-proven", "conflict_erased", "CONFLICT",
              "the controller reports failure and the witness the criterion met; the verifier "
              "reports PROVEN_TO_POLICY and drops the controller's claim",
              "issue 80 case 7", "conflict", proven(), observed=observation(),
              controller="failed"),
        _open("open-conflict-erased-to-not-satisfied", "conflict_erased", "CONFLICT",
              "the controller reports success and the witness the criterion not met; the "
              "verifier reports NOT_SATISFIED and drops the controller's claim",
              "draft Section 12 controller success against a witness", "unwritten",
              said("NOT_SATISFIED"), observed=observation(criterionMet=False),
              controller="succeeded"),
        _open("open-conflict-drops-a-claim", "conflict_drops_a_claim", "CONFLICT",
              "the conflict control, reported as CONFLICT carrying only the witness's claim",
              "issue 80 case 7", "conflict", said("CONFLICT", claims=CLAIMS[1:]),
              observed=observation(criterionMet=False), controller="succeeded"),
    ]


def cases() -> list[Case]:
    """Every case: id, record, decision, reason, what it shows and its provenance."""
    return [*_controls(), *_refusals(), *_open_cases()]


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
        entries.append(
            {
                "basis": provenance.pop("basis", [provenance["anchor"]["section"]]),
                **provenance,
                "edit": edit,
                "expected": expected,
                "files": {"record.json": _sha(data)},
                "id": name,
                "path": f"cases/{name}",
                "retained": reader.retained(copy.deepcopy(body)),
            }
        )
    words = [entry["expected"]["decision"] for entry in entries]
    manifest = {
        "contractId": reader.CONTRACT_ID,
        "corpusDigest": _sha(_json(entries)),
        "counts": {word: words.count(word) for word in sorted(set(words))},
        "proposal": PROPOSAL,
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
