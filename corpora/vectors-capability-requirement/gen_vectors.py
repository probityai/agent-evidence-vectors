"""Build the capability-requirement cases byte-identically.

Every case is one record: a signed requirement, a verifier's report on a hosted
endpoint, or a comparison of two signed runs. Each denied case changes the accepting
control so the check it names is the first that fails and every earlier check passes;
each allowed case is a control that keeps a verifier from denying everything. After a
change that a signature would catch first, the denied case signs again, so the check
under test is the one that fires. Keys are test keys and every member is synthetic.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

import run_vectors as rail  # noqa: E402
from agent_evidence_vectors import capabilityrequirement as reader  # noqa: E402

SUITE = reader.SUITE
REQUIRER = hashlib.sha256(b"capability-requirement/v1 requirer test key").digest()
ASSESSOR = hashlib.sha256(b"capability-requirement/v1 assessor test key").digest()
VERIFIER = hashlib.sha256(b"capability-requirement/v1 verifier test key").digest()
OTHER = hashlib.sha256(b"capability-requirement/v1 other test key").digest()
ITEMS = [hashlib.sha256(f"evaluation item {n}".encode()).hexdigest() for n in range(4)]
COMMITMENT = hashlib.sha256(b"held-out set kept by the assessor").hexdigest()
HOSTED = {"access": "hosted", "claimedModel": "model-a"}
Case = tuple[str, dict[str, Any], str, str, str]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def public_key(seed: bytes) -> str:
    return base64.b64encode(rail.ed25519_public_key(seed)).decode()


def signature(seed: bytes, data: bytes) -> dict[str, str]:
    """A key and a signature over ``data``."""
    return {"publicKey": public_key(seed),
            "signature": base64.b64encode(rail.ed25519_sign(seed, data)).decode()}


def requirement_body() -> dict[str, Any]:
    return {
        "capability": {
            "id": "ticket-routing",
            "statement": "Route an inbound support ticket to the right queue and refuse "
                         "only tickets that are out of scope.",
        },
        "evaluationSet": {
            "digest": reader.items_digest(ITEMS),
            "heldOut": {"assessorKey": public_key(ASSESSOR), "commitment": COMMITMENT},
            "items": list(ITEMS),
        },
        "issuedAt": "2026-10-01T09:00:00Z",
        "thresholds": [
            {"comparator": "gte", "maxDrift": 30, "metric": "accuracy-permille",
             "set": "public", "value": 900},
            {"comparator": "lte", "maxDrift": 20, "metric": "false-refusal-permille",
             "set": "heldOut", "value": 50},
        ],
    }


def sign_requirement(body: dict[str, Any], *, signer: bytes | None = REQUIRER,
                     attester: bytes | None = ASSESSOR) -> dict[str, Any]:
    """A requirement record: the body, the requirer's signature, the assessor's attestation."""
    record: dict[str, Any] = {"requirement": body}
    if signer is not None:
        record["requirerSignature"] = signature(signer, reader.canonical(body))
    if attester is not None and (body["evaluationSet"].get("heldOut") or None) is not None:
        record["assessorAttestation"] = signature(attester, reader.attestation_bytes(body))
    return record


def requirement_record() -> dict[str, Any]:
    return sign_requirement(requirement_body())


def sign_run(rr: dict[str, Any], run_id: str, observed: str, public: dict[str, int],
             held: dict[str, int] | None, *, digest: str | None = None,
             endpoint: str = "https://api.example.test/v1", signer: bytes | None = VERIFIER,
             assessor: bytes | None = ASSESSOR) -> dict[str, Any]:
    """One run, signed by the verifier and, for its held-out part, by the assessor."""
    body = {
        "endpoint": endpoint, "heldOut": None if held is None else {"results": held},
        "observedAt": observed, "public": public,
        "requirementDigest": digest or reader.requirement_digest(rr["requirement"]),
        "runId": run_id,
    }
    run: dict[str, Any] = {"body": body}
    if signer is not None:
        run["verifierSignature"] = signature(signer, reader.canonical(body))
    if held is not None and assessor is not None:
        run["assessorSignature"] = signature(assessor, reader.assessor_run_bytes(run))
    return run


def resign_run(run: dict[str, Any]) -> None:
    """Sign the verifier's part again after a change to the body."""
    run["verifierSignature"] = signature(VERIFIER, reader.canonical(run["body"]))


def good_run(rr: dict[str, Any], run_id: str = "run-1", observed: str = "2026-11-01T10:00:00Z",
             public: int = 931, held: int | None = 32, **options: Any) -> dict[str, Any]:
    return sign_run(rr, run_id, observed, {"accuracy-permille": public},
                    None if held is None else {"false-refusal-permille": held}, **options)


def envelope(name: str, kind: str, **members: Any) -> dict[str, Any]:
    record: dict[str, Any] = {"contractId": reader.CONTRACT_ID, "kind": kind,
                              "recordId": f"record-{name}"}
    record.update(members)
    return {key: item for key, item in record.items() if item is not None}


def without(record: dict[str, Any], key: str) -> dict[str, Any]:
    return {name: item for name, item in record.items() if name != key}


def requirement_case(name: str, rr: dict[str, Any], **top: Any) -> dict[str, Any]:
    return envelope(name, "requirement", **rr, **top)


def report_case(name: str, rr: dict[str, Any], run: dict[str, Any], behaviour: str | None = None,
                identity: str = "unproven", endpoint: dict[str, Any] | None = None,
                **top: Any) -> dict[str, Any]:
    stated = reader.behaviour(rr, run) if behaviour is None else behaviour
    return envelope(name, "endpoint-report", requirementRecord=rr, run=run,
                    endpoint=HOSTED if endpoint is None else endpoint,
                    modelIdentity=identity, behaviour=stated, **top)


def drift_case(name: str, rr: dict[str, Any], baseline: dict[str, Any],
               current: dict[str, Any], **top: Any) -> dict[str, Any]:
    return envelope(name, "drift", requirementRecord=rr, baseline=baseline, current=current,
                    comparison=reader.compare(rr, baseline, current), **top)


def _requirement_controls() -> list[Case]:
    free = requirement_body()
    free["capability"]["statement"] = ("Route a ticket to a queue; any model or rule set may "
                                       "do it.")
    single = requirement_body()
    single["thresholds"] = single["thresholds"][1:]
    ok = reader.ALLOWED_REASON
    cases = [
        ("allow-requirement-pinned", requirement_record(),
         "control: a capability apart from any model, two pinned thresholds, an evaluation "
         "set digest and an assessor-attested held-out commitment"),
        ("allow-requirement-one-held-out-threshold",
         requirement_case("x", sign_requirement(single)),
         "control: one threshold, read from the held-out part"),
        ("allow-capability-statement-uses-the-word-model",
         requirement_case("x", sign_requirement(free)),
         "control: the word model in the statement is not a member that names a model"),
    ]
    return [(name, requirement_case(name, rr) if "kind" not in rr else
             {**rr, "recordId": f"record-{name}"}, "allow", ok, edit)
            for name, rr, edit in cases]


def _tampered(name: str, mutate: Any, edit: str, reason: str) -> Case:
    """A requirement edited after both signatures, so its signature check fails first."""
    rr = requirement_record()
    mutate(rr["requirement"])
    return (name, requirement_case(name, rr), "deny", reason, edit)


def _resigned(name: str, mutate: Any, reason: str, edit: str) -> Case:
    """A requirement edited and signed again, so the check under test fires first."""
    body = requirement_body()
    mutate(body)
    return (name, requirement_case(name, sign_requirement(body)), "deny", reason, edit)


def _set(path: list[str | int], value: Any) -> Any:
    def mutate(body: dict[str, Any]) -> None:
        target: Any = body
        for step in path[:-1]:
            target = target[step]
        target[path[-1]] = value
    return mutate


def _drop(path: list[str | int]) -> Any:
    def mutate(body: dict[str, Any]) -> None:
        target: Any = body
        for step in path[:-1]:
            target = target[step]
        del target[path[-1]]
    return mutate


def _requirement_denials() -> list[Case]:
    unknown = reader.CONTRACT_ID.replace("/predicate/v1/", "/contract/v0/")
    base = requirement_record()
    cases: list[Case] = [
        ("reject-requirement-contract-id-missing",
         without(requirement_case("x", base), "contractId"), "deny", "contract_id_missing",
         "the record names no contract"),
        ("reject-requirement-contract-id-unknown",
         {**requirement_case("reject-requirement-contract-id-unknown", base),
          "contractId": unknown}, "deny", "contract_id_unknown",
         "the record names a contract that does not exist"),
        ("reject-requirement-kind-unknown",
         {**requirement_case("reject-requirement-kind-unknown", base), "kind": "requirement-2"},
         "deny", "kind_unknown", "the record's kind is not one of the three"),
    ]
    for name, edit in (
        ("reject-requirement-unsigned", "the requirement carries no signature"),
        ("reject-requirement-signed-by-another-key",
         "the signature comes from a key other than the one the record names"),
    ):
        rr = requirement_record()
        if name.endswith("unsigned"):
            del rr["requirerSignature"]
        else:
            rr["requirerSignature"] = {
                "publicKey": rr["requirerSignature"]["publicKey"],
                "signature": signature(OTHER, reader.canonical(rr["requirement"]))["signature"]}
        cases.append((name, requirement_case(name, rr), "deny",
                      "requirement_signature_invalid", edit))
    sig = "requirement_signature_invalid"
    cases += [
        _tampered("reject-threshold-changed-after-signing",
                  _set(["thresholds", 0, "value"], 700),
                  "the accuracy threshold was lowered after the requirer signed", sig),
        _tampered("reject-threshold-added-after-signing",
                  lambda b: b["thresholds"].append(
                      {"comparator": "gte", "maxDrift": 0, "metric": "extra-permille",
                       "set": "public", "value": 1}),
                  "a threshold was added after signing", sig),
        _tampered("reject-capability-changed-after-signing",
                  _set(["capability", "statement"], "Route every ticket to one queue."),
                  "the capability statement changed after signing", sig),
        _tampered("reject-evaluation-digest-edited-after-signing",
                  _set(["evaluationSet", "digest"], "0" * 64),
                  "the evaluation-set digest was edited after signing", sig),
        _tampered("reject-held-out-assessor-changed-after-signing",
                  _set(["evaluationSet", "heldOut", "assessorKey"], public_key(OTHER)),
                  "the named assessor key was swapped after signing", sig),
    ]
    model = "capability_names_a_model"
    for name, member, value in (
        ("reject-capability-names-a-model", "model", "model-a"),
        ("reject-capability-names-a-model-digest", "modelDigest", "a" * 64),
        ("reject-capability-names-an-endpoint", "endpoint", "https://api.example.test/v1"),
        ("reject-capability-names-a-provider", "provider", "provider-a"),
    ):
        cases.append(_resigned(name, _set(["capability", member], value), model,
                               f"the capability carries a {member} member, so it is not "
                               "stated apart from any model"))
    cases.append(_resigned("reject-capability-statement-missing",
                           _drop(["capability", "statement"]), model,
                           "the capability has an id and no statement"))
    bad = "thresholds_invalid"
    cases += [
        _resigned("reject-thresholds-empty", _set(["thresholds"], []), bad,
                  "no threshold, so a verdict has nothing to be checked against"),
        _resigned("reject-thresholds-duplicate-metric",
                  lambda b: b["thresholds"].append(copy.deepcopy(b["thresholds"][0])), bad,
                  "one metric pinned twice"),
        _resigned("reject-threshold-comparator-unknown",
                  _set(["thresholds", 0, "comparator"], "approximately"), bad,
                  "a comparator outside gte and lte"),
        _resigned("reject-threshold-value-a-string", _set(["thresholds", 0, "value"], "900"),
                  bad, "the pinned value is text, not an integer"),
        _resigned("reject-threshold-value-a-fraction",
                  _set(["thresholds", 0, "value"], 0.9), bad,
                  "the pinned value is a fraction, which parsers write several ways"),
        _resigned("reject-threshold-set-unknown", _set(["thresholds", 1, "set"], "private"),
                  bad, "a threshold read from a set the evaluation does not have"),
        _resigned("reject-threshold-without-drift-tolerance",
                  _drop(["thresholds", 0, "maxDrift"]), bad,
                  "no tolerance, so drift has no bound to be compared against"),
        _resigned("reject-threshold-negative-drift-tolerance",
                  _set(["thresholds", 0, "maxDrift"], -1), bad,
                  "a tolerance below zero"),
    ]
    mismatch = "evaluation_set_digest_mismatch"
    cases += [
        _resigned("reject-evaluation-digest-mismatch",
                  _set(["evaluationSet", "digest"], "0" * 64), mismatch,
                  "signed with a digest that is not the digest of the items"),
        _resigned("reject-evaluation-item-added-after-digest",
                  lambda b: b["evaluationSet"]["items"].append("1" * 64), mismatch,
                  "an item listed that the digest does not cover"),
        _resigned("reject-evaluation-item-not-a-digest",
                  _set(["evaluationSet", "items", 0], "item-0"), mismatch,
                  "an item named by a label, not by its digest"),
        _resigned("reject-evaluation-set-empty",
                  lambda b: b["evaluationSet"].update(items=[],
                                                      digest=reader.items_digest([])),
                  mismatch, "an evaluation set with no items"),
    ]
    attest = "held_out_commitment_not_attested"
    cases += [_held_out_denial(name, edit) for name, edit in (
        ("reject-held-out-absent", "the requirement names no held-out part"),
        ("reject-held-out-attestation-missing", "the assessor never attested the commitment"),
        ("reject-held-out-attested-by-another-key",
         "the attestation is by a key other than the assessor the requirement names"),
        ("reject-held-out-commitment-not-the-attested-one",
         "the requirement was signed again with a new commitment, and the attestation is "
         "still over the old one"),
        ("reject-held-out-attested-for-another-capability",
         "the assessor attested the commitment for a different capability"),
    )]
    assert all(case[3] == attest for case in cases[-5:])
    return cases


def _held_out_denial(name: str, edit: str) -> Case:
    body = requirement_body()
    attester: bytes | None = ASSESSOR
    if name.endswith("absent"):
        body["evaluationSet"]["heldOut"] = None
    elif name.endswith("missing"):
        attester = None
    elif name.endswith("another-key"):
        attester = OTHER
    rr = sign_requirement(body, attester=attester)
    if name.endswith("not-the-attested-one"):
        body["evaluationSet"]["heldOut"]["commitment"] = "2" * 64
        rr = {**sign_requirement(body), "assessorAttestation": rr["assessorAttestation"]}
    if name.endswith("another-capability"):
        other = copy.deepcopy(body)
        other["capability"]["id"] = "ticket-summarising"
        rr["assessorAttestation"] = signature(ASSESSOR, reader.attestation_bytes(other))
    return (name, requirement_case(name, rr), "deny", "held_out_commitment_not_attested", edit)


def _report_controls() -> list[Case]:
    rr = requirement_record()
    ok = reader.ALLOWED_REASON
    cases: list[tuple[str, dict[str, Any], str]] = []

    def add(name: str, run: dict[str, Any], edit: str, **options: Any) -> None:
        cases.append((name, report_case(name, rr, run, **options), edit))

    add("allow-report-identity-unproven-behaviour-supported", good_run(rr),
        "control: a hosted endpoint, model identity unproven and behaviour on the pinned "
        "set supported, as two findings")
    add("allow-report-behaviour-contradicted-public-miss", good_run(rr, public=871),
        "control: accuracy below its threshold, so behaviour is contradicted")
    add("allow-report-behaviour-contradicted-held-out-miss", good_run(rr, held=77),
        "control: a held-out value past its threshold, signed by the assessor")
    add("allow-report-threshold-exactly-met", good_run(rr, public=900, held=50),
        "control: both values on their thresholds, which meets them")
    add("allow-report-behaviour-not-established-no-held-out", good_run(rr, held=None),
        "control: no held-out part was run, so behaviour is not established, not supported")
    add("allow-report-contradiction-beats-missing-held-out", good_run(rr, public=871, held=None),
        "control: a public miss contradicts even when the held-out part is absent")
    missing = sign_run(rr, "run-1", "2026-11-01T10:00:00Z", {}, {"false-refusal-permille": 32})
    add("allow-report-behaviour-not-established-metric-missing", missing,
        "control: the public metric is absent from the run, so it is not established")
    held = {"access": "weights-held", "claimedWeightsDigest": "3" * 64}
    cases.append(("allow-report-identity-proven-with-weights-held",
                  report_case("allow-report-identity-proven-with-weights-held", rr, good_run(rr),
                              identity="proven", endpoint=held,
                              identityProof={"weightsDigest": "3" * 64}),
                  "control: the endpoint holds weights and the report proves the claimed digest"))
    return [(name, record, "allow", ok, edit) for name, record, edit in cases]


def _report_denials() -> list[Case]:
    rr = requirement_record()
    cases: list[tuple[str, dict[str, Any], str, str]] = []

    def add(name: str, record: dict[str, Any], reason: str, edit: str) -> None:
        cases.append((name, record, reason, edit))

    run = good_run(rr)
    unsigned = copy.deepcopy(rr)
    del unsigned["requirerSignature"]
    add("reject-report-requirement-unsigned",
        report_case("reject-report-requirement-unsigned", unsigned, run),
        "requirement_invalid", "the report carries a requirement the requirer never signed")
    other = requirement_body()
    other["thresholds"][0]["value"] = 800
    other_rr = sign_requirement(other)
    add("reject-report-run-for-another-requirement",
        report_case("reject-report-run-for-another-requirement", rr, good_run(other_rr)),
        "run_against_other_requirement",
        "the run names the digest of a requirement with a lower accuracy threshold")
    stale = good_run(rr, digest="4" * 64)
    add("reject-report-run-names-no-known-requirement",
        report_case("reject-report-run-names-no-known-requirement", rr, stale),
        "run_against_other_requirement", "the run names a requirement digest nobody signed")
    run_unsigned = good_run(rr, signer=None)
    add("reject-report-run-unsigned",
        report_case("reject-report-run-unsigned", rr, run_unsigned),
        "run_signature_invalid", "the run carries no verifier signature")
    edited = good_run(rr)
    edited["body"]["public"]["accuracy-permille"] = 960
    add("reject-report-run-edited-after-signing",
        report_case("reject-report-run-edited-after-signing", rr, edited, behaviour="supported"),
        "run_signature_invalid", "a public value was raised after the verifier signed")
    by_other = good_run(rr, signer=OTHER)
    by_other["verifierSignature"]["publicKey"] = public_key(VERIFIER)
    add("reject-report-run-signed-by-another-key",
        report_case("reject-report-run-signed-by-another-key", rr, by_other),
        "run_signature_invalid", "the signature is not by the key the run names")
    for name, edit in (
        ("reject-report-held-out-unsigned",
         "held-out results with no assessor signature"),
        ("reject-report-held-out-signed-by-the-verifier",
         "the verifier signed the held-out results in place of the assessor"),
        ("reject-report-held-out-signed-by-another-assessor",
         "a key other than the named assessor signed the held-out results"),
        ("reject-report-held-out-edited-after-assessor-signed",
         "the held-out result was lowered after the assessor signed, and the verifier signed "
         "the new body"),
        ("reject-report-held-out-signature-from-another-run",
         "the assessor's signature is from a different run of the same requirement"),
    ):
        held = good_run(rr)
        if name.endswith("unsigned"):
            del held["assessorSignature"]
        elif name.endswith("the-verifier"):
            held["assessorSignature"] = signature(VERIFIER, reader.assessor_run_bytes(held))
        elif name.endswith("another-assessor"):
            held["assessorSignature"] = signature(OTHER, reader.assessor_run_bytes(held))
        elif name.endswith("signed"):
            held["body"]["heldOut"]["results"]["false-refusal-permille"] = 10
            resign_run(held)
        else:
            donor = good_run(rr, run_id="run-0", held=44)
            held["assessorSignature"] = donor["assessorSignature"]
        add(name, report_case(name, rr, held, behaviour="supported"),
            "held_out_not_assessor_signed", edit)
    base = report_case("x", rr, run)
    merged = {**base, "verdict": "pass", "recordId": "record-reject-report-verdict-merged"}
    add("reject-report-single-verdict", merged, "findings_merged",
        "a combined verdict member sits beside the two findings")
    one = {key: item for key, item in base.items() if key != "modelIdentity"}
    one["recordId"] = "record-reject-report-model-identity-absent"
    one["verdict"] = "pass"
    add("reject-report-model-identity-absent", one, "findings_merged",
        "behaviour is stated and the identity finding is folded into a pass")
    nobehaviour = {key: item for key, item in base.items() if key != "behaviour"}
    nobehaviour["recordId"] = "record-reject-report-behaviour-absent"
    add("reject-report-behaviour-absent", nobehaviour, "findings_merged",
        "model identity is stated and the behaviour finding is missing")
    add("reject-report-identity-proven-for-a-hosted-endpoint",
        report_case("reject-report-identity-proven-for-a-hosted-endpoint", rr, run,
                    identity="proven"),
        "model_identity_overclaimed",
        "no bytes were held, so nothing can be proven about the model")
    add("reject-report-identity-matches-the-claimed-model",
        report_case("reject-report-identity-matches-the-claimed-model", rr, run,
                    identity="same-as-claimed"),
        "model_identity_overclaimed",
        "behaviour on the pinned set read as the identity of the model")
    held = {"access": "weights-held", "claimedWeightsDigest": "3" * 64}
    add("reject-report-identity-proven-with-another-digest",
        report_case("reject-report-identity-proven-with-another-digest", rr, run,
                    identity="proven", endpoint=held,
                    identityProof={"weightsDigest": "5" * 64}),
        "model_identity_overclaimed",
        "the weights held hash to a digest other than the claimed one")
    add("reject-report-identity-proven-without-proof",
        report_case("reject-report-identity-proven-without-proof", rr, run, identity="proven",
                    endpoint=held),
        "model_identity_overclaimed", "proven with no digest of the weights held")
    add("reject-report-behaviour-supported-with-a-miss",
        report_case("reject-report-behaviour-supported-with-a-miss", rr, good_run(rr, public=871),
                    behaviour="supported"),
        "behaviour_mismatch", "accuracy is below its threshold and the report says supported")
    add("reject-report-behaviour-contradicted-with-every-value-met",
        report_case("reject-report-behaviour-contradicted-with-every-value-met", rr, run,
                    behaviour="contradicted"),
        "behaviour_mismatch", "every pinned value is met and the report says contradicted")
    add("reject-report-behaviour-supported-without-held-out",
        report_case("reject-report-behaviour-supported-without-held-out", rr,
                    good_run(rr, held=None), behaviour="supported"),
        "behaviour_mismatch", "the held-out threshold has no value and the report says supported")
    add("reject-report-behaviour-not-established-when-measured",
        report_case("reject-report-behaviour-not-established-when-measured", rr, run,
                    behaviour="not_established"),
        "behaviour_mismatch",
        "every threshold has a usable value and the report says not established")
    add("reject-report-behaviour-value-unknown",
        report_case("reject-report-behaviour-value-unknown", rr, run, behaviour="passed"),
        "behaviour_mismatch", "a behaviour word outside the three")
    return [(name, record, "deny", reason, edit) for name, record, reason, edit in cases]


def _drift_controls() -> list[Case]:
    rr = requirement_record()
    ok = reader.ALLOWED_REASON
    base = good_run(rr)
    cases: list[tuple[str, dict[str, Any], str]] = []

    def add(name: str, current: dict[str, Any], edit: str,
            baseline: dict[str, Any] | None = None) -> None:
        cases.append((name, drift_case(name, rr, base if baseline is None else baseline, current),
                      edit))

    later = "2026-11-08T10:00:00Z"
    add("allow-drift-stable", good_run(rr, "run-2", later, public=925, held=35),
        "control: both runs meet their thresholds and no metric worsened past its tolerance")
    add("allow-drift-improvement-is-stable", good_run(rr, "run-2", later, public=985, held=5),
        "control: a better current run is not drift")
    add("allow-drift-change-within-tolerance", good_run(rr, "run-2", later, public=905, held=50),
        "control: accuracy fell by 26 against a tolerance of 30 and still meets its threshold")
    add("allow-drift-worsened-past-tolerance", good_run(rr, "run-2", later, public=900, held=32),
        "control: accuracy fell by 31 against a tolerance of 30 and still meets its threshold, "
        "which is drift")
    narrow = good_run(rr, "run-0", "2026-10-30T10:00:00Z", public=902, held=32)
    add("allow-drift-flip-is-drift-even-if-small",
        good_run(rr, "run-2", later, public=899, held=32),
        "control: a fall of 3 within the tolerance that crosses the threshold is drift",
        baseline=narrow)
    add("allow-drift-not-established-held-out-missing-now",
        good_run(rr, "run-2", later, public=931, held=None),
        "control: the current run has no held-out part, so that metric cannot be compared")
    return [(name, record, "allow", ok, edit) for name, record, edit in cases]


def _drift_denials() -> list[Case]:
    rr = requirement_record()
    base = good_run(rr)
    later = "2026-11-08T10:00:00Z"
    current = good_run(rr, "run-2", later, public=925, held=35)
    cases: list[tuple[str, dict[str, Any], str, str]] = []

    def add(name: str, record: dict[str, Any], reason: str, edit: str) -> None:
        cases.append((name, record, reason, edit))

    unsigned = copy.deepcopy(rr)
    del unsigned["requirerSignature"]
    add("reject-drift-requirement-unsigned",
        drift_case("reject-drift-requirement-unsigned", unsigned, base, current),
        "requirement_invalid", "the comparison rests on a requirement nobody signed")
    other = requirement_body()
    other["thresholds"][0]["value"] = 800
    other_rr = sign_requirement(other)
    add("reject-drift-runs-against-different-requirement-digests",
        drift_case("reject-drift-runs-against-different-requirement-digests", rr, base,
                   good_run(other_rr, "run-2", later)),
        "run_against_other_requirement",
        "the current run was made against a requirement with another threshold")
    add("reject-drift-baseline-for-another-requirement",
        drift_case("reject-drift-baseline-for-another-requirement", rr, good_run(other_rr),
                   current),
        "run_against_other_requirement", "the baseline names another requirement's digest")
    add("reject-drift-runs-on-different-endpoints",
        drift_case("reject-drift-runs-on-different-endpoints", rr, base,
                   good_run(rr, "run-2", later, public=925, held=35,
                            endpoint="https://api.example.test/v2")),
        "runs_on_different_endpoints", "two endpoints compared as one")
    add("reject-drift-baseline-unsigned",
        drift_case("reject-drift-baseline-unsigned", rr, good_run(rr, signer=None), current),
        "run_signature_invalid", "the baseline carries no verifier signature")
    add("reject-drift-current-unsigned",
        drift_case("reject-drift-current-unsigned", rr, base,
                   good_run(rr, "run-2", later, public=925, held=35, signer=None)),
        "run_signature_invalid", "the current run carries no verifier signature")
    edited = copy.deepcopy(current)
    edited["body"]["public"]["accuracy-permille"] = 980
    add("reject-drift-current-edited-after-signing",
        drift_case("reject-drift-current-edited-after-signing", rr, base, edited),
        "run_signature_invalid", "a current public value changed after the verifier signed")
    held_less = good_run(rr, "run-2", later, public=925, held=35, assessor=None)
    add("reject-drift-held-out-unsigned-in-the-current-run",
        drift_case("reject-drift-held-out-unsigned-in-the-current-run", rr, base, held_less),
        "held_out_not_assessor_signed",
        "the current held-out results carry no assessor signature")
    add("reject-drift-held-out-signed-by-the-verifier-in-the-baseline",
        drift_case("reject-drift-held-out-signed-by-the-verifier-in-the-baseline", rr,
                   _verifier_held(rr), current),
        "held_out_not_assessor_signed", "the baseline's held-out part is signed by the verifier")
    add("reject-drift-the-same-run-twice",
        drift_case("reject-drift-the-same-run-twice", rr, base, copy.deepcopy(base)),
        "runs_not_distinct", "one run listed as both baseline and current")
    same_id = good_run(rr, "run-1", later, public=925, held=35)
    add("reject-drift-two-runs-with-one-run-id",
        drift_case("reject-drift-two-runs-with-one-run-id", rr, base, same_id),
        "runs_not_distinct", "two different runs that share one run id")
    add("reject-drift-current-run-before-the-baseline",
        drift_case("reject-drift-current-run-before-the-baseline", rr, base,
                   good_run(rr, "run-2", "2026-10-20T10:00:00Z", public=925, held=35)),
        "runs_out_of_order", "the current run was made before the baseline")
    add("reject-drift-runs-at-one-instant",
        drift_case("reject-drift-runs-at-one-instant", rr, base,
                   good_run(rr, "run-2", base["body"]["observedAt"], public=925, held=35)),
        "runs_out_of_order", "two runs at the same instant are not a before and an after")
    cases += _comparison_denials(rr, base)
    return [(name, record, "deny", reason, edit) for name, record, reason, edit in cases]


def _verifier_held(rr: dict[str, Any]) -> dict[str, Any]:
    run = good_run(rr)
    run["assessorSignature"] = signature(VERIFIER, reader.assessor_run_bytes(run))
    return run


def _comparison_denials(
        rr: dict[str, Any], base: dict[str, Any]) -> list[tuple[str, dict[str, Any], str, str]]:
    later = "2026-11-08T10:00:00Z"
    reason = "comparison_wrong"
    out: list[tuple[str, dict[str, Any], str, str]] = []

    def add(name: str, current: dict[str, Any], edit: str, mutate: Any,
            baseline: dict[str, Any] | None = None) -> None:
        record = drift_case(name, rr, base if baseline is None else baseline, current)
        mutate(record["comparison"])
        out.append((name, record, reason, edit))

    worse = good_run(rr, "run-2", later, public=860, held=32)
    add("reject-drift-outcome-stable-but-worsened-past-tolerance", worse,
        "accuracy fell by 71 against a tolerance of 30 and the outcome says stable",
        _set(["outcome"], "stable"))
    within = good_run(rr, "run-2", later, public=925, held=35)
    add("reject-drift-outcome-drifted-within-tolerance", within,
        "nothing worsened past its tolerance and the outcome says drifted",
        _set(["outcome"], "drifted"))
    narrow = good_run(rr, "run-0", "2026-10-30T10:00:00Z", public=902, held=32)
    cross = good_run(rr, "run-2", later, public=899, held=32)
    add("reject-drift-threshold-crossed-called-stable", cross,
        "a metric fell from meeting its threshold to missing it and the outcome says stable",
        _set(["outcome"], "stable"), baseline=narrow)
    add("reject-drift-change-computed-the-wrong-way", worse,
        "worsenedBy computed as an increase, so a fall reads as an improvement",
        _set(["changes", 0, "worsenedBy"], -71))
    add("reject-drift-change-missing", within,
        "a compared metric left out of the changes", _drop(["changes", 1]))
    add("reject-drift-run-id-swapped", within,
        "the comparison names the runs the other way round",
        lambda c: c.update(baselineRunId=c["currentRunId"], currentRunId=c["baselineRunId"]))
    missing = good_run(rr, "run-2", later, public=931, held=None)
    add("reject-drift-stable-with-an-unmatched-metric", missing,
        "the held-out metric has no usable value in the current run and the outcome says stable",
        lambda c: c.update(outcome="stable"))
    return out


def cases() -> list[Case]:
    """Every case: id, record, decision, reason, and what it shows."""
    named: list[Case] = [*_requirement_controls(), *_requirement_denials(),
                         *_report_controls(), *_report_denials(),
                         *_drift_controls(), *_drift_denials()]
    return [(name, {**record, "recordId": f"record-{name}"}, decision, reason, edit)
            for name, record, decision, reason, edit in named]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base_dir = Path(root)
    rows = []
    for entry in manifest["vectors"]:
        directory = base_dir / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        rows.append({**entry, "files": files})
    return _sha(_json(rows))


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    if (root / "cases").exists():
        shutil.rmtree(root / "cases")
    rows = []
    for name, body, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True)
        data = _json(body)
        (directory / "record.json").write_bytes(data)
        expected = {"decision": decision, "reason": reason}
        observed = reader.verify(directory / "record.json")
        if observed != expected:
            raise SystemExit(f"{name}: the reader says {observed}, the case {expected}")
        rows.append({"edit": edit, "expected": expected,
                     "files": {"record.json": _sha(data)}, "id": name,
                     "path": f"cases/{name}", "retained": reader.retained(copy.deepcopy(body))})
    words = [row["expected"]["decision"] for row in rows]
    kinds = [row["retained"]["kind"] for row in rows]
    manifest = {
        "contractId": reader.CONTRACT_ID,
        "corpusDigest": _sha(_json(rows)),
        "counts": {word: words.count(word) for word in sorted(set(words))},
        "kinds": {kind: kinds.count(kind) for kind in sorted(set(kinds))},
        "suite": SUITE,
        "synthetic": True,
        "verifierContract": "verifier record.json --json; exit 0 allow, 1 deny",
        "vectors": rows,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
