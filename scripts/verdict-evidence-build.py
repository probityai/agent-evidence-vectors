#!/usr/bin/env python3
"""Build the ACS verdict evidence controls.

Each supported case is a signed verdict or quarantine record a consumer should
accept. Each refused case changes one thing about a supported twin and states
the first check that must refuse it. The generator uses the package's own
stdlib Ed25519, so the corpus builds with nothing but CPython.

TEST KEYS ONLY. Each seed is the SHA-256 of a published label, so anyone can
re-derive every key and re-sign every case.

    python scripts/verdict-evidence-build.py           # write the corpus
    python scripts/verdict-evidence-build.py --check   # exit 1 if it differs
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import shutil
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

PACKAGING = Path(__file__).resolve().parents[1] / "packaging"
sys.path.insert(0, str(PACKAGING))

import run_vectors  # noqa: E402
from agent_evidence_vectors.verdict_evidence.reader import (  # noqa: E402
    DIGEST_FIELDS,
    DOES_NOT_COVER,
    INTOTO,
    PEER_PREDICATE,
    QUARANTINE_FIELDS,
    STATEMENT_V1,
    SUITE,
    VECTOR_PREFIX,
    VERDICT_PREDICATE,
    canonical,
    pae,
    sha256_hex,
)

CORPUS = PACKAGING / "agent_evidence_vectors/verdict_evidence/corpus"
S, C, N = "supported", "contradicted", "not_established"
AS_OF = "2026-11-01T00:00:00Z"
ANCHOR = "docs/spec/instrument/specification.md#103-replay-protection"
OPERATOR = "acme-demo:operator/deployment-01"


def seed(role: str) -> bytes:
    return hashlib.sha256(f"aev-verdict-evidence-test-key/{role}/v1".encode()).digest()


def public(role: str) -> bytes:
    return run_vectors.ed25519_public_key(seed(role))


def keyid(role: str) -> str:
    return sha256_hex(public(role))


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def envelope(statement: dict[str, Any], signers: list[str]) -> dict[str, Any]:
    body = canonical(statement)
    return {"payloadType": INTOTO, "payload": b64(body), "signatures": [
        {"keyid": keyid(r), "sig": b64(run_vectors.ed25519_sign(seed(r), pae(INTOTO, body)))}
        for r in signers]}


# The two wire vectors of the draft's reference sample: a toolCallRequest with no
# request_id (replay protection), and a userMessage carrying a MODIFY redaction.
VECTOR: dict[str, Any] = {
    "jsonrpc": "2.0", "method": "steps/toolCallRequest", "id": 1,
    "params": {
        "acs_version": "0.1.0", "timestamp": "2026-10-17T00:00:00Z",
        "metadata": {"agent_id": "dev-agent", "session_id": "sess-1", "turn_id": "t1"},
        "payload": {"tool": {"id": "fs.write", "capability": "write"},
                    "arguments": [{"name": "path", "value": "/tmp/out"}],
                    "agent_reasoning": "write output"},
    },
}
QUARANTINE_VECTOR: dict[str, Any] = {
    "jsonrpc": "2.0", "method": "steps/userMessage", "id": 2,
    "params": {
        "acs_version": "0.1.0", "request_id": "uuid-0002", "timestamp": "2026-10-17T00:00:01Z",
        "metadata": {"agent_id": "dev-agent", "session_id": "sess-1", "turn_id": "t1"},
        "payload": {"content": "PII: card 4111-1111-1111-1111", "modify": {"redact": ["card"]}},
    },
}
OTHER_VECTOR = copy.deepcopy(VECTOR)
OTHER_VECTOR["params"]["timestamp"] = "2026-10-17T00:05:00Z"
OBSERVED = {"decision": "deny", "reason_codes": ["missing_request_id"]}


def vdigest(vector: dict[str, Any]) -> str:
    return sha256_hex(canonical(vector))


def transcript(observed: dict[str, Any] = OBSERVED) -> bytes:
    return canonical({"request": VECTOR, "response": {"jsonrpc": "2.0", "id": 1, "result": {
        "type": "final", "acs_version": "0.1.0", **observed}}})


def subject(vector: dict[str, Any]) -> list[dict[str, Any]]:
    d = vdigest(vector)
    return [{"name": VECTOR_PREFIX + d[:16], "digest": {"sha256": d}}]


def seal(predicate: dict[str, Any], fields: list[str]) -> dict[str, Any]:
    predicate["integrity"]["payload_digest"] = sha256_hex(
        canonical({f: predicate[f] for f in fields if f in predicate}))
    return predicate


def verdict(scope: str = "SELF", peer_artifact: str | None = None,
            hosting: str = OPERATOR, outcome: str = "rejected") -> dict[str, Any]:
    d = vdigest(VECTOR)
    p: dict[str, Any] = {
        "vector_id": d[:16], "profile": "acs-core", "anchor": ANCHOR,
        "clause": "10.3 Replay protection (ACS-Core)", "verdict": outcome,
        "witness_derivation": {"runner": {"id": "acs-runner@0.1.0-demo",
                                          "hosting_operator_id": hosting},
                               "deployment_operator_id": OPERATOR},
        "witness_scope": scope, "verification_basis": ["wire_transcript"],
        "expected": OBSERVED, "observed": OBSERVED, "behavior_snapshot": None,
        "integrity": {"payload_digest": "0" * 64, "payload_digest_fields": list(DIGEST_FIELDS),
                      "does_not_cover": list(DOES_NOT_COVER),
                      "binding": "observed hashes are bound only by the runner's own DSSE "
                                 "envelope signature; the subject is bound by the envelope"},
        "provenance": {"peer_artifact": peer_artifact, "anchor": None},
    }
    return seal(p, list(DIGEST_FIELDS))


def peer_statement(kind: str = "wire_transcript", vector: dict[str, Any] = VECTOR,
                   requirement: str = ANCHOR, observed: dict[str, Any] = OBSERVED,
                   transcript_bytes: bytes | None = None,
                   deployment: str = OPERATOR, outcome: str = "rejected") -> dict[str, Any]:
    artifact: dict[str, Any]
    if kind == "client_run":
        artifact = {"kind": "client_run", "deployment": deployment}
    elif kind == "wire_transcript":
        artifact = {"kind": "wire_transcript",
                    "transcript_digest": sha256_hex(transcript_bytes or transcript()),
                    "vector": VECTOR_PREFIX + vdigest(vector)[:16]}
    else:
        artifact = {"kind": kind}
    return {"_type": STATEMENT_V1, "subject": subject(vector), "predicateType": PEER_PREDICATE,
            "predicate": {"requirement": requirement, "evidence_artifact": artifact,
                          "observed": observed, "verdict": outcome,
                          "checked_at": "2026-10-18T01:00:00Z"}}


def statement(predicate: dict[str, Any], vector: dict[str, Any] = VECTOR) -> dict[str, Any]:
    return {"_type": STATEMENT_V1, "subject": subject(vector),
            "predicateType": VERDICT_PREDICATE, "predicate": predicate}


def quarantine() -> dict[str, Any]:
    d = vdigest(QUARANTINE_VECTOR)
    p: dict[str, Any] = {
        "vector_id": d[:16], "status": "quarantined",
        "reason": "payload carries a MODIFY redaction request; the disposition for an "
                  "unscoreable MODIFY composition is not normatively specified",
        "quarantine_ref": "https://github.com/GenAI-Security-Project/agent-control-standard/"
                          "issues/296",
        "quarantine_gap": "normative disposition for an unscoreable MODIFY composition",
        "owner": "spec workstream (issue 296 assignee)", "review_by": "2026-11-16",
        "excluded_from": "formal result until issue 296 is resolved",
        "expiry_disposition": "revert_to_unmeasurable",
        "integrity": {"payload_digest": "0" * 64,
                      "payload_digest_fields": list(QUARANTINE_FIELDS)},
    }
    return seal(p, list(QUARANTINE_FIELDS))


def policy(as_of: str = AS_OF) -> dict[str, Any]:
    return {
        "payload_type": INTOTO, "predicate_type": VERDICT_PREDICATE,
        "peer_predicate_type": PEER_PREDICATE,
        "trusted_keys": {keyid("runner"): b64(public("runner"))},
        "peer_keys": {
            keyid("peer"): {"public_key": b64(public("peer")), "relationship": "peer"},
            keyid("external"): {"public_key": b64(public("external")),
                                "relationship": "external"},
        },
        "as_of": as_of,
    }


class Case:
    """One case: the files it writes, its expected answer and its twin."""

    def __init__(self) -> None:
        self.record: dict[str, Any] = {}
        self.vector: dict[str, Any] = VECTOR
        self.policy = policy()
        self.peer: dict[str, Any] | None = None
        self.transcript: bytes | None = None

    def files(self) -> dict[str, bytes]:
        out = {"record.json": json.dumps(self.record, sort_keys=True).encode(),
               "vector.json": canonical(self.vector)}
        supplied = {}
        if self.peer is not None:
            out["peer-statement.json"] = json.dumps(self.peer, sort_keys=True).encode()
            supplied["peer_statement"] = "peer-statement.json"
        if self.transcript is not None:
            out["transcript.json"] = self.transcript
            supplied["transcript"] = "transcript.json"
        out["case.json"] = (json.dumps({"record": "record.json", "vector": "vector.json",
                                        "supplied": supplied, "policy": self.policy},
                                       indent=2, sort_keys=True) + "\n").encode()
        return out


def self_case(predicate: dict[str, Any] | None = None, signers: tuple[str, ...] = ("runner",)
              ) -> Case:
    case = Case()
    case.record = envelope(statement(predicate or verdict()), list(signers))
    return case


def peer_case(signer: str = "peer", scope: str = "PEER", supply_peer: bool = True,
              supply_transcript: bool = True, transcript_bytes: bytes | None = None,
              named_digest: str | None = None, record_outcome: str = "rejected",
              **peer_kw: Any) -> Case:
    ps = peer_statement(**peer_kw)
    case = Case()
    named = named_digest or sha256_hex(canonical(ps))
    case.record = envelope(statement(verdict(scope, named, outcome=record_outcome)), ["runner"])
    case.peer = envelope(ps, [signer]) if supply_peer else None
    if supply_transcript and ps["predicate"]["evidence_artifact"]["kind"] == "wire_transcript":
        case.transcript = transcript_bytes if transcript_bytes is not None else transcript()
    return case


def quarantine_case(edit: Callable[[dict[str, Any]], None] | None = None, reseal: bool = False,
                    resign: bool = True, as_of: str = AS_OF) -> Case:
    q = quarantine()
    original = envelope(statement(q, QUARANTINE_VECTOR), ["runner"])
    if edit is not None:
        edit(q)
        if reseal:
            seal(q, q["integrity"]["payload_digest_fields"])
    case = Case()
    case.vector = QUARANTINE_VECTOR
    case.policy = policy(as_of)
    if resign:
        case.record = envelope(statement(q, QUARANTINE_VECTOR), ["runner"])
    else:
        # The edited bytes under the signature the original bytes carried.
        case.record = dict(original, payload=b64(canonical(statement(q, QUARANTINE_VECTOR))))
    return case


def _with(edit: Callable[[dict[str, Any]], None], reseal: bool = True) -> dict[str, Any]:
    p = verdict()
    edit(p)
    if reseal:
        seal(p, p["integrity"]["payload_digest_fields"])
    return p


def _set(*path_value: Any) -> Callable[[dict[str, Any]], None]:
    *path, value = path_value

    def edit(d: dict[str, Any]) -> None:
        for part in path[:-1]:
            d = d[part]
        d[path[-1]] = value
    return edit


def _drop(key: str) -> Callable[[dict[str, Any]], None]:
    return lambda d: d.pop(key)


def _fields_without(name: str) -> Callable[[dict[str, Any]], None]:
    return lambda d: d["integrity"].__setitem__(
        "payload_digest_fields", [f for f in d["integrity"]["payload_digest_fields"] if f != name])


SELF_TWIN, PEER_TWIN, WIRE_TWIN, Q_TWIN = (
    "accept-self-no-peer", "accept-peer-client-run", "accept-peer-wire-transcript",
    "accept-quarantine-in-force")

# (id, control, builder, expected decision, expected reason, twin)
CASES: list[tuple[str, str, Callable[[], Case], str, str, str | None]] = [
    (SELF_TWIN, "scope", self_case, S, "verdict_verified_self", None),
    ("accept-self-unpinned-cosignature", "scope",
     lambda: self_case(signers=("runner", "stranger")), S, "verdict_verified_self", None),
    ("accept-self-with-anchor", "scope",
     lambda: self_case(_with(_set("provenance", "anchor",
                                  {"kind": "rfc3161-timestamp", "reference": "tsa:demo/1"}))),
     S, "verdict_verified_self", None),
    (PEER_TWIN, "peer", lambda: peer_case(kind="client_run"), S, "verdict_verified_peer", None),
    (WIRE_TWIN, "peer", lambda: peer_case(), S, "verdict_verified_peer", None),
    ("accept-external-wire-transcript", "peer",
     lambda: peer_case(signer="external", scope="EXTERNAL"), S, "verdict_verified_external",
     None),
    ("reject-peer-wrong-key", "peer", lambda: peer_case(signer="stranger"), C,
     "peer_artifact_unverified:untrusted_key", WIRE_TWIN),
    ("reject-peer-signed-by-runner", "peer", lambda: peer_case(signer="runner"), C,
     "peer_artifact_unverified:untrusted_key", WIRE_TWIN),
    ("reject-peer-wrong-vector", "peer", lambda: peer_case(vector=OTHER_VECTOR), C,
     "peer_artifact_unverified:wrong_vector", WIRE_TWIN),
    ("reject-peer-wrong-requirement", "peer",
     lambda: peer_case(requirement="docs/spec/instrument/specification.md#102-signatures"), C,
     "peer_artifact_unverified:wrong_requirement", WIRE_TWIN),
    ("reject-peer-artifact-absent", "peer", lambda: peer_case(supply_peer=False), N,
     "peer_artifact_unverified:not_supplied", WIRE_TWIN),
    ("reject-peer-artifact-digest-mismatch", "peer",
     lambda: peer_case(named_digest=sha256_hex(b"another peer statement")), C,
     "peer_artifact_unverified:digest_mismatch", WIRE_TWIN),
    ("reject-peer-no-evidence-artifact", "peer", lambda: peer_case(kind="attestation"), C,
     "peer_artifact_unverified:no_evidence_artifact", WIRE_TWIN),
    ("reject-peer-client-run-other-deployment", "peer",
     lambda: peer_case(kind="client_run", deployment="acme-demo:operator/deployment-02"), C,
     "peer_artifact_unverified:wrong_deployment", PEER_TWIN),
    ("reject-transcript-absent", "peer", lambda: peer_case(supply_transcript=False), N,
     "peer_artifact_unverified:transcript_not_supplied", WIRE_TWIN),
    ("reject-transcript-digest-mismatch", "peer",
     lambda: peer_case(transcript_bytes=transcript({"decision": "allow",
                                                     "reason_codes": []})), C,
     "peer_artifact_unverified:transcript_digest_mismatch", WIRE_TWIN),
    ("reject-peer-disagrees", "peer",
     lambda: peer_case(observed={"decision": "allow", "reason_codes": []}), C,
     "peer_disagrees", WIRE_TWIN),
    ("reject-peer-reused-for-other-verdict", "peer",
     lambda: peer_case(record_outcome="pass"), C, "peer_disagrees", WIRE_TWIN),
    ("reject-scope-peer-without-artifact", "scope",
     lambda: self_case(_with(_set("witness_scope", "PEER"))), C, "witness_scope_misderived",
     SELF_TWIN),
    ("reject-scope-external-from-peer-key", "scope", lambda: peer_case(scope="EXTERNAL"), C,
     "witness_scope_misderived", WIRE_TWIN),
    ("reject-operators-unequal-no-peer", "scope",
     lambda: self_case(verdict(hosting="other-org:operator/runner-01")), C,
     "witness_scope_misderived", SELF_TWIN),
    ("reject-runner-written-lift-state", "scope",
     lambda: self_case(_with(_set("provenance", "lift_state", "peer"))), N,
     "field_invalid:provenance.lift_state", SELF_TWIN),
    ("reject-verdict-observed-edited", "integrity",
     lambda: self_case(_with(_set("observed", {"decision": "allow", "reason_codes": []}),
                             reseal=False)), C, "payload_digest_mismatch", SELF_TWIN),
    ("reject-digest-fields-omit-witness-scope", "integrity",
     lambda: self_case(_with(_fields_without("witness_scope"))), N,
     "payload_digest_fields_incomplete", SELF_TWIN),
    ("reject-subject-other-vector", "integrity",
     lambda: _other_subject(), C, "subject_digest_mismatch", SELF_TWIN),
    ("reject-verdict-wrong-runner-key", "integrity",
     lambda: self_case(signers=("stranger",)), C, "untrusted_key", SELF_TWIN),
    (Q_TWIN, "quarantine", quarantine_case, S, "quarantine_in_force", None),
    ("reject-quarantine-review-by-edited", "quarantine",
     lambda: quarantine_case(_set("review_by", "2027-06-30")), C,
     "quarantine_digest_mismatch", Q_TWIN),
    ("reject-quarantine-owner-edited-resealed", "quarantine",
     lambda: quarantine_case(_set("owner", "nobody"), reseal=True, resign=False), C,
     "signature_invalid", Q_TWIN),
    ("reject-quarantine-no-expiry-disposition", "quarantine",
     lambda: quarantine_case(_drop("expiry_disposition"), reseal=True), N,
     "quarantine_field_missing:expiry_disposition", Q_TWIN),
    ("reject-quarantine-expiry-outside-digest", "quarantine",
     lambda: quarantine_case(_fields_without("expiry_disposition"), reseal=True), N,
     "payload_digest_fields_incomplete", Q_TWIN),
    ("reject-quarantine-no-ref-or-gap", "quarantine",
     lambda: quarantine_case(lambda q: (q.update(quarantine_ref="", quarantine_gap="")),
                             reseal=True), N, "quarantine_field_missing:quarantine_ref", Q_TWIN),
    ("reject-quarantine-overdue", "quarantine",
     lambda: quarantine_case(as_of="2026-11-17T00:00:01Z"), N, "quarantine_overdue", Q_TWIN),
]


MALFORMED: dict[str, Any] = {
    "vector_id": "70CBCB3D7D7AA44C", "profile": "", "anchor": "", "clause": "",
    "verdict": "maybe", "witness_derivation.runner.id": "",
    "witness_derivation.runner.hosting_operator_id": "",
    "witness_derivation.deployment_operator_id": "", "witness_scope": "self",
    "verification_basis": [], "expected": {"decision": "deny"}, "observed": "deny",
    "behavior_snapshot": "chain", "integrity.payload_digest": "not-hex",
    "integrity.payload_digest_fields": [], "integrity.does_not_cover": ["subject"],
    "integrity.binding": "", "provenance.peer_artifact": "not-hex",
    "provenance.anchor": {"kind": "notary"},
}


def _field_case(field: str) -> Case:
    return self_case(_with(_set(*field.split("."), MALFORMED[field]), reseal=False))


def _envelope_case(edit: Callable[[dict[str, Any]], None], payload_type: str = INTOTO) -> Case:
    st = statement(verdict())
    edit(st)
    body = canonical(st)
    case = Case()
    case.record = {"payloadType": payload_type, "payload": b64(body), "signatures": [
        {"keyid": keyid("runner"),
         "sig": b64(run_vectors.ed25519_sign(seed("runner"), pae(payload_type, body)))}]}
    return case


def _peer_sig_tampered() -> Case:
    case = peer_case()
    assert case.peer is not None
    sig = bytearray(base64.b64decode(case.peer["signatures"][0]["sig"]))
    sig[0] ^= 1
    case.peer["signatures"][0]["sig"] = b64(bytes(sig))
    return case


def _peer_wrong_predicate() -> Case:
    ps = peer_statement()
    ps["predicateType"] = VERDICT_PREDICATE
    case = Case()
    case.record = envelope(statement(verdict("PEER", sha256_hex(canonical(ps)))), ["runner"])
    case.peer = envelope(ps, ["peer"])
    case.transcript = transcript()
    return case


CASES += [
    ("reject-payload-type-json", "integrity",
     lambda: _envelope_case(lambda st: None, "application/json"), N,
     "unsupported_payload_type", SELF_TWIN),
    ("reject-not-a-statement", "integrity",
     lambda: _envelope_case(_set("_type", "https://in-toto.io/Statement/v0.1")), N,
     "payload_not_statement", SELF_TWIN),
    ("reject-other-predicate-type", "integrity",
     lambda: _envelope_case(_set("predicateType", PEER_PREDICATE)), N,
     "unsupported_predicate", SELF_TWIN),
    *[(f"reject-field-{f.replace('.', '-').replace('_', '-')}", "fields",
       (lambda f=f: _field_case(f)), N, f"field_invalid:{f}", SELF_TWIN) for f in MALFORMED],
    ("reject-peer-signature-invalid", "peer", _peer_sig_tampered, C,
     "peer_artifact_unverified:signature_invalid", WIRE_TWIN),
    ("reject-peer-statement-wrong-type", "peer", _peer_wrong_predicate, C,
     "peer_artifact_unverified:unsupported_predicate", WIRE_TWIN),
    ("reject-quarantine-expiry-not-defined", "quarantine",
     lambda: quarantine_case(_set("expiry_disposition", "keep_quarantined"), reseal=True), N,
     "field_invalid:expiry_disposition", Q_TWIN),
]


def _other_subject() -> Case:
    case = self_case()
    st = statement(verdict(), OTHER_VECTOR)
    case.record = envelope(st, ["runner"])
    return case


def render() -> dict[str, bytes]:
    """Every corpus file, by its path relative to the corpus root."""
    out: dict[str, bytes] = {}
    entries = []
    for cid, control, build, decision, reason, twin in CASES:
        files = build().files()
        for name, data in files.items():
            out[f"cases/{cid}/{name}"] = data
        entry: dict[str, Any] = {"id": cid, "control": control,
                                 "expected": {"decision": decision, "reason": reason},
                                 "files": {n: sha256_hex(d) for n, d in sorted(files.items())}}
        if twin:
            entry["twin"] = twin
        entries.append(entry)
    keys = {role: {"keyid": keyid(role), "public_key": b64(public(role)),
                   "seed_label": f"aev-verdict-evidence-test-key/{role}/v1"}
            for role in ("runner", "peer", "external", "stranger")}
    manifest = {"suite": SUITE, "verdictPredicate": VERDICT_PREDICATE,
                "peerPredicate": PEER_PREDICATE, "testKeys": keys,
                "corpusDigest": sha256_hex(json.dumps(entries, sort_keys=True).encode()),
                "cases": entries}
    out["MANIFEST.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    return out


def _tree(root: Path) -> dict[str, bytes]:
    return {str(p.relative_to(root)): p.read_bytes() for p in root.rglob("*") if p.is_file()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    wanted = render()
    if args.check:
        if _tree(CORPUS) != wanted:
            print("the committed corpus differs from what the builder writes; run without --check")
            return 1
        print(f"corpus matches the builder: {len(CASES)} cases")
        return 0
    with tempfile.TemporaryDirectory(dir=CORPUS.parent) as tmp:
        staged = Path(tmp) / "corpus"
        for rel, data in wanted.items():
            (staged / rel).parent.mkdir(parents=True, exist_ok=True)
            (staged / rel).write_bytes(data)
        if CORPUS.exists():
            shutil.rmtree(CORPUS)
        staged.rename(CORPUS)
    print(f"wrote {len(CASES)} cases to {CORPUS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
