"""Build the deterministic agent-change-admission cases.

    uv run --extra generators python vectors-agent-change-admission/gen_vectors.py

Each member is one signed admission decision about a proposed change to an AI
agent's harness, with the consumer policy that judges it and the stored reports
it names. Two members per carriage are accepted as issued; every other member
is one scripted mutation away from an accepted twin, and the mutation is the
only difference. Every envelope is signed here with the published test keys
below, so every byte in the corpus is a function of this file alone.

The decision payload, its canonical JSON (sorted keys, no whitespace, UTF-8)
and the envelope encoding match the reference issuer byte for byte: a signer
holding the same seed over the same payload writes the same envelope.

TEST KEYS ONLY. Each seed is the SHA-256 of a public label, so anyone can
re-derive the private key. Never trust these keys for anything else.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parent
_DIGEST = importlib.util.spec_from_file_location("change_admission_digest", ROOT / "digest.py")
assert _DIGEST is not None and _DIGEST.loader is not None
_digest_module = importlib.util.module_from_spec(_DIGEST)
_DIGEST.loader.exec_module(_digest_module)
corpus_digest = _digest_module.corpus_digest
SUITE = "agent-change-admission/v1"
PREDICATE = ("https://github.com/probityai/agent-evidence-vocabulary/blob/main/"
             "docs/predicates/agent-change-admission-v1.md")
BARE_TYPE = "application/vnd.ratchet.decision+json"
INTOTO_TYPE = "application/vnd.in-toto+json"
STATEMENT = "https://in-toto.io/Statement/v1"
GATES = ("replay", "heldout", "no_regression", "authority", "benign_twins", "overfit_lint")
ISSUER_LABEL = "agent-change-admission/v1 test issuer key"
OTHER_LABEL = "agent-change-admission/v1 test key that no policy pins"
GUARD = "guard-refund-over-limit"
REPORT_REPLAY = f"replay:{GUARD}"
REPORT_HELDOUT = "heldout-summary"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex(label: str) -> str:
    return _sha(label.encode())


def canonical(value: object) -> bytes:
    """The reference issuer's canonical JSON: sorted keys, no whitespace, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _pretty(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())


def public_raw(k: Ed25519PrivateKey) -> bytes:
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def keyid(k: Ed25519PrivateKey) -> str:
    """The SHA-256 of the raw 32-byte public key, lowercase hex."""
    return _sha(public_raw(k))


ISSUER, OTHER = key(ISSUER_LABEL), key(OTHER_LABEL)


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding."""
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def signature(k: Ed25519PrivateKey, payload_type: str, body: bytes,
              kid: str | None = None) -> dict[str, str]:
    return {"keyid": kid or keyid(k), "sig": _b64(k.sign(pae(payload_type, body)))}


def envelope(payload_type: str, body: bytes, signatures: list[dict[str, str]]) -> dict[str, Any]:
    return {"payload": _b64(body), "payloadType": payload_type, "signatures": signatures}


# Stored reports the decision names. Their bytes are what the digests cover.
REPLAY_TRACES = 41  # fixture data inside a report payload, not a count of this corpus
REPLAY_REPORT = {
    "coverage": f"{REPLAY_TRACES}/{REPLAY_TRACES} traces checked", "exhaustive": True,
    "guard_id": GUARD, "passed": True,
    "snapshot_digest": _hex("recorded trace snapshot"), "targets_hit": 3, "targets_total": 3,
    "false_positives": [], "benign_twin_fires": 0, "verdict": "CLEARED",
}
HELDOUT_REPORT = {
    "cases": 24, "mode": "FRESH", "parent_fresh_passed": [14, 15], "discordant": 1,
    "required": 17, "candidate_fresh_passed": 19, "confirm_fresh_passed": 19,
}
REPORTS = {REPORT_REPLAY: canonical(REPLAY_REPORT), REPORT_HELDOUT: canonical(HELDOUT_REPORT)}
REPORT_FILES = {REPORT_REPLAY: "report-replay.json", REPORT_HELDOUT: "report-heldout.json"}


def decision(admitted: bool = True) -> dict[str, Any]:
    """An admission decision in the bare carriage, every gate passed or held-out failed."""
    checks = [{"name": g, "passed": admitted or g != "heldout", "evidence": {}} for g in GATES]
    checks[0]["evidence"] = {"coverage": REPLAY_REPORT["coverage"], "verdict": "CLEARED",
                             "snapshot_digest": REPLAY_REPORT["snapshot_digest"]}
    checks.append({"name": "cost", "passed": True, "evidence": {"gate": False, "model_calls": 212}})
    return {
        "predicateType": PREDICATE,
        "type": "decision",
        "parent": "3f2a9c41d07e",
        "candidate": "8b1e5d72c4a9",
        "candidate_digest": _hex("candidate harness 8b1e5d72c4a9"),
        "admitted": admitted,
        "checks": checks,
        "evaluator": {
            "version": "c41f0a9e2b77",
            "components": {name: _hex(f"frozen {name}") for name in
                           ("cases", "graders", "faults", "model_config", "suite_file")},
        },
        "corpus_digests": {GUARD: REPLAY_REPORT["snapshot_digest"]},
        "report_digests": {name: _sha(raw) for name, raw in REPORTS.items()},
        "exceptions": [],
        "decided_at": "2026-10-11T12:00:00+00:00",
    }


def statement(body: dict[str, Any]) -> dict[str, Any]:
    """The same decision carried as an in-toto Statement v1 predicate."""
    predicate = {k: v for k, v in body.items() if k != "predicateType"}
    return {"_type": STATEMENT,
            "subject": [{"name": f"harness:{body['candidate']}",
                         "digest": {"sha256": body["candidate_digest"]}}],
            "predicateType": PREDICATE, "predicate": predicate}


class Member:
    """One case before it is written: the payload, the envelope edits and the policy."""

    def __init__(self, carriage: str, admitted: bool) -> None:
        self.carriage = carriage
        self.payload_type = BARE_TYPE if carriage == "dsse-bare" else INTOTO_TYPE
        self.body: Any = decision(admitted)
        self.supplied: dict[str, bytes] = dict(REPORTS)
        self.require_reports = True
        self.signer, self.signer_kid = ISSUER, keyid(ISSUER)
        self.extra_signatures: list[dict[str, str]] = []
        self.post: Callable[[dict[str, Any]], None] | None = None
        self.raw_envelope: bytes | None = None

    def payload(self) -> bytes:
        intoto = self.carriage == "dsse-intoto"
        if isinstance(self.body, dict) and intoto and "_type" not in self.body:
            return canonical(statement(self.body))
        return canonical(self.body)

    def envelope_bytes(self) -> bytes:
        if self.raw_envelope is not None:
            return self.raw_envelope
        body = self.payload()
        sigs = [*self.extra_signatures,
                signature(self.signer, self.payload_type, body, self.signer_kid)]
        env = envelope(self.payload_type, body, sigs)
        if self.post is not None:
            self.post(env)
        return canonical(env)


Mutation = Callable[[Member], None]


def _body(edit: Callable[[dict[str, Any]], None]) -> Mutation:
    def mutate(m: Member) -> None:
        edit(m.body)
    return mutate


def _set(field: str, value: Any) -> Mutation:
    return _body(lambda b: b.__setitem__(field, value))


def _drop(field: str) -> Mutation:
    return _body(lambda b: b.pop(field))


def _tamper_payload(m: Member) -> None:
    signed = m.payload()
    forged = json.loads(signed)
    target = forged["predicate"] if m.carriage == "dsse-intoto" else forged
    target["parent"] = "000000000000"

    def post(env: dict[str, Any]) -> None:
        env["payload"] = _b64(canonical(forged))
    m.post = post


def _tamper_signature(m: Member) -> None:
    def post(env: dict[str, Any]) -> None:
        raw = bytearray(base64.b64decode(env["signatures"][-1]["sig"]))
        raw[0] ^= 0x01
        env["signatures"][-1]["sig"] = _b64(bytes(raw))
    m.post = post


def _wrong_key(m: Member) -> None:
    m.signer, m.signer_kid = OTHER, keyid(OTHER)


def _wrong_key_claims_pinned_keyid(m: Member) -> None:
    m.signer, m.signer_kid = OTHER, keyid(ISSUER)


def _rotation(m: Member) -> None:
    m.extra_signatures = [signature(OTHER, m.payload_type, m.payload())]


def _payload_type(value: str) -> Mutation:
    def mutate(m: Member) -> None:
        m.payload_type = value
    return mutate


def _not_object(m: Member) -> None:
    m.body = [m.body]


def _subject_mismatch(m: Member) -> None:
    st = statement(m.body)
    st["subject"][0]["digest"]["sha256"] = _hex("a different harness")
    m.body = st


def _statement_type(m: Member) -> None:
    st = statement(m.body)
    st["_type"] = "https://in-toto.io/Statement/v0.1"
    m.body = st


def _gate(name: str, passed: bool | None) -> Mutation:
    def edit(b: dict[str, Any]) -> None:
        if passed is None:
            b["checks"] = [c for c in b["checks"] if c["name"] != name]
        else:
            next(c for c in b["checks"] if c["name"] == name)["passed"] = passed
    return _body(edit)


def _all_gates_pass(b: dict[str, Any]) -> None:
    for c in b["checks"]:
        c["passed"] = True


def _cost_failed(b: dict[str, Any]) -> None:
    next(c for c in b["checks"] if c["name"] == "cost")["passed"] = False


def _report_bytes(name: str, data: bytes) -> Mutation:
    def mutate(m: Member) -> None:
        m.supplied[name] = data
    return mutate


def _withhold(name: str) -> Mutation:
    def mutate(m: Member) -> None:
        m.supplied.pop(name)
    return mutate


def _withhold_all_optional(m: Member) -> None:
    m.supplied, m.require_reports = {}, False


def _raw(data: bytes) -> Mutation:
    def mutate(m: Member) -> None:
        m.raw_envelope = data
    return mutate


def _evaluator_without_version(b: dict[str, Any]) -> None:
    del b["evaluator"]["version"]


def _short_suite(b: dict[str, Any]) -> None:
    b["evaluator"]["components"]["suite_file"] = "abc123"


def _check_passed_string(b: dict[str, Any]) -> None:
    b["checks"][2]["passed"] = "yes"


SUPPORTED, CONTRADICTED, NOT_ESTABLISHED, NO_VERDICT = (
    "supported", "contradicted", "not_established", "no_verdict")

# (id, carriage, admitted twin flag, mutation or None, decision, reason, what the mutation does)
MEMBERS: tuple[tuple[str, str, bool, Mutation | None, str, str, str], ...] = (
    ("admitted", "dsse-bare", True, None, SUPPORTED, "admitted_receipt_verified",
     "an admitted decision, every required gate passed, both reports supplied"),
    ("rejected", "dsse-bare", False, None, SUPPORTED, "rejection_receipt_verified",
     "a rejected decision whose held-out gate failed: a rejection is a verifiable record too"),
    ("admitted-reports-not-supplied", "dsse-bare", True, _withhold_all_optional, SUPPORTED,
     "admitted_receipt_verified",
     "no report supplied under a policy that does not require them: authenticated, not recomputed"),
    ("admitted-unpinned-cosigner", "dsse-bare", True, _rotation, SUPPORTED,
     "admitted_receipt_verified",
     "a first signature by a key no policy pins is ignored; the pinned key's signature verifies"),
    ("admitted-informational-check-failed", "dsse-bare", True, _body(_cost_failed), SUPPORTED,
     "admitted_receipt_verified",
     "the cost check failed; it is informational and never a gate"),
    ("tampered-payload", "dsse-bare", True, _tamper_payload, CONTRADICTED, "signature_invalid",
     "the parent changed in the payload after signing"),
    ("tampered-signature", "dsse-bare", True, _tamper_signature, CONTRADICTED, "signature_invalid",
     "one bit of the signature flipped"),
    ("wrong-key", "dsse-bare", True, _wrong_key, CONTRADICTED, "untrusted_key",
     "signed by a key the policy does not pin, under that key's own keyid"),
    ("wrong-key-claims-pinned-keyid", "dsse-bare", True, _wrong_key_claims_pinned_keyid,
     CONTRADICTED, "signature_invalid",
     "signed by an unpinned key that names the pinned keyid"),
    ("wrong-payload-type", "dsse-bare", True, _payload_type("application/json"), NOT_ESTABLISHED,
     "unsupported_payload_type", "signed under a payload type the policy does not pin"),
    ("payload-not-object", "dsse-bare", True, _not_object, NOT_ESTABLISHED,
     "payload_not_json_object", "the signed payload is a JSON array holding the decision"),
    ("wrong-predicate", "dsse-bare", True,
     _set("predicateType", "https://in-toto.io/attestation/test-result/v0.1"), NOT_ESTABLISHED,
     "unsupported_predicate", "the payload names another predicate type"),
    ("missing-predicate", "dsse-bare", True, _drop("predicateType"), NOT_ESTABLISHED,
     "unsupported_predicate", "the payload names no predicate type"),
    ("field-parent-empty", "dsse-bare", True, _set("parent", ""), NOT_ESTABLISHED,
     "payload_field_invalid:parent", "parent is an empty string"),
    ("field-candidate-missing", "dsse-bare", True, _drop("candidate"), NOT_ESTABLISHED,
     "payload_field_invalid:candidate", "candidate is absent"),
    ("field-candidate-digest-uppercase", "dsse-bare", True,
     _body(lambda b: b.__setitem__("candidate_digest", b["candidate_digest"].upper())),
     NOT_ESTABLISHED, "payload_field_invalid:candidate_digest",
     "candidate_digest is upper-case hex"),
    ("field-evaluator-no-version", "dsse-bare", True, _body(_evaluator_without_version),
     NOT_ESTABLISHED, "payload_field_invalid:evaluator", "evaluator carries no version"),
    ("field-suite-file-short", "dsse-bare", True, _body(_short_suite), NOT_ESTABLISHED,
     "payload_field_invalid:evaluator.components.suite_file",
     "the frozen suite digest is not 64 hex characters"),
    ("field-exceptions-object", "dsse-bare", True, _set("exceptions", [{"code": "x"}]),
     NOT_ESTABLISHED, "payload_field_invalid:exceptions",
     "an exception is an object, not a string"),
    ("field-admitted-string", "dsse-bare", True, _set("admitted", "true"), NOT_ESTABLISHED,
     "payload_field_invalid:admitted", "admitted is the string \"true\""),
    ("field-check-passed-string", "dsse-bare", True, _body(_check_passed_string),
     NOT_ESTABLISHED, "payload_field_invalid:checks", "a check's passed value is a string"),
    ("field-corpus-digest-not-hex", "dsse-bare", True,
     _set("corpus_digests", {GUARD: "not-a-digest"}), NOT_ESTABLISHED,
     "payload_field_invalid:corpus_digests", "a replay corpus digest is not hex"),
    ("field-report-digests-empty", "dsse-bare", True, _set("report_digests", {}),
     NOT_ESTABLISHED, "payload_field_invalid:report_digests",
     "the decision names no report"),
    ("gate-missing", "dsse-bare", True, _gate("authority", None), NOT_ESTABLISHED,
     "gate_missing:authority", "the authority gate is not recorded"),
    ("admitted-with-failed-gate", "dsse-bare", True, _gate("heldout", False), CONTRADICTED,
     "admitted_with_failed_gate:heldout", "admitted while the held-out gate failed"),
    ("rejected-with-all-gates-passed", "dsse-bare", False, _body(_all_gates_pass), CONTRADICTED,
     "rejected_with_all_gates_passed", "rejected while every required gate passed"),
    ("report-digest-mismatch", "dsse-bare", True,
     _report_bytes(REPORT_HELDOUT, canonical({**HELDOUT_REPORT, "candidate_fresh_passed": 23})),
     CONTRADICTED, f"report_digest_mismatch:{REPORT_HELDOUT}",
     "the supplied held-out report is not the one the decision names"),
    ("report-not-named", "dsse-bare", True,
     _report_bytes("audit-cohort", canonical({"cases": 8})), CONTRADICTED,
     "report_not_named:audit-cohort", "a supplied report the decision does not name"),
    ("report-not-supplied", "dsse-bare", True, _withhold(REPORT_REPLAY), NOT_ESTABLISHED,
     f"report_not_supplied:{REPORT_REPLAY}",
     "the policy requires every named report and one is withheld"),
    ("malformed-not-json", "dsse-bare", True, _raw(b"{\"payload\": "), NO_VERDICT,
     "malformed_envelope", "the envelope bytes are not JSON"),
    ("malformed-signature-not-base64", "dsse-bare", True,
     lambda m: setattr(m, "post", lambda env: env["signatures"][-1].__setitem__("sig", "%%%")),
     NO_VERDICT, "malformed_envelope", "a signature is not base64"),
    ("intoto-admitted", "dsse-intoto", True, None, SUPPORTED, "admitted_receipt_verified",
     "the admitted decision carried as an in-toto Statement v1 predicate"),
    ("intoto-subject-mismatch", "dsse-intoto", True, _subject_mismatch, CONTRADICTED,
     "subject_digest_mismatch", "the statement's subject is not the candidate the predicate names"),
    ("intoto-statement-type", "dsse-intoto", True, _statement_type, NOT_ESTABLISHED,
     "unsupported_statement_type", "the statement names a superseded statement type"),
    ("intoto-tampered-payload", "dsse-intoto", True, _tamper_payload, CONTRADICTED,
     "signature_invalid", "the predicate's parent changed after signing"),
)


def _twin(carriage: str, admitted: bool) -> str:
    if carriage == "dsse-intoto":
        return "intoto-admitted"
    return "admitted" if admitted else "rejected"


def _policy(m: Member) -> dict[str, Any]:
    return {"payload_type": BARE_TYPE if m.carriage == "dsse-bare" else INTOTO_TYPE,
            "predicate_type": PREDICATE,
            "trusted_keys": {keyid(ISSUER): _b64(public_raw(ISSUER))},
            "required_gates": list(GATES), "require_reports": m.require_reports}


def _write_case(root: Path, name: str, m: Member) -> dict[str, str]:
    directory = root / "cases" / name
    directory.mkdir(parents=True, exist_ok=True)
    for stale in directory.iterdir():
        stale.unlink()
    files: dict[str, bytes] = {"envelope.json": m.envelope_bytes()}
    reports: dict[str, str] = {}
    for report, data in sorted(m.supplied.items()):
        file = REPORT_FILES.get(report, f"report-{report}.json")
        files[file], reports[report] = data, file
    case = {"carriage": m.carriage, "envelope": "envelope.json", "reports": reports,
            "policy": _policy(m)}
    files["case.json"] = _pretty(case)
    for file, data in files.items():
        (directory / file).write_bytes(data)
    return {file: _sha(data) for file, data in sorted(files.items())}


def _index(entries: list[dict[str, Any]], digest: str) -> bytes:
    lines = [
        "# Agent change admission vectors", "",
        "Generated by `gen_vectors.py`. Do not edit: every regeneration rewrites it.", "",
        f"Suite: `{SUITE}`. Predicate: {PREDICATE}", "",
        f"Issuer test keyid: `{keyid(ISSUER)}`", "",
        f"Corpus digest: `{digest}`", "",
        "| id | carriage | decision | reason | twin | mutation |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for e in entries:
        x = e["expected"]
        lines.append(f"| `{e['id']}` | {e['carriage']} | {x['decision']} | `{x['reason']}` | "
                     f"{e.get('twin', '')} | {e['description']} |")
    return ("\n".join(lines) + "\n").encode()


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case, the issuer's public key, the manifest and the index."""
    entries = []
    for name, carriage, admitted, mutate, verdict, reason, description in MEMBERS:
        m = Member(carriage, admitted)
        if mutate is not None:
            mutate(m)
        entry: dict[str, Any] = {
            "id": name, "path": f"cases/{name}", "carriage": carriage,
            "files": _write_case(root, name, m), "description": description,
            "expected": {"decision": verdict, "reason": reason},
        }
        if mutate is not None and verdict != SUPPORTED:
            entry["twin"] = _twin(carriage, admitted)
        entries.append(entry)
    digest = _sha(_pretty(entries))
    manifest = {"suite": SUITE, "predicateType": PREDICATE, "vectors": entries,
                "issuerKeyid": keyid(ISSUER),
                "verifierContract": "verifier case.json --json", "corpusDigest": digest}
    verdict_words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (root / "MANIFEST.json").write_bytes(_pretty(manifest))
    (root / "INDEX.md").write_bytes(_index(entries, digest))
    return manifest


if __name__ == "__main__":
    generate()
