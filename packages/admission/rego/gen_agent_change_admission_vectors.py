"""Generate the agent change admission vectors the rego, CEL and policy-controller rails are held to.

    python3 rego/gen_agent_change_admission_vectors.py           # write the file
    python3 rego/gen_agent_change_admission_vectors.py --check   # exit 1 on drift

Every vector is a function of this file. The signatures are Ed25519, which is
deterministic, over the DSSE v1 pre-authentication encoding, made with two test
keys whose seeds are derived from fixed labels below. The private halves are
test material and protect nothing; the public halves are pinned in each
vector's consumer block, never read out of the envelope.

The serialization is the one the reference issuer uses for both the payload and
the envelope: JSON with sorted keys, no whitespace and UTF-8 output. A vector
signed here and a receipt signed by that issuer from the same decision and seed
are the same bytes.

The output is `rego/agent_change_admission_vectors.json`. `opa test rego/`
loads it as data under `agent_change_admission_vectors`, and the rules in
`rego/agent_change_admission_test.rego` read each case by name. Each case
carries its input, the consumer pins it is evaluated under, and the exact set of
refusal reasons the rule set must return; an empty set means admit.

Needs the `cryptography` package to sign. The rails that read the output need
nothing but their engine.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = Path(__file__).resolve().parent
OUT = HERE / "agent_change_admission_vectors.json"

PREDICATE_URI = (
    "https://github.com/probityai/agent-evidence-vocabulary/blob/main/docs/predicates/"
    "agent-change-admission-v1.md"
)
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
BARE_TYPE = "application/vnd.ratchet.decision+json"
INTOTO_TYPE = "application/vnd.in-toto+json"
GATES = ("replay", "heldout", "no_regression", "benign_twins", "overfit_lint", "authority")


def _hex(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode("utf-8")).digest())


SIGNER = _key("agent-change-admission vectors: issuer test key")
OTHER = _key("agent-change-admission vectors: unpinned test key")


def keyid(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def pae(payload_type: str, body: bytes) -> bytes:
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def envelope(payload_type: str, body: bytes, key: Ed25519PrivateKey, claimed: str | None = None) -> dict[str, Any]:
    """A DSSE envelope. `claimed` names a keyid other than the signing key's."""
    sig = key.sign(pae(payload_type, body))
    return {
        "payload": base64.b64encode(body).decode("ascii"),
        "payloadType": payload_type,
        "signatures": [{"keyid": claimed or keyid(key), "sig": base64.b64encode(sig).decode("ascii")}],
    }


CANDIDATE_DIGEST = _hex("candidate harness")
IMAGE_DIGEST = _hex("container image carrying the candidate harness")


def decision(admitted: bool = True) -> dict[str, Any]:
    """An admission decision in the shape the reference issuer signs."""
    checks = [{"name": g, "passed": True, "evidence": {"gate": g}} for g in GATES]
    checks.append({"name": "cost", "passed": True, "evidence": {"gate": False}})
    if not admitted:
        checks[1] = {"name": "heldout", "passed": False, "evidence": {"required": 14, "candidate_fresh_passed": 12}}
    return {
        "admitted": admitted,
        "candidate": CANDIDATE_DIGEST[:12],
        "candidate_digest": CANDIDATE_DIGEST,
        "checks": checks,
        "context": {},
        "corpus_digests": {"guard-refund-once": _hex("replay snapshot")},
        "decided_at": "2026-10-11T12:00:00+00:00",
        "evaluator": {
            "cases": 40,
            "components": {
                "cases": _hex("cases"),
                "faults": _hex("faults"),
                "graders": _hex("graders"),
                "model_config": _hex("model configuration"),
                "suite_file": _hex("frozen suite"),
            },
            "model_config": {"model": "test-model"},
            "version": _hex("evaluator")[:12],
        },
        "exceptions": [],
        "parent": _hex("parent harness")[:12],
        "predicateType": PREDICATE_URI,
        "rates": {},
        "report_digests": {
            "candidate_confirm_run": _hex("candidate confirm run"),
            "candidate_run": _hex("candidate run"),
            "parent_run_1": _hex("parent run 1"),
            "parent_run_2": _hex("parent run 2"),
            "replay:guard-refund-once": _hex("replay report"),
        },
        "type": "decision",
        "visible_case_ids": [],
    }


def statement(body: dict[str, Any], subject_digest: str = CANDIDATE_DIGEST) -> dict[str, Any]:
    predicate = {k: v for k, v in body.items() if k != "predicateType"}
    return {
        "_type": STATEMENT_TYPE,
        "predicate": predicate,
        "predicateType": body.get("predicateType", PREDICATE_URI),
        "subject": [{"digest": {"sha256": subject_digest}, "name": "harness"}],
    }


def consumer(**overrides: Any) -> dict[str, Any]:
    """Pins for a deployment that verified the envelope upstream and trusts the test issuer key."""
    pins: dict[str, Any] = {"signature_verified_upstream": True, "trusted_keyids": [keyid(SIGNER)]}
    pins.update(overrides)
    return {k: v for k, v in pins.items() if v is not None}


def bare(body: dict[str, Any], key: Ed25519PrivateKey = SIGNER) -> dict[str, Any]:
    return envelope(BARE_TYPE, _canonical(body), key)


def intoto(body: dict[str, Any], key: Ed25519PrivateKey = SIGNER) -> dict[str, Any]:
    return envelope(INTOTO_TYPE, _canonical(statement(body)), key)


def mutate(change: Callable[[dict[str, Any]], None], admitted: bool = True) -> dict[str, Any]:
    body = copy.deepcopy(decision(admitted))
    change(body)
    return body


def _set(field: str, value: Any) -> Callable[[dict[str, Any]], None]:
    def change(body: dict[str, Any]) -> None:
        if value is _DROP:
            body.pop(field, None)
        else:
            body[field] = value

    return change


_DROP = object()


def _gate(name: str, passed: bool | None) -> Callable[[dict[str, Any]], None]:
    """Set one gate's outcome, or remove the gate when `passed` is None."""

    def change(body: dict[str, Any]) -> None:
        if passed is None:
            body["checks"] = [c for c in body["checks"] if c["name"] != name]
        else:
            for c in body["checks"]:
                if c["name"] == name:
                    c["passed"] = passed

    return change


def _tamper_payload(env: dict[str, Any]) -> dict[str, Any]:
    """Flip one field of the signed payload and keep the old signature."""
    body = json.loads(base64.b64decode(env["payload"]))
    body["candidate"] = "tampered0000"
    return {**env, "payload": base64.b64encode(_canonical(body)).decode("ascii")}


def _field_cases() -> list[dict[str, Any]]:
    bad: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        ("parent", _set("parent", "")),
        ("candidate", _set("candidate", 7)),
        ("candidate_digest", _set("candidate_digest", "ABC")),
        ("evaluator", _set("evaluator", {"components": {}})),
        ("evaluator.components.suite_file", lambda b: b["evaluator"]["components"].update(suite_file="0" * 63)),
        ("exceptions", _set("exceptions", [{"code": "run_error"}])),
        ("admitted", _set("admitted", "true")),
        ("checks", _set("checks", [{"name": "replay", "passed": "yes"}])),
        ("corpus_digests", _set("corpus_digests", {"guard-refund-once": "not-a-digest"})),
        ("report_digests", _set("report_digests", {})),
    ]
    return [
        {
            "name": f"field-invalid-{field.replace('.', '-').replace('_', '-')}",
            "description": f"the signed decision carries a malformed {field}",
            "input": bare(mutate(change)),
            "consumer": consumer(),
            "reasons": [f"payload_field_invalid:{field}"],
        }
        for field, change in bad
    ]


def cases() -> list[dict[str, Any]]:
    admitted = decision()
    rejected = decision(admitted=False)
    out: list[dict[str, Any]] = [
        {
            "name": "statement-admitted",
            "description": "a verified in-toto statement whose subject is the candidate harness, every gate passed",
            "input": statement(admitted),
            "consumer": consumer(trusted_keyids=None),
            "reasons": [],
        },
        {
            "name": "envelope-bare-admitted",
            "description": "a bare decision envelope signed by the pinned key, every gate passed",
            "input": bare(admitted),
            "consumer": consumer(),
            "reasons": [],
        },
        {
            "name": "envelope-intoto-admitted",
            "description": "an in-toto statement envelope signed by the pinned key, every gate passed",
            "input": intoto(admitted),
            "consumer": consumer(),
            "reasons": [],
        },
        {
            "name": "wrapper-harness-match",
            "description": "a deploy gate names the harness it is about to deploy and the receipt admits exactly it",
            "input": {"envelope": bare(admitted), "harness_digest": CANDIDATE_DIGEST},
            "consumer": consumer(),
            "reasons": [],
        },
        {
            "name": "wrapper-harness-mismatch",
            "description": "the receipt admits a different harness from the one being deployed",
            "input": {"envelope": bare(admitted), "harness_digest": _hex("some other harness")},
            "consumer": consumer(),
            "reasons": ["candidate_digest_mismatch"],
        },
        {
            "name": "rejection-receipt",
            "description": "a consistent, verified rejection: the held-out gate failed and the decision says rejected",
            "input": bare(rejected),
            "consumer": consumer(),
            "reasons": ["not_admitted"],
        },
        {
            "name": "required-gates-subset",
            "description": "the consumer requires three gates; the receipt omits benign_twins, which nobody requires",
            "input": bare(mutate(_gate("benign_twins", None))),
            "consumer": consumer(required_gates=["replay", "heldout", "authority"]),
            "reasons": [],
        },
        {
            "name": "untrusted-key",
            "description": "the envelope is signed by a key the consumer does not pin",
            "input": bare(admitted, OTHER),
            "consumer": consumer(),
            "reasons": ["untrusted_key"],
        },
        {
            "name": "trusted-keys-unpinned",
            "description": "an envelope reaches a consumer that pinned no signer key",
            "input": bare(admitted),
            "consumer": consumer(trusted_keyids=None),
            "reasons": ["trusted_keys_unpinned"],
        },
        {
            "name": "signature-verification-undeclared",
            "description": "the consumer never said anything verified the envelope signature before this rule ran",
            "input": bare(admitted),
            "consumer": consumer(signature_verified_upstream=None),
            "reasons": ["signature_verification_undeclared"],
        },
        {
            "name": "limit-tampered-payload-passes-this-rule",
            "description": (
                "the payload was edited after signing. This rule cannot check signature bytes; the "
                "upstream verifier the consumer declared refuses it with signature_invalid"
            ),
            "input": _tamper_payload(bare(admitted)),
            "consumer": consumer(),
            "reasons": [],
        },
        {
            "name": "unsupported-payload-type",
            "description": "the envelope carries a payload type that is neither carriage of the predicate",
            "input": envelope("application/json", _canonical(admitted), SIGNER),
            "consumer": consumer(),
            "reasons": ["unsupported_payload_type"],
        },
        {
            "name": "payload-not-json-object",
            "description": "the signed payload is a JSON array",
            "input": envelope(BARE_TYPE, b"[1,2,3]", SIGNER),
            "consumer": consumer(),
            "reasons": ["payload_not_json_object"],
        },
        {
            "name": "unsupported-predicate-bare",
            "description": "the bare decision names another predicate type",
            "input": bare(mutate(_set("predicateType", PREDICATE_URI.replace("-v1.md", "-v2.md")))),
            "consumer": consumer(),
            "reasons": ["unsupported_predicate"],
        },
        {
            "name": "unsupported-predicate-statement",
            "description": "the statement names another predicate type",
            "input": {**statement(admitted), "predicateType": "https://example.invalid/predicates/other/v1"},
            "consumer": consumer(trusted_keyids=None),
            "reasons": ["unsupported_predicate"],
        },
        {
            "name": "unsupported-statement-type",
            "description": "the statement is not an in-toto Statement v1",
            "input": {**statement(admitted), "_type": "https://in-toto.io/Statement/v0.1"},
            "consumer": consumer(trusted_keyids=None),
            "reasons": ["unsupported_statement_type"],
        },
        {
            "name": "subject-digest-mismatch",
            "description": "the statement's subject is not the candidate the decision admits",
            "input": statement(admitted, subject_digest=_hex("another artifact")),
            "consumer": consumer(trusted_keyids=None),
            "reasons": ["subject_digest_mismatch"],
        },
        {
            "name": "image-binding-pinned",
            "description": (
                "an attestation attached to an image: the engine binds the subject to the image, and the "
                "consumer pins the harness digest the image must carry"
            ),
            "input": statement(admitted, subject_digest=IMAGE_DIGEST),
            "consumer": consumer(
                trusted_keyids=None, subject_binding="image", expected_candidate_digest=CANDIDATE_DIGEST
            ),
            "reasons": [],
        },
        {
            "name": "image-binding-unpinned",
            "description": "image binding with no pinned harness digest admits nothing",
            "input": statement(admitted, subject_digest=IMAGE_DIGEST),
            "consumer": consumer(trusted_keyids=None, subject_binding="image"),
            "reasons": ["candidate_digest_unpinned"],
        },
        {
            "name": "image-binding-mismatch",
            "description": "the image carries a receipt for a different harness from the pinned one",
            "input": statement(admitted, subject_digest=IMAGE_DIGEST),
            "consumer": consumer(
                trusted_keyids=None, subject_binding="image", expected_candidate_digest=_hex("pinned harness")
            ),
            "reasons": ["candidate_digest_mismatch"],
        },
        {
            "name": "expected-candidate-digest-invalid",
            "description": "the pinned harness digest is still the placeholder",
            "input": bare(admitted),
            "consumer": consumer(expected_candidate_digest="PIN-ME-REPLACE-WITH-THE-ADMITTED-HARNESS-DIGEST"),
            "reasons": ["expected_candidate_digest_invalid"],
        },
        {
            "name": "subject-binding-unknown",
            "description": "the consumer names a subject binding this rule does not define",
            "input": statement(admitted),
            "consumer": consumer(trusted_keyids=None, subject_binding="tag"),
            "reasons": ["subject_binding_unknown"],
        },
        {
            "name": "gate-missing",
            "description": "the decision records no held-out gate",
            "input": bare(mutate(_gate("heldout", None))),
            "consumer": consumer(),
            "reasons": ["gate_missing:heldout"],
        },
        {
            "name": "gate-duplicated",
            "description": "the decision records the replay gate twice, so its outcome is ambiguous",
            "input": bare(mutate(lambda b: b["checks"].append({"name": "replay", "passed": True, "evidence": {}}))),
            "consumer": consumer(),
            "reasons": ["gate_duplicated:replay"],
        },
        {
            "name": "admitted-with-failed-gate",
            "description": "the decision says admitted while its replay gate failed",
            "input": bare(mutate(_gate("replay", False))),
            "consumer": consumer(),
            "reasons": ["admitted_with_failed_gate:replay"],
        },
        {
            "name": "rejected-with-all-gates-passed",
            "description": "the decision says rejected while every required gate passed",
            "input": bare(mutate(_gate("heldout", True), admitted=False)),
            "consumer": consumer(),
            "reasons": ["rejected_with_all_gates_passed"],
        },
        {
            "name": "statement-predicate-not-object",
            "description": "the statement names this predicate type and carries no decision object",
            "input": {**statement(admitted), "predicate": "admitted"},
            "consumer": consumer(trusted_keyids=None),
            "reasons": ["unsupported_predicate"],
        },
        {
            "name": "wrapper-harness-digest-invalid",
            "description": "the deploy gate names its harness by something other than a SHA-256 digest",
            "input": {"envelope": bare(admitted), "harness_digest": "latest"},
            "consumer": consumer(),
            "reasons": ["harness_digest_invalid"],
        },
        {
            "name": "required-gates-empty",
            "description": "the consumer pins an empty gate list, which would admit on the admitted flag alone",
            "input": bare(admitted),
            "consumer": consumer(required_gates=[]),
            "reasons": ["required_gates_empty"],
        },
        {
            "name": "required-gate-unknown",
            "description": "the consumer requires a check that is not an admission gate",
            "input": bare(admitted),
            "consumer": consumer(required_gates=["replay", "cost"]),
            "reasons": ["required_gate_unknown:cost"],
        },
    ]
    out.extend(_field_cases())
    return out


def render() -> str:
    doc = {
        "agent_change_admission_vectors": {
            "candidate_digest": CANDIDATE_DIGEST,
            "image_digest": IMAGE_DIGEST,
            "predicate_type": PREDICATE_URI,
            "issuer_keyid": keyid(SIGNER),
            "issuer_public_key_b64": public_b64(SIGNER),
            "unpinned_keyid": keyid(OTHER),
            "cases": {c["name"]: c for c in cases()},
        }
    }
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when the committed file differs")
    args = parser.parse_args(argv[1:])
    rendered = render()
    count = len(json.loads(rendered)["agent_change_admission_vectors"]["cases"])
    if args.check:
        if not OUT.is_file() or OUT.read_text(encoding="utf-8") != rendered:
            print(f"{OUT.name} is not what this generator renders; regenerate it and commit", file=sys.stderr)
            return 1
        print(f"check: {OUT.name} regenerates byte for byte ({count} cases)")
        return 0
    OUT.write_text(rendered, encoding="utf-8")
    print(f"wrote {OUT} ({count} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
