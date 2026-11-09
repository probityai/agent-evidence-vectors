"""The reader for control-decision/v1 records: one function, ``judge``, and its rules.

A control-decision record says what a policy decision point judged, under which policy,
and with what verdict. It is a DSSE envelope over an in-toto Statement v1. The reader
takes the envelope, the artifacts the producer disclosed (the context the decision
point judged, the manifest text and the policy bundle), the producer's public key and
the verdict the consumer got by replaying those artifacts through the named runtime.
Every trust input comes from the consumer: the key and the replayed verdict are never
read from the record.

The rules run in the order of ``RULES`` and the first that fails is the code.
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/control-decision"
DECISIONS = ("allow", "deny", "transform")
MAX_SAFE = 2**53 - 1
ACCEPTED = "decision-bound"

#: (rule, code), in the order the reader applies them.
RULES: tuple[tuple[str, str], ...] = (
    ("signature", "signature-invalid"),
    ("statement", "statement-malformed"),
    ("verdict-shape", "verdict-malformed"),
    ("policy-digest-present", "policy-digest-missing"),
    ("input-digest", "input-digest-mismatch"),
    ("policy-digest", "policy-digest-mismatch"),
    ("verdict", "verdict-mismatch"),
)


class Refusal(Exception):
    """A rule failed; ``code`` names it."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def canonical(value: Any) -> bytes:
    """RFC 8785 bytes for the JSON domain these records carry.

    The domain is objects, arrays, strings, booleans, null and integers inside
    +-(2**53 - 1), with every character in the Basic Multilingual Plane. Inside it,
    sorted members, no whitespace and UTF-8 output are the RFC 8785 form. A value
    outside the domain raises ValueError instead of being serialized some other way.
    """
    _check_domain(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _check_domain(value: Any) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        if any(ord(ch) > 0xFFFF for ch in value):
            raise ValueError("a character outside the Basic Multilingual Plane")
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE:
            raise ValueError("an integer outside the safe range")
        return
    if isinstance(value, list):
        for item in value:
            _check_domain(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _check_domain(key)
            _check_domain(item)
        return
    raise ValueError(f"a {type(value).__name__} is outside the record's JSON domain")


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def pae(payload_type: str, payload: bytes) -> bytes:
    kind = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


def _statement(envelope: dict[str, Any], public_key: bytes) -> dict[str, Any]:
    try:
        payload = base64.b64decode(envelope["payload"], validate=True)
        signatures = envelope["signatures"]
        if envelope["payloadType"] != PAYLOAD_TYPE or len(signatures) != 1:
            raise Refusal("signature-invalid")
        signature = base64.b64decode(signatures[0]["sig"], validate=True)
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, pae(PAYLOAD_TYPE, payload))
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        raise Refusal("signature-invalid") from exc
    try:
        statement = json.loads(payload)
    except ValueError as exc:
        raise Refusal("statement-malformed") from exc
    if not isinstance(statement, dict):
        raise Refusal("statement-malformed")
    return statement


def _predicate(statement: dict[str, Any]) -> dict[str, Any]:
    predicate = statement.get("predicate")
    subject = statement.get("subject")
    if (
        statement.get("_type") != STATEMENT_TYPE
        or statement.get("predicateType") != PREDICATE_TYPE
        or not isinstance(predicate, dict)
        or not isinstance(subject, list)
        or len(subject) != 1
        or not isinstance(subject[0], dict)
        or not isinstance(predicate.get("input"), dict)
        or not isinstance(predicate.get("policy"), dict)
        or not isinstance(predicate.get("interventionPoint"), str)
    ):
        raise Refusal("statement-malformed")
    return predicate


def _verdict(predicate: dict[str, Any]) -> dict[str, Any]:
    verdict = predicate.get("verdict")
    if not isinstance(verdict, dict) or verdict.get("decision") not in DECISIONS:
        raise Refusal("verdict-malformed")
    if "approval" in verdict and verdict["decision"] != "deny":
        raise Refusal("verdict-malformed")
    return verdict


def judge(
    envelope: dict[str, Any],
    disclosed: dict[str, Any],
    public_key: bytes,
    replayed_verdict: dict[str, Any],
) -> str:
    """Return ``ACCEPTED`` or raise Refusal with the first failing rule's code."""
    statement = _statement(envelope, public_key)
    predicate = _predicate(statement)
    verdict = _verdict(predicate)
    policy = predicate["policy"]
    manifest_digest = policy.get("manifestDigest")
    bundle_digest = policy.get("bundleDigest")
    if not isinstance(manifest_digest, str) or not isinstance(bundle_digest, str):
        raise Refusal("policy-digest-missing")
    try:
        context_digest = digest(canonical(disclosed["context"]))
        manifest_bytes = disclosed["manifest"].encode("utf-8")
        bundle_bytes = canonical(disclosed["policyBundle"])
    except (KeyError, AttributeError, ValueError) as exc:
        raise Refusal("input-digest-mismatch") from exc
    subject_digest = statement["subject"][0].get("digest", {}).get("sha256")
    if (
        predicate["input"].get("digest") != context_digest
        or "sha256:" + str(subject_digest) != context_digest
    ):
        raise Refusal("input-digest-mismatch")
    if digest(manifest_bytes) != manifest_digest or digest(bundle_bytes) != bundle_digest:
        raise Refusal("policy-digest-mismatch")
    if canonical(verdict) != canonical(replayed_verdict):
        raise Refusal("verdict-mismatch")
    return ACCEPTED
