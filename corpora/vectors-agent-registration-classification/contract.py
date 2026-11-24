"""Reference reader for the *proposed* BuddyLists registration evidence boundary.

This is a standalone, synthetic test policy, not an MCP standard and not a
verification of any live BuddyLists registration. Needs cryptography >= 41.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def canonical(value: Any) -> bytes:
    # Our local, explicitly constrained JSON subset, NOT RFC 8785 JCS.
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def signed(message: bytes, signature_b64: str, public_b64: str) -> bool:
    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64, validate=True))
        sig = base64.b64decode(signature_b64, validate=True)
        pub.verify(sig, message)
        return True
    except (InvalidSignature, TypeError, ValueError, KeyError):
        return False


def parse_time(value: str) -> datetime:
    d = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if d.tzinfo is None:
        raise ValueError("timestamp lacks offset")
    return d.astimezone(UTC)


class StrictDecodeError(ValueError):
    """The bytes are not one strict JSON document."""


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise StrictDecodeError("duplicate object member")
    return dict(pairs)


def _no_constants(name: str) -> Any:
    raise StrictDecodeError("non-finite number " + name)


def decode(data: bytes) -> Any:
    """Strict decoding: UTF-8, no duplicate member names, no NaN or Infinity.

    `json.loads` keeps the last of two equal member names, so a record whose
    bytes carry a member twice can be read as the signed value while the bytes
    say something else. The signature covers `canonical(core)` after parsing
    and never sees the duplicate, so the refusal has to happen here.
    """
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StrictDecodeError("not UTF-8") from exc
    return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)


def classify_bytes(record_bytes: bytes, context_bytes: bytes) -> tuple[bool, str]:
    """Classify a case from its file bytes, decoding both strictly first."""
    try:
        record, context = decode(record_bytes), decode(context_bytes)
    except ValueError:
        return False, "evidence_bytes_not_strict_json"
    return classify(record, context)


def _id(value: Any) -> bool:
    return isinstance(value, str) and value != ""


# Required members and their types. A member listed here must be present:
# an absent member is not read as its default, the same rule the `consumed`
# correction applies to the challenge state. `consumed` itself stays with
# its own explicit checks so its three refusal cases keep their reason.
_CORE_TYPES = {
    "event_type": lambda v: isinstance(v, str),
    "intake_state": lambda v: isinstance(v, str),
    "agent_id": _id,
    "swarm_id": _id,
    "parent_agent_id": lambda v: v is None or _id(v),
    "consent": lambda v: isinstance(v, bool),
    "consent_scope": lambda v: isinstance(v, str),
    "challenge_nonce": _id,
}
_CHALLENGE_TYPES = {
    "agent_id": _id,
    "swarm_id": _id,
    "challenge_nonce": _id,
    "agent_public_key": lambda v: isinstance(v, str),
    "issued_at": lambda v: isinstance(v, str),
    "expires_at": lambda v: isinstance(v, str),
}


def _members_typed(obj: Any, spec: dict) -> bool:
    return isinstance(obj, dict) and all(k in obj and ok(obj[k]) for k, ok in spec.items())


def _ids(value: Any) -> bool:
    return isinstance(value, list) and all(_id(v) for v in value)


def required_types_hold(record: Any, context: Any) -> bool:
    """True when every member the reader branches on is present with its type."""
    if not (isinstance(record, dict) and isinstance(context, dict)):
        return False
    receipt = record.get("registry_receipt")
    return (
        _members_typed(record.get("core"), _CORE_TYPES)
        and isinstance(record.get("agent_public_key"), str)
        and isinstance(record.get("agent_signature"), str)
        and isinstance(receipt, dict)
        and isinstance(receipt.get("body"), dict)
        and isinstance(receipt.get("signature"), str)
        and isinstance(context.get("evaluation_time"), str)
        and _ids(context.get("prior_registered_swarms"))
        and _ids(context.get("prior_registered_agents"))
        and isinstance(context.get("trusted_registry_public_key"), str)
        and _members_typed(context.get("issued_challenge"), _CHALLENGE_TYPES)
    )


def _core_refusal(core: dict, context: dict) -> str | None:
    """The first reason the registration event itself earns no credit, or None."""
    if core.get("event_type") != "registration":
        return "not_registration_event"
    if core.get("intake_state") != "durably_committed":
        return "not_durably_committed"
    if core.get("consent") is not True:
        return "consent_not_affirmative"
    if core.get("consent_scope") != "registration":
        return "consent_scope_mismatch"
    if core.get("parent_agent_id") is not None:
        return "ephemeral_or_child_agent"
    if core.get("swarm_id") in context["prior_registered_swarms"]:
        return "swarm_already_registered"
    if core.get("agent_id") in context["prior_registered_agents"]:
        return "agent_already_registered"
    return None


def _challenge_refusal(core: dict, context: dict) -> str | None:
    """The first reason the issued challenge does not back the event, or None."""
    challenge = context["issued_challenge"]
    if any(challenge.get(k) != core.get(k) for k in ("agent_id", "swarm_id", "challenge_nonce")):
        return "challenge_binding_mismatch"
    now = parse_time(context["evaluation_time"])
    if not (parse_time(challenge["issued_at"]) <= now < parse_time(challenge["expires_at"])):
        return "challenge_expired_or_not_yet_issued"
    if challenge.get("consumed") is True:
        return "challenge_replayed"
    # Unknown and missing consumption states are NOT evidence of non-use.
    # In particular, `None` or an omitted field must never be credited as
    # an unused nonce (the caller is relying on a trusted registry ledger).
    if challenge.get("consumed") is not False:
        return "challenge_state_unverified"
    return None


def _proof_refusal(record: dict, context: dict) -> str | None:
    """The first reason the agent proof or the durable receipt fails, or None."""
    core = record["core"]
    agent_public = record["agent_public_key"]
    if agent_public != context["issued_challenge"]["agent_public_key"]:
        return "challenge_key_mismatch"
    if not signed(
        b"BUDDYLISTS_TEST_REGISTRATION_V1\x00" + canonical(core),
        record["agent_signature"],
        agent_public,
    ):
        return "agent_proof_invalid"
    receipt = record["registry_receipt"]
    receipt_body = receipt["body"]
    if (
        receipt_body.get("record_digest") != digest(core)
        or receipt_body.get("agent_id") != core["agent_id"]
        or receipt_body.get("swarm_id") != core["swarm_id"]
        or receipt_body.get("status") != "committed"
    ):
        return "durable_receipt_binding_mismatch"
    if not signed(
        b"BUDDYLISTS_TEST_RECEIPT_V1\x00" + canonical(receipt_body),
        receipt["signature"],
        context["trusted_registry_public_key"],
    ):
        return "durable_receipt_signature_invalid"
    return None


def classify(record: dict, context: dict) -> tuple[bool, str]:
    """Return registration credit and the first explicit reason.

    Fail closed: an unknown or malformed record must not earn registration.
    This function deliberately grants no activation or independence credit.
    """
    if not required_types_hold(record, context):
        return False, "malformed_or_missing_evidence"
    try:
        core = record["core"]
        reason = (
            _core_refusal(core, context)
            or _challenge_refusal(core, context)
            or _proof_refusal(record, context)
        )
        if reason is not None:
            return False, reason
        return True, "registration_evidence_sufficient_for_fixture"
    except (KeyError, TypeError, ValueError, OverflowError, AttributeError):
        return False, "malformed_or_missing_evidence"
