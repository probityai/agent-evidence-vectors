"""Reference reader for the GovOps TRACE profile corpus.

It judges a bundle of producer records against the GovOps TRACE profile
(GovOpsWG/GovOps govops-trace-profile.md at 131cb66). Records arrive in the
profile's own form (Ed25519 over the RFC 8785 bytes of every member except
`signature`) or carried as the predicate of an in-toto Statement in a DSSE
envelope. Both forms reach the same record checks.

Every rule has a name in RULES. `judge(member, disabled={...})` turns rules off,
which is how check_vectors.py proves that each rule changes at least the members
written to exercise it. A rule that no member depends on is untested.

Where the profile names a check without fixing its recipe (the content digest,
the genesis sentinel, which policy store resolves an invocation), the recipe
used here is stated in README.md as a proposal for the profile's conformance
section. It is not presented as the profile's text.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from canonical import canonical_bytes  # noqa: E402

PROFILE = "tag:govops,2026:trace-v1"
PREDICATE_TYPE = (
    "https://probityai.github.io/agent-evidence-vectors/predicate/v1/govops-trace-record"
)
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
GENESIS = "sha256:" + "0" * 64
MVP_KINDS = ("AUTHORIZATION_DECISION", "CAPABILITY_INVOKED", "RUNTIME_EFFECT")

# Profile section 12: computed by the TRACE consumer, never producer-signed.
CONSUMER_DERIVED = (
    "capability_id",
    "capability_ids",
    "capability_resolution",
    "content_digest",
    "receipt_sequence",
    "received_at",
    "prev_receipt_hash",
    "trust_tier",
    "evidence_domain_id",
    "verified_at",
    "key_thumbprint",
)

RULES = (
    # refusals, in the order a record meets them
    "duplicate-member",
    "number-not-ijson",
    "dsse-payload-type",
    "key-unresolved",
    "dsse-bad-signature",
    "bad-signature",
    "predicate-type-mismatch",
    "subject-digest-mismatch",
    "profile-mismatch",
    "unknown-event-kind",
    "producer-mismatch",
    "decision-form-ambiguous",
    "missing-required-field",
    "key-temporally-invalid",
    "key-revoked",
    "producer-not-authorized-for-claim",
    # ingestion flags: the record is kept, the defect is reported
    "consumer-derived-field-ignored",
    "cnf-ignored",
    "chain-link-failure",
    "coverage-gap",
    "equivocation",
    "unresolved-parent",
    "capability-unmapped",
)


class Refusal(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _strict_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    seen: dict[str, Any] = {}
    for name, value in pairs:
        if name in seen:
            raise Refusal("duplicate-member")
        seen[name] = value
    return seen


def _no_float(text: str) -> Any:
    raise Refusal("number-not-ijson")


def _int(text: str) -> int:
    value = int(text)
    if abs(value) >= 2**53:
        raise Refusal("number-not-ijson")
    return value


def parse(text: str, on: set[str]) -> Any:
    """Admit the bytes before anything canonicalizes them."""
    hook = _strict_pairs if "duplicate-member" in on else dict
    if "number-not-ijson" in on:
        return json.loads(text, object_pairs_hook=hook, parse_float=_no_float, parse_int=_int)
    return json.loads(text, object_pairs_hook=hook)


def content_digest(record: dict[str, Any]) -> str:
    """sha256 over the RFC 8785 bytes of every member except `signature` (proposal).

    Those are exactly the bytes the profile's signature covers, so the digest is
    the same whether the record travels inline or as a DSSE predicate.
    """
    body = {k: v for k, v in record.items() if k != "signature"}
    return "sha256:" + hashlib.sha256(canonical_bytes(body)).hexdigest()


def _names(node: Any) -> set[str]:
    if isinstance(node, dict):
        return set(node) | {n for v in node.values() for n in _names(v)}
    if isinstance(node, list):
        return {n for v in node for n in _names(v)}
    return set()


def pae(payload_type: str, payload: bytes) -> bytes:
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def _verify(public_hex: str, sig: bytes, msg: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(sig, msg)
    except InvalidSignature:
        return False
    return True


def _b64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _key(registry: dict[str, Any], producer: Any, kid: Any, on: set[str]) -> dict[str, Any] | None:
    for entry in registry["keys"]:
        if entry["producer_id"] == producer and entry["kid"] == kid:
            found: dict[str, Any] = entry
            return found
    if "key-unresolved" in on:
        raise Refusal("key-unresolved")
    return None


def _require(on: set[str], rule: str, ok: bool) -> None:
    if rule in on and not ok:
        raise Refusal(rule)


FORMS = {
    "AUTHORIZATION_DECISION": ("decision", "decisions"),
    "CAPABILITY_INVOKED": ("invocation", "invocations"),
}


def _required_present(record: dict[str, Any], trace: dict[str, Any], kind: Any) -> bool:
    chain = record.get("producer_chain", {})
    event = trace.get("event", {})
    by_kind = {
        "AUTHORIZATION_DECISION": "pdp_id" in trace.get("runtime", {})
        and "policy_store_id" in trace.get("policy", {}),
        "CAPABILITY_INVOKED": "enforcement_point_id" in event,
        "RUNTIME_EFFECT": "outcome" in event,
    }
    return (
        all(f in record for f in ("producer", "record_id", "kid", "producer_chain"))
        and all(f in chain for f in ("producer_chain_id", "sequence_number", "prev_record_hash"))
        and "signed_at" in trace
        and by_kind.get(kind, True)
    )


def _check_shape(record: dict[str, Any], trace: dict[str, Any], on: set[str]) -> None:
    kind = trace.get("event_kind")
    _require(on, "profile-mismatch", trace.get("eat_profile") == PROFILE)
    _require(on, "unknown-event-kind", kind in MVP_KINDS)
    producer_id = record.get("producer_chain", {}).get("producer_id")
    _require(on, "producer-mismatch", record.get("producer") == producer_id)
    event = trace.get("event", {})
    pair = FORMS.get(str(kind))
    _require(on, "decision-form-ambiguous", not pair or (pair[0] in event) != (pair[1] in event))
    _require(on, "missing-required-field", _required_present(record, trace, kind))


def _check_authority(trace: dict[str, Any], key: dict[str, Any], on: set[str]) -> None:
    at = trace.get("signed_at", 0)
    _require(on, "key-temporally-invalid", key["valid_from"] <= at < key["valid_until"])
    revoked = key.get("revoked_at")
    _require(on, "key-revoked", revoked is None or revoked > at)
    allowed = trace.get("event_kind") in key["authorized_event_kinds"]
    _require(on, "producer-not-authorized-for-claim", allowed)


def _check_record(record: dict[str, Any], key: dict[str, Any] | None, on: set[str]) -> list[str]:
    trace = record.get("trace")
    if not isinstance(trace, dict):
        raise Refusal("missing-required-field")
    _check_shape(record, trace, on)
    if key is not None:
        _check_authority(trace, key, on)
    flags = []
    if "consumer-derived-field-ignored" in on and _names(record) & set(CONSUMER_DERIVED):
        flags.append("consumer-derived-field-ignored")
    if "cnf-ignored" in on and ("cnf" in record or "cnf" in trace):
        flags.append("cnf-ignored")
    return flags


def _inline(text: str, registry: dict[str, Any], on: set[str]) -> tuple[dict[str, Any], list[str]]:
    record = parse(text, on)
    key = _key(registry, record.get("producer"), record.get("kid"), on)
    body = {k: v for k, v in record.items() if k != "signature"}
    sig = _b64url(record.get("signature", ""))
    if (
        key is not None
        and "bad-signature" in on
        and not _verify(key["public_key_hex"], sig, canonical_bytes(body))
    ):
        raise Refusal("bad-signature")
    return record, _check_record(record, key, on)


def _dsse(text: str, registry: dict[str, Any], on: set[str]) -> tuple[dict[str, Any], list[str]]:
    env = parse(text, on)
    if "dsse-payload-type" in on and env.get("payloadType") != PAYLOAD_TYPE:
        raise Refusal("dsse-payload-type")
    payload = base64.b64decode(env["payload"])
    statement = parse(payload.decode("utf-8"), on)
    record = statement.get("predicate", {})
    sigs = env.get("signatures", [])
    key = _key(registry, record.get("producer"), sigs[0].get("keyid") if sigs else None, on)
    if key is not None and "dsse-bad-signature" in on:
        ok = any(
            _verify(
                key["public_key_hex"], base64.b64decode(s["sig"]), pae(env["payloadType"], payload)
            )
            for s in sigs
        )
        if not ok:
            raise Refusal("dsse-bad-signature")
    if "predicate-type-mismatch" in on and (
        statement.get("_type") != STATEMENT_TYPE or statement.get("predicateType") != PREDICATE_TYPE
    ):
        raise Refusal("predicate-type-mismatch")
    want = content_digest(record)[len("sha256:") :]
    got = [s.get("digest", {}).get("sha256") for s in statement.get("subject", [])]
    if "subject-digest-mismatch" in on and want not in got:
        raise Refusal("subject-digest-mismatch")
    return record, _check_record(record, key, on)


def _lookup(
    mapping: dict[str, Any], policy: dict[str, Any] | None, fact: dict[str, Any]
) -> dict[str, Any]:
    policy = policy or {}
    want = (
        policy.get("policy_store_id"),
        policy.get("policy_store_version"),
        fact["action"],
        fact["resource_type"],
    )
    for e in mapping["entries"]:
        if (
            e["policy_store_id"],
            e["policy_store_version"],
            e["action"],
            e["resource_type"],
        ) == want:
            return {"capability_ids": [e["capability_id"]], "resolution_status": "resolved"}
    return {"capability_ids": [], "resolution_status": "unmapped"}


def _policy_for(record: dict[str, Any], by_id: dict[Any, dict[str, Any]]) -> dict[str, Any] | None:
    """An invocation resolves against the policy store of the decision its
    `authorized` edge names (proposal); a decision uses its own."""
    if record["trace"]["event_kind"] != "CAPABILITY_INVOKED":
        policy: dict[str, Any] | None = record["trace"].get("policy")
        return policy
    for edge in record.get("parent_record_ids", []):
        parent = by_id.get((edge["producer_id"], edge["record_id"]))
        if edge["relationship_type"] == "authorized" and parent is not None:
            found: dict[str, Any] | None = parent["trace"].get("policy")
            return found
    return None


def _facts(event: dict[str, Any]) -> list[tuple[Any, dict[str, Any]]]:
    facts: list[tuple[Any, dict[str, Any]]] = []
    for single, many, idkey in (
        ("decision", "decisions", "decision_id"),
        ("invocation", "invocations", "invocation_id"),
    ):
        if single in event:
            facts.append((None, event[single]))
        facts += [(item[idkey], item) for item in event.get(many, [])]
    return facts


def _resolve(
    records: list[dict[str, Any]], mapping: dict[str, Any], on: set[str]
) -> tuple[dict[str, Any], list[str]]:
    by_id = {(r["producer"], r["record_id"]): r for r in records}
    out: dict[str, Any] = {}
    flags: list[str] = []
    for r in records:
        facts = _facts(r["trace"].get("event", {}))
        if not facts:
            continue
        policy = _policy_for(r, by_id)
        results = []
        for fid, fact in facts:
            res = _lookup(mapping, policy, fact)
            if fid is not None:
                res = {"decision_id": fid, **res}
            if res["resolution_status"] == "unmapped" and "capability-unmapped" in on:
                flags.append("capability-unmapped")
            results.append(res)
        out[r["record_id"]] = results
    return out, flags


def _chain_flags(members: list[dict[str, Any]], on: set[str]) -> list[str]:
    flags = []
    by_seq: dict[int, list[dict[str, Any]]] = {}
    for r in members:
        by_seq.setdefault(r["producer_chain"]["sequence_number"], []).append(r)
    if any(len({content_digest(x) for x in v}) > 1 for v in by_seq.values()):
        flags.append("equivocation")
    seqs = sorted(by_seq)
    for prev, cur in zip(seqs, seqs[1:], strict=False):
        if cur != prev + 1:
            flags.append("coverage-gap")
        elif any(
            x["producer_chain"]["prev_record_hash"] != content_digest(by_seq[prev][0])
            for x in by_seq[cur]
        ):
            flags.append("chain-link-failure")
    if (
        seqs
        and seqs[0] == 0
        and any(x["producer_chain"]["prev_record_hash"] != GENESIS for x in by_seq[0])
    ):
        flags.append("chain-link-failure")
    return [f for f in flags if f in on]


def _bundle_flags(records: list[dict[str, Any]], on: set[str]) -> list[str]:
    chains: dict[Any, list[dict[str, Any]]] = {}
    for r in records:
        chains.setdefault(r["producer_chain"]["producer_chain_id"], []).append(r)
    flags = [f for members in chains.values() for f in _chain_flags(members, on)]
    present = {(r["producer"], r["record_id"]) for r in records}
    edges = [e for r in records for e in r.get("parent_record_ids", [])]
    if "unresolved-parent" in on and any(
        (e["producer_id"], e["record_id"]) not in present for e in edges
    ):
        flags.append("unresolved-parent")
    return flags


def judge(
    member: dict[str, Any],
    registry: dict[str, Any],
    mapping: dict[str, Any],
    disabled: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    on = set(RULES) - set(disabled)
    records: list[dict[str, Any]] = []
    flags: list[str] = []
    try:
        for item in member["records"]:
            reader = _dsse if item["form"] == "dsse" else _inline
            record, f = reader(item["text"], registry, on)
            records.append(record)
            flags += f
        flags += _bundle_flags(records, on)
        resolution, f = _resolve(records, mapping, on)
        flags += f
    except Refusal as r:
        return {"verdict": "reject", "code": r.code}
    except (KeyError, TypeError, ValueError, AttributeError):
        return {"verdict": "reject", "code": "malformed"}
    flags = sorted(set(flags))
    return {
        "verdict": "flag" if flags else "accept",
        "flags": flags,
        "capability_resolution": resolution,
    }
