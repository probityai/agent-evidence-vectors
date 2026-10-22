"""Verify an ACS conformance verdict record, its peer statement and its quarantine record.

The records follow the draft ACS conformance verdict evidence predicate
(GenAI-Security-Project/agent-control-standard pull request 297,
``docs/predicates/acs-verdict-evidence-v1.md`` at ``v1.0.1-draft``). That draft
states two rules in prose:

* a lift of ``witness_scope`` above ``SELF`` must come from a statement the
  peer authored and signed, naming the requirement it checked and the artifact
  it checked it with, never from a field the runner writes;
* a quarantine record carries its own digest and a defined outcome for when
  ``review_by`` passes.

This reader makes both rules executable. A verifier gets the signed verdict or
quarantine record, the vector input, the consumer policy (pinned runner keys,
pinned peer keys with their relationship, the time of evaluation) and whatever
peer statement and transcript the consumer retained. It names the first check
that fails. The peer statement's type is
``https://probityai.github.io/agent-evidence-vectors/predicate/v1/peer-verification``.

Checks, in order, with the decision and reason of the first that fails:

1. the record is a DSSE v1 envelope (no verdict, ``malformed_envelope``);
2. its payload type is ``application/vnd.in-toto+json``
   (``not_established``, ``unsupported_payload_type``);
3. a signature naming a pinned runner keyid verifies over the DSSE PAE
   (``contradicted``, ``untrusted_key`` or ``signature_invalid``); a signature
   naming any other key is ignored and lifts nothing;
4. the payload is an in-toto Statement v1 (``payload_not_statement``);
5. its predicate type is the pinned one (``unsupported_predicate``);
6. every field is well formed, in the draft's table order, and no field by
   which the runner asserts its own scope is present
   (``field_invalid:<field>``);
7. the subject digest is the SHA-256 of the canonical vector input and
   ``vector_id`` is its first 16 hex characters (``subject_digest_mismatch``);
8. ``payload_digest`` recomputes over ``payload_digest_fields``, and that list
   covers every field the draft names (``payload_digest_mismatch``,
   ``payload_digest_fields_incomplete``);
9. ``witness_scope`` equals the scope derived from operator identifier
   equality and the verified peer statement (``witness_scope_misderived``,
   ``peer_artifact_unverified:<step>``, ``peer_disagrees`` when the peer observed
   something else or reached another verdict).

A quarantine record (a predicate whose ``status`` is ``quarantined``) passes
steps 1 to 5 and 7, then: every quarantine field is present
(``quarantine_field_missing:<field>``), its digest field list covers every one
of them including ``expiry_disposition`` (``payload_digest_fields_incomplete``), the digest
recomputes (``quarantine_digest_mismatch``), and ``review_by`` has not passed
at the policy's ``as_of`` time (``not_established``, ``quarantine_overdue``:
the vector reads ``unmeasurable`` and stays excluded).

External-verifier contract: ``<verifier> <case-dir>/case.json --json`` prints
one JSON object carrying ``decision`` and ``reason`` and exits 0 for
``supported``, 1 for ``contradicted`` or ``not_established``, 2 for no verdict.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import importlib
import json
import re
import sys
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

SUITE = "acs-verdict-evidence/v1.0.1-draft"
SUPPORTED, CONTRADICTED, NOT_ESTABLISHED, NO_VERDICT = (
    "supported", "contradicted", "not_established", "no_verdict")
EXIT_FOR = {SUPPORTED: 0, CONTRADICTED: 1, NOT_ESTABLISHED: 1, NO_VERDICT: 2}
STATEMENT_V1 = "https://in-toto.io/Statement/v1"
INTOTO = "application/vnd.in-toto+json"
VERDICT_PREDICATE = ("https://github.com/GenAI-Security-Project/agent-control-standard/"
                     "blob/main/docs/predicates/acs-verdict-evidence-v1.md")
PEER_PREDICATE = ("https://probityai.github.io/agent-evidence-vectors/"
                  "predicate/v1/peer-verification")
VECTOR_PREFIX = "acs-conformance-vector:"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX16 = re.compile(r"^[0-9a-f]{16}$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
MAX_BYTES = 4 * 1024 * 1024

VERDICTS = ("pass", "rejected", "unmeasurable", "quarantined")
SCOPES = ("SELF", "PEER", "EXTERNAL")
BASES = ("wire_transcript", "signed_decision_record", "policy_state",
         "terminal_state_evidence", "anchor_commitment")
DIGEST_FIELDS = ("anchor", "clause", "expected", "observed", "profile", "vector_id",
                 "verdict", "verification_basis", "witness_derivation", "witness_scope")
DOES_NOT_COVER = ("behavior_snapshot", "integrity", "provenance", "subject")
# Fields by which a runner could choose its own scope. The draft removes them.
RUNNER_LIFT_FIELDS = ("lift_state", "checked", "signer_relationship", "counter_signature")
FIELDS = (
    "vector_id", "profile", "anchor", "clause", "verdict",
    "witness_derivation.runner.id", "witness_derivation.runner.hosting_operator_id",
    "witness_derivation.deployment_operator_id", "witness_scope", "verification_basis",
    "expected", "observed", "behavior_snapshot", "integrity.payload_digest",
    "integrity.payload_digest_fields", "integrity.does_not_cover", "integrity.binding",
    "provenance.peer_artifact", "provenance.anchor",
)
QUARANTINE_FIELDS = ("vector_id", "status", "reason", "quarantine_ref", "quarantine_gap",
                     "owner", "review_by", "excluded_from", "expiry_disposition")
EXPIRY_DISPOSITIONS = ("revert_to_unmeasurable",)
EVIDENCE_KINDS = ("client_run", "wire_transcript")
RELATIONSHIPS = {"peer": "PEER", "external": "EXTERNAL"}

# Every rule, by the name the mutation check switches off.
RULES = (
    "payload_type", "pinned_keys_only", "signature", "statement_type", "predicate",
    *(f"field:{f}" for f in FIELDS), "runner_lift_field", "subject", "payload_digest",
    "digest_field_coverage", "ids_unequal", "peer:supplied", "peer:digest",
    "peer:pinned_key", "peer:signature", "peer:predicate", "peer:vector", "peer:requirement",
    "peer:evidence_kind", "peer:deployment", "peer:transcript_supplied",
    "peer:transcript_digest", "peer:agrees", "scope", "quarantine:fields",
    "quarantine:coverage", "quarantine:digest", "quarantine:expiry_value", "quarantine:overdue",
)

_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")


class Refusal(Exception):
    """The first failed check: a decision and a reason code."""

    def __init__(self, decision: str, reason: str) -> None:
        super().__init__(reason)
        self.decision, self.reason = decision, reason


def _rail() -> Any:
    """The rail module that holds the package's stdlib Ed25519."""
    for name in _RAIL_NAMES:
        module = sys.modules.get(name)
        if module is not None and hasattr(module, "ed25519_verify"):
            return module
    for name in _RAIL_NAMES[:2]:
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        if hasattr(module, "ed25519_verify"):
            return module
    raise ImportError("the reference rail's Ed25519 primitive is unavailable")


@lru_cache(maxsize=4096)
def _ed25519_verify(key: bytes, message: bytes, sig: bytes) -> bool:
    return bool(_rail().ed25519_verify(key, message, sig))


def canonical(value: Any) -> bytes:
    """The draft's canonical form: sorted keys, no whitespace, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding."""
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def _b64(value: Any, reason: str) -> bytes:
    if not isinstance(value, str):
        raise Refusal(NO_VERDICT, reason)
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise Refusal(NO_VERDICT, reason) from exc


def parse_envelope(raw: bytes, reason: str = "malformed_envelope"
                   ) -> tuple[str, bytes, list[tuple[str, bytes]]]:
    """(payloadType, payload, [(keyid, sig)]) or a no-verdict refusal."""
    if len(raw) > MAX_BYTES:
        raise Refusal(NO_VERDICT, reason)
    try:
        doc = json.loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise Refusal(NO_VERDICT, reason) from exc
    if not isinstance(doc, dict):
        raise Refusal(NO_VERDICT, reason)
    payload_type, entries = doc.get("payloadType"), doc.get("signatures")
    if not isinstance(payload_type, str) or not payload_type:
        raise Refusal(NO_VERDICT, reason)
    if not isinstance(entries, list) or not entries:
        raise Refusal(NO_VERDICT, reason)
    sigs = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("keyid"), str):
            raise Refusal(NO_VERDICT, reason)
        sigs.append((entry["keyid"], _b64(entry.get("sig"), reason)))
    return payload_type, _b64(doc.get("payload"), reason), sigs


def _signed(payload_type: str, body: bytes, sigs: list[tuple[str, bytes]],
            trusted: dict[str, bytes], pinned_only: bool, check_sig: bool) -> str | None:
    """The reason the signature check fails, or None when a pinned key verifies."""
    message = pae(payload_type, body)
    named = False
    for kid, sig in sigs:
        key = trusted.get(kid)
        if key is None:
            if pinned_only or not trusted:
                continue
            key = next(iter(trusted.values()))
        named = True
        if not check_sig or _ed25519_verify(key, message, sig):
            return None
    return "signature_invalid" if named else "untrusted_key"


def _get(d: Any, dotted: str) -> tuple[bool, Any]:
    for part in dotted.split("."):
        if not isinstance(d, dict) or part not in d:
            return False, None
        d = d[part]
    return True, d


def _nonempty_str(v: Any) -> bool:
    return isinstance(v, str) and bool(v)


def _disposition(v: Any) -> bool:
    return (isinstance(v, dict) and _nonempty_str(v.get("decision"))
            and isinstance(v.get("reason_codes"), list)
            and all(isinstance(c, str) for c in v["reason_codes"]))


def _hex(pattern: re.Pattern[str]) -> Any:
    return lambda v: isinstance(v, str) and bool(pattern.fullmatch(v))


def _str_list(v: Any) -> bool:
    return isinstance(v, list) and bool(v) and all(isinstance(f, str) for f in v)


_VALIDATORS: dict[str, Any] = {
    "vector_id": _hex(HEX16),
    "verdict": lambda v: v in VERDICTS,
    "witness_scope": lambda v: v in SCOPES,
    "verification_basis": lambda v: isinstance(v, list) and bool(v)
    and all(b in BASES for b in v),
    "expected": _disposition,
    "observed": _disposition,
    "behavior_snapshot": lambda v: v is None or isinstance(v, dict),
    "integrity.payload_digest": _hex(HEX64),
    "integrity.payload_digest_fields": _str_list,
    "integrity.does_not_cover": lambda v: isinstance(v, list)
    and set(DOES_NOT_COVER) <= set(v),
    "provenance.peer_artifact": lambda v: v is None or _hex(HEX64)(v),
    "provenance.anchor": lambda v: v is None or (
        isinstance(v, dict) and v.get("kind") in ("rfc3161-timestamp", "transparency-log")),
}


def _field_ok(field: str, d: dict[str, Any]) -> bool:
    present, v = _get(d, field)
    return present and bool(_VALIDATORS.get(field, _nonempty_str)(v))


def _statement(body: bytes, predicate_type: str, skip: frozenset[str],
               prefix: str = "") -> dict[str, Any]:
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, ValueError):
        payload = None
    if not isinstance(payload, dict) or (
            payload.get("_type") != STATEMENT_V1 and f"{prefix}statement_type" not in skip):
        raise Refusal(NOT_ESTABLISHED, "payload_not_statement")
    if payload.get("predicateType") != predicate_type and f"{prefix}predicate" not in skip:
        raise Refusal(NOT_ESTABLISHED, "unsupported_predicate")
    if not isinstance(payload.get("predicate"), dict):
        raise Refusal(NOT_ESTABLISHED, "field_invalid:predicate")
    return payload


def _subject_digests(statement: dict[str, Any]) -> list[str]:
    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        return []
    return [s["digest"]["sha256"] for s in subjects
            if isinstance(s, dict) and isinstance(s.get("digest"), dict)
            and isinstance(s["digest"].get("sha256"), str)]


def _check_subject(statement: dict[str, Any], vector_digest: str,
                   skip: frozenset[str]) -> None:
    d = statement["predicate"]
    if "subject" in skip:
        return
    if vector_digest not in _subject_digests(statement) or d.get("vector_id") != vector_digest[:16]:
        raise Refusal(CONTRADICTED, "subject_digest_mismatch")


def _covered_digest(d: dict[str, Any], required: tuple[str, ...], coverage_rule: str,
                    digest_rule: str, mismatch: str, skip: frozenset[str]) -> None:
    fields = d["integrity"]["payload_digest_fields"]
    if coverage_rule not in skip and not set(required) <= set(fields):
        raise Refusal(NOT_ESTABLISHED, "payload_digest_fields_incomplete")
    if digest_rule in skip:
        return
    if any(f not in d for f in fields):
        raise Refusal(CONTRADICTED, mismatch)
    if sha256_hex(canonical({f: d[f] for f in fields})) != d["integrity"]["payload_digest"]:
        raise Refusal(CONTRADICTED, mismatch)


def _peer_fail(step: str, decision: str = CONTRADICTED) -> Refusal:
    return Refusal(decision, f"peer_artifact_unverified:{step}")


def _peer_statement(raw: bytes, named: str, peer_keys: dict[str, Any],
                    skip: frozenset[str]) -> tuple[dict[str, Any], str | None]:
    """The verified peer statement and the pinned keyid that signed it."""
    trusted = {k: base64.b64decode(v["public_key"]) for k, v in peer_keys.items()}
    payload_type, body, sigs = parse_envelope(raw, "peer_artifact_unverified:malformed")
    reason = _signed(payload_type, body, sigs, trusted,
                     "peer:pinned_key" not in skip, "peer:signature" not in skip)
    if reason is not None:
        raise _peer_fail(reason)
    try:
        statement = _statement(body, PEER_PREDICATE, skip, "peer:")
    except Refusal as exc:
        raise _peer_fail(exc.reason) from exc
    if sha256_hex(canonical(statement)) != named and "peer:digest" not in skip:
        raise _peer_fail("digest_mismatch")
    return statement, next((k for k, _ in sigs if k in peer_keys), None)


def _peer_evidence(artifact: Any, d: dict[str, Any], vector_digest: str,
                   transcript: bytes | None, skip: frozenset[str]) -> None:
    """The evidence the peer names is the client run or the transcript the consumer holds."""
    kind = artifact.get("kind") if isinstance(artifact, dict) else None
    if kind not in EVIDENCE_KINDS and "peer:evidence_kind" not in skip:
        raise _peer_fail("no_evidence_artifact")
    if kind == "client_run" and "peer:deployment" not in skip and (
            artifact.get("deployment") != d["witness_derivation"]["deployment_operator_id"]):
        raise _peer_fail("wrong_deployment")
    if kind != "wire_transcript":
        return
    if transcript is None:
        if "peer:transcript_supplied" not in skip:
            raise _peer_fail("transcript_not_supplied", NOT_ESTABLISHED)
        return
    if "peer:transcript_digest" not in skip and (
            artifact.get("transcript_digest") != sha256_hex(transcript)
            or artifact.get("vector") != VECTOR_PREFIX + vector_digest[:16]):
        raise _peer_fail("transcript_digest_mismatch")


def _peer_lift(d: dict[str, Any], vector_digest: str, policy: dict[str, Any],
               supplied: dict[str, bytes], skip: frozenset[str]) -> str:
    """The scope a verified peer statement lifts the record to."""
    raw = supplied.get("peer_statement")
    if raw is None:
        if "peer:supplied" not in skip:
            raise _peer_fail("not_supplied", NOT_ESTABLISHED)
        return "PEER"
    peer_keys = policy.get("peer_keys", {})
    statement, signer = _peer_statement(raw, d["provenance"]["peer_artifact"], peer_keys, skip)
    p = statement["predicate"]
    if vector_digest not in _subject_digests(statement) and "peer:vector" not in skip:
        raise _peer_fail("wrong_vector")
    if p.get("requirement") != d["anchor"] and "peer:requirement" not in skip:
        raise _peer_fail("wrong_requirement")
    _peer_evidence(p.get("evidence_artifact"), d, vector_digest, supplied.get("transcript"), skip)
    if (p.get("observed") != d["observed"] or p.get("verdict") != d["verdict"]) and (
            "peer:agrees" not in skip):
        raise Refusal(CONTRADICTED, "peer_disagrees")
    relationship = peer_keys.get(signer, {}).get("relationship") if signer else None
    return RELATIONSHIPS.get(str(relationship), "PEER")


def _verdict(statement: dict[str, Any], vector_digest: str, policy: dict[str, Any],
             supplied: dict[str, bytes], skip: frozenset[str]) -> str:
    d = statement["predicate"]
    for field in FIELDS:
        if f"field:{field}" not in skip and not _field_ok(field, d):
            raise Refusal(NOT_ESTABLISHED, f"field_invalid:{field}")
    if "runner_lift_field" not in skip:
        for section in (d, d.get("provenance") or {}, d.get("witness_derivation") or {}):
            for name in RUNNER_LIFT_FIELDS:
                if isinstance(section, dict) and name in section:
                    where = "provenance." if section is d.get("provenance") else ""
                    raise Refusal(NOT_ESTABLISHED, f"field_invalid:{where}{name}")
    _check_subject(statement, vector_digest, skip)
    _covered_digest(d, DIGEST_FIELDS, "digest_field_coverage", "payload_digest",
                    "payload_digest_mismatch", skip)
    wd = d["witness_derivation"]
    same = wd["runner"]["hosting_operator_id"] == wd["deployment_operator_id"]
    if d["provenance"]["peer_artifact"] is None:
        if not same and "ids_unequal" not in skip:
            raise Refusal(CONTRADICTED, "witness_scope_misderived")
        derived = "SELF"
    else:
        derived = _peer_lift(d, vector_digest, policy, supplied, skip)
    if d["witness_scope"] != derived and "scope" not in skip:
        raise Refusal(CONTRADICTED, "witness_scope_misderived")
    return f"verdict_verified_{derived.lower()}"


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def _quarantine_fields(d: dict[str, Any]) -> None:
    """Every quarantine field is present; an issue or a named gap is required."""
    if not (_nonempty_str(d.get("quarantine_ref")) or _nonempty_str(d.get("quarantine_gap"))):
        raise Refusal(NOT_ESTABLISHED, "quarantine_field_missing:quarantine_ref")
    for field in QUARANTINE_FIELDS:
        if field not in ("quarantine_ref", "quarantine_gap") and not _nonempty_str(d.get(field)):
            raise Refusal(NOT_ESTABLISHED, f"quarantine_field_missing:{field}")
    if not DATE.fullmatch(str(d["review_by"])):
        raise Refusal(NOT_ESTABLISHED, "quarantine_field_missing:review_by")
    if not (isinstance(d.get("integrity"), dict)
            and _field_ok("integrity.payload_digest", d)
            and _field_ok("integrity.payload_digest_fields", d)):
        raise Refusal(NOT_ESTABLISHED, "quarantine_field_missing:integrity")


def _quarantine(statement: dict[str, Any], vector_digest: str, policy: dict[str, Any],
                skip: frozenset[str]) -> str:
    d = statement["predicate"]
    if "quarantine:fields" not in skip:
        _quarantine_fields(d)
    if (d.get("expiry_disposition") not in EXPIRY_DISPOSITIONS
            and "quarantine:expiry_value" not in skip):
        raise Refusal(NOT_ESTABLISHED, "field_invalid:expiry_disposition")
    _check_subject(statement, vector_digest, skip)
    _covered_digest(d, QUARANTINE_FIELDS, "quarantine:coverage", "quarantine:digest",
                    "quarantine_digest_mismatch", skip)
    review_end = _parse_time(f"{d['review_by']}T23:59:59Z")
    if _parse_time(policy["as_of"]) > review_end and "quarantine:overdue" not in skip:
        raise Refusal(NOT_ESTABLISHED, "quarantine_overdue")
    return "quarantine_in_force"


def judge(record: bytes, vector: bytes, policy: dict[str, Any], supplied: dict[str, bytes],
          skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision for one signed verdict or quarantine record."""
    trusted = {str(k): base64.b64decode(v) for k, v in policy["trusted_keys"].items()}
    vector_digest = sha256_hex(canonical(json.loads(vector)))
    try:
        payload_type, body, sigs = parse_envelope(record)
        if payload_type != INTOTO and "payload_type" not in skip:
            raise Refusal(NOT_ESTABLISHED, "unsupported_payload_type")
        reason = _signed(payload_type, body, sigs, trusted,
                         "pinned_keys_only" not in skip, "signature" not in skip)
        if reason is not None:
            raise Refusal(CONTRADICTED, reason)
        statement = _statement(body, policy["predicate_type"], skip)
        if statement["predicate"].get("status") == "quarantined":
            outcome = _quarantine(statement, vector_digest, policy, skip)
        else:
            outcome = _verdict(statement, vector_digest, policy, supplied, skip)
    except Refusal as stop:
        return {"decision": stop.decision, "reason": stop.reason}
    return {"decision": SUPPORTED, "reason": outcome}


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """Judge one case directory's ``case.json``."""
    case = json.loads(case_path.read_text(encoding="utf-8"))
    base = case_path.parent
    supplied = {name: (base / file).read_bytes() for name, file in case["supplied"].items()}
    return judge((base / case["record"]).read_bytes(), (base / case["vector"]).read_bytes(),
                 case["policy"], supplied, skip)
