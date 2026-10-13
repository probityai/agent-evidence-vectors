"""Bind an AAE verdict record to an observed-effect evidence record, claim by claim.

Four results are kept apart and never derived from one another:

* authorization: does the verdict record's core recompute to its core digest, and
  what verdict did the issuer assert at issuance;
* binding: does the evidence record's ``predicate.authorityDigest`` equal the RFC 8785
  SHA-256 of the verdict record (MATCH), name another document (MISMATCH), or is
  there no evidence record at all (ABSENT);
* execution: CLAIMED_BY_BOUND_RECORD only when a bound evidence record verifies under
  the pinned observer key and records an observed mutation, otherwise UNKNOWN. An
  evidence record is a claim, so execution is never reported as proven;
* completeness: always NOT_ESTABLISHED.

A valid authorization never sets execution, and a missing evidence record never
fails authorization. PROFILE.md states the binding field and the record shape.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import importlib.util
from functools import cache
from pathlib import Path
from types import ModuleType
from typing import Any

import kernel
import rfc8785
from pins import EVIDENCE_KEYS, trust_pins
from reproduce import require_pinned
from strict_json import load_json, refuse

HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parent.parent
EVIDENCE_VERIFIER = REPOSITORY / "vectors-observed-effect" / "check_vectors.py"
OBSERVED_EFFECT_TYPE = (
    "https://probityai.github.io/agent-evidence-vectors/predicate/v1/observed-effect"
)
BINDING_FIELD = "predicate.authorityDigest"
COMPLETENESS_REASON = (
    "A verdict record states what the issuer asserted at issuance. Neither it nor one "
    "evidence record shows that every decision in a set was written down."
)
CLAIMS = (
    "authorization.core_digest_recomputed",
    "authorization.verdict",
    "authorization.ratification.status",
    "binding.status",
    "evidence.verifier_verdict",
    "execution.status",
    "completeness.status",
)


@cache
def evidence_verifier() -> ModuleType:
    """Load this repository's observed-effect reference verifier under a unique name."""
    spec = importlib.util.spec_from_file_location(
        "aev_observed_effect_check_vectors", EVIDENCE_VERIFIER
    )
    if spec is None or spec.loader is None:
        refuse("the observed-effect verifier cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def record_digest(record: dict[str, Any]) -> str:
    """Lowercase hex SHA-256 of the RFC 8785 bytes of the whole verdict record."""
    return hashlib.sha256(rfc8785.dumps(record)).hexdigest()


def checked_record(record: Any) -> dict[str, Any]:
    """Refuse anything but a Section 6.2 verdict record: exactly core and core_digest."""
    if not isinstance(record, dict) or set(record) != {"core", "core_digest"}:
        refuse("a verdict record carries exactly core and core_digest")
    core = record["core"]
    if not isinstance(core, dict) or set(core) != set(kernel.CORE_MEMBERS):
        refuse("the verdict core does not carry exactly the Section 2.5.3 members")
    if core["verdict"] not in (kernel.PERMIT, kernel.DENY, kernel.PENDING):
        refuse("the verdict core carries a verdict outside PERMIT, DENY and PENDING")
    if not kernel.is_digest(record["core_digest"]) or not isinstance(core["trace"], list):
        refuse("the verdict record's core_digest or trace is malformed")
    index = core["grant_index"]
    if index is not None and (type(index) is not int or index < 0):
        refuse("grant_index is neither null nor a non-negative integer")
    return record


def authorization(record: dict[str, Any], ratification: Any) -> dict[str, Any]:
    """What the record asserts, whether its core recomputes, and any ratification."""
    recomputed = kernel.tagged_digest(kernel.TAG_CORE, record["core"])
    return {
        "core_digest": record["core_digest"],
        "core_digest_recomputed": recomputed is not None
        and kernel.same_text(recomputed, record["core_digest"]),
        "verdict": record["core"]["verdict"],
        "verdict_scope": "what the issuer asserted at issuance",
        "ratification": ratify_record(record, ratification),
    }


def ratify_record(record: dict[str, Any], request: Any) -> dict[str, Any]:
    """Run a requested ratification; a caller error produces no record (Section 6.4)."""
    if request is None:
        return {"status": "NOT_REQUESTED"}
    if not isinstance(request, dict) or set(request) - {
        "decision", "authority_proof", "prev_core_digest"
    }:
        refuse("a ratification request carries only decision, authority_proof, prev_core_digest")
    proof = request.get("authority_proof")
    require_pinned(proof.get("mandate") if isinstance(proof, dict) else None, trust_pins())
    try:
        outcome = kernel.ratify(record, request.get("decision"), proof,
                                request.get("prev_core_digest"))
    except kernel.CallerError as exc:
        return {"status": "CALLER_ERROR", "code": exc.code, "record_produced": False}
    return {
        "status": outcome.core["status"],
        "decision": outcome.core["decision"],
        "authority": outcome.core["authority"],
        "core_digest": outcome.core_digest,
        "record_produced": True,
    }


def evidence_claim(raw: bytes) -> tuple[dict[str, Any], str]:
    """Return (predicate, cited digest) from an observed-effect DSSE envelope."""
    envelope = load_json(raw)
    payload_text = envelope.get("payload")
    if not isinstance(payload_text, str):
        refuse("the evidence envelope carries no payload string")
    try:
        payload = base64.b64decode(payload_text, validate=True)
    except (binascii.Error, ValueError):
        refuse("the evidence payload is not base64")
    statement = load_json(payload)
    predicate = statement.get("predicate")
    if statement.get("predicateType") != OBSERVED_EFFECT_TYPE or not isinstance(predicate, dict):
        refuse("the evidence record is not an observed-effect statement")
    cited = predicate.get("authorityDigest")
    if not isinstance(cited, str) or len(cited) != 64 or set(cited) - set("0123456789abcdef"):
        refuse("the evidence record's authorityDigest is not 64 lowercase hex characters")
    return predicate, cited


def evidence_results(raw: bytes | None, record: dict[str, Any]) -> dict[str, Any]:
    """Binding, evidence-verifier and execution results for one optional record."""
    expected = record_digest(record)
    if raw is None:
        return {
            "binding": {"status": "ABSENT", "field": BINDING_FIELD, "cited": None,
                        "verdict_record_digest": expected},
            "evidence": {"verifier_verdict": "absent", "codes": []},
            "execution": {"status": "UNKNOWN", "reason": "there is no evidence record"},
        }
    predicate, cited = evidence_claim(raw)
    key = EVIDENCE_KEYS[0]["public_key"]
    verdict, codes = evidence_verifier().verify(raw, key, blobs=evidence_verifier().BLOBS)
    match = kernel.same_text(cited, expected)
    claimed = match and verdict == "valid" and predicate.get("mutation") == "observed"
    return {
        "binding": {"status": "MATCH" if match else "MISMATCH", "field": BINDING_FIELD,
                    "cited": cited, "verdict_record_digest": expected},
        "evidence": {"verifier_verdict": verdict, "codes": list(codes)},
        "execution": execution(claimed, match, verdict),
    }


def execution(claimed: bool, match: bool, verdict: str) -> dict[str, str]:
    """Execution is a claim carried by a bound, verifying record, never a proof."""
    if claimed:
        return {"status": "CLAIMED_BY_BOUND_RECORD",
                "reason": "a bound evidence record that verifies claims an observed mutation"}
    if not match:
        return {"status": "UNKNOWN", "reason": "the evidence record cites another document"}
    if verdict != "valid":
        return {"status": "UNKNOWN", "reason": "the evidence record fails its own verifier"}
    return {"status": "UNKNOWN", "reason": "the evidence record claims no observed mutation"}


def bind(record: Any, evidence: bytes | None, ratification: Any = None) -> dict[str, Any]:
    """Evaluate one verdict record, optional evidence and optional ratification.

    Parameters
    ----------
    record : object
        Parsed verdict record ``{"core", "core_digest"}``.
    evidence : bytes or None
        Raw observed-effect DSSE envelope bytes, or None when there is no record.
    ratification : object
        None, or ``{"decision", "authority_proof", "prev_core_digest"}``.

    Raises
    ------
    strict_json.InputError
        Malformed input, an unpinned key, or evidence outside the observed-effect shape.
    """
    checked = checked_record(record)
    result: dict[str, Any] = {"authorization": authorization(checked, ratification)}
    result.update(evidence_results(evidence, checked))
    result["completeness"] = {"status": "NOT_ESTABLISHED", "reason": COMPLETENESS_REASON}
    return result


def claim_values(result: dict[str, Any]) -> dict[str, Any]:
    """Flatten the closed-enum claims a case declares into dotted keys."""
    values: dict[str, Any] = {}
    for claim in CLAIMS:
        node: Any = result
        for part in claim.split("."):
            node = node[part]
        values[claim] = node
    return values
