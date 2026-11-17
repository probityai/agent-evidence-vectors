"""A co-signed tool-call receipt: the fail-closed member rules a verifier applies before signatures.

The record class is a receipt an agent signs for one tool call, which the caller may co-sign: a
format version, the two parties' identifiers, the tool name, hashes of the task and of the result,
the outcome (``success`` and a ``failureType`` that names the failure, empty on success), the
latency in milliseconds, a timestamp, and hex-encoded Ed25519 signatures.

Each rule here refuses a receipt whose signature can still verify, because a valid signature over
a malformed record is the case a signature check alone admits:

* an unknown ``formatVersion`` is refused, never read as the version the verifier knows;
* a full receipt carries every member: an absent hash is not a hash, and an absent ``failureType``
  is not an empty one;
* hashes are exactly 64 lowercase hex characters, signatures exactly 128: a lenient decoder that
  accepts uppercase, or truncates an odd-length string, reads two encodings as one signature;
* ``failureType`` is empty exactly when ``success`` is true;
* ``latencyMs`` is an integer in 0..2**53 - 1;
* ``agentDid``, ``toolName`` and any ``callerDid`` are non-empty strings: a ``null`` signer is no
  signer, and a verifier that resolves keys by ``agentDid`` must not be handed a number or nothing;
* a ``callerSignature`` comes with the ``callerDid`` it is checked against, and a ``callerDid``
  comes with the ``callerSignature`` that makes the caller a co-signer: a receipt that names a
  caller who did not sign reads as co-signed in any display that shows the caller;
* the co-signer is another party than the signer: a ``callerDid`` equal to ``agentDid``, or a
  ``callerSignature`` equal to ``signature`` (one Ed25519 key over one message), is one party
  shown as two (``cosigner-is-signer``).

Whether each signature verifies, and under which key, is the verifier's question after admission.
Two signatures bind two parties to one record; they do not show the record is true, or that the
parties are independent.
"""

from __future__ import annotations

import re
from typing import Any

from .freshness import instant
from .rules import Check, Context, RuleSet, register
from .strict_json import MAX_SAFE_INTEGER, Refusal

VERSIONS = frozenset({"1"})
MEMBERS = (
    "formatVersion",
    "agentDid",
    "toolName",
    "taskHash",
    "resultHash",
    "success",
    "failureType",
    "latencyMs",
    "timestamp",
    "signature",
)
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX128 = re.compile(r"[0-9a-f]{128}")


def _receipt(context: Context) -> dict[str, Any]:
    if not isinstance(context.document, dict):
        raise Refusal("receipt-shape-malformed", "", "a receipt is a JSON object")
    return context.document


def _check_version(context: Context) -> None:
    receipt = _receipt(context)
    if receipt.get("formatVersion") not in VERSIONS:
        raise Refusal("version-unknown", "/formatVersion", f"formatVersion {receipt.get('formatVersion')!r} is not one this verifier knows")


def _check_members(context: Context) -> None:
    receipt = _receipt(context)
    for member in MEMBERS:
        if member not in receipt:
            context.note(Refusal("member-missing", f"/{member}", f"a full receipt carries {member}"))


def _check_hashes(context: Context) -> None:
    receipt = _receipt(context)
    for member in ("taskHash", "resultHash"):
        value = receipt.get(member)
        if member in receipt and not (isinstance(value, str) and HEX64.fullmatch(value)):
            context.note(Refusal("hash-not-lowercase-hex64", f"/{member}", "a hash is exactly 64 lowercase hex characters"))


def _check_signatures(context: Context) -> None:
    receipt = _receipt(context)
    for member in ("signature", "callerSignature"):
        value = receipt.get(member)
        if member in receipt and not (isinstance(value, str) and HEX128.fullmatch(value)):
            context.note(Refusal("signature-not-lowercase-hex128", f"/{member}", "a signature is exactly 128 lowercase hex characters"))
    if "callerSignature" in receipt and "callerDid" not in receipt:
        context.note(Refusal("cosigner-missing", "/callerDid", "a callerSignature comes with the callerDid it is checked against"))
    if "callerDid" in receipt and "callerSignature" not in receipt:
        context.note(Refusal("cosignature-missing", "/callerSignature", "a callerDid names a co-signer, so the receipt carries its callerSignature"))
    if "callerDid" in receipt and receipt.get("callerDid") == receipt.get("agentDid"):
        context.note(Refusal("cosigner-is-signer", "/callerDid", "the co-signer is the agent itself: one party shown as two"))
    elif "callerSignature" in receipt and receipt.get("callerSignature") == receipt.get("signature"):
        context.note(Refusal("cosigner-is-signer", "/callerSignature", "the co-signature is the signature's own bytes: one key, one party"))


def _check_identities(context: Context) -> None:
    receipt = _receipt(context)
    for member in ("agentDid", "toolName", "callerDid"):
        if member in receipt and not (isinstance(receipt[member], str) and receipt[member]):
            context.note(Refusal("member-malformed", f"/{member}", f"{member} is a non-empty string"))


def _check_outcome(context: Context) -> None:
    receipt = _receipt(context)
    if "success" not in receipt or "failureType" not in receipt:
        return  # members reports the absence
    success, failure = receipt["success"], receipt["failureType"]
    if not isinstance(success, bool) or not isinstance(failure, str):
        context.note(Refusal("failure-type-inconsistent", "/failureType", "success is a boolean and failureType a string"))
    elif success and failure != "":
        context.note(Refusal("failure-type-inconsistent", "/failureType", 'failureType is "" when success is true'))
    elif not success and failure == "":
        context.note(Refusal("failure-type-inconsistent", "/failureType", "failureType names the failure when success is false"))


def _check_latency(context: Context) -> None:
    receipt = _receipt(context)
    if "latencyMs" not in receipt:
        return
    value = receipt["latencyMs"]
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_SAFE_INTEGER:
        context.note(Refusal("latency-out-of-range", "/latencyMs", "latencyMs is an integer in 0..2**53 - 1"))


def _check_timestamp(context: Context) -> None:
    receipt = _receipt(context)
    if "timestamp" in receipt:
        try:
            instant(receipt["timestamp"], "/timestamp")
        except Refusal as refusal:
            context.note(refusal)


CO_SIGNED_RECEIPT = register(
    RuleSet(
        name="co-signed-receipt",
        summary="a co-signed tool-call receipt: known version, every member, exact hex encodings, consistent outcome",
        checks=(
            Check("version", "formatVersion is a version this verifier knows", _check_version),
            Check("members", "a full receipt carries every member", _check_members),
            Check("hashes", "taskHash and resultHash are 64 lowercase hex characters", _check_hashes),
            Check("identities", "agentDid, toolName and any callerDid are non-empty strings", _check_identities),
            Check("signatures", "signatures are 128 lowercase hex characters; a co-signature and its signer come together", _check_signatures),
            Check("outcome", "failureType is empty exactly when success is true", _check_outcome),
            Check("latency", "latencyMs is an integer in 0..2**53 - 1", _check_latency),
            Check("timestamp", "timestamp is an RFC 3339 instant", _check_timestamp),
        ),
    )
)
