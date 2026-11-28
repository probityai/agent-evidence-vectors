"""A bounded absence check with a separately pinned prior witness."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime
from typing import Any

import run_vectors
from agent_evidence_vectors import observedeffect
from agent_evidence_vectors.identifiers import identifier

DOMAIN = b"probity-ws4-prior-witness-candidate-v0\0"
GENESIS = "0" * 64
PREDICATE_TYPE = identifier("agent-evidence-vectors/predicate/v1/observed-effect")
RECORD_DIGEST = "162352770f2f6c1cd861685e8e84c85603948b324cfa58752e7ad9dd76747da8"


class ProcessingFailure(ValueError):
    """The input or verifier failed before it could decide the property."""


def canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def _path(value: Any) -> bool:
    if not isinstance(value, str) or not value.startswith("/") or "\\" in value:
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return False
    parts = value.split("/")[1:]
    if value.endswith("/"):
        parts = parts[:-1]
    return all(part not in {"", ".", ".."} for part in parts)


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProcessingFailure(f"duplicate field {key}")
        result[key] = value
    return result


def _record(line: bytes, key: bytes, sequence: int, previous: str) -> dict[str, Any]:
    try:
        value = json.loads(line, object_pairs_hook=_unique_pairs)
        if canonical(value) != line or set(value) != {"body", "signature"}:
            raise ProcessingFailure("witness line is not canonical or has extra fields")
        body = value["body"]
        if not isinstance(body, dict):
            raise ProcessingFailure("witness body is not an object")
        if type(body.get("sequence")) is not int or body["sequence"] != sequence:
            raise ProcessingFailure("witness sequence differs")
        if body.get("previous") != previous:
            raise ProcessingFailure("witness chain differs")
        signature = bytes.fromhex(value["signature"])
        if not run_vectors.ed25519_verify(key, DOMAIN + canonical(body), signature):
            raise ProcessingFailure("witness signature differs")
    except (TypeError, ValueError, UnicodeDecodeError, KeyError) as exc:
        raise ProcessingFailure(f"invalid witness record: {exc}") from exc
    return value


def verify_witness(log: bytes, trusted: dict[str, Any], claim: str, commitment: str) -> str:
    """Verify prior and open records against pins supplied outside the log."""
    try:
        if not isinstance(log, bytes):
            raise ProcessingFailure("witness log must be bytes")
        if not isinstance(trusted, dict) or set(trusted) != {
            "witnessKey",
            "openHead",
            "invocationNonce",
        }:
            raise ProcessingFailure("witness policy fields differ")
        key = bytes.fromhex(trusted["witnessKey"])
        head = trusted["openHead"]
        nonce = trusted["invocationNonce"]
        if len(key) != 32 or not _hex(head, 64) or not _hex(nonce, 32):
            raise ProcessingFailure("witness policy fields differ")
        if not log.endswith(b"\n") or len(lines := log.splitlines()) != 2:
            raise ProcessingFailure("expected exactly two complete witness lines")
        first = _record(lines[0], key, 1, GENESIS)
        first_head = digest(canonical(first))
        second = _record(lines[1], key, 2, first_head)
        second_head = digest(canonical(second))
        if second_head != head:
            raise ProcessingFailure("witness head differs from the consumer pin")
        prior, opened = first["body"], second["body"]
        if set(prior) != {
            "sequence",
            "previous",
            "kind",
            "claimRef",
            "invocationNonce",
            "commitmentDigest",
        } or set(opened) != {
            "sequence",
            "previous",
            "kind",
            "claimRef",
            "invocationNonce",
            "priorHead",
        }:
            raise ProcessingFailure("witness body fields differ")
        if (
            prior["kind"] != "prior-commitment"
            or opened["kind"] != "invocation-open"
            or prior["claimRef"] != claim
            or opened["claimRef"] != claim
            or prior["invocationNonce"] != nonce
            or opened["invocationNonce"] != nonce
            or prior["commitmentDigest"] != commitment
            or opened["priorHead"] != first_head
        ):
            raise ProcessingFailure("witness does not bind the evaluated invocation")
    except (TypeError, KeyError, ValueError) as exc:
        raise ProcessingFailure(f"invalid witness policy or log: {exc}") from exc
    return second_head


def _under(path: str, scope: str) -> bool:
    return path == scope or path.startswith(scope.rstrip("/") + "/")


def _predicate(raw: bytes, observer_key: str) -> dict[str, Any]:
    if digest(raw) != RECORD_DIGEST:
        raise ProcessingFailure("the pinned Observed Effect record changed")
    report = observedeffect.verify(raw, observedeffect.Policy(PREDICATE_TYPE, observer_key))
    if report.verdict == "malformed":
        raise ProcessingFailure(f"malformed Observed Effect record: {report.codes}")
    if report.verdict != "valid":
        raise ProcessingFailure(f"Observed Effect record refused: {report.codes}")
    try:
        envelope = json.loads(raw, object_pairs_hook=_unique_pairs)
        statement = json.loads(
            base64.b64decode(envelope["payload"], validate=True), object_pairs_hook=_unique_pairs
        )
        return statement["predicate"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ProcessingFailure(f"cannot read verified predicate: {exc}") from exc


def _validate_policy(policy: dict[str, Any]) -> None:
    base = {"observerKey", "claimRef", "scope", "producerCapability"}
    if not isinstance(policy, dict) or set(policy) not in (
        base | {"claimedCommitmentDigest"},
        base | {"trustedWitness"},
    ):
        raise ProcessingFailure("property policy fields differ")
    if not _hex(policy["observerKey"], 64) or not isinstance(policy["claimRef"], str):
        raise ProcessingFailure("observer key or claim reference differs")
    if not policy["claimRef"] or not _path(policy["scope"]):
        raise ProcessingFailure("claim reference or scope differs")
    capability = policy["producerCapability"]
    if not isinstance(capability, dict) or set(capability) != {"claimRef", "visibleWritePaths"}:
        raise ProcessingFailure("producer capability fields differ")
    paths = capability["visibleWritePaths"]
    if not isinstance(capability["claimRef"], str) or not isinstance(paths, list):
        raise ProcessingFailure("producer capability values differ")
    if any(not _path(path) for path in paths):
        raise ProcessingFailure("producer capability path is not canonical")
    if "claimedCommitmentDigest" in policy and not _hex(policy["claimedCommitmentDigest"], 64):
        raise ProcessingFailure("claimed commitment digest differs")


def _validate_record_paths(predicate: dict[str, Any], observation: dict[str, Any]) -> None:
    if any(not _path(path) for path in predicate["pathScope"]):
        raise ProcessingFailure("record path scope is not canonical")
    if any(not _path(write["path"]) for write in predicate["writes"]):
        raise ProcessingFailure("record write path is not canonical")
    if any(not _path(gap) for gap in observation["coverage"]["gaps"]):
        raise ProcessingFailure("record coverage gap is not canonical")


def property_result(
    raw: bytes, policy: dict[str, Any], witness_log: bytes | None
) -> dict[str, Any]:
    """Decide one no-write property over the pinned read-only interval."""
    try:
        _validate_policy(policy)
        observer_key = policy["observerKey"]
        claim = policy["claimRef"]
        scope = policy["scope"]
        capability = policy["producerCapability"]
        predicate = _predicate(raw, observer_key)
        observation = predicate["observation"]
        _validate_record_paths(predicate, observation)
        if predicate["intervalId"] != claim:
            return {"verdict": "not_established", "unmet_obligation": "invocation_binding"}
        if not any(_under(scope, path) for path in predicate["pathScope"]):
            return {"verdict": "not_established", "unmet_obligation": "observation_coverage"}
        if observation["vantage"] != "below-observed":
            return {"verdict": "not_established", "unmet_obligation": "observation_vantage"}
        prior = observation["priorCommitment"]["commitmentDigest"]
        trusted = policy.get("trustedWitness")
        if trusted is None or witness_log is None:
            return {"verdict": "not_established", "unmet_obligation": "invocation_binding"}
        verify_witness(witness_log, trusted, claim, prior)
        writes = predicate["writes"]
        if any(_under(write["path"], scope) for write in writes):
            return {"verdict": "fail", "unmet_obligation": None}
        coverage = observation["coverage"]
        if not coverage["scopeComplete"] or coverage["gaps"]:
            return {"verdict": "not_established", "unmet_obligation": "observation_coverage"}
        if capability["claimRef"] != claim or not any(
            _under(scope, path) for path in capability["visibleWritePaths"]
        ):
            return {
                "verdict": "not_established",
                "unmet_obligation": "producer_capability_coverage",
            }
    except (KeyError, TypeError, ValueError) as exc:
        raise ProcessingFailure(f"invalid candidate input: {exc}") from exc
    return {"verdict": "pass", "unmet_obligation": None}


def action_outcome(action: dict[str, Any], claim_ref: str) -> str:
    """A reporting deadline alone cannot establish a terminal action result."""
    try:
        if set(action) != {
            "claimRef",
            "reported",
            "windowEnd",
            "checkedAt",
            "authenticatedTerminal",
        }:
            raise ProcessingFailure("action outcome fields differ")
        window_end = action["windowEnd"]
        checked_at = action["checkedAt"]
        if not isinstance(window_end, str) or not isinstance(checked_at, str):
            raise ProcessingFailure("action timestamps must be strings")
        end = datetime.fromisoformat(window_end.replace("Z", "+00:00"))
        checked = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
        if end.tzinfo is None or checked.tzinfo is None:
            raise ProcessingFailure("action timestamps require timezones")
        if action["claimRef"] != claim_ref:
            raise ProcessingFailure("the action outcome belongs to another invocation")
        if action["reported"] != "pending" or action.get("authenticatedTerminal") is not None:
            raise ProcessingFailure("this case has no authenticated terminal observation")
    except (KeyError, TypeError, ValueError) as exc:
        raise ProcessingFailure(f"invalid action outcome input: {exc}") from exc
    return "pending"


def evaluate(
    raw: bytes, policy: dict[str, Any], witness_log: bytes | None, action: dict[str, Any]
) -> dict[str, Any]:
    result = property_result(raw, policy, witness_log)
    predicate = _predicate(raw, policy["observerKey"])
    witness_head = (
        policy["trustedWitness"]["openHead"] if result["verdict"] in {"pass", "fail"} else None
    )
    return {
        "property": result,
        "actionOutcome": action_outcome(action, policy["claimRef"]),
        "binding": {
            "property": "no_write_in_scope",
            "claimRef": policy["claimRef"],
            "scope": policy["scope"],
            "recordIntervalId": predicate["intervalId"],
            "openedAt": predicate["interval"]["openedAt"],
            "sealedAt": predicate["interval"]["sealedAt"],
            "recordSha256": digest(raw),
            "witnessHead": witness_head,
        },
    }
