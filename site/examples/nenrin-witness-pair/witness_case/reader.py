"""Check signed witness bytes and their exact target without a producer reader."""

import argparse
import base64
import binascii
import json
from pathlib import Path

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .io import MAX_BYTES, Refusal, digest, file_bytes, operator, parse, pin, text

PURPOSE_PREFIX = "a2a-conduct-walk-v1: "


def _object(value, name: str) -> dict:
    if not isinstance(value, dict):
        raise Refusal("RECORD_SHAPE_INVALID", name + " must be an object")
    return value


def _b64(value, size: int, name: str) -> bytes:
    if not isinstance(value, str):
        raise Refusal("CRYPTO_ENCODING_INVALID", name + " must be canonical base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as error:
        raise Refusal("CRYPTO_ENCODING_INVALID", name + " has invalid base64") from error
    if len(raw) != size or base64.b64encode(raw).decode("ascii") != value:
        raise Refusal("CRYPTO_ENCODING_INVALID", name + " has a wrong length or encoding")
    return raw


def canonical_bytes(record: dict) -> bytes:
    """Check the retained pair's documented sorted-key/minified JSON profile."""

    def supported(value):
        if isinstance(value, dict):
            if any(not key.isascii() for key in value):
                raise Refusal("CANONICAL_VALUE_UNSUPPORTED", "this finite profile uses ASCII keys")
            for item in value.values():
                supported(item)
        elif isinstance(value, list):
            for item in value:
                supported(item)
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeError as error:
                raise Refusal("CANONICAL_VALUE_UNSUPPORTED", "invalid UTF-8 string") from error
        elif value is not None and type(value) not in {int, bool}:
            raise Refusal(
                "CANONICAL_VALUE_UNSUPPORTED", "this finite profile has no floating numbers"
            )

    try:
        supported(record)
        return json.dumps(
            record, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    except RecursionError as error:
        raise Refusal(
            "CANONICAL_VALUE_UNSUPPORTED", "record nesting exceeds this profile"
        ) from error


def assertion_projection(record: dict) -> dict:
    assertions = record.get("assertions")
    if not isinstance(assertions, list) or len(assertions) != 8:
        raise Refusal("ASSERTIONS_INVALID", "the retained full-walk profile has eight assertions")
    rows = []
    counts = {"true": 0, "false": 0, "null": 0}
    for index, item in enumerate(assertions):
        assertion = _object(item, "assertion")
        result = assertion.get("result", "missing")
        if result is not None and type(result) is not bool:
            raise Refusal("ASSERTIONS_INVALID", "assertion result must be true, false or null")
        claim = text(assertion.get("claim"), "assertion claim")
        key = "null" if result is None else "true" if result else "false"
        counts[key] += 1
        rows.append({"index": index, "claim": claim, "result": result})
    verdict = _object(record.get("verdict"), "verdict")
    evaluated = counts["true"] + counts["false"]
    expected = {
        "n_pass": counts["true"],
        "n_total": evaluated,
        "ok": counts["false"] == 0,
    }
    if any(type(verdict.get(k)) is not type(v) or verdict[k] != v for k, v in expected.items()):
        raise Refusal("VERDICT_COUNTS_DISAGREE", "declared verdict does not match signed results")
    label = text(verdict.get("outcome"), "declared verdict outcome")
    if label == "PASS" and counts["false"]:
        raise Refusal("VERDICT_COUNTS_DISAGREE", "PASS label contradicts a false signed assertion")
    return {
        "total_assertions": 8,
        "reported_true": counts["true"],
        "reported_false": counts["false"],
        "unevaluated": counts["null"],
        "evaluated": evaluated,
        "all_eight_reported_true": counts["true"] == 8,
        "producer_verdict": verdict,
        "rows": rows,
    }


def read(
    envelope_raw: bytes,
    key_raw: bytes,
    *,
    record_sha256: str,
    key_document_sha256: str,
    key_url: str,
    target: str,
    operator_identity: str,
) -> dict:
    """Keep byte authenticity, signed target and reported assertions separate."""
    identity = operator(operator_identity)
    expected_record = pin(record_sha256, "record pin")
    expected_key = pin(key_document_sha256, "key document pin")
    target, key_url = text(target, "target"), text(key_url, "pinned key URL")
    if not isinstance(key_raw, bytes) or len(key_raw) > MAX_BYTES:
        raise Refusal("INPUT_TOO_LARGE", "local key input must be bounded bytes")
    if digest(key_raw) != expected_key:
        raise Refusal("KEY_DOCUMENT_PIN_MISMATCH", "local key document differs from its pin")
    key_doc = parse(key_raw, "key document")
    key = _b64(key_doc.get("public_key_ed25519_b64"), 32, "local Ed25519 key")
    envelope = parse(envelope_raw, "witness API envelope")
    wrapper = _object(envelope.get("record"), "API record")
    canonical = wrapper.get("record_canonical")
    if not isinstance(canonical, str):
        raise Refusal("RECORD_BYTES_INVALID", "record_canonical must be literal UTF-8 text")
    try:
        raw = canonical.encode("utf-8")
    except UnicodeError as error:
        raise Refusal("RECORD_BYTES_INVALID", "record_canonical is not UTF-8") from error
    actual_sha = digest(raw)
    if actual_sha != expected_record:
        raise Refusal("RECORD_PIN_MISMATCH", "exact record bytes differ from their pin")
    if envelope.get("sha") != actual_sha or wrapper.get("sha") != actual_sha:
        raise Refusal("ENVELOPE_SHA_DISAGREES", "API digest fields disagree with the signed bytes")
    record = parse(raw, "signed record")
    if canonical_bytes(record) != raw:
        raise Refusal(
            "RECORD_NOT_CANONICAL", "signed bytes differ from the documented canonical form"
        )
    if record.get("schema") != "jidec-path-v1" or record.get("mode") != "full":
        raise Refusal(
            "RECORD_PROFILE_UNSUPPORTED", "reader requires the retained full-walk profile"
        )
    witness = _object(record.get("witness"), "witness")
    if witness.get("key_url") != key_url or wrapper.get("key_url") != key_url:
        raise Refusal("KEY_URL_DISAGREES", "key location differs from the separately pinned input")
    if wrapper.get("signed") is not True:
        raise Refusal("SIGNATURE_NOT_DECLARED", "API record does not declare a signed record")
    declared_key = _b64(wrapper.get("public_key_ed25519_b64"), 32, "declared Ed25519 key")
    if declared_key != key:
        raise Refusal(
            "DECLARED_KEY_DISAGREES", "record's supplied key differs from the local pinned key"
        )
    signature = _b64(wrapper.get("signature_ed25519_b64"), 64, "Ed25519 signature")
    try:
        Ed25519PublicKey.from_public_bytes(key).verify(signature, raw)
    except InvalidSignature as error:
        raise Refusal(
            "SIGNATURE_INVALID", "signature does not verify under the pinned key"
        ) from error
    except UnsupportedAlgorithm as error:
        raise Refusal("CRYPTO_UNAVAILABLE", "runtime does not support Ed25519") from error
    purpose = text(record.get("purpose"), "signed purpose")
    if not purpose.startswith(PURPOSE_PREFIX):
        raise Refusal("PURPOSE_UNSUPPORTED", "signed purpose has a different native grammar")
    purpose_url = text(purpose[len(PURPOSE_PREFIX) :], "signed purpose URL")
    ext = _object(record.get("conduct_ext"), "conduct extension")
    nodes = record.get("nodes")
    if not isinstance(nodes, list) or len(nodes) != 4:
        raise Refusal("NODES_INVALID", "retained full-walk profile requires four nodes")
    if any(not isinstance(n, dict) or type(n.get("n")) is not int for n in nodes):
        raise Refusal("NODES_INVALID", "node indices must be explicit integers")
    if [n["n"] for n in nodes] != [0, 1, 2, 3]:
        raise Refusal("NODES_INVALID", "node indices are missing, duplicated or reordered")
    request = _object(nodes[3].get("request"), "measured request")
    if ext.get("target") != purpose_url or request.get("url") != purpose_url:
        raise Refusal("SIGNED_TARGET_DISAGREES", "signed purpose and request target disagree")
    if nodes[3].get("kind") != "fetch" or request.get("method") != "POST":
        raise Refusal("NODES_INVALID", "measured node must declare the native POST request")
    assertions = assertion_projection(record)
    card = _object(record.get("card_signature"), "card signature observation")
    card_result = card.get("verified", "missing")
    if card_result is not None and type(card_result) is not bool:
        raise Refusal(
            "CARD_OBSERVATION_INVALID", "declared card verification must be boolean or null"
        )
    matches = purpose_url == target
    outcome = (
        "TARGET_MISMATCH"
        if not matches
        else "REPORTED_ASSERTION_FAILURE"
        if assertions["reported_false"]
        else "NO_EVALUATED_ASSERTIONS"
        if not assertions["evaluated"]
        else "MATCHING_SIGNED_OBSERVATION"
    )
    return {
        "profile": "probity.nenrin-witness-byte-reader/v1",
        "operator": identity,
        "reader_maintainer": "Probity",
        "record_sha256": actual_sha,
        "canonical_bytes": len(raw),
        "record_pin_matches": True,
        "signature_verified_under_pinned_key": True,
        "key_document_sha256": expected_key,
        "key_url": key_url,
        "target": target,
        "signed_purpose_url": purpose_url,
        "target_matches": matches,
        "outcome": outcome,
        "assertions": assertions,
        "witness_name": text(witness.get("name"), "witness name"),
        "witness_declared_vantage": text(witness.get("vantage"), "witness vantage"),
        "vantage_limitation": record.get("vantage_limitation"),
        "walked_at_declared": text(record.get("walked_at"), "declared walk time"),
        "card_signature_verified_declared": card_result,
        "reader_card_signature_verification": False,
        "scope": {
            "claims_recomputed_from_network_responses": False,
            "response_correctness_established": False,
            "historical_key_control_established": False,
            "domain_possession_established": False,
            "affiliation_independence_established": False,
            "opentimestamps_proof_checked": False,
            "new_network_walk_performed": False,
            "dispatch_outside_the_signed_record_observed": False,
        },
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("envelope", type=Path)
    parser.add_argument("key", type=Path)
    for name in ("record-sha256", "key-document-sha256", "key-url", "target", "operator"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(argv)
    try:
        result = read(
            file_bytes(args.envelope),
            file_bytes(args.key),
            record_sha256=args.record_sha256,
            key_document_sha256=args.key_document_sha256,
            key_url=args.key_url,
            target=args.target,
            operator_identity=args.operator,
        )
    except Refusal as error:
        print(json.dumps({"outcome": "REFUSED", "reason": error.code, "detail": str(error)}))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["outcome"] == "MATCHING_SIGNED_OBSERVATION" else 1


if __name__ == "__main__":
    raise SystemExit(main())
