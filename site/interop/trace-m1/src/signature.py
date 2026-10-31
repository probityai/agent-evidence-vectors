"""Verify the signed native-result bytes using caller-declared Ed25519 keys."""

import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from nacl.bindings import (
    crypto_core_ed25519_add,
    crypto_core_ed25519_is_valid_point,
    crypto_scalarmult_ed25519_noclamp,
)
from nacl.exceptions import CryptoError

from json_profile import Refusal, canonical, decode, digest, object_fields, parse, require

DOMAIN = "REMORA/FEDERATION-RESULT/v1"
ORDER = 2**252 + 27742317777372353535851937790883648493
IDENTITY = b"\x01" + b"\x00" * 31


def admissible_point(point):
    """Use libsodium's published main-subgroup check, including its older-build workaround."""
    require(type(point) is bytes and len(point) == 32, "invalid_ed25519_point")
    require(crypto_core_ed25519_is_valid_point(point), "inadmissible_ed25519_point")
    try:
        negated = crypto_scalarmult_ed25519_noclamp((ORDER - 1).to_bytes(32, "little"), point)
        product = crypto_core_ed25519_add(negated, point)
    except CryptoError as exc:
        raise Refusal("inadmissible_ed25519_point") from exc
    require(product == IDENTITY, "point_outside_prime_subgroup")


def trusted_public_keys(keys):
    require(type(keys) is list and len(keys) <= 1024, "invalid_key_population")
    result = {}
    for key in keys:
        require(type(key) is str and re.fullmatch(r"[0-9a-f]{64}", key), "invalid_public_key")
        raw = bytes.fromhex(key)
        admissible_point(raw)
        kid = "ed25519-" + digest(raw).removeprefix("sha256:")
        require(kid not in result, "duplicate_trust_key")
        result[kid] = raw
    return result


def verify_envelope(encoded, keys):
    raw = decode(encoded)
    outer = parse(raw)
    object_fields(outer, ("format", "result_b64", "signature"))
    require(outer["format"] == "remora-federation-result-evidence-v1", "envelope_format")
    signed = outer["signature"]
    object_fields(signed, ("algorithm", "domain", "kid", "signature"))
    require(signed["algorithm"] == "Ed25519", "signature_algorithm")
    require(signed["domain"] == DOMAIN, "signature_domain")
    public = trusted_public_keys(keys)
    require(type(signed["kid"]) is str and signed["kid"] in public, "untrusted_signer")
    payload = decode(outer["result_b64"])
    sig = decode(signed["signature"])
    require(len(sig) == 64, "signature_length")
    admissible_point(sig[:32])
    require(int.from_bytes(sig[32:], "little") < ORDER, "noncanonical_signature_scalar")
    try:
        Ed25519PublicKey.from_public_bytes(public[signed["kid"]]).verify(
            sig, DOMAIN.encode("ascii") + b"\0" + payload
        )
    except InvalidSignature as exc:
        raise Refusal("signature_mismatch") from exc
    document = parse(payload)
    require(canonical(document) == payload, "signed_payload_outside_canonical_profile")
    return document, digest(raw), signed["kid"]
