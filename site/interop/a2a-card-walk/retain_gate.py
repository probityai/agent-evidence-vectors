"""Bounded ES256 consumer gate for the frozen A2A S3 unknown-field corpus.

This provisional policy preserves every served field except top-level signatures.
It does not implement the unresolved rule-1 default-value semantics, discovery,
trust establishment, network key retrieval, or the complete A2A specification.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, NoReturn

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

LOGGER = logging.getLogger(__name__)
POLICY = "probity-a2a-s3-retain-v0-provisional"


class PolicyError(ValueError):
    """A supplied object falls outside the bounded consumer policy."""


def refuse(message: str) -> NoReturn:
    """Log a stable rejection reason and raise :class:`PolicyError`."""
    LOGGER.warning(message)
    raise PolicyError(message)


def decode_base64url(value: str) -> bytes:
    """Decode a canonical unpadded JOSE base64url string.

    Parameters
    ----------
    value : str
        URL-safe, unpadded encoded data; padding and noncanonical pad bits fail.

    Returns
    -------
    bytes
        Decoded bytes suitable for key coordinates or JOSE signature fields.

    Raises
    ------
    PolicyError
        If the input is not a canonical unpadded base64url string.
    """
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        refuse("invalid base64url encoding")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error):
        refuse("invalid base64url encoding")
    if encode_base64url(decoded) != value:
        refuse("invalid base64url encoding")
    return decoded


def encode_base64url(value: bytes) -> str:
    """Return canonical unpadded JOSE base64url text for ``value``."""
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build a JSON object while refusing duplicate member names at any depth."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            refuse("duplicate JSON member")
        result[key] = value
    return result


def load_json(raw: bytes) -> dict[str, Any]:
    """Parse a JSON object without silently collapsing duplicate member names.

    Numeric values are subsequently checked by RFC 8785 in :func:`canonicalize`.
    Unicode decoding and JSON syntax failures become a stable policy error.
    """
    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
    except (json.JSONDecodeError, UnicodeDecodeError):
        refuse("invalid JSON encoding")
    if not isinstance(value, dict):
        refuse("JSON root must be an object")
    return value


def canonicalize(card: dict[str, Any]) -> bytes:
    """Compute RFC 8785 bytes from the served object with signatures removed.

    This function retains unknown fields at every depth and does not mutate its
    argument. It deliberately has no alternative-form or default-pruning path.
    It is a policy candidate for the frozen S3 scope, not an A2A canonicalizer.
    """
    unsigned = {key: value for key, value in card.items() if key != "signatures"}
    try:
        return rfc8785.dumps(unsigned)
    except (rfc8785.CanonicalizationError, TypeError):
        refuse("card is outside the RFC 8785 input domain")


def public_key(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    """Load an explicitly supplied ES256 test public key without network access.

    No trust is inferred from the embedded key or protected ``jku``. The caller
    owns selection of the immutable test key; production key authorization is
    outside this regression's scope.
    """
    if (jwk.get("kty"), jwk.get("crv"), jwk.get("alg")) != ("EC", "P-256", "ES256"):
        refuse("unsupported test key")
    coordinates = [decode_base64url(jwk.get(axis, "")) for axis in ("x", "y")]
    if any(len(coordinate) != 32 for coordinate in coordinates):
        refuse("invalid P-256 coordinate length")
    try:
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(coordinates[0], "big"),
            int.from_bytes(coordinates[1], "big"),
            ec.SECP256R1(),
        ).public_key()
    except ValueError:
        refuse("invalid P-256 public point")


def verify_signature(signature: dict[str, Any], payload: bytes, jwk: dict[str, Any]) -> bool:
    """Verify one ES256 JOSE signature against exactly the supplied payload.

    The protected header must select the pinned key and standard base64 payload
    encoding. Unsupported critical extensions fail closed. A validly shaped
    but incorrect cryptographic signature returns False.
    """
    header = load_json(decode_base64url(signature.get("protected", "")))
    if (header.get("alg"), header.get("kid")) != ("ES256", jwk.get("kid")):
        refuse("signature algorithm or key id does not match pinned key")
    if "crit" in header or "b64" in header:
        refuse("unsupported JOSE header extension")
    raw = decode_base64url(signature.get("signature", ""))
    if len(raw) != 64:
        refuse("ES256 signature must contain 64 bytes")
    der = utils.encode_dss_signature(
        int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    )
    message = (signature["protected"] + "." + encode_base64url(payload)).encode("ascii")
    try:
        public_key(jwk).verify(der, message, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


@dataclass(frozen=True)
class AdmissionResult:
    """A bounded signature decision, distinct from identity or workload trust."""

    admitted: bool
    signature_results: tuple[bool, ...]
    policy: str = POLICY


def admit(card: dict[str, Any], jwk: dict[str, Any]) -> AdmissionResult:
    """Evaluate all signatures using one retained-field payload only.

    Parameters
    ----------
    card : dict[str, Any]
        Served JSON object parsed with :func:`load_json`. For the recorded
        corpus run, this is the original ``served_card`` fixture member.
    jwk : dict[str, Any]
        The caller-pinned ES256 test key, never retrieved from ``jku``.

    Returns
    -------
    AdmissionResult
        Each signature's result and admission if at least one verifies on the
        single policy-selected payload. Dual signing is permitted; alternate
        canonicalization fallback is structurally absent.

    Raises
    ------
    PolicyError
        On missing signatures, malformed JOSE objects, or unsupported input.
        A malformed member fails the entire bounded gate, even if another is
        valid; this is a conservative local policy, not normative A2A behavior.
    """
    signatures = card.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        refuse("card must contain a nonempty signatures array")
    if not all(isinstance(signature, dict) for signature in signatures):
        refuse("each signature must be an object")
    payload = canonicalize(card)
    results = tuple(verify_signature(signature, payload, jwk) for signature in signatures)
    return AdmissionResult(any(results), results)
