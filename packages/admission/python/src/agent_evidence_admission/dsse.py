"""DSSE envelopes (https://github.com/secure-systems-lab/dsse) signed with Ed25519.

An envelope is ``{payloadType, payload, signatures: [{keyid, sig}]}``. The signature covers the
pre-authentication encoding of the payload type and the payload bytes, so a signature made for
one payload type cannot be replayed under another. ``keyid`` is the lowercase hex SHA-256 of the
raw public key, the same value the change admission rules pin.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass

from . import ed25519

STATEMENT_TYPE = "application/vnd.in-toto+json"


class EnvelopeError(ValueError):
    """The envelope is malformed or no trusted signature verifies."""


def keyid(public: bytes) -> str:
    """The pinned identifier of a raw Ed25519 public key."""
    return hashlib.sha256(public).hexdigest()


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE pre-authentication encoding."""
    kind = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


def make_envelope(payload: bytes, seed: bytes, payload_type: str = STATEMENT_TYPE) -> dict:
    """Sign ``payload`` and return the envelope."""
    signature = ed25519.sign(seed, pae(payload_type, payload))
    return {
        "payloadType": payload_type,
        "payload": base64.b64encode(payload).decode("ascii"),
        "signatures": [{"keyid": keyid(ed25519.public_key(seed)), "sig": base64.b64encode(signature).decode("ascii")}],
    }


@dataclass(frozen=True)
class Opened:
    """A verified envelope: the payload bytes and the keyid whose signature held."""

    payload: bytes
    keyid: str


def _b64(text: object, what: str) -> bytes:
    if not isinstance(text, str):
        raise EnvelopeError(f"{what} is not a string")
    try:
        data = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as error:
        raise EnvelopeError(f"{what} is not base64") from error
    if base64.b64encode(data).decode("ascii") != text:
        raise EnvelopeError(f"{what} is not canonical base64")
    return data


def open_envelope(envelope: object, trusted: dict[str, bytes], payload_type: str = STATEMENT_TYPE) -> Opened:
    """Return the payload when a signature by a trusted key verifies; raise ``EnvelopeError`` (a ``ValueError``) otherwise.

    ``trusted`` maps keyid to raw public key. A key is looked up by its keyid and then checked
    against that keyid, so a mapping with a wrong entry cannot vouch for a stranger.
    """
    if not isinstance(envelope, dict):
        raise EnvelopeError("envelope is not an object")
    if envelope.get("payloadType") != payload_type:
        raise EnvelopeError(f"payloadType is not {payload_type}")
    payload = _b64(envelope.get("payload"), "payload")
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise EnvelopeError("envelope carries no signature")
    message = pae(payload_type, payload)
    for entry in signatures:
        if not isinstance(entry, dict):
            continue
        key_id = entry.get("keyid")
        public = trusted.get(key_id) if isinstance(key_id, str) else None
        if public is None or keyid(public) != key_id:
            continue
        try:
            signature = _b64(entry.get("sig"), "sig")
        except ValueError:
            continue
        if ed25519.verify(public, message, signature):
            return Opened(payload, key_id)
    raise EnvelopeError("no signature verified under a trusted key")
