"""Build signed CBOR receipt streams for tests and the example, from two neutral format profiles.

Test keys are derived from fixed seeds and carry no trust. The encoder writes the definite-length
subset the reader accepts.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

NEUTRAL = {
    "schema_version": "cbor-receipt-profile/v1", "profile_id": "neutral-cbor-receipt/1",
    "line_member": None, "signature_context_hex": b"receipt-chain-neutral-v1".hex(),
    "outer": {"version": "v", "payload": "p", "signer_key": "k", "signature": "s"},
    "key_form": "raw", "allow_outcome": "allow",
    "fields": {"version": 0, "prev_hash": 1, "outcome": 2, "request_hash": 3, "proof": 4,
               "revocation_hash": 5},
}
WRAPPED = {
    "schema_version": "cbor-receipt-profile/v1", "profile_id": "neutral-wrapped-receipt/1",
    "line_member": "receipt", "signature_context_hex": "00ff7a",
    "outer": {"version": "receipt_version", "payload": "payload", "signer_key": "signer_key",
              "signature": "signature"},
    "key_form": "pair", "allow_outcome": "permit",
    "fields": {"version": 7, "prev_hash": 11, "outcome": 3, "request_hash": 4, "proof": 5,
               "effect": 9},
}


def seed_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"test-key|" + label.encode()).digest())


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | info]) + n.to_bytes(size, "big")
    raise ValueError("integer too large")


def encode(value: Any) -> bytes:
    if value is None:
        return b"\xf6"
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return _head(3, len(raw)) + raw
    if isinstance(value, list):
        return _head(4, len(value)) + b"".join(encode(v) for v in value)
    return _head(5, len(value)) + b"".join(encode(k) + encode(v) for k, v in value.items())


def receipt(profile: dict, key: Ed25519PrivateKey, prev: bytes | None, *, outcome: str | None = None,
            request: str = "r0", proof: bytes | None = None, extra: dict | None = None,
            version: int = 1) -> bytes:
    """One signed receipt as raw bytes."""
    f = profile["fields"]
    body: dict[int, Any] = {f["version"]: version, f["prev_hash"]: prev}
    outcome = outcome or profile["allow_outcome"]
    if "outcome" in f:
        body[f["outcome"]] = outcome
    if "request_hash" in f:
        body[f["request_hash"]] = hashlib.sha256(request.encode()).digest()
    if "proof" in f:
        body[f["proof"]] = proof if proof is not None else hashlib.sha256(b"proof|" + request.encode()).digest()
    if "revocation_hash" in f:
        body[f["revocation_hash"]] = hashlib.sha256(b"srl").digest()
    for role, value in (extra or {}).items():
        body[f[role]] = value
    payload = encode(body)
    signature = key.sign(bytes.fromhex(profile["signature_context_hex"]) + bytes([version]) + payload)
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    wrap = (lambda b: [1, b]) if profile["key_form"] == "pair" else (lambda b: b)
    names = profile["outer"]
    return encode({names["version"]: version, names["payload"]: payload,
                   names["signer_key"]: wrap(pub), names["signature"]: wrap(signature)})


def chain(profile: dict, key: Ed25519PrivateKey, count: int, first_prev: bytes | None = None,
          **kw: Any) -> list[bytes]:
    """``count`` receipts, each linked to the SHA-256 of the one before it."""
    out: list[bytes] = []
    prev = first_prev
    for i in range(count):
        out.append(receipt(profile, key, prev, request=f"r{i}", **kw))
        prev = hashlib.sha256(out[-1]).digest()
    return out


def stream(profile: dict, receipts: list[bytes]) -> bytes:
    """The JSONL (or hex-per-line) file for a receipt list."""
    member = profile["line_member"]
    lines = [json.dumps({member: r.hex()}) if member else r.hex() for r in receipts]
    return ("\n".join(lines) + "\n").encode()


def head(receipts: list[bytes]) -> dict:
    return {"head": hashlib.sha256(receipts[-1]).hexdigest(), "count": len(receipts)}
