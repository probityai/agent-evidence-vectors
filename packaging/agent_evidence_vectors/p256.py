"""ECDSA over P-256 with SHA-256 (JWS ES256), in the standard library alone.

The rail is dependency-free, and a catalog signed under the AI Catalog did:web
Signer Profile is ES256, so the reader needs P-256 without `cryptography`.
Verification handles only public values, so a plain big-integer implementation
is safe for it. Signing is deterministic (RFC 6979 section 3.2) and exists for
the corpus generator: its keys are public test keys, never secrets.

The corpus test checks every signature here against `cryptography` in both
directions, and its second generator signs with `cryptography` alone.
"""

from __future__ import annotations

import hashlib
import hmac

P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
G = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
     0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)

Point = tuple[int, int] | None


def on_curve(point: Point) -> bool:
    """True when ``point`` is a finite point of P-256."""
    if point is None:
        return False
    x, y = point
    return 0 <= x < P and 0 <= y < P and (y * y - (x * x * x + A * x + B)) % P == 0


def _add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        slope = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def _mul(k: int, point: Point) -> Point:
    result: Point = None
    addend = point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def public_point(secret: int) -> tuple[int, int]:
    """The public point of a private scalar in [1, n-1]."""
    if not 0 < secret < N:
        raise ValueError("private scalar out of range")
    point = _mul(secret, G)
    assert point is not None
    return point


def _bits2int(data: bytes) -> int:
    return int.from_bytes(data[:32], "big")


def verify(public: tuple[int, int], message: bytes, signature: bytes) -> bool:
    """Verify a raw 64-byte JWS ES256 signature (r || s) over ``message``."""
    if len(signature) != 64 or not on_curve(public):
        return False
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    if not (0 < r < N and 0 < s < N):
        return False
    e = _bits2int(hashlib.sha256(message).digest())
    w = pow(s, -1, N)
    point = _add(_mul(e * w % N, G), _mul(r * w % N, public))
    return point is not None and point[0] % N == r


def _rfc6979_nonce(secret: int, digest: bytes) -> int:
    x = secret.to_bytes(32, "big")
    h1 = (_bits2int(digest) % N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = _bits2int(v)
        if 0 < candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign(secret: int, message: bytes) -> bytes:
    """Deterministic ES256 (RFC 6979) signature, raw r || s, low-s not enforced."""
    digest = hashlib.sha256(message).digest()
    e = _bits2int(digest)
    k = _rfc6979_nonce(secret, digest)
    point = _mul(k, G)
    assert point is not None
    r = point[0] % N
    s = pow(k, -1, N) * (e + r * secret) % N
    if r == 0 or s == 0:
        raise ValueError("degenerate signature")
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")
