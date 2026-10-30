"""Ed25519 (RFC 8032, section 5.1) in pure Python, so the package keeps zero dependencies.

Verification handles only public data, so its timing reveals nothing. ``sign`` follows the RFC's
reference code and is not constant time: use it for test keys and for keys held by a job runner,
and sign with an audited tool (cosign, openssl) when the key must resist a local timing attacker.
A signature made elsewhere verifies here unchanged.
"""

from __future__ import annotations

import hashlib

_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)

Point = tuple[int, int, int, int]


def _inv(x: int) -> int:
    return pow(x, _P - 2, _P)


def _recover_x(y: int, sign: int) -> int | None:
    if y >= _P:
        return None
    x2 = (y * y - 1) * _inv(_D * y * y + 1) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _I % _P
    if (x * x - x2) % _P:
        return None
    return _P - x if (x & 1) != sign else x


_BY = 4 * _inv(5) % _P
_BX = _recover_x(_BY, 0)
if _BX is None:  # pragma: no cover - the base point is a constant of the curve
    raise RuntimeError("Ed25519 base point does not decode")
_B: Point = (_BX, _BY, 1, _BX * _BY % _P)
_ZERO: Point = (0, 1, 1, 0)


def _add(p: Point, q: Point) -> Point:
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(scalar: int, point: Point) -> Point:
    result = _ZERO
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(p: Point, q: Point) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _compress(p: Point) -> bytes:
    zi = _inv(p[2])
    x, y = p[0] * zi % _P, p[1] * zi % _P
    return int(y | ((x & 1) << 255)).to_bytes(32, "little")


def _decompress(data: bytes) -> Point | None:
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


def _hash(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little")


def _expand(seed: bytes) -> tuple[int, bytes]:
    if len(seed) != 32:
        raise ValueError("an Ed25519 seed is 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def public_key(seed: bytes) -> bytes:
    """The 32-byte public key for a 32-byte seed."""
    scalar, _ = _expand(seed)
    return _compress(_mul(scalar, _B))


def sign(seed: bytes, message: bytes) -> bytes:
    """The 64-byte signature of ``message`` under ``seed``. Not constant time; see the module note."""
    scalar, prefix = _expand(seed)
    public = _compress(_mul(scalar, _B))
    r = _hash(prefix + message) % _Q
    big_r = _compress(_mul(r, _B))
    k = _hash(big_r + public + message) % _Q
    s = (r + k * scalar) % _Q
    return big_r + s.to_bytes(32, "little")


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """True when ``signature`` is a valid Ed25519 signature of ``message`` under ``public``."""
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decompress(public)
    r = _decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _Q:
        return False
    k = _hash(signature[:32] + public + message) % _Q
    return _equal(_mul(s, _B), _add(r, _mul(k, a)))
