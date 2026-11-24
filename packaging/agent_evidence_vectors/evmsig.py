"""EVM signatures with the standard library only: Keccak-256, secp256k1 and EIP-712.

The reference rail is stdlib-only, and an x402 payment on EVM is an EIP-712 signature
over an EIP-3009 ``TransferWithAuthorization`` message, so the reader needs three
primitives that ``hashlib`` does not carry:

- Keccak-256 as Ethereum uses it (the original Keccak padding, not FIPS 202 SHA3-256);
- secp256k1 public-key recovery from a 65-byte ``r || s || v`` signature;
- the EIP-712 typed-data digest for the structs a record names.

Signing with RFC 6979 deterministic nonces is here too, for the corpus generators;
the readers only recover. This is a reference implementation for conformance cases:
it is not constant-time and must never hold a key that matters.
"""

from __future__ import annotations

import hashlib
import hmac
import re

# --- Keccak-256 -------------------------------------------------------------------

_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)  # fmt: skip
_ROT = (
    (0, 36, 3, 41, 18), (1, 44, 10, 45, 2), (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56), (27, 20, 39, 8, 14),
)  # fmt: skip
_MASK = (1 << 64) - 1


def _rol(value: int, shift: int) -> int:
    return ((value << shift) | (value >> (64 - shift))) & _MASK if shift else value


def _keccak_f(state: list[list[int]]) -> None:
    for rc in _RC:
        c = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x][y] ^= d[x]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rol(state[x][y], _ROT[x][y])
        for x in range(5):
            for y in range(5):
                state[x][y] = b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y])
        state[0][0] ^= rc


def keccak256(data: bytes) -> bytes:
    """Keccak-256 with the 0x01 domain byte Ethereum uses."""
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate:
        padded.append(0)
    padded[-1] |= 0x80
    state = [[0] * 5 for _ in range(5)]
    for offset in range(0, len(padded), rate):
        block = padded[offset : offset + rate]
        for i in range(rate // 8):
            x, y = i % 5, i // 5
            state[x][y] ^= int.from_bytes(block[8 * i : 8 * i + 8], "little")
        _keccak_f(state)
    out = b"".join(state[i % 5][i // 5].to_bytes(8, "little") for i in range(4))
    return out


# --- secp256k1 --------------------------------------------------------------------

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
HALF_N = N // 2
Point = tuple[int, int] | None


def _add(a: Point, b: Point) -> Point:
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def _mul(k: int, point: Point) -> Point:
    result: Point = None
    addend = point
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def address_of_point(point: tuple[int, int]) -> str:
    """The checksummed EVM address of a public key."""
    raw = point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")
    return checksum(keccak256(raw)[12:].hex())


def address_of_key(private_key: int) -> str:
    point = _mul(private_key, G)
    assert point is not None
    return address_of_point(point)


def checksum(address: str) -> str:
    """EIP-55 mixed-case form of a 20-byte hex address."""
    plain = address.lower().removeprefix("0x")
    digest = keccak256(plain.encode("ascii")).hex()
    return "0x" + "".join(c.upper() if int(digest[i], 16) >= 8 else c for i, c in enumerate(plain))


def _rfc6979_k(private_key: int, digest: bytes) -> int:
    x = private_key.to_bytes(32, "big")
    h = (int.from_bytes(digest, "big") % N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign(private_key: int, digest: bytes) -> bytes:
    """A 65-byte ``r || s || v`` signature with low s and v in {27, 28} (RFC 6979 nonce)."""
    k = _rfc6979_k(private_key, digest)
    point = _mul(k, G)
    assert point is not None
    r = point[0] % N
    s = pow(k, -1, N) * (int.from_bytes(digest, "big") + r * private_key) % N
    recid = point[1] & 1
    if s > HALF_N:
        s, recid = N - s, recid ^ 1
    return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([27 + recid])


def split(signature: bytes) -> tuple[int, int, int] | None:
    """``(r, s, recid)`` of a 65-byte signature, or None when it is not one."""
    if len(signature) != 65 or signature[64] not in (27, 28):
        return None
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:64], "big")
    if not (1 <= r < N and 1 <= s < N):
        return None
    return r, s, signature[64] - 27


def is_low_s(signature: bytes) -> bool:
    """EIP-2: a signature whose s is above n/2 is the second encoding of another one."""
    parts = split(signature)
    return parts is not None and parts[1] <= HALF_N


def recover(digest: bytes, signature: bytes) -> str | None:
    """The checksummed address whose key made the signature, or None when none can."""
    parts = split(signature)
    if parts is None:
        return None
    r, s, recid = parts
    x = r
    alpha = (pow(x, 3, P) + 7) % P
    beta = pow(alpha, (P + 1) // 4, P)
    if beta * beta % P != alpha:
        return None
    y = beta if beta % 2 == recid else P - beta
    e = int.from_bytes(digest, "big") % N
    r_inv = pow(r, -1, N)
    q = _mul(r_inv, _add(_mul(s, (x, y)), _mul((-e) % N, G)))
    if q is None:
        return None
    return address_of_point(q)


# --- EIP-712 ----------------------------------------------------------------------

Types = dict[str, list[tuple[str, str]]]

EIP712_DOMAIN: list[tuple[str, str]] = [
    ("name", "string"),
    ("version", "string"),
    ("chainId", "uint256"),
    ("verifyingContract", "address"),
]
TRANSFER_WITH_AUTHORIZATION: list[tuple[str, str]] = [
    ("from", "address"),
    ("to", "address"),
    ("value", "uint256"),
    ("validAfter", "uint256"),
    ("validBefore", "uint256"),
    ("nonce", "bytes32"),
]
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
_BYTES32 = re.compile(r"^0x[0-9a-fA-F]{64}$")
_UINT = re.compile(r"^(0|[1-9][0-9]*)$")


def _deps(name: str, types: Types, found: set[str]) -> set[str]:
    if name in found or name not in types:
        return found
    found.add(name)
    for _, kind in types[name]:
        _deps(kind, types, found)
    return found


def encode_type(name: str, types: Types) -> str:
    rest = sorted(_deps(name, types, set()) - {name})
    return "".join(
        f"{n}({','.join(f'{kind} {field}' for field, kind in types[n])})" for n in [name, *rest]
    )


def _uint(value: object) -> int:
    text = str(value) if isinstance(value, int) and not isinstance(value, bool) else value
    if not isinstance(text, str) or not _UINT.match(text) or int(text) >= 1 << 256:
        raise ValueError(f"not a uint256: {value!r}")
    return int(text)


def _encode_value(kind: str, value: object, types: Types) -> bytes:
    if kind in types:
        if not isinstance(value, dict):
            raise ValueError(f"{kind} is not an object")
        return hash_struct(kind, value, types)
    if kind == "string":
        if not isinstance(value, str):
            raise ValueError("string member is not a string")
        return keccak256(value.encode("utf-8"))
    if kind == "address":
        if not isinstance(value, str) or not _ADDRESS.match(value):
            raise ValueError(f"not an address: {value!r}")
        return bytes(12) + bytes.fromhex(value[2:])
    if kind == "uint256":
        return _uint(value).to_bytes(32, "big")
    if kind == "bytes32":
        if not isinstance(value, str) or not _BYTES32.match(value):
            raise ValueError(f"not a bytes32: {value!r}")
        return bytes.fromhex(value[2:])
    raise ValueError(f"unsupported EIP-712 type {kind}")


def hash_struct(name: str, value: dict[str, object], types: Types) -> bytes:
    """``keccak256(typeHash || encodeData(value))``; a missing member is an error."""
    encoded = keccak256(encode_type(name, types).encode("ascii"))
    for field, kind in types[name]:
        if field not in value:
            raise ValueError(f"{name}.{field} is missing")
        encoded += _encode_value(kind, value[field], types)
    return keccak256(encoded)


def typed_data_digest(
    domain: dict[str, object], primary: str, message: dict[str, object], types: Types
) -> bytes:
    """The digest an EIP-712 signature is taken over."""
    all_types = {"EIP712Domain": EIP712_DOMAIN, **types}
    return keccak256(
        b"\x19\x01"
        + hash_struct("EIP712Domain", domain, all_types)
        + hash_struct(primary, message, all_types)
    )


def chain_id(network: object) -> int | None:
    """The EVM chain id of a CAIP-2 ``eip155:<id>`` network, or None for any other."""
    if not isinstance(network, str):
        return None
    match = re.fullmatch(r"eip155:([1-9][0-9]{0,18})", network)
    return int(match.group(1)) if match else None


def eip3009_digest(
    authorization: dict[str, object], network: object, asset: object, name: object, version: object
) -> bytes:
    """The digest of an EIP-3009 TransferWithAuthorization under the token's domain.

    Raises ValueError when the network is not an EVM chain or a member does not parse.
    """
    chain = chain_id(network)
    if chain is None:
        raise ValueError(f"not an eip155 network: {network!r}")
    domain = {"name": name, "version": version, "chainId": chain, "verifyingContract": asset}
    return typed_data_digest(
        domain,
        "TransferWithAuthorization",
        authorization,
        {"TransferWithAuthorization": TRANSFER_WITH_AUTHORIZATION},
    )
