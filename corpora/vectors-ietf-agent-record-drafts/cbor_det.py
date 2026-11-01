"""The CBOR subset these three drafts use, in a module that imports only the standard library.

One encoder and one decoder with three map policies, so the generator and the
checker read CBOR the same way and the duplicate-key members can be built and
read without a third-party CBOR library standing between the bytes and the
verdict:

  - `encode` writes the core deterministic encoding of RFC 8949 Section 4.2.1:
    shortest-form heads, definite lengths, map keys sorted by the bytewise order
    of their encodings.
  - `decode(..., policy="strict")` refuses anything that encoding would not have
    written: a non-shortest head, an indefinite length, unsorted or repeated map
    keys, trailing bytes. It raises `NotDeterministic`.
  - `decode(..., policy="last")` and `policy="first"` read any well-formed item
    and resolve a repeated map key by keeping the last or the first value. These
    are the two behaviours common decoders show, and the duplicate-key members
    exist to tell them apart.

The subset is unsigned and negative integers, byte strings, text strings,
arrays, maps and tags. Nothing in the three drafts' structures needs more.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class NotDeterministic(ValueError):
    """The bytes are well formed but not the core deterministic encoding."""


class Malformed(ValueError):
    """The bytes are not a well-formed item of the supported subset."""


@dataclass(frozen=True)
class Tag:
    number: int
    value: Any


def head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([(major << 5) | n])
    for ai, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([(major << 5) | ai]) + n.to_bytes(width, "big")
    raise ValueError(f"{n} does not fit a CBOR head")


def encode(value: Any) -> bytes:
    if isinstance(value, bool) or value is None or isinstance(value, float):
        raise TypeError("not in the subset these drafts use")
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return head(4, len(value)) + b"".join(encode(item) for item in value)
    if isinstance(value, dict):
        items = sorted((encode(k), encode(v)) for k, v in value.items())
        return head(5, len(items)) + b"".join(k + v for k, v in items)
    if isinstance(value, Tag):
        return head(6, value.number) + encode(value.value)
    raise TypeError(type(value).__name__)


def encode_pairs(pairs: list[tuple[Any, Any]]) -> bytes:
    """A map written from explicit pairs in the order given, repeats allowed.

    Used only to build members whose point is a map the deterministic encoding
    would never write.
    """
    return head(5, len(pairs)) + b"".join(encode(k) + encode(v) for k, v in pairs)


def decode(data: bytes, policy: str = "strict") -> Any:
    if policy not in ("strict", "last", "first"):
        raise ValueError(policy)
    value, end = _item(data, 0, policy)
    if end != len(data):
        if policy == "strict":
            raise NotDeterministic("trailing bytes")
        raise Malformed("trailing bytes")
    return value


def _length(data: bytes, i: int, policy: str) -> tuple[int, int, int, int]:
    if i >= len(data):
        raise Malformed("truncated")
    initial = data[i]
    major, ai = initial >> 5, initial & 0x1F
    i += 1
    if ai < 24:
        return major, ai, i, ai
    if ai > 27:
        raise Malformed("indefinite length or reserved additional information")
    width = 1 << (ai - 24)
    if i + width > len(data):
        raise Malformed("truncated")
    n = int.from_bytes(data[i : i + width], "big")
    if policy == "strict" and head(major, n) != data[i - 1 : i + width]:
        raise NotDeterministic("a head that is not in shortest form")
    return major, n, i + width, ai


def _string(data: bytes, i: int, n: int, major: int) -> tuple[Any, int]:
    if i + n > len(data):
        raise Malformed("truncated")
    raw = data[i : i + n]
    if major == 2:
        return bytes(raw), i + n
    try:
        return raw.decode("utf-8"), i + n
    except UnicodeDecodeError as exc:
        raise Malformed("a text string that is not UTF-8") from exc


def _item(data: bytes, i: int, policy: str) -> tuple[Any, int]:
    major, n, i, _ = _length(data, i, policy)
    if major == 0:
        return n, i
    if major == 1:
        return -1 - n, i
    if major in (2, 3):
        return _string(data, i, n, major)
    if major == 4:
        out: list[Any] = []
        for _ in range(n):
            item, i = _item(data, i, policy)
            out.append(item)
        return out, i
    if major == 5:
        return _map(data, i, n, policy)
    if major == 6:
        inner, i = _item(data, i, policy)
        return Tag(n, inner), i
    raise Malformed(f"major type {major} is outside the subset")


def _map(data: bytes, i: int, n: int, policy: str) -> tuple[dict[Any, Any], int]:
    out: dict[Any, Any] = {}
    previous: bytes | None = None
    for _ in range(n):
        start = i
        key, i = _item(data, i, policy)
        encoded_key = data[start:i]
        if policy == "strict" and previous is not None and encoded_key <= previous:
            raise NotDeterministic("map keys unsorted or repeated")
        previous = encoded_key
        if isinstance(key, (list, dict)):
            raise Malformed("a map key that is an array or a map")
        value, i = _item(data, i, policy)
        if policy == "first" and key in out:
            continue
        out[key] = value
    return out, i


def has_repeated_key(data: bytes) -> bool:
    """True when any map in the well-formed item repeats a key."""
    seen: list[bool] = []

    def walk(i: int) -> int:
        major, n, i, _ = _length(data, i, "last")
        if major in (0, 1):
            return i
        if major in (2, 3):
            return i + n
        if major == 4:
            for _ in range(n):
                i = walk(i)
            return i
        if major == 5:
            keys: set[bytes] = set()
            for _ in range(n):
                start = i
                i = walk(i)
                key = data[start:i]
                if key in keys:
                    seen.append(True)
                keys.add(key)
                i = walk(i)
            return i
        if major == 6:
            return walk(i)
        raise Malformed(f"major type {major} is outside the subset")

    walk(0)
    return bool(seen)
