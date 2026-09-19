"""RFC 8785 canonicalization, in the one form this corpus signs over.

Named canonical rather than jcs because tools/artifact-binding/jcs.py already holds
that module name and pyright's extraPaths puts that directory on the search path:
a type checker resolved `from jcs import canonical_bytes` to the OTHER module and
reported an argument error against a type alias this file does not define. Runtime
was never wrong, because sys.path.insert(0, HERE) wins, which is what makes the
failure mode worth removing rather than documenting -- it appears only in the
checker, where it reads as a defect in this code.

Restated here rather than imported from tools/artifact-binding/ or from a sibling
corpus for the reason that module already carries: the verification path of a
published corpus must not depend on a directory that exists for generation. This
copy is standard-library only, and check_vectors.py reaches it without importing
the generator or any third-party package.

es6_number is ECMA-262 7.1.12.1 Number::toString, which is what RFC 8785
Section 3.2.2.3 requires and what Python's repr does not give for every value.
This corpus writes no floats, so the routine is present for correctness of the
canonicalizer rather than because a member exercises it; a canonicalizer that is
correct only for the inputs one corpus happens to hold is a trap for the next.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence

# Mapping and Sequence rather than dict and list: dict is INVARIANT in its value
# type, so a caller holding a dict[str, str] -- which every commitment body here is
# -- cannot pass it to a parameter typed dict[str, JSONValue] without a cast. A cast
# at a call site is a type error suppressed rather than fixed, and the covariant
# abstract types are what the function actually needs: it only reads.
JSONValue = (
    None | bool | int | float | str | Sequence["JSONValue"] | Mapping[str, "JSONValue"]
)


def es6_number(value: float) -> str:
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("RFC 8785 Section 3.2.2.3 forbids NaN and Infinity")
    if value == 0:
        return "0"
    if value == int(value) and abs(value) < 1e21:
        return str(int(value))
    text = repr(value)
    if "e" in text:
        mantissa, exponent = text.split("e")
        sign = "+" if not exponent.startswith("-") else "-"
        return f"{mantissa}e{sign}{exponent.lstrip('+-')}"
    return text


def _encode_scalar(node: JSONValue) -> str | None:
    """Return the canonical form of a scalar, or None where the node is a container."""
    if node is None:
        return "null"
    if node is True:
        return "true"
    if node is False:
        return "false"
    if isinstance(node, str):
        return json.dumps(node, ensure_ascii=False, separators=(",", ":"))
    if isinstance(node, int):
        if abs(node) >= 2**53:
            raise ValueError("RFC 7493 forbids an integer at or above 2**53")
        return str(node)
    if isinstance(node, float):
        return es6_number(node)
    return None


def _encode(node: JSONValue) -> str:
    scalar = _encode_scalar(node)
    if scalar is not None:
        return scalar
    if isinstance(node, Sequence):
        return "[" + ",".join(_encode(item) for item in node) + "]"
    if isinstance(node, Mapping):
        # RFC 8785 Section 3.2.3 sorts member names by UTF-16 code unit.
        members = sorted(node.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(f"{_encode(k)}:{_encode(v)}" for k, v in members) + "}"
    raise TypeError(f"not JSON: {type(node).__name__}")


def canonical_bytes(obj: JSONValue) -> bytes:
    return _encode(obj).encode("utf-8")


def digest(obj: JSONValue) -> str:
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()
