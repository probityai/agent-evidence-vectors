"""RFC 8785 canonicalization, in the one form this contract signs over.

The repository already carries three JCS serializers in
``corpora/vectors-ai-agent-action/gen_vectors.py``: a fast one that is correct for
BMP-only member names and safe integers, one that sorts member names by UTF-16
code unit as the RFC actually says, and one that also writes numbers per
ECMA-262 rather than per Python. Only the third is unconditionally correct, and
a binding record is signed over its own bytes, so this module carries that one
and no other. ``es6_number`` below is the same algorithm as the house copy; it
is restated here rather than imported because the corpus generators live under
a directory this tool must not depend on at verification time.

The contract in ``spec/artifact-binding/v1.md`` section 4 says what these bytes
are for: they are the preimage of the manifest digest and of the detached
signature, and a manifest whose stored bytes differ from them is refused before
any signature is checked.
"""

from __future__ import annotations

import hashlib
import json

JSONValue = None | bool | int | float | str | list["JSONValue"] | dict[str, "JSONValue"]


def es6_number(value: float) -> str:
    """ECMA-262 7.1.12.1 Number::toString, which is what RFC 8785 requires.

    Python's ``repr`` already selects the shortest round-tripping decimal, which
    is the digit string ECMAScript selects too, so the only work is re-laying
    those digits out under the ECMAScript exponent rules.
    """
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("NaN and Infinity are not JSON numbers")
    if value == 0:
        return "0"
    if value < 0:
        return "-" + es6_number(-value)

    mantissa, _, exponent = repr(value).partition("e")
    n = int(exponent) if exponent else 0
    whole, _, frac = mantissa.partition(".")
    if whole == "0":
        stripped = frac.lstrip("0")
        n -= len(frac) - len(stripped)
        digits = stripped
    else:
        digits = whole + frac
        n += len(whole)
    digits = digits.rstrip("0") or "0"
    k = len(digits)

    if k <= n <= 21:
        return digits + "0" * (n - k)
    if 0 < n <= 21:
        return digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return "0." + "0" * -n + digits
    sign = "+" if n - 1 >= 0 else "-"
    tail = f"e{sign}{abs(n - 1)}"
    return (digits if k == 1 else digits[0] + "." + digits[1:]) + tail


def _encode(node: JSONValue) -> str:
    if isinstance(node, dict):
        members = sorted(node.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(
            json.dumps(name, ensure_ascii=False) + ":" + _encode(value)
            for name, value in members
        ) + "}"
    if isinstance(node, list):
        return "[" + ",".join(_encode(value) for value in node) + "]"
    if isinstance(node, bool) or node is None or isinstance(node, int):
        return json.dumps(node, ensure_ascii=False)
    if isinstance(node, float):
        return es6_number(node)
    return json.dumps(node, ensure_ascii=False, separators=(",", ":"))


def canonical_bytes(obj: JSONValue) -> bytes:
    """The RFC 8785 form of *obj*, and the only preimage this contract signs."""
    return _encode(obj).encode("utf-8")


def digest(obj: JSONValue) -> str:
    """Lowercase hexadecimal SHA-256 over the canonical bytes of *obj*."""
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def is_canonical(raw: bytes) -> bool:
    """Whether *raw* is already the canonical encoding of the value it parses to.

    A manifest that parses but was not stored canonically is refused: a
    signature over non-canonical bytes verifies for the party that produced
    them and for nobody who re-serializes before checking, which is the exact
    disagreement a second implementation is supposed to catch.
    """
    try:
        parsed: JSONValue = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return canonical_bytes(parsed) == raw
