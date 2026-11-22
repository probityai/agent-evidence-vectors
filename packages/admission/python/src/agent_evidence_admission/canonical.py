"""RFC 8785 canonical JSON bytes, for digests over an inline JSON value.

Strings are written as ``json.dumps`` writes them with ``ensure_ascii=False`` (RFC 8785 section
3.2.2.2 escapes exactly the characters ``json.dumps`` escapes, in the same forms), members are
sorted by UTF-16 code units, and numbers follow ECMAScript's Number-to-String: the shortest digits
that round-trip, in fixed notation from 1e-6 up to 1e21 and in exponent notation outside it. The
value must come from :mod:`strict_json`, which has already refused the inputs RFC 8785 cannot
write (lone surrogates, non-finite numbers, integers past 2^53).
"""

from __future__ import annotations

import json
from decimal import Decimal
from typing import Any


def number(value: float) -> str:
    if isinstance(value, bool):
        raise TypeError("a boolean is not a number")
    if isinstance(value, int):
        return str(value)
    if value == 0:
        return "0"
    if value.is_integer() and abs(value) < 1e21:
        return str(int(value))
    sign = "-" if value < 0 else ""
    digits_tuple, exponent = Decimal(repr(abs(value))).normalize().as_tuple()[1:]
    digits = "".join(str(d) for d in digits_tuple)
    k = len(digits)
    n = k + int(exponent)
    if k <= n <= 21:
        text = digits + "0" * (n - k)
    elif 0 < n <= 21:
        text = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        text = "0." + "0" * (-n) + digits
    else:
        mantissa = digits[0] + ("." + digits[1:] if k > 1 else "")
        text = f"{mantissa}e{'+' if n - 1 >= 0 else '-'}{abs(n - 1)}"
    return sign + text


def encode(node: Any) -> str:
    if node is None:
        return "null"
    if node is True:
        return "true"
    if node is False:
        return "false"
    if isinstance(node, str):
        return json.dumps(node, ensure_ascii=False)
    if isinstance(node, (int, float)):
        return number(node)
    if isinstance(node, list):
        return "[" + ",".join(encode(item) for item in node) + "]"
    if isinstance(node, dict):
        members = sorted(node.items(), key=lambda kv: kv[0].encode("utf-16-be", errors="surrogatepass"))
        return "{" + ",".join(f"{encode(k)}:{encode(v)}" for k, v in members) + "}"
    raise TypeError(f"{type(node).__name__} is not a JSON value")


def canonical_bytes(node: Any) -> bytes:
    return encode(node).encode("utf-8")
