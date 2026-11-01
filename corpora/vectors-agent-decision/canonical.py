"""RFC 8785 canonicalization and argument admission for the agent-decision corpus.

Standard library only, so the verification path of the published corpus runs on
a machine that installed nothing. The generator and `check_vectors.py` both import
it; neither carries a second spelling of either rule.

Two things live here.

`admit_arguments` reads the disclosed argument bytes of one tool call and decides
whether they are a value the corpus's `args_hash` rule can be computed over:

  - the bytes are one JSON object, the named projection the hash covers;
  - no object anywhere repeats a member name;
  - a number written without a fraction or an exponent is an integer literal,
    and it must lie inside the RFC 7493 section 2.2 range, -(2**53 - 1) to
    2**53 - 1. That boundary is where libraries split between refusing and
    rounding to the nearest double, so the corpus pins refusal;
  - any other number is a double by the writer's own spelling and must be
    finite once read as one.

`canonical_bytes` is RFC 8785 over the admitted value. Numbers follow ECMA-262
Number::toString (RFC 8785 section 3.2.2.3), member names sort by UTF-16 code
unit (section 3.2.3), and strings escape only what section 3.2.2.2 names.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping, Sequence
from typing import Any

MAX_SAFE_INTEGER = 2**53 - 1

JSONValue = None | bool | int | float | str | Sequence["JSONValue"] | Mapping[str, "JSONValue"]


class ArgumentsRefused(ValueError):
    """The disclosed arguments are not a value args_hash can be computed over."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


# The four admission rules, by the names the reader's rule sweep disables them
# under. A disabled rule is replaced by the behaviour a common library shows in
# its place, so a sweep measures whether the corpus catches that library.
ADMISSION_RULES = (
    "arguments-json",
    "arguments-duplicate",
    "arguments-integer",
    "arguments-overflow",
)


class _Hooks:
    """The parser callbacks, with the rules `lenient` names replaced.

    A replaced rule takes the behaviour a common library shows instead: the
    last of two repeated members wins, an out-of-range integer becomes the
    nearest double, and an overflowing double becomes null (what
    JSON.stringify writes for Infinity).
    """

    def __init__(self, lenient: frozenset[str]) -> None:
        self.lenient = lenient

    def pairs(self, items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for name, value in items:
            if name in out and "arguments-duplicate" not in self.lenient:
                raise ArgumentsRefused(
                    "arguments-duplicate-member", f"member {name!r} appears twice"
                )
            out[name] = value
        return out

    def integer(self, text: str) -> int | float:
        value = int(text)
        if abs(value) <= MAX_SAFE_INTEGER:
            return value
        if "arguments-integer" in self.lenient:
            return float(value)
        raise ArgumentsRefused(
            "arguments-integer-unsafe", f"integer literal {text} lies outside the RFC 7493 range"
        )

    def double(self, text: str) -> float | None:
        value = float(text)
        if not math.isinf(value):
            return value
        if "arguments-overflow" in self.lenient:
            return None
        raise ArgumentsRefused("arguments-number-overflow", f"{text} is not a finite double")

    @staticmethod
    def constant(text: str) -> Any:
        raise ArgumentsRefused("arguments-not-json", f"{text} is not a JSON value")


def admit_arguments(raw: bytes, lenient: frozenset[str] = frozenset()) -> Any:
    """Parse disclosed argument bytes under the corpus's admission rules.

    `lenient` names rules to replace with the common library behaviour (see
    `_Hooks`); a projection that is not an object is then kept as well.
    """
    hooks = _Hooks(lenient)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ArgumentsRefused("arguments-not-json", "the bytes are not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=hooks.pairs,
            parse_int=hooks.integer,
            parse_float=hooks.double,
            parse_constant=hooks.constant,
        )
    except ArgumentsRefused:
        raise
    except ValueError as exc:
        raise ArgumentsRefused("arguments-not-json", str(exc)) from exc
    if not isinstance(value, dict) and "arguments-json" not in lenient:
        raise ArgumentsRefused("arguments-not-json", "the projection is not a JSON object")
    return value


def es6_number(value: float) -> str:
    """ECMA-262 Number::toString for a finite double."""
    if not math.isfinite(value):
        raise ValueError("RFC 8785 section 3.2.2.3 forbids NaN and Infinity")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    # repr is the shortest decimal that round-trips, which is the digit string
    # ECMA-262 asks for; only the placement of the decimal point differs.
    text = repr(abs(value))
    mantissa, _, exponent = text.partition("e")
    whole, _, fraction = mantissa.partition(".")
    if whole.strip("0"):
        point = len(whole.lstrip("0"))
        digits = (whole.lstrip("0") + fraction).rstrip("0")
    else:
        stripped = fraction.lstrip("0")
        point = -(len(fraction) - len(stripped))
        digits = stripped.rstrip("0")
    n = point + (int(exponent) if exponent else 0)
    k = len(digits)
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        lead = digits[0] + ("." + digits[1:] if k > 1 else "")
        body = f"{lead}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + body


def _encode(node: Any) -> str:
    if node is None:
        return "null"
    if node is True:
        return "true"
    if node is False:
        return "false"
    if isinstance(node, str):
        return json.dumps(node, ensure_ascii=False)
    if isinstance(node, int):
        if abs(node) > MAX_SAFE_INTEGER:
            raise ValueError("RFC 7493 section 2.2 bounds an integer at 2**53 - 1")
        return str(node)
    if isinstance(node, float):
        return es6_number(node)
    if isinstance(node, Mapping):
        members = sorted(node.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(f"{_encode(k)}:{_encode(v)}" for k, v in members) + "}"
    if isinstance(node, Sequence):
        return "[" + ",".join(_encode(item) for item in node) + "]"
    raise TypeError(f"not JSON: {type(node).__name__}")


def canonical_bytes(value: Any) -> bytes:
    return _encode(value).encode("utf-8")


def args_hash(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()
