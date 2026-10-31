"""RFC 8785 canonical JSON for the value space this corpus uses, standard library only.

Kept in its own module rather than inside the generator for the reason
`vectors-scitt-cose/digest.py` gives at length: `scripts/release-digests.py`
recomputes every corpus digest by loading the module that OWNS that corpus's
preimage, and that path has to run for somebody who installed nothing. The
generator signs, so it needs a signing library; this file and `digest.py` do
not, and between them they carry everything the verification path reaches.

The value space is narrow: null, booleans, integers, strings, arrays and
objects. There is no float anywhere in this corpus, so RFC 8785 number
serialization, the one place two correct implementations differ, is reachable
only by a value this contract forbids. A float raises rather than guessing,
because a guess here is a silent wrong digest, and a wrong digest is the one
defect a digest exists to make loud. Member names ARE ordered by UTF-16 code
unit, as RFC 8785 requires: a name above U+FFFF sorts before one in
U+E000..U+FFFF, which code-point order would reverse.

`decode_strict` is the one reader of member bytes. It keeps every number as the
token it was written with, so an integer is never a float and a 4200-digit
integer is not a Python limit, and it refuses what two files could differ in
without differing in meaning: bytes that are not UTF-8, bytes after the first
document, NaN and the infinities.
"""

from __future__ import annotations

import json
import re
from typing import Any

_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


class Number:
    """A JSON number kept as the token it was written with."""

    __slots__ = ("is_float", "text")

    def __init__(self, text: str, is_float: bool) -> None:
        self.text = text
        self.is_float = is_float


def _int_token(text: str) -> Number:
    return Number(text, False)


def _float_token(text: str) -> Number:
    return Number(text, True)


def _reject_constant(name: str) -> Any:
    raise ValueError(f"invalid character in literal {name}")


def _scrub(value: Any) -> Any:
    """Replace each unpaired surrogate with U+FFFD, as Go's decoder does."""
    if isinstance(value, str):
        return _LONE_SURROGATE.sub("\ufffd", value)
    if isinstance(value, list):
        return [_scrub(item) for item in value]
    if isinstance(value, dict):
        return {_scrub(key): _scrub(item) for key, item in value.items()}
    return value


def decode_strict(raw: bytes) -> Any:
    """The one JSON document in *raw*, numbers kept as tokens.

    Raises ValueError (UnicodeDecodeError and JSONDecodeError are both one) or
    RecursionError when *raw* is not exactly one JSON document in UTF-8.
    """
    text = raw.decode("utf-8").lstrip(" \t\n\r")
    decoder = json.JSONDecoder(
        parse_int=_int_token, parse_float=_float_token, parse_constant=_reject_constant
    )
    value, end = decoder.raw_decode(text)
    if text[end:].strip(" \t\n\r"):
        raise ValueError("extra data after the statement")
    return _scrub(value)


def _utf16_key(name: str) -> bytes:
    return name.encode("utf-16-be", errors="surrogatepass")


def _spell(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, Number):
        if value.is_float:
            raise TypeError(f"{value.text} is a JSON float")
        # "-0" is the one integer token whose value has a different spelling.
        return "0" if value.text == "-0" else value.text
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        raise TypeError(
            "this corpus's canonical form covers no float: RFC 8785 number "
            "serialization is the one place two correct implementations differ, "
            "so a float is refused rather than spelled"
        )
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(_spell(item) for item in value) + "]"
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise TypeError(f"a JSON member name is a string, got {type(key).__name__}")
        return (
            "{"
            + ",".join(
                json.dumps(name, ensure_ascii=False) + ":" + _spell(value[name])
                for name in sorted(value, key=_utf16_key)
            )
            + "}"
        )
    raise TypeError(f"unsupported type {type(value).__name__}")


def jcs(value: Any) -> bytes:
    """The RFC 8785 canonical bytes of *value*, or TypeError for what it will not spell."""
    return _spell(value).encode("utf-8")
