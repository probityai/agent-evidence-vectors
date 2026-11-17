"""A strict JSON reader for admission: refuse the byte strings two decoders read apart.

Python's ``json`` module, like most decoders, is lenient where a record format can least afford it.
A repeated member keeps its last value, an escaped lone surrogate decodes, an integer past 2^53
parses exactly here and rounds in every double-based reader, ``1e400`` reads as infinity, and
nesting has no bound below the interpreter's. Each of those is one byte string that two verifiers
read as two documents, so a signature over it validates both.

This reader is written by hand so that every refusal names a JSON Pointer and a code, and so that
each check can be switched off one at a time (``checks``), which is how the ablation command
proves that every check is needed. The codes match the strict reader of agent-evidence-verify
(``not-utf8``, ``not-parseable``, ``non-json-number``, ``duplicate-member``, ``lone-surrogate``,
``unsafe-integer``, ``value-not-representable``, ``nesting-too-deep``) and add four that only an
admission profile refuses:

``case-fold-collision``
    Two member names of one object that are equal under Unicode case folding, with the dotless
    and dotted i (U+0131, U+0130), the long s (U+017F) and the Kelvin and Angstrom signs folded
    to their ASCII letters. RFC 8785 keeps them as distinct members; a decoder that matches names
    without regard to case reads one of them as the field the signer meant.
``number-token-too-long``
    A number token longer than the bound (64 characters by default), refused before conversion.
``noncharacter``
    A string holding a Unicode noncharacter, which RFC 7493 section 2.1 excludes.
``negative-zero``
    ``-0`` in any spelling: RFC 8785 writes it as ``0``, so a signature over the received bytes
    and one over the canonical bytes disagree on it.

Two profiles: ``ijson`` admits fractions and exponents whose double is finite, below 2^53 in
magnitude, and holds the token's whole value: the token is the shortest spelling of its double or
that double's exact decimal expansion, in any notation. A token with more precision than a double
holds (RFC 7493 section 2.2's own example is ``3.141592653589793238462643383279``) is read as
itself by a decimal reader and rounded by a double one, so it is refused
(``value-not-representable``). ``integer-only`` refuses any fraction or exponent (``value-not-representable``), so a
record format whose numbers are all counts can say so and refuse ``1000.0`` and ``1e3``.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

#: Exact integers in an I-JSON number: RFC 7493 section 2.2.
MAX_SAFE_INTEGER = 2**53 - 1
MAX_DEPTH = 64
MAX_NUMBER_CHARS = 64

PROFILES = ("ijson", "integer-only")

#: Every check this reader can switch off, in the order a document meets them. ``not-parseable``
#: (bytes that are not JSON at all) is the grammar itself and always refuses.
CHECKS = (
    "not-utf8",
    "non-json-number",
    "nesting-too-deep",
    "lone-surrogate",
    "noncharacter",
    "duplicate-member",
    "case-fold-collision",
    "number-token-too-long",
    "unsafe-integer",
    "value-not-representable",
    "negative-zero",
)

#: Folded beyond ``str.casefold``: the letters that case-insensitive matchers in common decoders
#: (Go's ``encoding/json`` field match, .NET and Java locale-sensitive comparisons) treat as ASCII.
_EXTRA_FOLD = str.maketrans({"ı": "i", "İ": "i", "ſ": "s", "K": "k", "Å": "å"})


class Refusal(ValueError):
    """One refusal: the rule ``code``, the JSON Pointer ``at`` where it applies, and a ``detail``."""

    def __init__(self, code: str, at: str = "", detail: str = "") -> None:
        super().__init__(f"{code} at {at or '/'}: {detail}" if detail else f"{code} at {at or '/'}")
        self.code = code
        self.at = at
        self.detail = detail


def pointer(parts: Iterable[str | int]) -> str:
    """The RFC 6901 JSON Pointer for a path of member names and indexes."""
    out = []
    for part in parts:
        out.append("/" + str(part).replace("~", "~0").replace("/", "~1"))
    return "".join(out)


def fold(name: str) -> str:
    """A member name as a case-insensitive decoder compares it."""
    return name.translate(_EXTRA_FOLD).casefold().replace("̇", "")


def _is_noncharacter(code: int) -> bool:
    return 0xFDD0 <= code <= 0xFDEF or (code & 0xFFFE) == 0xFFFE


@dataclass
class _Reader:
    text: str
    profile: str
    checks: frozenset[str]
    max_depth: int
    max_number_chars: int
    pos: int = 0

    def on(self, code: str) -> bool:
        return code in self.checks

    def fail(self, code: str, path: list[str | int], detail: str) -> Refusal:
        return Refusal(code, pointer(path), detail)

    def skip_ws(self) -> None:
        while self.pos < len(self.text) and self.text[self.pos] in " \t\n\r":
            self.pos += 1

    def expect(self, char: str, path: list[str | int]) -> None:
        if self.pos >= len(self.text) or self.text[self.pos] != char:
            got = self.text[self.pos] if self.pos < len(self.text) else "end of input"
            raise self.fail("not-parseable", path, f"expected {char!r} at offset {self.pos}, found {got!r}")
        self.pos += 1

    def value(self, path: list[str | int], depth: int) -> Any:
        self.skip_ws()
        if self.pos >= len(self.text):
            raise self.fail("not-parseable", path, "unexpected end of input")
        char = self.text[self.pos]
        if char in "{[":
            if depth >= self.max_depth and self.on("nesting-too-deep"):
                raise self.fail("nesting-too-deep", path, f"nesting deeper than {self.max_depth}")
            return self.obj(path, depth + 1) if char == "{" else self.arr(path, depth + 1)
        if char == '"':
            return self.string(path)
        for word, result in (("true", True), ("false", False), ("null", None)):
            if self.text.startswith(word, self.pos):
                self.pos += len(word)
                return result
        return self.number(path)

    def obj(self, path: list[str | int], depth: int) -> dict[str, Any]:
        self.pos += 1
        out: dict[str, Any] = {}
        folded: dict[str, str] = {}
        self.skip_ws()
        if self.pos < len(self.text) and self.text[self.pos] == "}":
            self.pos += 1
            return out
        while True:
            self.skip_ws()
            if self.pos >= len(self.text) or self.text[self.pos] != '"':
                raise self.fail("not-parseable", path, f"expected a member name at offset {self.pos}")
            name = self.string(path)
            if name in out and self.on("duplicate-member"):
                raise self.fail("duplicate-member", [*path, name], f"member {name!r} appears more than once")
            key = fold(name)
            if key in folded and folded[key] != name and self.on("case-fold-collision"):
                raise self.fail(
                    "case-fold-collision", [*path, name], f"{name!r} and {folded[key]!r} are one name under case folding"
                )
            folded.setdefault(key, name)
            self.skip_ws()
            self.expect(":", path)
            out[name] = self.value([*path, name], depth)
            self.skip_ws()
            if self.pos < len(self.text) and self.text[self.pos] == ",":
                self.pos += 1
                continue
            self.expect("}", path)
            return out

    def arr(self, path: list[str | int], depth: int) -> list[Any]:
        self.pos += 1
        out: list[Any] = []
        self.skip_ws()
        if self.pos < len(self.text) and self.text[self.pos] == "]":
            self.pos += 1
            return out
        while True:
            out.append(self.value([*path, len(out)], depth))
            self.skip_ws()
            if self.pos < len(self.text) and self.text[self.pos] == ",":
                self.pos += 1
                continue
            self.expect("]", path)
            return out

    def string(self, path: list[str | int]) -> str:
        self.pos += 1
        units: list[int] = []
        text = self.text
        while True:
            if self.pos >= len(text):
                raise self.fail("not-parseable", path, "unterminated string")
            char = text[self.pos]
            if char == '"':
                self.pos += 1
                break
            if char == "\\":
                self.pos += 1
                esc = text[self.pos : self.pos + 1]
                simple = {'"': 0x22, "\\": 0x5C, "/": 0x2F, "b": 0x08, "f": 0x0C, "n": 0x0A, "r": 0x0D, "t": 0x09}
                if esc in simple:
                    units.append(simple[esc])
                    self.pos += 1
                elif esc == "u":
                    digits = text[self.pos + 1 : self.pos + 5]
                    if len(digits) != 4 or any(d not in "0123456789abcdefABCDEF" for d in digits):
                        raise self.fail("not-parseable", path, f"bad \\u escape at offset {self.pos}")
                    units.append(int(digits, 16))
                    self.pos += 5
                else:
                    raise self.fail("not-parseable", path, f"bad escape at offset {self.pos}")
                continue
            if ord(char) < 0x20:
                raise self.fail("not-parseable", path, f"unescaped control character at offset {self.pos}")
            units.extend(_utf16(char))
            self.pos += 1
        return self.decode_units(units, path)

    def decode_units(self, units: list[int], path: list[str | int]) -> str:
        chars: list[str] = []
        i = 0
        while i < len(units):
            unit = units[i]
            if 0xD800 <= unit <= 0xDBFF and i + 1 < len(units) and 0xDC00 <= units[i + 1] <= 0xDFFF:
                code = 0x10000 + ((unit - 0xD800) << 10) + (units[i + 1] - 0xDC00)
                i += 2
            else:
                code = unit
                i += 1
                if 0xD800 <= code <= 0xDFFF:
                    if self.on("lone-surrogate"):
                        raise self.fail("lone-surrogate", path, f"a string holds the lone surrogate U+{code:04X}")
                    code = 0xFFFD
            if _is_noncharacter(code) and self.on("noncharacter"):
                raise self.fail("noncharacter", path, f"a string holds the noncharacter U+{code:04X}")
            chars.append(chr(code))
        return "".join(chars)

    def number(self, path: list[str | int]) -> int | float:
        start = self.pos
        text = self.text
        while self.pos < len(text) and text[self.pos] in "+-0123456789.eE":
            self.pos += 1
        token = text[start : self.pos]
        if not token:
            if self.on("non-json-number") and text[start:].startswith(("NaN", "Infinity", "-Infinity")):
                raise self.fail("non-json-number", path, "NaN and Infinity are not JSON numbers")
            raise self.fail("not-parseable", path, f"unexpected character at offset {start}")
        if not _is_json_number(token):
            if token in ("-",) and text[self.pos :].startswith("Infinity") and self.on("non-json-number"):
                raise self.fail("non-json-number", path, "-Infinity is not a JSON number")
            raise self.fail("not-parseable", path, f"{token!r} is not a JSON number")
        if len(token) > self.max_number_chars and self.on("number-token-too-long"):
            raise self.fail("number-token-too-long", path, f"a number token of {len(token)} characters")
        integral = not any(c in token for c in ".eE")
        if integral:
            try:
                value = int(token)
            except ValueError as error:  # past the interpreter's digit limit, with the length bound off
                raise self.fail("value-not-representable", path, f"a {len(token)}-digit integer") from error
            if token.startswith("-") and value == 0 and self.on("negative-zero"):
                raise self.fail("negative-zero", path, "-0 has no distinct canonical form")
            if abs(value) > MAX_SAFE_INTEGER and self.on("unsafe-integer"):
                raise self.fail("unsafe-integer", path, f"{token} is outside +-(2**53 - 1)")
            return value
        if self.profile == "integer-only" and self.on("value-not-representable"):
            raise self.fail("value-not-representable", path, f"{token} has a fraction or exponent; the profile is integer-only")
        number = float(token)
        if not math.isfinite(number) and self.on("value-not-representable"):
            raise self.fail("value-not-representable", path, f"{token} is not a finite double")
        if number == 0 and _nonzero_digits(token) and self.on("value-not-representable"):
            raise self.fail("value-not-representable", path, f"{token} is not zero and underflows to a double zero")
        if abs(number) > MAX_SAFE_INTEGER and self.on("unsafe-integer"):
            raise self.fail("unsafe-integer", path, f"{token} parses to a double outside +-(2**53 - 1)")
        if number == 0 and token.startswith("-") and self.on("negative-zero"):
            raise self.fail("negative-zero", path, f"{token} is negative zero")
        if not _holds(token, number) and self.on("value-not-representable"):
            raise self.fail("value-not-representable", path, f"{token} has more precision than a double holds; it reads as {number!r}")
        return number


def _holds(token: str, number: float) -> bool:
    """True when the double ``number`` holds the whole decimal value of ``token``: the token equals
    the double's shortest round-trip spelling (``0.1``, ``1e5``, ``1.50``) or its exact expansion."""
    value = Decimal(token)
    return value == Decimal(repr(number)) or value == Decimal(number)


def _nonzero_digits(token: str) -> bool:
    """True when the significand of a number token has a digit other than 0: ``1e-400`` is not zero
    in a decimal reader (Go's ``json.Number``, Java's ``BigDecimal``) and is zero in a double one,
    which RFC 8785 then writes as ``0``."""
    significand = token.lower().partition("e")[0]
    return any(c in "123456789" for c in significand)


def _utf16(char: str) -> list[int]:
    raw = char.encode("utf-16-be", errors="surrogatepass")
    return [int.from_bytes(raw[i : i + 2], "big") for i in range(0, len(raw), 2)]


def _is_json_number(token: str) -> bool:
    i = 0
    if token.startswith("-"):
        i = 1
    if i >= len(token):
        return False
    if token[i] == "0":
        i += 1
    elif token[i].isdigit() and token[i] in "123456789":
        while i < len(token) and token[i] in "0123456789":
            i += 1
    else:
        return False
    if i < len(token) and token[i] == ".":
        i += 1
        begin = i
        while i < len(token) and token[i] in "0123456789":
            i += 1
        if i == begin:
            return False
    if i < len(token) and token[i] in "eE":
        i += 1
        if i < len(token) and token[i] in "+-":
            i += 1
        begin = i
        while i < len(token) and token[i] in "0123456789":
            i += 1
        if i == begin:
            return False
    return i == len(token)


def decode_text(data: bytes, checks: frozenset[str] = frozenset(CHECKS)) -> str:
    """UTF-8 text with no byte-order mark, or a ``not-utf8`` refusal."""
    if data.startswith(b"\xef\xbb\xbf"):
        if "not-utf8" in checks:
            raise Refusal("not-utf8", "", "a byte-order mark precedes the text")
        data = data[3:]
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        if "not-utf8" in checks:
            raise Refusal("not-utf8", "", f"invalid UTF-8 at byte {error.start}") from error
        return data.decode("utf-8", errors="replace")


def loads(
    data: bytes | str,
    profile: str = "ijson",
    checks: Iterable[str] | None = None,
    max_depth: int = MAX_DEPTH,
    max_number_chars: int = MAX_NUMBER_CHARS,
) -> Any:
    """Parse ``data`` under ``profile``, or raise :class:`Refusal` naming the first rule it breaks.

    ``checks`` names the checks that run (every check by default). A check left out reads the way
    a lenient decoder does: a repeated member keeps its last value, a lone surrogate becomes
    U+FFFD, and a number is taken as Python reads it.
    """
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}; known: {', '.join(PROFILES)}")
    enabled = frozenset(CHECKS if checks is None else checks)
    unknown = enabled - set(CHECKS)
    if unknown:
        raise ValueError(f"unknown checks: {', '.join(sorted(unknown))}")
    text = decode_text(data, enabled) if isinstance(data, bytes) else data
    reader = _Reader(text, profile, enabled, max_depth, max_number_chars)
    try:
        result = reader.value([], 0)
    except RecursionError as error:
        raise Refusal("nesting-too-deep", "", "nesting exceeds the interpreter's limit") from error
    reader.skip_ws()
    if reader.pos != len(text):
        raise Refusal("not-parseable", "", f"trailing data at offset {reader.pos}")
    return result
