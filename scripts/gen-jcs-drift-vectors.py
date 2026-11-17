#!/usr/bin/env python3
"""Write the canonicalizer-drift and nesting-depth negative families into cases.json.

``corpora/jcs-byte-vectors/cases.json`` carries two kinds of members. The
canonical and reject cases are authored by hand. ``driftCases``,
``depthCases``, ``refusalCases``, ``noncharacterCases`` and ``preimageCases``
are written by this script, and nothing else touches those keys. ``--check``
regenerates them in memory and exits 1 when the file on disk differs, so a hand
edit to a generated key cannot survive CI.

Drift cases (``driftCases``): bytes that a producer printed and presented as the
canonical form of a value, which RFC 8785 does not print that way. Each member
pins the correct canonical bytes by hand in this file (``CANONICAL``), and
nothing derives them from the code under test. The checkers hold the bytes to
three oracles: the ECMAScript oracle in ``check.mjs``, the Python reference in
``packaging/agent_evidence_vectors/a2ajcs.py`` and the ``jcs-admit`` crate. The
expected answer for every member is the same: the presented bytes are not
canonical, and canonicalizing them gives ``canonicalHex``.

Depth cases (``depthCases``): arrays and objects nested 129, 256, 512 and 1024
levels, which an admission gate with the 128-level cap refuses, and the same
shapes at exactly 128 levels, which it admits.

Refusal cases (``refusalCases``): inputs that are not one valid JCS input at all
(non-finite numbers, trailing content, malformed syntax, a string that is not a
sequence of Unicode scalar values, a repeated member name). Every canonicalizer
must refuse them. ``error`` names the refusal class; ``inputHex`` replaces
``input`` where the bytes are not valid UTF-8 and so cannot sit in a JSON string.

Noncharacter cases (``noncharacterCases``): a Unicode noncharacter inside a
string value and inside a member name, written raw and as a ``\\u`` escape.
RFC 8785 prints a noncharacter as its UTF-8 bytes, so the default profile pins
``canonicalHex``. RFC 7493 section 2.1 says a member name or string value MUST
NOT include one, escaped or not, so the bounded profile refuses every
``noncharacter`` member (``boundedError``), as ``jcs_admit::admit_ijson`` does.
The ``noncharacter-neighbour`` members carry the scalar value next to each edge of
the noncharacter set (U+FDCF, U+FDF0, U+FFFD, U+1FFFD, U+10FFFD) and no
``boundedError``: every profile prints them, so a bounded verifier whose
noncharacter test is too wide fails them instead of passing the family.

Preimage cases (``preimageCases``): which bytes a field digest covers. A scalar
text value hashes its raw UTF-8 bytes, a structured value hashes its RFC 8785
bytes, and an absent value hashes the empty input. A present ``null`` is a
structured value and hashes the four bytes ``null``; only a field the record does
not carry is absent. Each member pins the correct
``sha256`` and the ``statedWrongSha256`` a reader gets from the usual mistake
(hashing the scalar's JSON form, the structured value as written, or ``null``),
so a reader that makes the mistake fails the member instead of agreeing with it.

The README's examples block is written from the same values, one member per
family, so a worked example in the documentation cannot drift from the corpus:
``--check`` fails when either file differs.

Usage (from the repository root):
    python3 scripts/gen-jcs-drift-vectors.py           # write
    python3 scripts/gen-jcs-drift-vectors.py --check   # exit 1 on drift
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CASES = ROOT / "corpora" / "jcs-byte-vectors" / "cases.json"
README = CASES.with_name("README.md")

DEPTH_CAP = 128
REJECT_DEPTHS = (129, 256, 512, 1024)

# Where the presented bytes come from. A source other than "go-encoding-json"
# is a printer that does the same thing; the Go module's test holds only the
# first to a real run of encoding/json.
GO = "go-encoding-json"
PYTHON = "python-json-default"
BIG = "arbitrary-precision-printer"
VERBATIM = "go-json-number-or-int64"
HAND = "hand-written"

# id, family, source, input JSON text, presented bytes, correct canonical text.
# Every canonical text below was checked against ECMAScript's JSON.stringify
# (RFC 8785 section 3.2.2 takes its string and number rules from it).
DRIFT: tuple[tuple[str, str, str, str, str, str], ...] = (
    (
        "html-less-than",
        "html-escape",
        GO,
        '{"a":"<"}',
        '{"a":"\\u003c"}',
        '{"a":"<"}',
    ),
    (
        "html-greater-than",
        "html-escape",
        GO,
        '{"a":">"}',
        '{"a":"\\u003e"}',
        '{"a":">"}',
    ),
    (
        "html-ampersand",
        "html-escape",
        GO,
        '{"a":"&"}',
        '{"a":"\\u0026"}',
        '{"a":"&"}',
    ),
    (
        "html-markup-in-value",
        "html-escape",
        GO,
        '{"msg":"<b>a&b</b>"}',
        '{"msg":"\\u003cb\\u003ea\\u0026b\\u003c/b\\u003e"}',
        '{"msg":"<b>a&b</b>"}',
    ),
    (
        "html-in-member-name",
        "html-escape",
        GO,
        '{"a<b":1}',
        '{"a\\u003cb":1}',
        '{"a<b":1}',
    ),
    (
        "non-ascii-bmp-escaped",
        "non-ascii-escape",
        PYTHON,
        '{"label":"caf\\u00e9"}',
        '{"label":"caf\\u00e9"}',
        '{"label":"café"}',
    ),
    (
        "non-ascii-astral-surrogate-pair",
        "non-ascii-escape",
        PYTHON,
        '{"k":"\\ud83d\\ude00"}',
        '{"k":"\\ud83d\\ude00"}',
        '{"k":"\U0001f600"}',
    ),
    (
        "non-ascii-line-separator",
        "non-ascii-escape",
        GO,
        '{"k":"\\u2028"}',
        '{"k":"\\u2028"}',
        '{"k":" "}',
    ),
    (
        "non-ascii-paragraph-separator",
        "non-ascii-escape",
        GO,
        '{"k":"\\u2029"}',
        '{"k":"\\u2029"}',
        '{"k":" "}',
    ),
    (
        "non-ascii-in-member-name",
        "non-ascii-escape",
        PYTHON,
        '{"caf\\u00e9":1}',
        '{"caf\\u00e9":1}',
        '{"café":1}',
    ),
    (
        "number-negative-zero",
        "number-format",
        GO,
        '{"n":-0}',
        '{"n":-0}',
        '{"n":0}',
    ),
    (
        "number-trailing-fraction-zero",
        "number-format",
        PYTHON,
        '{"n":1.0}',
        '{"n":1.0}',
        '{"n":1}',
    ),
    (
        "number-two-digit-exponent",
        "number-format",
        PYTHON,
        '{"n":1e-7}',
        '{"n":1e-07}',
        '{"n":1e-7}',
    ),
    (
        "number-expanded-large",
        "number-format",
        BIG,
        '{"n":1e21}',
        '{"n":1000000000000000000000}',
        '{"n":1e+21}',
    ),
    (
        "number-expanded-small",
        "number-format",
        BIG,
        '{"n":1e-7}',
        '{"n":0.0000001}',
        '{"n":1e-7}',
    ),
    (
        "number-exponent-without-sign",
        "number-format",
        HAND,
        '{"n":1e30}',
        '{"n":1e30}',
        '{"n":1e+30}',
    ),
    (
        "number-uppercase-exponent",
        "number-format",
        HAND,
        '{"n":1E2}',
        '{"n":1E2}',
        '{"n":100}',
    ),
    (
        "number-integer-beyond-double",
        "number-format",
        VERBATIM,
        '{"n":9007199254740993}',
        '{"n":9007199254740993}',
        '{"n":9007199254740992}',
    ),
)


def drift_cases() -> list[dict[str, str]]:
    out = []
    for case_id, family, source, text, presented, canonical in DRIFT:
        pinned = canonical.encode("utf-8")
        out.append(
            {
                "id": f"drift-{case_id}",
                "family": family,
                "source": source,
                "input": text,
                "presented": presented,
                "canonicalHex": pinned.hex(),
                "sha256": hashlib.sha256(pinned).hexdigest(),
                "expect": "reject-as-canonical",
                "error": "not-canonical",
            }
        )
    return out


def nest(shape: str, depth: int) -> str:
    if shape == "array":
        return "[" * depth + "]" * depth
    return '{"a":' * depth + "1" + "}" * depth


def depth_cases() -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for shape in ("array", "object"):
        for depth in (DEPTH_CAP, *REJECT_DEPTHS):
            text = nest(shape, depth)
            member: dict[str, object] = {
                "id": f"depth-{shape}-{depth}",
                "shape": shape,
                "depth": depth,
                "limit": DEPTH_CAP,
                "input": text,
            }
            if depth > DEPTH_CAP:
                member["expect"] = "reject"
                member["error"] = "too-deep"
            else:
                pinned = text.encode("utf-8")
                member["expect"] = "accept"
                member["canonicalHex"] = pinned.hex()
                member["sha256"] = hashlib.sha256(pinned).hexdigest()
            out.append(member)
    return out


# id, family, error class, input text (or None), input bytes as hex (or None).
REFUSALS: tuple[tuple[str, str, str, str | None, str | None], ...] = (
    ("non-finite-overflow-positive", "non-finite", "non-finite-number", '{"a":1e999}', None),
    ("non-finite-overflow-negative", "non-finite", "non-finite-number", "[-1e999]", None),
    (
        "non-finite-overflow-large-mantissa",
        "non-finite",
        "non-finite-number",
        "[1.7976931348623159e308]",
        None,
    ),
    ("non-finite-nan-literal", "non-finite", "syntax", '{"a":NaN}', None),
    ("non-finite-infinity-literal", "non-finite", "syntax", "[Infinity]", None),
    ("non-finite-negative-infinity-literal", "non-finite", "syntax", "[-Infinity]", None),
    ("trailing-second-value", "trailing-content", "trailing-content", "{}{}", None),
    ("trailing-garbage", "trailing-content", "trailing-content", "[1] x", None),
    ("syntax-unclosed-array", "syntax", "syntax", "[1,2", None),
    ("syntax-trailing-comma", "syntax", "syntax", "[1,]", None),
    ("syntax-single-quoted-string", "syntax", "syntax", "['a']", None),
    ("syntax-leading-zero", "syntax", "syntax", "[01]", None),
    ("syntax-empty-input", "syntax", "syntax", "", None),
    ("unicode-lone-low-surrogate", "invalid-unicode", "invalid-unicode", '["\\udc00"]', None),
    (
        "unicode-reversed-surrogate-pair",
        "invalid-unicode",
        "invalid-unicode",
        '["\\udc00\\ud800"]',
        None,
    ),
    (
        "unicode-high-surrogate-then-text",
        "invalid-unicode",
        "invalid-unicode",
        '["\\ud800a"]',
        None,
    ),
    (
        "unicode-lone-surrogate-in-member-name",
        "invalid-unicode",
        "invalid-unicode",
        '{"\\ud800":1}',
        None,
    ),
    ("unicode-raw-control-character", "invalid-unicode", "invalid-unicode", '["a\u0001b"]', None),
    ("unicode-invalid-utf8-byte", "invalid-unicode", "invalid-unicode", None, "5b22ff225d"),
    ("unicode-overlong-utf8", "invalid-unicode", "invalid-unicode", None, "5b22c0805d"),
    (
        "unicode-surrogate-encoded-in-utf8",
        "invalid-unicode",
        "invalid-unicode",
        None,
        "5b22eda08022 5d".replace(" ", ""),
    ),
    (
        "duplicate-member-escaped-spelling",
        "duplicate-member",
        "duplicate-member",
        '{"a":1,"\\u0061":2}',
        None,
    ),
    (
        "duplicate-member-nested",
        "duplicate-member",
        "duplicate-member",
        '{"o":{"k":1,"k":1}}',
        None,
    ),
)


def refusal_cases() -> list[dict[str, str]]:
    out = []
    for case_id, family, error, text, hex_bytes in REFUSALS:
        member = {"id": f"refuse-{case_id}", "family": family, "expect": "reject", "error": error}
        if text is not None:
            member["input"] = text
        else:
            member["inputHex"] = hex_bytes or ""
        out.append(member)
    return out


# Noncharacters, RFC 7493 section 2.1 by way of Unicode chapter 23.7: the
# contiguous U+FDD0..U+FDEF run (both ends) and the last two code points of a
# plane (the BMP pair and the first and last supplementary planes).
NONCHARACTERS: tuple[int, ...] = (0xFDD0, 0xFDEF, 0xFFFE, 0xFFFF, 0x1FFFE, 0x10FFFF)
# The scalar value just outside each edge of that set: below and above the run,
# and below the pair of the BMP and of the first and last supplementary planes.
# Each must be accepted under every profile.
NEIGHBOURS: tuple[int, ...] = (0xFDCF, 0xFDF0, 0xFFFD, 0x1FFFD, 0x10FFFD)


def escape(code_point: int) -> str:
    """The JSON escape for one code point: a UTF-16 surrogate pair past the BMP."""
    if code_point < 0x10000:
        return f"\\u{code_point:04x}"
    offset = code_point - 0x10000
    return f"\\u{0xD800 + (offset >> 10):04x}\\u{0xDC00 + (offset & 0x3FF):04x}"


def noncharacter_cases() -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    families = [("noncharacter", c) for c in NONCHARACTERS]
    families += [("noncharacter-neighbour", c) for c in NEIGHBOURS]
    for family, code_point in families:
        raw = chr(code_point)
        for position in ("value", "member-name"):
            for spelling in ("raw", "escaped"):
                written = raw if spelling == "raw" else escape(code_point)
                if position == "value":
                    text, canonical = f'["{written}"]', f'["{raw}"]'
                else:
                    text, canonical = f'{{"{written}":1}}', f'{{"{raw}":1}}'
                pinned = canonical.encode("utf-8")
                member = {
                    "id": f"{family}-u{code_point:04x}-{position}-{spelling}",
                    "family": family,
                    "codePoint": f"U+{code_point:04X}",
                    "position": position,
                    "spelling": spelling,
                    "input": text,
                    "canonicalHex": pinned.hex(),
                    "sha256": hashlib.sha256(pinned).hexdigest(),
                }
                if family == "noncharacter":
                    member["boundedError"] = "invalid-unicode"
                out.append(member)
    return out


# id, profile, the value as JSON text (None when absent), the correct preimage,
# the preimage of the stated wrong answer, and what the wrong answer hashed.
PREIMAGES: tuple[tuple[str, str, str | None, bytes, bytes, str], ...] = (
    ("scalar-ascii", "scalar-text", '"approve"', b"approve", b'"approve"', "json-form"),
    (
        "scalar-non-ascii",
        "scalar-text",
        '"caf\\u00e9"',
        "caf\u00e9".encode(),
        '"caf\u00e9"'.encode(),
        "json-form",
    ),
    ("scalar-newline", "scalar-text", '"a\\nb"', b"a\nb", b'"a\\nb"', "json-form"),
    ("scalar-empty", "scalar-text", '""', b"", b'""', "json-form"),
    (
        "structured-reordered",
        "structured-json",
        '{"b":2,"a":1}',
        b'{"a":1,"b":2}',
        b'{"b":2,"a":1}',
        "as-written",
    ),
    (
        "structured-escaped",
        "structured-json",
        '["caf\\u00e9"]',
        '["caf\u00e9"]'.encode(),
        b'["caf\\u00e9"]',
        "as-written",
    ),
    ("structured-null", "structured-json", "null", b"null", b"", "null-as-absent"),
    ("absent", "absent", None, b"", b"null", "json-null"),
)


def preimage_cases() -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for case_id, profile, text, right, wrong, mistake in PREIMAGES:
        member: dict[str, object] = {"id": f"preimage-{case_id}", "profile": profile}
        if text is not None:
            member["value"] = text
        member["preimageHex"] = right.hex()
        member["sha256"] = hashlib.sha256(right).hexdigest()
        member["statedWrongPreimageHex"] = wrong.hex()
        member["statedWrongSha256"] = hashlib.sha256(wrong).hexdigest()
        member["statedWrongReading"] = mistake
        out.append(member)
    empty = hashlib.sha256(b"").hexdigest()
    for member in out:
        if member["sha256"] == empty and member["profile"] != "absent":
            member["collidesWith"] = "preimage-absent"
    return out


def render() -> str:
    corpus = json.loads(CASES.read_text("utf-8"))
    corpus["driftCases"] = drift_cases()
    corpus["depthCases"] = depth_cases()
    corpus["refusalCases"] = refusal_cases()
    corpus["noncharacterCases"] = noncharacter_cases()
    corpus["preimageCases"] = preimage_cases()
    return json.dumps(corpus, indent=2) + "\n"


BEGIN = "<!-- examples: written by scripts/gen-jcs-drift-vectors.py from cases.json -->"
END = "<!-- examples: end -->"


def example_rows(corpus: dict[str, Any]) -> list[str]:
    """One worked example per family, every value read from the corpus itself."""

    def code(text: str) -> str:
        return "`" + text.replace("|", "\\|") + "`" if text else "(empty)"

    rows = []
    for member in corpus["canonicalCases"][:1]:
        rows.append((member["id"], member["input"], f"bytes {member['canonicalHex']}"))
    for member in corpus["driftCases"][:1]:
        rows.append(
            (member["id"], member["presented"], f"not canonical; bytes {member['canonicalHex']}")
        )
    for member in corpus["refusalCases"][:1]:
        rows.append((member["id"], member["input"], f"refuse ({member['error']})"))
    escaped = [m for m in corpus["noncharacterCases"] if m["spelling"] == "escaped"]
    for member in escaped[:1]:
        rows.append(
            (
                member["id"],
                member["input"],
                f"bytes {member['canonicalHex']}; bounded: refuse ({member['boundedError']})",
            )
        )
    for member in corpus["preimageCases"][:1]:
        rows.append(
            (
                member["id"],
                member["value"],
                f"sha256 {member['sha256']}, never {member['statedWrongSha256']}",
            )
        )
    out = ["| Member | Input | Expected answer |", "| --- | --- | --- |"]
    out += [f"| `{ident}` | {code(text)} | {answer} |" for ident, text, answer in rows]
    return out


def render_readme(corpus_text: str) -> str:
    """The README with its examples block rewritten from ``corpus_text``."""
    readme = README.read_text("utf-8")
    head, rest = readme.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    block = "\n".join([BEGIN, *example_rows(json.loads(corpus_text)), END])
    return head + block + tail


def main(argv: list[str]) -> int:
    if argv not in ([], ["--check"]):
        print(__doc__)
        return 2
    wanted = render()
    wanted_readme = render_readme(wanted)
    if argv:
        status = 0
        for path, text in ((CASES, wanted), (README, wanted_readme)):
            if path.read_text("utf-8") != text:
                print(f"{path.relative_to(ROOT)} differs from what {Path(__file__).name} writes")
                status = 1
        return status
    CASES.write_text(wanted, encoding="utf-8")
    README.write_text(wanted_readme, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
