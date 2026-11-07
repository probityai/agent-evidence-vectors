#!/usr/bin/env python3
"""Write the canonicalizer-drift and nesting-depth negative families into cases.json.

``corpora/jcs-byte-vectors/cases.json`` carries two kinds of members. The
canonical and reject cases are authored by hand. ``driftCases`` and
``depthCases`` are written by this script, and nothing else touches those two
keys. ``--check`` regenerates them in memory and exits 1 when the file on disk
differs, so a hand edit to a generated key cannot survive CI.

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

Usage (from the repository root):
    python3 scripts/gen-jcs-drift-vectors.py           # write
    python3 scripts/gen-jcs-drift-vectors.py --check   # exit 1 on drift
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CASES = ROOT / "corpora" / "jcs-byte-vectors" / "cases.json"

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
        "html-less-than", "html-escape", GO,
        '{"a":"<"}',
        '{"a":"\\u003c"}',
        '{"a":"<"}',
    ),
    (
        "html-greater-than", "html-escape", GO,
        '{"a":">"}',
        '{"a":"\\u003e"}',
        '{"a":">"}',
    ),
    (
        "html-ampersand", "html-escape", GO,
        '{"a":"&"}',
        '{"a":"\\u0026"}',
        '{"a":"&"}',
    ),
    (
        "html-markup-in-value", "html-escape", GO,
        '{"msg":"<b>a&b</b>"}',
        '{"msg":"\\u003cb\\u003ea\\u0026b\\u003c/b\\u003e"}',
        '{"msg":"<b>a&b</b>"}',
    ),
    (
        "html-in-member-name", "html-escape", GO,
        '{"a<b":1}',
        '{"a\\u003cb":1}',
        '{"a<b":1}',
    ),
    (
        "non-ascii-bmp-escaped", "non-ascii-escape", PYTHON,
        '{"label":"caf\\u00e9"}',
        '{"label":"caf\\u00e9"}',
        '{"label":"café"}',
    ),
    (
        "non-ascii-astral-surrogate-pair", "non-ascii-escape", PYTHON,
        '{"k":"\\ud83d\\ude00"}',
        '{"k":"\\ud83d\\ude00"}',
        '{"k":"\U0001f600"}',
    ),
    (
        "non-ascii-line-separator", "non-ascii-escape", GO,
        '{"k":"\\u2028"}',
        '{"k":"\\u2028"}',
        '{"k":" "}',
    ),
    (
        "non-ascii-paragraph-separator", "non-ascii-escape", GO,
        '{"k":"\\u2029"}',
        '{"k":"\\u2029"}',
        '{"k":" "}',
    ),
    (
        "non-ascii-in-member-name", "non-ascii-escape", PYTHON,
        '{"caf\\u00e9":1}',
        '{"caf\\u00e9":1}',
        '{"café":1}',
    ),
    (
        "number-negative-zero", "number-format", GO,
        '{"n":-0}',
        '{"n":-0}',
        '{"n":0}',
    ),
    (
        "number-trailing-fraction-zero", "number-format", PYTHON,
        '{"n":1.0}',
        '{"n":1.0}',
        '{"n":1}',
    ),
    (
        "number-two-digit-exponent", "number-format", PYTHON,
        '{"n":1e-7}',
        '{"n":1e-07}',
        '{"n":1e-7}',
    ),
    (
        "number-expanded-large", "number-format", BIG,
        '{"n":1e21}',
        '{"n":1000000000000000000000}',
        '{"n":1e+21}',
    ),
    (
        "number-expanded-small", "number-format", BIG,
        '{"n":1e-7}',
        '{"n":0.0000001}',
        '{"n":1e-7}',
    ),
    (
        "number-exponent-without-sign", "number-format", HAND,
        '{"n":1e30}',
        '{"n":1e30}',
        '{"n":1e+30}',
    ),
    (
        "number-uppercase-exponent", "number-format", HAND,
        '{"n":1E2}',
        '{"n":1E2}',
        '{"n":100}',
    ),
    (
        "number-integer-beyond-double", "number-format", VERBATIM,
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


def render() -> str:
    corpus = json.loads(CASES.read_text("utf-8"))
    corpus["driftCases"] = drift_cases()
    corpus["depthCases"] = depth_cases()
    return json.dumps(corpus, indent=2) + "\n"


def main(argv: list[str]) -> int:
    if argv not in ([], ["--check"]):
        print(__doc__)
        return 2
    wanted = render()
    if argv:
        if CASES.read_text("utf-8") != wanted:
            print(f"{CASES.relative_to(ROOT)} differs from what {Path(__file__).name} writes")
            return 1
        return 0
    CASES.write_text(wanted, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
