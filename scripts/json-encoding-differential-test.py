#!/usr/bin/env python3
"""One table of JSON documents, and the bytes each digest encoding writes for them.

    python3 scripts/json-encoding-differential-test.py          # refuse a table that drifted
    python3 scripts/json-encoding-differential-test.py --write  # rewrite the table

Two readers of one corpus must write the same bytes for the same JSON value, or
two digests over one report differ by which reader took them. That held in
code nobody compared across languages: the Go encoder in corpusreaders/pyjson.go
copied the integer token -0 where CPython writes 0, and the split was found by
a list participant measuring both readers, not by a test. This is the test.

The table is corpusreaders/testdata/json-encodings.json. Each case is a document and,
for each encoding, the bytes it writes (hex) or the reason it refuses. This
script computes every Python column from the Python implementation that owns
it and refuses a table that differs, so the file cannot be edited by hand
into agreement. The Go encoders are held to the same file by
corpusreaders/pyjson_table_test.go; a column a Go encoder writes differently fails
there, which makes the pair a differential test over one table rather than two
lists of expectations that only claim to agree.

Columns:
  cpython-ascii   json.dumps(value, sort_keys=True, separators=(",", ":")) in
                  CPython, the encoding corpusreaders/pyjson.go reproduces with
                  EnsureASCII; a number token with a fraction or an exponent
                  is refused, as the Go encoder refuses it
  cpython-raw     the same with ensure_ascii=False (pyEncodeOpts{})
  cpython-utf16   the same with member names ordered by UTF-16 code unit
                  (pyEncodeOpts{UTF16Order: true})
  jcs-sha256      the W3C report readers' digest over a JSON value: RFC 8785
                  under the integer profile, a refusal written as its cause
                  code (the Go reader in corpusreaders/w3cjcs.go and the Rust reader
                  in readers/w3c-report-rs are held to it)
  rfc8785         the W3C report readers' member identifier: RFC 8785 as
                  written, numbers as IEEE 754 doubles

The repository's Python twins of the Go encoder (TWINS) must reproduce their
column through the parse their reader uses.

And one section beside the columns, number-truth: number tokens and whether CPython
reads each as a false value, which corpusreaders/pyjson.go's jsonNumberIsZero must
match.

Exit 0 when the table holds; 1 when it differs, naming each cell.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "packaging"))

from agent_evidence_vectors import mcpowasp, w3creport  # noqa: E402

TABLE = REPO / "corpora" / "testdata" / "json-encodings.json"

#: The documents: the measured boundary cases of the v0.1 digest encoding
#: (list messages 2026Oct/0026, 0031, 0038, 0041) and the structure every
#: encoder must also get right. A document is JSON text exactly as a producer
#: writes it, so a token such as -0 or 1e21 reaches each encoder as written.
CASES: tuple[tuple[str, str], ...] = (
    ("negative zero", '{"v": -0}'),
    ("zero", '{"v": 0}'),
    ("minus one", '{"v": -1}'),
    ("2^53-2", '{"v": 9007199254740990}'),
    ("2^53-1", '{"v": 9007199254740991}'),
    ("2^53", '{"v": 9007199254740992}'),
    ("2^53+1", '{"v": 9007199254740993}'),
    ("-(2^53-2)", '{"v": -9007199254740990}'),
    ("-(2^53-1)", '{"v": -9007199254740991}'),
    ("-2^53", '{"v": -9007199254740992}'),
    ("-(2^53+1)", '{"v": -9007199254740993}'),
    ("1e21 in digits", '{"v": 1000000000000000000000}'),
    ("1e21 in digits plus one", '{"v": 1000000000000000000001}'),
    ("1e21 as an exponent", '{"v": 1e21}'),
    ("1e+21 as an exponent", '{"v": 1e+21}'),
    ("one with a fraction", '{"v": 1.0}'),
    ("one half", '{"v": 0.5}'),
    ("negative zero with a fraction", '{"v": -0.0}'),
    ("1e16 as an exponent", '{"v": 1e16}'),
    ("1e2 as an exponent", '{"v": 1e2}'),
    ("1e-7", '{"v": 1e-7}'),
    ("seventeen nines after the point", '{"v": 0.99999999999999999}'),
    ("1e400, past the largest double", '{"v": 1e400}'),
    ("U+007F", '{"v": "\\u007f"}'),
    ("U+001F", '{"v": "\\u001f"}'),
    ("U+00E9", '{"v": "\\u00e9"}'),
    ("U+20AC", '{"v": "\\u20ac"}'),
    ("U+2028", '{"v": "\\u2028"}'),
    ("U+1F600", '{"v": "\\ud83d\\ude00"}'),
    ("member names U+FB33 and U+1F600", '{"\\ufb33": "U+FB33", "\\ud83d\\ude00": "U+1F600"}'),
    ("member names U+E000 and U+10000", '{"\\ue000": 1, "\\ud800\\udc00": 2}'),
    ("numeric strings", '{"a": "9007199254740993", "b": "1e+21", "c": "-0", "d": "0.5"}'),
    ("escapes", '{"v": "quote \\" backslash \\\\ newline \\n tab \\t"}'),
    ("characters Go escapes and CPython does not", '{"v": "<&>"}'),
    ("nesting and empty containers", '{"b": [], "a": {"d": {}, "c": [null, true, false]}}'),
    ("all five cases of 2026Oct/0031 in one object",
     '{"\\ufb33": "\\u20ac", "z": 1000000000000000000000, '
     '"\\ud83d\\ude00": "\\u007f", "a": -0}'),
)


#: Number tokens, for the truth CPython gives the value it parses each into. A
#: Python reader tests a parsed value's truth; a Go reader holds the token, and
#: corpusreaders/pyjson.go's jsonNumberIsZero must answer as CPython does: the Go
#: readers once compared the token's text with "0" and read -0 and 0.0 as true.
NUMBER_TOKENS: tuple[str, ...] = (
    "0", "-0", "0.0", "-0.0", "0e5", "0E-5", "1e-400", "-1e-400", "2e-324",
    "5e-324", "1", "-1", "0.5", "1e400", "-1e400", "9007199254740993",
)


class Refused(Exception):
    """The encoding has no bytes for this document; the message is the reason."""


class _Float(str):
    """A number token with a fraction or an exponent, kept as written."""


def _parse_marking_floats(doc: str) -> Any:
    return json.loads(doc, parse_float=_Float)


def _has_float(value: Any) -> bool:
    if isinstance(value, _Float):
        return True
    if isinstance(value, dict):
        return any(_has_float(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_float(v) for v in value)
    return False


def _utf16_ordered(value: Any) -> Any:
    if isinstance(value, dict):
        order = sorted(value, key=lambda name: name.encode("utf-16-be"))
        return {k: _utf16_ordered(value[k]) for k in order}
    if isinstance(value, list):
        return [_utf16_ordered(v) for v in value]
    return value


def _cpython(doc: str, ensure_ascii: bool, utf16: bool) -> bytes:
    value = _parse_marking_floats(doc)
    if _has_float(value):
        raise Refused("float")
    if utf16:
        return json.dumps(_utf16_ordered(value), separators=(",", ":"),
                          ensure_ascii=ensure_ascii).encode("utf-8")
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=ensure_ascii).encode("utf-8")


def _w3c(encode: Callable[[Any], bytes]) -> Callable[[str], bytes]:
    """A W3C report reader encoding, through that reader's own parse."""

    def run(doc: str) -> bytes:
        try:
            return encode(w3creport.load_json(doc))
        except w3creport.DigestRefused as exc:
            # The cause, not the token: each reader names the token in its own
            # spelling (serde_json writes 1e21 back as 1e+21), and the cause is
            # what the list asked a reader to name.
            raise Refused(exc.cause) from exc

    return run


#: Every column, and the Python implementation that owns it.
ENCODINGS: dict[str, Callable[[str], bytes]] = {
    "cpython-ascii": lambda doc: _cpython(doc, ensure_ascii=True, utf16=False),
    "cpython-raw": lambda doc: _cpython(doc, ensure_ascii=False, utf16=False),
    "cpython-utf16": lambda doc: _cpython(doc, ensure_ascii=False, utf16=True),
    "jcs-sha256": _w3c(w3creport.jcs_sha256),
    "rfc8785": _w3c(w3creport.rfc8785),
}


def _cell(encode: Callable[[str], bytes], doc: str) -> dict[str, str]:
    try:
        out = encode(doc)
    except Refused as exc:
        return {"refused": str(exc)}
    return {"hex": out.hex()}


def build() -> dict[str, Any]:
    return {
        "about": (
            "Each case is a JSON document as a producer writes it and, for each digest "
            "encoding, the bytes that encoding writes for it (hex) or the reason it refuses. "
            "Written by scripts/json-encoding-differential-test.py --write from the Python "
            "implementations, held to them by the same script, held to the Go encoders by "
            "corpusreaders/pyjson_table_test.go and corpusreaders/w3cjcs_test.go, and held to the Rust "
            "W3C reader by a unit test in readers/w3c-report-rs/src/json.rs. Never edit by hand."
        ),
        "columns": list(ENCODINGS),
        "cases": [
            {"name": name, "doc": doc,
             **{column: _cell(encode, doc) for column, encode in ENCODINGS.items()}}
            for name, doc in CASES
        ],
        "number-truth": [
            {"token": token, "cpython-falsy": not json.loads(token)} for token in NUMBER_TOKENS
        ],
    }


def render(table: dict[str, Any]) -> str:
    return json.dumps(table, indent=2, ensure_ascii=True) + "\n"


def differences(table: dict[str, Any], committed: dict[str, Any]) -> list[str]:
    """Every cell where the committed table and the Python implementations part."""
    out: list[str] = []
    if committed.get("columns") != table["columns"]:
        out.append(f"the table's columns are {committed.get('columns')}, the encoders' are "
                   f"{table['columns']}")
    by_name = {case["name"]: case for case in committed.get("cases", [])}
    if len(by_name) != len(table["cases"]):
        out.append(f"the table holds {len(by_name)} cases and the script {len(table['cases'])}")
    for case in table["cases"]:
        held = by_name.get(case["name"])
        if held is None:
            out.append(f"case {case['name']!r} is not in the table")
            continue
        for column in [*table["columns"], "doc"]:
            if held.get(column) != case[column]:
                out.append(f"{case['name']!r} {column}: the table holds {held.get(column)}, "
                           f"the Python implementation writes {case[column]}")
    if committed.get("number-truth") != table["number-truth"]:
        out.append("the number-truth section is not what CPython answers for its tokens")
    return out


def _mcpowasp(doc: str) -> bytes:
    try:
        return mcpowasp.compact(mcpowasp.load_record(doc))
    except mcpowasp.FloatRefused as exc:
        raise Refused("float") from exc


#: The repository's Python twins of the Go encoder, each through the parse its
#: reader uses, and the column each must reproduce. The mcp-owasp reader digested
#: a float with repr while its Go twin refused it, so the two parted on any
#: record that carried one.
TWINS: dict[str, tuple[str, Callable[[str], bytes]]] = {
    "mcp-owasp reader": ("cpython-ascii", _mcpowasp),
}


def twin_differences(table: dict[str, Any]) -> list[str]:
    """Every case where a Python twin of the Go encoder parts from its column."""
    out: list[str] = []
    for twin, (column, encode) in TWINS.items():
        for case in table["cases"]:
            got = _cell(encode, case["doc"])
            if got != case[column]:
                out.append(f"{case['name']!r}: the {twin} writes {got}, {column} holds "
                           f"{case[column]}")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Hold the shared JSON encoding table to the Python encoders."
    )
    parser.add_argument("--write", action="store_true", help="rewrite the table")
    args = parser.parse_args()
    table = build()
    text = render(table)
    if args.write:
        TABLE.parent.mkdir(parents=True, exist_ok=True)
        TABLE.write_text(text, encoding="ascii")
        print(f"wrote {TABLE.relative_to(REPO)}: {len(table['cases'])} cases, "
              f"{len(table['columns'])} columns")
        return 0
    if not TABLE.is_file():
        print(f"FAIL {TABLE.relative_to(REPO)} is missing; run with --write")
        return 1
    failures = differences(table, json.loads(TABLE.read_text(encoding="ascii")))
    failures += twin_differences(table)
    if not failures and TABLE.read_text(encoding="ascii") != text:
        failures.append("the table's bytes are not what --write would write")
    for failure in failures:
        print(f"FAIL {failure}")
    if failures:
        print(f"{len(failures)} difference(s); rerun with --write only if the Python change "
              "is the intended one, and the Go test then holds the Go encoders to it")
        return 1
    print(f"OK {len(table['cases'])} cases x {len(table['columns'])} columns hold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
