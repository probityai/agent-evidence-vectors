"""RFC 8785 Appendix B through the Python binding.

The table is the crate's own pinned copy of the RFC's number table
(`tests/vectors/rfc8785/appendix-b.tsv` in the bound release). Two independent
checks per row, as in the crate's Rust test: the double is rebuilt from its bit
pattern and serialized, and the RFC's output is required to be its own
canonical form.
"""

from __future__ import annotations

import struct

import pytest

from conftest import bound_crate, data_lines
import jcs_admit as jcs


def rows() -> list[tuple[str, str, str]]:
    path = bound_crate("jcs-admit").root / "tests/vectors/rfc8785/appendix-b.tsv"
    out = []
    for line in data_lines(path):
        bits, expected, *comment = line.split("\t")
        if expected == "-":
            continue  # NaN and Infinity: no JSON number token denotes them.
        out.append((bits, expected, comment[0] if comment else "-"))
    return out


ROWS = rows()


def test_the_table_parsed_whole():
    # 26 rows in the RFC, minus NaN and Infinity.
    assert len(ROWS) == 24


def token(bits: str) -> bytes:
    # repr() is shortest round-trip, so the token denotes exactly this double;
    # what is under test is the serializer, not the token's spelling.
    (value,) = struct.unpack(">d", bytes.fromhex(bits))
    return repr(value).encode()


@pytest.mark.parametrize(("bits", "expected", "comment"), ROWS, ids=[r[0] for r in ROWS])
def test_row_serializes_as_the_rfc_says_from_the_bit_pattern(bits, expected, comment):
    assert jcs.admit(token(bits)) == expected.encode(), comment


@pytest.mark.parametrize(("bits", "expected", "comment"), ROWS, ids=[r[0] for r in ROWS])
def test_row_output_is_already_canonical(bits, expected, comment):
    assert jcs.admit(expected.encode()) == expected.encode()
    assert jcs.is_canonical(expected.encode())


@pytest.mark.parametrize("literal", [b"NaN", b"Infinity", b"-Infinity"])
def test_nan_and_infinity_have_no_json_token(literal):
    with pytest.raises(jcs.JcsError) as info:
        jcs.admit(literal)
    assert info.value.variant == "Syntax"


def test_a_number_past_the_double_range_is_refused_not_rounded():
    with pytest.raises(jcs.JcsError) as info:
        jcs.admit(b"1e400")
    assert info.value.variant == "NonFiniteNumber"
    assert info.value.fields == {"token": "1e400"}
