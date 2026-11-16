"""jcs-admit as the oracle for a digest input written as sorted compact JSON.

Several record formats build a digest input with
``json.dumps(params, sort_keys=True, separators=(",", ":"), ensure_ascii=False)``
instead of RFC 8785. For a flat map of string values whose member names are
ASCII, the two encodings produce the same bytes, so ``jcs_admit.admit`` checks
such an input from any language that has the bytes. This file pins where that
holds and the three places where it does not, so a format moving from one
encoding to the other knows which of its inputs change digest.
"""

from __future__ import annotations

import json

import jcs_admit as jcs
import pytest


def sorted_compact(params: object) -> bytes:
    text = json.dumps(params, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return text.encode("utf-8")


# Flat maps of strings with ASCII member names: the encodings agree byte for byte.
AGREE = [
    {},
    {"alpn": "mcp", "port": "443"},
    {"z": "last", "a": "first", "M": "upper sorts before lower"},
    {"desc": "café ☃ \U0001f600", "ipv4hint": "192.0.2.1"},
    {"quote": 'say "hi"', "backslash": "a\\b", "slash": "a/b"},
    # Control characters: both escape \b \f \n \r \t by short form and the rest as \u00XX.
    {"ctl": "".join(chr(c) for c in range(0x20)) + "\u007f"},
    # Line and paragraph separators stay raw in both.
    {"sep": "  "},
]


@pytest.mark.parametrize("params", AGREE)
def test_flat_ascii_keyed_string_maps_agree(params):
    raw = sorted_compact(params)
    assert jcs.admit(raw) == raw
    assert jcs.is_canonical(raw)


def test_non_ascii_member_names_below_the_surrogate_block_agree():
    # Code point order and UTF-16 code unit order differ only where a name has a
    # code point at or above U+10000 and the other has one in U+E000..U+FFFF at
    # the first position where they differ. Names below that range sort the same.
    params = {"\u00fc": "b", "z": "c", "\u00e9": "a", "\u4e2d": "d"}
    raw = sorted_compact(params)
    assert jcs.admit(raw) == raw


def test_non_ascii_member_names_can_sort_differently():
    # Python sorts member names by code point; RFC 8785 sorts by UTF-16 code
    # unit. U+E000 precedes U+1F600 by code point, and the UTF-16 high
    # surrogate 0xD83D of U+1F600 precedes 0xE000.
    params = {"": "a", "\U0001f600": "b"}
    raw = sorted_compact(params)
    canonical = jcs.admit(raw)
    assert canonical != raw
    assert canonical == '{"\U0001f600":"b","":"a"}'.encode("utf-8")


@pytest.mark.parametrize(
    ("value", "python", "rfc8785"),
    [
        (1.0, b"1.0", b"1"),
        (1e16, b"1e+16", b"10000000000000000"),
        (0.000001, b"1e-06", b"0.000001"),
        # Python writes an int exactly; RFC 8785 writes the nearest double.
        (10**21, b"1000000000000000000000", b"1e+21"),
        (2**53 + 1, b"9007199254740993", b"9007199254740992"),
    ],
)
def test_number_values_part(value, python, rfc8785):
    raw = sorted_compact({"n": value})
    assert raw == b'{"n":' + python + b"}"
    assert jcs.admit(raw) == b'{"n":' + rfc8785 + b"}"


def test_a_repeated_member_name_has_no_sorted_form_to_compare():
    # A dict cannot hold a repeated name, so sorted compact JSON never writes
    # one; bytes that carry one were not produced by the encoding and are refused.
    with pytest.raises(jcs.JcsError) as info:
        jcs.admit(b'{"alpn":"mcp","alpn":"a2a"}')
    assert info.value.variant == "DuplicateMember"
