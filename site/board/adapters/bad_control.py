"""A deliberately wrong canonicalizer, used only as the board's failing control.

json.dumps with sorted keys is the usual near-miss for RFC 8785: it sorts keys by code point
rather than UTF-16 code unit, spells numbers the Python way, and accepts NaN and Infinity.
The corpus is expected to fail it on exactly ten vectors.
"""
import json


def canonicalize(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
