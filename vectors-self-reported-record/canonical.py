"""RFC 8785 canonical JSON for the value space this corpus uses, standard library only.

Kept in its own module rather than inside the generator for the reason
`vectors-scitt-cose/digest.py` gives at length: `scripts/release-digests.py`
recomputes every corpus digest by loading the module that OWNS that corpus's
preimage, and that path has to run for somebody who installed nothing. The
generator signs, so it needs a signing library; this file and `digest.py` do
not, and between them they carry everything the verification path reaches.

The value space is deliberately narrow: null, booleans, integers, strings,
arrays and objects. There is no float anywhere in this corpus and there is no
code point above U+007F in any member name, so the two places RFC 8785 is
subtle -- number serialization, and member ordering by UTF-16 code unit rather
than by code point -- are both reachable only by a value this contract forbids.
A float raises rather than guessing, because a guess here is a silent wrong
digest, and a wrong digest is the one defect a digest exists to make loud.
"""

from __future__ import annotations

import json
from typing import Any


def _reject_floats(value: Any) -> None:
    """Refuse a float anywhere in *value*.

    `json.dumps` would happily spell one, and CPython's repr and Go's strconv
    disagree on several values, so a corpus carrying a float would name a
    different digest on each rail while both rails canonicalized correctly.
    """
    if isinstance(value, float):
        raise TypeError(
            "this corpus's canonical form covers no float: RFC 8785 number "
            "serialization is the one place two correct implementations differ, "
            "so a float is refused rather than spelled"
        )
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"a JSON member name is a string, got {type(key).__name__}")
            _reject_floats(item)
    elif isinstance(value, list):
        for item in value:
            _reject_floats(item)


def jcs(value: Any) -> bytes:
    """The RFC 8785 canonical bytes of *value*.

    Member names are sorted by UTF-16 code unit, which for the ASCII names this
    corpus uses is the same order `sort_keys=True` produces. `ensure_ascii` is
    off so a string is emitted as UTF-8 rather than escaped, which is what RFC
    8785 requires and what `json.dumps` does not do by default.
    """
    _reject_floats(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
