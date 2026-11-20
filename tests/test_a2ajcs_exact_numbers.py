"""The A2A canonicalizer refuses a number token that no double holds exactly.

RFC 8785 requires I-JSON input, and RFC 7493 section 2.2 rules out numbers with more precision
than an IEEE 754 double. Such a token names one number to an exact reader and another to a double
reader: a signature over the canonical bytes of ``9007199254740993`` (written ``9007199254740992``)
is read by an int64 verifier as a signature over another value, so the token has no canonical form.
The cases are the ones the ``jcs_canonical/v1`` verifier is held to, so the two canonicalizers
agree.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packaging"))

from agent_evidence_vectors import a2ajcs


def canonical(text: str) -> bytes:
    return a2ajcs.canonicalize(a2ajcs.parse(text))


@pytest.mark.parametrize(
    "text,reason",
    [
        ('{"n":9007199254740993}', "more precision than a double holds"),
        ('{"n":-9007199254740993}', "more precision than a double holds"),
        ('{"n":12345678901234567890}', "more precision than a double holds"),
        ('{"n":1e-400}', "reads as the double 0.0"),
        ('{"n":3.141592653589793238462643383279}', "reads as the double"),
        ('{"n":9007199254740993.0}', "reads as the double"),
        ('{"n":1e999}', "NaN and Infinity"),
        ('{"n":' + "9" * 400 + "}", "integer outside the IEEE 754 double range"),
    ],
)
def test_a_number_no_double_holds_exactly_has_no_canonical_form(text: str, reason: str) -> None:
    with pytest.raises(a2ajcs.Refusal, match=reason):
        canonical(text)


@pytest.mark.parametrize(
    "text,expected",
    [
        ('{"n":9007199254740991}', b'{"n":9007199254740991}'),
        ('{"n":100000000000000000000}', b'{"n":100000000000000000000}'),
        ('{"n":1180591620717411303424}', b'{"n":1.1805916207174113e+21}'),
        ('{"n":1E21}', b'{"n":1e+21}'),
        ('{"n":0.1}', b'{"n":0.1}'),
        ('{"n":1.10}', b'{"n":1.1}'),
        ('{"n":-0.0}', b'{"n":0}'),
        ('{"n":0.30000000000000004}', b'{"n":0.30000000000000004}'),
    ],
)
def test_a_number_a_double_holds_exactly_keeps_its_form(text: str, expected: bytes) -> None:
    assert canonical(text) == expected


@pytest.mark.parametrize("token", ["NaN", "Infinity", "-Infinity"])
def test_a_constant_still_parses_and_is_refused_at_canonicalization(token: str) -> None:
    value = a2ajcs.parse('{"n":' + token + "}")
    with pytest.raises(a2ajcs.Refusal, match="NaN and Infinity"):
        a2ajcs.canonicalize(value)
