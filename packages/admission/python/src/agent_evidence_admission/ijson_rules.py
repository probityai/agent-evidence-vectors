"""The strict parse alone, as two rule sets: any JSON record, before a format-specific reader.

``ijson`` admits numbers whose double is finite and inside +-(2**53 - 1); ``ijson-integer-only``
also refuses any fraction or exponent, for formats whose numbers are all counts. Both refuse a
repeated member at any depth, two names equal under case folding, a lone surrogate, a
noncharacter, ``-0``, a number token past 64 characters and nesting past 64 levels; see
:mod:`agent_evidence_admission.strict_json` for each code.
"""

from __future__ import annotations

from .rules import RuleSet, register

IJSON = register(
    RuleSet(
        name="ijson",
        summary="strict I-JSON parse: the byte strings two decoders read as two documents are refused",
        checks=(),
    )
)

IJSON_INTEGER_ONLY = register(
    RuleSet(
        name="ijson-integer-only",
        summary="strict I-JSON parse with integers only: a fraction or exponent is refused",
        checks=(),
        profile="integer-only",
    )
)
