"""Decode gate evidence without ambiguous members or nonfinite numbers."""

from __future__ import annotations

import json
import math
from typing import Any


def members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Require one value for every member at every object level."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("gate JSON repeats an object member")
        result[key] = value
    return result


def constant(_value: str) -> Any:
    """Refuse extensions that are not JSON numbers."""
    raise ValueError("gate JSON contains a nonfinite number")


def finite_float(value: str) -> float:
    """Refuse finite decimal syntax that overflows the decoder's number type."""
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("gate JSON contains a nonfinite number")
    return parsed


def decode_json(raw: bytes | str) -> Any:
    """Read original bytes with unique members and finite numbers only."""
    return json.loads(
        raw, object_pairs_hook=members, parse_constant=constant, parse_float=finite_float
    )
