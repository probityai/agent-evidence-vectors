"""Bounded, strict JSON reading shared by every input this package accepts.

The profile is narrower than JSON: at most 64 KiB, strict UTF-8 with no byte-order
mark, an object at the root, unique member names at every depth, no floating-point
or non-finite numbers, integers inside the IEEE 754 safe range, and bounded depth
and node count. Anything outside it is refused before evaluation.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, NoReturn

MAX_BYTES = 65536
MAX_DEPTH = 32
MAX_NODES = 8192
SAFE_INTEGER = 2**53 - 1


class InputError(ValueError):
    """Input outside the profile: no result is produced from it."""


def refuse(message: str) -> NoReturn:
    """Raise InputError with a bounded diagnostic that never echoes input content."""
    raise InputError(message)


def unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build an object, refusing a repeated member name instead of keeping one copy."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            refuse("duplicate JSON object member")
        result[key] = value
    return result


def no_float(text: str) -> NoReturn:
    """Refuse every number spelled with a fraction or an exponent."""
    del text
    refuse("floating-point numbers are outside this profile")


def no_constant(text: str) -> NoReturn:
    """Refuse NaN and the infinities, which Python's parser accepts by default."""
    del text
    refuse("non-finite numbers are outside this profile")


def children(value: Any) -> list[Any]:
    """Nested values of an array or object, object member names included."""
    if isinstance(value, dict):
        return list(value) + list(value.values())
    return list(value) if isinstance(value, list) else []


def check_scalar(value: Any) -> None:
    """Integers stay in the safe range and strings hold Unicode scalar values only."""
    if isinstance(value, float) and not math.isfinite(value):
        refuse("non-finite numbers are outside this profile")
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            refuse("a string carries an unpaired surrogate")
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > SAFE_INTEGER:
        refuse("integer is outside the safe range")


def check_budget(value: Any) -> None:
    """Iterative depth and node budget, so a deep input cannot exhaust the stack."""
    pending = [(value, 0)]
    count = 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            refuse("JSON resource budget exceeded")
        check_scalar(item)
        pending.extend((child, depth + 1) for child in children(item))


def load_json(payload: bytes) -> dict[str, Any]:
    """Parse bytes under the profile and return the root object."""
    if len(payload) > MAX_BYTES:
        refuse("JSON byte budget exceeded")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        refuse("input is not strict UTF-8")
    if text.startswith("\ufeff"):
        refuse("a byte-order mark is outside this profile")
    try:
        value = json.loads(
            text,
            object_pairs_hook=unique_members,
            parse_float=no_float,
            parse_constant=no_constant,
        )
    except (json.JSONDecodeError, RecursionError):
        refuse("malformed JSON input")
    if not isinstance(value, dict):
        refuse("JSON root must be an object")
    check_budget(value)
    return value


def read_bounded(path: Path) -> bytes:
    """Read at most the budget plus one byte, refusing an oversized file."""
    with path.open("rb") as stream:
        payload = stream.read(MAX_BYTES + 1)
    if len(payload) > MAX_BYTES:
        refuse("JSON byte budget exceeded")
    return payload


def load_file(path: Path) -> dict[str, Any]:
    """read_bounded followed by load_json."""
    return load_json(read_bounded(path))
