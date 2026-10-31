"""Append a Lab record without rewriting the retained registry byte prefix.

The registry's closing layout is part of this operation's contract. A caller
validates the new record and writes the returned bytes; this module does not
change files or recode any earlier record.
"""

from __future__ import annotations

import json


ENDING = b"\n  ]\n}\n"


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _finite_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value: {value}")


def append_record(registry: bytes, record: dict[str, object]) -> bytes:
    """Return one appended record and the exact unchanged preceding bytes."""
    previous = json.loads(
        registry, object_pairs_hook=_unique_object, parse_constant=_finite_constant
    )
    if not isinstance(previous, dict) or not isinstance(previous.get("records"), list):
        raise ValueError("registry must contain a records array")
    if not registry.endswith(ENDING):
        raise ValueError("registry closing layout differs from the retained contract")
    records = previous["records"]
    identifiers = []
    for row in records:
        if not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"]:
            raise ValueError("existing record must have a nonempty string ID")
        identifiers.append(row["id"])
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("existing record IDs are repeated")
    if not isinstance(record, dict) or not isinstance(record.get("id"), str) or not record["id"]:
        raise ValueError("new record must have a nonempty string ID")
    if record["id"] in identifiers:
        raise ValueError("new record ID already exists")
    encoded = json.dumps(record, indent=2, ensure_ascii=True, allow_nan=False).encode()
    entry = b"\n".join(b"    " + line for line in encoded.splitlines())
    separator = b",\n" if records else b"\n"
    return registry[:-len(ENDING)] + separator + entry + ENDING
