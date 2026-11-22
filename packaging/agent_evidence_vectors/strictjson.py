"""The one JSON parser every reader in this package uses for bytes it did not write.

Python's ``json`` module reads three things a JSON text may not carry and keeps going:

* ``NaN``, ``Infinity`` and ``-Infinity``, which RFC 8259 section 6 does not admit as numbers.
  A reader that compares ``amount > cap`` gets ``False`` for ``NaN``, so a record whose amount
  is ``NaN`` passes every cap a policy states.
* A finite literal too large for a double, such as ``1e999``, which ``float`` turns into
  ``inf``: the same value as ``Infinity`` under a spelling no constant hook sees.
* An object that repeats a member. ``json`` keeps the last one; a reader in another language
  may keep the first, and a signature covers the bytes, so the record one reader verified is
  not the record another reader judged.

A strict reader refuses all three. :func:`loads` and :func:`load` raise :class:`NotStrictJson`
for them, and for anything else ``json`` refuses. It subclasses ``json.JSONDecodeError``, so
every reader that already maps a parse failure to its own malformed-input refusal maps these
bytes to the same refusal without a second handler.

The Go readers under ``corpusreaders/`` refuse the same bytes: ``encoding/json`` refuses the
three constants and an overflowing literal, and ``strictUnmarshal`` there refuses a repeated
member.
"""

from __future__ import annotations

import json
import math
from typing import IO, Any

__all__ = ["NotStrictJson", "load", "loads", "refuse_constant", "refuse_repeated"]


class NotStrictJson(json.JSONDecodeError):
    """Bytes a strict reader refuses: not JSON, a non-finite number, or a repeated member."""


def _refused(message: str) -> NotStrictJson:
    return NotStrictJson(message, "", 0)


def refuse_repeated(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """An ``object_pairs_hook`` that refuses an object naming one member twice.

    A reader that keeps its own ``json.loads`` call for a profile of its own (exact integers,
    no floats) passes this hook, and :func:`refuse_constant`, so the two refusals hold there too.
    """
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise _refused(f"repeated member {key!r}")
        out[key] = value
    return out


def refuse_constant(name: str) -> Any:
    """A ``parse_constant`` hook: ``NaN``, ``Infinity`` and ``-Infinity`` are not JSON numbers."""
    raise _refused(f"non-finite number {name}")


def _finite_float(literal: str) -> float:
    value = float(literal)
    if not math.isfinite(value):
        raise _refused(f"number {literal} overflows to a non-finite value")
    return value


def _text(data: str | bytes | bytearray) -> str:
    if isinstance(data, str):
        return data
    return bytes(data).decode("utf-8", "replace")


def loads(data: str | bytes | bytearray, *, parse_float: Any = None, parse_int: Any = None) -> Any:
    """Parse one JSON text, refusing what :mod:`json` lets through.

    ``parse_float`` and ``parse_int`` pass through for readers that keep numbers exact
    (``decimal.Decimal``); the constant and repeated-member refusals cannot be turned off.
    """
    try:
        return json.loads(
            data,
            object_pairs_hook=refuse_repeated,
            parse_constant=refuse_constant,
            parse_float=parse_float or _finite_float,
            parse_int=parse_int,
        )
    except NotStrictJson as exc:
        raise NotStrictJson(exc.msg, _text(data), 0) from None
    except json.JSONDecodeError as exc:
        raise NotStrictJson(exc.msg, exc.doc, exc.pos) from None
    except (ValueError, RecursionError) as exc:
        # Bytes that are not text in a JSON encoding, or nesting deeper than the
        # interpreter's stack: the same refusal, never a crash a caller has to expect.
        raise NotStrictJson(str(exc) or type(exc).__name__, _text(data), 0) from None


def load(fp: IO[str] | IO[bytes]) -> Any:
    """:func:`loads` over a file object's whole contents."""
    return loads(fp.read())
