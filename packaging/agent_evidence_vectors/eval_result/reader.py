"""Read the attributes of an evaluation result the way a consumer must, and refuse the rest.

An evaluation result is the attribute set of a ``gen_ai.evaluation.result`` event plus the
evidence items it rests on. This reader derives three things from what the producer
declared, and from nothing else:

* **Score direction.** A score is ordered only under a declared ``maximize`` or
  ``minimize``. A name such as ``toxicity`` never stands in for a declaration.
* **Evidence origin.** Each evidence item names who produced it. An item the evaluated agent
  wrote is ``self_reported``; a party that later checked it does not change that. Producer
  origin and verifier identity are separate fields and are read separately.
* **Held-out status.** ``true``, ``false`` and absent are three different states. Absent
  means unknown, and unknown is not false.

``read`` returns ``{"readings", "ordering", "reasons"}``. A reason is a code from ``CODES``;
a clean input has none. The module is stdlib-only and offline.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Container, Iterable
from typing import Any

from ..invocation_axes.reader import MalformedInput

__all__ = [
    "CODES",
    "MalformedInput",
    "ORIGINS",
    "parse_strict",
    "read",
    "sha256_tag",
]

NAME = "gen_ai.evaluation.name"
VALUE = "gen_ai.evaluation.score.value"
DIRECTION = "gen_ai.evaluation.score.direction"
EVALUATOR_ID = "gen_ai.evaluation.evaluator.id"
EVALUATOR_VERSION = "gen_ai.evaluation.evaluator.version"
INPUT_ORIGIN = "gen_ai.evaluation.input.origin"
HELD_OUT = "gen_ai.evaluation.items.held_out"

DIRECTIONS = ("maximize", "minimize")
ORIGINS = ("self_reported", "system_generated", "evaluator_obtained", "external")

#: One reason code per rule. Each rule is a function below that can be disabled by name.
CODES = (
    "direction_undeclared",
    "direction_invalid",
    "direction_conflict",
    "evaluator_differs",
    "origin_missing",
    "origin_invalid",
    "origin_mismatch",
    "origin_contradicts_producer",
    "self_verified",
    "held_out_invalid",
    "held_out_unknown",
    "not_held_out",
)
BLOCKS_ORDERING = frozenset(
    {"direction_undeclared", "direction_invalid", "direction_conflict", "evaluator_differs"}
)


def sha256_tag(data: bytes) -> str:
    """The digest tag of ``data``: ``sha256:`` and 64 lowercase hex digits."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise MalformedInput(f"duplicate object member {key!r}")
        out[key] = value
    return out


def parse_strict(data: bytes) -> Any:
    """Parse UTF-8 JSON, refusing duplicate object members and non-finite numbers."""

    def refuse(token: str) -> Any:
        raise MalformedInput(f"{token} is not a JSON number")

    try:
        return json.loads(
            data.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=refuse
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MalformedInput(f"not valid JSON: {exc}") from exc


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _direction_state(attrs: dict[str, Any]) -> str:
    """``maximize``, ``minimize``, ``undeclared`` or ``invalid``; never inferred from a name."""
    if DIRECTION not in attrs:
        return "undeclared"
    return attrs[DIRECTION] if attrs[DIRECTION] in DIRECTIONS else "invalid"


def _better(state: str) -> str:
    return {"maximize": "higher", "minimize": "lower"}.get(state, "unknown")


def _held_out_state(attrs: dict[str, Any]) -> str:
    if HELD_OUT not in attrs:
        return "unknown"
    value = attrs[HELD_OUT]
    if value is True:
        return "held_out"
    if value is False:
        return "not_held_out"
    return "invalid"


def _item_origin(item: dict[str, Any]) -> str:
    """``missing``, ``invalid`` or the declared origin."""
    if "origin" not in item:
        return "missing"
    return item["origin"] if item["origin"] in ORIGINS else "invalid"


def _verification(item: dict[str, Any]) -> str:
    verifier = item.get("verified_by")
    if verifier is None:
        return "none"
    return "not_independent" if verifier == item.get("produced_by") else "independent_party"


def _declared_origins(attrs: dict[str, Any]) -> list[str] | None:
    if INPUT_ORIGIN not in attrs:
        return None
    declared = attrs[INPUT_ORIGIN]
    return sorted(declared) if isinstance(declared, list) else [declared]


def _reading(result: dict[str, Any]) -> dict[str, Any]:
    attrs, items = result["attributes"], result.get("evidence", [])
    state = _direction_state(attrs)
    origins = sorted({o for o in map(_item_origin, items) if o in ORIGINS})
    return {
        "name": attrs.get(NAME),
        "better": _better(state),
        "origins": origins,
        "any_self_reported": "self_reported" in origins,
        "verification": [_verification(i) for i in items],
        "held_out": _held_out_state(attrs),
    }


def _rule_direction_invalid(case: dict[str, Any], out: set[str]) -> None:
    for result in case["results"]:
        if _direction_state(result["attributes"]) == "invalid":
            out.add("direction_invalid")


def _compared(case: dict[str, Any]) -> list[dict[str, Any]]:
    return [case["results"][i] for i in case.get("compare", [])]


def _rule_direction_undeclared(case: dict[str, Any], out: set[str]) -> None:
    if any(_direction_state(r["attributes"]) == "undeclared" for r in _compared(case)):
        out.add("direction_undeclared")


def _rule_direction_conflict(case: dict[str, Any], out: set[str]) -> None:
    seen: dict[tuple[Any, Any], set[str]] = {}
    for result in case["results"]:
        attrs = result["attributes"]
        state = _direction_state(attrs)
        if state in DIRECTIONS:
            key = (attrs.get(EVALUATOR_ID), attrs.get(EVALUATOR_VERSION))
            seen.setdefault(key, set()).add(state)
    if any(len(states) > 1 for states in seen.values()):
        out.add("direction_conflict")


def _rule_evaluator_differs(case: dict[str, Any], out: set[str]) -> None:
    pair = _compared(case)
    keys = {
        (r["attributes"].get(EVALUATOR_ID), r["attributes"].get(EVALUATOR_VERSION)) for r in pair
    }
    if len(keys) > 1:
        out.add("evaluator_differs")


def _each_item(case: dict[str, Any]) -> Iterable[tuple[dict[str, Any], dict[str, Any]]]:
    for result in case["results"]:
        for item in result.get("evidence", []):
            yield result, item


def _rule_origin_missing(case: dict[str, Any], out: set[str]) -> None:
    if any(_item_origin(i) == "missing" for _, i in _each_item(case)):
        out.add("origin_missing")


def _rule_origin_invalid(case: dict[str, Any], out: set[str]) -> None:
    if any(_item_origin(i) == "invalid" for _, i in _each_item(case)):
        out.add("origin_invalid")


def _rule_origin_mismatch(case: dict[str, Any], out: set[str]) -> None:
    for result in case["results"]:
        declared = _declared_origins(result["attributes"])
        if declared is None:
            continue
        items = sorted({_item_origin(i) for i in result.get("evidence", [])})
        if declared != items:
            out.add("origin_mismatch")


def _rule_origin_contradicts_producer(case: dict[str, Any], out: set[str]) -> None:
    agent = case.get("agent_id")
    for _, item in _each_item(case):
        origin = _item_origin(item)
        if origin not in ORIGINS or "produced_by" not in item:
            continue
        if (item["produced_by"] == agent) != (origin == "self_reported"):
            out.add("origin_contradicts_producer")


def _rule_self_verified(case: dict[str, Any], out: set[str]) -> None:
    if any(_verification(i) == "not_independent" for _, i in _each_item(case)):
        out.add("self_verified")


def _rule_held_out_invalid(case: dict[str, Any], out: set[str]) -> None:
    if any(_held_out_state(r["attributes"]) == "invalid" for r in case["results"]):
        out.add("held_out_invalid")


def _rule_held_out_required(case: dict[str, Any], out: set[str]) -> None:
    if not case.get("rule", {}).get("require_held_out"):
        return
    for result in case["results"]:
        state = _held_out_state(result["attributes"])
        if state == "unknown":
            out.add("held_out_unknown")
        elif state == "not_held_out":
            out.add("not_held_out")


_RULE_FUNCTIONS = {
    "direction_invalid": _rule_direction_invalid,
    "direction_undeclared": _rule_direction_undeclared,
    "direction_conflict": _rule_direction_conflict,
    "evaluator_differs": _rule_evaluator_differs,
    "origin_missing": _rule_origin_missing,
    "origin_invalid": _rule_origin_invalid,
    "origin_mismatch": _rule_origin_mismatch,
    "origin_contradicts_producer": _rule_origin_contradicts_producer,
    "self_verified": _rule_self_verified,
    "held_out_invalid": _rule_held_out_invalid,
    # One function emits both held-out requirement codes; disabling either name disables it.
    "held_out_unknown": _rule_held_out_required,
    "not_held_out": _rule_held_out_required,
}


def _ordering(case: dict[str, Any], reasons: Container[str]) -> dict[str, Any] | None:
    if "compare" not in case:
        return None
    pair = list(case["compare"])
    if any(code in reasons for code in BLOCKS_ORDERING):
        return {"compared": pair, "verdict": "not_comparable"}
    first, second = (r["attributes"] for r in _compared(case))
    if not (_is_number(first.get(VALUE)) and _is_number(second.get(VALUE))):
        raise MalformedInput("a compared result carries no numeric score value")
    if first[VALUE] == second[VALUE]:
        return {"compared": pair, "verdict": "tie"}
    direction = first.get(DIRECTION)
    if direction not in DIRECTIONS or second.get(DIRECTION) != direction:
        return {"compared": pair, "verdict": "not_comparable"}
    higher_first = first[VALUE] > second[VALUE]
    wins_first = higher_first if direction == "maximize" else not higher_first
    return {"compared": pair, "verdict": "first_better" if wins_first else "second_better"}


def _validate(case: Any) -> None:
    if not isinstance(case, dict) or not isinstance(case.get("results"), list):
        raise MalformedInput("an input is an object with a results list")
    for result in case["results"]:
        if not isinstance(result, dict) or not isinstance(result.get("attributes"), dict):
            raise MalformedInput("each result carries an attributes object")
        for item in result.get("evidence", []):
            if not isinstance(item, dict):
                raise MalformedInput("each evidence item is an object")
    compare = case.get("compare")
    if compare is not None and not (
        isinstance(compare, list)
        and len(compare) == 2
        and all(isinstance(i, int) and 0 <= i < len(case["results"]) for i in compare)
    ):
        raise MalformedInput("compare names two result positions")


def read(case: Any, disabled: frozenset[str] = frozenset()) -> dict[str, Any]:
    """Read ``case``; ``disabled`` names rules to switch off, for the rule-kill test only."""
    _validate(case)
    found: set[str] = set()
    for code in CODES:
        if code not in disabled:
            _RULE_FUNCTIONS[code](case, found)
    found -= disabled
    reasons = sorted(found)
    return {
        "readings": [_reading(r) for r in case["results"]],
        "ordering": _ordering(case, found),
        "reasons": reasons,
    }
