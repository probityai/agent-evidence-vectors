#!/usr/bin/env python3
"""Executes the Statement-layer verdict the manifest records, rather than trusting it.

Three reject vectors carry an absent `predicate`, `"predicate": null` and
`"predicate": {}`. An AEE verifier must reject all three -- the empty predicate
lacks every required member -- and an in-toto Statement parser must accept all
three, because the framework types `predicate` as optional and says "Unset is
treated the same as set-but-empty" (in-toto/attestation spec/v1/statement.md
lines 62-66). The manifest records the second half as a `statementLayer` field
on each of the three. A field nobody executes is a sentence, so this file runs a
Statement-layer check over the three and holds the recorded verdict to it.

The check is the Statement layer and nothing more: a JSON object whose `_type`
is the v1 Statement type, a non-empty `subject` whose every element carries a
non-empty `digest` object, a non-empty string `predicateType`, and a `predicate`
that is absent, null or an object. It does not read the predicate, because the
Statement layer does not.

Two controls keep it from passing vacuously. The check must REFUSE statements
that break the Statement layer (a predicate that is a string, an array or a
number; no predicateType; no subject), or a check that accepted everything would
pass every case here. And a reading that refuses an unset predicate -- the one
the reference in-toto bindings shipped until in-toto/attestation#598, where the
Go binding refused the absent and null spellings and the Python binding refused
all three -- must FAIL on these vectors, which is what makes them worth running
against a Statement parser at all.

Usage: python3 scripts/statement-layer-test.py
Exit 0 when every case holds; 1 on a summary of the failures.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
VECTORS = REPO / "vectors"
GEN = VECTORS / "gen_manifest.py"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
CONDITION = "aee-c-109"
ABSENT = "absent"


def statement_layer_verdict(stmt: Any) -> str:
    """The in-toto Statement layer's verdict on a parsed statement: valid or invalid."""
    if not isinstance(stmt, dict) or stmt.get("_type") != STATEMENT_TYPE:
        return "invalid"
    subject = stmt.get("subject")
    if not isinstance(subject, list) or not subject:
        return "invalid"
    for element in subject:
        digest = element.get("digest") if isinstance(element, dict) else None
        if not isinstance(digest, dict) or not digest:
            return "invalid"
    ptype = stmt.get("predicateType")
    if not isinstance(ptype, str) or not ptype:
        return "invalid"
    # Optional: absent, null and an object are all the Statement layer allows.
    # Unset is treated the same as set-but-empty.
    predicate = stmt.get("predicate")
    if predicate is not None and not isinstance(predicate, dict):
        return "invalid"
    return "valid"


def refusing_unset_verdict(stmt: Any) -> str:
    """The reading the reference bindings shipped before the fix: a predicate is required."""
    if not isinstance(stmt.get("predicate"), dict) or not stmt["predicate"]:
        return "invalid"
    return statement_layer_verdict(stmt)


def _manifest() -> dict[str, Any]:
    with open(VECTORS / "MANIFEST.json", encoding="utf-8") as fh:
        loaded: dict[str, Any] = json.load(fh)
    return loaded


def _recorded() -> list[dict[str, Any]]:
    """Every entry carrying a Statement-layer verdict, or a refusal if there is none."""
    entries = [v for v in _manifest()["vectors"] if "statementLayer" in v]
    if not entries:
        raise AssertionError(
            "no manifest entry carries statementLayer; regenerate with "
            "python3 vectors/gen_manifest.py"
        )
    return entries


def _load(entry: dict[str, Any]) -> Any:
    with open(VECTORS / entry["file"], encoding="utf-8") as fh:
        return json.load(fh)


def _spelling(stmt: dict[str, Any]) -> str:
    return ABSENT if "predicate" not in stmt else json.dumps(stmt["predicate"])


def case_recorded_verdict_is_the_executed_one() -> None:
    """Each recorded Statement-layer verdict is what the check computes."""
    for entry in _recorded():
        got = statement_layer_verdict(_load(entry))
        want = entry["statementLayer"]["verdict"]
        if got != want:
            raise AssertionError(f"{entry['id']}: recorded {want}, the check says {got}")


def case_the_three_spellings_and_only_them() -> None:
    """The recorded entries are exactly the members citing the condition, one per spelling."""
    citing = {v["id"] for v in _manifest()["vectors"] if CONDITION in v["conditions"]}
    recorded = {e["id"] for e in _recorded()}
    if citing != recorded:
        raise AssertionError(f"cite {CONDITION}: {sorted(citing)}; recorded: {sorted(recorded)}")
    spellings = sorted(_spelling(_load(e)) for e in _recorded())
    if spellings != sorted([ABSENT, "null", "{}"]):
        raise AssertionError(f"expected absent, null and {{}}; got {spellings}")


def case_the_three_differ_only_in_predicate() -> None:
    """Strip `predicate` and the three are one statement, so the verdict can only come from it."""
    stripped = []
    for entry in _recorded():
        stmt = copy.deepcopy(_load(entry))
        stmt.pop("predicate", None)
        stripped.append(json.dumps(stmt, sort_keys=True))
    if len(set(stripped)) != 1:
        raise AssertionError("the recorded statements differ outside `predicate`")


def case_the_two_layers_disagree_by_design() -> None:
    """The AEE layer rejects what the Statement layer accepts; both are recorded."""
    for entry in _recorded():
        if entry["kind"] != "reject" or entry["expected"]["verdict"] != "invalid":
            raise AssertionError(f"{entry['id']}: the AEE expectation is not a rejection")
        if entry["statementLayer"]["verdict"] != "valid":
            raise AssertionError(f"{entry['id']}: the Statement layer should accept it")


def case_the_check_refuses_what_the_statement_layer_refuses() -> None:
    """Negative controls: a check that accepted everything would pass the cases above."""
    base = _load(_recorded()[0])
    base.pop("predicate", None)
    broken: dict[str, Callable[[dict[str, Any]], None]] = {
        "predicate a string": lambda s: s.__setitem__("predicate", "x"),
        "predicate an array": lambda s: s.__setitem__("predicate", []),
        "predicate a number": lambda s: s.__setitem__("predicate", 0),
        "no predicateType": lambda s: s.pop("predicateType"),
        "empty subject": lambda s: s.__setitem__("subject", []),
        "subject without digest": lambda s: s.__setitem__("subject", [{"name": "a"}]),
        "wrong _type": lambda s: s.__setitem__("_type", "https://in-toto.io/Statement/v0.1"),
    }
    for name, edit in broken.items():
        stmt = copy.deepcopy(base)
        edit(stmt)
        if statement_layer_verdict(stmt) != "invalid":
            raise AssertionError(f"the check accepted a statement with {name}")


def case_a_reading_that_requires_the_predicate_fails() -> None:
    """The pre-fix binding reading disagrees with the record: the vectors discriminate."""
    wrong = [e["id"] for e in _recorded() if refusing_unset_verdict(_load(e)) != "valid"]
    if len(wrong) != len(_recorded()):
        raise AssertionError(
            f"a reading that requires a non-empty predicate passed {len(_recorded()) - len(wrong)} "
            "of the recorded members, so they do not separate it from the Statement layer"
        )


def case_generator_refuses_a_stale_key() -> None:
    """A Statement-layer key reaching no member is a refusal, never a silently dropped claim."""
    spec = importlib.util.spec_from_file_location("gen_manifest_under_test", GEN)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {GEN}")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    try:
        gen.apply_statement_layer([{"id": "v0", "conditions": ["aee-c-1"]}])
    except SystemExit as exc:
        if "no vector cites" not in str(exc):
            raise AssertionError(f"refused for the wrong reason: {exc}") from exc
        return
    raise AssertionError("a key no member cites was accepted")


CASES: list[Callable[[], None]] = [
    case_recorded_verdict_is_the_executed_one,
    case_the_three_spellings_and_only_them,
    case_the_three_differ_only_in_predicate,
    case_the_two_layers_disagree_by_design,
    case_the_check_refuses_what_the_statement_layer_refuses,
    case_a_reading_that_requires_the_predicate_fails,
    case_generator_refuses_a_stale_key,
]


def main() -> int:
    failures: list[str] = []
    for case in CASES:
        try:
            case()
        except Exception as exc:  # noqa: BLE001 -- every case is reported, not the first
            failures.append(f"{case.__name__}: {exc}")
        else:
            print(f"ok {case.__name__}")
    for line in failures:
        print(f"FAIL {line}", file=sys.stderr)
    print(f"{len(CASES) - len(failures)}/{len(CASES)} cases held")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
