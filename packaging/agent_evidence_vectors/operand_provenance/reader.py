"""Judge whether a declared constant grounds an operand: declared is not consumed.

A provenance check classes each operand of a computation as grounded (it resolves
to a source value, a declared constant, an intermediate or an earlier grounded
result) or originated (it resolves to none of them). The failure this reader
makes executable is the declared-but-unconsumed constant: a derivation declares
a constant that its computation never reads, and the check accepts an operand as
grounded on the strength of the declaration alone.

A case models the derivation as data. Each derivation lists the constants it
declares and, separately, the constants its executed computation actually read
(``executed_reads``), each with the value it read. The operand names the value
it carries and the grounding it claims: a constant of one named derivation, or
``originated``. The rule is mechanical: a declared constant grounds an operand
only if the executed derivation read it, at the declared value.

Checks, in order, with the decision and reason of the first that fails:

1. the case is well formed (``no_verdict``, ``malformed_case:<field>``);
2. an operand classed ``originated`` makes no grounding claim, so the record's
   classification stands (``supported``, ``operand_originated``);
3. the claimed derivation exists and declares the claimed constant
   (``contradicted``, ``constant_not_declared``);
4. the operand's value equals the declared constant's value
   (``contradicted``, ``operand_value_differs``);
5. the derivation's executed reads were recorded; ``null`` means the
   consumption cannot be observed, which is never a pass
   (``not_established``, ``consumption_unobservable``);
6. the executed computation read the declared constant
   (``contradicted``, ``constant_declared_not_consumed``);
7. the value it read equals the declared value exactly as a decimal, so a
   value rounded or extended away from the declared digits fails
   (``contradicted``, ``constant_value_differs_at_declared_precision``).

A case that passes every check reads ``supported``,
``constant_declared_and_consumed``.

External-verifier contract: ``<verifier> <case-dir>/case.json --json`` prints
one JSON object carrying ``decision`` and ``reason`` and exits 0 for
``supported``, 1 for ``contradicted`` or ``not_established``, 2 for no verdict.
"""

from __future__ import annotations

import hashlib
import json
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

SUITE = "operand-provenance/declared-constant-v1"
SUPPORTED, CONTRADICTED, NOT_ESTABLISHED, NO_VERDICT = (
    "supported", "contradicted", "not_established", "no_verdict")
EXIT_FOR = {SUPPORTED: 0, CONTRADICTED: 1, NOT_ESTABLISHED: 1, NO_VERDICT: 2}
GROUNDING_KINDS = ("constant", "originated")

# Each rule can be switched off by name, so the test suite proves that removing
# any one of them changes some case's answer.
RULES = ("declared", "operand_value", "observed", "consumed", "precision")


class MalformedCase(ValueError):
    """The case cannot be judged; the message names the field."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _answer(decision: str, reason: str) -> dict[str, str]:
    return {"decision": decision, "reason": reason}


def _decimal(value: Any, field: str) -> Decimal:
    if not isinstance(value, str):
        raise MalformedCase(field)
    try:
        number = Decimal(value)
    except InvalidOperation as exc:
        raise MalformedCase(field) from exc
    if not number.is_finite():
        raise MalformedCase(field)
    return number


def _constants(entries: Any, field: str) -> dict[str, Decimal]:
    if not isinstance(entries, list):
        raise MalformedCase(field)
    table: dict[str, Decimal] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("id"), str):
            raise MalformedCase(f"{field}.id")
        if entry["id"] in table:
            raise MalformedCase(f"{field}.duplicate")
        table[entry["id"]] = _decimal(entry.get("value"), f"{field}.value")
    return table


def _derivations(case: dict[str, Any]) -> dict[str, dict[str, Any]]:
    derivations = case.get("derivations")
    if not isinstance(derivations, list) or not derivations:
        raise MalformedCase("derivations")
    parsed: dict[str, dict[str, Any]] = {}
    for derivation in derivations:
        if not isinstance(derivation, dict) or not isinstance(derivation.get("id"), str):
            raise MalformedCase("derivations.id")
        if derivation["id"] in parsed:
            raise MalformedCase("derivations.duplicate")
        reads = derivation.get("executed_reads", ...)
        if reads is ...:
            raise MalformedCase("derivations.executed_reads")
        parsed[derivation["id"]] = {
            "declared": _constants(derivation.get("declared_constants"),
                                   "derivations.declared_constants"),
            "reads": None if reads is None else _constants(reads, "derivations.executed_reads"),
        }
    return parsed


def _operand(case: dict[str, Any]) -> tuple[Decimal, dict[str, Any]]:
    operand = case.get("operand")
    if not isinstance(operand, dict):
        raise MalformedCase("operand")
    value = _decimal(operand.get("value"), "operand.value")
    claim = operand.get("grounding")
    if not isinstance(claim, dict) or claim.get("kind") not in GROUNDING_KINDS:
        raise MalformedCase("operand.grounding")
    if claim["kind"] == "constant" and not (
            isinstance(claim.get("derivation"), str) and isinstance(claim.get("constant"), str)):
        raise MalformedCase("operand.grounding.constant")
    return value, claim


def _judge_constant(value: Decimal, claim: dict[str, Any],
                    derivations: dict[str, dict[str, Any]],
                    skip: frozenset[str]) -> dict[str, str]:
    derivation = derivations.get(claim["derivation"], {"declared": {}, "reads": None})
    name = claim["constant"]
    declared = derivation["declared"].get(name)
    if declared is None:
        if "declared" not in skip:
            return _answer(CONTRADICTED, "constant_not_declared")
        declared = value
    if value != declared and "operand_value" not in skip:
        return _answer(CONTRADICTED, "operand_value_differs")
    reads = derivation["reads"]
    if reads is None:
        if "observed" not in skip:
            return _answer(NOT_ESTABLISHED, "consumption_unobservable")
        reads = {name: declared}
    if name not in reads:
        if "consumed" not in skip:
            return _answer(CONTRADICTED, "constant_declared_not_consumed")
        reads = {**reads, name: declared}
    if reads[name] != declared and "precision" not in skip:
        return _answer(CONTRADICTED, "constant_value_differs_at_declared_precision")
    return _answer(SUPPORTED, "constant_declared_and_consumed")


def judge(case: dict[str, Any], skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """Judge one parsed case; ``skip`` switches named rules off for mutation tests."""
    try:
        if case.get("suite") != SUITE:
            raise MalformedCase("suite")
        derivations = _derivations(case)
        value, claim = _operand(case)
    except MalformedCase as exc:
        return _answer(NO_VERDICT, f"malformed_case:{exc}")
    if claim["kind"] == "originated":
        return _answer(SUPPORTED, "operand_originated")
    return _judge_constant(value, claim, derivations, skip)


def verify(case_json: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """Read one case file and judge it."""
    try:
        case = json.loads(Path(case_json).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return _answer(NO_VERDICT, "malformed_case:unreadable")
    if not isinstance(case, dict):
        return _answer(NO_VERDICT, "malformed_case:not_an_object")
    return judge(case, skip)
