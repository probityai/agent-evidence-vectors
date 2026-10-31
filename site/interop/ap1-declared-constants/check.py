#!/usr/bin/env python3
"""Refuse a declared constant that its derivation never consumes.

AP-1's grounding rule lets a declared constant ground an operand. Erratum E3 in
zorrzai/ap1-run records the failure this admits: Q07 declared the constant 4,
its computation never used it, and every operand equal to 4 resolved as
grounded. ap1-run's own seal check (`seal_constants.declared_constants_check`)
covers the other direction only, a constant used and not declared, and its test
`test_e3b_ast_check_allows_unused_constants` requires that a declared, unused
constant pass.

This check reads a ground-truth module as source and never imports or runs it.
For every `derive_*` function it collects each `{"constant": "<value>"}` the
function declares and every numeric literal its computation uses (a `D("...")`
or `Decimal("...")` call, or a bare number), and reports each declared constant
whose value the computation never uses. Values are compared as decimals, so
"12" and "12.0" are one constant.

Limit: the comparison is per function, not per step. A constant declared on one
step and used only in another passes. A literal used for something other than
arithmetic (an index, a precision) counts as used, so the check can miss an
unconsumed constant and cannot invent one.

Usage: check.py GROUND_TRUTH_MODULE [--json]. Exit 0 when every declared
constant is consumed, 1 when one is not, 2 when the input cannot be read.
"""

from __future__ import annotations

import ast
import json
import sys
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation

DECIMAL_CALLS = frozenset({"D", "Decimal"})


@dataclass
class Derivation:
    """One derive_* function: what it declares and what it computes with."""

    name: str
    declared: list[tuple[str, int]] = field(default_factory=list)
    used: set[Decimal] = field(default_factory=set)

    def unconsumed(self) -> list[tuple[str, int]]:
        return [
            (value, line)
            for value, line in self.declared
            if _number(value) not in self.used
        ]


def _number(text: str) -> Decimal | None:
    try:
        return Decimal(text)
    except InvalidOperation:
        return None


def _declared_dicts(fn: ast.FunctionDef) -> tuple[list[tuple[str, int]], set[int]]:
    """Every {"constant": "<value>"} literal, and the ids of its value nodes."""
    found: list[tuple[str, int]] = []
    skip: set[int] = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values, strict=True):
            if (
                isinstance(key, ast.Constant)
                and key.value == "constant"
                and isinstance(value, ast.Constant)
                and isinstance(value.value, str)
            ):
                found.append((value.value, value.lineno))
                skip.add(id(value))
    return found, skip


def _used_literals(fn: ast.FunctionDef, skip: set[int]) -> set[Decimal]:
    """Every number the function's code uses outside the declarations."""
    used: set[Decimal] = set()
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in DECIMAL_CALLS
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        ):
            number = _number(node.args[0].value)
            if number is not None:
                used.add(number)
        elif (
            isinstance(node, ast.Constant)
            and id(node) not in skip
            and isinstance(node.value, int | float)
            and not isinstance(node.value, bool)
        ):
            used.add(Decimal(str(node.value)))
    return used


def read_derivations(source: str) -> list[Derivation]:
    tree = ast.parse(source)
    out: list[Derivation] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name.startswith("derive_"):
            declared, skip = _declared_dicts(node)
            out.append(Derivation(node.name, declared, _used_literals(node, skip)))
    return out


def report(derivations: list[Derivation]) -> dict[str, object]:
    findings = [
        {"derivation": d.name, "constant": value, "line": line}
        for d in derivations
        for value, line in d.unconsumed()
    ]
    return {
        "check": "declared-constant-consumed",
        "derivations": len(derivations),
        "declaredConstants": sum(len(d.declared) for d in derivations),
        "unconsumed": findings,
        "result": "fail" if findings else "pass",
    }


def main(argv: list[str]) -> int:
    if not argv or argv[0].startswith("-"):
        print(__doc__.strip().splitlines()[-2], file=sys.stderr)
        return 2
    try:
        # A byte-order mark is legal at the start of a Python source file.
        with open(argv[0], encoding="utf-8-sig") as fh:
            source = fh.read()
        derivations = read_derivations(source)
    except (OSError, SyntaxError, UnicodeDecodeError) as exc:
        print(f"cannot read {argv[0]}: {exc}", file=sys.stderr)
        return 2
    if not derivations:
        print(
            f"{argv[0]} defines no derive_* function, so nothing was checked",
            file=sys.stderr,
        )
        return 2
    result = report(derivations)
    if "--json" in argv[1:]:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        for row in result["unconsumed"]:  # type: ignore[union-attr]
            print(
                f"FAIL {row['derivation']} declares constant {row['constant']} "
                f"(line {row['line']}) and never uses it"
            )
        print(
            f"{result['result'].upper()} {result['derivations']} derivations, "  # type: ignore[union-attr]
            f"{result['declaredConstants']} declared constants"
        )
    return 1 if result["unconsumed"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
