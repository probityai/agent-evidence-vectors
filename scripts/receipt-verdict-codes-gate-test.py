#!/usr/bin/env python3
"""Break the receipt verdict-code registry one way at a time; the gate must notice each."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("gate", HERE / "receipt-verdict-codes-gate.py")
assert spec and spec.loader
gate = importlib.util.module_from_spec(spec)
sys.modules["gate"] = gate
spec.loader.exec_module(gate)

registry: dict[str, Any] = json.loads(gate.REGISTRY.read_text(encoding="utf-8"))
manifest: dict[str, Any] = json.loads(gate.MANIFEST.read_text(encoding="utf-8"))
validity, policy = gate.parse_codes(gate.CODES_GO)


def entry(reg: dict[str, Any], name: str) -> dict[str, Any]:
    return next(item for item in reg["codes"] if item["code"] == name)


def drop_validity_code(reg: dict[str, Any]) -> None:
    entry(reg, "PROOF_BROKEN")["validity_codes"].remove("batch-root-mismatch")


def double_map(reg: dict[str, Any]) -> None:
    entry(reg, "MALFORMED")["validity_codes"].append("batch-root-mismatch")


def invent_code(reg: dict[str, Any]) -> None:
    entry(reg, "MALFORMED")["validity_codes"].append("no-such-code")


def rename_verdict(reg: dict[str, Any]) -> None:
    entry(reg, "MALFORMED")["code"] = "BROKEN_BADLY"


def swap_vector(reg: dict[str, Any]) -> None:
    entry(reg, "PROOF_BROKEN")["vector"] = entry(reg, "MALFORMED")["vector"]


def wrong_tier(reg: dict[str, Any]) -> None:
    entry(reg, "NOT_RECONSTRUCTIBLE")["tier"] = "attested"


def missing_vector(reg: dict[str, Any]) -> None:
    entry(reg, "SUMMARY_MISMATCH")["vector"] = "vffffffffffffffff"


def unlist_policy_code(reg: dict[str, Any]) -> None:
    reg["outside_receipt_axis"].remove("scope-unpinned")


BREAKS: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
    ("a validity code left unmapped", drop_validity_code),
    ("a code mapped twice", double_map),
    ("a code aee/codes.go does not define", invent_code),
    ("a verdict code outside the closed seven", rename_verdict),
    ("two verdict codes on one vector", swap_vector),
    ("a limit with a tier its vector lacks", wrong_tier),
    ("a vector the manifest does not hold", missing_vector),
    ("a policy code classified nowhere", unlist_policy_code),
]


def main() -> int:
    failures = []
    if gate.check(registry, validity, policy, manifest):
        failures.append("the shipped registry does not pass")
    for label, mutate in BREAKS:
        broken = copy.deepcopy(registry)
        mutate(broken)
        if not gate.check(broken, validity, policy, manifest):
            failures.append(f"not noticed: {label}")
    for code in ("no-such-code", ""):
        try:
            gate.verdict_for(code, registry)
        except gate.UnknownCode:
            continue
        failures.append(f"verdict_for accepted unknown code {code!r}")
    if gate.verdict_for("batch-root-mismatch", registry) != "PROOF_BROKEN":
        failures.append("batch-root-mismatch does not map to PROOF_BROKEN")
    if gate.verdict_for("scope-unpinned", registry) is not None:
        failures.append("a code outside the receipt axis must map to None")
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    if not failures:
        print("receipt verdict-code gate: every break is noticed, unknown codes are refused")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
