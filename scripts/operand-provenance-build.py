#!/usr/bin/env python3
"""Build the declared-constant operand provenance cases.

Each supported case is an operand classification a consumer should accept. Each
refused case changes one thing about a supported twin and states the first check
that must refuse it. The derivations follow the shape of a quarterly net-return
item: a monthly return from a balance and an annual rate, less a fee, times the
months in a quarter.

    python scripts/operand-provenance-build.py           # write the corpus
    python scripts/operand-provenance-build.py --check   # exit 1 if it differs
"""

from __future__ import annotations

import argparse
import copy
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

PACKAGING = Path(__file__).resolve().parents[1] / "packaging"
sys.path.insert(0, str(PACKAGING))

from agent_evidence_vectors.operand_provenance.reader import (  # noqa: E402
    SUITE,
    judge,
    sha256_hex,
)

CORPUS = PACKAGING / "agent_evidence_vectors/operand_provenance/corpus"
S, C, N, X = "supported", "contradicted", "not_established", "no_verdict"
REFERENCE = "quarterly-net-reference"
QUARTERLY_ROUTE = "quarterly-net-annual-over-quarters"


def constants(*pairs: tuple[str, str]) -> list[dict[str, str]]:
    return [{"id": name, "value": value} for name, value in pairs]


BASE = constants(("percent", "100"), ("months_per_year", "12"), ("months_per_quarter", "3"))
QUARTERS = ("quarters_per_year", "4")


def derivation(ident: str, declared: list[dict[str, str]],
               reads: list[dict[str, str]] | None) -> dict[str, Any]:
    return {"id": ident, "declared_constants": declared, "executed_reads": reads}


def case(derivations: list[dict[str, Any]], value: str, grounding: dict[str, str],
         note: str) -> dict[str, Any]:
    return {
        "suite": SUITE,
        "note": note,
        "derivations": derivations,
        "operand": {"value": value, "grounding": grounding},
    }


def claim(constant: str, on: str = REFERENCE) -> dict[str, str]:
    return {"kind": "constant", "derivation": on, "constant": constant}


ORIGINATED = {"kind": "originated"}
WITH_QUARTERS = [*BASE, {"id": QUARTERS[0], "value": QUARTERS[1]}]


def consumed() -> dict[str, Any]:
    return case([derivation(REFERENCE, WITH_QUARTERS, WITH_QUARTERS)], "4",
                claim("quarters_per_year"),
                "The derivation declares the constant and its computation reads it.")


def not_consumed() -> dict[str, Any]:
    return case([derivation(REFERENCE, WITH_QUARTERS, BASE)], "4", claim("quarters_per_year"),
                "The declared-but-unconsumed constant: declared, never read by the "
                "computation, and claimed as the operand's grounding.")


def not_declared(grounding: dict[str, str]) -> dict[str, Any]:
    return case([derivation(REFERENCE, BASE, BASE)], "4", grounding,
                "The constant appears in neither the declaration nor the computation.")


RATE = ("monthly_rate", "0.0065")


def precision(read: str) -> dict[str, Any]:
    declared = [*BASE, {"id": RATE[0], "value": RATE[1]}]
    reads = [*BASE, {"id": RATE[0], "value": read}]
    return case([derivation(REFERENCE, declared, reads)], RATE[1], claim(RATE[0]),
                f"The constant is declared as {RATE[1]}; the computation read {read}.")


def routes(on: str) -> dict[str, Any]:
    reference = derivation(REFERENCE, WITH_QUARTERS, BASE)
    route = derivation(QUARTERLY_ROUTE, constants(("percent", "100"), QUARTERS),
                       constants(("percent", "100"), QUARTERS))
    return case([reference, route], "4", claim("quarters_per_year", on),
                "A second route that divides the annual figure by four is declared as its "
                "own derivation, with its own reads; the claim names the derivation.")


def edited(base: dict[str, Any], path: tuple[Any, ...], value: Any) -> dict[str, Any]:
    out = copy.deepcopy(base)
    target = out
    for key in path[:-1]:
        target = target[key]
    if value is ...:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return out


CASES: list[tuple[str, str, dict[str, Any], str, str, str | None]] = [
    ("accept-constant-declared-and-consumed", "consumed", consumed(), S,
     "constant_declared_and_consumed", None),
    ("reject-constant-declared-not-consumed", "consumed", not_consumed(), C,
     "constant_declared_not_consumed", "accept-constant-declared-and-consumed"),
    ("accept-operand-originated", "declared", not_declared(ORIGINATED), S,
     "operand_originated", None),
    ("reject-constant-not-declared", "declared", not_declared(claim("quarters_per_year")), C,
     "constant_not_declared", "accept-operand-originated"),
    ("accept-constant-read-at-declared-value", "precision", precision(RATE[1]), S,
     "constant_declared_and_consumed", None),
    ("accept-constant-read-with-trailing-zero", "precision", precision("0.00650"), S,
     "constant_declared_and_consumed", None),
    ("reject-constant-read-rounded", "precision", precision("0.007"), C,
     "constant_value_differs_at_declared_precision", "accept-constant-read-at-declared-value"),
    ("reject-constant-read-extended", "precision", precision("0.00651"), C,
     "constant_value_differs_at_declared_precision", "accept-constant-read-at-declared-value"),
    ("reject-operand-value-differs", "operand", edited(consumed(), ("operand", "value"), "4.01"),
     C, "operand_value_differs", "accept-constant-declared-and-consumed"),
    ("reject-consumption-unobservable", "observed",
     edited(consumed(), ("derivations", 0, "executed_reads"), None), N,
     "consumption_unobservable", "accept-constant-declared-and-consumed"),
    ("reject-executed-reads-absent", "form",
     edited(consumed(), ("derivations", 0, "executed_reads"), ...), X,
     "malformed_case:derivations.executed_reads", "accept-constant-declared-and-consumed"),
    ("accept-second-route-reads-constant", "route", routes(QUARTERLY_ROUTE), S,
     "constant_declared_and_consumed", None),
    ("reject-claim-names-route-that-did-not-read", "route", routes(REFERENCE), C,
     "constant_declared_not_consumed", "accept-second-route-reads-constant"),
]


def _encode(data: dict[str, Any]) -> bytes:
    return (json.dumps(data, indent=2, sort_keys=True) + "\n").encode()


def render() -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    entries = []
    for ident, control, body, decision, reason, twin in CASES:
        expected = {"decision": decision, "reason": reason}
        if judge(body) != expected:
            raise SystemExit(f"{ident}: the reader answers {judge(body)}, expected {expected}")
        data = _encode(body)
        out[f"cases/{ident}/case.json"] = data
        entry: dict[str, Any] = {"id": ident, "control": control, "expected": expected,
                                 "files": {"case.json": sha256_hex(data)}}
        if twin is not None:
            entry["twin"] = twin
        entries.append(entry)
    manifest = {
        "suite": SUITE,
        "derived_from": ("zorrzai/ap1-run FINDINGS_ERRATA.md erratum E3 at "
                         "650084da6927b3b97e81d3b160b0c6da646ea25a"),
        "corpusDigest": sha256_hex(json.dumps(entries, sort_keys=True).encode()),
        "cases": entries,
    }
    out["MANIFEST.json"] = _encode(manifest)
    return out


def _tree(root: Path) -> dict[str, bytes]:
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in sorted(root.rglob("*")) if p.is_file()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    files = render()
    if args.check:
        if not CORPUS.is_dir() or _tree(CORPUS) != files:
            print("the committed corpus differs from what the builder writes; run without --check")
            return 1
        print(f"{SUITE}: committed corpus matches the builder")
        return 0
    with tempfile.TemporaryDirectory() as scratch:
        staged = Path(scratch) / "corpus"
        for name, data in files.items():
            target = staged / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        if CORPUS.exists():
            shutil.rmtree(CORPUS)
        shutil.copytree(staged, CORPUS)
    print(f"{SUITE}: wrote the corpus")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
