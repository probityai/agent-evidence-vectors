"""The corpus regenerates from real ledger runs, forces every check in order, reproduces
the mutation table, and passes the unmodified P04 ledger through the runtime contract
while failing every mutant the table says a scenario kills."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "tests" / "billing_adapter.py"


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("execution_billing_corpus", ROOT / "check_vectors.py")
generator = _load("execution_billing_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import executionbilling as reader  # noqa: E402
from agent_evidence_vectors import executionbilling_runtime as runtime  # noqa: E402

MANIFEST = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
DENIED = {c[0]: c[5] for c in generator.cases() if c[4] == "deny"}


def _record(name: str) -> dict:  # type: ignore[type-arg]
    loaded: dict = json.loads(  # type: ignore[type-arg]
        (ROOT / "cases" / name / "record.json").read_text(encoding="utf-8"))
    return loaded


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {
        p.relative_to(ROOT): p.read_bytes()
        for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")] if p.is_file()
    }
    regenerated = {p.relative_to(tmp_path): p.read_bytes()
                   for p in tmp_path.rglob("*") if p.is_file()}
    assert regenerated == committed


def test_reference_reader_agrees_with_every_case() -> None:
    answered, errors = reader.check()
    assert errors == []
    assert answered == len(MANIFEST["vectors"]) == 21


def test_corpus_digest_routine_recomputes_the_manifest() -> None:
    assert generator.corpus_digest(MANIFEST, str(ROOT)) == MANIFEST["corpusDigest"]


@pytest.mark.parametrize("check", reader.CHECKS)
def test_every_check_is_forced_by_a_member(check: str) -> None:
    """Switching one check off moves at least one member, and only to a later reason."""
    forced = [name for name, reason in DENIED.items() if reason == check]
    assert forced, f"no member names {check}"
    for name in forced:
        moved = reader.verify(ROOT / "cases" / name / "record.json", frozenset({check}))
        assert moved != {"decision": "deny", "reason": check}
        if moved["decision"] == "deny":
            assert reader.CHECKS.index(moved["reason"]) > reader.CHECKS.index(check)


def test_dispatch_state_is_required_in_every_state() -> None:
    record = _record("allow-x1-invoice-before-dispatch")
    for index, state in enumerate(reader.states(record)):
        for value in (None, False, "reserved", 0):
            broken = json.loads(json.dumps(record))
            list(reader.states(broken))[index]["dispatchState"] = value
            assert reader.decide(broken)["reason"] == "dispatch_state_missing"


def test_an_integer_is_not_a_boolean_return() -> None:
    record = _record("allow-x1-invoice-before-dispatch")
    record["probes"][0]["return"]["dispatchAllowed"] = 0
    assert reader.decide(record) == {"decision": "deny", "reason": "record_malformed"}


def test_scenarios_carry_no_expected_value() -> None:
    shipped = reader.shipped_scenarios(ROOT)
    assert [s["id"] for s in shipped] == ["F01", "F05", "F03", "F04", "F14", "X1"]
    assert "expect" not in json.dumps(shipped) and "raises" not in json.dumps(shipped)


def test_mutation_table_matches_the_published_classification() -> None:
    killed = {row["id"]: sorted(row["killedBy"]) for row in MANIFEST["mutants"]}
    assert killed == {
        "M1-guard-removed": ["F03", "F04", "X1"],
        "M2-final-billing-bypasses-guard": ["F04", "X1"],
        "M3-billing-clause-removed": [],
        "M4-invoice-possible-write-removed": ["X1"],
        "M5-M3-plus-M4": ["X1"],
        "success-releases-exposure": ["F01", "F05"],
        "invoice-implies-execution": ["F04", "X1"],
    }
    assert [row["id"] for row in MANIFEST["mutants"] if row["equivalent"]] == [
        "M3-billing-clause-removed"]
    assert MANIFEST["mutants"][3]["killedBy"] == {"X1": "dispatch_state_reserved_after_billing"}


def test_unmodified_ledger_passes_the_runtime_contract(tmp_path: Path) -> None:
    report = runtime.check_runtime([sys.executable, str(ADAPTER)], ROOT)
    assert report["failures"] == []
    assert report["verifier"]["vectorsExecuted"] == report["totals"]["vectors"] == 6


@pytest.mark.parametrize("row", MANIFEST["mutants"], ids=lambda r: r["id"])
def test_runtime_contract_fails_each_mutant_where_the_table_says(row: dict, tmp_path: Path) -> None:  # type: ignore[type-arg]
    source = generator.mutant_source(row["id"], tmp_path)
    report = runtime.check_runtime([sys.executable, str(ADAPTER), "--source", str(source)], ROOT)
    failed = {failure.split(":")[0] for failure in report["failures"]}
    assert failed == set(row["killedBy"])


def test_a_runtime_that_prints_nothing_did_not_pass(tmp_path: Path) -> None:
    silent = tmp_path / "silent.py"
    silent.write_text("import sys\nsys.exit(0)\n", encoding="utf-8")
    report = runtime.check_runtime([sys.executable, str(silent)], ROOT)
    assert report["totals"]["fail"] == 6


def test_damaged_corpus_is_refused(tmp_path: Path) -> None:
    import shutil

    copied = tmp_path / "corpus"
    shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("__pycache__"))
    path = copied / "cases" / "allow-f14-first-dispatch" / "record.json"
    path.write_text(path.read_text(encoding="utf-8").replace('"RESERVED"', '"POSSIBLE"', 1),
                    encoding="utf-8")
    _, errors = reader.check(None, copied)
    assert errors == ["allow-f14-first-dispatch: fixture digest mismatch"]


def test_checker_entry_point_answers_every_case() -> None:
    assert corpus.main([]) == 0
