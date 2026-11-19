"""The corpus regenerates, forces every check, differs from its control by one field in
every reject, and refuses a verifier that denies everything."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("htx_cases_corpus", ROOT / "check_vectors.py")
generator = _load("htx_cases_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import htxcases as reader  # noqa: E402

CHECKS = reader.CHECKS
DENIED = {case[0]: case[3] for case in generator.cases() if case[2] == "deny"}
ALLOWED = [case[0] for case in generator.cases() if case[2] == "allow"]


def _records() -> dict[str, dict]:  # type: ignore[type-arg]
    return {p.parent.name: json.loads(p.read_text(encoding="utf-8"))
            for p in (ROOT / "cases").glob("*/record.json")}


def _manifest() -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {p.relative_to(ROOT): p.read_bytes()
                 for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")] if p.is_file()}
    regenerated = {p.relative_to(tmp_path): p.read_bytes()
                   for p in tmp_path.rglob("*") if p.is_file()}
    assert regenerated == committed


def test_reference_reader_agrees_with_every_case() -> None:
    answered, errors = corpus.check()
    assert errors == []
    assert answered == len(generator.cases())


def test_counts_come_from_the_manifest() -> None:
    assert _manifest()["counts"] == {"allow": len(ALLOWED), "deny": len(DENIED)}


def test_every_expected_result_is_accept_or_reject_with_the_reader_reason() -> None:
    for entry in _manifest()["vectors"]:
        expected, htx = entry["expected"], entry["htxExpected"]
        assert htx["result"] == {"allow": "accept", "deny": "reject"}[expected["decision"]]
        assert ("reason" in htx) == (expected["decision"] == "deny")
        assert htx.get("reason", expected["reason"]) == expected["reason"]


@pytest.mark.parametrize("name", sorted(DENIED))
def test_each_reject_differs_from_its_control_by_exactly_one_field(name: str) -> None:
    entry = next(e for e in _manifest()["vectors"] if e["id"] == name)
    records = _records()
    assert generator.diff_paths(records[entry["control"]], records[name]) == [entry["changedField"]]
    assert entry["control"] in ALLOWED


@pytest.mark.parametrize("name", sorted(DENIED))
def test_each_denied_case_fails_exactly_its_named_check(name: str) -> None:
    record, reason = _records()[name], DENIED[name]
    assert reader._first_failure(record, frozenset()) == reason
    shape = reader.shape(record)
    assert shape is not None, f"{name}: the reader names no shape for this record"
    later = reader.CHECKS_FOR[shape]
    assert reader._first_failure(record, frozenset(later[later.index(reason):])) is None


@pytest.mark.parametrize("name", CHECKS)
def test_every_check_is_forced_by_some_case(name: str) -> None:
    _, errors = corpus.check(skip=frozenset({name}))
    assert errors, f"switching off {name} changed no verdict"


def test_a_record_in_neither_shape_is_denied() -> None:
    assert reader._first_failure({"action": {}}, frozenset()) == reader.SHAPE_UNKNOWN


def test_declined_consent_with_nothing_disclosed_is_not_a_disclosure_failure() -> None:
    record = _records()["reject-consent-declined-with-disclosure"]
    record["disclosure"]["fields"] = []
    assert reader._first_failure(record, frozenset()) is None


def test_verifier_that_denies_everything_fails_the_controls(tmp_path: Path) -> None:
    script = tmp_path / "deny.py"
    script.write_text('import json, sys\nprint(json.dumps({"decision": "deny", '
                      '"reason": "not-confirmed"}))\nsys.exit(1)\n', encoding="ascii")
    _, errors = corpus.check(f"{sys.executable} {script}")
    assert set(ALLOWED) <= _failed(errors)


def test_missing_verifier_does_not_count_as_answered(tmp_path: Path) -> None:
    answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
    assert answered == 0 and errors
