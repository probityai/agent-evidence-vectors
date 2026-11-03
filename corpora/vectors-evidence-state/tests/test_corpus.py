"""The corpus regenerates, forces every check in order, and refuses a verifier that
reads an unmeasured silence as clean or accepts a code its observations do not support."""

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


corpus = _load("evidence_state_corpus", ROOT / "check_vectors.py")
generator = _load("evidence_state_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import evidencestate as reader  # noqa: E402

CHECKS = reader.CHECKS
DENIED = {case[0]: case[3] for case in generator.cases() if case[2] == "deny"}
ALLOWED = [case[0] for case in generator.cases() if case[2] == "allow"]


def _records() -> dict[str, dict]:  # type: ignore[type-arg]
    return {p.parent.name: json.loads(p.read_text(encoding="utf-8"))
            for p in (ROOT / "cases").glob("*/record.json")}


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
    manifest = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["counts"] == {"allow": len(ALLOWED), "deny": len(DENIED)}


@pytest.mark.parametrize("name", sorted(DENIED))
def test_each_denied_case_fails_exactly_its_named_check(name: str) -> None:
    record, reason = _records()[name], DENIED[name]
    assert reader._first_failure(record, frozenset()) == reason
    assert reader._first_failure(record, frozenset(CHECKS[CHECKS.index(reason):])) is None


@pytest.mark.parametrize("name", CHECKS)
def test_every_check_is_forced_by_some_case(name: str) -> None:
    _, errors = corpus.check(skip=frozenset({name}))
    assert errors, f"switching off {name} changed no verdict"


def test_verifier_that_reads_an_unmeasured_silence_as_clean_is_refused() -> None:
    _, errors = corpus.check(skip=frozenset({"clean_without_coverage",
                                             "evidence_state_unsupported"}))
    assert "reject-clean-without-coverage" in _failed(errors)


def test_every_code_has_an_accepting_control() -> None:
    accepted = {reader.derive(_records()[name]["observations"]) for name in ALLOWED}
    assert accepted == set(reader.STATES)


def test_reader_judges_a_list_of_records(capsys) -> None:  # type: ignore[no-untyped-def]
    paths = [str(ROOT / "cases" / name / "record.json")
             for name in ("allow-es1", "reject-clean-without-coverage")]
    assert reader.main([*paths, "--json"]) == 1
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [line["decision"] for line in lines] == ["allow", "deny"]
    assert [line["derivedState"] for line in lines] == ["ES1", "ES0"]


def test_verifier_that_denies_everything_fails_the_controls(tmp_path: Path) -> None:
    script = tmp_path / "deny.py"
    script.write_text('import json, sys\nprint(json.dumps({"decision": "deny", '
                      '"reason": "contract_id_missing"}))\nsys.exit(1)\n', encoding="ascii")
    _, errors = corpus.check(f"{sys.executable} {script}")
    assert set(ALLOWED) <= _failed(errors)


def test_missing_verifier_does_not_count_as_answered(tmp_path: Path) -> None:
    answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
    assert answered == 0 and errors
