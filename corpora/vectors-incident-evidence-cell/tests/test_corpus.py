"""The corpus regenerates, forces every check in order, and refuses a verifier that
accepts an empty cell labelled supported or a paraphrased truth disclaimer."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parents[1]


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("incident_evidence_cell_corpus", ROOT / "check_vectors.py")
generator = _load("incident_evidence_cell_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import evidencecell as reader  # noqa: E402

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


@pytest.mark.parametrize("name", CHECKS)
def test_every_check_has_a_denied_case(name: str) -> None:
    assert name in DENIED.values()


def test_controls_cover_every_closed_value_and_an_empty_cell() -> None:
    predicates = [_records()[name]["predicate"] for name in ALLOWED]
    assert {p["response"] for p in predicates} == set(reader.RESPONSES)
    assert {p["supportLabel"] for p in predicates} == set(reader.SUPPORT_LABELS)
    assert {f"{reader.STATE_TERM}#ES{n}" for n in (0, 6, 8)} <= {p["state"] for p in predicates}
    assert any("notAddressed" in p and p["supportLabel"] == "unknown" for p in predicates)


def test_column_mapping_names_every_response_once() -> None:
    assert sorted(generator.COLUMNS.values()) == sorted(reader.RESPONSES)


def test_registry_digest_names_the_committed_snapshot() -> None:
    snapshot = (REPO / "pages" / "vocab" / "v1" / "registry"
                / f"sha256-{reader.REGISTRY_DIGEST}.yaml")
    assert hashlib.sha256(snapshot.read_bytes()).hexdigest() == reader.REGISTRY_DIGEST


def test_published_schema_agrees_with_every_case() -> None:
    schema = json.loads((REPO / "spec" / "schemas" / "incident-evidence-cell-v1.schema.json")
                        .read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    verdicts = {name: validator.is_valid(record) for name, record in _records().items()}
    assert verdicts == {name: name in ALLOWED for name in verdicts}


def test_verifier_that_accepts_an_empty_cell_labelled_supported_is_refused() -> None:
    _, errors = corpus.check(skip=frozenset({"empty_cell_labelled"}))
    assert {"reject-empty-cell-supported", "reject-empty-cell-unsupported"} <= _failed(errors)


def test_verifier_that_accepts_a_paraphrased_disclaimer_is_refused() -> None:
    _, errors = corpus.check(skip=frozenset({"truth_disclaimer_missing"}))
    assert "reject-disclaimer-paraphrased" in _failed(errors)


def test_reader_judges_a_list_of_records(capsys) -> None:  # type: ignore[no-untyped-def]
    paths = [str(ROOT / "cases" / name / "record.json")
             for name in ("allow-remediation-empty-es6", "reject-empty-cell-supported")]
    assert reader.main([*paths, "--json"]) == 1
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [line["decision"] for line in lines] == ["allow", "deny"]
    assert [line["reason"] for line in lines] == ["cell_recorded", "empty_cell_labelled"]


def test_unreadable_record_exits_two(tmp_path: Path) -> None:
    listed = tmp_path / "list.json"
    listed.write_text("[]", encoding="ascii")
    assert reader.main([str(listed)]) == 2


def test_verifier_that_denies_everything_fails_the_controls(tmp_path: Path) -> None:
    script = tmp_path / "deny.py"
    script.write_text('import json, sys\nprint(json.dumps({"decision": "deny", '
                      '"reason": "statement_malformed"}))\nsys.exit(1)\n', encoding="ascii")
    _, errors = corpus.check(f"{sys.executable} {script}")
    assert set(ALLOWED) <= _failed(errors)


def test_missing_verifier_does_not_count_as_answered(tmp_path: Path) -> None:
    answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
    assert answered == 0 and errors
