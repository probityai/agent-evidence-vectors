"""The corpus regenerates, forces every check and every proposal rule in order, and refuses a
verifier that reads completion out of a receipt, reports an unqualified proof, turns a gap into a
negative finding, or settles a question the draft leaves open."""

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


corpus = _load("physical_completion_corpus", ROOT / "check_vectors.py")
generator = _load("physical_completion_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import physicalcompletion as reader  # noqa: E402

CHECKS = reader.CHECKS
NONCONFORMANT = {c[0]: c[3] for c in generator.cases() if c[2] == "nonconformant"}
CONFORMANT = [c[0] for c in generator.cases() if c[2] == "conformant"]
OPEN = {c[0]: c[3] for c in generator.cases() if c[2] == "ambiguous"}


def _records() -> dict[str, dict]:  # type: ignore[type-arg]
    return {
        p.parent.name: json.loads(p.read_text(encoding="utf-8"))
        for p in (ROOT / "cases").glob("*/record.json")
    }


def _failed(errors: list[str]) -> set[str]:
    """Names with a wrong decision; a declared-fields mismatch is a separate error."""
    return {e.split(":", 1)[0] for e in errors if "declared retained" not in e}


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {
        p.relative_to(ROOT): p.read_bytes()
        for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")]
        if p.is_file()
    }
    regenerated = {
        p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()
    }
    assert regenerated == committed


def test_reference_reader_agrees_with_every_case() -> None:
    answered, errors = corpus.check()
    assert errors == []
    assert answered == len(generator.cases())


def test_counts_come_from_the_manifest() -> None:
    manifest = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["counts"] == {
        "ambiguous": len(OPEN),
        "conformant": len(CONFORMANT),
        "nonconformant": len(NONCONFORMANT),
    }


def test_every_member_names_its_source_and_its_sentence() -> None:
    manifest = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["provenance"]["source"] == "hippoley, issue 80"
    assert manifest["spec"]["sha256"] == (
        "246b5da4c6ab0045e20d50f7f60ba41db03d49518255b360d8bf39b6ac0560a4"
    )
    assert manifest["proposal"]["rules"] == list(reader.PROPOSAL)
    for entry in manifest["vectors"]:
        assert entry["source"] and entry["rule"] and entry["anchor"]["quote"], entry["id"]
        if entry["expected"]["decision"] == "ambiguous":
            decisions = [reading["decision"] for reading in entry["readings"]]
            assert decisions == ["conformant", "nonconformant"], entry["id"]


@pytest.mark.parametrize("name", sorted(NONCONFORMANT))
def test_each_nonconformant_case_fails_exactly_its_named_check(name: str) -> None:
    record, reason = _records()[name], NONCONFORMANT[name]
    assert reader._first_failure(record, frozenset()) == reason
    assert reader._first_failure(record, frozenset(CHECKS[CHECKS.index(reason) :])) is None


@pytest.mark.parametrize("name", sorted(OPEN))
def test_each_open_case_passes_every_profile_check_and_breaks_its_proposal_rule(
    name: str,
) -> None:
    record = _records()[name]
    assert reader._first_failure(record, frozenset()) is None
    assert reader._proposal_failure(record, frozenset()) == OPEN[name]


@pytest.mark.parametrize("name", [*CHECKS, *reader.PROPOSAL])
def test_every_check_and_proposal_rule_is_forced_by_some_case(name: str) -> None:
    _, errors = corpus.check(skip=frozenset({name}))
    assert errors, f"switching off {name} changed no verdict"


def test_every_proposal_rule_decides_some_open_case() -> None:
    assert set(OPEN.values()) == set(reader.PROPOSAL)


def test_verifier_that_reads_completion_out_of_a_receipt_is_refused() -> None:
    _, errors = corpus.check(skip=frozenset({"completion_from_receipt"}))
    assert _failed(errors) == {"nonconformant-receipt-executed-read-as-completion"}


def test_verifier_that_reads_a_gap_as_a_negative_finding_is_refused() -> None:
    _, errors = corpus.check(skip=frozenset({"negative_without_observation"}))
    assert _failed(errors) == {
        name for name, reason in NONCONFORMANT.items() if reason == "negative_without_observation"
    }


def test_verifier_that_settles_the_open_questions_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reader, "_proposal_failure", lambda record, skip: None)
    _, errors = corpus.check()
    assert _failed(errors) == set(OPEN)


def test_verifier_that_refuses_everything_fails_the_controls(tmp_path: Path) -> None:
    script = tmp_path / "refuse.py"
    script.write_text(
        'import json, sys\nprint(json.dumps({"decision": "nonconformant", '
        '"reason": "contract_id_missing"}))\nsys.exit(1)\n',
        encoding="ascii",
    )
    _, errors = corpus.check(f"{sys.executable} {script}")
    assert set(CONFORMANT) <= _failed(errors)


def test_verifier_that_accepts_everything_fails_the_refusals_and_the_open_cases(
    tmp_path: Path,
) -> None:
    script = tmp_path / "accept.py"
    script.write_text(
        'import json, sys\nprint(json.dumps({"decision": "conformant", '
        '"reason": "result_follows_presentation"}))\n',
        encoding="ascii",
    )
    _, errors = corpus.check(f"{sys.executable} {script}")
    assert (set(NONCONFORMANT) | set(OPEN)) <= _failed(errors)


def test_missing_verifier_does_not_count_as_answered(tmp_path: Path) -> None:
    answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
    assert answered == 0 and errors
