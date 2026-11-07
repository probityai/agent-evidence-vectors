"""The corpus regenerates, forces every check in order, and refuses a verifier that scores
any applicable refusal value instead of the first, reads a diagnostic read as authority,
or settles a boundary the draft leaves open."""

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


corpus = _load("refusal_reason_corpus", ROOT / "check_vectors.py")
generator = _load("refusal_reason_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import refusalreason as reader  # noqa: E402

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
    assert manifest["provenance"]["source"] == "Aicent Stack, issue 453"
    assert manifest["spec"]["sha256"] == (
        "02491c5a59d1e7471be04e8e0d4933dfc22ce19f9b054ead0aa449d6b4485044"
    )
    for entry in manifest["vectors"]:
        assert entry["source"] and entry["rule"] and entry["anchor"]["quote"], entry["id"]
        if entry["expected"]["decision"] == "ambiguous":
            assert len(entry["readings"]) == 2, entry["id"]


@pytest.mark.parametrize("name", sorted(NONCONFORMANT))
def test_each_nonconformant_case_fails_exactly_its_named_check(name: str) -> None:
    record, reason = _records()[name], NONCONFORMANT[name]
    assert reader._first_failure(record, frozenset()) == reason
    assert reader._first_failure(record, frozenset(CHECKS[CHECKS.index(reason) :])) is None


@pytest.mark.parametrize("name", CHECKS)
def test_every_check_is_forced_by_some_case(name: str) -> None:
    _, errors = corpus.check(skip=frozenset({name}))
    assert errors, f"switching off {name} changed no verdict"


def test_checker_that_scores_any_applicable_value_fails_exactly_one_of_each_pair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def any_applicable(facts: dict) -> frozenset:  # type: ignore[type-arg]
        if reader.lease_only(facts):
            return reader.LEASE_READINGS
        found = reader.applicable(facts)
        return frozenset(found) if found else reader.NO_REASON

    monkeypatch.setattr(reader, "owed_values", any_applicable)
    _, errors = corpus.check()
    failed = _failed(errors)
    assert {
        "nonconformant-revocation-over-expiry",
        "nonconformant-operation-not-permitted-over-revocation",
        "nonconformant-not-determined-over-expiry",
        "nonconformant-expiry-over-mismatch",
        "nonconformant-revocation-of-three",
    } <= failed
    assert not failed & {
        "conformant-expiry-over-revocation",
        "conformant-revocation-over-operation-not-permitted",
        "conformant-expiry-over-not-determined",
        "conformant-mismatch-over-expiry",
    }


def test_checker_that_lets_frame_acceptance_decide_reliance_fails_the_frame_case(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reader, "_derived_boundary", lambda lease: None)
    _, errors = corpus.check()
    assert _failed(errors) == {
        "conformant-exclusive-expired-at-instant",
        "conformant-frame-accepted-reliance-refused",
        "open-exclusive-declared-permit-at-instant",
    }


def test_checker_that_settles_the_open_boundary_questions_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reader, "_open_question", lambda record: None)
    _, errors = corpus.check()
    assert _failed(errors) == set(OPEN)


def test_verifier_that_reads_a_diagnostic_read_as_authority_is_refused() -> None:
    _, errors = corpus.check(skip=frozenset({"condition_ignored"}))
    assert _failed(errors) == {"nonconformant-permit-over-diagnostic-read"}


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
        '"reason": "response_follows_source"}))\n',
        encoding="ascii",
    )
    _, errors = corpus.check(f"{sys.executable} {script}")
    assert (set(NONCONFORMANT) | set(OPEN)) <= _failed(errors)


def test_missing_verifier_does_not_count_as_answered(tmp_path: Path) -> None:
    answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
    assert answered == 0 and errors
