"""The corpus regenerates, forces every check, and refuses a verifier that infers authority,
receipt, acceptance or closure from evidence that is not there, reads the current record as
the decision-time one, or reads a late or out-of-role step as a clean close."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("responsibility_escalation_corpus", ROOT / "check_vectors.py")
generator = _load("responsibility_escalation_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import responsibilityescalation as reader  # noqa: E402

CHECKS = reader.CHECKS
CASES = {c[0]: c for c in generator.cases()}
#: Checks a member of the corpus names as its reason.
FORCED_BY_CASE = {
    "receipt_not_evidenced": "h02-referral-without-receipt",
    "acceptance_not_evidenced": "h03-acknowledged-without-acceptance",
    "escalation_unanswered": "h04-unanswered-escalation",
    "reference_unavailable": "h05-reference-unavailable",
    "authority_narrowed_before_acknowledgement": "h06-authority-narrowed-before-acknowledgement",
    "current_record_resolved_not_decision_time": "h07-current-record-resolved",
    "acknowledged_outside_designated_role": "h08-acknowledged-outside-role",
}


def _clean() -> dict[str, Any]:
    return copy.deepcopy(CASES["h09-clean-path-closed-on-time"][1])


def _mutated(change: Any) -> dict[str, Any]:
    record = _clean()
    change(record)
    return record


def _slots(record: dict[str, Any]) -> dict[str, Any]:
    slots: dict[str, Any] = record["escalation"]["slots"]
    return slots


#: Checks no member names; each is forced by one change to the clean record.
FORCED_BY_MUTATION = {
    "contract_id_missing": lambda r: r.pop("contractId"),
    "contract_id_unknown": lambda r: r.update(contractId=r["contractId"] + "-v0"),
    "referral_not_evidenced": lambda r: _slots(r).update(referral=generator.absent()),
    "event_after_evaluation_instant": lambda r: r.update(evaluatedAt="2026-03-02T11:15:00Z"),
    "reference_inconsistent": lambda r: r["authority"]["resolution"].update(returned="v9"),
    "authority_not_held_at_read_instant": lambda r: r["authority"]["versions"][0].update(
        holds=False
    ),
    "accepted_outside_designated_role": lambda r: _slots(r)["acceptance"].update(by="recruiter"),
    "closure_not_evidenced": lambda r: _slots(r).update(closure=generator.absent()),
    "closed_outside_designated_role": lambda r: _slots(r)["closure"].update(by="recruiter"),
    "closed_late": lambda r: _slots(r)["closure"].update(at="2026-03-03T18:00:00Z"),
}


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
    assert answered == len(CASES) == 9


def test_counts_come_from_the_manifest() -> None:
    manifest = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["counts"] == {
        "established": 2,
        "not_established": 2,
        "partial": 4,
        "unresolved": 1,
    }


def test_every_member_names_its_list_case_and_its_class() -> None:
    manifest = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
    assert "messages 2026Oct 0035 and 0043" in manifest["provenance"]["source"]
    assert [e["case"] for e in manifest["vectors"]] == list(range(1, 10))
    assert {e["decisionClass"] for e in manifest["vectors"]} == set(generator.CLASSES)


def test_the_corpus_names_no_person_and_no_company() -> None:
    text = "".join(
        p.read_text(encoding="utf-8")
        for p in [ROOT / "MANIFEST.json", ROOT / "README.md", *(ROOT / "cases").rglob("*.json")]
    ).lower()
    for word in ("prasanna", "touche", "raphael", "latouche", "deusproof", "bableshwar"):
        assert word not in text


@pytest.mark.parametrize("check", sorted(FORCED_BY_CASE))
def test_each_check_a_case_names_is_forced_by_that_case(check: str) -> None:
    name = FORCED_BY_CASE[check]
    record, expected = _records()[name], CASES[name][3]
    assert expected == check
    assert reader._first_failure(record, frozenset()) == check
    assert reader._first_failure(record, frozenset({check})) != check
    _, errors = corpus.check(skip=frozenset({check}))
    assert name in _failed(errors)


@pytest.mark.parametrize("check", sorted(FORCED_BY_MUTATION))
def test_each_remaining_check_is_forced_by_one_change_to_the_clean_record(check: str) -> None:
    record = _mutated(FORCED_BY_MUTATION[check])
    answer = reader.judge(record)
    assert answer["reason"] == check
    assert answer["decision"] == reader.CHECK_OUTCOME[check]
    assert reader.judge(record, frozenset({check}))["reason"] != check


def test_every_check_is_forced_by_a_case_or_a_mutation() -> None:
    assert set(FORCED_BY_CASE) | set(FORCED_BY_MUTATION) == set(CHECKS)


def test_a_late_closure_is_its_own_state_not_a_clean_pass_and_not_unresolved() -> None:
    answer = reader.judge(_mutated(FORCED_BY_MUTATION["closed_late"]))
    assert answer == {"decision": "partial", "reason": "closed_late"}


def test_later_evidence_does_not_repair_a_missing_receipt() -> None:
    record = copy.deepcopy(CASES["h02-referral-without-receipt"][1])
    _slots(record)["acknowledgement"] = generator.present(
        "2026-03-02T11:00:00Z", record["escalation"]["designatedRole"]
    )
    assert reader.judge(record) == {"decision": "partial", "reason": "receipt_not_evidenced"}


def test_authority_read_at_the_referral_instant_names_that_instant_when_clean() -> None:
    record = copy.deepcopy(CASES["h01-authority-narrowed-after-decision"][1])
    record["authority"]["readAt"] = "referral"
    assert reader.judge(record) == {
        "decision": "established",
        "reason": "authority_held_at_referral_instant",
    }


def test_authority_narrowed_at_the_referral_instant_is_not_established() -> None:
    record = copy.deepcopy(CASES["h06-authority-narrowed-before-acknowledgement"][1])
    record["authority"]["versions"][1]["effectiveFrom"] = "2026-03-02T10:02:00Z"
    record["authority"]["resolution"]["returned"] = "v2"
    assert reader.judge(record) == {
        "decision": "not_established",
        "reason": "authority_not_held_at_read_instant",
    }


def test_incomplete_coverage_of_an_absent_slot_does_not_change_the_outcome() -> None:
    record = copy.deepcopy(CASES["h04-unanswered-escalation"][1])
    _slots(record)["acknowledgement"]["coverage"] = "incomplete"
    assert reader.judge(record) == {"decision": "unresolved", "reason": "escalation_unanswered"}


def test_checker_that_reads_the_resolved_version_without_the_decision_instant_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reader, "_current_returned", lambda record: False)
    _, errors = corpus.check()
    assert "h07-current-record-resolved" in _failed(errors)


def test_checker_that_infers_acceptance_from_acknowledgement_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = reader.evidenced

    def inferred(record: dict, name: str) -> bool:  # type: ignore[type-arg]
        if name == "acceptance":
            return original(record, "acknowledgement")
        return original(record, name)

    monkeypatch.setattr(reader, "evidenced", inferred)
    _, errors = corpus.check()
    assert "h03-acknowledged-without-acceptance" in _failed(errors)


def test_verifier_that_refuses_everything_fails_the_established_controls(tmp_path: Path) -> None:
    script = tmp_path / "refuse.py"
    script.write_text(
        'import json, sys\nprint(json.dumps({"decision": "not_established", '
        '"reason": "contract_id_missing"}))\nsys.exit(1)\n',
        encoding="ascii",
    )
    _, errors = corpus.check(f"{sys.executable} {script}")
    assert {"h01-authority-narrowed-after-decision", "h09-clean-path-closed-on-time"} <= _failed(
        errors
    )


def test_verifier_that_establishes_everything_fails_every_other_case(tmp_path: Path) -> None:
    script = tmp_path / "accept.py"
    script.write_text(
        'import json, sys\nprint(json.dumps({"decision": "established", '
        '"reason": "closed_as_accepted"}))\n',
        encoding="ascii",
    )
    _, errors = corpus.check(f"{sys.executable} {script}")
    failed = _failed(errors)
    assert set(CASES) - {"h09-clean-path-closed-on-time"} <= failed


def test_missing_verifier_does_not_count_as_answered(tmp_path: Path) -> None:
    answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
    assert answered == 0 and errors
