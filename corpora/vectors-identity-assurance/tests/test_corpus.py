"""The corpus regenerates, grades every set at the level below its first gap, refuses what it
cannot read, and fails closed against forged, replayed, swapped and downgraded findings."""

from __future__ import annotations

import copy
import importlib.util
import itertools
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))
sys.path.insert(0, str(ROOT))


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = _load("identity_assurance_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import assurancelevels as reader  # noqa: E402

import reuse  # noqa: E402

TESTS = [t[0] for t in reader.TESTS]
LADDER = generator.LADDER


def _record(name: str) -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / "cases" / name / "record.json").read_text(encoding="utf-8"))


def _level(record: dict) -> int:  # type: ignore[type-arg]
    return reader.grade(record)[0]


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    (tmp_path / "reuse.json").write_bytes((ROOT / "reuse.json").read_bytes())
    generator.generate(tmp_path)
    committed = {
        p.relative_to(ROOT): p.read_bytes()
        for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")]
        if p.is_file()
    }
    regenerated = {
        p.relative_to(tmp_path): p.read_bytes()
        for p in tmp_path.rglob("*")
        if p.is_file() and p.name != "reuse.json"
    }
    assert regenerated == committed


def test_reference_reader_agrees_with_every_case() -> None:
    answered, errors = reader.check(root=ROOT)
    assert errors == []
    assert answered == len(generator.cases())


def test_every_level_has_a_member() -> None:
    reasons = {c[3] for c in generator.cases() if c[2] == "accept"}
    for level in range(7):
        assert any(r.startswith(f"level={level} ") for r in reasons), level


def test_every_unreadable_set_code_has_a_member() -> None:
    refused = {c[3] for c in generator.cases() if c[2] == "reject"}
    assert refused == set(reader.CHECKS)


def test_every_test_has_a_gap_member_and_a_refusal_member() -> None:
    reasons = [c[3] for c in generator.cases() if c[2] == "accept"]
    for test in TESTS[1:]:
        assert any(f"next={test}:no_finding" in r for r in reasons), test
        assert any(f"next={test}:finding_refused" in r for r in reasons), test


def test_a_set_that_skips_a_level_is_graded_at_the_level_below_the_gap() -> None:
    record = _record("skips-holder-bound")
    assert {f["suite"] for f in record["findings"]} >= {
        "delegator-right/v1",
        "credential-reachability/v1",
        "evidence-grade-floor/v1",
    }
    assert reader.judge(record) == {"decision": "accept", "reason": "level=2 next=T3:no_finding"}


@pytest.mark.parametrize("present", list(itertools.product([0, 1], repeat=6)))
def test_the_level_is_the_length_of_the_unbroken_prefix(present: tuple[int, ...]) -> None:
    findings = [generator.finding(k) for k, on in zip(LADDER, present, strict=True) if on]
    prefix = 0
    for on in present:
        if not on:
            break
        prefix += 1
    assert _level(generator.build(*findings)) == prefix


def test_removing_a_finding_never_raises_the_level() -> None:
    full = generator.build(*[generator.finding(k) for k in LADDER])
    for index in range(len(LADDER)):
        smaller = copy.deepcopy(full)
        del smaller["findings"][index]
        assert _level(smaller) <= _level(full)


def test_finding_order_never_changes_the_answer() -> None:
    findings = [generator.finding(k) for k in LADDER]
    expected = reader.judge(generator.build(*findings))
    for order in itertools.permutations(findings[:4]):
        assert reader.judge(generator.build(*order, *findings[4:])) == expected


def test_a_forged_acceptance_for_another_subject_lifts_nothing() -> None:
    record = _record("subject-mismatch")
    assert _level(record) == 2
    swapped = copy.deepcopy(record)
    swapped["findings"][-1]["subject"] = "agent:planner "
    assert reader.judge(swapped)["reason"] == "finding_malformed"


def test_a_refusal_is_never_outvoted_by_more_acceptances() -> None:
    record = _record("refusal-outvotes-acceptance")
    for _ in range(5):
        record["findings"].append(copy.deepcopy(record["findings"][2]))
    assert reader.judge(record)["reason"].startswith("level=2 next=T3:finding_refused")


def test_the_same_evidence_cannot_be_reported_both_ways() -> None:
    record = generator.build(generator.finding(LADDER[0]))
    twin = copy.deepcopy(record["findings"][0])
    twin["decision"] = "reject"
    record["findings"].append(twin)
    assert reader.judge(record) == {"decision": "reject", "reason": "finding_conflict"}


def test_a_downgrade_of_a_refusal_to_an_acceptance_changes_the_evidence_digest_or_conflicts() -> (
    None
):
    record = _record("marker-stripped")
    flipped = copy.deepcopy(record)
    flipped["findings"][1]["decision"] = "accept"
    flipped["findings"][1]["reason"] = "marker_survives"
    # the digest still names the refused member, and the corpus' pointer says so
    entry = reuse.load()["vectors-actor-marker-survival/own-marker-stripped"]
    assert flipped["findings"][1]["evidence"]["sha256"] == entry["sha256"]
    assert entry["decision"] == "reject"


def test_a_reason_that_is_not_a_proof_is_not_a_proof() -> None:
    record = _record("reachability-exposed")
    assert reader.judge(record)["reason"] == "level=4 next=T5:reason_not_proving:exposed_verified"


@pytest.mark.parametrize("rung", ["E0", "E1"])
def test_a_floor_finding_below_e2_does_not_prove_level_6(rung: str) -> None:
    findings = [generator.finding(k) for k in LADDER[:5]]
    findings.append(generator.finding(LADDER[5], rung=rung))
    assert reader.judge(generator.build(*findings))["reason"] == (
        f"level=5 next=T6:rung_below_floor:{rung}"
    )


def test_malformed_files_are_refusals_never_crashes(tmp_path: Path) -> None:
    for text in ("{", "[]", '{"a": 1, "a": 2}', ""):
        path = tmp_path / "record.json"
        path.write_text(text, encoding="utf-8")
        assert reader.verify(path) == {"decision": "reject", "reason": "record_malformed"}


def test_the_corpus_refuses_a_verifier_that_grades_everything_level_6(tmp_path: Path) -> None:
    script = tmp_path / "six.py"
    script.write_text(
        "import json\nprint(json.dumps({'decision':'accept','reason':'level=6 next=none'}))\n",
        encoding="utf-8",
    )
    answered, errors = reader.check(f"{sys.executable} {script}", ROOT)
    assert answered == len(generator.cases())
    assert errors


def test_every_reuse_pointer_is_a_real_finding_shape() -> None:
    for key, entry in reuse.load().items():
        assert key == f"{entry['corpus']}/{entry['member']}"
        assert entry["decision"] in ("accept", "reject")
        assert len(entry["sha256"]) == 64


def test_pending_siblings_are_counted_not_hidden(tmp_path: Path) -> None:
    verified, pending, errors = reuse.check(tmp_path)
    assert (verified, errors) == (0, [])
    assert pending == len(reuse.load())
    _, _, strict = reuse.check(tmp_path, require_all=True)
    assert strict


def test_one_digest_listed_under_several_suites_grades_nothing() -> None:
    record = generator._one_evidence_six_suites()
    assert reader.judge(record) == {"decision": "reject", "reason": "finding_conflict"}


def test_one_digest_about_two_subjects_is_a_conflict() -> None:
    first = generator.finding(generator.T1)
    second = generator.finding(generator.T1, subject="agent:other")
    record = generator.build(first, second)
    assert reader.judge(record) == {"decision": "reject", "reason": "finding_conflict"}
