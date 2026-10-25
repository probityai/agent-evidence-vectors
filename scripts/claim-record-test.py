"""Challenge the evaluation-claim verifier: every case, every repair, and every rule kill.

Three properties are proved here, not assumed:

* every negative case refuses with exactly the reason it names, and the same record
  with its defect undone (the case's ``repair``) is admitted, so no negative refuses
  for some other reason;
* every refusal reason and every coordinate has at least one positive and one
  negative case;
* every rule in the verifier is load-bearing: disabling it makes at least one
  negative case stop reporting its reason.
"""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

PACKAGING = Path(__file__).resolve().parents[1] / "packaging"
sys.path.insert(0, str(PACKAGING))

from agent_evidence_vectors.claim_record import reader  # noqa: E402
from agent_evidence_vectors.claim_record.ops import apply_ops, mutate  # noqa: E402
from agent_evidence_vectors.claim_record.reader import (  # noqa: E402
    CODES,
    COORDINATES,
    MalformedInput,
    digest_of,
    emit,
    summary,
    verify,
)
from agent_evidence_vectors.claim_record.run import load_corpus, run_corpus  # noqa: E402
from agent_evidence_vectors.claim_record.run import main as claim_main  # noqa: E402

CORPUS = PACKAGING / "agent_evidence_vectors/claim_record/corpus"
LOADED = load_corpus(CORPUS)
PROFILES, CASE_SETS, RULES = LOADED["profiles"], LOADED["case_sets"], LOADED["rules"]
CASES = LOADED["cases"]["cases"]
NEGATIVES = [c for c in CASES if c["kind"] == "negative"]
POSITIVES = [c for c in CASES if c["kind"] == "positive"]
BY_ID = {c["id"]: c for c in CASES}


def _judge(record: Any, rule: str) -> dict[str, Any]:
    return summary(verify(record, RULES[rule], PROFILES, CASE_SETS))


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_every_case_matches_its_expected_answer(case: dict[str, Any]) -> None:
    assert _judge(case["record"], case["rule"]) == case["expected"]


@pytest.mark.parametrize("case", NEGATIVES, ids=lambda c: c["id"])
def test_every_negative_is_admitted_once_its_defect_is_removed(case: dict[str, Any]) -> None:
    repaired = apply_ops(case["record"], case["repair"])
    got = _judge(repaired, case.get("repair_rule", case["rule"]))
    assert got["result"] == "ADMITTED", got
    assert len(case["expected"]["reasons"]) == 1, "a negative names exactly one defect"


@pytest.mark.parametrize("case", NEGATIVES, ids=lambda c: c["id"])
def test_each_repair_touches_only_what_the_defect_changed(case: dict[str, Any]) -> None:
    base = LOADED["cases"]["bases"][case["base"]]
    assert apply_ops(case["record"], case["repair"]) == base
    _, undo = mutate(case["record"], case["repair"])
    assert apply_ops(base, undo) == case["record"]


def test_every_code_has_a_negative_and_a_repaired_positive() -> None:
    named = {code for case in NEGATIVES for code in case["expected"]["reasons"]}
    assert named == set(CODES)


def test_every_coordinate_has_positive_and_negative_cases() -> None:
    def about(cases: list[dict[str, Any]]) -> set[str]:
        return {part for c in cases for part in c["about"].split("+")}

    for coord in COORDINATES:
        assert coord in about(POSITIVES), coord
        assert coord in about(NEGATIVES), coord


def test_corpus_is_what_the_builder_writes() -> None:
    builder = Path(__file__).with_name("claim-record-build.py")
    done = subprocess.run([sys.executable, str(builder), "--check"], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr


def test_verifier_never_reads_the_expected_answer() -> None:
    case = copy.deepcopy(BY_ID["not-run-read-as-pass"])
    case["expected"] = {"result": "ADMITTED", "verdict": "pass", "reasons": []}
    assert _judge(case["record"], case["rule"])["reasons"] == ["ABSENCE_READ_AS_CLEAN"]


def test_run_corpus_reports_no_failures() -> None:
    report = run_corpus(CORPUS)
    assert report["failures"] == []
    assert all(r["repaired"]["result"] == "ADMITTED" for r in report["results"] if "repaired" in r)


# --- profiles: the producer cannot pick one, and none can launder an absence ----


def test_profile_cannot_authorise_an_absence_as_not_applicable() -> None:
    bad = copy.deepcopy(next(iter(PROFILES.values())))
    bad["not_applicable"]["settlement"] = ["unknown"]
    with pytest.raises(MalformedInput):
        reader.check_profile(bad)


def test_rule_pinning_a_profile_that_launders_absence_is_refused() -> None:
    bad = copy.deepcopy(next(p for p in PROFILES.values() if p["id"] == "conformance/v1"))
    bad["not_applicable"]["population"] = ["not_run"]
    rule = copy.deepcopy(RULES["conformance"])
    rule["profile"] = {"id": bad["id"], "digest": digest_of(bad)}
    record = copy.deepcopy(BY_ID["conformance-full-pass"]["record"])
    record["profile"] = dict(rule["profile"])
    got = summary(verify(record, rule, {**PROFILES, digest_of(bad): bad}, CASE_SETS))
    assert got["reasons"] == ["PROFILE_UNRESOLVED"]


def test_profile_that_drops_a_coordinate_is_refused() -> None:
    bad = copy.deepcopy(next(iter(PROFILES.values())))
    bad["coordinates"] = bad["coordinates"][:-1]
    with pytest.raises(MalformedInput):
        reader.check_profile(bad)


def test_weaker_profile_is_refused_even_when_the_record_is_clean_under_it() -> None:
    record = copy.deepcopy(BY_ID["conformance-full-pass"]["record"])
    assert _judge(record, "conformance")["result"] == "ADMITTED"
    # Judged under the profile the rule pins, not the one the record names: the
    # mismatch is refused, and so is every not-applicable the pinned profile forbids.
    assert _judge(record, "execution")["reasons"] == [
        "PROFILE_MISMATCH",
        "UNAUTHORISED_NOT_APPLICABLE",
    ]


@pytest.mark.parametrize("state", ["unknown", "unresolved", "failed"])
@pytest.mark.parametrize("coord", COORDINATES)
def test_no_unsettled_state_is_ever_admitted(coord: str, state: str) -> None:
    record = copy.deepcopy(BY_ID["execution-settled"]["record"])
    record["coordinates"][coord] = {"state": state}
    assert "UNRESOLVED_COORDINATE" in _judge(record, "execution")["reasons"]


def test_duplicate_member_names_are_refused() -> None:
    with pytest.raises(MalformedInput):
        reader.parse_strict(b'{"verdict": "fail", "verdict": "pass"}')


# --- rule kills: disabling any rule turns at least one named negative ----------


def _never(*_a: Any, **_k: Any) -> None:
    return None


_CONFORMANCE = next(p for p in PROFILES.values() if p["id"] == "conformance/v1")


def _values_only(ctx: Any, profile: Any, coords: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in coords.items() if isinstance(v, dict) and v.get("state") == "value"}


#: (function in the verifier, the reason it carries, a replacement that disables it)
KILLS: list[tuple[str, str, Callable[..., Any]]] = [
    ("check_envelope", "MALFORMED_RECORD", lambda record: record),
    ("resolve_profile", "PROFILE_UNRESOLVED", lambda ctx, profiles, pinned: _CONFORMANCE),
    ("check_profile_pin", "PROFILE_MISMATCH", _never),
    ("check_states", "MISSING_COORDINATE", _values_only),
    ("check_states", "UNRESOLVED_COORDINATE", _values_only),
    ("check_not_applicable", "UNAUTHORISED_NOT_APPLICABLE", _never),
    ("is_immutable", "INVALID_REFERENTIAL_PIN", lambda ref: True),
    ("resolve_case_set", "CASE_SET_NOT_ACCEPTED", lambda ctx, rule, sets, ref: None),
    ("resolve_case_set", "CASE_SET_UNRESOLVED", lambda ctx, rule, sets, ref: None),
    ("partition_ok", "APPLICABILITY_MISMATCH", lambda whole, parts: True),
    ("partition_ok", "POPULATION_MISMATCH", lambda whole, parts: True),
    ("verdict_reason", "ABSENCE_READ_AS_CLEAN", lambda *a: None),
    ("verdict_reason", "VERDICT_CONTRADICTED", lambda *a: None),
    ("check_vantage", "VANTAGE_NOT_ACCEPTED", _never),
    ("check_bytes", "BYTES_MISMATCH", _never),
    ("live_epochs", "STALE_EPOCH", lambda epoch, ids: dict.fromkeys(ids, "e1")),
    ("check_epoch_settlement", "UNSETTLED_OUTCOME", _never),
    (
        "_has_later_transition",
        "UNSETTLED_ACROSS_EPOCH",
        lambda epoch, ids: dict.fromkeys(ids, False),
    ),
]


def test_every_code_has_a_rule_kill() -> None:
    assert {code for _, code, _ in KILLS} == set(CODES)


def test_a_store_keyed_under_the_wrong_digest_resolves_nothing() -> None:
    case = BY_ID["profile-bytes-not-supplied"]
    conf = next(p for p in PROFILES.values() if p["id"] == "conformance/v1")
    profiles = {**PROFILES, case["record"]["profile"]["digest"]: conf}
    got = summary(verify(case["record"], RULES[case["rule"]], profiles, CASE_SETS))
    assert got["reasons"] == ["PROFILE_UNRESOLVED"]
    r1 = BY_ID["historical-case-set-revision"]
    r2 = next(
        cs for cs in CASE_SETS.values() if cs["revision"] == "2" and "reduced" not in cs["name"]
    )
    sets = {**CASE_SETS, r1["record"]["coordinates"]["applicability"]["case_set"]["digest"]: r2}
    got = summary(verify(r1["record"], RULES["conformance"], PROFILES, sets))
    assert got["reasons"] == ["CASE_SET_UNRESOLVED"]


def _still_refuses(case: dict[str, Any], code: str) -> bool:
    """Whether a case still reports ``code`` with a rule disabled; a crash counts as no."""
    try:
        return code in _judge(case["record"], case["rule"])["reasons"]
    except (KeyError, TypeError, AttributeError):
        return False


@pytest.mark.parametrize(
    ("name", "code", "replacement"), KILLS, ids=lambda v: v if isinstance(v, str) else ""
)
def test_each_rule_is_load_bearing(
    name: str, code: str, replacement: Callable[..., Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    named = [c for c in NEGATIVES if code in c["expected"]["reasons"]]
    assert named, code
    monkeypatch.setattr(reader, name, replacement)
    survivors = [c["id"] for c in named if _still_refuses(c, code)]
    assert len(survivors) < len(named), f"killing {name} left every {code} case refusing"


def test_settlement_evidence_rule_is_load_bearing(monkeypatch: pytest.MonkeyPatch) -> None:
    case = BY_ID["committed-without-evidence"]
    record = copy.deepcopy(case["record"])
    record["coordinates"]["settlement"]["actions"][0]["evidence"] = {"uri": "x:y"}
    assert _judge(record, "execution")["reasons"] == ["INVALID_REFERENTIAL_PIN"]


# --- emit: a run's absences become not_run, never a pass ----------------------


def _emit(results: dict[str, Any]) -> dict[str, Any]:
    r2 = next(
        cs for cs in CASE_SETS.values() if cs["revision"] == "2" and "reduced" not in cs["name"]
    )
    conf = next(p for p in PROFILES.values() if p["id"] == "conformance/v1")
    return emit(
        case_set=r2,
        results=results,
        profile={"id": conf["id"], "digest": digest_of(conf)},
        implementation={"name": "impl", "digest": "sha256:" + "a" * 64},
        verifier={"name": "verifier", "digest": "sha256:" + "b" * 64},
        observation_vantage="substrate",
        observer="ci",
    )


def test_emit_lists_unreported_cases_as_not_run() -> None:
    record = _emit({"passed": ["c1", "c2"]})
    assert record["coordinates"]["population"]["not_run"] == ["c3", "c4", "c5"]
    assert record["verdict"] == "incomplete"
    assert _judge(record, "conformance") == {
        "result": "ADMITTED",
        "verdict": "incomplete",
        "reasons": [],
    }


def test_emit_full_pass_is_admitted_as_pass() -> None:
    record = _emit({"passed": ["c1", "c2", "c3", "c4", "c5"]})
    assert _judge(record, "conformance")["verdict"] == "pass"


def test_emit_refuses_a_case_the_set_does_not_hold() -> None:
    with pytest.raises(MalformedInput):
        _emit({"passed": ["c1", "c9"]})


# --- the CLI -----------------------------------------------------------------


def _write(tmp: Path, name: str, value: Any) -> Path:
    path = tmp / name
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


@pytest.mark.parametrize(
    ("case_id", "rule", "code"),
    [
        ("conformance-full-pass", "conformance", 0),
        ("incomplete-lists-not-run", "conformance", 3),
        ("not-run-read-as-pass", "conformance", 1),
    ],
)
def test_cli_verify_exit_codes(tmp_path: Path, case_id: str, rule: str, code: int) -> None:
    record = _write(tmp_path, "record.json", BY_ID[case_id]["record"])
    rule_file = _write(tmp_path, "rule.json", RULES[rule])
    case_set = CORPUS / "case-sets/sample-r2.json"
    argv = [
        "verify",
        "--record",
        str(record),
        "--rule",
        str(rule_file),
        "--case-set",
        str(case_set),
    ]
    assert claim_main(argv) == code


def test_cli_verify_unusable_input_exits_2(tmp_path: Path) -> None:
    record = tmp_path / "record.json"
    record.write_bytes(b'{"a": 1, "a": 2}')
    rule_file = _write(tmp_path, "rule.json", RULES["conformance"])
    assert claim_main(["verify", "--record", str(record), "--rule", str(rule_file)]) == 2


def test_cli_emit_then_verify_round_trip(tmp_path: Path) -> None:
    results = _write(tmp_path, "results.json", {"passed": ["c1", "c2", "c3", "c4", "c5"]})
    out = tmp_path / "claim.json"
    argv = [
        "emit",
        "--case-set",
        str(CORPUS / "case-sets/sample-r2.json"),
        "--results",
        str(results),
        "--implementation-name",
        "impl",
        "--implementation-digest",
        "sha256:" + "a" * 64,
        "--verifier-name",
        "verifier",
        "--verifier-digest",
        "sha256:" + "b" * 64,
        "--observation-vantage",
        "substrate",
        "--observer",
        "ci",
        "--statement",
        "--output",
        str(out),
    ]
    assert claim_main(argv) == 0
    rule_file = _write(tmp_path, "rule.json", RULES["conformance"])
    assert (
        claim_main(
            [
                "verify",
                "--record",
                str(out),
                "--rule",
                str(rule_file),
                "--case-set",
                str(CORPUS / "case-sets/sample-r2.json"),
            ]
        )
        == 0
    )


def test_main_cli_dispatches_the_claim_subcommand(tmp_path: Path) -> None:
    record = _write(tmp_path, "record.json", BY_ID["not-run-read-as-pass"]["record"])
    rule_file = _write(tmp_path, "rule.json", RULES["conformance"])
    done = subprocess.run(
        [
            sys.executable,
            str(PACKAGING / "run_vectors.py"),
            "claim",
            "verify",
            "--record",
            str(record),
            "--rule",
            str(rule_file),
            "--case-set",
            str(CORPUS / "case-sets/sample-r2.json"),
        ],
        capture_output=True,
        text=True,
        cwd=PACKAGING,
    )
    assert done.returncode == 1, done.stderr
    assert "ABSENCE_READ_AS_CLEAN" in done.stdout


def test_tampered_corpus_is_refused(tmp_path: Path) -> None:
    import shutil

    copy_root = tmp_path / "corpus"
    shutil.copytree(CORPUS, copy_root)
    rules = copy_root / "rules/conformance.json"
    rules.write_text(rules.read_text().replace('"substrate"', '"artifact"'), encoding="utf-8")
    with pytest.raises(MalformedInput):
        load_corpus(copy_root)


def test_cli_run_writes_a_report_and_refuses_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    argv = ["run", "--output", "out", "--implementation-revision", "0" * 40]
    assert claim_main(argv) == 0
    report = json.loads((tmp_path / "out/report.json").read_text())
    assert report["failures"] == []
    assert claim_main(argv) == 2, "an existing output directory is refused, never reused"


def test_cli_verify_malformed_rule_is_unusable_not_a_refusal(tmp_path: Path) -> None:
    record = _write(tmp_path, "record.json", BY_ID["conformance-full-pass"]["record"])
    rule = copy.deepcopy(RULES["conformance"])
    rule["profile"] = {"id": "conformance/v1", "name": "by tag only"}
    rule_file = _write(tmp_path, "rule.json", rule)
    assert claim_main(["verify", "--record", str(record), "--rule", str(rule_file)]) == 2
