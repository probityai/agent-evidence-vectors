"""Challenge the occurrence-binding reader: every expected answer, refusal and rule kill."""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

PACKAGING = Path(__file__).resolve().parents[1] / "packaging"
sys.path.insert(0, str(PACKAGING))

from agent_evidence_vectors.occurrence_binding import reader  # noqa: E402
from agent_evidence_vectors.occurrence_binding.reader import (  # noqa: E402
    NOT_ESTABLISHED,
    MalformedInput,
    evaluate,
    summary,
)
from agent_evidence_vectors.occurrence_binding.run import main as run_main  # noqa: E402
from agent_evidence_vectors.occurrence_binding.run import run_corpus  # noqa: E402

CORPUS = PACKAGING / "agent_evidence_vectors/occurrence_binding/corpus"
OCCURRENCE = json.loads((CORPUS / "occurrence.json").read_text())
TRUST = json.loads((CORPUS / "trust.json").read_text())
CASES = json.loads((CORPUS / "cases.json").read_text())["cases"]
BY_ID = {case["id"]: case for case in CASES}


def _judge(case_id: str, case: dict[str, Any] | None = None) -> dict[str, str]:
    return summary(evaluate(OCCURRENCE, TRUST, case or BY_ID[case_id]))


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_every_case_matches_its_expected_answer(case: dict[str, Any]) -> None:
    assert summary(evaluate(OCCURRENCE, TRUST, case)) == case["expected"]


def test_each_axis_has_all_three_answers() -> None:
    for axis in reader.AXES:
        words = {case["expected"][axis] for case in CASES}
        assert {"ESTABLISHED", "CONTRADICTED", "NOT_ESTABLISHED"} <= words, axis


def test_both_controls_are_present_and_natively_valid() -> None:
    for cid in ("mismatched_occurrence", "same_content_different_execution"):
        got = _judge(cid)
        assert got["occurrence_link"] == "CONTRADICTED", cid
        for axis in reader.NATIVE_AXES:
            assert got[axis] == "ESTABLISHED", (cid, axis)


def test_same_content_control_really_shares_the_call() -> None:
    execution = BY_ID["same_content_different_execution"]["artifacts"]["execution"]["statement"]
    assert execution["call_binding"] == reader.invocation_binding(OCCURRENCE["request"])
    assert execution["occurrence_binding"] != reader.occurrence_binding(OCCURRENCE)


def test_reader_never_reads_the_expected_answer() -> None:
    case = copy.deepcopy(BY_ID["intact_occurrence"])
    del case["expected"]
    assert _judge("", case)["occurrence_link"] == "ESTABLISHED"


def test_non_claims_cannot_be_raised_by_an_artifact() -> None:
    case = copy.deepcopy(BY_ID["intact_occurrence"])
    case["artifacts"]["execution"]["statement"]["settled_final"] = True
    case["artifacts"]["execution"]["statement"]["accepted"] = True
    for prop in reader.NON_CLAIMS:
        assert _judge("", case)[prop] == NOT_ESTABLISHED


def test_jsonrpc_id_is_not_part_of_the_occurrence() -> None:
    moved = copy.deepcopy(OCCURRENCE)
    moved["request"]["id"] = "other-transport-id"
    assert reader.occurrence_binding(moved) == reader.occurrence_binding(OCCURRENCE)


def test_nonce_separates_two_runs_of_one_call() -> None:
    second = copy.deepcopy(OCCURRENCE)
    second["occurrence_nonce"] = "occ-0002"
    assert reader.occurrence_binding(second) != reader.occurrence_binding(OCCURRENCE)


def test_corpus_is_what_the_builder_writes() -> None:
    script = Path(__file__).with_name("occurrence-binding-build.py")
    assert subprocess.run([sys.executable, str(script), "--check"], check=False).returncode == 0


@pytest.mark.parametrize(
    "mutate",
    [
        lambda o: o.update(schema="other"),
        lambda o: o.update(occurrence_nonce=""),
        lambda o: o["request"].update(method="tools/list"),
    ],
    ids=["schema", "empty-nonce", "not-tools-call"],
)
def test_malformed_occurrence_is_refused(mutate: Any) -> None:
    occurrence = copy.deepcopy(OCCURRENCE)
    mutate(occurrence)
    with pytest.raises(MalformedInput):
        reader.occurrence_binding(occurrence)


def test_wrong_statement_schema_is_refused() -> None:
    case = copy.deepcopy(BY_ID["intact_occurrence"])
    case["artifacts"]["payment"]["statement"]["schema"] = "other"
    with pytest.raises(MalformedInput):
        evaluate(OCCURRENCE, TRUST, case)


def test_wrong_trust_schema_is_refused() -> None:
    with pytest.raises(MalformedInput):
        evaluate(OCCURRENCE, dict(TRUST, schema="other"), BY_ID["intact_occurrence"])


@pytest.mark.parametrize("amount", [-1, True, "300"])
def test_non_integer_or_negative_amount_is_refused(amount: Any) -> None:
    case = copy.deepcopy(BY_ID["intact_occurrence"])
    case["artifacts"]["payment"]["statement"]["amount_units"] = amount
    # The signature no longer verifies, so re-sign is not possible here; judge
    # spend directly with both natives forced established.
    native = {axis: {"result": "ESTABLISHED"} for axis in reader.NATIVE_AXES}
    with pytest.raises(MalformedInput):
        reader.judge_spend(case["artifacts"], native)


def test_input_pin_is_the_two_line_fixture() -> None:
    pins = reader.input_pins(OCCURRENCE)
    held = json.loads((CORPUS / OCCURRENCE["input_file"]).read_text())
    digest = reader.sha256_tag(reader.canonical(held))
    assert digest == pins["input_sha256"]
    assert digest == "sha256:1f75bcabc3506eca614e047d72629e175160b7b3688c1016a31b4e7a09eb1fbd"
    assert len(reader.canonical(held)) == 207 and len(held["lines"]) == 2


def test_lost_call_controls_stay_unresolved() -> None:
    for cid in (
        "lost_call_no_statement",
        "lost_call_statement_names_other_occurrence",
        "lost_call_statement_names_call_content_only",
        "lost_call_statement_signed_by_payer",
    ):
        got = _judge(cid)
        assert got["not_run_settlement"] == NOT_ESTABLISHED, cid
        assert got["execution_receipt"] == NOT_ESTABLISHED, cid
    assert _judge("lost_call_settled_not_run")["not_run_settlement"] == "ESTABLISHED"


def test_other_occurrence_statement_is_signed_by_the_responder() -> None:
    case = BY_ID["lost_call_statement_names_other_occurrence"]
    verdict = reader.judge_signed(
        case["artifacts"]["not_run"], reader.NOT_RUN_SCHEMA, "responder", TRUST
    )
    assert verdict["result"] == "ESTABLISHED"


def test_not_run_statement_must_say_not_run() -> None:
    case = copy.deepcopy(BY_ID["lost_call_settled_not_run"])
    case["artifacts"]["not_run"]["statement"]["outcome"] = "RAN"
    with pytest.raises(MalformedInput):
        reader.judge_not_run(
            case["artifacts"],
            {"execution_receipt": {"result": NOT_ESTABLISHED}},
            {"keys": TRUST["keys"], "roles": {"responder": list(TRUST["keys"])}},
            reader.occurrence_binding(OCCURRENCE),
            reader.invocation_binding(OCCURRENCE["request"]),
        )


@pytest.mark.parametrize(
    "pins",
    [None, {"input_sha256": "sha256:" + "0" * 64}, {"input_sha256": "x", "dataset_sha256": "y"}],
    ids=["absent", "one-pin", "not-tags"],
)
def test_malformed_pins_are_refused(pins: Any) -> None:
    occurrence = copy.deepcopy(OCCURRENCE)
    occurrence["input_pins"] = pins
    with pytest.raises(MalformedInput):
        evaluate(occurrence, TRUST, BY_ID["intact_occurrence"])


def test_input_file_that_differs_from_its_pin_is_refused(tmp_path: Path) -> None:
    copy_root = tmp_path / "corpus"
    shutil.copytree(CORPUS, copy_root)
    held = json.loads((copy_root / "input.json").read_text())
    held["lines"] = held["lines"][:1]
    text = json.dumps(held, indent=2, ensure_ascii=False) + "\n"
    (copy_root / "input.json").write_text(text)
    manifest = json.loads((copy_root / "manifest.json").read_text())
    manifest["members"]["input.json"] = reader.sha256_tag(text.encode())
    (copy_root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    with pytest.raises(MalformedInput):
        run_corpus(copy_root)


class TestKills:
    """Disable one rule at a time; a named case must turn."""

    def test_link_by_call_content_alone(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real = reader.judge_link

        def content_only(arts: dict[str, Any], occ: str, call: str) -> dict[str, Any]:
            execution = arts.get("execution")
            if execution and execution["statement"].get("call_binding") == call:
                return reader._result("ESTABLISHED", "content matched")
            return real(arts, occ, call)

        monkeypatch.setattr(reader, "judge_link", content_only)
        assert _judge("same_content_different_execution")["occurrence_link"] == "ESTABLISHED"
        assert _judge("execution_names_call_content_only")["occurrence_link"] == "ESTABLISHED"

    def test_role_check(self) -> None:
        trust = copy.deepcopy(TRUST)
        trust["roles"] = {role: list(trust["keys"]) for role in trust["roles"]}
        got = summary(evaluate(OCCURRENCE, trust, BY_ID["budget_signed_by_agent"]))
        assert got["budget_statement"] == "ESTABLISHED"

    def test_signature_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(reader, "ed25519_verify", lambda pub, msg, sig: True)
        assert _judge("budget_signature_broken")["budget_statement"] == "ESTABLISHED"

    def test_limit_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        case = copy.deepcopy(BY_ID["payment_exceeds_issuer_limit"])
        case["artifacts"]["budget"]["statement"]["limit_units"] = 10**6
        monkeypatch.setattr(reader, "ed25519_verify", lambda pub, msg, sig: True)
        named = case["artifacts"]["payment"]["statement"]["budget_digest"]
        monkeypatch.setattr(reader, "statement_digest", lambda env: named)
        assert _judge("", case)["spend_within_budget"] == "ESTABLISHED"

    def test_input_digest_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real = reader.judge_input

        def other_pin(arts: Any, native: Any, pins: dict[str, str], occ: str) -> Any:
            return real(arts, native, dict(pins, input_sha256="sha256:" + "0" * 64), occ)

        def lax(arts: Any, native: Any, pins: dict[str, str], occ: str) -> Any:
            got = real(arts, native, pins, occ)
            return reader._result("ESTABLISHED", "lax") if got["result"] == "CONTRADICTED" else got

        monkeypatch.setattr(reader, "judge_input", lax)
        assert _judge("input_other_fixture")["input_pinned"] == "ESTABLISHED"
        assert _judge("input_other_dataset_version")["input_pinned"] == "ESTABLISHED"
        monkeypatch.setattr(reader, "judge_input", other_pin)
        assert _judge("intact_occurrence")["input_pinned"] == "CONTRADICTED"

    def test_not_run_needs_the_responder_role(self) -> None:
        trust = copy.deepcopy(TRUST)
        trust["roles"]["responder"] = list(trust["keys"])
        got = summary(evaluate(OCCURRENCE, trust, BY_ID["lost_call_statement_signed_by_payer"]))
        assert got["not_run_settlement"] == "ESTABLISHED"

    def test_not_run_needs_this_occurrence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real = reader.judge_not_run

        def any_occurrence(arts: Any, native: Any, trust: Any, occ: str, call: str) -> Any:
            named = arts.get("not_run", {}).get("statement", {}).get("occurrence_binding", occ)
            return real(arts, native, trust, named, call)

        monkeypatch.setattr(reader, "judge_not_run", any_occurrence)
        got = _judge("lost_call_statement_names_other_occurrence")
        assert got["not_run_settlement"] == "ESTABLISHED"

    def test_not_run_yields_to_an_execution_receipt(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real = reader.judge_not_run

        def no_receipt_check(arts: Any, native: Any, trust: Any, occ: str, call: str) -> Any:
            blind = dict(native, execution_receipt={"result": NOT_ESTABLISHED})
            return real(arts, blind, trust, occ, call)

        monkeypatch.setattr(reader, "judge_not_run", no_receipt_check)
        assert _judge("not_run_beside_execution_receipt")["not_run_settlement"] == "ESTABLISHED"

    def test_link_ignores_signatures(self) -> None:
        got = _judge("payment_signature_broken_link_intact")
        assert got["payment_receipt"] == "CONTRADICTED" and got["occurrence_link"] == "ESTABLISHED"


def test_tampered_corpus_is_refused(tmp_path: Path) -> None:
    copy_root = tmp_path / "corpus"
    shutil.copytree(CORPUS, copy_root)
    path = copy_root / "cases.json"
    path.write_text(path.read_text().replace("ESTABLISHED", "CONTRADICTED", 1))
    with pytest.raises(MalformedInput):
        run_corpus(copy_root)


def test_cli_writes_a_report_and_refuses_reuse(tmp_path: Path) -> None:
    out = tmp_path / "run"
    assert run_main(["--output", str(out), "--implementation-revision", "a" * 40]) == 0
    report = json.loads((out / "report.json").read_text())
    assert report["failures"] == [] and len(report["results"]) == len(CASES)
    assert report["native_axes"] == list(reader.NATIVE_AXES)
    with pytest.raises(FileExistsError):
        run_main(["--output", str(out), "--implementation-revision", "a" * 40])
    with pytest.raises(SystemExit):
        run_main(["--output", str(tmp_path / "bad"), "--implementation-revision", "HEAD"])


def test_cli_reports_a_wrong_expectation(tmp_path: Path) -> None:
    copy_root = tmp_path / "corpus"
    shutil.copytree(CORPUS, copy_root)
    cases = json.loads((copy_root / "cases.json").read_text())
    cases["cases"][0]["expected"]["occurrence_link"] = "CONTRADICTED"
    text = json.dumps(cases, indent=2, ensure_ascii=False) + "\n"
    (copy_root / "cases.json").write_text(text)
    manifest = json.loads((copy_root / "manifest.json").read_text())
    manifest["members"]["cases.json"] = reader.sha256_tag(text.encode())
    (copy_root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    out = tmp_path / "run"
    code = run_main(
        ["--corpus", str(copy_root), "--output", str(out), "--implementation-revision", "b" * 40]
    )
    assert code == 1
