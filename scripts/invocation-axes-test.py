"""Challenge the three-axis reader: every expected answer, every refusal, every kill."""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

PACKAGING = Path(__file__).resolve().parents[1] / "packaging"
sys.path.insert(0, str(PACKAGING))

from agent_evidence_vectors.invocation_axes import reader  # noqa: E402
from agent_evidence_vectors.invocation_axes.reader import (  # noqa: E402
    NOT_ESTABLISHED,
    MalformedInput,
    evaluate,
    parse_strict,
    summary,
)
from agent_evidence_vectors.invocation_axes.run import main as run_main  # noqa: E402
from agent_evidence_vectors.invocation_axes.run import run_corpus  # noqa: E402

CORPUS = PACKAGING / "agent_evidence_vectors/invocation_axes/corpus"
INVOCATION = json.loads((CORPUS / "invocation.json").read_text())
CASES = json.loads((CORPUS / "cases.json").read_text())["cases"]
BY_ID = {case["id"]: case for case in CASES}


def _judge(case_id: str) -> dict[str, str]:
    return summary(evaluate(INVOCATION, BY_ID[case_id]))


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_every_case_matches_its_expected_answer(case: dict[str, Any]) -> None:
    assert summary(evaluate(INVOCATION, case)) == case["expected"]


def test_each_axis_has_accept_and_reject_vectors() -> None:
    for axis in reader.AXES:
        words = {case["expected"][axis] for case in CASES}
        assert {"ESTABLISHED", "CONTRADICTED", "NOT_ESTABLISHED"} <= words, axis


def test_reader_never_reads_the_expected_answer() -> None:
    case = copy.deepcopy(BY_ID["intact_pair"])
    del case["expected"]
    assert summary(evaluate(INVOCATION, case))["observed_effect"] == "ESTABLISHED"


def _with_outcome(case_id: str, outcome: Any) -> dict[str, str]:
    case = copy.deepcopy(BY_ID[case_id])
    case["execution"]["dispatch"]["outcome"] = outcome
    return summary(evaluate(INVOCATION, case))


def test_dispatch_outcomes_follow_remora_vocabulary() -> None:
    assert _with_outcome("intact_pair", "BEGAN_OUTCOME_UNKNOWN")["observed_effect"] == "ESTABLISHED"
    assert _with_outcome("dispatched_after_deny", "BEGAN_OUTCOME_UNKNOWN")[
        "observed_effect"
    ] == "CONTRADICTED"
    assert _with_outcome("intact_pair", "REFUSED")["observed_effect"] == "CONTRADICTED"


@pytest.mark.parametrize("outcome", ["NOT_DISPATCHED", "dispatched", None, 1])
def test_unrecognised_dispatch_outcome_is_not_established(outcome: Any) -> None:
    case = copy.deepcopy(BY_ID["success_reported_without_dispatch"])
    case["execution"]["dispatch"]["outcome"] = outcome
    result = evaluate(INVOCATION, case)
    assert summary(result)["observed_effect"] == "NOT_ESTABLISHED"


def test_corpus_is_what_the_builder_writes() -> None:
    script = Path(__file__).with_name("invocation-axes-build.py")
    assert subprocess.run([sys.executable, str(script), "--check"], check=False).returncode == 0


@settings(max_examples=60, deadline=None)
@given(st.dictionaries(st.text(min_size=1, max_size=12), st.text(max_size=40), max_size=4))
def test_no_member_can_raise_a_non_claim(extra: dict[str, str]) -> None:
    case = copy.deepcopy(BY_ID["package_claims_complete_coverage"])
    case["capture"]["objects"].update({f"x-{k}": v for k, v in extra.items()})
    got = summary(evaluate(INVOCATION, case))
    for prop in reader.NON_CLAIMS:
        assert got[prop] == NOT_ESTABLISHED


@pytest.mark.parametrize(
    "data",
    [b'{"a":1,"a":2}', b'{"a":1.5}', b'{"a":NaN}', b"\xff\xfe", b"{not json"],
    ids=["duplicate", "float", "nan", "not-utf8", "not-json"],
)
def test_malformed_input_is_refused_before_judgement(data: bytes) -> None:
    with pytest.raises(MalformedInput):
        parse_strict(data)


def test_non_tools_call_request_is_refused() -> None:
    with pytest.raises(MalformedInput):
        reader.invocation_binding({"method": "tools/list", "params": {}})


def test_wrong_schemas_are_refused() -> None:
    capture = copy.deepcopy(BY_ID["intact_pair"]["capture"])
    capture["manifest"]["schema"] = "other"
    with pytest.raises(MalformedInput):
        reader.judge_package(capture)
    case = copy.deepcopy(BY_ID["intact_pair"])
    case["execution"]["schema"] = "other"
    with pytest.raises(MalformedInput):
        evaluate(INVOCATION, case)


def test_canonical_refuses_floats() -> None:
    with pytest.raises(MalformedInput):
        reader.canonical({"a": 1.5})


class TestKills:
    """Disable one rule at a time; a named case must turn."""

    def test_strict_kinds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(reader, "_same", lambda a, b: a == b)
        assert _judge("bool_is_not_integer")["observed_effect"] == "ESTABLISHED"

    def test_canonical_member_order(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def unsorted(request: dict[str, Any]) -> str:
            body = {"method": request["method"], "params": request["params"]}
            return reader.sha256_tag(json.dumps(body, separators=(",", ":")).encode())

        real = reader.invocation_binding
        pinned = real(INVOCATION)
        monkeypatch.setattr(
            reader, "invocation_binding", lambda r: pinned if r is INVOCATION else unsorted(r)
        )
        assert (
            _judge("argument_members_reordered")["request_decision_correspondence"]
            == "CONTRADICTED"
        )

    def test_pin_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real = reader.sha256_tag
        monkeypatch.setattr(
            reader,
            "judge_package",
            lambda capture: reader._result("ESTABLISHED", "pin skipped"),
        )
        assert real(b"x").startswith("sha256:")
        assert _judge("manifest_rewritten_to_cover_change")["package_integrity"] == "ESTABLISHED"

    def test_independent_source(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(reader, "INDEPENDENT_SOURCE", "tool")
        assert _judge("observation_from_the_tool")["observed_effect"] == "ESTABLISHED"

    def test_deny_dispatch(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real = reader._dispatch_gate
        monkeypatch.setattr(
            reader,
            "_dispatch_gate",
            lambda b, bind, corr: real(b, bind, dict(corr, decision="allow")),
        )
        assert _judge("dispatched_after_deny")["observed_effect"] == "ESTABLISHED"


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
    with pytest.raises(FileExistsError):
        run_main(["--output", str(out), "--implementation-revision", "a" * 40])
    with pytest.raises(SystemExit):
        run_main(["--output", str(tmp_path / "bad"), "--implementation-revision", "HEAD"])


def test_cli_reports_a_wrong_expectation(tmp_path: Path) -> None:
    copy_root = tmp_path / "corpus"
    shutil.copytree(CORPUS, copy_root)
    cases = json.loads((copy_root / "cases.json").read_text())
    cases["cases"][0]["expected"]["observed_effect"] = "CONTRADICTED"
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
