"""Challenge the resumed-task reader: every expected answer, refusal and rule kill."""

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

from agent_evidence_vectors.resume_turns import reader  # noqa: E402
from agent_evidence_vectors.resume_turns.reader import (  # noqa: E402
    MalformedInput,
    evaluate,
    summary,
)
from agent_evidence_vectors.resume_turns.run import main as run_main  # noqa: E402
from agent_evidence_vectors.resume_turns.run import run_corpus  # noqa: E402

CORPUS = PACKAGING / "agent_evidence_vectors/resume_turns/corpus"
CASES = json.loads((CORPUS / "cases.json").read_text())["cases"]
BY_ID = {case["id"]: case for case in CASES}


def _judge(case_id: str) -> dict[str, str]:
    return summary(evaluate(BY_ID[case_id]))


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_every_case_matches_its_expected_answer(case: dict[str, Any]) -> None:
    assert summary(evaluate(case)) == case["expected"]


def test_each_axis_has_all_three_answers() -> None:
    for axis in reader.AXES:
        assert {c["expected"][axis] for c in CASES} == {
            "ESTABLISHED",
            "CONTRADICTED",
            "NOT_ESTABLISHED",
        }, axis


def test_replay_and_repeated_effect_are_separate_claims() -> None:
    replay = _judge("earlier_turn_artifacts_replayed")
    assert (
        replay["artifact_replay"] == "CONTRADICTED" and replay["repeated_effect"] == "ESTABLISHED"
    )
    hidden = _judge("second_effect_hidden_by_deduplicated_display")
    assert (
        hidden["artifact_replay"] == "ESTABLISHED" and hidden["repeated_effect"] == "CONTRADICTED"
    )


def test_reader_never_reads_the_expected_answer() -> None:
    case = copy.deepcopy(BY_ID["intact_resume"])
    del case["expected"]
    assert summary(evaluate(case))["turn_owner"] == "ESTABLISHED"


def test_corpus_is_what_the_builder_writes() -> None:
    script = Path(__file__).with_name("resume-turns-build.py")
    assert subprocess.run([sys.executable, str(script), "--check"], check=False).returncode == 0


def test_unknown_author_and_operation_and_schema_are_refused() -> None:
    case = copy.deepcopy(BY_ID["intact_resume"])
    case["task"]["paused_by"] = "ghost"
    with pytest.raises(MalformedInput):
        evaluate(case)
    case = copy.deepcopy(BY_ID["intact_resume"])
    case["task"]["resumed_response_artifacts"][0]["op"] = "merge"
    with pytest.raises(MalformedInput):
        evaluate(case)
    case = copy.deepcopy(BY_ID["intact_resume"])
    case["task"]["schema"] = "other"
    with pytest.raises(MalformedInput):
        evaluate(case)


class TestKills:
    """Disable one rule at a time; a named case must turn."""

    def test_single_turn_is_delegated(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(reader, "DELEGATED_MODES", frozenset({"task"}))
        assert _judge("paused_single_turn_agent_answers_user")["turn_owner"] == "ESTABLISHED"

    def test_replace_is_whole(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real = reader._new_parts
        monkeypatch.setattr(reader, "_new_parts", lambda e, p, op: real(e, p, "append"))
        assert _judge("replaced_artifact_shares_leading_part")["artifact_replay"] == "ESTABLISHED"

    def test_positional_comparison(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            reader,
            "_new_parts",
            lambda e, p, op: [x for x in e if x not in p] if op == "append" else e,
        )
        assert _judge("appended_part_equal_to_an_earlier_one")["artifact_replay"] == "CONTRADICTED"

    def test_only_independent_observations_count(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(reader, "INDEPENDENT", "tool")
        assert _judge("effect_reported_only_by_the_tool")["repeated_effect"] == "CONTRADICTED"


def test_tampered_corpus_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "corpus"
    shutil.copytree(CORPUS, root)
    path = root / "cases.json"
    path.write_text(path.read_text().replace("ESTABLISHED", "CONTRADICTED", 1))
    with pytest.raises(MalformedInput):
        run_corpus(root)


def test_cli_writes_a_report_and_refuses_reuse(tmp_path: Path) -> None:
    out = tmp_path / "run"
    assert run_main(["--output", str(out), "--implementation-revision", "a" * 40]) == 0
    assert json.loads((out / "report.json").read_text())["failures"] == []
    with pytest.raises(FileExistsError):
        run_main(["--output", str(out), "--implementation-revision", "a" * 40])
