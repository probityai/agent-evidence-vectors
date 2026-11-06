"""The second producer: its sample conforms, and what it cannot map is refused."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "packaging"))
sys.path.insert(0, str(HERE))
import from_log  # noqa: E402
from agent_evidence_vectors import w3creport  # noqa: E402

HEADER = '{"run": {"checker": "c@1", "constraint_set": "cs"}}\n'


def run(tmp_path: Path, log: str, capsys: pytest.CaptureFixture[str], name: str = "run.jsonl") -> tuple[int, str, Path]:
    source = tmp_path / name
    source.write_text(log, encoding="utf-8")
    out = tmp_path / "report.json"
    code = from_log.main([str(source), "-o", str(out)])
    return code, capsys.readouterr().out, out


def test_sample_run_conforms(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, report = run(tmp_path, (HERE / "sample-run.jsonl").read_text(), capsys)
    assert (code, out) == (0, "conforms\n")
    rollup = json.loads(report.read_text())["roll-up"]
    assert rollup["negative-capable"]["kind"] == "control-failed"
    assert (rollup["pass"], rollup["fail"], rollup["inconclusive"]) == (3, 1, 2)
    assert (rollup["not-exercised"], rollup["void"]) == (1, 1)


def test_sample_inspect_log_conforms(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, out, _ = run(tmp_path, (HERE / "sample-inspect-log.json").read_text(), capsys, "log.json")
    assert (code, out) == (0, "conforms\n")


@pytest.mark.parametrize("line,why", [
    ('{"check": "a", "outcome": "error"}', "needs a reason"),
    ('{"check": "a", "outcome": "skipped", "reason": "it was slow"}', "needs a reason"),
    ('{"check": "a", "outcome": "void", "reason": "withheld"}', "needs a reason"),
    ('{"check": "a", "outcome": "maybe"}', "outcome 'maybe'"),
    ('{"check": "a", "outcome": "pass", "reason": "failed"}', "carries no reason"),
    ('{"check": "a", "outcome": "pass", "score": 1}', "unknown field"),
    ('{"check": "a", "outcome": "pass", "control": "maybe"}', "control 'maybe'"),
    ('{"outcome": "pass"}', "check must be"),
    ("not json", "not JSON"),
])
def test_unmappable_line_is_refused_and_nothing_is_written(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], line: str, why: str
) -> None:
    source = tmp_path / "run.jsonl"
    source.write_text(HEADER + line + "\n", encoding="utf-8")
    report = tmp_path / "report.json"
    assert from_log.main([str(source), "-o", str(report)]) == 2
    captured = capsys.readouterr()
    assert captured.out == "" and why in captured.err
    assert not report.exists()


def test_refusal_names_the_line(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    source = tmp_path / "run.jsonl"
    source.write_text(HEADER + '{"check": "a", "outcome": "pass"}\n{"check": "b", "outcome": "error"}\n')
    assert from_log.main([str(source), "-o", str(tmp_path / "r.json")]) == 2
    assert "line 3: error needs a reason" in capsys.readouterr().err


@pytest.mark.parametrize("log", [
    "",
    HEADER,
    '{"check": "a", "outcome": "pass"}\n',
    HEADER + '{"check": "a", "outcome": "pass"}\n{"check": "a", "outcome": "fail"}\n',
    '{"run": {"checker": "c"}}\n{"check": "a", "outcome": "pass"}\n',
])
def test_header_duplicates_and_empty_logs_are_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], log: str
) -> None:
    code, _, report = run(tmp_path, log, capsys)
    assert code == 2 and not report.exists()


def test_inspect_partial_credit_is_refused(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    doc = json.loads((HERE / "sample-inspect-log.json").read_text())
    doc["samples"][0]["scores"]["match"]["value"] = "P"
    source = tmp_path / "log.json"
    source.write_text(json.dumps(doc), encoding="utf-8")
    report = tmp_path / "report.json"
    assert from_log.main([str(source), "-o", str(report)]) == 2
    assert "neither correct nor incorrect" in capsys.readouterr().err
    assert not report.exists()


def test_a_control_that_did_not_fail_shows_nothing(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = HEADER + '{"check": "a", "outcome": "pass", "control": "pass"}\n'
    log += '{"check": "b", "outcome": "pass", "control": "error"}\n'
    code, out, report = run(tmp_path, log, capsys)
    assert (code, out) == (0, "conforms\n")
    assert json.loads(report.read_text())["roll-up"]["negative-capable"] == {"kind": "nothing"}


def test_a_failed_check_is_shown_by_run_without_a_control(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    log = HEADER + '{"check": "a", "outcome": "fail"}\n'
    _, _, report = run(tmp_path, log, capsys)
    assert json.loads(report.read_text())["roll-up"]["negative-capable"] == {"kind": "shown-by-run"}


def test_reader_rejects_a_tampered_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    _, _, report = run(tmp_path, (HERE / "sample-run.jsonl").read_text(), capsys)
    body = json.loads(report.read_text())
    broken = copy.deepcopy(body)
    broken["checks"][0]["state"] = "fail"
    report.write_text(json.dumps(broken))
    assert w3creport.read(str(report)) == 1
    broken = copy.deepcopy(body)
    broken["roll-up"]["negative-capable"]["control"]["checks"] = ["not-a-check"]
    report.write_text(json.dumps(broken))
    assert w3creport.read(str(report)) == 1
    assert "W3C-R-013" in capsys.readouterr().out


def test_every_reason_is_in_the_package_vocabulary() -> None:
    for causes in from_log.CAUSES_FOR.values():
        assert set(causes) <= set(w3creport.CAUSES)
    assert not set(from_log.CAUSES_FOR["void"]) & set(w3creport.NEVER_EXAMINED)
    assert "integrity-failure" not in from_log.CAUSES_FOR["not-exercised"]
