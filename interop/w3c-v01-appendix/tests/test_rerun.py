"""Refusal paths of the appendix harness: a pin that does not hold fails the row."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rerun  # noqa: E402


def test_every_row_has_a_handler_messages_and_a_command() -> None:
    assert set(rerun.ROWS["rows"]) == set(rerun.HANDLERS)
    for row_id, row in rerun.ROWS["rows"].items():
        assert row["messages"], row_id
        assert row["command"], row_id
        assert row["kind"] in {"rerun", "comparison", "no-command"}, row_id


def test_every_commit_pin_is_a_full_sha() -> None:
    def walk(value: object) -> list[str]:
        if isinstance(value, dict):
            return [s for k, v in value.items() for s in
                    ([v] if k in {"commit"} and isinstance(v, str) else walk(v))]
        if isinstance(value, list):
            return [s for v in value for s in walk(v)]
        return []
    pins = walk(rerun.ROWS["rows"]) + list(rerun.ROWS["aev_tags"].values())
    pins += rerun.ROWS["rows"]["R6"]["pins"]["commits"]
    assert pins
    for pin in pins:
        assert len(pin) == 40 and int(pin, 16) >= 0, pin


def test_short_commit_is_refused(tmp_path: Path) -> None:
    with pytest.raises(rerun.Refused, match="not a full commit SHA"):
        rerun.fetch_commit("probityai/agent-evidence-vectors", "82b8bb6", tmp_path / "x",
                           tmp_path / "log.txt")


def _seed_attachment(cache: Path, name: str, data: bytes) -> None:
    path = cache / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def test_attachment_with_other_bytes_is_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    name = "att-0063/disensor-w3c-v01-dbdb651.zip"
    _seed_attachment(tmp_path, name, b"not the posted zip")
    with pytest.raises(rerun.Refused, match="posted"):
        rerun.attachment(name, tmp_path)


def test_text_attachment_drops_only_the_archive_newline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    body = b"v1\nv2\n"
    name = "att-9999/ids.txt"
    monkeypatch.setitem(rerun.ROWS["attachments"], name,
                        {"sha256": hashlib.sha256(body).hexdigest(), "text": True})
    _seed_attachment(tmp_path, name, body + b"\n")
    assert rerun.attachment(name, tmp_path) == body
    _seed_attachment(tmp_path, name, body + b"x\n\n")
    with pytest.raises(rerun.Refused):
        rerun.attachment(name, tmp_path)


def test_compare_trees_fails_on_a_changed_missing_or_extra_file() -> None:
    posted = {"a.json": "1", "b.json": "2", "run.json": "3"}
    allowed = {"run.json": "carries the runner"}
    assert rerun.compare_trees(posted, dict(posted), allowed)["ok"]
    assert rerun.compare_trees(posted, {**posted, "run.json": "9"}, allowed)["ok"]
    assert not rerun.compare_trees(posted, {**posted, "a.json": "9"}, allowed)["ok"]
    assert not rerun.compare_trees(posted, {"a.json": "1", "run.json": "3"}, allowed)["ok"]
    assert not rerun.compare_trees(posted, {**posted, "new.json": "4"}, allowed)["ok"]
    beside = rerun.compare_trees(posted, {**posted, "evaluation/t.json": "4"}, allowed,
                                 {"evaluation/": "traces"})
    assert beside["ok"] and beside["outside_record_set"]["files"] == 1


def test_expect_files_reports_the_observed_digest(tmp_path: Path) -> None:
    (tmp_path / "report.json").write_bytes(b"{}")
    detail = rerun.expect_files(tmp_path, {"report.json": "0" * 64})
    assert not detail["ok"]
    assert detail["files"][0]["observed"] == hashlib.sha256(b"{}").hexdigest()


def test_a_row_that_does_not_reproduce_exits_nonzero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(rerun.HANDLERS, "R1", lambda w, log, row: (False, {"observed": "x"}))
    status = rerun.rerun("R1", tmp_path / "work", tmp_path / "results")
    assert status == rerun.DIFFERS
    written = json.loads((tmp_path / "results" / "R1.json").read_text())
    assert written["status"] == "differs" and written["detail"] == {"observed": "x"}


def test_a_refused_pin_is_an_error_not_a_pass(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(w: Path, log: Path, row: dict) -> tuple[bool, dict]:
        raise rerun.Refused("pin moved")
    monkeypatch.setitem(rerun.HANDLERS, "R15", refuse)
    assert rerun.rerun("R15", tmp_path / "work", tmp_path / "results") == rerun.ERROR


def test_unittest_summary_counts_runs_and_skips() -> None:
    assert rerun.unittest_summary("Ran 18 tests in 0.3s\n\nOK\n") == {"ran": 18, "skipped": 0, "ok": True}
    assert rerun.unittest_summary("Ran 6 tests in 0.1s\n\nOK (skipped=2)\n")["skipped"] == 2
    assert not rerun.unittest_summary("Ran 6 tests in 0.1s\n\nFAILED (failures=1)\n")["ok"]
    assert rerun.unittest_summary("no tests here")["ran"] is None
