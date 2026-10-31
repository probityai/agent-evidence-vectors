"""Matching output cannot turn a failed R10 reader invocation into a pass."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rerun  # noqa: E402
from rows import r10_minus_zero  # noqa: E402


@pytest.mark.parametrize("tag,reader,child_exit,wrong_bytes,expected_exit", [
    ("v0.17.4", "python", 0, False, 0),
    ("v0.17.4", "python", 7, False, 1),
    ("v0.17.4", "go", 7, False, 1),
    ("v0.18.1", "python", 7, False, 1),
    ("v0.18.1", "go", 7, False, 1),
    ("v0.18.1", "python", 0, True, 1),
    ("v0.18.1", "go", 0, True, 1),
])
def test_row_requires_successful_readers_and_matching_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    tag: str, reader: str, child_exit: int, wrong_bytes: bool, expected_exit: int,
) -> None:
    # Replace only the network/process boundaries; run the row's real comparison
    # and result writer. These fixtures do not execute the reference readers.
    def tree(_tag: str, dest: Path, _log: Path, _paths: list[str]) -> Path:
        (dest / "corpora").mkdir(parents=True)
        (dest / "vectors-w3c-report").mkdir()
        return dest

    def run(cmd: list[str], cwd: Path, log: Path, *,
            stdout: Path, env: dict[str, str] | None = None) -> int:
        current_reader, current_tag = stdout.stem.split("-", 1)
        selected = (current_tag, current_reader) == (tag, reader)
        output = ("7b2276223a2d307d" if (current_tag, current_reader) == ("v0.17.4", "go")
                  else "7b2276223a307d")
        if selected and wrong_bytes:
            output = "00"
        stdout.write_text(("HEX " if current_reader == "go" else "") + output + "\n",
                          encoding="utf-8")
        return child_exit if selected else 0

    result = tmp_path / "result.json"
    monkeypatch.setattr(rerun, "aev_tree", tree)
    monkeypatch.setattr(rerun, "run", run)
    monkeypatch.setattr(sys, "argv", ["r10_minus_zero.py", str(tmp_path), str(result)])

    actual_exit = r10_minus_zero.main()
    written = json.loads(result.read_text(encoding="utf-8"))
    # Keep failure diagnostics even when matching bytes cannot justify a pass.
    assert written["releases"][tag][reader]["exit"] == child_exit
    assert set(written["releases"]) == {"v0.17.4", "v0.18.1"}
    assert actual_exit == expected_exit
    assert written["ok"] is (expected_exit == 0)
