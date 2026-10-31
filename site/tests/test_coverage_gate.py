"""A completely covered defect must still fail the public example gate."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest


EXAMPLE = Path(__file__).resolve().parents[1] / "examples/approved-sql"


@pytest.mark.parametrize(
    ("test_source", "expected_exit", "pytest_exit"),
    [
        ("from sample.answer import answer\ndef test_answer():\n    assert answer() == 42\n", 0, None),
        ("from sample.answer import answer\ndef test_answer():\n    assert answer() == 99\n", 2, 1),
        ("from sample.answer import answer\nraise RuntimeError('collection defect')\n", 2, 2),
        ("from sample.answer import answer\n", 2, 5),
        ("def test_unrelated():\n    assert True\n", 2, None),
    ],
    ids=["passing-control", "fully-covered-defect", "collection-error", "no-tests", "no-source-coverage"],
)
def test_actual_pytest_exit_controls_coverage_result(
    tmp_path: Path, test_source: str, expected_exit: int, pytest_exit: int | None
) -> None:
    """Use actual pytest/coverage processes and fresh isolated source files."""
    (tmp_path / "sample").mkdir()
    (tmp_path / "sample/answer.py").write_text("def answer():\n    return 42\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests/test_answer.py").write_text(test_source)
    environment = os.environ.copy()
    environment["PATH"] = str(EXAMPLE / ".venv/bin") + os.pathsep + environment["PATH"]
    environment["PYTHONPATH"] = str(tmp_path)
    environment.pop("COVERAGE_PROCESS_START", None)
    environment.pop("COVERAGE_FILE", None)
    result = subprocess.run(
        [str(EXAMPLE / ".venv/bin/python"), str(EXAMPLE / "scripts/check_coverage.py"),
         "--src-dir", "sample", "--test-path", "tests", "--threshold", "100", "--json"],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == expected_exit, result.stdout + result.stderr
    if expected_exit:
        if pytest_exit is not None:
            assert f"pytest exited {pytest_exit}" in result.stderr
        else:
            assert "Coverage JSON not generated successfully (exit 1)" in result.stderr
        assert not result.stdout
        assert not (tmp_path / ".coverage.json").exists()
    else:
        report = json.loads(result.stdout)
        assert report["files_failing"] == 0
        assert report["total_files"] == 1
        assert report["aggregate_coverage"] == 100
        assert report["passing"] is True
