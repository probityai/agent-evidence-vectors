"""CHECKS.md lists every row of rows.json once, in order, with each of its five cells filled."""

from __future__ import annotations

import json
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def table_rows() -> list[list[str]]:
    lines = (HERE / "CHECKS.md").read_text(encoding="utf-8").splitlines()
    cells = [[c.strip() for c in line.strip().strip("|").split("|")] for line in lines
             if line.startswith("| ") and not line.startswith("| Row ")]
    return cells


def test_checks_md_lists_every_row_once_in_rows_json_order() -> None:
    rows = json.loads((HERE / "rows.json").read_text(encoding="utf-8"))["rows"]
    assert [cells[0] for cells in table_rows()] == list(rows)


def test_every_line_says_what_decides_green_and_what_does_not() -> None:
    for cells in table_rows():
        assert len(cells) == 5, cells
        assert all(cells), cells


def test_rows_that_let_whole_files_differ_name_those_files() -> None:
    rows = json.loads((HERE / "rows.json").read_text(encoding="utf-8"))["rows"]
    by_row = {cells[0]: cells for cells in table_rows()}
    for row_id, row in rows.items():
        for name in row.get("may_differ") or {}:
            assert f"{name} as a whole file" in by_row[row_id][4], (row_id, name)
