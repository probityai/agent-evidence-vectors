"""The paper's table is generated from rows.json, so the committed copy must match it."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent


def test_reproducing_tex_is_generated_from_rows_json() -> None:
    proc = subprocess.run([sys.executable, str(HERE / "paper" / "make_tex.py"), "--check"],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr


def test_every_row_appears_once_in_the_table() -> None:
    text = (HERE / "paper" / "reproducing.tex").read_text(encoding="utf-8")
    sys.path.insert(0, str(HERE))
    import rerun  # noqa: PLC0415
    for row_id in rerun.ROWS["rows"]:
        assert sum(line.startswith(row_id + " & ") for line in text.splitlines()) == 1, row_id
