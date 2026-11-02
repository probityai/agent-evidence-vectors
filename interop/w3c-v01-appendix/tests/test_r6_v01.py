"""R6-v01: the committed re-encoding is what the script writes, and it conforms."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent / "R6-v01"
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "packaging"))
_SPEC = importlib.util.spec_from_file_location("reencode_r6", HERE / "reencode_r6.py")
assert _SPEC is not None and _SPEC.loader is not None
reencode_r6 = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(reencode_r6)
from agent_evidence_vectors import w3creport  # noqa: E402


def test_committed_output_is_the_script_output(tmp_path: Path) -> None:
    out = tmp_path / "report-v01.json"
    assert reencode_r6.main([str(HERE / "posted-records.v0.1.json"), "--out", str(out)]) == 0
    assert out.read_bytes() == (HERE / "report-v01.json").read_bytes()


def test_output_conforms_and_posted_does_not() -> None:
    out = json.loads((HERE / "report-v01.json").read_text(encoding="utf-8"))
    assert w3creport.shape_errors(out) == []
    assert w3creport.rejections(out) == []
    posted = json.loads((HERE / "posted-records.v0.1.json").read_text(encoding="utf-8"))
    assert w3creport.shape_errors(posted) != []


def test_refuses_any_other_input() -> None:
    raw = (HERE / "posted-records.v0.1.json").read_bytes()
    with pytest.raises(reencode_r6.Refused):
        reencode_r6.reencode(raw + b" ")


def test_a_flipped_state_is_rejected() -> None:
    out = json.loads((HERE / "report-v01.json").read_text(encoding="utf-8"))
    out["checks"][0]["state"] = "fail"
    assert w3creport.rejections(out) != []
