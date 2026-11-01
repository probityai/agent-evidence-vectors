"""The R9 reader comparison: the probe corpus makes a reader print its own verdict per member."""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "rows"))
import r9_corpus_history as r9  # noqa: E402


def test_probe_expects_every_member_rejected_under_a_row_nobody_cites(tmp_path: Path) -> None:
    source = tmp_path / "corpus"
    source.mkdir()
    manifest = {"vectors": [{"id": "va", "expected": {"verdict": "accept", "rejects": []}},
                            {"id": "vb", "expected": {"verdict": "reject", "rejects": ["W3C-R-016"]}}]}
    (source / "MANIFEST.json").write_text(json.dumps(manifest), encoding="utf-8")
    r9.probe_corpus(source, tmp_path / "probe")
    probed = json.loads((tmp_path / "probe" / "MANIFEST.json").read_text(encoding="utf-8"))
    assert [e["expected"]["rejects"] for e in probed["vectors"]] == [[r9.PROBE_ROW]] * 2
    assert json.loads((source / "MANIFEST.json").read_text(encoding="utf-8")) == manifest


def test_verdicts_read_rows_and_malformed_subjects_from_the_printed_lines() -> None:
    text = "\n".join([
        "suite: w3c-report-v01-conformance",
        "FAIL va: the validator rejects under [] and the manifest expects [W3C-R-999]",
        "FAIL vb: the validator rejects under [W3C-R-016, W3C-R-020] and the manifest expects [W3C-R-999]",
        "FAIL vb: identifier does not recompute from the member's own bytes",
        f"FAIL vc: {r9.SHAPE}: checks is not a list",
        "verdict: 3 member(s) and 0 corpus-level claim(s) do not hold",
    ])
    assert r9.verdicts(text) == {"va": [], "vb": ["W3C-R-016", "W3C-R-020"], "vc": "malformed"}


def test_a_verdict_digest_moves_with_any_member_verdict() -> None:
    base = {"va": [], "vb": ["W3C-R-016"]}
    assert r9.verdict_digest(base) == r9.verdict_digest(dict(reversed(list(base.items()))))
    assert r9.verdict_digest(base) != r9.verdict_digest({**base, "vb": []})
    assert r9.verdict_digest(base) != r9.verdict_digest({**base, "vb": None})
