"""The R9 reader comparison: the probe corpus makes a reader print its own verdict per member."""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
from rows import r9_corpus_history as r9  # noqa: E402


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


PYTHON_RAN = {"version": "agent-evidence-vectors==0.17.4"}
GO_RAN = {"argv": ["aee-verify"], "version": "go1.24"}
RUST_ABSENT = {"absent": "readers/w3c-report-rs does not exist at v0.17.4"}


def test_coverage_passes_when_the_named_readers_are_exactly_the_ones_that_ran() -> None:
    covered = r9.coverage(["go", "python"], {"python": PYTHON_RAN, "go": GO_RAN, "rust": RUST_ABSENT})
    assert covered["ok"]
    assert covered["ran"] == ["go", "python"] and covered["absent"] == ["rust"]


def test_a_failed_build_fails_coverage_instead_of_leaving_the_reader_out() -> None:
    covered = r9.coverage(["go", "python"],
                          {"python": PYTHON_RAN, "go": {"build_failed": "go build exited 1"},
                           "rust": RUST_ABSENT})
    assert not covered["ok"]
    assert covered["build_failed"] == ["go"] and covered["ran"] == ["python"]


def test_a_named_reader_absent_at_the_tag_fails_coverage() -> None:
    covered = r9.coverage(["go", "python", "rust"], {"python": PYTHON_RAN, "go": GO_RAN, "rust": RUST_ABSENT})
    assert not covered["ok"]


def test_a_reader_present_but_not_named_fails_coverage() -> None:
    covered = r9.coverage(["go", "python"], {"python": PYTHON_RAN, "go": GO_RAN,
                                             "rust": {"argv": ["w3c-report-rs"], "version": "rustc 1.96.0"}})
    assert not covered["ok"]


def test_rows_json_names_the_readers_for_every_release_r9_checks() -> None:
    row = r9.rerun.ROWS["rows"]["R9"]
    readers = row["pins"]["readers"]
    assert sorted(readers) == sorted(row["expect"]) == sorted(row["pins"]["tags"])
    assert readers["v0.17.4"] == ["go", "python"]
    assert all(readers[tag] == ["go", "python", "rust"] for tag in ("v0.18.0", "v0.18.1"))
