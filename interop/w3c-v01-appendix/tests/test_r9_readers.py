"""The R9 reader comparison: the probe corpus makes a reader print its own verdict per member."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path
from typing import Any

import pytest

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


def run_r9_on_one_release(tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
                          go: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    """Run main() over one fake release whose digest and counts hold, with every reader mocked.

    Nothing is fetched or built: the tree is a one-member corpus written here,
    the reference reader and the Python reader print the clean verdict, and the
    Go reader is whatever ``go`` says. So the row's result turns only on how the
    Go reader is recorded.
    """
    tag = "v9.9.9"
    tree = tmp_path / "tree"
    corpus = tree / "vectors-w3c-report"
    corpus.mkdir(parents=True)
    (corpus / "va.json").write_text("{}\n", encoding="utf-8")
    manifest: dict[str, Any] = {
        "requirements": [{"id": r9.ROW, "status": "agreed"}],
        "vectors": [{"id": "va", "file": "va.json", "subjectType": "report", "kind": "reject",
                     "requirements": [r9.ROW], "expected": {"verdict": "reject", "rejects": [r9.ROW]}}],
    }
    digest = r9.corpus_digest(corpus, manifest)
    (corpus / "MANIFEST.json").write_text(json.dumps({**manifest, "corpusDigest": digest}), encoding="utf-8")

    rows = copy.deepcopy(r9.rerun.ROWS)
    rows["aev_tags"] = {tag: "0" * 40}
    rows["rows"]["R9"]["expect"] = {tag: {"corpusDigest": digest, "selected": {"reject": 1, "accept": 0}}}
    rows["rows"]["R9"]["pins"]["readers"] = {tag: ["go", "python"]}
    monkeypatch.setattr(r9.rerun, "ROWS", rows)
    monkeypatch.setattr(r9.rerun, "aev_tree", lambda tag, dest, log, paths: tree)

    def reference_reader(cmd: list[str], cwd: Path, log: Path, env: dict[str, str] | None = None,
                         stdout: Path | None = None, merge: bool = False) -> int:
        assert stdout is not None
        stdout.write_text(r9.CLEAN + "\n", encoding="utf-8")
        return 0

    monkeypatch.setattr(r9.rerun, "run", reference_reader)
    monkeypatch.setattr(r9, "reader_commands", lambda tag, tree, work, log: {
        "go": dict(go), "rust": {"absent": "readers/w3c-report-rs does not exist at v9.9.9"}})
    probe = f"FAIL va: the validator rejects under [{r9.ROW}] and the manifest expects [{r9.PROBE_ROW}]\n"

    def judged(label: str) -> tuple[int, str]:
        return (0, r9.CLEAN + "\n") if label == "clean" else (1, probe)

    monkeypatch.setattr(r9, "judge_python", lambda tag, corpus, work, log, label: judged(label))
    monkeypatch.setattr(r9, "judge_binary", lambda argv, tag, name, corpus, work, log, label: judged(label))

    work = tmp_path / "work"
    work.mkdir()
    result = tmp_path / "result.json"
    monkeypatch.setattr(sys, "argv", ["r9_corpus_history.py", str(work), str(result)])
    code = r9.main()
    return code, json.loads(result.read_text(encoding="utf-8"))


def test_row_passes_when_every_named_reader_built_and_agrees(tmp_path: Path,
                                                             monkeypatch: pytest.MonkeyPatch) -> None:
    code, result = run_r9_on_one_release(tmp_path, monkeypatch, {"argv": ["aee-verify"], "version": "go1.24"})
    comparison = result["releases"]["v9.9.9"]["reader_comparison"]
    assert code == 0 and result["ok"] and comparison["ok"]
    assert comparison["readers_run"] == ["go", "python"]


def test_a_failed_required_build_fails_the_row_while_the_other_reader_passes(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, result = run_r9_on_one_release(tmp_path, monkeypatch, {"build_failed": "go build exited 1"})
    comparison = result["releases"]["v9.9.9"]["reader_comparison"]
    assert comparison["readers"]["python"]["ok"]
    assert comparison["coverage"]["build_failed"] == ["go"] and comparison["readers_run"] == ["python"]
    assert not comparison["ok"]
    assert code == 1 and not result["ok"]
