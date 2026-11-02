"""The corpus refuses byte drift and a verifier that supports every case."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
TOTAL = len(MANIFEST["vectors"])
SUPPORTED = sum(v["expected"]["decision"] == "supported" for v in MANIFEST["vectors"])
SPEC = importlib.util.spec_from_file_location("source_coverage_corpus", ROOT / "check_vectors.py")
assert SPEC and SPEC.loader
corpus = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(corpus)
GEN_SPEC = importlib.util.spec_from_file_location(
    "source_coverage_generator", ROOT / "gen_vectors.py"
)
assert GEN_SPEC and GEN_SPEC.loader
generator = importlib.util.module_from_spec(GEN_SPEC)
GEN_SPEC.loader.exec_module(generator)


class TestSourceCoverageCorpus:
    class TestPassingCases:
        def test_regeneration_is_byte_identical(self, tmp_path: Path) -> None:
            generator.generate(tmp_path)
            committed_files = [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")]
            committed = {p.relative_to(ROOT): p.read_bytes()
                         for p in committed_files if p.is_file()}
            regenerated = {p.relative_to(tmp_path): p.read_bytes()
                           for p in tmp_path.rglob("*") if p.is_file()}
            assert regenerated == committed

        def test_published_verifier_executes_all_cases(self) -> None:
            verifier = os.environ.get("SOURCE_COVERAGE_VERIFIER")
            if verifier is None:
                pytest.skip("set SOURCE_COVERAGE_VERIFIER to the verifier under test")
            executed, errors = corpus.check(verifier)
            assert executed == TOTAL
            assert errors == []

    class TestFailingCases:
        def test_missing_verifier_does_not_count_as_executed(self, tmp_path: Path) -> None:
            executed, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert executed == 0
            assert len(errors) == TOTAL
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            (copied / "cases" / "complete" / "report.txt").write_bytes(b"different")
            executed, errors = corpus.check("/bin/false", root=copied)
            assert executed == TOTAL - 1
            assert "complete: fixture digest mismatch" in errors

        def test_always_support_verifier_is_refused(self, tmp_path: Path) -> None:
            stub = tmp_path / "always.py"
            stub.write_text(
                'import json\nprint(json.dumps({"decision": "supported", '
                '"reason": "all_selected_spans_present"}))\n',
                encoding="ascii",
            )
            executed, errors = corpus.check(f"{sys.executable} {stub}")
            assert executed == TOTAL
            assert len(errors) == TOTAL - SUPPORTED
            assert all("expected" in error for error in errors)


class TestScannerTruncationPair:
    """The pair from sushant-me/reputation: the tool printed its truncation and passed."""

    def test_defect_record_states_its_own_truncation_and_still_claims_clean(self) -> None:
        record = (ROOT / "cases" / "scanner-truncation-reported-clean" / "report.txt").read_text()
        assert "truncated: 5 repo(s) not opened" in record
        assert "no credential-shaped values found in public repositories" in record

    def test_control_record_reads_every_repository(self) -> None:
        source = (ROOT / "cases" / "scanner-complete-scan" / "source.html").read_text()
        record = (ROOT / "cases" / "scanner-complete-scan" / "report.txt").read_text()
        assert source.count("<p>repo-") == 12
        assert all(f"repo-{n:02d} scanned" in record for n in range(1, 13))
        assert "truncated" not in record

    def test_pair_shares_one_source_and_one_selected_passage(self) -> None:
        a = ROOT / "cases" / "scanner-truncation-reported-clean"
        b = ROOT / "cases" / "scanner-complete-scan"
        assert (a / "source.html").read_bytes() == (b / "source.html").read_bytes()
        pa = json.loads((a / "policy.json").read_text())["assessments"]
        pb = json.loads((b / "policy.json").read_text())["assessments"]
        spans = [next(iter(p.values()))["required_spans"] for p in (pa, pb)]
        assert spans[0] == spans[1]
