"""The corpus refuses byte drift and a verifier that supports every case."""

from __future__ import annotations

import importlib.util
import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
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
            verifier = os.environ.get("PROBITY_VERIFY_COMMAND")
            if verifier is None:
                sibling = ROOT.parent.parent / "probity-verify-review"
                if not sibling.exists():
                    pytest.skip("set PROBITY_VERIFY_COMMAND to the verifier under test")
                verifier = f"uv run --project {sibling} --locked probity-verify"
            executed, errors = corpus.check(verifier)
            assert executed == 6
            assert errors == []

    class TestFailingCases:
        def test_missing_verifier_does_not_count_as_executed(self, tmp_path: Path) -> None:
            executed, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert executed == 0
            assert len(errors) == 6
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            (copied / "cases" / "complete" / "report.txt").write_bytes(b"different")
            executed, errors = corpus.check("/bin/false", root=copied)
            assert executed == 5
            assert "complete: fixture digest mismatch" in errors

        def test_always_support_verifier_is_refused(self, tmp_path: Path) -> None:
            stub = tmp_path / "always.py"
            stub.write_text(
                'import json\nprint(json.dumps({"decision": "supported", '
                '"reason": "all_selected_spans_present"}))\n',
                encoding="ascii",
            )
            executed, errors = corpus.check(f"{sys.executable} {stub}")
            assert executed == 6
            assert len(errors) == 5
            assert all("expected" in error for error in errors)
