"""The corpus regenerates, forces every check and refuses a reader that trusts the statement."""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("empty_interval_corpus", ROOT / "check_vectors.py")
generator = _load("empty_interval_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import emptyinterval  # noqa: E402


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    """A verifier that runs the reference reader with the named checks switched off."""
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "import run_vectors\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import emptyinterval as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


class TestEmptyIntervalCorpus:
    class TestPassingCases:
        def test_regeneration_is_byte_identical(self, tmp_path: Path) -> None:
            generator.generate(tmp_path)
            committed = {
                p.relative_to(ROOT): p.read_bytes()
                for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")]
                if p.is_file()
            }
            regenerated = {
                p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()
            }
            assert regenerated == committed

        def test_reference_reader_agrees_with_every_case(self) -> None:
            answered, errors = corpus.check()
            assert errors == []
            assert answered == len(generator.cases())

        def test_reference_reader_through_the_external_contract(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(_stub(tmp_path, ()))
            assert errors == []
            assert answered == len(generator.cases())

        def test_every_value_of_the_term_is_reached(self) -> None:
            manifest = emptyinterval.json.loads((ROOT / "MANIFEST.json").read_text())
            assert set(manifest["counts"]) == set(emptyinterval.EXIT_FOR)

    class TestFailingCases:
        @pytest.mark.parametrize("name", emptyinterval.CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_reader_that_trusts_the_statement_is_refused(self, tmp_path: Path) -> None:
            _, errors = corpus.check(_stub(tmp_path, emptyinterval.CHECKS[2:]))
            assert {
                "event-edited-in-place",
                "event-deleted-from-interval",
                "ledger-rolled-back-to-abandoned-branch",
                "forged-statement-signature",
            } <= _failed(errors)

        def test_verifier_that_reads_every_empty_list_as_not_recorded_fails_the_controls(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "empty.py"
            script.write_text(
                'import json, sys\nprint(json.dumps({"decision": "not_recorded", '
                '"reason": "no_revocation_in_covered_interval"}))\nsys.exit(1)\n',
                encoding="ascii",
            )
            _, errors = corpus.check(f"{sys.executable} {script}")
            assert {
                "interval-holds-revocation",
                "statement-omits-recorded-event",
                "query-failed",
                "cross-federation-unsynchronised",
            } <= _failed(errors)

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            (copied / "cases" / "query-failed" / "ledger.jsonl").write_bytes(b"{}\n")
            _, errors = corpus.check(root=copied)
            assert "query-failed: fixture digest mismatch" in errors
