"""The corpus regenerates, forces every check, and refuses a signature-only verifier."""

from __future__ import annotations

import importlib.util
import json
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


corpus = _load("print_witness_corpus", ROOT / "check_vectors.py")
generator = _load("print_witness_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import printwitness  # noqa: E402

ACCEPTS = {"intact", "intact-other-witness"}
# Every record of these logs verifies under a key the consumer trusts.
SIGNED_REJECTS = {
    "log-stops-early",
    "log-closes-early",
    "gcode-changed-after-signing",
    "gcode-not-ordered",
    "witness-changed-mid-print",
    "log-from-other-print",
    "log-reordered",
    "log-without-intake",
}
# The three questions the corpus answers, each as a reject paired with an accept.
QUESTIONS = {
    "log-stops-early": "intact",
    "gcode-changed-after-signing": "intact",
    "witness-changed-mid-print": "intact-other-witness",
}


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    """A verifier that runs the reference reader with the named checks switched off."""
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "import run_vectors\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import printwitness as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


def _manifest() -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))


class TestPrintWitnessCorpus:
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
            _, errors = corpus.check(_stub(tmp_path, ()))
            assert errors == []

        @pytest.mark.parametrize("name", printwitness.CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_signed_rejects_are_the_listed_cases(self) -> None:
            signed = {
                e["id"]
                for e in _manifest()["vectors"]
                if e["logSignaturesVerify"] and e["expected"]["decision"] == "rejected"
            }
            assert signed == SIGNED_REJECTS

        def test_each_question_is_a_reject_paired_with_an_accept(self) -> None:
            rows = {e["id"]: e for e in _manifest()["vectors"]}
            for reject, accept in QUESTIONS.items():
                assert rows[reject]["pairsWith"] == accept
                assert rows[reject]["expected"]["decision"] == "rejected"
                assert rows[accept]["expected"] == {
                    "decision": "verified",
                    "reason": "print_witnessed",
                }
            assert all(
                rows[e["pairsWith"]]["expected"]["decision"] == "verified"
                for e in rows.values()
                if "pairsWith" in e
            )

        def test_the_intake_names_the_ordered_job_file(self) -> None:
            case = json.loads((ROOT / "cases" / "intact" / "case.json").read_text())
            job = (ROOT / "cases" / "intact" / "job.gcode").read_bytes()
            first = json.loads(
                (ROOT / "cases" / "intact" / "log.jsonl").read_bytes().split(b"\n")[0]
            )["record"]
            assert first["gcode_sha256"] == generator._sha(job) == case["order"]["gcode_sha256"]

    class TestFailingCases:
        def test_signature_only_verifier_is_refused_on_the_signed_rejects(
            self, tmp_path: Path
        ) -> None:
            _, errors = corpus.check(_stub(tmp_path, printwitness.CHECKS[1:]))
            assert _failed(errors) == SIGNED_REJECTS

        def test_verifier_without_the_witness_check_accepts_a_switched_witness(
            self, tmp_path: Path
        ) -> None:
            _, errors = corpus.check(_stub(tmp_path, ("witness_changed",)))
            assert _failed(errors) == {"witness-changed-mid-print"}

        def test_verifier_that_rejects_everything_fails_the_controls(self, tmp_path: Path) -> None:
            script = tmp_path / "reject.py"
            script.write_text(
                'import json, sys\nprint(json.dumps({"decision": "rejected", '
                '"reason": "log_truncated"}))\nsys.exit(1)\n',
                encoding="ascii",
            )
            _, errors = corpus.check(f"{sys.executable} {script}")
            assert ACCEPTS <= _failed(errors)

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            (copied / "cases" / "intact" / "job.gcode").write_bytes(b"G28\n")
            _, errors = corpus.check(root=copied)
            assert "intact: fixture digest mismatch" in errors

        def test_a_pair_naming_no_case_refuses_the_corpus(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            manifest = json.loads((copied / "MANIFEST.json").read_text())
            manifest["vectors"][2]["pairsWith"] = "no-such-case"
            manifest["corpusDigest"] = generator._sha(generator._json(manifest["vectors"]))
            (copied / "MANIFEST.json").write_bytes(generator._json(manifest))
            assert corpus.check(root=copied) == (
                0,
                ["a case pairs with a case the manifest does not hold"],
            )
