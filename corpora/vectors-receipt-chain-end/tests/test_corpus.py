"""The corpus regenerates, forces every check, and refuses a continuity-only verifier."""

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


corpus = _load("receipt_chain_end_corpus", ROOT / "check_vectors.py")
generator = _load("receipt_chain_end_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import receiptchainend  # noqa: E402


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    """A verifier that runs the reference reader with the named checks switched off."""
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parent / 'packaging')!r})\n"
        "import run_vectors\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import receiptchainend as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


class TestReceiptChainEndCorpus:
    class TestPassingCases:
        def test_regeneration_is_byte_identical(self, tmp_path: Path) -> None:
            generator.generate(tmp_path)
            committed = {p.relative_to(ROOT): p.read_bytes()
                         for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")]
                         if p.is_file()}
            regenerated = {p.relative_to(tmp_path): p.read_bytes()
                           for p in tmp_path.rglob("*") if p.is_file()}
            assert regenerated == committed

        def test_reference_reader_agrees_with_every_case(self) -> None:
            answered, errors = corpus.check()
            assert errors == []
            assert answered == len(generator.cases())

        def test_reference_reader_through_the_external_contract(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(_stub(tmp_path, ()))
            assert errors == []
            assert answered == len(generator.cases())

        def test_every_attack_holds_only_genuine_signatures(self) -> None:
            manifest = json.loads((ROOT / "MANIFEST.json").read_text())
            forged = {e["id"] for e in manifest["vectors"] if not e["signaturesVerify"]}
            assert forged == {"signature-tamper"}

        def test_every_case_says_what_it_does_not_assert(self) -> None:
            manifest = json.loads((ROOT / "MANIFEST.json").read_text())
            assert all(e["doesNotAssert"].strip() for e in manifest["vectors"])

        def test_every_decision_and_reason_is_reached(self) -> None:
            manifest = json.loads((ROOT / "MANIFEST.json").read_text())
            reasons = {e["expected"]["reason"] for e in manifest["vectors"]}
            assert set(receiptchainend.CHECKS) | {
                "end_proven_close", "end_proven_head", "end_unproven"} == reasons

    class TestFailingCases:
        def test_continuity_only_verifier_is_refused(self, tmp_path: Path) -> None:
            # Signatures, root key and links only: no rotation authority, no
            # lifecycle, no retained head.
            _, errors = corpus.check(_stub(tmp_path, receiptchainend.CHECKS[3:]))
            assert {"rotation-resigned-tail-keys-pinned", "tail-truncation-retained-head",
                    "seq-reset-hides-gap", "fork-branch-against-retained-head",
                    "prefix-replay-other-run"} <= _failed(errors)

        def test_verifier_without_rotation_authority_accepts_the_reroot(
            self, tmp_path: Path
        ) -> None:
            _, errors = corpus.check(_stub(tmp_path, ("rotation_unendorsed",)))
            assert _failed(errors) == {"rotation-resigned-tail-keys-pinned",
                                       "rotation-resigned-tail-endorsement"}

        def test_verifier_that_matches_seq_without_segment_misses_the_reset(
            self, tmp_path: Path
        ) -> None:
            _, errors = corpus.check(_stub(tmp_path, ("head_position_mismatch",)))
            assert _failed(errors) == {"seq-reset-hides-gap"}

        @pytest.mark.parametrize("name", receiptchainend.CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_verifier_that_calls_every_valid_prefix_complete_is_refused(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "prefix-is-end.py"
            script.write_text(
                "import json, sys\n"
                f"sys.path.insert(0, {str(ROOT.parent / 'packaging')!r})\n"
                "import run_vectors\n"
                "from pathlib import Path\n"
                "from agent_evidence_vectors import receiptchainend as m\n"
                "a = m.verify(Path(sys.argv[1]))\n"
                "if a['decision'] == 'prefix':\n"
                "    a = {'decision': 'verified', 'reason': 'end_proven_close'}\n"
                "print(json.dumps(a))\n"
                "sys.exit(m.EXIT_FOR[a['decision']])\n", encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            assert {"tail-truncation", "prefix-replay-shared-session-close",
                    "fork-branch-against-retained-seq", "stale-head-truncated-to-it",
                    "control-open-prefix"} <= _failed(errors)

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            (copied / "cases" / "control-closed-run" / "chain.jsonl").write_bytes(b"{}\n")
            _, errors = corpus.check(root=copied)
            assert "control-closed-run: fixture digest mismatch" in errors
