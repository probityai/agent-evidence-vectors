"""The corpus regenerates, forces every check, and refuses a signature-only verifier."""

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


corpus = _load("anchored_chain_corpus", ROOT / "check_vectors.py")
generator = _load("anchored_chain_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import anchoredchain  # noqa: E402

GENUINE_REJECTS = {"t2-tail-removal", "t3-middle-deletion", "t4-reorder",
                   "t6-cross-context-replay", "t7-rollback-older-record",
                   "t9-snapshot-rollback"}


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    """A verifier that runs the reference reader with the named checks switched off."""
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parent / 'packaging')!r})\n"
        "import run_vectors\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import anchoredchain as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


class TestAnchoredChainCorpus:
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

        def test_eight_rejected_stores_hold_only_genuine_signed_records(self) -> None:
            manifest = anchoredchain.json.loads((ROOT / "MANIFEST.json").read_text())
            genuine = {e["id"] for e in manifest["vectors"]
                       if e["storeSignaturesVerify"] and e["expected"]["decision"] == "rejected"}
            assert genuine == GENUINE_REJECTS | {"tail-removal-reanchored",
                                                 "rollback-to-abandoned-branch"}

    class TestFailingCases:
        def test_signature_only_verifier_is_refused_on_the_genuine_records(
            self, tmp_path: Path
        ) -> None:
            _, errors = corpus.check(_stub(tmp_path, anchoredchain.CHECKS[2:]))
            assert _failed(errors) == GENUINE_REJECTS | {"rollback-to-abandoned-branch"}

        def test_verifier_without_the_anchor_misses_removal_and_branch_rollback(
            self, tmp_path: Path
        ) -> None:
            _, errors = corpus.check(_stub(tmp_path, anchoredchain.CHECKS[4:]))
            assert _failed(errors) == {"t2-tail-removal", "t9-snapshot-rollback",
                                       "rollback-to-abandoned-branch"}

        @pytest.mark.parametrize("name", anchoredchain.CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_verifier_that_rejects_everything_fails_the_controls(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "reject.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "rejected", '
                              '"reason": "chain_link_broken"}))\nsys.exit(1)\n',
                              encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            assert {"intact", "records-after-last-anchor",
                    "t2-tail-removal-after-last-anchor"} <= _failed(errors)

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            (copied / "cases" / "intact" / "store.jsonl").write_bytes(b"{}\n")
            _, errors = corpus.check(root=copied)
            assert "intact: fixture digest mismatch" in errors
