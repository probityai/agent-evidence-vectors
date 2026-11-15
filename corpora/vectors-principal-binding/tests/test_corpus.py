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


corpus = _load("principal_binding_corpus", ROOT / "check_vectors.py")
generator = _load("principal_binding_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import principalbinding  # noqa: E402

ACCEPTS = {"uma-bound", "hcp-bound"}
UNSIGNED = {"uma-edited-after-signing", "uma-signed-by-other-key", "hcp-edited-after-signing"}
# The same one-field change of the request, made against each native form.
ONE_FIELD = {
    "agent_mismatch": "other-agent",
    "principal_mismatch": "other-principal",
    "scope_exceeded": "scope-widened",
}


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    """A verifier that runs the reference reader with the named checks switched off."""
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "import run_vectors\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import principalbinding as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


def _rows() -> dict[str, dict]:  # type: ignore[type-arg]
    manifest = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
    return {row["id"]: row for row in manifest["vectors"]}


class TestPrincipalBindingCorpus:
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

        @pytest.mark.parametrize("name", principalbinding.CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        @pytest.mark.parametrize("reason", sorted(ONE_FIELD))
        def test_each_one_field_change_is_made_against_both_forms(self, reason: str) -> None:
            rows = _rows()
            for profile in ("uma", "hcp"):
                row = rows[f"{profile}-{ONE_FIELD[reason]}"]
                assert row["expected"] == {"decision": "rejected", "reason": reason}
                assert row["pairsWith"] == f"{profile}-bound"
                assert row["bindingSignatureVerifies"]

        def test_unsigned_cases_are_the_listed_ones(self) -> None:
            assert {
                name for name, row in _rows().items() if not row["bindingSignatureVerifies"]
            } == UNSIGNED

    class TestFailingCases:
        def test_signature_only_verifier_is_refused_on_the_signed_rejects(
            self, tmp_path: Path
        ) -> None:
            _, errors = corpus.check(_stub(tmp_path, principalbinding.CHECKS[1:]))
            signed_rejects = {
                name for name, row in _rows().items() if row["bindingSignatureVerifies"]
            } - ACCEPTS
            assert _failed(errors) == signed_rejects

        def test_verifier_that_rejects_everything_fails_the_controls(self, tmp_path: Path) -> None:
            script = tmp_path / "reject.py"
            script.write_text(
                'import json, sys\nprint(json.dumps({"decision": "rejected", '
                '"reason": "agent_mismatch"}))\nsys.exit(1)\n',
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
            (copied / "cases" / "hcp-bound" / "binding.json").write_bytes(b"{}\n")
            _, errors = corpus.check(root=copied)
            assert "hcp-bound: fixture digest mismatch" in errors

        def test_an_unknown_profile_is_refused(self, tmp_path: Path) -> None:
            case = json.loads((ROOT / "cases" / "hcp-bound" / "case.json").read_text())
            case["profile"] = "no-such-profile"
            (tmp_path / "case.json").write_text(json.dumps(case))
            shutil.copy(ROOT / "cases" / "hcp-bound" / "binding.json", tmp_path)
            with pytest.raises(ValueError, match="unknown profile"):
                principalbinding.verify(tmp_path / "case.json")
