"""The corpus regenerates, forces every rule and refuses a reader that trusts the record."""

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


corpus = _load("model_preservation_corpus", ROOT / "check_vectors.py")
generator = _load("model_preservation_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import modelpreservation  # noqa: E402


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    """A verifier that runs the reference reader with the named checks switched off."""
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "import run_vectors\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import modelpreservation as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


class TestModelPreservationCorpus:
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

        def test_every_decision_is_reached(self) -> None:
            manifest = json.loads((ROOT / "MANIFEST.json").read_text())
            assert set(manifest["counts"]) == set(modelpreservation.EXIT_FOR)

        def test_each_record_has_a_match_a_tampered_digest_and_a_wrong_signer(self) -> None:
            expected = {
                e["id"]: e["expected"]["reason"]
                for e in json.loads((ROOT / "MANIFEST.json").read_text())["vectors"]
            }
            for kind, match, tampered in (
                ("reference", "copy_matches_record", "reference-record-digest-tampered"),
                ("swap", "swap_passed", "swap-verdict-tampered"),
            ):
                assert expected[f"{kind}-wrong-signer"] == "signer_not_trusted"
                assert expected[tampered] == "signature_invalid"
                assert match in {r for i, r in expected.items() if i.startswith(kind)}

        def test_reference_statement_is_the_model_signing_v1_shape(self) -> None:
            statement = generator.reference_statement()
            assert statement["predicateType"] == "https://model_signing/signature/v1.0"
            names = [r["name"] for r in statement["predicate"]["resources"]]
            assert names == sorted(names)
            assert statement["subject"][0]["digest"]["sha256"] == modelpreservation.root_digest(
                statement["predicate"]["resources"]
            )

        def test_pointer_id_is_the_git_blob_id_of_the_lfs_pointer(self) -> None:
            # git hash-object of the pointer text for 64 bytes 0x00..0x3f, computed independently.
            data = bytes(range(64))
            pointer = (
                "version https://git-lfs.github.com/spec/v1\n"
                f"oid sha256:{modelpreservation._sha(data)}\nsize 64\n"
            ).encode()
            import hashlib

            header = b"blob %d\x00" % len(pointer)
            want = hashlib.sha1(header + pointer, usedforsecurity=False).hexdigest()
            assert modelpreservation.pointer_id(data) == want

    class TestFailingCases:
        @pytest.mark.parametrize("name", modelpreservation.CHECKS)
        def test_every_rule_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_reader_that_trusts_the_record_is_refused(self, tmp_path: Path) -> None:
            _, errors = corpus.check(_stub(tmp_path, modelpreservation.CHECKS[:3]))
            assert {
                "reference-wrong-signer",
                "reference-wrong-signer-names-trusted-keyid",
                "reference-record-digest-tampered",
                "reference-record-is-a-swap-record",
                "swap-wrong-signer",
                "swap-verdict-tampered",
            } <= _failed(errors)

        def test_verifier_that_verifies_everything_fails(self, tmp_path: Path) -> None:
            script = tmp_path / "yes.py"
            script.write_text(
                'import json, sys\nprint(json.dumps({"decision": "verified", '
                '"reason": "copy_matches_record"}))\nsys.exit(0)\n',
                encoding="ascii",
            )
            _, errors = corpus.check(f"{sys.executable} {script}")
            assert len(_failed(errors)) == len(generator.cases()) - 2

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            target = copied / "cases" / "reference-copy-matches" / "copy-model.safetensors"
            target.write_bytes(b"\x00")
            _, errors = corpus.check(root=copied)
            assert "reference-copy-matches: fixture digest mismatch" in errors
