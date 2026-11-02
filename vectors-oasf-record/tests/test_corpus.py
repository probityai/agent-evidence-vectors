"""The corpus regenerates, forces every check, and refuses a verifier that
hashes a general-purpose serializer's bytes or matches the signer as a pattern."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/contract/oasf-record/v1"


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("oasf_record_corpus", ROOT / "check_vectors.py")
generator = _load("oasf_record_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import oasfrecord  # noqa: E402

# The checks a verifier that trusts the producer's digest and signer would run.
SHAPE_ONLY = ("contract_id_missing", "contract_id_unknown", "malformed_case", "record_not_json",
              "oasf_required_field")


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parent / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import oasfrecord as m\n"
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


class TestOasfRecordCorpus:
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

        def test_contract_id_is_the_published_one(self) -> None:
            assert oasfrecord.CONTRACT_ID == CONTRACT_ID
            assert _manifest()["contractId"] == CONTRACT_ID

        def test_every_denial_reason_is_a_check(self) -> None:
            reasons = {e["expected"]["reason"] for e in _manifest()["vectors"]
                       if e["expected"]["decision"] == "deny"}
            assert reasons == set(oasfrecord.CHECKS)

    class TestFailingCases:
        def test_shape_only_verifier_is_refused_on_every_identity_case(
            self, tmp_path: Path
        ) -> None:
            skip = tuple(c for c in oasfrecord.CHECKS if c not in SHAPE_ONLY)
            _, errors = corpus.check(_stub(tmp_path, skip))
            expected = {e["id"] for e in _manifest()["vectors"]
                        if e["expected"]["decision"] == "deny"
                        and e["expected"]["reason"] not in SHAPE_ONLY}
            assert _failed(errors) == expected

        @pytest.mark.parametrize("name", oasfrecord.CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_each_denial_is_its_own_check_alone(self) -> None:
            """Switching off the one check a denied case names turns it into an
            allow, so the defect is the only thing between it and its control."""
            for entry in _manifest()["vectors"]:
                reason = entry["expected"]["reason"]
                if entry["expected"]["decision"] != "deny" or reason in (
                        "malformed_case", "record_not_json", "contract_id_missing",
                        "contract_id_unknown"):
                    continue
                answer = oasfrecord.verify(
                    ROOT / entry["path"] / "case.json", frozenset({reason}))
                assert answer == {"decision": "allow", "reason": "conformant"}, entry["id"]

        def test_verifier_that_denies_everything_fails_the_controls(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "deny.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "deny", '
                              '"reason": "digest_mismatch"}))\nsys.exit(1)\n',
                              encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            controls = {e["id"] for e in _manifest()["vectors"]
                        if e["expected"]["decision"] == "allow"}
            assert controls and controls <= _failed(errors)

        def test_verifier_that_allows_everything_fails_every_denial(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "allow.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "allow", '
                              '"reason": "conformant"}))\nsys.exit(0)\n', encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            denied = {e["id"] for e in _manifest()["vectors"]
                      if e["expected"]["decision"] == "deny"}
            assert _failed(errors) == denied

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            (copied / "cases" / "allow-plain" / "record.json").write_bytes(b"{}")
            _, errors = corpus.check(root=copied)
            assert "allow-plain: fixture digest mismatch" in errors
