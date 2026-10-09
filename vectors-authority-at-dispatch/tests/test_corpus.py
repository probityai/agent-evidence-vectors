"""The corpus regenerates, forces every check, and refuses a verifier that only
compares the approved action."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ID = "https://probityai.github.io/agent-evidence-observer/contract/authority-at-dispatch/v1"


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("authority_dispatch_corpus", ROOT / "check_vectors.py")
generator = _load("authority_dispatch_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import authoritydispatch  # noqa: E402

# Members whose dispatched bytes match the approved digest exactly, and which a
# verifier must still deny: authority at dispatch time, not the approval, decides.
APPROVED_BYTES_DENIED = {"revoked-before-dispatch", "stale-authority-evidence",
                         "scope-amplified-across-hops", "grant-expired",
                         "contract-id-missing", "contract-id-unknown",
                         "evidence-age-inconsistent"}


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parent / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import authoritydispatch as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


def _records() -> dict[str, dict]:  # type: ignore[type-arg]
    return {p.parent.name: json.loads(p.read_text(encoding="utf-8"))
            for p in (ROOT / "cases").glob("*/record.json")}


class TestAuthorityAtDispatchCorpus:
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

        def test_every_record_but_the_contract_cases_carries_the_contract_id(self) -> None:
            records = _records()
            assert "contractId" not in records["contract-id-missing"]
            assert records["contract-id-unknown"]["contractId"] != CONTRACT_ID
            others = {k: v for k, v in records.items()
                      if k not in {"contract-id-missing", "contract-id-unknown"}}
            assert others and all(r["contractId"] == CONTRACT_ID for r in others.values())
            assert authoritydispatch.CONTRACT_ID == CONTRACT_ID

        def test_every_record_carries_its_evidence_age(self) -> None:
            for name, record in _records().items():
                age = record["authorityEvidence"]["evidenceAgeSeconds"]
                assert isinstance(age, int) and not isinstance(age, bool), name

        def test_approved_bytes_are_denied_on_authority_alone(self) -> None:
            manifest = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
            denied = {e["id"] for e in manifest["vectors"]
                      if e["dispatchMatchesApproval"] and e["expected"]["decision"] == "deny"}
            assert denied == APPROVED_BYTES_DENIED

    class TestFailingCases:
        def test_approval_only_verifier_is_refused_on_every_authority_case(
            self, tmp_path: Path
        ) -> None:
            skip = tuple(c for c in authoritydispatch.CHECKS if c != "dispatch_not_approved")
            _, errors = corpus.check(_stub(tmp_path, skip))
            assert _failed(errors) == APPROVED_BYTES_DENIED

        @pytest.mark.parametrize("name", authoritydispatch.CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_verifier_that_denies_everything_fails_the_controls(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "deny.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "deny", '
                              '"reason": "grant_revoked"}))\nsys.exit(1)\n',
                              encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            assert {"allow-direct", "allow-two-hop-narrowing", "allow-revoked-after-dispatch",
                    "allow-evidence-age-at-limit"} <= _failed(errors)

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            (copied / "cases" / "allow-direct" / "dispatched.bin").write_bytes(b"other")
            _, errors = corpus.check(root=copied)
            assert "allow-direct: fixture digest mismatch" in errors
