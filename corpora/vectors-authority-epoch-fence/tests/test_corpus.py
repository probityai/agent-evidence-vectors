"""The corpus regenerates, forces every rule and refuses a reader that reads open as closed."""

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


corpus = _load("authority_epoch_corpus", ROOT / "check_vectors.py")
generator = _load("authority_epoch_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import authorityepoch  # noqa: E402

FAMILIES = (
    "epoch-", "approval-", "suspend-", "delegation-", "root-", "rereg-", "owner-", "fork-",
    "status-",
)
UNRESOLVED = {
    "status-open-dispute-reads-unknown",
    "status-truncated-log-reads-unknown",
    "status-new-admissions-scope-reads-partial",
}


def _manifest() -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))


def _stub(tmp_path: Path, skip: tuple[str, ...] = (), close_open: bool = False) -> str:
    """A verifier that runs the reference reader with checks off, or with open read as closed."""
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "import run_vectors\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import authorityepoch as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        f"if {close_open!r} and answer['revocation_status'] in ('unknown', 'partial'):\n"
        "    answer['revocation_status'] = 'closed'\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


class TestAuthorityEpochFenceCorpus:
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
            answered, errors = corpus.check(_stub(tmp_path))
            assert errors == []
            assert answered == len(generator.cases())

        def test_every_decision_reason_and_status_is_reached(self) -> None:
            expected = [entry["expected"] for entry in _manifest()["vectors"]]
            assert {e["decision"] for e in expected} == set(authorityepoch.EXIT_FOR)
            assert {e["reason"] for e in expected} == set(authorityepoch.REASONS)
            assert {e["revocation_status"] for e in expected} == set(authorityepoch.STATUSES)

        def test_every_family_is_present_and_every_id_names_one(self) -> None:
            ids = [entry["id"] for entry in _manifest()["vectors"]]
            assert all(any(i.startswith(f) for f in FAMILIES) for i in ids)
            assert all(any(i.startswith(f) for i in ids) for f in FAMILIES)

        def test_each_case_is_normative_or_a_proposal(self) -> None:
            status = {e["id"]: e["status"] for e in _manifest()["vectors"]}
            assert set(status.values()) == {"normative", "proposed"}
            assert status["fork-second-signer-recorded"] == "proposed"
            assert status["epoch-dead-request-presented-two-epochs-later"] == "proposed"

    class TestFailingCases:
        def test_reader_that_reports_closed_on_an_unresolved_epoch_fails(
            self, tmp_path: Path
        ) -> None:
            _, errors = corpus.check(_stub(tmp_path, close_open=True))
            assert UNRESOLVED <= _failed(errors)

        @pytest.mark.parametrize("name", authorityepoch.CHECKS)
        def test_every_rule_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_verifier_that_admits_everything_fails(self, tmp_path: Path) -> None:
            script = tmp_path / "admit.py"
            script.write_text(
                'import json, sys\nprint(json.dumps({"decision": "admit", '
                '"reason": "authority_valid", "revocation_status": "live"}))\nsys.exit(0)\n',
                encoding="ascii",
            )
            _, errors = corpus.check(f"{sys.executable} {script}")
            assert {
                "epoch-closed-after-restart",
                "status-no-head-reads-unknown",
                "rereg-does-not-lift-a-kill",
                "owner-kill-survives-owner-change",
            } <= _failed(errors)

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert errors and all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            target = copied / "cases" / "epoch-current-epoch-admitted" / "request.json"
            target.write_bytes(b"{}\n")
            _, errors = corpus.check(root=copied)
            assert "epoch-current-epoch-admitted: fixture digest mismatch" in errors
