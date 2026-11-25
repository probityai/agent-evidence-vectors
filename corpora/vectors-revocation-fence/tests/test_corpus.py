"""The corpus regenerates, forces every rule and refuses a reader that reads an open revocation as closed."""

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


corpus = _load("revocation_fence_corpus", ROOT / "check_vectors.py")
generator = _load("revocation_fence_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import revocationfence  # noqa: E402

#: Every refusal code the fence defines; each one is the expected reason of some case.
FENCE_CODES = (
    "malformed", "unknown_authority", "unknown_epoch_source", "unknown_target_key", "bad_signature",
    "wrong_audience", "not_yet_valid", "expired", "epoch_unknown", "epoch_mismatch", "epoch_unavailable",
    "epoch_rollback", "lease_expired", "revoked_before_commit", "revocation_pending", "key_reused",
    "retry_after_revoke",
)
#: The refusal codes of the feed kind.
FEED_CODES = (
    "set_malformed", "unknown_issuer_key", "bad_signature", "wrong_audience", "set_shape",
    "subject_issuer_mismatch", "jti_reused", "event_unknown",
)
#: The decision each kind reaches when every check passes.
ACCEPTS = {
    "permit": "valid", "epoch-update": "installed", "outcome": "valid", "commit": "committed",
    "propagation": "revoked_for_new_admissions", "ledger": "done", "feed": "revoked",
}


def _manifest() -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))


def _kind(entry: dict) -> str:  # type: ignore[type-arg]
    case = json.loads((ROOT / entry["path"] / "case.json").read_text(encoding="utf-8"))
    return str(case["kind"])


def _stub(tmp_path: Path, skip: tuple[str, ...] = (), close_open: bool = False) -> str:
    """A verifier that runs the reference reader, optionally reading every open status as closed."""
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "import run_vectors\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import revocationfence as m\n"
        f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
        f"if {close_open!r}:\n"
        "    def close(value):\n"
        "        if value in ('unknown', 'partial'):\n"
        "            return 'closed'\n"
        "        if isinstance(value, dict):\n"
        "            return {k: close(v) for k, v in value.items()}\n"
        "        return value\n"
        "    for key in ('revocation_status', 'subjects'):\n"
        "        if key in answer:\n"
        "            answer[key] = close(answer[key])\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n",
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


class TestRevocationFenceCorpus:
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

        def test_every_fence_code_is_the_reason_of_some_case(self) -> None:
            reasons = {entry["expected"]["reason"] for entry in _manifest()["vectors"]}
            assert set(FENCE_CODES) <= reasons
            assert set(FEED_CODES) <= reasons

        def test_every_kind_has_its_accept_case(self) -> None:
            reached = {(_kind(e), e["expected"]["decision"]) for e in _manifest()["vectors"]}
            assert set(ACCEPTS.items()) <= reached
            assert {kind for kind, _ in reached} == set(revocationfence.KINDS)

        def test_every_case_id_names_its_kind(self) -> None:
            prefixes = {
                "permit": ("permit-",), "epoch-update": ("update-",), "outcome": ("outcome-",),
                "commit": ("commit-a-", "commit-b-", "commit-c-"), "propagation": ("propagation-",),
                "ledger": ("ledger-",), "feed": ("feed-",),
            }
            for entry in _manifest()["vectors"]:
                assert entry["id"].startswith(prefixes[_kind(entry)]), entry["id"]

        def test_every_case_about_a_revocation_states_its_status(self) -> None:
            for entry in _manifest()["vectors"]:
                expected, kind = entry["expected"], _kind(entry)
                about = kind in ("propagation", "ledger") or (
                    kind == "commit" and expected["decision"] != "no_outcome"
                )
                if about:
                    assert expected.get("revocation_status") in revocationfence.STATUSES, entry["id"]
                if "revocation_status" in expected:
                    assert expected["revocation_status"] in revocationfence.STATUSES

        def test_every_status_value_is_reached(self) -> None:
            statuses = {e["expected"].get("revocation_status") for e in _manifest()["vectors"]}
            assert set(revocationfence.STATUSES) <= statuses

    class TestFailingCases:
        @pytest.mark.parametrize("name", revocationfence.CHECKS)
        def test_every_rule_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_reader_that_reports_closed_on_an_unresolved_revocation_fails(
            self, tmp_path: Path
        ) -> None:
            _, errors = corpus.check(_stub(tmp_path, close_open=True))
            assert errors, "a reader that maps unknown and partial to closed passed every case"
            open_cases = {
                e["id"] for e in _manifest()["vectors"]
                if e["expected"].get("revocation_status") in ("unknown", "partial")
            }
            assert open_cases and open_cases <= _failed(errors)

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert errors and all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            first = _manifest()["vectors"][0]["id"]
            (copied / "cases" / first / "case.json").write_bytes(b"{}\n")
            _, errors = corpus.check(root=copied)
            assert f"{first}: fixture digest mismatch" in errors
