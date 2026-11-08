"""The corpus regenerates, forces every check, and refuses a verifier that only
checks that the grant is not in the newest revocation list."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/contract/revocation-epoch/v1"


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("revocation_epoch_corpus", ROOT / "check_vectors.py")
generator = _load("revocation_epoch_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import revocationepoch  # noqa: E402

# What the field ships today: parse the record, then refuse only when the
# newest list carries the permit's grant digest. Every case below gets through
# it, and it refuses three controls.
NAIVE_LETS_THROUGH = {
    "srl-issuer-untrusted", "grant-binding-effect-names-other-permit",
    "epoch-reused-with-different-content", "epoch-rolled-back-in-witness-log",
    "epoch-issued-before-predecessor", "srl-absent-at-permit", "srl-absent-at-effect",
    "srl-digest-mismatch-at-permit", "srl-epoch-unknown-at-permit",
    "srl-digest-mismatch-at-effect", "srl-stale-at-permit-at-limit",
    "srl-stale-newer-list-witnessed-before-permit", "srl-stale-permit-backdated",
    "srl-stale-permit-list-issued-after-permit", "srl-stale-at-effect-at-limit",
    "srl-stale-at-effect-backdated", "revoked-at-permit-holder",
    "revoked-at-permit-parent-grant", "revoked-at-permit-authority-key",
    "effect-after-revocation-holder-in-flight", "effect-after-revocation-parent-in-flight",
    "effect-after-revocation-dropped-in-later-list", "ambiguous-witness-log-gap",
    "ambiguous-effect-witnessed-before-permit", "ambiguous-effect-list-witnessed-after-effect",
    "ambiguous-witnessed-list-not-in-record", "ambiguous-permit-not-witnessed",
    "effect-epoch-behind",
}
NAIVE_REFUSES = {"allow-grant-revoked-after-effect", "allow-race-effect-witnessed-first",
                 "allow-revoked-in-flight-refused-at-effect"}
CONTRACT_CHECKS = ("contract_id_missing", "contract_id_unknown", "malformed_record")


def _script(tmp_path: Path, name: str, body: str) -> str:
    script = tmp_path / name
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import revocationepoch as m\n" + body,
        encoding="ascii",
    )
    return f"{sys.executable} {script}"


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    return _script(tmp_path, "stub.py",
                   f"answer = m.verify(Path(sys.argv[1]), frozenset({skip!r}))\n"
                   "print(json.dumps(answer))\n"
                   "sys.exit(m.EXIT_FOR[answer['decision']])\n")


def _naive(tmp_path: Path) -> str:
    return _script(tmp_path, "naive.py", (
        "record = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))\n"
        "answer = {'decision': 'allow', 'reason': 'not_revoked'}\n"
        "if record.get('contractId') != m.CONTRACT_ID or m._malformed(record):\n"
        "    answer = {'decision': 'deny', 'reason': 'malformed_record'}\n"
        "else:\n"
        "    newest = max(record['srls'], key=lambda s: s['epoch'])\n"
        "    if record['permit']['grantDigest'] in newest['revoked']:\n"
        "        answer = {'decision': 'deny', 'reason': 'revoked_at_permit'}\n"
        "print(json.dumps(answer))\n"
        "sys.exit(m.EXIT_FOR[answer['decision']])\n"))


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


def _manifest() -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))


def _ids(decision: str) -> set[str]:
    return {e["id"] for e in _manifest()["vectors"] if e["expected"]["decision"] == decision}


class TestRevocationEpochCorpus:
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
            assert revocationepoch.CONTRACT_ID == CONTRACT_ID
            assert _manifest()["contractId"] == CONTRACT_ID

        def test_every_denial_reason_is_a_check(self) -> None:
            reasons = {e["expected"]["reason"] for e in _manifest()["vectors"]
                       if e["expected"]["decision"] == "deny"}
            assert reasons == set(revocationepoch.CHECKS)

        def test_every_allow_reason_has_a_control(self) -> None:
            reasons = {e["expected"]["reason"] for e in _manifest()["vectors"]
                       if e["expected"]["decision"] == "allow"}
            assert reasons == set(revocationepoch.ALLOW_REASONS)

        def test_absent_and_empty_lists_are_different_states(self) -> None:
            def answer(name: str) -> dict[str, str]:
                return revocationepoch.verify(ROOT / "cases" / name / "record.json")
            assert answer("allow-empty-list-epoch-1")["decision"] == "allow"
            assert answer("srl-absent-at-permit")["reason"] == "srl_absent"

    class TestFailingCases:
        def test_newest_list_only_verifier_lets_these_through(self, tmp_path: Path) -> None:
            _, errors = corpus.check(_naive(tmp_path))
            assert _failed(errors) == NAIVE_LETS_THROUGH | NAIVE_REFUSES
            assert NAIVE_LETS_THROUGH <= _ids("deny")
            assert NAIVE_REFUSES <= _ids("allow")

        @pytest.mark.parametrize("name", revocationepoch.CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_each_denial_is_named_by_its_own_check(self) -> None:
            """Switching off the check a denied case names changes its answer,
            so that check, and no earlier one, is what refuses it."""
            for entry in _manifest()["vectors"]:
                reason = entry["expected"]["reason"]
                if entry["expected"]["decision"] != "deny" or reason in CONTRACT_CHECKS:
                    continue
                answer = revocationepoch.verify(
                    ROOT / entry["path"] / "record.json", frozenset({reason}))
                assert answer != entry["expected"], entry["id"]

        def test_verifier_that_denies_everything_fails_the_controls(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "deny.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "deny", '
                              '"reason": "revoked_at_permit"}))\nsys.exit(1)\n',
                              encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            controls = _ids("allow")
            assert controls and controls <= _failed(errors)

        def test_verifier_that_allows_everything_fails_every_denial(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "allow.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "allow", '
                              '"reason": "not_revoked"}))\nsys.exit(0)\n', encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            assert _ids("deny") <= _failed(errors)

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            (copied / "cases" / "allow-other-grant-revoked" / "record.json").write_bytes(b"{}")
            _, errors = corpus.check(root=copied)
            assert "allow-other-grant-revoked: fixture digest mismatch" in errors

        def test_a_digest_claim_is_recomputed_not_trusted(self, tmp_path: Path) -> None:
            """Editing what a list revokes changes its digest, so the permit that
            names the old digest no longer names any list."""
            record = json.loads((ROOT / "cases" / "allow-other-grant-revoked" /
                                 "record.json").read_text(encoding="utf-8"))
            record["srls"][0]["revoked"] = []
            path = tmp_path / "record.json"
            path.write_text(json.dumps(record), encoding="utf-8")
            assert revocationepoch.verify(path)["reason"] == "srl_digest_mismatch"
