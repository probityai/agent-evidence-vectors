"""The corpus regenerates, forces every check, and refuses the two verifiers the
field ships: approval matched by call identifier, and single-approval binding."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/contract/approval-binding/v2"


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("approval_binding_v2_corpus", ROOT / "check_vectors.py")
generator = _load("approval_binding_v2_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import approvalbindingv2  # noqa: E402

CONTRACT = ("contract_id_missing", "contract_id_unknown", "malformed_record")
# An approval found by the call identifier and read as a yes: the shape a resume
# that trusts the client's history and a plain approved flag ships.
ID_ONLY = (*CONTRACT, "approval_not_for_call", "approval_not_granted")
# One approval checked the way a single-approval binding checks it: its call,
# its signer, its bytes, its validity and whether it was spent before.
SINGLE_APPROVAL = (*ID_ONLY, "approver_claim_mismatch", "approver_key_not_bound",
                   "approval_not_for_bytes", "args_changed_after_approval",
                   "approval_expired", "approval_postdates_consumption",
                   "approval_replayed")
# The attacks reproduced against a resume keyed by call identifier.
ID_ONLY_ATTACKS = {"swapped-args-same-call-id", "same-approval-resent",
                   "resume-field-replaces-args", "validator-rewrites-after-approval"}
# Quorum, proposer and delegation cases a single-approval binding cannot express.
SINGLE_APPROVAL_GAPS = {
    "one-approval-of-two", "no-approvals-and-dispatched", "proposer-approves-own-call",
    "proposer-approves-through-delegate", "delegation-removes-approver",
    "delegation-lowers-quorum", "delegation-issued-by-non-approver",
    "same-approver-approves-twice", "delegate-and-delegator-both-counted",
    "approver-named-only-in-body", "approver-not-in-policy", "eligible-reject-vetoes",
}
# Cases whose attack changes two things at once, and the check the second change
# reaches when the first check is switched off.
TWO_DEFECTS = {
    "proposer-delegates-its-own-approver": "approver_ineligible",
    "split-quorum-different-bytes": "args_changed_after_approval",
    "swapped-args-same-call-id": "transforms_unaccounted",
    "args-changed-with-no-transform-recorded": "transforms_unaccounted",
    "same-approval-resent": "call_already_executed",
    "concurrent-double-click-loser": "call_already_executed",
}


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import approvalbindingv2 as m\n"
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


def _denied() -> list[dict]:  # type: ignore[type-arg]
    return [e for e in _manifest()["vectors"] if e["expected"]["decision"] == "deny"]


def _let_through(kept: tuple[str, ...]) -> set[str]:
    skip = frozenset(c for c in approvalbindingv2.CHECKS if c not in kept)
    _, errors = corpus.check(skip=skip)
    return _failed(errors)


class TestApprovalBindingV2Corpus:
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
            assert approvalbindingv2.CONTRACT_ID == CONTRACT_ID
            assert _manifest()["contractId"] == CONTRACT_ID

        def test_every_denial_reason_is_a_check(self) -> None:
            reasons = {e["expected"]["reason"] for e in _denied()}
            assert reasons == set(approvalbindingv2.CHECKS)

        def test_every_digest_the_witness_holds_recomputes(self) -> None:
            """The conformant record's consumptions are the digests of their statements."""
            record = json.loads((ROOT / "cases" / "allow-two-of-three-distinct" /
                                 "record.json").read_text(encoding="utf-8"))
            wanted = {approvalbindingv2.digest(approvalbindingv2.consumption_statement(
                i, record["execution"])) for i in record["execution"]["approvalIds"]}
            assert wanted <= {e["digest"] for e in record["witness"]}
            assert record["proposal"]["historyDigest"] == approvalbindingv2.digest(
                record["proposal"]["modelResponse"])

    class TestFailingCases:
        def test_id_only_verifier_lets_the_resume_attacks_through(self) -> None:
            through = _let_through(ID_ONLY)
            expected = {e["id"] for e in _denied() if e["expected"]["reason"] not in ID_ONLY}
            assert through == expected
            assert ID_ONLY_ATTACKS <= through

        def test_single_approval_verifier_lets_the_quorum_cases_through(self) -> None:
            through = _let_through(SINGLE_APPROVAL)
            expected = {e["id"] for e in _denied()
                        if e["expected"]["reason"] not in SINGLE_APPROVAL}
            assert through == expected
            assert SINGLE_APPROVAL_GAPS <= through

        @pytest.mark.parametrize("name", approvalbindingv2.CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_each_denial_is_its_own_check_alone(self) -> None:
            """Switching off the check a denied case names turns it into an allow,
            or, for an attack that changes two things, into the second check."""
            alone: set[str] = set()
            for entry in _denied():
                reason = entry["expected"]["reason"]
                if reason in CONTRACT:
                    continue
                answer = approvalbindingv2.verify(
                    ROOT / entry["path"] / "record.json", frozenset({reason}))
                if entry["id"] in TWO_DEFECTS:
                    assert answer == {"decision": "deny",
                                      "reason": TWO_DEFECTS[entry["id"]]}, entry["id"]
                    continue
                assert answer == {"decision": "allow", "reason": "quorum_bound"}, entry["id"]
                alone.add(reason)
            assert alone == set(approvalbindingv2.CHECKS) - set(CONTRACT)

        def test_verifier_that_denies_everything_fails_the_controls(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "deny.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "deny", '
                              '"reason": "quorum_not_met"}))\nsys.exit(1)\n',
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
                              '"reason": "quorum_bound"}))\nsys.exit(0)\n', encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            assert _failed(errors) == {e["id"] for e in _denied()}

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            (copied / "cases" / "allow-two-of-three-distinct" / "record.json").write_bytes(b"{}")
            _, errors = corpus.check(root=copied)
            assert "allow-two-of-three-distinct: fixture digest mismatch" in errors

        def test_a_record_that_is_not_an_object_is_malformed(self, tmp_path: Path) -> None:
            path = tmp_path / "record.json"
            path.write_text("[]", encoding="ascii")
            assert approvalbindingv2.verify(path) == {"decision": "deny",
                                                      "reason": "malformed_record"}
