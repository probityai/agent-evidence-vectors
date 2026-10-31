"""The corpus regenerates, forces every check, and refuses a verifier that only
checks the approval's own payload and expiry."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/contract/approval-binding/v1"


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("approval_binding_corpus", ROOT / "check_vectors.py")
generator = _load("approval_binding_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import approvalbinding  # noqa: E402

# Checks a verifier that reads only the approval it was handed would run.
SELF_CONTAINED = ("payload_mismatch", "approval_outside_validity")


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parent / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import approvalbinding as m\n"
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


class TestApprovalBindingCorpus:
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
            assert approvalbinding.CONTRACT_ID == CONTRACT_ID
            assert _manifest()["contractId"] == CONTRACT_ID

        def test_every_denial_reason_is_a_check(self) -> None:
            reasons = {e["expected"]["reason"] for e in _manifest()["vectors"]
                       if e["expected"]["decision"] == "deny"}
            assert reasons == set(approvalbinding.CHECKS)

    class TestFailingCases:
        def test_self_contained_verifier_is_refused_on_every_binding_case(
            self, tmp_path: Path
        ) -> None:
            skip = tuple(c for c in approvalbinding.CHECKS if c not in SELF_CONTAINED)
            _, errors = corpus.check(_stub(tmp_path, skip))
            expected = {e["id"] for e in _manifest()["vectors"]
                        if e["expected"]["decision"] == "deny"
                        and e["expected"]["reason"] not in SELF_CONTAINED}
            assert _failed(errors) == expected

        @pytest.mark.parametrize("name", approvalbinding.CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_verifier_that_denies_everything_fails_the_controls(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "deny.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "deny", '
                              '"reason": "approval_replayed"}))\nsys.exit(1)\n',
                              encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            controls = {e["id"] for e in _manifest()["vectors"]
                        if e["expected"]["decision"] == "allow"}
            assert controls and controls <= _failed(errors)

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            (copied / "cases" / "allow-bound" / "payload.bin").write_bytes(b"other")
            _, errors = corpus.check(root=copied)
            assert "allow-bound: fixture digest mismatch" in errors


def _case(name: str) -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / "cases" / name / "record.json").read_text(encoding="utf-8"))


def _verdict(name: str, skip: frozenset[str] = frozenset()) -> dict:  # type: ignore[type-arg]
    return approvalbinding.verify(ROOT / "cases" / name / "record.json", skip)


class TestRenewalByReplacement:
    """A replaced approval is refused for supersession, and for nothing else."""

    def test_replacement_is_allowed_with_distinct_decisions_and_equal_bounds(self) -> None:
        record = _case("approval-renewed-same-bounds")
        predecessor, successor = record["presentedApprovals"]
        assert predecessor["decisionId"] != successor["decisionId"]
        assert all(predecessor[f] == successor[f] for f in approvalbinding.BOUND_FIELDS)
        assert record["transitions"][0]["predecessorDecisionId"] == predecessor["decisionId"]
        assert _verdict("approval-renewed-same-bounds") == {"decision": "allow",
                                                            "reason": "bound"}

    def test_predecessor_is_refused_before_any_execution_under_the_successor(self) -> None:
        record = _case("approval-reused-after-renewal")
        approval, use = record["approval"], record["use"]
        # Nothing else can be what refuses it: it has not expired, it is not
        # consumed, and the effect is reserved and not executed.
        assert approval["issuedAt"] <= use["usedAt"] < approval["expiresAt"]
        assert approval["approvalId"] not in record["consumedApprovalIds"]
        assert record["effectRegistry"][use["effectKey"]] == "RESERVED"
        assert _verdict("approval-reused-after-renewal") == {
            "decision": "deny", "reason": "approval_superseded"}

    def test_predecessor_passes_every_other_check(self) -> None:
        skipped = _verdict("approval-reused-after-renewal",
                           frozenset({"approval_superseded"}))
        assert skipped == {"decision": "allow", "reason": "bound"}

    def test_deduplicating_verifier_misses_the_supersession(self, tmp_path: Path) -> None:
        # A reader that refuses only an approval already consumed lets A through.
        skip = tuple(c for c in approvalbinding.CHECKS if c != "approval_replayed")
        _, errors = corpus.check(_stub(tmp_path, skip))
        assert "approval-reused-after-renewal" in _failed(errors)

    def test_predecessor_is_applicable_until_the_replacement_is_accepted(self) -> None:
        record = _case("allow-predecessor-before-replacement")
        assert record["use"]["usedAt"] < record["transitions"][0]["acceptedAt"]
        assert _verdict("allow-predecessor-before-replacement")["decision"] == "allow"

    @pytest.mark.parametrize("name,reason", [
        ("approval-renewal-transition-not-accepted", "renewal_transition_missing"),
        ("approval-renewal-decision-not-distinct", "renewal_binding_invalid"),
        ("approval-renewal-predecessor-decision-not-cited", "renewal_binding_invalid"),
        ("approval-renewal-bounds-differ", "renewal_binding_invalid"),
        ("approval-renewal-reopens-consumed-effect", "effect_already_closed"),
        ("approval-renewal-reopens-uncertain-effect", "effect_already_closed"),
    ])
    def test_renewal_claim_is_refused_for_its_own_reason(self, name: str, reason: str) -> None:
        assert _verdict(name) == {"decision": "deny", "reason": reason}
        # The same record clears every other check, so the reason is the only cause.
        assert _verdict(name, frozenset({reason}))["decision"] == "allow"

    def test_renewed_claim_is_not_evidence_of_a_transition(self) -> None:
        record = _case("approval-renewal-transition-not-accepted")
        assert record["use"]["authorityForm"] == "renewed"
        assert record["transitions"][0]["status"] == "proposed"

    def test_closed_effect_is_refused_whatever_the_transition(self) -> None:
        for name in ("approval-renewal-reopens-consumed-effect",
                     "approval-renewal-reopens-uncertain-effect"):
            record = _case(name)
            assert record["transitions"][0]["status"] == "accepted"
            assert record["effectRegistry"][record["use"]["effectKey"]] in (
                approvalbinding.CLOSED_EFFECT_STATES)
