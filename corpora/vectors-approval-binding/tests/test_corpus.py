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


def _probe(tmp_path: Path, name: str, move) -> dict:  # type: ignore[no-untyped-def, type-arg]
    """``move`` applied to a copy of member ``name``, judged by the packaged reader."""
    record = _case(name)
    move(record)
    shutil.copy(ROOT / "cases" / name / "payload.bin", tmp_path / "payload.bin")
    (tmp_path / "record.json").write_text(json.dumps(record), encoding="utf-8")
    return approvalbinding.verify(tmp_path / "record.json")


ALLOW = {"decision": "allow", "reason": "bound"}


class TestBindingsAtTheUse:
    """The probes from the review of the renewal cases, each on a copy of the
    positive renewal record with one field changed."""

    def test_unchanged_positive_record_is_allowed(self, tmp_path: Path) -> None:
        assert _probe(tmp_path, "approval-renewed-same-bounds", lambda r: None) == ALLOW

    def test_transition_accepted_after_the_use_does_not_establish_renewal(
        self, tmp_path: Path
    ) -> None:
        def later(record: dict) -> None:  # type: ignore[type-arg]
            assert record["use"]["usedAt"] == "2026-10-21T12:00:00Z"
            record["transitions"][0]["acceptedAt"] = "2026-10-21T12:00:01Z"
        assert _probe(tmp_path, "approval-renewed-same-bounds", later) == {
            "decision": "deny", "reason": "renewal_transition_missing"}

    def test_transition_accepted_at_the_use_establishes_renewal(self, tmp_path: Path) -> None:
        def at(record: dict) -> None:  # type: ignore[type-arg]
            record["transitions"][0]["acceptedAt"] = record["use"]["usedAt"]
        assert _probe(tmp_path, "approval-renewed-same-bounds", at) == ALLOW

    @pytest.mark.parametrize("name", ["approval-renewed-same-bounds", "allow-bound"])
    @pytest.mark.parametrize("cited", ["appr-0001", "appr-0002", "appr-9999", None])
    def test_use_must_cite_the_approval_checked(
        self, tmp_path: Path, name: str, cited: str | None
    ) -> None:
        # The base reader and the renewal reader alike: a use is judged against
        # the approval it names, and only that one.
        def cite(record: dict) -> None:  # type: ignore[type-arg]
            if cited is None:
                record["use"].pop("approvalId")
            else:
                record["use"]["approvalId"] = cited
        checked = _case(name)["approval"]["approvalId"]
        want = ALLOW if cited == checked else {"decision": "deny",
                                               "reason": "approval_not_cited"}
        assert _probe(tmp_path, name, cite) == want

    @pytest.mark.parametrize("position", [1, 0])
    def test_conflicting_predecessor_records_refuse_in_either_order(
        self, tmp_path: Path, position: int
    ) -> None:
        def conflict(record: dict) -> None:  # type: ignore[type-arg]
            other = {**record["presentedApprovals"][0], "decisionId": "dec-0099"}
            record["presentedApprovals"].insert(position, other)
        assert _probe(tmp_path, "approval-renewed-same-bounds", conflict) == {
            "decision": "deny", "reason": "renewal_binding_invalid"}

    def test_identical_predecessor_copies_are_one_predecessor(self, tmp_path: Path) -> None:
        def copy_first(record: dict) -> None:  # type: ignore[type-arg]
            record["presentedApprovals"].insert(0, dict(record["presentedApprovals"][0]))
        assert _probe(tmp_path, "approval-renewed-same-bounds", copy_first) == ALLOW


class TestBindingMembers:
    @pytest.mark.parametrize("name,reason", [
        ("approval-renewal-accepted-after-use", "renewal_transition_missing"),
        ("approval-renewal-predecessor-ambiguous", "renewal_binding_invalid"),
        ("approval-use-cites-predecessor", "approval_not_cited"),
        ("approval-use-cites-no-approval", "approval_not_cited"),
    ])
    def test_member_is_refused_for_its_own_reason(self, name: str, reason: str) -> None:
        assert _verdict(name) == {"decision": "deny", "reason": reason}
        assert _verdict(name, frozenset({reason})) == ALLOW

    def test_ambiguous_predecessor_verdict_does_not_depend_on_order(
        self, tmp_path: Path
    ) -> None:
        member = _verdict("approval-renewal-predecessor-ambiguous")
        reversed_ = _probe(tmp_path, "approval-renewal-predecessor-ambiguous",
                           lambda r: r["presentedApprovals"].reverse())
        conflict_first = _probe(tmp_path, "approval-renewal-predecessor-ambiguous",
                                lambda r: r["presentedApprovals"].insert(
                                    0, r["presentedApprovals"].pop(1)))
        assert member == reversed_ == conflict_first == {
            "decision": "deny", "reason": "renewal_binding_invalid"}

    def test_ambiguous_predecessor_member_is_the_order_a_first_match_reader_allows(
        self,
    ) -> None:
        presented = _case("approval-renewal-predecessor-ambiguous")["presentedApprovals"]
        cited = _case("approval-renewal-predecessor-ambiguous")["transitions"][0][
            "predecessorDecisionId"]
        assert [a["approvalId"] for a in presented[:2]] == ["appr-0001", "appr-0001"]
        assert presented[0]["decisionId"] == cited != presented[1]["decisionId"]

    def test_accepted_after_use_member_differs_from_the_control_only_in_time(self) -> None:
        member, control = _case("approval-renewal-accepted-after-use"), _case(
            "approval-renewed-same-bounds")
        assert member["transitions"][0]["acceptedAt"] > member["use"]["usedAt"]
        member["transitions"][0]["acceptedAt"] = control["transitions"][0]["acceptedAt"]
        assert member == control
