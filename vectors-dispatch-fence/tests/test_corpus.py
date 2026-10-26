"""The corpus regenerates, forces every check in order, and refuses a verifier that
reads the fence and the check separately or ignores the hold."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ID = "https://probityai.github.io/agent-evidence-observer/contract/dispatch-fence/v1"


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("dispatch_fence_corpus", ROOT / "check_vectors.py")
generator = _load("dispatch_fence_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import dispatchfence  # noqa: E402

CHECKS = dispatchfence.CHECKS
DENIED = {name: reason for name, _, decision, reason, _ in generator.cases()
          if decision == "deny"}
ALLOWED = [name for name, _, decision, _, _ in generator.cases() if decision == "allow"]


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parent / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import dispatchfence as m\n"
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


def _first(record: dict, skip: frozenset[str] = frozenset()) -> str | None:  # type: ignore[type-arg]
    return dispatchfence._first_failure(record, skip)


class TestDispatchFenceCorpus:
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
            assert dispatchfence.CONTRACT_ID == CONTRACT_ID

        def test_both_verdicts_are_present(self) -> None:
            assert ALLOWED and DENIED

    class TestFailingCases:
        @pytest.mark.parametrize("name", sorted(DENIED))
        def test_each_denied_case_fails_exactly_its_named_check(self, name: str) -> None:
            record = _records()[name]
            reason = DENIED[name]
            assert _first(record) == reason
            # Switching off the named check and every later one leaves only the
            # earlier checks, and the record passes all of them.
            assert _first(record, frozenset(CHECKS[CHECKS.index(reason):])) is None

        @pytest.mark.parametrize("name", sorted(DENIED))
        def test_switching_off_the_named_check_moves_the_verdict(self, name: str) -> None:
            record = _records()[name]
            assert _first(record, frozenset({DENIED[name]})) != DENIED[name]

        @pytest.mark.parametrize("name", CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_verifier_that_re_reads_state_in_the_fence_is_refused(self) -> None:
            # Without the binding check the unbound fence passes, so a verifier
            # that trusts a fence for re-reading state accepts the record.
            _, errors = corpus.check(skip=frozenset({"fence_not_bound_to_check"}))
            assert "fence-rereads-state" in _failed(errors)

        def test_verifier_that_ignores_the_hold_is_refused_on_every_hold_case(self) -> None:
            hold = {"runtime_exceeds_hold", "hold_expired_before_effect_ended",
                    "commit_after_hold_expired"}
            _, errors = corpus.check(skip=frozenset(hold))
            assert {n for n, r in DENIED.items() if r in hold} <= _failed(errors)

        def test_verifier_that_denies_everything_fails_the_controls(
            self, tmp_path: Path
        ) -> None:
            script = tmp_path / "deny.py"
            script.write_text('import json, sys\nprint(json.dumps({"decision": "deny", '
                              '"reason": "contract_id_missing"}))\nsys.exit(1)\n',
                              encoding="ascii")
            _, errors = corpus.check(f"{sys.executable} {script}")
            assert set(ALLOWED) <= _failed(errors)

        def test_missing_verifier_does_not_count_as_answered(self, tmp_path: Path) -> None:
            answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
            assert answered == 0
            assert all("verifier did not run" in error for error in errors)

        def test_mutated_fixture_is_refused_before_execution(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            path = copied / "cases" / "allow-single-read" / "record.json"
            path.write_bytes(path.read_bytes() + b" ")
            _, errors = corpus.check(root=copied)
            assert "allow-single-read: fixture digest mismatch" in errors

    class TestBoundaries:
        def _record(self, name: str = "allow-single-read") -> dict:  # type: ignore[type-arg]
            return _records()[name]

        def test_event_at_the_read_sequence_does_not_change_state_after_the_check(self) -> None:
            record = self._record()
            record["stateEvents"].append({"at": "x", "kind": "late", "seq": 5})
            assert _first(record) is None

        def test_event_at_the_append_sequence_is_after_the_check(self) -> None:
            record = self._record()
            record["fence"]["appendSeq"] = 6
            record["stateEvents"].append({"at": "x", "kind": "late", "seq": 6})
            assert _first(record) == "state_changed_between_check_and_fence"

        def test_an_attempt_that_was_not_admitted_is_not_concurrent(self) -> None:
            record = self._record()
            record["otherAttempts"] = [{"admitted": False, "beganAt": generator.at(30),
                                        "proposalId": "proposal-other"}]
            assert _first(record) is None

        def test_attempt_at_the_end_of_the_effect_is_inside_the_window(self) -> None:
            record = self._record()
            record["otherAttempts"] = [{"admitted": True, "beganAt": generator.at(60),
                                        "proposalId": "proposal-other"}]
            assert _first(record) == "concurrent_dispatch_admitted"

        def test_attempt_after_the_effect_is_outside_the_window(self) -> None:
            record = self._record()
            record["otherAttempts"] = [{"admitted": True, "beganAt": generator.at(61),
                                        "proposalId": "proposal-other"}]
            assert _first(record) is None

        def test_declared_runtime_equal_to_the_ttl_needs_no_renewal(self) -> None:
            record = self._record()
            record["effect"]["declaredMaxRuntimeSeconds"] = 120
            assert _first(record) is None

        def test_the_hold_expires_at_its_latest_renewal(self) -> None:
            record = self._record("allow-renewed-hold-covers-effect")
            assert dispatchfence.hold_expiry(record) == dispatchfence._when(generator.at(360))
