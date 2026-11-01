"""The corpus regenerates, forces every check in order, refuses a verifier that reads a
lost reply as settled, and fails a runtime that resends a write whose reply it lost."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "tests" / "runtime_adapter.py"
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/uncertain-effect"


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("uncertain_effect_corpus", ROOT / "check_vectors.py")
generator = _load("uncertain_effect_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import uncertaineffect as effect  # noqa: E402
from agent_evidence_vectors import uncertaineffect_runtime as runtime  # noqa: E402

CHECKS = effect.CHECKS
DENIED = {case[0]: case[3] for case in generator.cases() if case[2] == "deny"}
ALLOWED = [case[0] for case in generator.cases() if case[2] == "allow"]


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parent / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import uncertaineffect as m\n"
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
    return effect._first_failure(record, skip)


def _manifest() -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))


class TestUncertainEffectCorpus:
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
            assert effect.CONTRACT_ID == CONTRACT_ID

        def test_each_requested_shape_has_a_fault_and_its_safe_control(self) -> None:
            pairs = {
                "retry-after-commit-timeout": "allow-commit-timeout-reconciled-present",
                "retry-after-lookup-not-final": "allow-late-commit-awaited",
                "unknown-released-at-expiry": "allow-unknown-charged-past-expiry",
                "reconciled-present-still-unknown": "allow-commit-timeout-reconciled-present",
                "key-reused-args-changed": "allow-retry-same-key-owner-deduplicates",
                "dispatch-after-lease-expired": "allow-lease-taken-over-reconciled",
                "timeout-reported-not-run": "allow-timeout-reconciled-absent-not-run",
                "retry-under-new-key": "allow-retry-after-final-absent",
            }
            assert set(pairs) <= set(DENIED)
            assert set(pairs.values()) <= set(ALLOWED)

    class TestFailingCases:
        @pytest.mark.parametrize("name", sorted(DENIED))
        def test_each_denied_case_fails_exactly_its_named_check(self, name: str) -> None:
            record = _records()[name]
            reason = DENIED[name]
            assert _first(record) == reason
            assert _first(record, frozenset(CHECKS[CHECKS.index(reason):])) is None

        @pytest.mark.parametrize("name", sorted(DENIED))
        def test_switching_off_the_named_check_moves_the_verdict(self, name: str) -> None:
            record = _records()[name]
            assert _first(record, frozenset({DENIED[name]})) != DENIED[name]

        @pytest.mark.parametrize("name", CHECKS)
        def test_every_check_is_forced_by_some_case(self, name: str) -> None:
            _, errors = corpus.check(skip=frozenset({name}))
            assert errors, f"switching off {name} changed no verdict"

        def test_verifier_that_trusts_a_blind_retry_is_refused(self) -> None:
            _, errors = corpus.check(skip=frozenset({"retry_after_unknown"}))
            assert {"retry-after-commit-timeout", "retry-under-new-key"} <= _failed(errors)

        def test_verifier_that_reads_a_lost_reply_as_settled_is_refused(self) -> None:
            _, errors = corpus.check(skip=frozenset({"outcome_settled_without_authority"}))
            assert {"timeout-reported-not-run", "timeout-reported-committed"} <= _failed(errors)

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
            path = copied / "cases" / "allow-confirmed-first-attempt" / "record.json"
            path.write_bytes(path.read_bytes() + b" ")
            _, errors = corpus.check(root=copied)
            assert "allow-confirmed-first-attempt: fixture digest mismatch" in errors

        def test_a_retained_field_that_differs_from_the_record_is_a_corpus_error(
            self, tmp_path: Path
        ) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            path = copied / "MANIFEST.json"
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest["vectors"][0]["retained"]["ownerEffects"] += 1
            manifest["corpusDigest"] = effect._sha(effect._json(manifest["vectors"]))
            path.write_bytes(effect._json(manifest))
            _, errors = corpus.check(root=copied)
            assert any("declared retained fields do not hold" in e for e in errors)

    class TestBoundaries:
        def test_a_lookup_that_is_not_final_settles_nothing(self) -> None:
            record = _records()["allow-late-commit-awaited"]
            record["reconciliations"] = record["reconciliations"][:1]
            assert effect.settled_outcome(record) == "unknown"

        def test_a_resend_inside_the_key_retention_window_is_protected(self) -> None:
            record = _records()["retry-after-key-retention-expired"]
            record["effectOwner"]["keyRetentionSeconds"] = 90000
            assert _first(record) == "duplicate_effect"

        def test_a_dispatch_at_the_lease_expiry_instant_is_outside_it(self) -> None:
            record = _records()["dispatch-after-lease-expired"]
            record["leases"][0]["expiresAt"] = record["attempts"][1]["dispatchedAt"]
            assert _first(record) == "dispatch_beyond_lease"
            record["leases"][0]["expiresAt"] = "2026-10-28T12:00:41Z"
            assert _first(record) is None

    class TestRuntimeScenarios:
        def test_every_case_pairs_with_a_scenario_and_one_effect_at_most(self) -> None:
            entries = _manifest()["vectors"]
            scenarios = effect.scenarios(entries)
            assert len(scenarios) == len(generator.SCENARIOS)
            for scenario in scenarios:
                assert scenario["accepted"]
                assert all(item["effects"] <= 1 for item in scenario["accepted"])

        def test_a_runtime_that_reconciles_passes_every_scenario(self, tmp_path: Path) -> None:
            report = runtime.check_runtime([sys.executable, str(ADAPTER)], ROOT)
            assert report["failures"] == []
            assert report["verifier"]["vectorsExecuted"] == report["totals"]["vectors"]
            assert report["totals"]["vectors"] == len(generator.SCENARIOS)

        def test_a_runtime_that_resends_blindly_is_refused(self) -> None:
            report = runtime.check_runtime(
                [sys.executable, str(ADAPTER), "--policy", "blind"], ROOT)
            failed = {row["id"] for row in report["vectors"] if row["status"] == "FAIL"}
            assert {"commit-then-lost-reply", "late-commit-after-missed-lookup",
                    "lease-lost-after-lost-reply"} <= failed
            assert "confirmed" not in failed

        def test_a_runtime_that_cannot_start_does_not_count_as_run(self, tmp_path: Path) -> None:
            report = runtime.check_runtime([str(tmp_path / "no-such-runtime")], ROOT)
            assert report["verifier"]["vectorsExecuted"] == 0
            assert report["totals"]["fail"] == report["totals"]["vectors"]

        def test_the_runtime_report_writes_and_exits_by_its_result(self, tmp_path: Path) -> None:
            path = tmp_path / "report.json"
            code = runtime.run_runtime([sys.executable, str(ADAPTER)], str(path), ROOT)
            assert code == 0
            assert json.loads(path.read_text(encoding="utf-8"))["rail"] == "external"
            code = runtime.run_runtime(
                [sys.executable, str(ADAPTER), "--policy", "blind"], str(path), ROOT)
            assert code == 1
