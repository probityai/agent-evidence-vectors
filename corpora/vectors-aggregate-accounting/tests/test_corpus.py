"""The corpus regenerates, forces every check in order, and refuses a verifier that
admits what the shared budget cannot cover or forgets what it cannot see."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ID = "https://probityai.github.io/agent-evidence-observer/contract/aggregate-accounting/v1"


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("aggregate_accounting_corpus", ROOT / "check_vectors.py")
generator = _load("aggregate_accounting_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import aggregateaccounting as accounting  # noqa: E402

CHECKS = accounting.CHECKS
DENIED = {name: reason for name, _, decision, reason, _ in generator.cases()
          if decision == "deny"}
ALLOWED = [name for name, _, decision, _, _ in generator.cases() if decision == "allow"]


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parent / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import aggregateaccounting as m\n"
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
    return accounting._first_failure(record, skip)


class TestAggregateAccountingCorpus:
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
            assert accounting.CONTRACT_ID == CONTRACT_ID

        def test_both_verdicts_are_present(self) -> None:
            assert ALLOWED and DENIED

        def test_the_four_stated_cases_are_present(self) -> None:
            assert {"allow-concurrent-both-fit", "allow-race-one-admitted",
                    "allow-unknown-outcome-stays-charged",
                    "allow-past-latency-bound-refused"} <= set(ALLOWED)
            assert {"race-both-admitted", "unknown-outcome-released-after-expiry",
                    "latency-bound-admitted"} <= set(DENIED)

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

        def test_verifier_that_checks_each_agent_alone_is_refused(self) -> None:
            _, errors = corpus.check(skip=frozenset({"aggregate_overspend"}))
            assert {"race-both-admitted",
                    "per-agent-limits-hold-aggregate-fails"} <= _failed(errors)

        def test_verifier_that_forgets_unknown_outcomes_is_refused(self) -> None:
            _, errors = corpus.check(skip=frozenset({"unknown_outcome_not_charged"}))
            assert "unknown-outcome-released-after-expiry" in _failed(errors)

        def test_verifier_that_fails_open_past_the_bound_is_refused(self) -> None:
            _, errors = corpus.check(skip=frozenset({"latency_bound_admitted"}))
            assert "latency-bound-admitted" in _failed(errors)

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
            path = copied / "cases" / "allow-concurrent-both-fit" / "record.json"
            path.write_bytes(path.read_bytes() + b" ")
            _, errors = corpus.check(root=copied)
            assert "allow-concurrent-both-fit: fixture digest mismatch" in errors

    class TestRetainedFields:
        def test_every_case_retains_principal_subtrees_budget_actions_and_counts(self) -> None:
            manifest = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
            for entry in manifest["vectors"]:
                kept = entry["retained"]
                assert set(kept) == {"actions", "budget", "counts", "principal", "subtrees"}
                assert set(kept["counts"]) == {"admitted", "refused", "held",
                                               "chargedUnits", "remainingUnits"}

        def test_a_retained_field_that_differs_from_the_decisions_is_a_corpus_error(
            self, tmp_path: Path
        ) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            path = copied / "MANIFEST.json"
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest["vectors"][0]["retained"]["counts"]["chargedUnits"] += 1
            manifest["corpusDigest"] = accounting._sha(accounting._json(manifest["vectors"]))
            path.write_bytes(accounting._json(manifest))
            _, errors = corpus.check(root=copied)
            assert any("declared retained fields do not hold" in e for e in errors)

    class TestBoundaries:
        def _record(self, name: str = "allow-concurrent-both-fit") -> dict:  # type: ignore[type-arg]
            return _records()[name]

        def test_spending_the_budget_exactly_is_not_overspend(self) -> None:
            assert _first(self._record("allow-exact-fit-both-admitted")) is None

        def test_one_unit_over_is_overspend(self) -> None:
            record = self._record("allow-exact-fit-both-admitted")
            record["decisions"][1]["units"] = 6
            record["effectCounts"] = accounting.effect_counts(record)
            assert _first(record) == "aggregate_overspend"

        def test_a_latency_at_the_bound_is_inside_it(self) -> None:
            assert _first(self._record("allow-latency-at-bound-admitted")) is None

        def test_a_latency_one_millisecond_past_the_bound_is_not(self) -> None:
            record = self._record("allow-latency-at-bound-admitted")
            record["decisions"][0]["latencyMs"] = record["latencyBoundMs"] + 1
            assert _first(record) == "latency_bound_admitted"

        def test_a_released_reservation_is_not_charged(self) -> None:
            record = self._record("allow-released-reservation-returns-units")
            assert accounting.charged_units(record) == 6

        def test_a_refusal_for_latency_is_not_an_over_refusal(self) -> None:
            assert _first(self._record("allow-past-latency-bound-refused")) is None

        def test_a_held_request_is_not_charged(self) -> None:
            record = self._record("allow-past-latency-bound-held")
            assert accounting.effect_counts(record)["held"] == 1
            assert accounting.charged_units(record) == 0
