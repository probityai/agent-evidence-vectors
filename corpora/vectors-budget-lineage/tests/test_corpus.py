"""The corpus regenerates, forces every check in order, and refuses a verifier that
judges one flow's counters while a sub-agent spends from a root nobody delegated."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ID = "https://probityai.github.io/agent-evidence-observer/contract/budget-lineage/v1"


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("budget_lineage_corpus", ROOT / "check_vectors.py")
generator = _load("budget_lineage_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import aggregateaccounting as accounting  # noqa: E402
from agent_evidence_vectors import budgetlineage as lineage  # noqa: E402

CHECKS = lineage.CHECKS
DENIED = {name: reason for name, _, decision, reason, _ in generator.cases()
          if decision == "deny"}
ALLOWED = [name for name, _, decision, _, _ in generator.cases() if decision == "allow"]


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import budgetlineage as m\n"
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
    return lineage._first_failure(record, skip)


class TestBudgetLineageCorpus:
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
            assert lineage.CONTRACT_ID == CONTRACT_ID

        def test_both_verdicts_are_present(self) -> None:
            assert ALLOWED and DENIED

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

        def test_verifier_that_reads_only_the_principals_budget_is_refused(self) -> None:
            _, errors = corpus.check(skip=frozenset({"charge_outside_lineage"}))
            assert {"subagent-rerooted-budget", "rerooted-charge-before-revocation",
                    "rerooted-unknown-outcome"} <= _failed(errors)

        def test_verifier_that_counts_depth_per_flow_is_refused(self) -> None:
            _, errors = corpus.check(skip=frozenset({"depth_limit_exceeded"}))
            assert "depth-reset-by-fresh-root" in _failed(errors)

        def test_verifier_that_takes_the_delegators_word_is_refused(self) -> None:
            _, errors = corpus.check(skip=frozenset({"delegation_unilateral"}))
            assert {"delegation-recorded-only-by-delegator",
                    "delegation-claimed-only-by-delegate"} <= _failed(errors)

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
            path = copied / "cases" / "allow-two-hop-tree-within-budget" / "record.json"
            path.write_bytes(path.read_bytes() + b" ")
            _, errors = corpus.check(root=copied)
            assert "allow-two-hop-tree-within-budget: fixture digest mismatch" in errors

    class TestWhatOneBudgetsLogCannotSee:
        def test_the_principals_own_accounting_log_holds_while_the_lineage_does_not(
            self, tmp_path: Path
        ) -> None:
            """The rerooted case, written as the principal's aggregate-accounting log.

            That log lists only what was booked against the principal's budget, so
            the aggregate reader allows it; the lineage record names the sub-agent's
            charge on the fresh root and is refused.
            """
            record = _records()["subagent-rerooted-budget"]
            booked = [item for item in record["ledger"] if item["budget"] == record["budget"]["id"]]
            log = {
                "asOf": record["asOf"],
                "budget": {"id": record["budget"]["id"], "limit": record["budget"]["limit"],
                           "remainingBefore": record["budget"]["limit"], "unit": "units"},
                "contractId": accounting.CONTRACT_ID, "latencyBoundMs": 200,
                "principal": record["principal"], "recordId": "principal-log",
                "decisions": [{
                    "action": "invoke", "agent": item["agent"], "budget": item["budget"],
                    "charged": True, "decision": "admitted", "latencyMs": 20,
                    "outcome": item["outcome"], "principal": record["principal"],
                    "requestId": item["requestId"], "subtree": "subtree-a",
                    "units": item["units"]} for item in booked],
            }
            log["effectCounts"] = accounting.effect_counts(log)
            path = tmp_path / "record.json"
            path.write_text(json.dumps(log), encoding="utf-8")
            assert accounting.verify(path) == {"decision": "allow", "reason": "aggregate_held"}
            assert _first(record) == "charge_outside_lineage"

    class TestRetainedFields:
        def test_every_case_retains_principal_budget_agents_and_units(self) -> None:
            manifest = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
            for entry in manifest["vectors"]:
                assert set(entry["retained"]) == {"agents", "budget", "chargedUnits",
                                                  "principal"}

        def test_a_retained_field_that_differs_is_a_corpus_error(self, tmp_path: Path) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            path = copied / "MANIFEST.json"
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest["vectors"][0]["retained"]["chargedUnits"] += 1
            manifest["corpusDigest"] = lineage._sha(lineage._json(manifest["vectors"]))
            path.write_bytes(lineage._json(manifest))
            _, errors = corpus.check(root=copied)
            assert any("declared retained fields do not hold" in e for e in errors)

    class TestBoundaries:
        def test_a_charge_at_the_revocation_instant_is_outside_the_grant(self) -> None:
            record = _records()["rerooted-charge-before-revocation"]
            record["ledger"][1]["at"] = record["delegations"][1]["revokedAt"]
            assert _first(record) is None

        def test_one_level_deeper_than_the_limit_is_refused(self) -> None:
            record = _records()["allow-depth-at-limit"]
            record["maxDepth"] = 2
            assert _first(record) == "depth_limit_exceeded"

        def test_a_carve_equal_to_the_parent_is_inside_it(self) -> None:
            record = _records()["carve-wider-than-parent"]
            record["delegations"][1]["carve"]["limit"] = 6
            assert _first(record) is None

        def test_an_acceptance_before_its_grant_is_unilateral(self) -> None:
            record = _records()["allow-two-hop-tree-within-budget"]
            record["acceptances"][1]["acceptedAt"] = "2026-11-16T12:00:00Z"
            assert _first(record) == "delegation_unilateral"

        def test_the_principal_charging_another_budget_is_not_a_reroot(self) -> None:
            record = _records()["allow-two-hop-tree-within-budget"]
            record["ledger"].append({"agent": "principal-1", "at": "2026-11-16T12:10:00Z",
                                     "budget": "budget-9", "decision": "admitted",
                                     "outcome": "committed", "requestId": "r9", "units": 9})
            assert _first(record) is None
