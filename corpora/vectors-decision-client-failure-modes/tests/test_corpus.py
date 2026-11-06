"""The corpus regenerates, forces every check in order, refuses a verifier that reads a
fault as a decision, and fails a decision client that acts on a fault."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "tests" / "client_adapter.py"
CONTRACT_ID = ("https://probityai.github.io/agent-evidence-vectors/predicate/v1/"
               "decision-client-failure-modes")


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("decision_client_corpus", ROOT / "check_vectors.py")
generator = _load("decision_client_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import decisionclient as reader  # noqa: E402
from agent_evidence_vectors import decisionclient_runtime as runtime  # noqa: E402

CHECKS = reader.CHECKS
DENIED = {case[0]: case[3] for case in generator.cases() if case[2] == "deny"}
ALLOWED = [case[0] for case in generator.cases() if case[2] == "allow"]
CONDITIONS = ("unreachable", "http-500", "http-503", "unparseable-body", "timeout",
              "unknown-verdict", "missing-verdict")
CONTROLS = ("control-block", "control-halt", "control-allow", "control-401")


def _stub(tmp_path: Path, skip: tuple[str, ...]) -> str:
    script = tmp_path / "stub.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(ROOT.parents[1] / 'packaging')!r})\n"
        "from pathlib import Path\n"
        "from agent_evidence_vectors import decisionclient as m\n"
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
    return reader._first_failure(record, skip)


def _manifest() -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))


class TestDecisionClientCorpus:
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
            assert "contractId" not in records["reject-contract-id-missing"]
            assert records["reject-contract-id-unknown"]["contractId"] != CONTRACT_ID
            others = {k: v for k, v in records.items()
                      if k not in {"reject-contract-id-missing", "reject-contract-id-unknown"}}
            assert others and all(r["contractId"] == CONTRACT_ID for r in others.values())
            assert reader.CONTRACT_ID == CONTRACT_ID

        def test_every_scenario_has_a_conforming_record(self) -> None:
            assert {f"accept-{sid}" for sid in generator.SCENARIOS} == set(ALLOWED)

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

        def test_verifier_that_reads_an_unknown_verdict_as_known_is_refused(self) -> None:
            _, errors = corpus.check(skip=frozenset({"condition_misclassified"}))
            assert {"reject-unknown-verdict-read-as-allow",
                    "reject-missing-verdict-read-as-allow"} <= _failed(errors)

        def test_verifier_that_accepts_a_fallback_allow_is_refused(self) -> None:
            _, errors = corpus.check(skip=frozenset({"fault_allowed"}))
            assert {"reject-unreachable-allowed", "reject-timeout-allowed",
                    "reject-unauthorized-allowed"} <= _failed(errors)

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
            path = copied / "cases" / "accept-control-allow" / "record.json"
            path.write_bytes(path.read_bytes() + b" ")
            _, errors = corpus.check(root=copied)
            assert "accept-control-allow: fixture digest mismatch" in errors

        def test_a_retained_field_that_differs_from_the_record_is_a_corpus_error(
            self, tmp_path: Path
        ) -> None:
            copied = tmp_path / "corpus"
            shutil.copytree(ROOT, copied, ignore=shutil.ignore_patterns("tests", "__pycache__"))
            path = copied / "MANIFEST.json"
            manifest = json.loads(path.read_text(encoding="utf-8"))
            manifest["vectors"][0]["retained"]["performed"] = not \
                manifest["vectors"][0]["retained"]["performed"]
            manifest["corpusDigest"] = reader._sha(reader._json(manifest["vectors"]))
            path.write_bytes(reader._json(manifest))
            _, errors = corpus.check(root=copied)
            assert any("declared retained fields do not hold" in e for e in errors)

    class TestBoundaries:
        @pytest.mark.parametrize("status,condition", [
            (199, "http-error"), (200, "ok"), (299, "ok"), (300, "http-error"),
            (401, "unauthorized"), (403, "unauthorized"), (404, "http-error")])
        def test_the_status_boundaries(self, status: int, condition: str) -> None:
            exchange = {"bodyIsJsonObject": True, "httpStatus": status, "reached": True,
                        "timedOut": False, "verdict": "allow"}
            assert reader.derived_condition(exchange) == condition

        def test_an_empty_verdict_string_is_unknown(self) -> None:
            exchange = {"bodyIsJsonObject": True, "httpStatus": 200, "reached": True,
                        "timedOut": False, "verdict": ""}
            assert reader.derived_condition(exchange) == "unknown-verdict"

        def test_a_reply_that_arrived_carries_a_status(self) -> None:
            record = _records()["accept-control-allow"]
            record["exchange"]["httpStatus"] = None
            assert _first(record) == "record_malformed"

    class TestRuntimeScenarios:
        def test_the_matrix_is_seven_conditions_by_two_modes_and_four_controls(self) -> None:
            ids = [s["id"] for s in reader.scenarios(_manifest()["vectors"])]
            expected = {f"{c}--{m}" for c in CONDITIONS for m in reader.MODES} | set(CONTROLS)
            assert len(ids) == len(expected) and set(ids) == expected

        def test_every_fault_scenario_accepts_only_a_marked_denial(self) -> None:
            for scenario in reader.scenarios(_manifest()["vectors"]):
                if scenario["id"] in ("control-block", "control-halt", "control-allow"):
                    continue
                assert scenario["accepted"] == {"basis": "fallback", "effects": 0,
                                                "halted": False, "outcome": "deny"}

        def test_a_client_that_fails_closed_passes_every_scenario(self) -> None:
            report = runtime.check_runtime([sys.executable, str(ADAPTER)], ROOT)
            assert report["failures"] == []
            executed = report["verifier"]["vectorsExecuted"]
            assert executed == report["totals"]["vectors"] == len(generator.SCENARIOS)
            assert all(row["observed"]["recordWritten"] for row in report["vectors"])

        def test_a_client_that_fails_open_is_refused(self) -> None:
            report = runtime.check_runtime(
                [sys.executable, str(ADAPTER), "--policy", "open"], ROOT)
            failed = {row["id"] for row in report["vectors"] if row["status"] == "FAIL"}
            transport = ("unreachable", "http-500", "http-503", "unparseable-body", "timeout")
            assert failed == ({f"{c}--default" for c in transport}
                              | {f"{c}--{m}" for c in ("unknown-verdict", "missing-verdict")
                                 for m in reader.MODES})

        def test_a_client_without_a_record_is_judged_on_what_it_did(self) -> None:
            report = runtime.check_runtime(
                [sys.executable, str(ADAPTER), "--no-record"], ROOT)
            assert report["failures"] == []
            assert not any(row["observed"]["recordWritten"] for row in report["vectors"])

        def test_a_client_that_cannot_start_does_not_count_as_run(self, tmp_path: Path) -> None:
            report = runtime.check_runtime([str(tmp_path / "no-such-client")], ROOT)
            assert report["verifier"]["vectorsExecuted"] == 0
            assert report["totals"]["fail"] == report["totals"]["vectors"]

        def test_the_runtime_report_writes_and_exits_by_its_result(self, tmp_path: Path) -> None:
            path = tmp_path / "report.json"
            code = runtime.run_runtime([sys.executable, str(ADAPTER)], str(path), ROOT)
            assert code == 0
            assert json.loads(path.read_text(encoding="utf-8"))["rail"] == "external"
            code = runtime.run_runtime(
                [sys.executable, str(ADAPTER), "--policy", "open"], str(path), ROOT)
            assert code == 1
