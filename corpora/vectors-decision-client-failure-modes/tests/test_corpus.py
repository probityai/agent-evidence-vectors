"""The corpus regenerates, keeps every case it shipped before the optional members, forces
every check in order, refuses a verifier that reads a fault as a decision or ignores the
posture, and fails a decision client that acts on a fault or runs under a posture that
does not enforce."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "tests" / "client_adapter.py"
BASELINE = ROOT / "tests" / "v1-baseline.json"
CONTRACT_ID = (
    "https://probityai.github.io/agent-evidence-vectors/predicate/v1/decision-client-failure-modes"
)


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
CONDITIONS = (
    "unreachable",
    "http-500",
    "http-503",
    "unparseable-body",
    "timeout",
    "unknown-verdict",
    "missing-verdict",
    "oversize",
    "outage",
)
CONTROLS = ("control-block", "control-halt", "control-allow", "control-401", "control-at-limit")
POSTURE_STATED = {
    f"accept-posture-stated-{sid}"
    for sid in ("control-allow", "control-block", "control-halt", "http-500--strict")
}
POSTURE_CHECKS = ("monitor_mode", "fail_open_posture", "fail_mode_defaulted")
SCENARIO_IDS = {f"{c}--{m}" for c in CONDITIONS for m in ("default", "strict")} | set(CONTROLS)


def _naive(record: dict) -> dict:  # type: ignore[type-arg]
    """What a verifier written before the optional members sees of a record."""
    seen = json.loads(json.dumps(record))
    seen.pop("posture", None)
    seen.get("client", {}).pop("maxResponseBytes", None)
    for member in ("bodyBytes", "circuitOpen"):
        seen.get("exchange", {}).pop(member, None)
    return seen


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
    return {
        p.parent.name: json.loads(p.read_text(encoding="utf-8"))
        for p in (ROOT / "cases").glob("*/record.json")
    }


def _first(record: dict, skip: frozenset[str] = frozenset()) -> str | None:  # type: ignore[type-arg]
    return reader._first_failure(record, skip)


def _manifest() -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))


class TestDecisionClientCorpus:
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
            answered, errors = corpus.check(_stub(tmp_path, ()))
            assert errors == []
            assert answered == len(generator.cases())

        def test_every_record_but_the_contract_cases_carries_the_contract_id(self) -> None:
            records = _records()
            assert "contractId" not in records["reject-contract-id-missing"]
            assert records["reject-contract-id-unknown"]["contractId"] != CONTRACT_ID
            others = {
                k: v
                for k, v in records.items()
                if k not in {"reject-contract-id-missing", "reject-contract-id-unknown"}
            }
            assert others and all(r["contractId"] == CONTRACT_ID for r in others.values())
            assert reader.CONTRACT_ID == CONTRACT_ID

        def test_every_scenario_has_a_conforming_record(self) -> None:
            assert {f"accept-{sid}" for sid in generator.SCENARIOS} | POSTURE_STATED == set(
                ALLOWED
            )

        def test_the_cases_shipped_before_the_optional_members_are_unchanged(self) -> None:
            baseline = json.loads(BASELINE.read_text(encoding="utf-8"))["cases"]
            regenerated = {case[0]: case for case in generator.cases()}
            for name, held in baseline.items():
                case = regenerated[name]
                assert reader._sha(reader._json(case[1])) == held["recordSha256"], name
                assert {"decision": case[2], "reason": case[3]} == held["expected"], name
                assert reader.verify(ROOT / "cases" / name / "record.json") == held["expected"]
                assert not {"posture"} & set(case[1])
                assert "maxResponseBytes" not in case[1]["client"]

        def test_every_stated_posture_on_an_allowed_record_enforces(self) -> None:
            records = _records()
            for name in ALLOWED:
                posture = records[name].get("posture")
                assert posture is None or posture == reader.ENFORCING_POSTURE, name

    class TestFailingCases:
        @pytest.mark.parametrize("name", sorted(DENIED))
        def test_each_denied_case_fails_exactly_its_named_check(self, name: str) -> None:
            record = _records()[name]
            reason = DENIED[name]
            assert _first(record) == reason
            assert _first(record, frozenset(CHECKS[CHECKS.index(reason) :])) is None

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
            assert {
                "reject-unknown-verdict-read-as-allow",
                "reject-missing-verdict-read-as-allow",
            } <= _failed(errors)

        def test_verifier_that_accepts_a_fallback_allow_is_refused(self) -> None:
            _, errors = corpus.check(skip=frozenset({"fault_allowed"}))
            assert {
                "reject-unreachable-allowed",
                "reject-timeout-allowed",
                "reject-unauthorized-allowed",
            } <= _failed(errors)

        def test_verifier_that_ignores_the_posture_is_refused(self) -> None:
            _, errors = corpus.check(skip=frozenset(POSTURE_CHECKS))
            assert _failed(errors) == {
                name for name, reason in DENIED.items() if reason in POSTURE_CHECKS
            }

        def test_the_naive_verifier_the_field_ships_lets_exactly_these_through(self) -> None:
            # Blind to posture, response limits and breakers: it judges the exchange
            # a v1-era record carries and nothing else.
            records = _records()
            through = {
                name
                for name in DENIED
                if _first(_naive(records[name])) is None
            }
            assert through == {
                "reject-monitor-allow",
                "reject-fail-open-posture-ok",
                "reject-fail-open-posture-fault-denied",
                "reject-fail-mode-defaulted-closed",
                "reject-strict-mode-defaulted",
                "reject-oversize-prefix-parsed",
                "reject-limit-without-body-size",
                "reject-body-size-without-reply",
                "reject-posture-outside-vocabulary",
                "reject-posture-flag-unstated",
                "reject-circuit-open-recorded-as-unreachable",
            }
            refused_controls = {name for name in ALLOWED if _first(_naive(records[name]))}
            assert refused_controls == {
                f"accept-{c}--{m}" for c in ("oversize", "outage") for m in ("default", "strict")
            }

        def test_verifier_that_denies_everything_fails_the_controls(self, tmp_path: Path) -> None:
            script = tmp_path / "deny.py"
            script.write_text(
                'import json, sys\nprint(json.dumps({"decision": "deny", '
                '"reason": "contract_id_missing"}))\nsys.exit(1)\n',
                encoding="ascii",
            )
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
            manifest["vectors"][0]["retained"]["performed"] = not manifest["vectors"][0][
                "retained"
            ]["performed"]
            manifest["corpusDigest"] = reader._sha(reader._json(manifest["vectors"]))
            path.write_bytes(reader._json(manifest))
            _, errors = corpus.check(root=copied)
            assert any("declared retained fields do not hold" in e for e in errors)

    class TestBoundaries:
        @pytest.mark.parametrize(
            "status,condition",
            [
                (199, "http-error"),
                (200, "ok"),
                (299, "ok"),
                (300, "http-error"),
                (401, "unauthorized"),
                (403, "unauthorized"),
                (404, "http-error"),
            ],
        )
        def test_the_status_boundaries(self, status: int, condition: str) -> None:
            exchange = {
                "bodyIsJsonObject": True,
                "httpStatus": status,
                "reached": True,
                "timedOut": False,
                "verdict": "allow",
            }
            assert reader.derived_condition(exchange) == condition

        def test_an_empty_verdict_string_is_unknown(self) -> None:
            exchange = {
                "bodyIsJsonObject": True,
                "httpStatus": 200,
                "reached": True,
                "timedOut": False,
                "verdict": "",
            }
            assert reader.derived_condition(exchange) == "unknown-verdict"

        @pytest.mark.parametrize("size,condition", [(4095, "ok"), (4096, "ok"), (4097, "oversize")])
        def test_the_response_limit_boundaries(self, size: int, condition: str) -> None:
            exchange = {
                "bodyBytes": size,
                "bodyIsJsonObject": True,
                "httpStatus": 200,
                "reached": True,
                "timedOut": False,
                "verdict": "allow",
            }
            assert reader.derived_condition(exchange, 4096) == condition
            assert reader.derived_condition(exchange) == "ok"

        def test_an_error_status_outranks_an_oversize_body(self) -> None:
            exchange = {
                "bodyBytes": 9999,
                "bodyIsJsonObject": False,
                "httpStatus": 500,
                "reached": True,
                "timedOut": False,
            }
            assert reader.derived_condition(exchange, 4096) == "http-error"

        @pytest.mark.parametrize(
            "edit",
            [
                {"client": {"maxResponseBytes": True}},
                {"client": {"maxResponseBytes": 0}},
                {"exchange": {"bodyBytes": -1}},
                {"exchange": {"circuitOpen": "yes"}},
                {"posture": "enforce"},
            ],
        )
        def test_optional_members_are_typed(self, edit: dict) -> None:  # type: ignore[type-arg]
            record = _records()["accept-control-at-limit"]
            for key, value in edit.items():
                if isinstance(value, dict):
                    record[key].update(value)
                else:
                    record[key] = value
            assert _first(record) == "record_malformed"

        def test_a_reply_that_arrived_carries_a_status(self) -> None:
            record = _records()["accept-control-allow"]
            record["exchange"]["httpStatus"] = None
            assert _first(record) == "record_malformed"

    class TestRuntimeScenarios:
        def test_the_matrix_is_nine_conditions_by_two_modes_and_five_controls(self) -> None:
            ids = [s["id"] for s in reader.scenarios(_manifest()["vectors"])]
            assert len(ids) == len(SCENARIO_IDS) and set(ids) == SCENARIO_IDS

        def test_the_limit_scenarios_straddle_the_limit(self) -> None:
            scenarios = {s["id"]: s for s in reader.scenarios(_manifest()["vectors"])}
            for sid, size in (("control-at-limit", 0), ("oversize--strict", 1)):
                scenario = scenarios[sid]
                body = runtime.point_body(scenario["decisionPoint"]).encode()
                assert len(body) == scenario["maxResponseBytes"] + size
                assert json.loads(body)["verdict"] == "allow"

        def test_every_fault_scenario_accepts_only_a_marked_denial(self) -> None:
            for scenario in reader.scenarios(_manifest()["vectors"]):
                if scenario["id"] in (
                    "control-block", "control-halt", "control-allow", "control-at-limit"
                ):
                    continue
                assert scenario["accepted"] == {
                    "basis": "fallback",
                    "effects": 0,
                    "halted": False,
                    "outcome": "deny",
                }

        def test_a_client_that_fails_closed_passes_every_scenario(self) -> None:
            report = runtime.check_runtime([sys.executable, str(ADAPTER)], ROOT)
            assert report["failures"] == []
            executed = report["verifier"]["vectorsExecuted"]
            assert executed == report["totals"]["vectors"] == len(generator.SCENARIOS)
            assert all(row["observed"]["recordWritten"] for row in report["vectors"])

        def test_a_client_that_states_a_fail_open_posture_fails_every_scenario(self) -> None:
            report = runtime.check_runtime([sys.executable, str(ADAPTER), "--policy", "open"], ROOT)
            assert {row["id"] for row in report["vectors"] if row["status"] == "FAIL"} == (
                SCENARIO_IDS
            )
            assert all("fail-open" in " ".join(row["reasons"]) for row in report["vectors"])

        def test_a_client_that_fails_open_and_claims_closed_is_refused_by_what_it_did(
            self,
        ) -> None:
            command = [sys.executable, str(ADAPTER), "--policy", "open", "--fail-mode", "closed"]
            report = runtime.check_runtime(command, ROOT)
            failed = {row["id"] for row in report["vectors"] if row["status"] == "FAIL"}
            transport = ("unreachable", "http-500", "http-503", "unparseable-body", "timeout")
            assert failed == (
                {f"{c}--default" for c in (*transport, "outage")}
                | {
                    f"{c}--{m}"
                    for c in ("unknown-verdict", "missing-verdict", "oversize")
                    for m in reader.MODES
                }
            )

        @pytest.mark.parametrize(
            "flags,word",
            [(["--enforcement", "monitor"], "monitored"), (["--no-posture"], "unstated")],
        )
        def test_a_client_that_does_not_enforce_fails_every_scenario(
            self, flags: list[str], word: str
        ) -> None:
            report = runtime.check_runtime([sys.executable, str(ADAPTER), *flags], ROOT)
            assert {row["id"] for row in report["vectors"] if row["status"] == "FAIL"} == (
                SCENARIO_IDS
            )
            assert all(word in " ".join(row["reasons"]) for row in report["vectors"])

        def test_a_defaulted_fail_mode_passes_only_the_shipped_default(self) -> None:
            command = [sys.executable, str(ADAPTER), "--fail-mode-source", "default"]
            report = runtime.check_runtime(command, ROOT)
            failed = {row["id"] for row in report["vectors"] if row["status"] == "FAIL"}
            assert failed == {sid for sid in SCENARIO_IDS if sid.endswith("--strict")}

        def test_every_row_reports_the_posture_the_client_stated(self) -> None:
            report = runtime.check_runtime([sys.executable, str(ADAPTER)], ROOT)
            assert all(
                row["observed"]["posture"] == reader.ENFORCING_POSTURE for row in report["vectors"]
            )

        def test_a_record_that_omits_the_printed_posture_is_refused(self, tmp_path: Path) -> None:
            scenario = reader.scenarios(_manifest()["vectors"])[0]
            record = tmp_path / "record.json"
            written = dict(_records()[f"accept-{scenario['id']}"])
            record.write_text(json.dumps(written), encoding="utf-8")
            reported = {"basis": "fallback", "halted": False, "outcome": "deny",
                        "posture": reader.ENFORCING_POSTURE}
            problems = runtime._record_problems(scenario["mode"], record, reported)
            assert any("states posture None" in problem for problem in problems)

        def test_a_client_without_a_record_is_judged_on_what_it_did(self) -> None:
            report = runtime.check_runtime([sys.executable, str(ADAPTER), "--no-record"], ROOT)
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
                [sys.executable, str(ADAPTER), "--policy", "open"], str(path), ROOT
            )
            assert code == 1
