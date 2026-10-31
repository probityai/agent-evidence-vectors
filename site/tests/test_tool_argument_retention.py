"""Model-free adversarial controls for authentic native tool-argument retention."""
from __future__ import annotations

import copy
import json
import logging
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, strategies as st

from imported_commits import here
from tools.check_lab import artifact_path, validate_register
from tools.check_tool_argument_retention import (
    BASELINE, HASHES, IDENTITY, UNMEASURED, archive_members, digest, encode,
    expected_scores, source_record, strict_json, verify_attempts,
    verify_quality, verify_source_closure, verify_terminal,
)

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "../experiments/" + IDENTITY + "/"
SOURCE = ROOT / "experiments" / IDENTITY


@pytest.fixture
def originals() -> tuple[dict[str, bytes], dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Read authentic selected data without importing the retained packet sources."""
    provenance = strict_json((SOURCE / "provenance.json").read_bytes())
    with zipfile.ZipFile(SOURCE / "original-artifact.zip") as bundle:
        members = archive_members(bundle, provenance)
    return (members, strict_json(members["report.json"]),
            strict_json(members["protocol.json"]),
            strict_json((SOURCE / "source-contract.json").read_bytes()))


@pytest.fixture
def retained(tmp_path: Path) -> tuple[dict[str, Any], Path]:
    """Copy the selected compact native retention into an isolated test root."""
    record = source_record(strict_json((SOURCE / "provenance.json").read_bytes()),
                           strict_json((SOURCE / "native-report.json").read_bytes()))
    for artifact in record["artifacts"]:
        target = artifact_path(tmp_path, artifact["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(artifact_path(ROOT, artifact["path"]), target)
    return {"protocolVersion": "0.1", "records": [record]}, tmp_path


def refused(register: dict[str, Any], root: Path, caplog: pytest.LogCaptureFixture,
            message: str) -> None:
    """Require stable fail-closed validation and the public refusal log together."""
    with caplog.at_level(logging.ERROR, logger="atlas.lab_register"):
        with pytest.raises(ValueError, match=message):
            validate_register(register, root)
    assert "lab register refused: " + message in caplog.text


class TestToolArgumentRetention:
    class TestPassingCases:
        def test_complete_original_native_population(self, retained: tuple[dict[str, Any], Path], originals: tuple[dict[str, bytes], dict[str, Any], dict[str, Any], dict[str, Any]]) -> None:
            register, root = retained
            validate_register(register, root)
            members, report, protocol, contract = originals
            assert len(members) == 331
            assert len(protocol["sourceClosure"]) == 12
            verify_source_closure(members, protocol, contract)
            verify_attempts(members, report, protocol)
            verify_quality(report)
            verify_terminal(members, report)
            assert report["population"] == {"planned": 128, "started": 128, "scored": 128,
                                            "error": 0, "incomplete": 0, "unknown-start": 0, "unsupported": 0}
            assert sum(row["truncated"] for row in report["attempts"]) == 64
            assert report["nativeTokens"] == {"prompt": 29992, "completion": 3468}
            assert all(row["fullyCorrectPairs"] == row["correctAbstentions"] == 0
                       for row in report["quality"])
            assert [row["correct"] for row in report["quality"]] == [0, 0, 0, 0, 0, 0, 7, 7]
            assert all(row["planned"] == row["scored"] == 16 and row["plannedPairs"] == 8
                       and row["plannedAbstentions"] == 8 for row in report["quality"])

        def test_eighteen_prior_records_and_all_original_bytes_preserved(self) -> None:
            before = subprocess.check_output(["git", "show", here(BASELINE) + ":./data/lab-register.json"], cwd=ROOT)
            current = (ROOT / "data/lab-register.json").read_bytes()
            previous = json.loads(before)["records"]
            assert len(previous) == 18 and json.loads(current)["records"][:18] == previous
            assert current.startswith(before[:-len(b"\n  ]\n}\n")])
            for record in previous:
                for artifact in record["artifacts"]:
                    path = artifact_path(ROOT, artifact["path"])
                    original = subprocess.check_output(["git", "show", here(BASELINE) + ":./" + path.relative_to(ROOT).as_posix()], cwd=ROOT)
                    assert path.read_bytes() == original

        def test_parseable_length_finish_is_not_strict_correctness(self) -> None:
            schema = {"type": "object", "required": ["x"], "properties": {"x": {"type": "integer"}}}
            assert expected_scores('{"x":3}', {"x": 3}, schema, "length") == {
                "formatValid": True, "schemaValid": True, "correct": False}

    class TestFailingCases:
        @pytest.mark.parametrize("row", range(8))
        def test_schema_validity_cannot_promote_any_quality_row(self, retained: tuple[dict[str, Any], Path], caplog: pytest.LogCaptureFixture, row: int) -> None:
            register, root = retained
            claim = next(c for c in register["records"][0]["claimResults"] if c.get("recordedField") == "/quality/" + str(row))
            claim["result"] = "pass"
            refused(register, root, caplog, "tool-argument scope, ownership or measured claims changed")

        @pytest.mark.parametrize("name", UNMEASURED)
        def test_outside_axis_cannot_borrow_scoped_publication(self, retained: tuple[dict[str, Any], Path], caplog: pytest.LogCaptureFixture, name: str) -> None:
            register, root = retained
            claim = next(c for c in register["records"][0]["claimResults"] if c["claim"] == name)
            claim.update(result="pass", recordedField="/publicationDecision", expectedValue="publish-scoped-report")
            refused(register, root, caplog, "tool-argument scope, ownership or measured claims changed")

        @pytest.mark.parametrize("name", list(HASHES))
        def test_truthful_reselected_digest_cannot_change_originals(self, retained: tuple[dict[str, Any], Path], caplog: pytest.LogCaptureFixture, name: str) -> None:
            register, root = retained
            path = artifact_path(root, PREFIX + name)
            raw = path.read_bytes() + b"\n"
            path.write_bytes(raw)
            next(a for a in register["records"][0]["artifacts"] if a["path"] == PREFIX + name)["sha256"] = digest(raw)
            refused(register, root, caplog, "tool-argument source-bound artifact selection changed")

        @pytest.mark.parametrize("field,value", [("readerRevision", "0" * 40),
            ("sourceRevision", "0" * 40), ("reviewState", "independently-accepted"),
            ("answerExposure", "blind"), ("evidenceClaim", "effect-authority")])
        def test_source_or_acceptance_cannot_be_promoted(self, retained: tuple[dict[str, Any], Path], caplog: pytest.LogCaptureFixture, field: str, value: Any) -> None:
            register, root = retained
            register["records"][0][field] = value
            refused(register, root, caplog, "tool-argument scope, ownership or measured claims changed")

        @pytest.mark.parametrize("field", ["independentEffectCustody", "independentOperation", "outsideRecurringUse"])
        def test_authored_custody_is_not_independence(self, retained: tuple[dict[str, Any], Path], caplog: pytest.LogCaptureFixture, field: str) -> None:
            register, root = retained
            register["records"][0]["roles"][field] = "established"
            refused(register, root, caplog, "tool-argument scope, ownership or measured claims changed")

        @pytest.mark.parametrize("mutation", ["omit", "reorder", "duplicate", "remove-start"])
        def test_complete_denominator_is_required(self, originals: tuple[dict[str, bytes], dict[str, Any], dict[str, Any], dict[str, Any]], mutation: str) -> None:
            members, report, protocol, _ = copy.deepcopy(originals)
            if mutation == "omit":
                report["attempts"].pop()
            elif mutation == "reorder":
                report["attempts"].reverse()
            elif mutation == "duplicate":
                report["attempts"][-1] = report["attempts"][0]
            else:
                del members["calls/" + report["attempts"][0]["id"] + "-started.json"]
            with pytest.raises(ValueError, match="tool-argument (complete native denominator|native started/returned population) changed"):
                verify_attempts(members, report, protocol)

        @pytest.mark.parametrize("field,value", [("correct", True), ("usage", {}),
            ("pair", "other"), ("targetAbstention", True), ("targetAbstention", 0),
            ("finishReason", "stop")])
        def test_semantics_and_resource_identity_rederived(self, originals: tuple[dict[str, bytes], dict[str, Any], dict[str, Any], dict[str, Any]], field: str, value: Any) -> None:
            members, report, protocol, _ = copy.deepcopy(originals)
            report["attempts"][0][field] = value
            with pytest.raises(ValueError, match="tool-argument (semantic scores|usage or resources|pair or abstention identity)"):
                verify_attempts(members, report, protocol)

        @pytest.mark.parametrize("mutation", ["duplicate-cell", "missing-cell", "duplicate-case", "missing-role"])
        def test_quality_requires_unique_cells_cases_and_pair_roles(
                self, originals: tuple[dict[str, bytes], dict[str, Any], dict[str, Any], dict[str, Any]],
                mutation: str) -> None:
            _, report, _, _ = copy.deepcopy(originals)
            if mutation == "duplicate-cell":
                report["quality"] = [report["quality"][0]] * 8
            elif mutation == "missing-cell":
                report["quality"].pop()
            elif mutation == "duplicate-case":
                same_cell = [r for r in report["attempts"] if r["model"] == "smol135-q4"
                             and r["configuration"] == "short24" and r["mode"] == "control"]
                same_cell[1]["originalIdentity"] = same_cell[0]["originalIdentity"]
            else:
                report["attempts"][0]["pairRole"] = "b"
            with pytest.raises(ValueError, match="tool-argument (complete distinct quality cell|unique quality case|complete quality pair roles) population changed|complete quality pair roles changed"):
                verify_quality(report)

        @pytest.mark.parametrize("field", ["elapsed_ns", "process_cpu_ns", "process_maxrss_kib"])
        def test_child_only_resource_claim_cannot_replace_whole_child(self, originals: tuple[dict[str, bytes], dict[str, Any], dict[str, Any], dict[str, Any]], field: str) -> None:
            members, report, _, _ = copy.deepcopy(originals)
            report["resources"][field] = strict_json(members["inference-terminal.json"])[field] - 1
            with pytest.raises(ValueError, match="whole-child resource boundary changed"):
                verify_terminal(members, report)

        def test_changed_source_file_refused_before_execution(self, originals: tuple[dict[str, bytes], dict[str, Any], dict[str, Any], dict[str, Any]]) -> None:
            members, _, protocol, contract = copy.deepcopy(originals)
            members["sources/native_runner.py"] += b"\n"
            with pytest.raises(ValueError, match="retained source differs"):
                verify_source_closure(members, protocol, contract)

        @pytest.mark.parametrize("raw", ['{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}', '{"x":1e999}'])
        def test_duplicate_or_nonfinite_response_never_scores(self, raw: str) -> None:
            assert expected_scores(raw, {"x": 1}, {"type": "object"}, "stop") == {
                "formatValid": False, "schemaValid": False, "correct": False}

        @given(value=st.integers(min_value=-10**8, max_value=10**8))
        def test_exact_numeric_arguments_do_not_accept_boolean_substitution(self, value: Any) -> None:
            schema = {"type": "object", "required": ["x"], "properties": {"x": {"type": "integer"}}}
            assert expected_scores(encode({"x": value}).decode(), {"x": value}, schema, "stop")["correct"]
            result = expected_scores('{"x":true}', {"x": value}, schema, "stop")
            assert result == {"formatValid": True, "schemaValid": False, "correct": False}

        @given(key=st.text(min_size=1, max_size=30))
        def test_duplicate_members_always_refused(self, key: str) -> None:
            encoded = json.dumps(key)
            with pytest.raises(ValueError, match="repeats a member"):
                strict_json("{" + encoded + ":0," + encoded + ":1}")
