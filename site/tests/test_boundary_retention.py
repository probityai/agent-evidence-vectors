"""Adversarial selected-boundary retention and original-byte research checks."""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings, strategies as st

from tools.check_boundary_retention import IDENTITY, REPORT_SHA256, validate_boundary_retention
from tools.check_lab import artifact_path, validate_register
from tools.derive_boundary_findings import derive_findings, encode
from imported_commits import here

ROOT = Path(__file__).resolve().parents[1]
BASELINE = "422a7241f8351f167fe407fe2bfe9aab5f079a6d"


def row_dimensions(row: dict[str, Any]) -> tuple[str, ...]:
    """Select unpooled dimensions for order-independent diagnostic comparisons."""
    return tuple(row[field] for field in ("model", "configuration", "decoder", "family"))


def originals() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Read pristine selected indexing and frozen original report/protocol bytes."""
    register = json.loads((ROOT / "data/lab-register.json").read_bytes())
    record = next(record for record in register["records"] if record["id"] == IDENTITY)
    report = json.loads(artifact_path(ROOT, record["report"]).read_bytes())
    provenance = json.loads(artifact_path(ROOT, record["provenance"]).read_bytes())
    with zipfile.ZipFile(ROOT / "experiments" / IDENTITY / "original-artifact.zip") as bundle:
        protocol = json.loads(bundle.read("protocol.json"))
    return record, report, provenance, protocol


def refuse_semantic(record: dict[str, Any], report: dict[str, Any], provenance: dict[str, Any],
                    reason: str, caplog: pytest.LogCaptureFixture) -> None:
    """Require both the exact semantic refusal and its bounded log message."""
    with caplog.at_level(logging.ERROR, logger="atlas.boundary_retention"):
        with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"):
            validate_boundary_retention(record, report, provenance)
    assert caplog.messages == ["boundary retention refused: " + reason]


@pytest.fixture
def selected_register(tmp_path: Path) -> tuple[dict[str, Any], Path]:
    """Copy only selected artifacts; each attack stays isolated from originals."""
    record, _, _, _ = originals()
    for artifact in record["artifacts"]:
        source = artifact_path(ROOT, artifact["path"])
        target = artifact_path(tmp_path, artifact["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return {"protocolVersion": "0.1", "records": [record]}, tmp_path


def reselect(record: dict[str, Any], root: Path, field: str, document: Any) -> None:
    """Reselect a changed artifact SHA to exercise checks beyond generic hashing."""
    reference = record[field]
    raw = encode(document)
    artifact_path(root, reference).write_bytes(raw)
    next(artifact for artifact in record["artifacts"] if artifact["path"] == reference)["sha256"] = (
        hashlib.sha256(raw).hexdigest())


def refuse_register(register: dict[str, Any], root: Path, reason: str,
                    caplog: pytest.LogCaptureFixture) -> None:
    """Require exact source/retention refusal after legitimate digest reselection."""
    with caplog.at_level(logging.ERROR, logger="atlas.lab_register"):
        with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"):
            validate_register(register, root)
    assert caplog.messages == ["lab register refused: " + reason]


class TestBoundaryRetention:
    class TestPassingCases:
        def test_original_24_rows_and_384_attempts_admitted(self) -> None:
            record, report, provenance, _ = originals()
            validate_boundary_retention(record, report, provenance)
            assert len(report["quality"]) == 24
            assert len(report["attempts"]) == 384
            assert sum(row["schemaValid"] for row in report["quality"] if row["decoder"] == "schema") == 192
            assert all(row["fullyCorrectPairs"] == 0 for row in report["quality"]
                       if row["family"] in {"policy-boundary", "grounded-boundary"})

        def test_selected_real_register_passes(self, selected_register: tuple[dict[str, Any], Path]) -> None:
            register, root = selected_register
            validate_register(register, root)

        def test_all_fourteen_original_records_and_artifacts_preserved(self) -> None:
            before = json.loads(subprocess.check_output(
                ["git", "show", here(BASELINE) + ":./data/lab-register.json"], cwd=ROOT))
            after = json.loads((ROOT / "data/lab-register.json").read_bytes())
            assert len(before["records"]) == 14
            assert after["records"][:14] == before["records"]
            for record in before["records"]:
                for artifact in record["artifacts"]:
                    path = artifact_path(ROOT, artifact["path"])
                    previous = subprocess.check_output(
                        ["git", "show", here(BASELINE) + ":./" + path.relative_to(ROOT).as_posix()], cwd=ROOT)
                    assert path.read_bytes() == previous

    class TestFailingCases:
        @pytest.mark.parametrize("row_index", [0, 1, 2, 3, 4, 5, 12, 23])
        def test_missing_or_pooled_row_refused(self, row_index: int,
                                              caplog: pytest.LogCaptureFixture) -> None:
            record, report, provenance, _ = originals()
            report["quality"].pop(row_index)
            refuse_semantic(record, report, provenance,
                            "boundary retention must preserve all24 separate rows", caplog)

        @pytest.mark.parametrize("mutation", ["missing", "duplicate"])
        def test_missing_or_duplicate_semantic_binding_refused(
                self, mutation: str, caplog: pytest.LogCaptureFixture) -> None:
            record, report, provenance, _ = originals()
            claims = record["claimResults"]
            selected = next(claim for claim in claims if claim.get("recordedField") == "/quality/4")
            if mutation == "missing":
                claims.remove(selected)
            else:
                next(claim for claim in claims if claim.get("recordedField") == "/quality/5")["recordedField"] = "/quality/4"
            refuse_semantic(record, report, provenance,
                            "boundary retention requires24 unique row bindings", caplog)

        @pytest.mark.parametrize("row_index", [4, 5, 10, 11, 15, 16, 17, 21, 22, 23])
        def test_schema_or_partial_cases_cannot_promote_semantic_failure(
                self, row_index: int, caplog: pytest.LogCaptureFixture) -> None:
            record, report, provenance, _ = originals()
            next(claim for claim in record["claimResults"]
                 if claim.get("recordedField") == f"/quality/{row_index}")["result"] = "pass"
            refuse_semantic(record, report, provenance,
                            "boundary schema validity cannot promote semantic case or pair failure", caplog)

        @pytest.mark.parametrize("field,value,reason", [
            ("planned", True, "boundary selected row population changed"),
            ("correct", True, "boundary selected quality count must be a bounded integer"),
            ("schemaValid", 17, "boundary selected quality count must be a bounded integer"),
            ("fullyCorrectPairs", False, "boundary selected pair count must be a bounded integer"),
            ("fullyCorrectPairs", 9, "boundary selected pair count must be a bounded integer"),
            ("resourceScope", "per-model allocated RAM", "boundary shared resource scope changed"),
        ])
        def test_typed_population_counts_and_resource_scopes_refused(
                self, field: str, value: Any, reason: str, caplog: pytest.LogCaptureFixture) -> None:
            record, report, provenance, _ = originals()
            report["quality"][0][field] = value
            next(claim for claim in record["claimResults"]
                 if claim.get("recordedField") == "/quality/0")["expectedValue"] = copy.deepcopy(report["quality"][0])
            refuse_semantic(record, report, provenance, reason, caplog)

        @pytest.mark.parametrize("field,reason", [
            ("correct", "boundary row count differs from retained attempts"),
            ("fullyCorrectPairs", "boundary pair count differs from retained attempts"),
            ("callElapsedNs", "boundary row resource differs from retained attempts"),
            ("processCpuNs", "boundary row resource differs from retained attempts"),
            ("promptTokens", "boundary row resource differs from retained attempts"),
            ("completionTokens", "boundary row resource differs from retained attempts"),
            ("processLifetimePeakRssKiB", "boundary RSS must remain a shared lifetime maximum"),
        ])
        def test_reselected_row_disagrees_with_original_attempts(
                self, field: str, reason: str, caplog: pytest.LogCaptureFixture) -> None:
            record, report, provenance, _ = originals()
            report["quality"][0][field] += 1
            next(claim for claim in record["claimResults"]
                 if claim.get("recordedField") == "/quality/0")["expectedValue"] = copy.deepcopy(report["quality"][0])
            refuse_semantic(record, report, provenance, reason, caplog)

        @pytest.mark.parametrize("axis", ["independentOperation", "independentEffectCustody", "outsideRecurringUse"])
        def test_coordinated_role_promotion_refused(self, axis: str,
                                                  caplog: pytest.LogCaptureFixture) -> None:
            record, report, provenance, _ = originals()
            provenance["roles"][axis] = record["roles"][axis] = "established"
            refuse_semantic(record, report, provenance,
                            "boundary retention cannot invent operation adoption or custody", caplog)

        @pytest.mark.parametrize("mutation,reason", [
            ("member-count", "boundary full preparation member population changed"),
            ("omission", "boundary full preparation omissions hidden"),
            ("mapping", "boundary compact mapping rebinds native bytes"),
            ("invented", "boundary omission carries invented compact mapping"),
            ("full-sha", "boundary complete original archive rebound"),
            ("omitted-hash", "boundary authenticated full-member inventory rebound"),
            ("history", "boundary five preparation envelopes cannot be reported as one"),
            ("cpu", "boundary total process CPU cannot be replaced by call CPU"),
        ])
        def test_complete_original_history_and_mapping_mutants_refused(
                self, mutation: str, reason: str, caplog: pytest.LogCaptureFixture) -> None:
            record, report, provenance, _ = originals()
            full = provenance["fullPreparationMembers"]
            mutations = {
                "member-count": full.pop,
                "omission": lambda: provenance["fullPreparationArchive"].update(omittedPreparationMembers=29),
                "mapping": lambda: next(member for member in full if member["retainedInCompact"]).update(sha256="0" * 64),
                "invented": lambda: next(member for member in full if not member["retainedInCompact"]).update(compactMember="protocol.json"),
                "full-sha": lambda: provenance["fullPreparationArchive"].update(sha256="0" * 64),
                "omitted-hash": lambda: next(member for member in full if not member["retainedInCompact"]).update(sha256="0" * 64),
                "history": lambda: provenance["preparationHistory"].update(allFiveAttemptsBodyBytes=472221945),
                "cpu": lambda: report.update(process_cpu_ns=sum(row["processCpuNs"] for row in report["quality"]) - 1),
            }
            mutations[mutation]()
            refuse_semantic(record, report, provenance, reason, caplog)

        def test_reselected_false_finding_refused(self, selected_register: tuple[dict[str, Any], Path],
                                                caplog: pytest.LogCaptureFixture) -> None:
            register, root = selected_register
            record = register["records"][0]
            findings = json.loads(artifact_path(root, record["derivedFindings"]).read_bytes())
            findings["capComparisons"][1]["identicalOutputText"] = 95
            reselect(record, root, "derivedFindings", findings)
            refuse_register(register, root, "boundary finite findings differ from original-byte rederivation", caplog)

        def test_reselected_native_report_refused(self, selected_register: tuple[dict[str, Any], Path],
                                                caplog: pytest.LogCaptureFixture) -> None:
            register, root = selected_register
            record = register["records"][0]
            report = json.loads(artifact_path(root, record["report"]).read_bytes())
            report["attempts"][0]["output"] += " "
            reselect(record, root, "report", report)
            refuse_register(register, root, "boundary original native report rebound", caplog)

        @pytest.mark.parametrize("name", ["independent-effect-custody", "outside-recurring-host-use",
                                         "representative-benchmark-performance"])
        def test_unexercised_claim_cannot_borrow_truthful_unrelated_report_value(
                self, selected_register: tuple[dict[str, Any], Path], name: str,
                caplog: pytest.LogCaptureFixture) -> None:
            register, root = selected_register
            claim = next(claim for claim in register["records"][0]["claimResults"] if claim["claim"] == name)
            claim.update(result="pass", recordedField="/effects", expectedValue="not executed")
            reason = "boundary unexercised claim cannot borrow unrelated measured evidence"
            with caplog.at_level(logging.ERROR):
                with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"):
                    validate_register(register, root)
            assert caplog.messages == ["boundary retention refused: " + reason,
                                       "lab register refused: " + reason]

        @pytest.mark.parametrize("mutation,reason", [
            ("reviewed-reader", "boundary source revisions rebound"),
            ("reviewed-head", "boundary source revisions rebound"),
            ("merged-head", "boundary source revisions rebound"),
            ("new-inference", "boundary original retention cannot claim new inference"),
            ("private-custody", "boundary private complete retention cannot invent custody or holder"),
            ("private-holder", "boundary private complete retention cannot invent custody or holder"),
        ])
        def test_actual_provenance_reselection_cannot_rewrite_review_or_custody(
                self, selected_register: tuple[dict[str, Any], Path], mutation: str,
                reason: str, caplog: pytest.LogCaptureFixture) -> None:
            register, root = selected_register
            record = register["records"][0]
            provenance = json.loads(artifact_path(root, record["provenance"]).read_bytes())
            mutations = {
                "reviewed-reader": lambda: (record.update(readerRevision="0" * 40),
                                            provenance.update(readerCommit="0" * 40)),
                "reviewed-head": lambda: provenance.update(reviewedHead="0" * 40),
                "merged-head": lambda: provenance.update(mergedHead="0" * 40),
                "new-inference": lambda: provenance.update(newInferenceExecuted=True),
                "private-custody": lambda: provenance["fullPreparationArchive"].update(independentCustody="established"),
                "private-holder": lambda: provenance["fullPreparationArchive"].update(privateRetentionHolder="outside operator"),
            }
            mutations[mutation]()
            reselect(record, root, "provenance", provenance)
            with caplog.at_level(logging.ERROR):
                with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"):
                    validate_register(register, root)
            assert caplog.messages == ["boundary retention refused: " + reason,
                                       "lab register refused: " + reason]

        @settings(deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
        @given(st.sampled_from(["error", "incomplete", "unknown-start", "unsupported"]),
               st.integers(min_value=1, max_value=384))
        def test_absent_or_failed_outcome_cannot_drop_from_original_denominator(
                self, caplog: pytest.LogCaptureFixture, outcome: str, count: int) -> None:
            record, report, provenance, _ = originals()
            report["population"][outcome] = count
            caplog.clear()
            refuse_semantic(record, report, provenance, "boundary original population changed", caplog)


class TestDeriveFindings:
    class TestPassingCases:
        def test_all_original_pairs_and_rows_rederive(self) -> None:
            _, report, _, protocol = originals()
            findings = derive_findings(report, protocol, REPORT_SHA256)
            assert len(findings["qualityRowsUnpooled"]) == 24
            assert sum(len(row["pairs"]) for row in findings["pairRows"]) == 192
            assert findings["authoredCaseIdentities"] == 48
            assert findings["uniqueLiteralInputs"] == 46
            assert findings["capComparisons"][1]["identicalOutputText"] == 96
            assert len(findings["allConstrainedTypedFailures"]) == 6
            assert [(row["outsideFrozenActionVocabulary"], row["inVocabularyButWrong"],
                     row["publishedStrictCorrect"]) for row in findings["policyVocabularyDiagnostic"]] == [
                         (16, 0, 0), (16, 0, 0), (9, 5, 2), (9, 5, 2)]
            assert encode(findings) == (ROOT / "experiments" / IDENTITY / "finite-findings.json").read_bytes()

        @settings(deadline=None)
        @given(st.permutations(tuple(range(24))))
        def test_reordering_rows_preserves_dimensional_pair_measurements(self, order: tuple[int, ...]) -> None:
            _, report, _, protocol = originals()
            original = derive_findings(report, protocol, REPORT_SHA256)
            report["quality"] = [report["quality"][index] for index in order]
            reordered = derive_findings(report, protocol, REPORT_SHA256)
            assert sorted(original["pairRows"], key=row_dimensions) == sorted(reordered["pairRows"], key=row_dimensions)
            assert original["capComparisons"] == reordered["capComparisons"]
            assert original["policyVocabularyDiagnostic"] == reordered["policyVocabularyDiagnostic"]

    class TestFailingCases:
        def test_wrong_semantic_pair_is_visible_despite_valid_schema(self) -> None:
            _, report, _, protocol = originals()
            result = derive_findings(report, protocol, REPORT_SHA256)
            selected = [row for row in result["pairRows"]
                        if row["decoder"] == "schema" and row["family"] == "policy-boundary"]
            assert all(not pair["bothStrictlyCorrect"] for row in selected for pair in row["pairs"])
            assert all(attempt["schemaValid"] for row in selected for pair in row["pairs"]
                       for attempt in pair["attempts"])
