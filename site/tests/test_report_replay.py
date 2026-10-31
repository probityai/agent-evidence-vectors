"""Exercise actual retained originals and independently reselected corruptions."""
from __future__ import annotations
import copy
import hashlib
import json
import shutil
from pathlib import Path
import pytest
from tools.check_lab import validate_register
from tools.check_report_replay import IDENTITY, derive, check_selected_report_replay
from imported_commits import here

ROOT = Path(__file__).resolve().parents[1]


def selected():
    return copy.deepcopy(next(row for row in json.loads((ROOT / "data/lab-register.json").read_text())["records"] if row["id"] == IDENTITY))


def test_original_full_accounting():
    report = derive(ROOT)
    assert report["historical"]["harnessPassingComparisons"] == 272
    assert report["historical"]["reportStates"] == {"pass": 31, "fail": 239, "inconclusive": 2}
    assert [row["changedRejects"] for row in report["diagnostic"]] == [1, 2]
    assert [row["unchangedAccepts"] for row in report["diagnostic"]] == [116, 116]
    validate_register({"protocolVersion": "0.1", "records": [selected()]}, ROOT)


@pytest.mark.parametrize("filename", ["original-report.json", "original-conformance-report.json", "per-case-outcomes.json", "negative-witness-state.per-case.json", "checker-and-configuration.per-case.json", "negative-witness-state.mutant.py", "checker-and-configuration.mutant.py"])
def test_reselected_original_bytes_refused(tmp_path, filename):
    directory = tmp_path / "experiments" / IDENTITY
    shutil.copytree(ROOT / "experiments" / IDENTITY, directory)
    target = directory / filename
    target.write_bytes(target.read_bytes() + b" ")
    record = selected()
    for artifact in record["artifacts"]:
        if artifact["path"].endswith("/" + filename):
            artifact["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="source bytes changed"):
        validate_register({"protocolVersion": "0.1", "records": [record]}, tmp_path)


@pytest.mark.parametrize("field,value", [("roles", {"independentOperator": "verified"}), ("answerExposure", "blind"), ("comparisonOrder", "blind raw first"), ("reviewState", "independent-reviewed"), ("evidenceClaim", "production-refund-complete"), ("sourceRevision", "0" * 40), ("readerRevision", "0" * 40)])
def test_role_source_scope_promotion_refused(field, value):
    record = selected()
    record[field] = value
    with pytest.raises(ValueError):
        check_selected_report_replay({"records": [record]}, ROOT)


@pytest.mark.parametrize("name", ["real-workload-action-completion", "independent-operation", "outside-maintained-host-adoption", "current-vectors-reader-replay"])
def test_unexercised_claim_cannot_be_promoted(name):
    record = selected()
    claim = next(claim for claim in record["claimResults"] if claim["claim"] == name)
    claim.update(result="pass", recordedField="/historical/harnessPassingComparisons", expectedValue=272)
    with pytest.raises(ValueError, match="claims changed"):
        check_selected_report_replay({"records": [record]}, ROOT)


def test_reselected_manifest_base_refused(tmp_path):
    directory = tmp_path / "experiments" / IDENTITY
    shutil.copytree(ROOT / "experiments" / IDENTITY, directory)
    target = directory / "source-manifest.json"
    manifest = json.loads(target.read_text());manifest["base_directory"] = "../"
    target.write_text(json.dumps(manifest))
    record = selected()
    for artifact in record["artifacts"]:
        if artifact["path"].endswith("/source-manifest.json"):
            artifact["sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
    with pytest.raises(ValueError, match="source manifest changed"):
        validate_register({"protocolVersion": "0.1", "records": [record]}, tmp_path)


def test_preceding_register_objects_exact():
    import subprocess
    original = json.loads(subprocess.run(["git", "show", here("0f5d25ab4cb00337f332eb109ac0dbc8b5651e00") + ":./data/lab-register.json"], cwd=ROOT, capture_output=True, check=True).stdout)
    current = json.loads((ROOT / "data/lab-register.json").read_text())
    assert len(original["records"]) == 25
    assert current["records"][:25] == original["records"]
    assert current["records"][25]["id"] == IDENTITY
    before = subprocess.run(["git", "show", here("0f5d25ab4cb00337f332eb109ac0dbc8b5651e00") + ":./data/lab-register.json"], cwd=ROOT, capture_output=True, check=True).stdout
    ending = b"\n  ]\n}\n"
    assert before.endswith(ending)
    assert (ROOT / "data/lab-register.json").read_bytes().startswith(before[:-len(ending)] + b",\n")
