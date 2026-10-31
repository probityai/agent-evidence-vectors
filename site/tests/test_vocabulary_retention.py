"""Hostile controls for source-bound native vocabulary and installed quality retention."""
from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from imported_commits import here
from tools.check_lab import artifact_path, validate_register
from tools.check_vocabulary_retention import (
    BASELINE, HASHES, IDENTITY, READER, RETENTION, SOURCE, claim_results, encode,
)

ROOT = Path(__file__).resolve().parents[1]
PREFIX = "../experiments/" + IDENTITY + "/"


def source_record() -> dict[str, Any]:
    """Select the retained profile; the factory also permits the raw-first checkpoint."""
    source = ROOT / "experiments" / IDENTITY
    provenance = json.loads((source / "provenance.json").read_bytes())
    report = json.loads((source / "report.json").read_bytes())
    return {
        "id": IDENTITY, "atlasRevision": BASELINE, "sourceRevision": SOURCE,
        "readerRevision": READER, "report": PREFIX + "report.json",
        "provenance": PREFIX + "provenance.json",
        "contract": "https://github.com/probityai/agent-evidence-observer/tree/" + READER + "/interop/local-model-vocabulary-2026-10-02",
        "reviewState": "author-retained-measured-record",
        "evidenceClaim": "authored-native-action-vocabulary-and-installed-quality-hold",
        "roles": provenance["roles"], "answerExposure": provenance["answerExposure"],
        "comparisonOrder": "Native inference follows frozen protocol, source-bound controls and protected merge; Atlas raw retention precedes indexing at " + RETENTION + ". Same-operator replay does not establish independent custody.",
        "limits": provenance["limits"],
        "artifacts": [{"path": PREFIX + name, "sha256": digest} for name, digest in HASHES.items()],
        "claimResults": claim_results(report),
    }


@pytest.fixture
def retained(tmp_path: Path) -> tuple[dict[str, Any], Path]:
    record = source_record()
    for artifact in record["artifacts"]:
        target = artifact_path(tmp_path, artifact["path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(artifact_path(ROOT, artifact["path"]), target)
    return {"protocolVersion": "0.1", "records": [record]}, tmp_path


def reselect(register: dict[str, Any], root: Path, name: str, raw: bytes) -> None:
    """Give the tampered bytes a truthful new outer digest, without changing trusted pins."""
    reference = PREFIX + name
    artifact_path(root, reference).write_bytes(raw)
    next(a for a in register["records"][0]["artifacts"] if a["path"] == reference)["sha256"] = hashlib.sha256(raw).hexdigest()


def test_original_packet_and_installed_hold(retained) -> None:
    register, root = retained
    validate_register(register, root)
    report = json.loads(artifact_path(root, PREFIX + "report.json").read_bytes())
    assert report["comparison"] == {
        "control": {"correct": 4, "planned": 64, "fullyCorrectPairs": 0, "plannedPairs": 32},
        "vocabulary": {"correct": 18, "planned": 64, "fullyCorrectPairs": 2, "plannedPairs": 32},
    }
    assert all(r["schemaValid"] == 16 for r in report["native"]["quality"])
    assert report["installed"]["consumerDecision"] == "hold-quality"
    assert report["installed"]["defaultQualityFailures"] == 8
    assert report["installed"]["reviewNativeInferenceCalls"] == 0


def test_seventeen_prior_literal_records_and_every_artifact_byte_preserved() -> None:
    before = subprocess.check_output(["git", "show", here(BASELINE) + ":./data/lab-register.json"], cwd=ROOT)
    previous = json.loads(before)["records"]
    current = json.loads((ROOT / "data/lab-register.json").read_bytes())["records"]
    assert len(previous) == 17 and current[:17] == previous
    # Existing tests also enforce the older sixteen-record textual prefix.
    for record in previous:
        for artifact in record["artifacts"]:
            path = artifact_path(ROOT, artifact["path"])
            original = subprocess.check_output(["git", "show", here(BASELINE) + ":./" + path.relative_to(ROOT).as_posix()], cwd=ROOT)
            assert path.read_bytes() == original


@pytest.mark.parametrize("row", range(8))
def test_every_quality_row_cannot_borrow_complete_schema_success(retained, row) -> None:
    register, root = retained
    claim = next(c for c in register["records"][0]["claimResults"] if c.get("recordedField") == "/native/quality/" + str(row))
    claim["result"] = "pass"
    with pytest.raises(ValueError, match="vocabulary measured or unexercised claims changed"):
        validate_register(register, root)


@pytest.mark.parametrize("name", [
    "outside-producer-acceptance", "external-host-recurring-adoption", "independent-effect-custody",
    "model-action-acceptance", "general-benchmark-performance", "independent-transfer-or-inference-witness",
])
def test_unmeasured_claim_cannot_bind_a_truthful_publication_result(retained, name) -> None:
    register, root = retained
    claim = next(c for c in register["records"][0]["claimResults"] if c["claim"] == name)
    claim.update(result="pass", recordedField="/native/publicationDecision", expectedValue="publish-scoped-report")
    with pytest.raises(ValueError, match="vocabulary measured or unexercised claims changed"):
        validate_register(register, root)


@pytest.mark.parametrize("name", list(HASHES))
def test_reselected_artifact_cannot_replace_frozen_primary_bytes(retained, name) -> None:
    register, root = retained
    raw = artifact_path(root, PREFIX + name).read_bytes()
    reselect(register, root, name, raw + b"\n")
    with pytest.raises(ValueError, match="vocabulary source-bound artifact selection changed"):
        validate_register(register, root)


@pytest.mark.parametrize("field,value", [
    ("sourceRevision", "0" * 40), ("readerRevision", "0" * 40),
    ("reviewState", "independently-accepted"), ("answerExposure", "blind"),
    ("evidenceClaim", "model-authority-established"),
])
def test_record_metadata_cannot_promote_source_or_acceptance(retained, field, value) -> None:
    register, root = retained
    register["records"][0][field] = value
    with pytest.raises(ValueError, match="vocabulary scope, ownership or source metadata changed"):
        validate_register(register, root)


@pytest.mark.parametrize("field", ["independentEffectCustody", "independentOperation", "outsideRecurringUse"])
def test_same_operator_custody_axes_remain_unestablished(retained, field) -> None:
    register, root = retained
    register["records"][0]["roles"][field] = "established"
    with pytest.raises(ValueError, match="vocabulary scope, ownership or source metadata changed"):
        validate_register(register, root)


def test_omitted_weights_and_environment_cannot_be_claimed_as_retained(retained) -> None:
    register, root = retained
    provenance = json.loads(artifact_path(root, PREFIX + "provenance.json").read_bytes())
    for key in ("fullPreparationMemberMapping", "installedMemberMapping"):
        omitted = next(m for m in provenance[key] if not m["retained"])
        omitted["retained"] = True
        omitted.pop("omission")
    reselect(register, root, "provenance.json", encode(provenance))
    with pytest.raises(ValueError, match="vocabulary source-bound artifact selection changed"):
        validate_register(register, root)


def test_reselected_semantic_report_and_claims_cannot_promote_scores(retained) -> None:
    register, root = retained
    report = json.loads(artifact_path(root, PREFIX + "report.json").read_bytes())
    report["comparison"]["vocabulary"]["correct"] = 64
    report["native"]["quality"][1]["correct"] = 16
    report["installed"]["consumerDecision"] = "admit-scoped-quality"
    register["records"][0]["claimResults"] = claim_results(report)
    reselect(register, root, "report.json", encode(report))
    with pytest.raises(ValueError, match="vocabulary source-bound artifact selection changed"):
        validate_register(register, root)


def test_missing_quality_row_claim_is_not_complete_population(retained) -> None:
    register, root = retained
    register["records"][0]["claimResults"] = [c for c in register["records"][0]["claimResults"] if c.get("recordedField") != "/native/quality/7"]
    with pytest.raises(ValueError, match="vocabulary measured or unexercised claims changed"):
        validate_register(register, root)
