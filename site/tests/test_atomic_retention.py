"""Hostile controls and baseline preservation for the actual Atomic record."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from tools.check_lab import artifact_path, validate_register
from imported_commits import here

ROOT = Path(__file__).resolve().parents[1]
IDENTITY = "atomic-delegation-2026-10-02"
BASELINE = "34a9f73c80f4909b032f1f42c4cb7663fd61123e"


@pytest.fixture
def selected(tmp_path: Path) -> tuple[dict, Path]:
    original = json.loads((ROOT / "data/lab-register.json").read_text())
    record = copy.deepcopy(next(r for r in original["records"] if r["id"] == IDENTITY))
    for item in record["artifacts"]:
        destination = artifact_path(tmp_path, item["path"])
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(artifact_path(ROOT, item["path"]), destination)
    return {"protocolVersion": "0.1", "records": [record]}, tmp_path


def reselect(record: dict, root: Path, reference: str) -> None:
    for item in record["artifacts"]:
        if item["path"] == reference:
            item["sha256"] = hashlib.sha256(artifact_path(root, reference).read_bytes()).hexdigest()


def test_actual_complete_native_capsule_passes(selected: tuple[dict, Path]) -> None:
    register, root = selected
    validate_register(register, root)


def test_changed_native_case_cannot_keep_its_pass(selected: tuple[dict, Path]) -> None:
    register, root = selected
    record = register["records"][0]
    path = artifact_path(root, record["report"])
    report = json.loads(path.read_text())
    report["results"][0]["passed"] = False
    path.write_text(json.dumps(report))
    reselect(record, root, record["report"])
    with pytest.raises(ValueError, match="measured claim differs from the retained report"):
        validate_register(register, root)


def test_reselected_report_and_claim_cannot_replace_original(selected: tuple[dict, Path]) -> None:
    register, root = selected
    record = register["records"][0]
    path = artifact_path(root, record["report"])
    report = json.loads(path.read_text())
    report["results"][0]["wall_seconds"] += 1
    path.write_text(json.dumps(report))
    record["claimResults"][1]["expectedValue"] = copy.deepcopy(report["results"][0])
    reselect(record, root, record["report"])
    with pytest.raises(ValueError, match="Atomic report differs from the original native report"):
        validate_register(register, root)


def test_reselected_capsule_cannot_replace_original(selected: tuple[dict, Path]) -> None:
    register, root = selected
    record = register["records"][0]
    reference = next(a["path"] for a in record["artifacts"] if a["path"].endswith(".zip"))
    path = artifact_path(root, reference)
    path.write_bytes(path.read_bytes() + b"changed packaging")
    reselect(record, root, reference)
    with pytest.raises(ValueError, match="Atomic original capsule differs from its immutable retention pin"):
        validate_register(register, root)


def test_incomplete_member_provenance_is_refused(selected: tuple[dict, Path]) -> None:
    register, root = selected
    record = register["records"][0]
    path = artifact_path(root, record["provenance"])
    provenance = json.loads(path.read_text())
    provenance["members"].pop()
    path.write_text(json.dumps(provenance))
    reselect(record, root, record["provenance"])
    with pytest.raises(ValueError, match="Atomic capsule inventory is incomplete or repeated"):
        validate_register(register, root)


@pytest.mark.parametrize("axis", ["independentOperation", "independentEffectCustody", "outsideRecurringUse"])
def test_local_operation_cannot_be_promoted(selected: tuple[dict, Path], axis: str) -> None:
    register, root = selected
    register["records"][0]["roles"][axis] = "established"
    with pytest.raises(ValueError, match="Atomic local-operation claim ceiling changed"):
        validate_register(register, root)


def test_unmeasured_server_boundary_cannot_disappear(selected: tuple[dict, Path]) -> None:
    register, root = selected
    record = register["records"][0]
    record["claimResults"] = [c for c in record["claimResults"] if c["claim"] != "server-permission-enforcement"]
    with pytest.raises(ValueError, match="Atomic unmeasured boundary was promoted or removed"):
        validate_register(register, root)


def test_all_fifteen_baseline_records_and_artifact_bytes_are_preserved() -> None:
    baseline = json.loads(subprocess.check_output(
        ["git", "show", here(BASELINE) + ":./data/lab-register.json"], cwd=ROOT))
    current = json.loads((ROOT / "data/lab-register.json").read_text())
    assert len(baseline["records"]) == 15
    assert current["records"][:15] == baseline["records"]
    for record in baseline["records"]:
        for item in record["artifacts"]:
            path = artifact_path(ROOT, item["path"])
            original = subprocess.check_output(
                ["git", "show", here(BASELINE) + ":./" + path.relative_to(ROOT).as_posix()], cwd=ROOT)
            assert path.read_bytes() == original
