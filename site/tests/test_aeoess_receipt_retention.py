"""Refuse changed outside-run semantics even after local digest rebinding."""

import hashlib
import importlib.util
import json
import shutil
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FOLDER = ROOT / "experiments/aeoess-receipt-signature-2026-10-05"
SPEC = importlib.util.spec_from_file_location("receipt_retention", FOLDER / "validate_capsule.py")
assert SPEC and SPEC.loader
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def content() -> dict[str, bytes]:
    """Get actual retained public sources."""
    return CHECKER.read_capsule(FOLDER)


def repin_record(files: dict[str, bytes]) -> None:
    """Let hostile tests cross the integrity layer to test semantic refusal."""
    original = files["record/SHA256SUMS.txt"].decode().splitlines()
    files["record/SHA256SUMS.txt"] = ("\n".join(
        hashlib.sha256(files["record/" + name]).hexdigest() + "  " + name
        for _, name in (line.split("  ") for line in original)
    ) + "\n").encode()


def test_actual_public_originals_and_outside_gaps() -> None:
    report = CHECKER.validate()
    assert report["originalRecordDigestBindings"] == 16
    assert report["outsideVerifier"]["executed"] == 25
    assert report["identifiers"]["outsideContextFreeIdentifiers"] == 21
    assert len(report["identifiers"]["outsideContextIdentifiersNotCovered"]) == 4
    assert report["controls"]["signatureMutationAffectedMembers"] == 5


@pytest.mark.parametrize("value", [b"NaN", b"Infinity", b"-Infinity", b"1e9999", b"-1e9999"])
def test_nonfinite_json_refuses(value: bytes) -> None:
    with pytest.raises(ValueError, match="nonfinite JSON"):
        CHECKER.load_json(b'{"value":' + value + b"}")


def test_finite_float_is_read_without_coercion() -> None:
    assert CHECKER.load_json(b'{"value":1.25}') == {"value": 1.25}


@pytest.mark.parametrize("fault", ["omit", "duplicate", "answer", "executed", "totals", "kind", "reason"])
def test_rebound_report_semantics_refuse(fault: str) -> None:
    files = content()
    report = json.loads(files["record/report1.json"])
    if fault == "omit":
        report["vectors"].pop()
    elif fault == "duplicate":
        report["vectors"][-1] = report["vectors"][0]
    elif fault == "answer":
        report["vectors"][0]["withoutWindows"] = "invalid signature_invalid"
    elif fault == "executed":
        report["vectors"][0]["verifierRan"] = False
    elif fault == "totals":
        report["totals"]["vectors"] = 24
    elif fault == "kind":
        report["vectors"][0]["kind"] = "gap"
    else:
        report["vectors"][0]["reasons"] = ["unresolved"]
    files["record/report1.json"] = files["record/report2.json"] = json.dumps(report).encode()
    repin_record(files)
    with pytest.raises(ValueError):
        CHECKER.derive(files)


@pytest.mark.parametrize("name,fault", [
    ("ctrl1.txt", "count"), ("ctrl1.txt", "answer"), ("ctrl1.txt", "omit"),
    ("ctrl2.txt", "answer"), ("ctrl2.txt", "shared"), ("ctrl2ok.txt", "answer"),
    ("run1.txt", "stdout"),
])
def test_rebound_control_or_stdout_refuses(name: str, fault: str) -> None:
    files = content()
    text = files["record/" + name].decode()
    if fault == "count":
        text = text.replace("14 pass", "15 pass")
    elif fault == "answer":
        text = text.replace("windows: valid; no windows: valid", "windows: bogus; no windows: bogus", 1)
    elif fault == "omit":
        text = "\n".join(line for line in text.splitlines() if not line.startswith("v0142580fad54af78"))
    elif fault == "shared":
        text = text.replace("v6d872b14889dc9e2", "v0000000000000000", 1)
    else:
        text = text.replace("windows: valid; no windows: valid", "windows: invalid; no windows: invalid", 1)
    files["record/" + name] = text.encode()
    if name == "run1.txt":
        files["record/run2.txt"] = text.encode()
    repin_record(files)
    with pytest.raises(ValueError):
        CHECKER.derive(files)


def test_context_identifier_cannot_be_counted_as_outside_recomputed() -> None:
    files = content()
    files["record/digests21.txt"] = files["record/digests21.txt"].replace(
        b"v6d872b14889dc9e2  NOT COVERED (has a context)", b"v6d872b14889dc9e2  MATCH")
    repin_record(files)
    with pytest.raises(ValueError, match="coverage changed"):
        CHECKER.derive(files)


def test_changed_canonical_context_refuses() -> None:
    files = content()
    manifest = json.loads(files["corpus/MANIFEST.json"])
    entry = next(row for row in manifest["vectors"] if row.get("context"))
    entry["context"]["commitmentLoggedAt"] = "2026-03-02T00:00:00Z"
    files["corpus/MANIFEST.json"] = json.dumps(manifest).encode()
    with pytest.raises(ValueError, match="identifier does not recompute"):
        CHECKER.derive(files)


def test_original_digest_set_cannot_omit_a_file() -> None:
    files = content()
    files["record/SHA256SUMS.txt"] = b"\n".join(files["record/SHA256SUMS.txt"].splitlines()[1:]) + b"\n"
    with pytest.raises(ValueError, match="omits a record"):
        CHECKER.derive(files)


def test_duplicate_json_names_refuse() -> None:
    with pytest.raises(ValueError, match="duplicate JSON name"):
        CHECKER.load_json(b'{"vectors":[],"vectors":[]}')


@pytest.mark.parametrize("name", ["../outside", "/outside", "corpus\\outside", "corpus//outside"])
def test_unsafe_member_refuses(name: str) -> None:
    with pytest.raises(ValueError):
        CHECKER.safe_member(name)


def test_changed_archive_bytes_refuse(tmp_path: Path) -> None:
    shutil.copytree(FOLDER, tmp_path / "record")
    archive = tmp_path / "record/selected-public-source.zip"
    archive.write_bytes(archive.read_bytes() + b"changed")
    with pytest.raises(ValueError):
        CHECKER.validate(tmp_path / "record")


def test_duplicate_archive_member_refuses_after_archive_repin(tmp_path: Path) -> None:
    shutil.copytree(FOLDER, tmp_path / "record")
    folder = tmp_path / "record"
    archive = folder / "selected-public-source.zip"
    with pytest.warns(UserWarning, match="Duplicate name"):
        with zipfile.ZipFile(archive, "a") as bundle:
            bundle.writestr("record/RUN.md", bundle.read("record/RUN.md"))
    manifest = json.loads((folder / "source-manifest.json").read_bytes())
    manifest["archiveBytes"] = archive.stat().st_size
    manifest["archiveSha256"] = hashlib.sha256(archive.read_bytes()).hexdigest()
    (folder / "source-manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="population changed"):
        CHECKER.validate(folder)
