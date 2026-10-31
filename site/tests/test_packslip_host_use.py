"""A forged summary cannot replace the frozen public host observations."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "experiments/packslip-dsse-host-ci-2026-10-11"


def reader():
    spec = importlib.util.spec_from_file_location("packslip_host_use", PACKET / "validate_capsule.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def copied(tmp_path):
    path = tmp_path / "packet"
    shutil.copytree(PACKET, path)
    return path


def test_original_sources_derive_exact_report_with_native_exit_unknown():
    module = reader()
    module.validate(PACKET)
    report = module.derive(PACKET)
    assert report["hostCI"]["numericNativeExit"] is None
    assert report["hostCI"]["cargoTestAllFeatures"]["conclusion"] == "success"
    assert report["publishedDependency"]["kind"] == "dev"
    assert report["contribution"]["author"] == "astrogilda"


@pytest.mark.parametrize("field, value", [
    ("numericNativeExit", 0), ("jobConclusion", "failure"), ("source", "0" * 40),
])
def test_report_substitution_refused_even_with_valid_json(tmp_path, field, value):
    path = copied(tmp_path)
    report = json.loads((path / "report.json").read_text())
    report["hostCI"][field] = value
    (path / "report.json").write_text(json.dumps(report))
    with pytest.raises(ValueError, match="report differs"):
        reader().validate(path)


@pytest.mark.parametrize("file, mutate", [
    ("raw/host-job.json", lambda d: d.update(head_sha="0" * 40)),
    ("raw/contribution-pr.json", lambda d: d["user"].update(login="jdx")),
    ("raw/reverse-dependencies.json", lambda d: next(x for x in d["dependencies"] if x["crate_id"] == "dsse").update(kind="normal")),
])
def test_source_substitution_refused_after_provenance_hash_is_repinned(tmp_path, file, mutate):
    path = copied(tmp_path)
    data = json.loads((path / file).read_text())
    mutate(data)
    raw = json.dumps(data).encode()
    (path / file).write_bytes(raw)
    provenance = json.loads((path / "provenance.json").read_text())
    next(row for row in provenance["sources"] if row["path"] == file)["sha256"] = hashlib.sha256(raw).hexdigest()
    (path / "provenance.json").write_text(json.dumps(provenance))
    with pytest.raises(ValueError, match="retained public source differs"):
        reader().validate(path)


@pytest.mark.parametrize("field, value, message", [
    ("captureTime", "2030-01-01T00:00:00Z", "capture identity"),
    ("numericNativeExit", 0, "native output availability"),
    ("rawNativeOutputRetained", True, "native output availability"),
])
def test_capture_cannot_invent_time_or_native_output(tmp_path, field, value, message):
    path = copied(tmp_path)
    data = json.loads((path / "provenance.json").read_text())
    data[field] = value
    (path / "provenance.json").write_text(json.dumps(data))
    with pytest.raises(ValueError, match=message):
        reader().validate(path)


def test_source_url_substitution_is_refused(tmp_path):
    path = copied(tmp_path)
    data = json.loads((path / "provenance.json").read_text())
    data["sources"][0]["url"] = "https://example.org/unrelated"
    (path / "provenance.json").write_text(json.dumps(data))
    with pytest.raises(ValueError, match="provenance source pins"):
        reader().validate(path)
