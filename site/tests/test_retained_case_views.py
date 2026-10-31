"""Original public output cannot be replaced by an edited summary or repinned source."""
import hashlib
import ast
import importlib.util
import json
from pathlib import Path
import shutil
from collections import Counter

import pytest

ROOT = Path(__file__).resolve().parents[1]
IDENTITIES = ["horizon-signed-target-reader-2026-10-09", "ten-sdk-json-bytes-2026-10-09",
              "nist-ai300-1-checker-2026-10-13", "signed-history-boundaries-2026-10-13",
              "ratchet-benign-heredoc-2026-10-15"]

@pytest.mark.parametrize("expression", ["__import__('os').getcwd()", "'x' * 100000"])
def test_captured_fixture_reader_refuses_code_execution_and_unbounded_expansion(expression):
    module, packet = reader(IDENTITIES[4])
    with pytest.raises(ValueError, match="bounded literal"):
        module._case_literal(ast.parse(expression, mode="eval").body)

def reader(identity):
    packet = ROOT / "experiments" / identity
    spec = importlib.util.spec_from_file_location("retained_" + identity.replace("-", "_"), packet / "validate_capsule.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, packet

def copy_packet(identity, tmp_path):
    module, packet = reader(identity)
    copied = tmp_path / identity
    shutil.copytree(packet, copied)
    return module, copied

@pytest.mark.parametrize("identity", IDENTITIES)
def test_original_body_population_derives_the_complete_report(identity):
    module, packet = reader(identity)
    module.validate(packet)
    assert module.derive(packet)["question"]
    assert "runs.html#record-" + identity in (packet / "README.md").read_text()

def test_real_register_keeps_raw_case_outcomes_and_operation_limits():
    data = json.loads((ROOT / "data/lab-register.json").read_text())
    selected = [record for record in data["records"] if record["id"] in IDENTITIES]
    assert len(data["records"]) == 34 and len(selected) == 5
    counts = Counter(claim["result"] for record in selected for claim in record["claimResults"])
    assert counts == {"pass": 15, "fail": 1, "not-exercised": 14}
    assert all(record["roles"]["independentOperation"] == "not-established" for record in selected)
    assert sum(len(record["claimResults"]) for record in data["records"]) == 509

@pytest.mark.parametrize("identity", IDENTITIES)
def test_report_substitution_is_refused(identity, tmp_path):
    module, packet = copy_packet(identity, tmp_path)
    report = json.loads((packet / "report.json").read_text())
    report["question"] = "A different question with no original output"
    (packet / "report.json").write_text(json.dumps(report))
    with pytest.raises(ValueError, match="report differs"):
        module.validate(packet)

@pytest.mark.parametrize("identity", IDENTITIES)
def test_source_substitution_cannot_be_laundered_by_repinning_provenance(identity, tmp_path):
    module, packet = copy_packet(identity, tmp_path)
    provenance = json.loads((packet / "provenance.json").read_text())
    first = provenance["sources"][0]
    raw = b"\n" + (packet / first["path"]).read_bytes()
    (packet / first["path"]).write_bytes(raw)
    first.update(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    (packet / "provenance.json").write_text(json.dumps(provenance))
    with pytest.raises(ValueError, match="retained public source differs"):
        module.validate(packet)

@pytest.mark.parametrize("identity", IDENTITIES)
def test_missing_original_body_is_refused(identity, tmp_path):
    module, packet = copy_packet(identity, tmp_path)
    source = module.PROVENANCE["sources"][0]["path"]
    (packet / source).unlink()
    with pytest.raises(FileNotFoundError):
        module.validate(packet)

@pytest.mark.parametrize("identity", IDENTITIES)
def test_host_metadata_cannot_invent_numeric_native_exit(identity, tmp_path):
    module, packet = copy_packet(identity, tmp_path)
    report = json.loads((packet / "report.json").read_text())
    target = report.get("nativeLog", report.get("hostCI", report))
    assert target["numericNativeExit"] is None
    target["numericNativeExit"] = 0
    (packet / "report.json").write_text(json.dumps(report))
    with pytest.raises(ValueError, match="report differs"):
        module.validate(packet)

@pytest.mark.parametrize("identity", IDENTITIES)
def test_provenance_cannot_change_source_identity(identity, tmp_path):
    module, packet = copy_packet(identity, tmp_path)
    provenance = json.loads((packet / "provenance.json").read_text())
    provenance["sourceCommit"] = "0" * 40
    (packet / "provenance.json").write_text(json.dumps(provenance))
    with pytest.raises(ValueError, match="source provenance differs"):
        module.validate(packet)

@pytest.mark.parametrize("identity", IDENTITIES)
def test_duplicate_report_keys_are_refused(identity, tmp_path):
    module, packet = copy_packet(identity, tmp_path)
    original = (packet / "report.json").read_text().lstrip()
    (packet / "report.json").write_text('{"question":"substituted",' + original[1:])
    with pytest.raises(ValueError, match="duplicate JSON key"):
        module.validate(packet)

@pytest.mark.parametrize("identity, path", [
    (IDENTITIES[0], ["pairA", "signatureVerified"]),
    (IDENTITIES[1], ["workflowReportsDifferencesByDefault"]),
    (IDENTITIES[2], ["nativeLog", "unitTestsPassed"]),
    (IDENTITIES[3], ["sourceAssertions", "allSixChecksForced"]),
    (IDENTITIES[4], ["publicRegression", "benignPythonDocumentHeredocExpectedFire"]),
])
def test_numeric_values_do_not_alias_boolean_or_integer_claims(identity, path, tmp_path):
    module, packet = copy_packet(identity, tmp_path)
    report = json.loads((packet / "report.json").read_text())
    target = report
    for part in path[:-1]:
        target = target[part]
    value = target[path[-1]]
    target[path[-1]] = int(value) if type(value) is bool else float(value)
    (packet / "report.json").write_text(json.dumps(report))
    with pytest.raises(ValueError, match="report differs"):
        module.validate(packet)
