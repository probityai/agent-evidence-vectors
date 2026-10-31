"""Original-byte contract and reader controls, independent of study acceptance."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import time

import pytest

from test_discovery_capture import invocation, answer_body
import discovery_capture as driver
import discovery_capture_journal as custody
import discovery_capture_v2 as reader


def selection():
    return {"component_ids": ["observer"], "profile_ids": ["spend-reservation-v1"],
            "recipe_url": "literal-url-string", "command": None}


def retained(tmp_path, code=0):
    manifest, prompt = invocation(tmp_path, answer_body(), code)
    attempt = tmp_path / "attempt"
    driver.capture(manifest, prompt, attempt)
    return attempt


@pytest.mark.parametrize("code,valid", [(0, False), (7, True)])
def test_contract_is_separate_from_answer_and_exit(tmp_path, code, valid):
    attempt = retained(tmp_path, code)
    earlier = tmp_path / "earlier-record.json"
    earlier.write_bytes((attempt / "record.json").read_bytes())
    metadata = tmp_path / "metadata.json"
    original = selection()
    if not valid:
        original["profile_ids"] = ["spend_reservation/v1"]
    data = json.dumps(original, indent=3).encode()
    metadata.write_bytes(data)
    record = reader.retain_contract(attempt, metadata)
    assert record["contract"]["origin"] == "supplied_metadata"
    assert record["contract"]["state"] == ("valid" if valid else "invalid")
    assert record["contract"]["selection"] == (original if valid else None)
    assert record["native_closure"]["exit_code"] == code
    assert record["response"]["state"] == "observed"
    assert (attempt / "response-metadata.json").read_bytes() == data
    assert reader.check_record(attempt / "record.json", attempt) == record
    assert reader.check_record(earlier, attempt)["contract"]["state"] == "not_evaluated"
    rows, _ = custody.read_journal(attempt)
    assert rows[-1]["receiver_clock_id"] != rows[0]["receiver_clock_id"]
    before = (attempt / "receiver-journal.jsonl").read_bytes()
    with pytest.raises(ValueError):
        reader.retain_contract(attempt, metadata)
    assert (attempt / "receiver-journal.jsonl").read_bytes() == before


@pytest.mark.parametrize("data", [b'{"component_ids":[],"component_ids":[]}', b'{"x":NaN}', b'[]', b'{"x":1e999}'])
def test_metadata_refusal_preserves_original(tmp_path, data):
    attempt = retained(tmp_path)
    metadata = tmp_path / "metadata.json"
    metadata.write_bytes(data)
    record = reader.retain_contract(attempt, metadata)
    assert record["contract"]["state"] == "invalid"
    assert record["contract"]["selection"] is None
    assert record["contract"]["refusal_detail"]
    assert (attempt / "response-metadata.json").read_bytes() == data
    assert reader.check_record(attempt / "record.json", attempt) == record


def test_oversized_metadata_remains_complete(tmp_path):
    metadata = tmp_path / "metadata.json"
    metadata.write_bytes(b"x" * (custody.JSON_LIMIT + 1))
    attempt = retained(tmp_path)
    record = reader.retain_contract(attempt, metadata)
    assert record["contract"]["refusal"] == "metadata_oversized"
    assert custody.file_binding(attempt / "response-metadata.json") == custody.file_binding(metadata)


def test_reader_rejects_schema_range_origin_source_and_float_drift(tmp_path):
    attempt = retained(tmp_path)
    original = custody.strict_json((attempt / "record.json").read_bytes())
    mutants = []
    value = copy.deepcopy(original)
    value["response"]["captures"][0]["origin"] = "native_output_file"
    mutants.append(value)
    value = copy.deepcopy(original)
    value["events"][0]["offset"] = 1
    mutants.append(value)
    value = copy.deepcopy(original)
    value["schema_version"] = 2.0
    mutants.append(value)
    value = copy.deepcopy(original)
    value["contract"]["state"] = "valid"
    mutants.append(value)
    for value in mutants:
        path = tmp_path / "mutant.json"
        path.write_bytes(custody.canonical(value))
        with pytest.raises(ValueError):
            reader.check_record(path, attempt)
    source = attempt / "driver-source" / "discovery_capture.py"
    source.write_bytes(source.read_bytes() + b"\n# changed source\n")
    with pytest.raises(ValueError, match="source bindings"):
        reader.check_record(attempt / "record.json", attempt)


def test_actual_capture_and_contract_processes_cannot_overlap(tmp_path):
    ready = tmp_path / "ready"
    body = f"from pathlib import Path\nimport time\nPath({str(ready)!r}).write_text('ready')\ntime.sleep(2)\n" + answer_body()
    manifest, prompt = invocation(tmp_path, body)
    attempt = tmp_path / "attempt"
    metadata = tmp_path / "metadata.json"
    metadata.write_bytes(custody.canonical(selection()))
    process = subprocess.Popen([sys.executable, str(Path(driver.__file__)), "capture", "--manifest", str(manifest), "--prompt", str(prompt), "--attempt-dir", str(attempt)])
    try:
        deadline = time.monotonic() + 10
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ready.exists()
        with pytest.raises(ValueError, match="active writer"):
            reader.retain_contract(attempt, metadata)
        with pytest.raises(ValueError, match="active writer"):
            custody.project(attempt)
        assert not (attempt / "response-metadata.json").exists()
        assert process.wait(timeout=10) == 0
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=10)
    reader.retain_contract(attempt, metadata)
    reader.check_record(attempt / "record.json", attempt)


def test_reader_and_contract_cli(tmp_path):
    attempt = retained(tmp_path)
    metadata = tmp_path / "metadata.json"
    metadata.write_bytes(custody.canonical(selection()))
    assert driver.main(["contract", "--attempt-dir", str(attempt), "--metadata", str(metadata)]) == 0
    assert driver.main(["contract", "--attempt-dir", str(attempt)]) == 2
    assert reader.main(["check", "--attempt-dir", str(attempt), "--record", str(attempt / "record.json")]) == 0
    assert reader.main(["check", "--attempt-dir", str(attempt), "--record", str(tmp_path / "missing")]) == 2


def test_frozen_literal_response_grammar_is_exact():
    original = custody.strict_json((reader.SCHEMA.parent / "discovery-evaluation.schema.json").read_bytes())
    assert reader.schema()["$defs"]["selection"] == original["$defs"]["response"]


def test_projection_cannot_replace_retained_originals(tmp_path):
    attempt = retained(tmp_path)
    record = custody.project(attempt)
    for name in ("invocation.json", "native-events.jsonl", "receiver-journal.jsonl", "response-metadata.json", "driver-source/discovery_capture.py"):
        path = attempt / name
        original = path.read_bytes() if path.exists() else None
        with pytest.raises(ValueError, match="original evidence"):
            custody.write_projection(attempt, path, record)
        assert (path.read_bytes() if path.exists() else None) == original
    other = tmp_path / "original.json"
    other.write_bytes(b'{"original":true}')
    with pytest.raises(ValueError):
        custody.write_projection(attempt, other, record)
    assert other.read_bytes() == b'{"original":true}'
