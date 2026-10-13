"""Tests for the AgentID action_ref v2 recompute."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("action_ref_v2_reader", HERE / "reader.py")
assert _spec is not None and _spec.loader is not None
reader = importlib.util.module_from_spec(_spec)
sys.modules["action_ref_v2_reader"] = reader
_spec.loader.exec_module(reader)

PINNED = {
    "agent_id": "agent_d1b7ef01f9af191f",
    "action_type": "read",
    "scope": "conformance-fixture",
    "timestamp_ms": 1790882271509,
}
V1_PINNED = "6fe8b805ca46d0f71f06b1b4b3301be537ffd53cedb8726df2545c3369445ecb"
V2_PINNED = "08dae3cc5023ccad5b8b978e0b6dda181cc92cc10f28359015fc47d5bcc48ac2"


def _copy_package(tmp_path: Path) -> Path:
    base = tmp_path / "pkg"
    shutil.copytree(HERE, base, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
    return base


def _run(base: Path, out: Path) -> int:
    return reader.main(["--base", str(base), "--output-dir", str(out)])


def test_pinned_tuple_against_hand_written_bytes() -> None:
    pre = (
        b"agent_d1b7ef01f9af191f"
        + b"read"
        + b"conformance-fixture"
        + bytes.fromhex("000001a0f8e6d115")
    )
    assert reader.v1_preimage(PINNED) == pre
    assert hashlib.sha256(pre).hexdigest() == V1_PINNED
    jcs = (
        b'{"action_type":"read","agent_id":"agent_d1b7ef01f9af191f",'
        b'"scope":"conformance-fixture","timestamp_ms":1790882271509}'
    )
    assert reader.v2_bytes(PINNED) == jcs
    assert hashlib.sha256(jcs).hexdigest() == V2_PINNED


def test_collision_pair_separates_only_under_v2() -> None:
    other = dict(PINNED, action_type="rea", scope="dconformance-fixture")
    assert reader.v1_preimage(other) == reader.v1_preimage(PINNED)
    assert reader.v2_bytes(other) != reader.v2_bytes(PINNED)


def test_full_run_passes(tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert _run(HERE, out) == 0
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["upstream_checks"]["passed"] == report["upstream_checks"]["total"] == 30
    assert report["domain_cases"]["passed"] == report["domain_cases"]["total"] == 15
    assert report["source"]["source_commit"] == "bd1f2e7c0d3b8bf55fe5a70479be504cb5533455"


def test_existing_output_dir_is_refused(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    assert _run(HERE, out) == 2
    assert not (out / "report.json").exists()


def test_changed_fixture_byte_fails_the_pin(tmp_path: Path) -> None:
    base = _copy_package(tmp_path)
    target = base / "fixtures" / "positive-pinned-pr9-tuple.json"
    data = bytearray(target.read_bytes())
    data[data.index(b"6fe8b805")] = ord("7")
    target.write_bytes(bytes(data))
    out = tmp_path / "out"
    assert _run(base, out) == 2
    assert not out.exists()


def test_wrong_expected_value_is_reported_not_hidden(tmp_path: Path) -> None:
    base = _copy_package(tmp_path)
    target = base / "fixtures" / "negative-collision-action-type-scope-boundary.json"
    text = target.read_text(encoding="utf-8").replace(
        "71411f6671a959bf2e7450355cca6aec63014c5c0e3fad2fb1ce7d76c72b9287",
        "08dae3cc5023ccad5b8b978e0b6dda181cc92cc10f28359015fc47d5bcc48ac2",
    )
    target.write_text(text, encoding="utf-8")
    inputs = json.loads((base / "INPUTS.json").read_text(encoding="utf-8"))
    for entry in inputs["files"]:
        if entry["path"].endswith(target.name):
            raw = target.read_bytes()
            entry["sha256"], entry["bytes"] = hashlib.sha256(raw).hexdigest(), len(raw)
    (base / "INPUTS.json").write_text(json.dumps(inputs, indent=2), encoding="utf-8")
    out = tmp_path / "out"
    assert _run(base, out) == 1
    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    failed = [r["check"] for r in report["upstream_checks"]["rows"] if r["result"] == "FAIL"]
    assert "b: action_ref_v2 recomputes" in failed


def test_wrong_domain_declaration_is_reported(tmp_path: Path) -> None:
    base = _copy_package(tmp_path)
    domain = json.loads((base / "DOMAIN-CASES.json").read_text(encoding="utf-8"))
    for case in domain["cases"]:
        if case["id"] == "D02-two-to-the-53":
            case["expect"]["v2"] = "defined"
    (base / "DOMAIN-CASES.json").write_text(json.dumps(domain), encoding="utf-8")
    out = tmp_path / "out"
    assert _run(base, out) == 1


@pytest.mark.parametrize(
    "text",
    [
        '{"a":1,"a":2}',
        '{"a":NaN}',
        '{"a":Infinity}',
    ],
)
def test_strict_parse_refuses(text: str) -> None:
    with pytest.raises(ValueError):
        reader.strict_loads(text)


@pytest.mark.parametrize("ts", [True, 1790882271509.0, "1790882271509", None])
def test_non_integer_timestamp_is_refused(ts: object) -> None:
    with pytest.raises(reader.Refused):
        reader.v2_bytes(dict(PINNED, timestamp_ms=ts))
    with pytest.raises(reader.Refused):
        reader.v1_preimage(dict(PINNED, timestamp_ms=ts))


def test_float_token_survives_parsing() -> None:
    obj = reader.strict_loads('{"timestamp_ms":1790882271509.0}')
    assert type(obj["timestamp_ms"]) is not int


def test_v2_domain_edge() -> None:
    assert reader.v2_bytes(dict(PINNED, timestamp_ms=2**53 - 1))
    assert reader.v2_bytes(dict(PINNED, timestamp_ms=-(2**53 - 1)))
    for ts in (2**53, -(2**53), 2**63 - 1):
        with pytest.raises(reader.Refused):
            reader.v2_bytes(dict(PINNED, timestamp_ms=ts))
    assert reader.v1_preimage(dict(PINNED, timestamp_ms=2**63 - 1))[-8:] == bytes.fromhex(
        "7fffffffffffffff"
    )
    with pytest.raises(reader.Refused):
        reader.v1_preimage(dict(PINNED, timestamp_ms=2**63))
