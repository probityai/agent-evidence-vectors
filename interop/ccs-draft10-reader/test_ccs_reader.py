"""The draft-10 reader reproduces its committed results from the vendored corpus.

The reader runs as a subprocess, twice, with PYTHONHASHSEED 0 and 1, and with the
jcs-admit check binary producing every canonical byte string a second time. Its three
outputs must equal the committed results byte for byte and carry the pinned digests.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from importlib.metadata import version
from pathlib import Path
from typing import Any

import ccs_pins
import pytest

HERE = Path(__file__).resolve().parent
FIXTURES = HERE / "fixtures" / "ccs-v1.4.0"
RESULTS = HERE / "results"

PINNED = {
    "cases.jsonl": "003b4889329eb3ad81f409b1bae201002f41add9120f9d6c8c2a5486f5ed463c",
    "summary.json": "6b4c890ba445e3be8eecbbc831b0a88ac7ca6b48f3de5076400679d4b902aa3b",
    "controls.json": "0e660e944ba914a61a3cd2fcc1b7543b77233ae347de3257f7e84824e8f94005",
}

# The reading-B disagreements, split by what the draft says about each case.
DRAFT_DECIDES_OTHER_WAY = {"02-deny-pre-admission"}
DRAFT_ALLOWS = {
    "10-chain-negatives/10a-sequence-gap",
    "07-structure-negatives/07a-missing-max_clock_skew",
    "07-structure-negatives/07a-missing-response_hash",
    "07-structure-negatives/07a-missing-runtime_context_hash",
    "07-structure-negatives/07a-missing-sequence",
    "08-temporal-negatives/08b-future-timestamp",
    "08-temporal-negatives/08d-clock-skew-boundary",
}
DRAFT_STATES_NO_RULE = {
    "05-cross-field-semantic/05b-sandbox-flag-mismatch",
    "06-l2-behavior/06d-behavior-wrong-l1-digest",
    *(
        "07-structure-negatives/07a-missing-" + field
        for field in (
            "args_digest",
            "deployment_mode",
            "latency_us",
            "public_key_fingerprint",
            "receipt_version",
            "rule_version",
            "signing_algorithm",
            "tool_call_id",
            "verifier_source_class",
        )
    ),
    "07-structure-negatives/07b-unknown-field",
    "07-structure-negatives/07c-latency-as-string",
    "09-identity-negatives/09a-fingerprint-mismatch",
    "10-chain-negatives/10b-prev-hash-mismatch",
    "10-chain-negatives/10c-trace-id-mismatch",
    "10-chain-negatives/10d-empty-chain",
    "10-chain-negatives/10e-prev-hash-unanchored",
    "11-integrity-negatives/11a-request-hash-mismatch",
    "11-integrity-negatives/11b-params-hash-mismatch",
    "11-integrity-negatives/11c-config-hash-mismatch",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cases() -> list[dict[str, Any]]:
    lines = (RESULTS / "cases.jsonl").read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


@pytest.fixture(scope="session")
def jcs_admit(tmp_path_factory: pytest.TempPathFactory) -> Path:
    cargo = shutil.which("cargo")
    assert cargo, "cargo is required to build the jcs-admit cross-check"
    target = tmp_path_factory.mktemp("jcs-admit-target")
    subprocess.run(
        [cargo, "build", "-q", "--release", "--locked", "--target-dir", str(target)],
        cwd=HERE / "jcs-admit-check",
        check=True,
        env={**os.environ, "RUSTC_WRAPPER": ""},
    )
    return target / "release" / "jcs-admit-check"


def run_reader(out: Path, seed: str, jcs_admit: Path | None) -> None:
    env = {**os.environ, "PYTHONHASHSEED": seed}
    env.pop("JCS_ADMIT", None)
    if jcs_admit is not None:
        env["JCS_ADMIT"] = str(jcs_admit)
    subprocess.run(
        [sys.executable, "-I", str(HERE / "ccs_spec_reader.py"), str(FIXTURES), str(out)],
        check=True,
        env=env,
        capture_output=True,
    )


def test_tool_versions_are_the_pinned_ones() -> None:
    assert version("agent-evidence-vectors") == ccs_pins.TOOLS["agent-evidence-vectors"]
    assert version("cryptography") == ccs_pins.TOOLS["cryptography"]
    lock = (HERE / "jcs-admit-check" / "Cargo.lock").read_text(encoding="utf-8")
    assert f'name = "jcs-admit"\nversion = "{ccs_pins.TOOLS["jcs-admit"]}"' in lock


def test_inputs_pins_match_the_files_on_disk() -> None:
    assert (HERE / "INPUTS.json").read_text(encoding="ascii") == ccs_pins.render(ccs_pins.build())


def test_vendored_files_match_the_upstream_manifest() -> None:
    manifest = json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
    listed = manifest["files"]
    assert listed
    for rel, want in listed.items():
        assert sha(FIXTURES / rel) == want, rel


@pytest.mark.parametrize("seed", ["0", "1"])
def test_reader_reproduces_the_committed_results(
    tmp_path: Path, seed: str, jcs_admit: Path
) -> None:
    run_reader(tmp_path, seed, jcs_admit)
    for name, want in PINNED.items():
        assert sha(tmp_path / name) == want, name
        assert (tmp_path / name).read_bytes() == (RESULTS / name).read_bytes(), name


def test_without_the_cross_check_only_the_flag_moves(tmp_path: Path) -> None:
    run_reader(tmp_path, "0", None)
    assert sha(tmp_path / "cases.jsonl") == PINNED["cases.jsonl"]
    assert sha(tmp_path / "controls.json") == PINNED["controls.json"]
    fresh = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    committed = json.loads((RESULTS / "summary.json").read_text(encoding="utf-8"))
    assert fresh.pop("jcs_admit_cross_check") is False
    assert committed.pop("jcs_admit_cross_check") is True
    assert fresh == committed


def test_constructions_reproduce(tmp_path: Path) -> None:
    out = tmp_path / "constructions.json"
    subprocess.run(
        [sys.executable, "-I", str(HERE / "infer_constructions.py"), str(FIXTURES), str(out)],
        check=True,
        capture_output=True,
    )
    assert out.read_bytes() == (RESULTS / "constructions.json").read_bytes()


def test_the_reading_b_split_partitions_every_disagreement() -> None:
    disagree = {c["case"] for c in cases() if c["reading_b"] != c["expected"]}
    groups = (DRAFT_DECIDES_OTHER_WAY, DRAFT_ALLOWS, DRAFT_STATES_NO_RULE)
    assert [len(g) for g in groups] == [1, 7, 21]
    assert set().union(*groups) == disagree
    assert sum(c["reading_b"] == c["expected"] for c in cases()) == 37
    assert len(cases()) == 66


def test_reading_a_refuses_every_case() -> None:
    assert all(c["reading_a"] == "invalid" for c in cases())
    assert sum(c["expected"] == "valid" for c in cases()) == 6


def test_signature_readings() -> None:
    tally = json.loads((RESULTS / "summary.json").read_text(encoding="utf-8"))["check_tally"]
    assert tally["sig-4.2-literal"]["PASS"] == 0
    assert tally["sig-4.2+7.2"]["PASS"] == 0
    assert tally["sig-all-but-signature"] == {"FAIL": 4, "PASS": 69, "SILENT": 0}
    assert tally["our-bytes-equal-corpus-signing-input"]["PASS"] == 73


def test_construction_figures() -> None:
    """The README's D3 to D7 and D13 figures, read from the committed results."""
    built = json.loads((RESULTS / "constructions.json").read_text(encoding="utf-8"))
    tally = built["tally"]
    params = tally["params_hash"]
    assert params["_receipts"] == 32
    assert params["sha256(JCS{tool, param_keys sorted})"] == 31
    assert params["args_digest == sha256(JCS(args))"] == 32
    assert params["draft-6.5 sha256(params) full or first 16"] == 0
    assert tally["action"] == {
        "_receipts": 32,
        "draft-6.4 ccs:tool-invoke:{tool}:{sha256(params)}": 0,
    }
    fingerprint = tally["fingerprint"]
    assert fingerprint["_receipts"] == 66
    assert fingerprint["sha256(raw key) first 8 bytes"] == 64
    assert fingerprint["draft-7.2 sha256(raw key) full"] == 0
    demo = built["params_hash_value_change"]
    assert demo["receipt_params_hash"].startswith("f516269c")
    assert demo["names_only_hash_after_value_change"] == demo["receipt_params_hash"]
    assert demo["args_digest_after_value_change"] != demo["receipt_args_digest"]
    hops = built["previous_digest"]
    assert len(hops) == 5
    unanchored = [h["case"] for h in hops if not h["equals_sha256_of_signing_input"]]
    assert unanchored == ["10-chain-negatives/10e-prev-hash-unanchored"]
    summary = json.loads((RESULTS / "summary.json").read_text(encoding="utf-8"))
    assert summary["check_tally"]["response_hash-value"] == {"FAIL": 1, "PASS": 31, "SILENT": 0}


def test_controls() -> None:
    controls = json.loads((RESULTS / "controls.json").read_text(encoding="utf-8"))
    assert len(controls["mutations"]) == 4
    assert all(m["refused"] for m in controls["mutations"].values())
    signature_refused = [
        r for r in controls["relaxed_signature"] if "sig-all-but-signature" in r["baseline_grounds"]
    ]
    flipped = {r["case"] for r in signature_refused if r["signature_relaxed"] == "valid"}
    assert flipped == {
        "07-structure-negatives/07a-missing-public_key",
        "09-identity-negatives/09c-malformed-public-key",
    }
    kept = {r["case"]: r["relaxed_grounds"] for r in signature_refused if r["relaxed_grounds"]}
    assert kept == {
        "04-tampered-negative": ["deny-response_hash-empty"],
        "07-structure-negatives/07a-missing-signature": ["required-fields-b"],
    }
