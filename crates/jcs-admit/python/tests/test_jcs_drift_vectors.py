"""The published drift and depth families, through the Python binding.

The Rust test `tests/corpus_drift.rs` holds the crate to
`corpora/jcs-byte-vectors/cases.json`; this holds the binding to the same
pins, so the Python side cannot disagree with the Rust side. The corpus is read
from the repository checkout, at the root above `crates/`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import jcs_admit as jcs

CORPUS = json.loads(
    (Path(__file__).resolve().parents[3].parent / "corpora/jcs-byte-vectors/cases.json").read_text("utf-8")
)
DRIFT = CORPUS["driftCases"]
DEPTH = CORPUS["depthCases"]


def test_the_families_are_not_empty() -> None:
    assert (len(DRIFT), len(DEPTH)) == (18, 10)


@pytest.mark.parametrize("case", DRIFT, ids=[c["id"] for c in DRIFT])
def test_drifted_bytes_are_not_canonical_and_admit_to_the_pin(case: dict[str, str]) -> None:
    pinned = bytes.fromhex(case["canonicalHex"])
    presented = case["presented"].encode("utf-8")
    assert presented != pinned
    assert not jcs.is_canonical(presented)
    assert jcs.admit(presented) == pinned
    assert jcs.admit(case["input"].encode("utf-8")) == pinned
    assert jcs.is_canonical(pinned)


@pytest.mark.parametrize("case", DEPTH, ids=[c["id"] for c in DEPTH])
def test_depth_cases(case: dict[str, object]) -> None:
    data = str(case["input"]).encode("utf-8")
    if case["expect"] == "reject":
        with pytest.raises(jcs.JcsError) as raised:
            jcs.admit(data)
        assert raised.value.variant == "TooDeep"
    else:
        assert jcs.admit(data) == bytes.fromhex(str(case["canonicalHex"]))
