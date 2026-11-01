"""The opentimestamps-bitcoin-header binding of the recorded-set reader.

The witness acknowledgements of the horizon-shield pilot run carry real
OpenTimestamps proofs. These tests take one of them, with the Bitcoin header
the corpus holds for its block, and change one trust input at a time: each
change must draw its own code, and the intact binding must draw none.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packaging"))
from agent_evidence_vectors import recorded

ROOT = Path(__file__).resolve().parents[1] / "corpora" / "vectors-recorded"


def _member(name: str) -> dict:
    manifest = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
    return next(e for e in manifest["vectors"] if e["name"] == name)


def _anchor(entry: dict, height: int) -> dict:
    return next(b for b in entry["bindings"]
                if b["type"] == recorded.BINDING_BTC and b["block"]["height"] == height)


def _codes(entry: dict, bindings: list[dict]) -> list[str]:
    return recorded.check_set(ROOT / entry["dir"], entry["sumsSha256"], bindings)


def test_real_acknowledgement_proofs_reach_their_held_headers() -> None:
    entry = _member("hs51-set2-acks")
    anchors = [b for b in entry["bindings"] if b["type"] == recorded.BINDING_BTC]
    assert anchors and _codes(entry, anchors) == []


def test_a_real_proof_against_the_next_block_is_refused() -> None:
    entry = _member("hs51-set2-acks")
    good, other = _anchor(entry, 972403), _anchor(entry, 972405)
    wrong = {**copy.deepcopy(good), "block": copy.deepcopy(other["block"])}
    wrong["block"]["height"] = good["block"]["height"]
    assert _codes(entry, [wrong]) == ["anchor-mismatch"]
    swapped = {**copy.deepcopy(good), "proof": good["proof"].replace("budget", "criteria_A"),
               "subject": good["subject"]}
    assert _codes(entry, [swapped]) == ["binding-mismatch"]


def test_a_held_header_that_does_not_hash_to_its_block_id_is_malformed() -> None:
    entry = _member("hs51-set2-acks")
    good = copy.deepcopy(_anchor(entry, 972403))
    good["block"]["id"] = "00" * 32
    assert _codes(entry, [good]) == ["binding-malformed"]


def test_a_seen_pointer_the_subject_does_not_carry_is_malformed() -> None:
    entry = _member("hs51-set2-acks")
    good = copy.deepcopy(_anchor(entry, 972403))
    good["after"] = "/seen_block/missing"
    assert _codes(entry, [good]) == ["binding-malformed"]


def test_the_checkpoint_states_a_time_inside_the_window_of_its_anchor() -> None:
    entry = _member("hs51-set2")
    anchors = [b for b in entry["bindings"] if b["type"] == recorded.BINDING_BTC]
    assert {b["block"]["height"] for b in anchors} == {972551, 972552}
    assert _codes(entry, anchors) == []


def test_header_time_and_tolerance_are_the_draft_values() -> None:
    assert recorded.OTS_TOLERANCE_SECONDS == 7200
    header = bytes.fromhex(_anchor(_member("hs51-set2-acks"), 972403)["block"]["header"])
    assert recorded.header_time(header) == 1792548064
