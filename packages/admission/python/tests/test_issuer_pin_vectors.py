"""Replay conformance/issuer-pin-vectors.json through the pin-set client."""

import importlib.util
import json
import pathlib

import pytest
from agent_evidence_admission import issuer_pin as ip

CONFORMANCE = pathlib.Path(__file__).resolve().parents[2] / "conformance"
VECTORS = json.loads((CONFORMANCE / "issuer-pin-vectors.json").read_text(encoding="utf-8"))


def _pin_set(raw):
    return ip.PinSet(raw["epoch"], frozenset(raw["thumbprints"]))


def run(case):
    try:
        pins = ip.PinnedIssuers(case["issuers"], {i: _pin_set(p) for i, p in case["pins"].items()},
                                unpinned=case["unpinned"], seen_epochs=case["seen_epochs"],
                                fetch=lambda issuer: case["jwks"])
        if case["rotate"] is not None:
            pins = pins.rotate(case["verify"]["issuer"], _pin_set(case["rotate"]))
        pins.key_for(case["verify"]["issuer"], case["verify"]["kid"])
    except ip.PinError as exc:
        return exc.code
    return "accept"


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["id"])
def test_vector(case):
    assert run(case) == case["expect"]


def test_file_is_what_the_generator_writes():
    spec = importlib.util.spec_from_file_location("gen_issuer_pin_vectors", CONFORMANCE / "gen_issuer_pin_vectors.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    assert (CONFORMANCE / "issuer-pin-vectors.json").read_text(encoding="utf-8") == gen.document()


def test_every_refusal_kind_and_acceptance_present():
    expects = {c["expect"] for c in VECTORS["cases"]}
    assert {"accept", "pin-downgrade", "pin-conflict", "pin-thumbprint-mismatch",
            "pin-mixed-configuration", "pin-error"} <= expects
