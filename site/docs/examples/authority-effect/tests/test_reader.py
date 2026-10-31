"""Refusal and claim-separation controls for immutable input bytes."""

import copy
import hashlib
import json

import pytest
from agent_evidence_vectors import run_vectors as rail

from authority_effect.reader import MAX_BYTES, InputError, assess, canonical, commitment
from authority_effect.runner import ROOT

BASE = json.loads((ROOT / "cases" / "matching-supplied-records.json").read_bytes())
POLICY = json.loads((ROOT / "policy.json").read_bytes())
MANIFEST = json.loads((ROOT / "manifest.json").read_bytes())


def raw(value):
    return json.dumps(value, ensure_ascii=True).encode()


@pytest.mark.parametrize("entry", MANIFEST["cases"], ids=lambda entry: entry["id"])
def test_every_frozen_expected_axis(entry):
    answer = assess((ROOT / entry["path"]).read_bytes(), (ROOT / entry["policy"]).read_bytes())
    assert {name: claim["value"] for name, claim in answer["claims"].items()} == entry["expected"]
    assert answer["caseSha256"] == entry["sha256"]
    assert answer["policySha256"] == entry["policySha256"]
    assert answer["scope"]["admission"] == "not_evaluated"


def test_tampered_preimage_preserves_valid_signature_but_not_authority():
    original = copy.deepcopy(BASE)
    tampered = copy.deepcopy(BASE)
    tampered["authorization"]["intent"]["target"] = "https://fixture.example/b"
    assert tampered["authorization"]["signature"] == original["authorization"]["signature"]
    assert tampered["authorization"]["commitment"] == original["authorization"]["commitment"]
    assert (
        commitment(tampered["authorization"]["intent"]) != original["authorization"]["commitment"]
    )
    claims = assess(raw(tampered), raw(POLICY))["claims"]
    assert claims["signatureUnderSelectedKey"]["value"] is True
    assert claims["commitmentRecomputed"]["value"] is False
    assert claims["destinationAuthorized"]["value"] is None
    assert claims["callEnvelopeAuthorized"]["value"] is None


def test_observation_does_not_rewrite_historical_report_or_create_provenance():
    case = copy.deepcopy(BASE)
    case["observation"]["effectSha256"] = "ff" * 32
    case["observation"]["operator"] = "self-described independent verifier"
    claims = assess(raw(case), raw(POLICY))["claims"]
    assert claims["historicalCompletionReported"]["value"] is True
    assert claims["suppliedCurrentEffectMatches"]["value"] is False
    assert claims["observationProvenanceAuthenticated"]["value"] is None


def test_canonical_preimage_uses_installed_rail_and_full_profile():
    intent = BASE["authorization"]["intent"]
    preimage = {"profile": "probity.authority-effect-intent/v1", "intent": intent}
    assert canonical(preimage) == rail.jcs_dumps(preimage)
    assert commitment(intent) == hashlib.sha256(rail.jcs_dumps(preimage)).hexdigest()
    unicode_value = {"\U0001f600": "astral", "\ufffd": "bmp"}
    assert canonical(unicode_value) == b'{"\xf0\x9f\x98\x80":"astral","\xef\xbf\xbd":"bmp"}'


@pytest.mark.parametrize(
    "data",
    [
        b"[]",
        b"null",
        b"{}\xff",
        b'{"x":1,"x":2}',
        b'{"x":"\\ud800"}',
        b'{"x":NaN}',
        b'{"x":9007199254740992}',
        b"x" * (MAX_BYTES + 1),
        {"mutable": "object"},
    ],
)
def test_refuse_malformed_or_mutable_input(data):
    with pytest.raises(InputError):
        assess(data, raw(POLICY))


@pytest.mark.parametrize(
    "path,value",
    [
        (("profile",), "unsupported"),
        (("caseId",), ""),
        (("runtime", "chainId"), True),
        (("runtime", "chainId"), 0),
        (("runtime", "value"), "01"),
        (("runtime", "value"), "-1"),
        (("runtime", "value"), "١"),
        (("runtime", "target"), "x" * 8193),
        (("runtime", "submittedAt"), 1121),
        (("authorization", "signature"), "AA" * 64),
        (("authorization", "commitment"), "ab"),
        (("authorization", "intent", "validUntil"), 999),
        (("report", "completed"), "true"),
        (("observation", "observedAt"), False),
        (("scan", "exitCode"), -1),
        (("scan", "stdout"), ""),
        (("scan", "scanned"), ["unit-a", "unit-a"]),
        (("scan", "scanned"), ["unit-a"]),
        (("scan", "skipped"), ["unit-a"]),
        (("scan", "findings"), "findings"),
        (("scan", "findings"), ["x"] * 4097),
    ],
)
def test_refuse_case_profile_violations(path, value):
    case = copy.deepcopy(BASE)
    current = case
    for field in path[:-1]:
        current = current[field]
    current[path[-1]] = value
    with pytest.raises(InputError):
        assess(raw(case), raw(POLICY))


@pytest.mark.parametrize(
    "changes",
    [
        {"profile": "other"},
        {"principalPublicKey": "AB" * 32},
        {"referenceTime": 1099},
        {"maxObservationAge": -1},
        {"scanUnits": ["unit-a", "unit-a"]},
        {"unknown": True},
    ],
)
def test_refuse_policy_profile_violations(changes):
    with pytest.raises(InputError):
        assess(raw(BASE), raw(POLICY | changes))


@pytest.mark.parametrize(
    "path",
    [
        (),
        ("authorization",),
        ("authorization", "intent"),
        ("runtime",),
        ("report",),
        ("observation",),
        ("scan",),
    ],
)
def test_unknown_fields_cannot_smuggle_alternate_authority(path):
    case = copy.deepcopy(BASE)
    current = case
    for field in path:
        current = current[field]
    current["unverifiedAuthority"] = "accept me"
    with pytest.raises(InputError):
        assess(raw(case), raw(POLICY))


def test_optional_records_may_be_omitted():
    case = {k: v for k, v in BASE.items() if k not in {"report", "observation", "scan"}}
    answer = assess(raw(case), raw(POLICY))
    for name in ("historicalCompletionReported", "observationFresh", "coverageComplete"):
        assert answer["claims"][name]["value"] is None
