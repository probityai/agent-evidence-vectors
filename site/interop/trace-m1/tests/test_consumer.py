"""Single-fault controls for native byte binding and unsupported claim upgrades."""

import base64
import copy
import json
import shutil

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from json_profile import Refusal, canonical, decode, digest, integer, object_fields, parse, text
from mapping import check_mapping_ceiling
from reader import read
from replay import HERE, compare_case, load_cases, main, replay
from signature import DOMAIN, IDENTITY, ORDER, admissible_point, trusted_public_keys


def case(number=1):
    path = next((HERE / "private-inputs").glob(f"{number:02d}-*.json"))
    return parse(path.read_bytes())


def replace_signed(input_document, change):
    item = copy.deepcopy(input_document)
    outer = parse(decode(item["evidence_b64"]))
    document = parse(decode(outer["result_b64"]))
    change(document)
    key = Ed25519PrivateKey.from_private_bytes(b"\x42" * 32)
    public = key.public_key().public_bytes_raw()
    payload = canonical(document)
    outer["result_b64"] = base64.b64encode(payload).decode()
    outer["signature"]["kid"] = "ed25519-" + digest(public).removeprefix("sha256:")
    outer["signature"]["signature"] = base64.b64encode(
        key.sign(DOMAIN.encode() + b"\0" + payload)
    ).decode()
    item["evidence_b64"] = base64.b64encode(canonical(outer)).decode()
    item["trusted_keys"] = [public.hex()]
    return item


def replace_context(input_document, change):
    item = copy.deepcopy(input_document)
    context = parse(item["execution_context"].encode("ascii"))
    change(context)
    item["execution_context"] = canonical(context).decode("ascii")
    report = item["reports"][0]
    report["body"]["execution_context_digest"] = digest(canonical(context)).removeprefix("sha256:")
    report_digest = digest(canonical(report))
    item["request"]["subject"]["report_digest"] = report_digest

    def bind(document):
        document["subject"]["report_digest"] = report_digest
        document["evidence_selection"]["selected_digest"] = report_digest

    return replace_signed(item, bind)


@pytest.mark.parametrize(
    "path",
    (
        (),
        ("subject",),
        ("subject", "authority"),
        ("model_initiator",),
        ("model_initiator", "authority"),
        ("runtime",),
        ("runtime", "authority"),
        ("data_scope",),
        ("data_scope", "authority"),
    ),
)
def test_signed_context_cannot_add_unqualified_capability_fields(path):
    def add(context):
        target = context
        for field in path:
            target = target[field]
        target["verified_authority"] = True

    item = replace_context(case()["input"], add)
    assert read(item)["reason"] == "unknown_field"


@pytest.mark.parametrize(
    "field,value",
    (
        ("tool_call_hash", "z" * 64),
        ("data_scope", {}),
        ("subject", []),
        ("captured_at", ""),
    ),
)
def test_rebound_context_must_still_meet_the_declared_profile(field, value):
    item = replace_context(case()["input"], lambda context: context.update({field: value}))
    assert read(item)["decision"] == "REFUSED"


@pytest.mark.parametrize(
    "path",
    (
        (),
        ("trace",),
        ("trace", "origin"),
        ("trace", "appraisal"),
        ("trace", "model"),
        ("remora",),
        ("remora", "subject"),
        ("remora", "execution_context"),
        ("remora", "available_unmapped"),
    ),
)
def test_mapping_cannot_smuggle_capabilities_beside_its_false_ceiling(path):
    fixture = case()
    mapping = copy.deepcopy(fixture["expected"]["mapping"])
    target = mapping
    for field in path:
        target = target[field]
    target["verified_authority"] = True
    with pytest.raises(Refusal):
        check_mapping_ceiling(mapping, read(fixture["input"]))


def test_constructed_python_keys_cannot_be_coerced_into_json_strings():
    with pytest.raises(Refusal, match="json_object_key_must_be_string"):
        canonical({1: "value"})
    with pytest.raises(Refusal, match="object_too_large"):
        canonical({str(i): i for i in range(1025)})


def test_ascii_del_is_preserved_while_c0_characters_are_escaped():
    assert canonical({"s": "\x7f"}) == b'{"s":"\x7f"}'
    assert canonical({"s": "\x00\b\t\n\f\r"}) == b'{"s":"\\u0000\\b\\t\\n\\f\\r"}'


@pytest.mark.parametrize(
    "point",
    (
        IDENTITY,
        b"\x00" * 32,
        (2**255 - 20).to_bytes(32, "little"),
        (2**255 - 19).to_bytes(32, "little"),
        b"\xff" * 32,
    ),
)
def test_low_order_and_noncanonical_keys_are_refused(point):
    with pytest.raises(Refusal):
        trusted_public_keys([point.hex()])


def test_mixed_order_point_is_refused_even_when_on_the_curve():
    prime = 2**255 - 19
    base_y = 4 * pow(5, -1, prime) % prime
    # Adding the order-two point (0, -1) to the base gives (-x, -y).
    mixed_order = ((prime - base_y) | (1 << 255)).to_bytes(32, "little")
    with pytest.raises(Refusal):
        admissible_point(mixed_order)


def test_identity_key_forgery_cannot_bind_an_arbitrary_native_result():
    item = copy.deepcopy(case()["input"])
    outer = parse(decode(item["evidence_b64"]))
    outer["signature"]["kid"] = "ed25519-" + digest(IDENTITY).removeprefix("sha256:")
    outer["signature"]["signature"] = base64.b64encode(IDENTITY + bytes(32)).decode("ascii")
    item["trusted_keys"] = [IDENTITY.hex()]
    item["evidence_b64"] = base64.b64encode(canonical(outer)).decode("ascii")
    assert read(item)["decision"] == "REFUSED"


def test_noncanonical_signature_scalar_is_refused_before_backend_verify():
    item = copy.deepcopy(case()["input"])
    outer = parse(decode(item["evidence_b64"]))
    signature = decode(outer["signature"]["signature"])
    outer["signature"]["signature"] = base64.b64encode(
        signature[:32] + ORDER.to_bytes(32, "little")
    ).decode("ascii")
    item["evidence_b64"] = base64.b64encode(canonical(outer)).decode("ascii")
    assert read(item)["reason"] == "noncanonical_signature_scalar"


@pytest.mark.parametrize("number", range(1, 13))
def test_frozen_population_preserves_three_native_results_and_nine_refusals(number):
    fixture = case(number)
    observed = read(fixture["input"])
    assert observed["decision"] == ("BOUND" if number <= 3 else "REFUSED")
    if number <= 3:
        assert (
            observed["native_result"] == fixture["expected"]["mapping"]["remora"]["native_result"]
        )
        assert check_mapping_ceiling(fixture["expected"]["mapping"], observed)
    else:
        assert observed["native_result"] is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", "unknown"),
        ("native_claim", "different.claim"),
        ("subject", {}),
        ("native_result", {"status": True}),
        ("extra", "unsigned-contract-extension"),
    ],
)
def test_even_a_trusted_signer_cannot_change_the_requested_contract(field, value):
    item = replace_signed(case()["input"], lambda doc: doc.update({field: value}))
    assert read(item)["decision"] == "REFUSED"


@pytest.mark.parametrize(
    "field,value",
    [
        ("selected_ref", "other-attempt"),
        ("selected_digest", "sha256:" + "0" * 64),
        ("selection_rule", "last"),
        ("eligible", True),
        ("eligible", 0),
    ],
)
def test_signed_selection_cannot_rebind_or_use_boolean_counts(field, value):
    item = replace_signed(
        case()["input"], lambda doc: doc["evidence_selection"].update({field: value})
    )
    assert read(item)["decision"] == "REFUSED"


def test_native_vocabulary_is_preserved_without_truth_inference():
    native = {
        "status": "foreign-status",
        "reason_code": "foreign-reason",
        "vocabulary": "foreign-v1",
    }
    item = replace_signed(case()["input"], lambda doc: doc.update(native_result=native))
    observed = read(item)
    assert observed["native_result"] == native
    assert observed["claim_ceiling"]["native_result_re_evaluated"] is False


def test_signed_boolean_sequence_cannot_alias_requested_integer():
    item = replace_signed(case()["input"], lambda doc: doc["subject"].update(sequence=True))
    assert read(item)["decision"] == "REFUSED"


def test_mapping_boolean_sequence_cannot_alias_native_integer():
    fixture = case()
    mapping = copy.deepcopy(fixture["expected"]["mapping"])
    mapping["remora"]["subject"]["sequence"] = True
    with pytest.raises(Refusal, match="native_sidecar_mismatch"):
        check_mapping_ceiling(mapping, read(fixture["input"]))


@pytest.mark.parametrize(
    "field,value",
    [
        ("is_trust_record", True),
        ("is_trust_record", 0),
        ("trace_conformance_level", "L1"),
        ("trace_role", "trust-record-issuer"),
    ],
)
def test_mapping_upgrade_is_refused(field, value):
    fixture = case()
    mapping = copy.deepcopy(fixture["expected"]["mapping"])
    mapping[field] = value
    with pytest.raises(Refusal):
        check_mapping_ceiling(mapping, read(fixture["input"]))


@pytest.mark.parametrize(
    "field", ("subject", "runtime", "policy", "data_class", "build_provenance", "cnf")
)
def test_fabricated_required_field_is_refused_individually(field):
    fixture = case()
    mapping = copy.deepcopy(fixture["expected"]["mapping"])
    mapping["trace"][field] = {"invented": "value"}
    with pytest.raises(Refusal, match="invented_required_field"):
        check_mapping_ceiling(mapping, read(fixture["input"]))


@pytest.mark.parametrize("part", ("appraisal", "model", "native"))
def test_mapping_cannot_invent_appraisal_model_or_native_outcome(part):
    fixture = case()
    mapping = copy.deepcopy(fixture["expected"]["mapping"])
    if part == "native":
        mapping["remora"]["native_result"]["status"] = "ESTABLISHED_FOR_ALL_REPORTS"
    else:
        mapping["trace"][part] = (
            {"status": "pass"} if part == "appraisal" else {"provider": "other"}
        )
    with pytest.raises(Refusal):
        check_mapping_ceiling(mapping, read(fixture["input"]))


def test_missing_context_cannot_satisfy_requested_tenant():
    item = copy.deepcopy(case(3)["input"])
    item["request"]["expected_tenant"] = "tenant-a"
    assert read(item)["decision"] == "REFUSED"


def test_duplicate_identity_is_refused_even_when_one_report_matches():
    item = copy.deepcopy(case()["input"])
    duplicate = copy.deepcopy(item["reports"][0])
    duplicate["sequence"] += 1
    item["reports"].append(duplicate)
    assert read(item)["reason"] == "duplicate_report_identity"


def test_whole_report_body_tamper_is_detected():
    item = copy.deepcopy(case()["input"])
    item["reports"][0]["body"]["observed"] = "different"
    assert read(item)["decision"] == "REFUSED"


@pytest.mark.parametrize(
    "field,value",
    [
        ("issued_at", True),
        ("ingested_at", 1791000001),
        ("producer", ""),
        ("resolver", ""),
        ("retention", "P2Y"),
        ("native_claim", ""),
    ],
)
def test_request_declared_values_are_not_coerced(field, value):
    item = copy.deepcopy(case()["input"])
    item["request"][field] = value
    assert read(item)["decision"] == "REFUSED"


@pytest.mark.parametrize(
    "field,value",
    [
        ("format", "unknown"),
        ("result_b64", "%%%"),
        ("algorithm", "HS256"),
        ("domain", "other-domain"),
        ("signature", "AA=="),
    ],
)
def test_envelope_single_faults(field, value):
    item = copy.deepcopy(case()["input"])
    outer = parse(decode(item["evidence_b64"]))
    target = outer if field in ("format", "result_b64") else outer["signature"]
    target[field] = value
    item["evidence_b64"] = base64.b64encode(canonical(outer)).decode()
    assert read(item)["decision"] == "REFUSED"


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'{"a":1.5}',
        b'"\\ud800"',
        b'"\\u00e9"',
        b"\xff",
        b"{",
        b'{"n":9007199254740992}',
        b"[" * 34 + b"0" + b"]" * 34,
    ],
)
def test_invalid_or_out_of_profile_json_is_refused(raw):
    with pytest.raises(Refusal):
        parse(raw)


@pytest.mark.parametrize("value", (None, "%%%", "AB==", "AA===", "A" * 1_398_105))
def test_noncanonical_or_unbounded_base64_is_refused(value):
    with pytest.raises(Refusal):
        decode(value)


@pytest.mark.parametrize("keys", (["z" * 64], ["00"], [True], ["A" * 64], ["0" * 64] * 2, None))
def test_invalid_trust_population_is_refused(keys):
    with pytest.raises(Refusal):
        trusted_public_keys(keys)


def test_json_profile_retains_boolean_null_and_integer_types():
    assert parse(canonical({"null": None, "b": True, "n": -1, "s": '\\"'})) == {
        "null": None,
        "b": True,
        "n": -1,
        "s": '\\"',
    }
    assert integer(1) == 1 and text("a") == "a"
    with pytest.raises(Refusal):
        integer(True)
    with pytest.raises(Refusal):
        object_fields({"unknown": 1}, ())


def test_changed_input_archive_and_population_are_refused(tmp_path):
    shutil.copytree(HERE / "private-inputs", tmp_path / "private-inputs")
    shutil.copy2(HERE / "INPUT-MANIFEST.json", tmp_path / "INPUT-MANIFEST.json")
    load_cases(tmp_path)
    chosen = next((tmp_path / "private-inputs").glob("*.json"))
    chosen.write_bytes(chosen.read_bytes() + b"\n")
    with pytest.raises(Refusal, match="case_size_changed"):
        load_cases(tmp_path)
    chosen.unlink()
    with pytest.raises(Refusal, match="case_population_changed"):
        load_cases(tmp_path)


def test_full_recount_and_native_command(tmp_path, monkeypatch):
    result = replay(HERE)
    assert result["cases"] == result["agreements"] == 12
    monkeypatch.setattr("sys.argv", ["replay.py", "--out", str(tmp_path / "retained")])
    assert main() == 0
    saved = json.loads((tmp_path / "retained/report.json").read_bytes())
    public = json.loads((tmp_path / "retained/public-report.json").read_bytes())
    assert public["cases"] == public["agreements"] == len(public["rows"]) == 12
    assert all("upstream_expected" not in row for row in public["rows"])
    assert all("bound_context" not in row["observed"] for row in public["rows"])
    assert [row["observed"]["native_result"] for row in public["rows"]] == [
        row["observed"]["native_result"] for row in saved["rows"]
    ]
    assert sum(row["observed"]["decision"] == "BOUND" for row in saved["rows"]) == 3
    assert all(row["refusal_code_equivalence_assumed"] is False for row in saved["rows"])


def test_comparison_cannot_hide_a_bad_native_mapping():
    fixture = case()
    fixture["expected"]["mapping"]["remora"]["native_result"]["status"] = "different"
    row = compare_case("single-fault", "0" * 64, fixture)
    assert row["agreement"] is False
