"""Actual external signature reads and separately authored adverse controls."""

import base64
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from witness_case import reader
from witness_case.io import MAX_BYTES, Refusal, digest

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
PINS = json.loads((FIXTURES / "pins.json").read_text())
A = "https://gate.horizonshield.dev/a2a"
B = "https://gate.horizonshield.dev/mcp"


def inputs(name="a"):
    row = PINS[name]
    return (
        (FIXTURES / row["envelope_file"]).read_bytes(),
        (FIXTURES / row["key_file"]).read_bytes(),
        {k: row[k] for k in ("record_sha256", "key_document_sha256", "key_url")}
        | {"target": A, "operator_identity": "Probity / finite reader author-run"},
    )


def edited_envelope(change):
    raw, key, args = inputs()
    obj = json.loads(raw)
    change(obj)
    return json.dumps(obj).encode(), key, args


def signed_control(change):
    """Sign an author-created mutation with a test key, never a witness's private key."""
    original, _, args = inputs()
    obj = json.loads(original)
    record = json.loads(obj["record"]["record_canonical"])
    change(record)
    raw = reader.canonical_bytes(record)
    private = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"Probity author-created witness-reader test key only").digest()
    )
    public = base64.b64encode(private.public_key().public_bytes_raw()).decode()
    key_doc = json.dumps({"public_key_ed25519_b64": public}).encode()
    obj["sha"] = obj["record"]["sha"] = digest(raw)
    obj["record"]["record_canonical"] = raw.decode()
    obj["record"]["public_key_ed25519_b64"] = public
    obj["record"]["signature_ed25519_b64"] = base64.b64encode(private.sign(raw)).decode()
    args.update(record_sha256=digest(raw), key_document_sha256=digest(key_doc))
    return json.dumps(obj).encode(), key_doc, args


@pytest.mark.parametrize(
    "name,target,expected",
    [("a", A, True), ("b", A, False), ("a", A + "/", False), ("b", A + "/", False), ("b", B, True)],
)
def test_actual_supplied_signatures_bind_the_exact_purpose_url(name, target, expected):
    raw, key, args = inputs(name)
    args["target"] = target
    result = reader.read(raw, key, **args)
    assert result["signature_verified_under_pinned_key"]
    assert result["target_matches"] is expected
    assert result["outcome"] == ("MATCHING_SIGNED_OBSERVATION" if expected else "TARGET_MISMATCH")
    assert result["card_signature_verified_declared"] is None
    assert not result["reader_card_signature_verification"]
    assert not any(result["scope"].values())
    count = result["assertions"]
    assert count["total_assertions"] == 8
    assert count["reported_true"] == (7 if name == "a" else 4)
    assert count["unevaluated"] == (1 if name == "a" else 4)
    assert not count["all_eight_reported_true"]


def test_same_card_hash_does_not_cover_another_endpoint():
    a = json.loads(inputs("a")[0])
    b = json.loads(inputs("b")[0])
    aa = json.loads(a["record"]["record_canonical"])
    bb = json.loads(b["record"]["record_canonical"])
    assert aa["nodes"][0]["response"]["body_sha256"] == bb["nodes"][0]["response"]["body_sha256"]
    assert aa["purpose"] != bb["purpose"]
    raw, key, args = inputs("b")
    assert not reader.read(raw, key, **args)["target_matches"]


@pytest.mark.parametrize(
    "change,code",
    [
        (lambda e: e["record"].__setitem__("record_canonical", None), "RECORD_BYTES_INVALID"),
        (lambda e: e["record"].__setitem__("record_canonical", "\ud800"), "RECORD_BYTES_INVALID"),
        (
            lambda e: e["record"].__setitem__(
                "record_canonical", e["record"]["record_canonical"] + " "
            ),
            "RECORD_PIN_MISMATCH",
        ),
        (lambda e: e.__setitem__("sha", "0" * 64), "ENVELOPE_SHA_DISAGREES"),
        (lambda e: e["record"].__setitem__("signed", 1), "SIGNATURE_NOT_DECLARED"),
        (
            lambda e: e["record"].__setitem__("key_url", "https://another.example/key"),
            "KEY_URL_DISAGREES",
        ),
        (
            lambda e: e["record"].__setitem__("signature_ed25519_b64", False),
            "CRYPTO_ENCODING_INVALID",
        ),
        (
            lambda e: e["record"].__setitem__("signature_ed25519_b64", "not base64"),
            "CRYPTO_ENCODING_INVALID",
        ),
        (
            lambda e: e["record"].__setitem__(
                "signature_ed25519_b64", base64.b64encode(b"short").decode()
            ),
            "CRYPTO_ENCODING_INVALID",
        ),
        (
            lambda e: e["record"].__setitem__(
                "signature_ed25519_b64", base64.b64encode(b"x" * 64).decode()
            ),
            "SIGNATURE_INVALID",
        ),
        (
            lambda e: e["record"].__setitem__(
                "public_key_ed25519_b64", base64.b64encode(b"x" * 32).decode()
            ),
            "DECLARED_KEY_DISAGREES",
        ),
        (lambda e: e.__setitem__("record", None), "RECORD_SHAPE_INVALID"),
    ],
)
def test_unsigned_envelope_fields_and_bad_signatures_do_not_override_pins(change, code):
    raw, key, args = edited_envelope(change)
    with pytest.raises(Refusal) as error:
        reader.read(raw, key, **args)
    assert error.value.code == code


def test_separately_pinned_key_cannot_be_replaced_by_envelope_key():
    raw, key, args = inputs()
    with pytest.raises(Refusal) as error:
        reader.read(raw, key + b" ", **args)
    assert error.value.code == "KEY_DOCUMENT_PIN_MISMATCH"
    for malformed in ("{}", b"x" * (MAX_BYTES + 1)):
        with pytest.raises(Refusal) as error:
            reader.read(raw, malformed, **args)
        assert error.value.code == "INPUT_TOO_LARGE"


@pytest.mark.parametrize(
    "change,code",
    [
        (lambda r: r.__setitem__("schema", "invented"), "RECORD_PROFILE_UNSUPPORTED"),
        (lambda r: r.__setitem__("mode", "summary"), "RECORD_PROFILE_UNSUPPORTED"),
        (lambda r: r.__setitem__("purpose", "subject:target=" + A), "PURPOSE_UNSUPPORTED"),
        (lambda r: r.__setitem__("purpose", reader.PURPOSE_PREFIX), "TEXT_INVALID"),
        (lambda r: r["conduct_ext"].__setitem__("target", B), "SIGNED_TARGET_DISAGREES"),
        (lambda r: r["nodes"][3]["request"].__setitem__("url", B), "SIGNED_TARGET_DISAGREES"),
        (lambda r: r["nodes"][3]["request"].__setitem__("method", "GET"), "NODES_INVALID"),
        (lambda r: r.__setitem__("nodes", []), "NODES_INVALID"),
        (lambda r: r["nodes"][0].__setitem__("n", False), "NODES_INVALID"),
        (lambda r: r["nodes"][3].__setitem__("n", 2), "NODES_INVALID"),
        (lambda r: r.__setitem__("assertions", []), "ASSERTIONS_INVALID"),
        (lambda r: r["assertions"][0].__setitem__("result", 1), "ASSERTIONS_INVALID"),
        (lambda r: r["assertions"][0].pop("result"), "ASSERTIONS_INVALID"),
        (lambda r: r["verdict"].__setitem__("n_total", 8), "VERDICT_COUNTS_DISAGREE"),
        (lambda r: r["verdict"].__setitem__("ok", 1), "VERDICT_COUNTS_DISAGREE"),
        (lambda r: r["card_signature"].__setitem__("verified", 1), "CARD_OBSERVATION_INVALID"),
    ],
)
def test_author_created_signed_controls_keep_native_meanings(change, code):
    raw, key, args = signed_control(change)
    with pytest.raises(Refusal) as error:
        reader.read(raw, key, **args)
    assert error.value.code == code


def test_false_assertions_and_nulls_are_not_promoted():
    def fail(record):
        record["assertions"][0]["result"] = False
        record["verdict"] = {"n_pass": 6, "n_total": 7, "ok": False, "outcome": "FAIL"}

    raw, key, args = signed_control(fail)
    result = reader.read(raw, key, **args)
    assert result["outcome"] == "REPORTED_ASSERTION_FAILURE"
    assert result["assertions"]["reported_false"] == 1
    assert result["assertions"]["unevaluated"] == 1

    def none(record):
        for assertion in record["assertions"]:
            assertion["result"] = None
        record["verdict"] = {"n_pass": 0, "n_total": 0, "ok": True, "outcome": "PASS"}

    raw, key, args = signed_control(none)
    result = reader.read(raw, key, **args)
    assert result["outcome"] == "NO_EVALUATED_ASSERTIONS"
    assert result["assertions"]["unevaluated"] == 8


def test_pass_label_cannot_hide_a_false_assertion():
    raw = json.loads(inputs()[0])["record"]["record_canonical"]
    record = json.loads(raw)
    record["assertions"][0]["result"] = False
    record["verdict"].update(n_pass=6, ok=False)
    with pytest.raises(Refusal) as error:
        reader.assertion_projection(record)
    assert error.value.code == "VERDICT_COUNTS_DISAGREE"


def test_canonical_profile_has_no_float_or_key_sort_alias():
    for record in ({"fraction": 1.5}, {"nonascii-\u00e9": True}, {"value": "\ud800"}):
        with pytest.raises(Refusal) as error:
            reader.canonical_bytes(record)
        assert error.value.code == "CANONICAL_VALUE_UNSUPPORTED"
    assert (
        reader.canonical_bytes({"b": [True, None, 3], "a": "\u00e9"})
        == b'{"a":"\xc3\xa9","b":[true,null,3]}'
    )


def test_noncanonical_bytes_are_not_reserialized_before_verification():
    original, key, args = inputs()
    obj = json.loads(original)
    obj["record"]["record_canonical"] += "\n"
    digest_now = digest(obj["record"]["record_canonical"].encode())
    obj["sha"] = obj["record"]["sha"] = args["record_sha256"] = digest_now
    with pytest.raises(Refusal) as error:
        reader.read(json.dumps(obj).encode(), key, **args)
    assert error.value.code == "RECORD_NOT_CANONICAL"


def test_crypto_unavailable_refuses_instead_of_guessing(monkeypatch):
    def unavailable(_):
        raise UnsupportedAlgorithm("controlled backend refusal")

    monkeypatch.setattr(reader.Ed25519PublicKey, "from_public_bytes", unavailable)
    raw, key, args = inputs()
    with pytest.raises(Refusal) as error:
        reader.read(raw, key, **args)
    assert error.value.code == "CRYPTO_UNAVAILABLE"


def test_cli_reports_actual_match_mismatch_and_malformed_inputs(capsys, tmp_path):
    row = PINS["a"]
    argv = [str(FIXTURES / row["envelope_file"]), str(FIXTURES / row["key_file"])]
    for key in ["record_sha256", "key_document_sha256", "key_url"]:
        argv += ["--" + key.replace("_", "-"), row[key]]
    argv += ["--operator", "Probity / finite CLI author-run", "--target", A]
    assert reader.main(argv) == 0
    assert json.loads(capsys.readouterr().out)["target_matches"]
    argv[-1] = A + "/"
    assert reader.main(argv) == 1
    assert json.loads(capsys.readouterr().out)["outcome"] == "TARGET_MISMATCH"
    wrong = tmp_path / "wrong"
    wrong.write_text("{")
    argv[0] = str(wrong)
    assert reader.main(argv) == 2
    assert json.loads(capsys.readouterr().out)["reason"] == "JSON_MALFORMED"
    with pytest.raises(SystemExit) as error:
        reader.main(["--runner", "legacy"])
    assert error.value.code == 2
