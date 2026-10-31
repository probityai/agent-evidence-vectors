"""The DSSE binding's contract: round trips, threshold counting, every refusal."""

from __future__ import annotations

import base64
import json

import pytest

from conftest import bound_crate
# _native is the compiled extension; the checker reads its .pyi stub and has no source for it
from jcs_admit import _native, dsse  # pyright: ignore[reportMissingModuleSource]

PT = "application/vnd.in-toto+json"


def signer(seed: int, key_id: str | None) -> dsse.Ed25519Signer:
    return dsse.Ed25519Signer(bytes([seed]) * 32, key_id=key_id)


def env_dict(envelope: bytes) -> dict:
    return json.loads(envelope)


def encode(d: dict) -> bytes:
    return json.dumps(d).encode()


def refusal(fn, *args) -> dsse.DsseError:
    with pytest.raises(dsse.DsseError) as info:
        fn(*args)
    return info.value


def test_round_trip_returns_the_signed_bytes_and_type():
    s = signer(1, "harness")
    envelope = dsse.sign(PT, b'{"a":1}', s)
    got = dsse.verify(envelope, s.verifier())
    assert (got.payload_type, got.payload, got.accepted_keys) == (PT, b'{"a":1}', ("harness",))
    assert type(got.payload) is bytes
    assert env_dict(envelope)["signatures"][0]["keyid"] == "harness"


def test_keys_expose_public_bytes_and_ids():
    s = signer(2, "a")
    v = s.verifier()
    assert len(s.public_key) == 32 and s.public_key == v.public_key
    assert dsse.Ed25519Verifier(v.public_key, key_id="a").public_key == v.public_key
    assert (s.key_id, v.key_id) == ("a", "a")
    assert signer(2, None).key_id is None
    assert "a" in repr(s) and s.public_key.hex() in repr(v)


def test_secret_key_is_not_in_the_repr():
    seed = bytes(range(32))
    assert seed.hex() not in repr(dsse.Ed25519Signer(seed))


def test_two_distinct_keys_meet_a_two_of_two():
    a, b = signer(1, "harness"), signer(2, "witness")
    envelope = dsse.sign(PT, b"x", [a, b])
    got = dsse.verify_threshold(envelope, [a.verifier(), b.verifier()], 2)
    assert got.accepted_keys == ("harness", "witness")


def test_one_signature_copied_five_times_has_one_key_behind_it():
    a, b = signer(1, "a"), signer(2, "b")
    d = env_dict(dsse.sign(PT, b"x", a))
    d["signatures"] = d["signatures"] * 5
    err = refusal(dsse.verify_threshold, encode(d), [a.verifier(), b.verifier()], 2)
    assert (err.variant, err.fields) == ("ThresholdNotMet", {"accepted": 1, "threshold": 2})
    assert dsse.verify_threshold(encode(d), [a.verifier(), b.verifier()], 1).accepted_keys == ("a",)


def test_two_labels_for_one_key_do_not_count_twice():
    a = signer(1, "a")
    alias = dsse.Ed25519Verifier(a.public_key, key_id="b")
    envelope = dsse.sign(PT, b"x", a)
    err = refusal(dsse.verify_threshold, envelope, [a.verifier(), alias], 2)
    assert (err.variant, err.fields) == ("DuplicateKeyIdentity", {"first": 0, "second": 1})


def test_a_wrong_keyid_hint_does_not_block_a_valid_signature():
    a = signer(1, "a")
    d = env_dict(dsse.sign(PT, b"x", a))
    d["signatures"][0]["keyid"] = "somebody-else"
    assert dsse.verify(encode(d), a.verifier()).payload == b"x"


def test_an_untrusted_extra_signature_is_skipped_not_fatal():
    a, mallory = signer(1, "a"), signer(9, "m")
    envelope = dsse.sign(PT, b"x", [mallory, a])
    assert dsse.verify(envelope, a.verifier()).accepted_keys == ("a",)


def test_a_tampered_payload_or_swapped_type_names_a_signature_failure():
    a = signer(1, "a")
    d = env_dict(dsse.sign(PT, b"x", a))
    tampered = dict(d, payload=base64.b64encode(b"y").decode())
    swapped = dict(d, payloadType="application/json")
    for bad in (tampered, swapped):
        err = refusal(dsse.verify, encode(bad), a.verifier())
        assert (err.variant, err.fields) == (
            "NoValidSignature",
            {"entries": 1, "keys": 1, "mismatched_keys": ["a"]},
        )


def test_a_signature_by_an_untrusted_key_names_no_mismatched_key():
    a, b = signer(1, "a"), signer(2, "b")
    err = refusal(dsse.verify, dsse.sign(PT, b"x", a), b.verifier())
    assert (err.variant, err.fields) == (
        "NoValidSignature",
        {"entries": 1, "keys": 1, "mismatched_keys": []},
    )


def test_both_canonical_alphabets_verify_and_noncanonical_base64_is_refused():
    a = signer(1, "a")
    payload = bytes([0xFB, 0xFF])  # '+/' in standard, '-_' in URL-safe
    d = env_dict(dsse.sign(PT, payload, a))
    url = dict(d, payload=base64.urlsafe_b64encode(payload).decode())
    assert dsse.verify(encode(url), a.verifier()).payload == payload
    # 'eA==' and 'eB==' both decode to b'x' under a lenient decoder.
    lenient = dict(d, payload="eB==")
    err = refusal(dsse.verify, encode(lenient), a.verifier())
    assert (err.variant, err.fields) == ("NonCanonicalBase64", {"field": "payload"})


# Every refusal the crate can raise, reached through the binding. `Signing` has
# no path through the ed25519 backend.
def test_every_reachable_refusal_is_mapped():
    a, b = signer(1, "a"), signer(2, "b")
    good = env_dict(dsse.sign(PT, b"x", a))
    cases = {
        "InvalidKey": lambda: dsse.Ed25519Signer(b"short"),
        "MalformedEnvelope": lambda: dsse.verify(b"{}", a.verifier()),
        "NoSignatures": lambda: dsse.verify(encode(dict(good, signatures=[])), a.verifier()),
        "ZeroThreshold": lambda: dsse.verify_threshold(encode(good), [a.verifier()], 0),
        "EmptyPayloadType": lambda: dsse.sign("", b"x", a),
        "TooManySignatures": lambda: dsse.verify(
            encode(dict(good, signatures=good["signatures"] * (dsse.MAX_SIGNATURES + 1))), a.verifier()
        ),
        "DuplicateKeyId": lambda: dsse.verify_threshold(
            encode(good), [a.verifier(), dsse.Ed25519Verifier(b.public_key, key_id="a")], 2
        ),
        "UnidentifiedKey": lambda: dsse.verify_threshold(encode(good), [signer(1, None).verifier(), b.verifier()], 2),
        "NoValidSignature": lambda: dsse.verify(encode(good), b.verifier()),
        "ThresholdNotMet": lambda: dsse.verify_threshold(
            encode(dict(good, signatures=good["signatures"] * 5)), [a.verifier(), b.verifier()], 2
        ),
        "NonCanonicalBase64": lambda: dsse.verify(
            encode(dict(good, signatures=[{"sig": "not base64!"}])), a.verifier()
        ),
    }
    for variant, call in cases.items():
        err = refusal(call)
        assert err.variant == variant, (variant, err.variant, str(err))
        assert isinstance(err, ValueError)
    shapes = {
        "InvalidKey": str,  # a tuple variant: its one field, bare
        "MalformedEnvelope": str,
        "NoSignatures": type(None),  # a unit variant
        "ZeroThreshold": type(None),
        "NoValidSignature": dict,  # a struct variant
        "ThresholdNotMet": dict,
    }
    for variant, shape in shapes.items():
        assert isinstance(refusal(cases[variant]).fields, shape), variant


def test_the_message_is_the_crates_display_text():
    a = signer(1, "a")
    err = refusal(dsse.verify_threshold, dsse.sign(PT, b"x", a), [a.verifier()], 0)
    assert str(err) == "a threshold of zero accepts an unsigned envelope"


def test_sign_needs_at_least_one_signer():
    with pytest.raises(ValueError, match="at least one signer"):
        dsse.sign(PT, b"x", [])


@pytest.mark.parametrize("bad", ["envelope", bytearray(b"{}"), None])
def test_envelopes_are_bytes(bad):
    with pytest.raises(TypeError):
        dsse.verify(bad, signer(1, "a").verifier())


def test_signers_and_keys_are_typed():
    with pytest.raises(TypeError):
        dsse.sign(PT, b"x", "not a signer")  # pyright: ignore[reportArgumentType]  # deliberate wrong type
    with pytest.raises(TypeError):
        dsse.verify_threshold(dsse.sign(PT, b"x", signer(1, "a")), [b"\x00" * 32], 1)  # pyright: ignore[reportArgumentType]  # deliberate wrong type


def test_the_reported_version_is_the_version_cargo_linked():
    assert dsse.DSSE_VERSION == bound_crate("dsse").version
    assert dsse.MAX_SIGNATURES == 1024


def test_types_live_where_users_import_them():
    for name in ("DsseError", "Ed25519Signer", "Ed25519Verifier", "VerifiedPayload"):
        obj = getattr(dsse, name)
        assert obj is getattr(_native, name)
        assert obj.__module__ == "jcs_admit.dsse"
