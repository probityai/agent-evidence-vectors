"""Ed25519 against the RFC 8032 test vectors, and the DSSE envelope around it."""

import base64
import copy

import pytest
from agent_evidence_admission import dsse, ed25519

# RFC 8032, section 7.1, tests 1 and 2.
RFC = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
]
SEED = bytes(range(32))
OTHER = bytes(range(1, 33))


@pytest.mark.parametrize("seed,public,message,signature", RFC)
def test_rfc_vectors(seed, public, message, signature):
    assert ed25519.public_key(bytes.fromhex(seed)).hex() == public
    assert ed25519.sign(bytes.fromhex(seed), bytes.fromhex(message)).hex() == signature
    assert ed25519.verify(bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature))


def test_verify_refuses_what_is_not_a_valid_signature():
    public = ed25519.public_key(SEED)
    signature = ed25519.sign(SEED, b"message")
    assert ed25519.verify(public, b"message", signature)
    assert not ed25519.verify(public, b"messagE", signature)
    assert not ed25519.verify(ed25519.public_key(OTHER), b"message", signature)
    assert not ed25519.verify(public, b"message", signature[:-1])
    assert not ed25519.verify(public[:-1], b"message", signature)
    # s at or above the group order is malleable and refused.
    big_s = (int.from_bytes(signature[32:], "little") + ed25519._Q).to_bytes(32, "little")
    assert not ed25519.verify(public, b"message", signature[:32] + big_s)
    # A point that does not decode: y = 2 has no x on the curve.
    assert not ed25519.verify(public, b"message", (2).to_bytes(32, "little") + signature[32:])
    assert not ed25519.verify((2).to_bytes(32, "little"), b"message", signature)
    # y at or above the field prime does not decode.
    assert not ed25519.verify(public, b"message", (2**255 - 19).to_bytes(32, "little") + signature[32:])


def test_decode_edge_cases():
    # y = 1 is the identity: x is zero, so a set sign bit is not a point.
    assert ed25519._decompress((1).to_bytes(32, "little")) is not None
    assert ed25519._decompress(((1 << 255) | 1).to_bytes(32, "little")) is None


def test_seed_must_be_32_bytes():
    with pytest.raises(ValueError, match="32 bytes"):
        ed25519.public_key(b"short")


def test_envelope_round_trip():
    public = ed25519.public_key(SEED)
    trusted = {dsse.keyid(public): public}
    envelope = dsse.make_envelope(b'{"a":1}', SEED)
    opened = dsse.open_envelope(envelope, trusted)
    assert opened.payload == b'{"a":1}'
    assert opened.keyid == dsse.keyid(public)


def _trusted():
    public = ed25519.public_key(SEED)
    return {dsse.keyid(public): public}


def _mutations():
    base = dsse.make_envelope(b'{"a":1}', SEED)
    cases = {}

    def mutate(name, edit):
        envelope = copy.deepcopy(base)
        edit(envelope)
        cases[name] = envelope

    mutate("payload-edited", lambda e: e.update(payload=base64.b64encode(b'{"a":2}').decode()))
    mutate("wrong-type", lambda e: e.update(payloadType="text/plain"))
    mutate("no-signatures", lambda e: e.update(signatures=[]))
    mutate("signatures-not-list", lambda e: e.update(signatures="x"))
    mutate("entry-not-object", lambda e: e.update(signatures=["x"]))
    mutate("unknown-keyid", lambda e: e["signatures"][0].update(keyid="0" * 64))
    mutate("keyid-not-string", lambda e: e["signatures"][0].update(keyid=7))
    mutate("sig-not-base64", lambda e: e["signatures"][0].update(sig="!!"))
    mutate("sig-not-string", lambda e: e["signatures"][0].update(sig=1))
    mutate("payload-not-base64", lambda e: e.update(payload="!!"))
    mutate("payload-not-string", lambda e: e.update(payload=1))
    mutate("payload-not-canonical", lambda e: e.update(payload=e["payload"].rstrip("=") ))
    cases["not-an-object"] = []
    return cases


@pytest.mark.parametrize("name", sorted(_mutations()))
def test_envelope_refusals(name):
    with pytest.raises(ValueError):
        dsse.open_envelope(_mutations()[name], _trusted())


def test_envelope_refuses_a_mapping_that_lies_about_a_keyid():
    envelope = dsse.make_envelope(b"{}", SEED)
    stranger = ed25519.public_key(OTHER)
    with pytest.raises(ValueError, match="no signature verified"):
        dsse.open_envelope(envelope, {dsse.keyid(ed25519.public_key(SEED)): stranger})


def test_envelope_accepts_a_second_signature_when_the_first_is_untrusted():
    envelope = dsse.make_envelope(b"{}", SEED)
    envelope["signatures"].insert(0, {"keyid": "f" * 64, "sig": base64.b64encode(b"x" * 64).decode()})
    assert dsse.open_envelope(envelope, _trusted()).payload == b"{}"


def test_pae_binds_the_payload_type():
    assert dsse.pae("a/b", b"xyz") == b"DSSEv1 3 a/b 3 xyz"
