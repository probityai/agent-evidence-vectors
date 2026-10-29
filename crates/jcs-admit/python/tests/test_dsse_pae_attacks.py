"""PAE attack vectors through the binding.

Ported from the bound `dsse` release's `tests/pae_attacks.rs`: each case is a
payload type or payload built to break the length-prefix discipline that makes
the pre-authentication encoding injective. The second half carries the same
cases through signing and verification, where a length-prefix mistake turns a
signature over one message into a signature over another.
"""

from __future__ import annotations

import pytest

from jcs_admit import dsse


def test_length_prefix_counts_bytes_not_characters():
    # "tyb\u00e9" (e with an acute accent) is four characters and five bytes.
    assert dsse.pae("tyb\u00e9", b"x") == b"DSSEv1 5 tyb\xc3\xa9 1 x"


def test_length_prefix_counts_bytes_for_astral_characters():
    got = dsse.pae("\U0001f512", b"")
    assert got == b"DSSEv1 4 \xf0\x9f\x94\x92 0 "
    assert not got.startswith(b"DSSEv1 1 ")


def test_payload_type_containing_a_space_is_carried_verbatim():
    assert dsse.pae("a b", b"c") == b"DSSEv1 3 a b 1 c"


def test_payload_type_shaped_like_a_length_field():
    assert dsse.pae("9 not-a-length", b"body") == b"DSSEv1 14 9 not-a-length 4 body"


def test_empty_payload_keeps_its_trailing_space():
    got = dsse.pae("t", b"")
    assert got == b"DSSEv1 1 t 0 "
    assert got.endswith(b" ")


def test_empty_payload_type_keeps_both_spaces():
    got = dsse.pae("", b"x")
    assert got == b"DSSEv1 0  1 x"
    assert got[7:10] == b"0  "


def test_both_members_empty():
    assert dsse.pae("", b"") == b"DSSEv1 0  0 "


@pytest.mark.parametrize("n", [0, 1, 9, 10, 11, 99, 100, 101, 255, 1000])
def test_length_prefix_has_no_leading_zeros(n):
    got = dsse.pae("t", b"z" * n)
    assert got.startswith(f"DSSEv1 1 t {n} ".encode())
    assert not got.startswith(f"DSSEv1 1 t 0{n} ".encode())


def test_encoding_is_injective_across_the_type_body_boundary():
    assert dsse.pae("ab", b"c") != dsse.pae("a", b"bc")
    assert dsse.pae("a", b"b") != dsse.pae("", b"ab")
    assert dsse.pae("", b"ab") != dsse.pae("ab", b"")


def test_payload_that_is_itself_a_valid_pae_stays_nested():
    inner = dsse.pae("inner-type", b"inner-body")
    outer = dsse.pae("outer-type", inner)
    assert outer != inner
    assert outer.startswith(f"DSSEv1 10 outer-type {len(inner)} ".encode())
    assert outer.endswith(inner)
    assert outer.count(b"DSSEv1") == 2


def test_payload_need_not_be_valid_utf8():
    payload = bytes([0xFF, 0xFE, 0x00, 0x80])
    assert dsse.pae("t", payload) == b"DSSEv1 1 t 4 \xff\xfe\x00\x80"


def test_payload_type_is_case_sensitive():
    assert dsse.pae("Application/JSON", b"x") != dsse.pae("application/json", b"x")


def test_payload_type_must_be_str_and_payload_bytes():
    with pytest.raises(TypeError):
        dsse.pae(b"t", b"x")  # pyright: ignore[reportArgumentType]  # deliberate wrong type
    with pytest.raises(TypeError):
        dsse.pae("t", "x")  # pyright: ignore[reportArgumentType]  # deliberate wrong type


# ---- the same boundaries, end to end ----------------------------------------

SIGNER = dsse.Ed25519Signer(bytes([7]) * 32, key_id="k")
KEY = SIGNER.verifier()

# Pairs whose naive concatenation is identical but whose PAE differs: moving the
# boundary between type and body must break the signature.
SHIFTED = [
    (("ab", b"c"), ("a", b"bc")),
    (("a", b"b"), ("a b", b"")),
    (("tyb\u00e9", b"x"), ("tyb\u00c3\u00a9", b"x")),
    (("Application/JSON", b"x"), ("application/json", b"x")),
]


@pytest.mark.parametrize(("signed", "presented"), SHIFTED)
def test_a_signature_never_verifies_with_the_boundary_moved(
    signed: tuple[str, bytes], presented: tuple[str, bytes]
) -> None:
    import base64
    import json

    env = json.loads(dsse.sign(*signed, SIGNER))
    env["payloadType"] = presented[0]
    env["payload"] = base64.b64encode(presented[1]).decode()
    with pytest.raises(dsse.DsseError) as info:
        dsse.verify(json.dumps(env).encode(), KEY)
    assert info.value.variant == "ThresholdNotMet"


def test_a_signed_pae_payload_verifies_only_as_the_outer_type():
    inner = dsse.pae("inner-type", b"inner-body")
    env = dsse.sign("outer-type", inner, SIGNER)
    got = dsse.verify(env, KEY)
    assert (got.payload_type, got.payload) == ("outer-type", inner)
