"""The cross-language DSSE vectors, through the binding.

`vectors/cross_lang_signing.json` in the bound `dsse` release was written by the
DSSE reference Go implementation (go-securesystemslib/dsse, at the version in
its `generated_by` member): eleven cases across five payload types, each with
the pre-image Go built, a real ed25519 signature over it, and the envelope Go
emitted. The file is read from the release's own registry source; nothing in
it was produced by the crate or by this binding.
"""

from __future__ import annotations

import base64
import json

import pytest

from conftest import bound_crate
import jcs_admit as jcs
from jcs_admit import dsse

DOC = json.loads((bound_crate("dsse").root / "vectors/cross_lang_signing.json").read_text(encoding="utf-8"))
FIXTURES = DOC["fixtures"]
IDS = [f["name"] for f in FIXTURES]

# The fixed SubjectPublicKeyInfo header of an ed25519 key.
SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")


def b64(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def fixture_key() -> dsse.Ed25519Verifier:
    body = "".join(line for line in DOC["public_key_pem"].splitlines() if not line.startswith("-----"))
    der = b64(body)
    assert len(der) == 44 and der[:12] == SPKI_PREFIX
    return dsse.Ed25519Verifier(der[12:], key_id=DOC["key_id"])


KEY = fixture_key()


def test_the_file_is_whole():
    assert DOC["generated_by"]["implementation"] == "github.com/secure-systems-lab/go-securesystemslib/dsse"
    assert len(FIXTURES) == 11
    assert len({f["payload_type"] for f in FIXTURES}) == 5


@pytest.mark.parametrize("f", FIXTURES, ids=IDS)
def test_pae_matches_the_go_implementation_byte_for_byte(f):
    assert dsse.pae(f["payload_type"], b64(f["canonical_b64"])) == b64(f["pae_b64"])


@pytest.mark.parametrize("f", FIXTURES, ids=IDS)
def test_the_go_envelope_verifies_through_the_binding(f):
    got = dsse.verify(json.dumps(f["envelope"]).encode(), KEY)
    assert got.payload == b64(f["canonical_b64"])
    assert got.payload_type == f["payload_type"]
    assert got.accepted_keys == (DOC["key_id"],)


@pytest.mark.parametrize("f", FIXTURES, ids=IDS)
def test_signing_with_the_published_seed_reproduces_gos_signature(f):
    # ed25519 is deterministic, so this checks the signing path, not only the
    # verifying one.
    signer = dsse.Ed25519Signer(bytes.fromhex(DOC["test_seed_hex"]), key_id=DOC["key_id"])
    assert signer.public_key == KEY.public_key
    env = json.loads(dsse.sign(f["payload_type"], b64(f["canonical_b64"]), signer))
    assert env["payload"] == f["canonical_b64"]
    assert env["payloadType"] == f["payload_type"]
    assert env["signatures"] == [{"keyid": DOC["key_id"], "sig": f["signature_b64"]}]


@pytest.mark.parametrize("f", [f for f in FIXTURES if f["payload_type"].endswith("+json")], ids=lambda f: f["name"])
def test_every_signed_json_body_is_already_rfc8785_canonical(f):
    # The two bindings meet here: the bytes Go signed are the bytes jcs admits
    # unchanged.
    body = b64(f["canonical_b64"])
    assert jcs.admit(body) == body


def test_binary_payload_survives_verbatim():
    f = next(f for f in FIXTURES if f["name"] == "binary_batch_root")
    payload = dsse.verify(json.dumps(f["envelope"]).encode(), KEY).payload
    assert len(payload) == 40 and payload.startswith(bytes(7) + b"\x08")
    with pytest.raises(UnicodeDecodeError):
        payload.decode("utf-8")


def test_a_real_signature_does_not_verify_under_another_payload_type():
    record = next(f for f in FIXTURES if f["name"] == "record_0")
    other = next(f for f in FIXTURES if f["name"] == "statement_0")
    env = dict(record["envelope"], payloadType=other["payload_type"])
    with pytest.raises(dsse.DsseError) as info:
        dsse.verify(json.dumps(env).encode(), KEY)
    assert info.value.variant == "NoValidSignature"
