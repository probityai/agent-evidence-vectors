"""The OpenTimestamps reader accepts one byte string per proof.

A proof that a varuint spells with a redundant continuation byte, or that
repeats one operation or one attestation at one node, is a second byte string
for the same timestamp. Readers that keep only one branch of a repeated
operation see a different set of attestations from readers that keep both, so
the reader refuses all three shapes rather than choose.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packaging"))
from agent_evidence_vectors import auditrecord as ar

SUBJECT = b"own-reader strict ots subject"
DIGEST = hashlib.sha256(SUBJECT).digest()
NONCE = bytes(range(16))


def _btc(height: bytes) -> bytes:
    return b"\x00" + ar.OTS_BITCOIN + bytes([len(height)]) + height


def _proof(body: bytes, version: bytes = b"\x01") -> bytes:
    return ar.OTS_MAGIC + version + bytes([ar.OTS_SHA256]) + DIGEST + body


def _append(argument: bytes) -> bytes:
    return bytes([ar.OTS_APPEND, len(argument)]) + argument


HONEST = _append(NONCE) + bytes([ar.OTS_SHA256]) + _btc(b"\x81\x01")


def test_the_minimal_proof_is_read() -> None:
    found = ar.ots_attestations(_proof(HONEST), DIGEST)
    assert [kind for _, kind, _ in found] == [ar.OTS_BITCOIN]


@pytest.mark.parametrize("version", [b"\x81\x00", b"\x81\x80\x00"])
def test_a_non_minimal_version_varuint_is_refused(version: bytes) -> None:
    with pytest.raises(ValueError, match="non-minimal"):
        ar.ots_attestations(_proof(HONEST, version), DIGEST)


def test_a_non_minimal_argument_length_is_refused() -> None:
    padded = bytes([ar.OTS_APPEND, 0x90, 0x00]) + NONCE + bytes([ar.OTS_SHA256]) + _btc(b"\x81\x01")
    with pytest.raises(ValueError, match="non-minimal"):
        ar.ots_attestations(_proof(padded), DIGEST)


def test_a_non_minimal_bitcoin_height_is_refused() -> None:
    body = _append(NONCE) + bytes([ar.OTS_SHA256]) + _btc(b"\x81\x81\x00")
    with pytest.raises(ValueError, match="non-minimal"):
        ar._ots_moment(_proof(body), DIGEST, [])


def test_zero_is_spelled_with_one_byte() -> None:
    assert ar._Reader(b"\x00").varuint() == 0
    with pytest.raises(ValueError, match="non-minimal"):
        ar._Reader(b"\x80\x00").varuint()


@pytest.mark.parametrize("order", ["bogus-first", "honest-first"])
def test_a_repeated_operation_at_one_node_is_refused(order: str) -> None:
    bogus = _append(NONCE) + _btc(b"\x01")
    honest = HONEST
    first, last = (bogus, honest) if order == "bogus-first" else (honest, bogus)
    with pytest.raises(ValueError, match="repeated"):
        ar.ots_attestations(_proof(b"\xff" + first + last), DIGEST)


def test_a_repeated_attestation_at_one_node_is_refused() -> None:
    body = _append(NONCE) + bytes([ar.OTS_SHA256]) + b"\xff" + _btc(b"\x81\x01") + _btc(b"\x81\x01")
    with pytest.raises(ValueError, match="repeated"):
        ar.ots_attestations(_proof(body), DIGEST)


def test_two_different_operations_at_one_node_are_read() -> None:
    other = _append(bytes(16)) + bytes([ar.OTS_SHA256]) + _btc(b"\x82\x01")
    found = ar.ots_attestations(_proof(b"\xff" + HONEST + other), DIGEST)
    assert len(found) == 2
