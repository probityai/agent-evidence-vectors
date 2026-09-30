#!/usr/bin/env python3
"""Rebuild the signed ACP authorship pair with a published test key."""

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


HERE = Path(__file__).resolve().parent
TYPE = b"application/vnd.in-toto+json"
HEAD = "7c4a8d09ca3762af61e59520943dc26494f8941b"
SEED = hashlib.sha256(b"agent-evidence-vectors/acp-test-key/v1").digest()


def pae(payload: bytes) -> bytes:
    return b"DSSEv1 " + str(len(TYPE)).encode() + b" " + TYPE + b" " + str(len(payload)).encode() + b" " + payload


def envelope(payload: bytes, signature: bytes) -> dict:
    return {
        "payload": base64.b64encode(payload).decode(),
        "payloadType": TYPE.decode(),
        "signatures": [{"keyid": "test-author", "sig": base64.b64encode(signature).decode()}],
    }


def main() -> None:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "github:acme/api:pr:421", "digest": {"gitCommit": HEAD}}],
        "predicateType": "https://noru.tech/spec/ai-change-provenance/provenance/v0.1",
        "predicate": {
            "spec_version": "0.1",
            "agent": {"name": "codex", "version": "2026.9.1"},
            "operator": {"id": "github:alice"},
            "session": {"id": "sess_7f3a9c", "started_at": "2026-09-18T09:12:00Z"},
            "change": {
                "base_commit": "5d41402abc4b2a76b9719d911017c592e2c1a5f0",
                "head_commit": HEAD,
            },
        },
    }
    # This is deliberately not JCS: a DSSE verifier must check the signed bytes.
    payload = json.dumps(statement, indent=2).encode()
    key = Ed25519PrivateKey.from_private_bytes(SEED)
    signature = key.sign(pae(payload))
    changed = payload.replace(b"github:alice", b"github:alixe", 1)
    assert changed != payload and len(changed) == len(payload)

    (HERE / "public.key").write_text(
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() + "\n",
        encoding="ascii",
    )
    (HERE / "expected-head.txt").write_text(HEAD + "\n", encoding="ascii")
    for name, data in (("valid", payload), ("changed-operator", changed)):
        path = HERE / "cases" / (name + ".json")
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(envelope(data, signature), indent=2) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
