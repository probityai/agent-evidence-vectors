"""Walk a public A2A agent card, check its signatures, and sign what was seen.

``walk`` fetches a card and the JWKS its signatures name, keeps both byte for
byte, runs the retained-field ES256 gate over the served card, and signs one
record of the result with an Ed25519 key. ``verify`` repeats every check offline
from the retained bytes: the record signature under the pinned walk key, both
body digests, and the gate's per-signature results.

The envelope matches the NENRIN witness record shape: ``record_canonical`` is
sorted-key, no-space ASCII JSON with integer numbers, and the Ed25519 signature
covers exactly its UTF-8 bytes.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

import retain_gate

HERE = Path(__file__).resolve().parent
PURPOSE = "a2a-card-signature-walk-v1: "
WALKER = "https://github.com/probityai/agent-evidence-atlas"
GATE_SOURCE = (
    "https://github.com/probityai/agent-evidence-vectors/blob/"
    "9e596fbff7bb29809d38319aebb56f2141923eb2/"
    "interop/a2a-s3-retain-2026-10-01/retain_gate.py"
)
GATE_SHA256 = "6313158bd50a5b3db15ae5d8cc7f34aca9d5c747f52749ae3f8b668198c12742"
PAYLOAD_RULE = (
    "RFC 8785 over the served card with the top-level signatures member removed"
)
DOES_NOT_ESTABLISH = [
    "who operates the host or controls the key",
    "that the key was the host's key at any time other than the walk",
    "anything about the agent's behaviour or responses",
    "that a signature refused here is invalid under another canonical form",
]
MAX_BODY = 1024 * 1024
SEED_ENV = "WALK_ED25519_SEED_B64"
USER_AGENT = "agent-evidence-atlas-a2a-card-walk/1 (+" + WALKER + ")"


class WalkError(ValueError):
    """A walk or a retained walk falls outside this profile."""


def canonical(value: dict) -> bytes:
    """Sorted-key, no-space ASCII JSON; floats are refused."""
    _no_floats(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _no_floats(value) -> None:
    if isinstance(value, float):
        raise WalkError("record carries a non-integer number")
    if isinstance(value, dict):
        for item in value.values():
            _no_floats(item)
    if isinstance(value, list):
        for item in value:
            _no_floats(item)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text, validate=True)
    except (ValueError, TypeError) as error:
        raise WalkError("invalid base64") from error


def check_result(card_raw: bytes, jwks_raw: bytes) -> dict:
    """Run the gate over served bytes and return the per-signature result."""
    card = retain_gate.load_json(card_raw)
    jwks = retain_gate.load_json(jwks_raw)
    signatures = card.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise WalkError("card carries no signatures")
    headers = []
    for signature in signatures:
        if not isinstance(signature, dict):
            raise WalkError("signature entry is not an object")
        header = retain_gate.load_json(
            retain_gate.decode_base64url(signature.get("protected", ""))
        )
        headers.append(header)
    kids = {header.get("kid") for header in headers}
    if len(kids) != 1:
        raise WalkError("signatures name more than one key")
    kid = kids.pop()
    keys = [
        k for k in jwks.get("keys", []) if isinstance(k, dict) and k.get("kid") == kid
    ]
    if len(keys) != 1:
        raise WalkError("JWKS does not hold exactly one key with the signature kid")
    result = retain_gate.admit(card, keys[0])
    return {
        "count": len(signatures),
        "kid": kid,
        "admitted": result.admitted,
        "results": [
            {
                "index": index,
                "alg": header.get("alg"),
                "kid": header.get("kid"),
                "jku": header.get("jku"),
                "verified": verified,
            }
            for index, (header, verified) in enumerate(
                zip(headers, result.signature_results, strict=True)
            )
        ],
    }


def jku_of(card_raw: bytes, card_url: str) -> str:
    """The one same-host jku the card's signatures name."""
    card = retain_gate.load_json(card_raw)
    jkus = set()
    for signature in card.get("signatures") or []:
        header = retain_gate.load_json(
            retain_gate.decode_base64url(signature.get("protected", ""))
        )
        jkus.add(header.get("jku"))
    if len(jkus) != 1 or not isinstance(next(iter(jkus)), str):
        raise WalkError("signatures do not name exactly one jku")
    jku = jkus.pop()
    if urllib.parse.urlsplit(jku).netloc != urllib.parse.urlsplit(card_url).netloc:
        raise WalkError("jku is not on the card's host")
    if urllib.parse.urlsplit(jku).scheme != "https":
        raise WalkError("jku is not https")
    return jku


def build_record(
    card_url: str, card_raw: bytes, jwks_url: str, jwks_raw: bytes, walked_at: str
) -> dict:
    gate_raw = (HERE / "retain_gate.py").read_bytes()
    if sha256(gate_raw) != GATE_SHA256:
        raise WalkError("verifier source differs from its pin")
    return {
        "purpose": PURPOSE + card_url,
        "walker": WALKER,
        "walked_at": walked_at,
        "card": {
            "url": card_url,
            "body_sha256": sha256(card_raw),
            "body_bytes": len(card_raw),
        },
        "jwks": {
            "url": jwks_url,
            "body_sha256": sha256(jwks_raw),
            "body_bytes": len(jwks_raw),
            "same_host_as_card": True,
        },
        "verifier": {
            "policy": retain_gate.POLICY,
            "source": GATE_SOURCE,
            "source_sha256": GATE_SHA256,
            "payload": PAYLOAD_RULE,
        },
        "card_signature": check_result(card_raw, jwks_raw),
        "does_not_establish": DOES_NOT_ESTABLISH,
    }


def sign(record: dict, seed: bytes) -> dict:
    key = Ed25519PrivateKey.from_private_bytes(seed)
    raw = canonical(record)
    public = key.public_key().public_bytes_raw()
    return {
        "record": {
            "sha": sha256(raw),
            "record_canonical": raw.decode("ascii"),
            "signature_ed25519_b64": _b64(key.sign(raw)),
            "public_key_ed25519_b64": _b64(public),
        }
    }


def verify(directory: Path, key_document: Path) -> dict:
    """Recheck a retained walk offline; return its record or raise WalkError."""
    envelope = retain_gate.load_json((directory / "record.json").read_bytes())
    inner = envelope.get("record") if isinstance(envelope, dict) else None
    if not isinstance(inner, dict):
        raise WalkError("envelope has no record")
    pinned = retain_gate.load_json(key_document.read_bytes()).get(
        "public_key_ed25519_b64"
    )
    if not isinstance(pinned, str) or inner.get("public_key_ed25519_b64") != pinned:
        raise WalkError("record key differs from the pinned walk key")
    text = inner.get("record_canonical")
    if not isinstance(text, str):
        raise WalkError("record_canonical is missing")
    raw = text.encode("utf-8")
    if inner.get("sha") != sha256(raw):
        raise WalkError("record hash differs")
    try:
        Ed25519PublicKey.from_public_bytes(_unb64(pinned)).verify(
            _unb64(inner.get("signature_ed25519_b64", "")), raw
        )
    except (InvalidSignature, ValueError) as error:
        raise WalkError("record signature does not verify") from error
    record = retain_gate.load_json(raw)
    if canonical(record) != raw:
        raise WalkError("record is not in canonical form")
    card_raw = (directory / "agent-card.json").read_bytes()
    jwks_raw = (directory / "jwks.json").read_bytes()
    if record["card"]["body_sha256"] != sha256(card_raw):
        raise WalkError("retained card differs from the signed digest")
    if record["jwks"]["body_sha256"] != sha256(jwks_raw):
        raise WalkError("retained JWKS differs from the signed digest")
    if jku_of(card_raw, record["card"]["url"]) != record["jwks"]["url"]:
        raise WalkError("signed JWKS URL is not the card's jku")
    if record["card_signature"] != check_result(card_raw, jwks_raw):
        raise WalkError("gate result differs from the signed result")
    if record["verifier"]["source_sha256"] != sha256(
        (HERE / "retain_gate.py").read_bytes()
    ):
        raise WalkError("verifier source differs from the signed pin")
    return record


def _fetch(url: str) -> bytes:
    request = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": USER_AGENT}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        if response.status != 200 or response.geturl() != url:
            raise WalkError("fetch did not answer 200 at the requested URL: " + url)
        body = response.read(MAX_BODY + 1)
    if len(body) > MAX_BODY:
        raise WalkError("response exceeds one MiB")
    return body


def walk(card_url: str, out: Path, seed: bytes) -> dict:
    card_raw = _fetch(card_url)
    jwks_url = jku_of(card_raw, card_url)
    jwks_raw = _fetch(jwks_url)
    walked_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    envelope = sign(
        build_record(card_url, card_raw, jwks_url, jwks_raw, walked_at), seed
    )
    out.mkdir(parents=True, exist_ok=False)
    (out / "agent-card.json").write_bytes(card_raw)
    (out / "jwks.json").write_bytes(jwks_raw)
    (out / "record.json").write_text(
        json.dumps(envelope, indent=2) + "\n", encoding="ascii"
    )
    return envelope


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    walk_cmd = sub.add_parser("walk")
    walk_cmd.add_argument("card_url")
    walk_cmd.add_argument("out", type=Path)
    verify_cmd = sub.add_parser("verify")
    verify_cmd.add_argument("directory", type=Path)
    verify_cmd.add_argument("--key", type=Path, default=HERE / "walk-key.json")
    args = parser.parse_args(argv)
    try:
        if args.command == "walk":
            seed = _unb64(os.environ.get(SEED_ENV, ""))
            if len(seed) != 32:
                raise WalkError(SEED_ENV + " must hold a 32-byte Ed25519 seed")
            envelope = walk(args.card_url, args.out, seed)
            print(envelope["record"]["sha"])
            return 0
        record = verify(args.directory, args.key)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("refused: " + str(error), file=sys.stderr)
        return 2
    print(json.dumps(record["card_signature"], sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
