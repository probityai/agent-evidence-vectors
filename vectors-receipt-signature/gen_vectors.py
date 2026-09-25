#!/usr/bin/env python3
"""Regenerate the receipt-signature corpus byte-identically.

    python3 gen_vectors.py            # write receipts/, keys/, MANIFEST.json, INDEX.md
    python3 gen_vectors.py --check    # refuse when the tree on disk differs

The subject under test is a verifier of signed decision receipts in the
envelope shape of draft-farley-acta-signed-receipts-03 (vendored under
spec-vendored/ and pinned by digest in the manifest). Each member is one
receipt. The verifier is handed the receipt and a JWK Set that lives outside
it, twice: once with the keys' validity windows and once with them removed.

Four members are lifted from giskard09/argentum-core at a pinned commit. They
are not copied: this generator derives the same test keys from the same public
recipe and signs the same payloads, Ed25519 is deterministic, and the build
refuses unless each of those four files and the key set hash to the digests
recorded for them upstream. The other members are this corpus's own.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
import re
import sys
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

HERE = os.path.dirname(os.path.abspath(__file__))


def _load_digest_of() -> Any:
    """The preimage lives in digest.py beside this file, loaded by path.

    By path rather than by module name, because every corpus that owns a
    stdlib preimage names its module digest.py, and an import by name reaches
    whichever of them is first on the search path.
    """
    spec = importlib.util.spec_from_file_location(
        "receipt_signature_digest", os.path.join(HERE, "digest.py")
    )
    if spec is None or spec.loader is None:
        raise SystemExit("FAIL: digest.py beside this generator cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.digest_of


digest_of = _load_digest_of()

SUITE = "receipt-signature-conformance"
SPEC_NAME = "draft-farley-acta-signed-receipts-03"
SPEC_URL = "https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/03/"
SPEC_VENDORED = "spec-vendored/draft-farley-acta-signed-receipts-03.txt"
KEYS_WITH_WINDOWS = "keys/jwks.json"
KEYS_WITHOUT_WINDOWS = "keys/jwks-no-window.json"
SEED_PREFIX = "agent-evidence-vectors/test-only/"

UPSTREAM_REPOSITORY = "giskard09/argentum-core"
UPSTREAM_COMMIT = "541ce84b4f970c1dd3d9e53f2a4562dbbc354e46"
UPSTREAM_PATH = "examples/conformance/farley-receipt-signature"
UPSTREAM_INDEX_SHA256 = "6b9460491cdf479a85d731b4a2c6fb4fef4dde862bba4c2ba3bb91b69e71e9ec"
# The digest of each lifted file at the pinned commit. The build refuses when
# the bytes it produces differ from any of them, which is what makes "lifted
# unchanged" a checked property rather than a sentence.
UPSTREAM_SHA256 = {
    "signature-input-drift.reject.json": (
        "e116653dd041dda0d00164fae31d899a27baffc5c8ee8f5d649fbd7d95313c06"
    ),
    "signature-input-drift.conformant.json": (
        "4f9fe96e52a39bfb332e405381beeca347a3283a491cf81aaa51717ab84ec440"
    ),
    "superseded-key.reject.json": (
        "c4b43c5739979581d7ccac7275c2caf78754f53188ca22ac23ac32d3abaa5508"
    ),
    "superseded-key.conformant.json": (
        "ea8370fb85e1b4b143d88e349fb38581f30a37a86b1d8bdc7539f2cae77cb1ee"
    ),
    "jwks.json": "d87ce8558523c32ed1ee6cd4204ddc02bd074c1f9e2f81161811dc9ccdb3ba1f",
}

# Requirements are quoted from the vendored text, whitespace collapsed, and bound
# to it by digest. The level is the keyword the sentence itself carries, and the
# reader refuses a level the sentence does not contain.
REQUIREMENTS: list[dict[str, str]] = [
    {
        "id": "RS-R-001",
        "section": "6.6",
        "level": "MUST",
        "sentence": (
            "The signature MUST cover the canonical JCS bytes of the _signing input_ directly"
        ),
    },
    {
        "id": "RS-R-002",
        "section": "9.2",
        "level": "SHOULD",
        "sentence": "Verifiers SHOULD check key validity windows when available.",
    },
    {
        "id": "RS-R-003",
        "section": "6.6",
        "level": "MUST",
        "sentence": (
            "implementations MUST NOT pre-hash the canonical bytes (for example with "
            "SHA-256) before signing."
        ),
    },
    {
        "id": "RS-R-004",
        "section": "6.6",
        "level": "MUST",
        "sentence": (
            "An implementation MUST determine the shape before computing the signing "
            "input, and MUST NOT apply one shape's rule to the other"
        ),
    },
    {
        "id": "RS-R-005",
        "section": "6.6",
        "level": "MUST",
        "sentence": (
            "In either shape the object canonicalized MUST NOT contain a signature "
            "member, and that member MUST NOT be included as null or as the empty string"
        ),
    },
]

CONDITIONS: dict[str, dict[str, Any]] = {
    "rs-c-1": {
        "requires": (
            "The signature is computed over JCS(payload), and a verifier recomputes that "
            "byte string rather than trusting the bytes the payload arrived in."
        ),
        "requirements": ["RS-R-001"],
    },
    "rs-c-2": {
        "requires": (
            "A receipt whose issued_at falls outside its key's validity window, as the "
            "external key set publishes it, is not reported valid by a verifier that "
            "applies the window."
        ),
        "requirements": ["RS-R-002"],
    },
    "rs-c-3": {
        "requires": (
            "The window includes valid_from and excludes valid_until, as RFC 7519 treats "
            "nbf and exp. Section 9.2 of the vendored text does not fix the boundary."
        ),
        "requirements": ["RS-R-002"],
    },
    "rs-c-4": {
        "requires": (
            "The canonical bytes are the message given to Ed25519, with no intermediate "
            "hash, so a signature over their SHA-256 digest does not verify."
        ),
        "requirements": ["RS-R-001", "RS-R-003"],
    },
    "rs-c-5": {
        "requires": (
            "An envelope receipt is verified under the envelope rule. A signature made "
            "under the flat rule, over the receipt with its signature member removed, "
            "does not verify as an envelope."
        ),
        "requirements": ["RS-R-004"],
    },
    "rs-c-6": {
        "requires": (
            "A payload that carries a signature member, null included, is refused even "
            "though a signature over its canonical bytes verifies."
        ),
        "requirements": ["RS-R-005"],
    },
}

CODE_REGISTRY = {
    "signature_invalid": (
        "the signature does not verify over JCS(payload) under the key the external key "
        "set resolves for kid"
    ),
    "key_outside_validity_window": (
        "issued_at is before the key's valid_from or at or after its valid_until"
    ),
    "signature_in_signing_input": (
        "the canonicalized object carries a signature member (Section 6.6)"
    ),
}

GRADE_NOTE = (
    "Section 9.2 of draft-03 makes the window check a SHOULD, so a member whose only "
    "defect is the window is indeterminate here: a verifier given the windows that "
    "rejects it with key_outside_validity_window honours Section 9.2, one that accepts "
    "it is reported by name as not honouring it and is not failed, and one that rejects "
    "it without the windows, or with another code, fails. The draft's next revision "
    "makes the check a MUST (Section 5.5 of draft-farley-acta-signed-receipts-04, open "
    "as VeritasActa/drafts#3 and not yet on the datatracker). When that revision is "
    "published these members become reject members and the not-honouring case becomes "
    "a failure."
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def jcs(value: Any) -> bytes:
    """RFC 8785 for the one shape this corpus signs: an object of strings and nulls.

    Member names and values are ASCII, so code-unit order and code-point order
    coincide and sort_keys is the RFC's order. Anything else is refused rather
    than canonicalized by a routine that was never meant for it.
    """
    if isinstance(value, dict):
        for key, item in value.items():
            if not key.isascii():
                raise SystemExit(f"FAIL: non-ASCII member name {key!r}")
            if isinstance(item, dict):
                jcs(item)
            elif item is not None and not (isinstance(item, str) and item.isascii()):
                raise SystemExit(f"FAIL: {key!r} is neither an ASCII string nor null")
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


class TestKey:
    """A test key derived from a public label: nothing it signs means anything."""

    def __init__(self, label: str) -> None:
        self.label = label
        seed = hashlib.sha256((SEED_PREFIX + label).encode()).digest()
        self.private = Ed25519PrivateKey.from_private_bytes(seed)
        self.public = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        # Section 2.1.1: sb:issuer:<first 12 characters of base58(public key)>.
        self.kid = "sb:issuer:" + b58(self.public)[:12]

    def sign(self, message: bytes) -> bytes:
        return self.private.sign(message)


KEY_A = TestKey("key-A-superseded")
KEY_B = TestKey("key-B-current")
WINDOW_A = {"valid_from": "2026-01-01T00:00:00Z", "valid_until": "2026-06-01T00:00:00Z"}
WINDOW_B = {"valid_from": "2026-06-01T00:00:00Z"}


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def key_sets() -> tuple[dict[str, Any], dict[str, Any]]:
    """The external key set, with and without the validity windows.

    The windowed set is upstream's jwks.json. The windowless one is the same keys
    with valid_from and valid_until removed, which is the key source a verifier
    has when the issuer publishes no rotation metadata.
    """
    windowed = {
        "keys": [
            {"kty": "OKP", "crv": "Ed25519", "kid": KEY_A.kid, "x": b64u(KEY_A.public),
             "use": "sig", **WINDOW_A},
            {"kty": "OKP", "crv": "Ed25519", "kid": KEY_B.kid, "x": b64u(KEY_B.public),
             "use": "sig", **WINDOW_B},
        ]
    }
    bare = {
        "keys": [
            {k: v for k, v in key.items() if k not in ("valid_from", "valid_until")}
            for key in windowed["keys"]
        ]
    }
    return windowed, bare


def payload(key: TestKey, issued_at: str = "2026-07-15T12:00:00Z",
            tool_name: str = "payments.transfer") -> dict[str, Any]:
    """A protectmcp:decision payload (Section 3.1.1), in upstream's member order."""
    return {
        "type": "protectmcp:decision",
        "issued_at": issued_at,
        "issuer_id": key.kid,
        "tool_name": tool_name,
        "decision": "allow",
        "policy_digest": "sha256:" + sha(b"test-policy-v1"),
    }


def envelope(body: dict[str, Any], key: TestKey, signature: bytes) -> dict[str, Any]:
    """The envelope shape of Section 2.1: exactly a payload and a signature object."""
    return {"payload": body, "signature": {"alg": "EdDSA", "kid": key.kid, "sig": signature.hex()}}


VALID = {"verdict": "valid", "code": None}


def invalid(code: str) -> dict[str, Any]:
    return {"verdict": "invalid", "code": code}


def member(
    *,
    kind: str,
    condition: str,
    key: TestKey,
    body: dict[str, Any],
    signed_input: bytes,
    expected: dict[str, Any],
    without_windows: dict[str, Any],
    cites: str,
    upstream: str | None = None,
    if_not_honoured: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "kind": kind,
        "conditions": [condition],
        "receipt": envelope(body, key, key.sign(signed_input)),
        "signedInput": signed_input,
        "keyId": key.kid,
        "expected": expected,
        "expectedWithoutWindows": without_windows,
        "cites": cites,
    }
    if if_not_honoured is not None:
        out["expectedIfNotHonoured"] = if_not_honoured
    if upstream is not None:
        out["upstreamFile"] = upstream
    return out


def lifted_members() -> list[dict[str, Any]]:
    """giskard09's two cases, each a defect and its conformant twin."""
    drift = payload(KEY_B)
    pretty = json.dumps(drift, indent=2).encode()
    old = payload(KEY_A)
    inside = payload(KEY_A, "2026-03-15T12:00:00Z")
    return [
        member(
            kind="reject", condition="rs-c-1", key=KEY_B, body=drift, signed_input=pretty,
            expected=invalid("signature_invalid"),
            without_windows=invalid("signature_invalid"),
            upstream="signature-input-drift.reject.json",
            cites=(
                "signed over the pretty-printed payload bytes, Python json.dumps(payload, "
                "indent=2), and not over JCS(payload). The signature verifies over the bytes "
                "it was made over and fails over the bytes a verifier must recompute."
            ),
        ),
        member(
            kind="accept", condition="rs-c-1", key=KEY_B, body=drift, signed_input=jcs(drift),
            expected=VALID, without_windows=VALID,
            upstream="signature-input-drift.conformant.json",
            cites="the same payload, signed over JCS(payload).",
        ),
        member(
            kind="indeterminate", condition="rs-c-2", key=KEY_A, body=old, signed_input=jcs(old),
            expected=invalid("key_outside_validity_window"), without_windows=VALID,
            if_not_honoured=VALID,
            upstream="superseded-key.reject.json",
            cites=(
                "a valid signature under key A with issued_at after key A's valid_until. "
                "issued_at is asserted by the signer, so this catches a key still in use "
                "after an honest rotation, not a compromised key dated into its window. "
                "This is the stale-external-key case."
            ),
        ),
        member(
            kind="accept", condition="rs-c-2", key=KEY_A, body=inside,
            signed_input=jcs(inside), expected=VALID, without_windows=VALID,
            upstream="superseded-key.conformant.json",
            cites=(
                "the minimal twin: the same key, issued_at inside key A's window. issued_at is "
                "the only difference from the member above."
            ),
        ),
    ]


def own_members() -> list[dict[str, Any]]:
    """This corpus's own cases: the window's two edges and three Section 6.6 rules."""
    before = payload(KEY_A, "2025-12-01T00:00:00Z")
    at_until = payload(KEY_A, "2026-06-01T00:00:00Z")
    at_from = payload(KEY_A, "2026-01-01T00:00:00Z")
    hashed = payload(KEY_B, tool_name="records.export")
    crossed = payload(KEY_B, tool_name="records.delete")
    nulled = payload(KEY_B, tool_name="records.share")
    carrying_null = {**nulled, "signature": None}
    return [
        member(
            kind="indeterminate", condition="rs-c-2", key=KEY_A, body=before,
            signed_input=jcs(before), expected=invalid("key_outside_validity_window"),
            without_windows=VALID, if_not_honoured=VALID,
            cites=(
                "a valid signature under key A with issued_at a month before key A's "
                "valid_from: the other side of the window from the stale-external-key case."
            ),
        ),
        member(
            kind="indeterminate", condition="rs-c-3", key=KEY_A, body=at_until,
            signed_input=jcs(at_until), expected=invalid("key_outside_validity_window"),
            without_windows=VALID, if_not_honoured=VALID,
            cites=(
                "issued_at exactly at key A's valid_until. The moment a key stops being "
                "valid is outside its validity, as with exp in RFC 7519 Section 4.1.4. A "
                "verifier that reads the end as inclusive accepts this member; draft-03 "
                "leaves that reading open, so it is reported with the not-honouring case."
            ),
        ),
        member(
            kind="accept", condition="rs-c-3", key=KEY_A, body=at_from,
            signed_input=jcs(at_from), expected=VALID, without_windows=VALID,
            cites=(
                "issued_at exactly at key A's valid_from, the start of the window, which is "
                "inside it as with nbf in RFC 7519 Section 4.1.5."
            ),
        ),
        member(
            kind="reject", condition="rs-c-4", key=KEY_B, body=hashed,
            signed_input=hashlib.sha256(jcs(hashed)).digest(),
            expected=invalid("signature_invalid"), without_windows=invalid("signature_invalid"),
            cites=(
                "signed over SHA-256(JCS(payload)) instead of JCS(payload). PureEdDSA hashes "
                "the message itself, and a pre-hashed signature verifies only for a verifier "
                "that pre-hashes too."
            ),
        ),
        member(
            kind="accept", condition="rs-c-4", key=KEY_B, body=hashed, signed_input=jcs(hashed),
            expected=VALID, without_windows=VALID,
            cites="the same payload, with JCS(payload) given to Ed25519 unhashed.",
        ),
        member(
            kind="reject", condition="rs-c-5", key=KEY_B, body=crossed,
            signed_input=jcs({"payload": crossed}),
            expected=invalid("signature_invalid"), without_windows=invalid("signature_invalid"),
            cites=(
                "an envelope receipt signed under the flat rule: the receipt with its "
                "signature member removed, canonicalized, which for an envelope is "
                "JCS({\"payload\": payload}). A verifier that applies one rule to both shapes "
                "accepts it and refuses its twin."
            ),
        ),
        member(
            kind="accept", condition="rs-c-5", key=KEY_B, body=crossed, signed_input=jcs(crossed),
            expected=VALID, without_windows=VALID,
            cites="the same payload, signed under the envelope rule over JCS(payload).",
        ),
        member(
            kind="reject", condition="rs-c-6", key=KEY_B, body=carrying_null,
            signed_input=jcs(carrying_null),
            expected=invalid("signature_in_signing_input"),
            without_windows=invalid("signature_in_signing_input"),
            cites=(
                "the payload carries \"signature\": null and the signature is over JCS of that "
                "payload, so the signature verifies. Only the rule that the canonicalized "
                "object carries no signature member, not even as null, refuses it."
            ),
        ),
        member(
            kind="accept", condition="rs-c-6", key=KEY_B, body=nulled, signed_input=jcs(nulled),
            expected=VALID, without_windows=VALID,
            cites="the same payload without the null signature member, signed over JCS(payload).",
        ),
    ]


def file_bytes(value: Any) -> bytes:
    """Upstream's serialization: two-space indent, a trailing newline."""
    return json.dumps(value, indent=2).encode("utf-8") + b"\n"


def vendored_text() -> str:
    with open(os.path.join(HERE, SPEC_VENDORED), encoding="utf-8") as handle:
        return re.sub(r"\s+", " ", handle.read())


def requirements() -> list[dict[str, str]]:
    text = vendored_text()
    out = []
    for req in REQUIREMENTS:
        if req["sentence"] not in text:
            raise SystemExit(f"FAIL: {req['id']} is not in the vendored text")
        if req["level"] not in req["sentence"]:
            raise SystemExit(f"FAIL: {req['id']} does not carry its level {req['level']}")
        out.append({**req, "sentenceDigest": sha(req["sentence"].encode("utf-8"))})
    return out


def build_manifest() -> tuple[dict[str, Any], dict[str, bytes]]:
    windowed, bare = key_sets()
    files: dict[str, bytes] = {
        KEYS_WITH_WINDOWS: file_bytes(windowed),
        KEYS_WITHOUT_WINDOWS: file_bytes(bare),
    }
    if sha(files[KEYS_WITH_WINDOWS]) != UPSTREAM_SHA256["jwks.json"]:
        raise SystemExit("FAIL: the key set is not upstream's jwks.json byte for byte")
    entries = []
    origin_members = []
    for m in lifted_members() + own_members():
        body = file_bytes(m["receipt"])
        vid = "v" + sha(body)[:16]
        rel = f"receipts/{vid}.json"
        if rel in files:
            raise SystemExit(f"FAIL: duplicate identifier {vid}")
        files[rel] = body
        entry: dict[str, Any] = {
            "id": vid,
            "kind": m["kind"],
            "file": rel,
            "conditions": m["conditions"],
            "keyId": m["keyId"],
            "expected": m["expected"],
            "expectedWithoutWindows": m["expectedWithoutWindows"],
        }
        if "expectedIfNotHonoured" in m:
            entry["expectedIfNotHonoured"] = m["expectedIfNotHonoured"]
        entry["signedInputHex"] = m["signedInput"].hex()
        entry["cites"] = m["cites"]
        if "upstreamFile" in m:
            upstream = m["upstreamFile"]
            if sha(body) != UPSTREAM_SHA256[upstream]:
                raise SystemExit(f"FAIL: {upstream} is not upstream's bytes")
            origin_members.append({"upstreamFile": upstream, "id": vid, "sha256": sha(body)})
        entries.append(entry)
    entries.sort(key=lambda entry: entry["id"])
    counts = {
        kind: sum(1 for entry in entries if entry["kind"] == kind)
        for kind in ("accept", "indeterminate", "reject")
    }
    with open(os.path.join(HERE, SPEC_VENDORED), "rb") as handle:
        spec_digest = sha(handle.read())
    manifest: dict[str, Any] = {
        "suite": SUITE,
        "subject": "a verifier of signed decision receipts",
        "profile": (
            f"{SPEC_NAME}, envelope shape (Section 2.1), archival verification "
            "(Section 9.1): no freshness window is applied"
        ),
        "tracksUpstream": SPEC_URL,
        "specVendored": SPEC_VENDORED,
        "specDigest": spec_digest,
        "contract": "README.md",
        "keySets": {
            "withWindows": {"file": KEYS_WITH_WINDOWS, "sha256": sha(files[KEYS_WITH_WINDOWS])},
            "withoutWindows": {
                "file": KEYS_WITHOUT_WINDOWS, "sha256": sha(files[KEYS_WITHOUT_WINDOWS]),
            },
        },
        "testKeys": (
            f"TEST ONLY. Each Ed25519 seed is SHA-256(\"{SEED_PREFIX}\" + label), labels "
            f"\"{KEY_A.label}\" and \"{KEY_B.label}\"; the recipe is upstream's, kept so the "
            "lifted receipts stay byte-identical."
        ),
        "origin": {
            "repository": UPSTREAM_REPOSITORY,
            "commit": UPSTREAM_COMMIT,
            "path": UPSTREAM_PATH,
            "author": "giskard09",
            "indexSha256": UPSTREAM_INDEX_SHA256,
            "license": "Apache-2.0",
            "members": origin_members,
            "note": (
                "giskard09 wrote the signature-input-drift and superseded-key cases, each a "
                "reject and its conformant twin, for this corpus. superseded-key is the "
                "stale-external-key case. The second expected outcome on the window member "
                "follows the scoring his suite adopted at this commit."
            ),
        },
        "grade": GRADE_NOTE,
        "codeRegistry": CODE_REGISTRY,
        "requirements": requirements(),
        "conditions": CONDITIONS,
        "counts": counts,
        "corpusDigest": digest_of(entries, lambda rel: files[rel]),
        "vectors": entries,
    }
    files["MANIFEST.json"] = json.dumps(manifest, indent=2).encode("utf-8") + b"\n"
    files["INDEX.md"] = render_index(manifest).encode("utf-8")
    return manifest, files


def outcome(expected: dict[str, Any]) -> str:
    if expected["verdict"] == "valid":
        return "valid"
    return f"invalid `{expected['code']}`"


def render_index(manifest: dict[str, Any]) -> str:
    rows = "\n".join(
        "| `{id}` | {kind} | {cond} | {w} | {nw} | {nh} |".format(
            id=e["id"],
            kind=e["kind"],
            cond=", ".join(e["conditions"]),
            w=outcome(e["expected"]),
            nw=outcome(e["expectedWithoutWindows"]),
            nh=outcome(e["expectedIfNotHonoured"]) if "expectedIfNotHonoured" in e else "",
        )
        for e in manifest["vectors"]
    )
    conditions = "\n".join(
        f"| `{key}` | {value['requires']} | {', '.join(value['requirements'])} |"
        for key, value in sorted(CONDITIONS.items())
    )
    reqs = "\n".join(
        f"| `{r['id']}` | {r['section']} | {r['level']} | {r['sentence']} |"
        for r in manifest["requirements"]
    )
    counts = manifest["counts"]
    total = len(manifest["vectors"])
    lifted = "\n".join(
        f"| `{m['upstreamFile']}` | `{m['id']}` |" for m in manifest["origin"]["members"]
    )
    return f"""# Conformance vectors (signed decision receipts)

Every member of this suite in one table. The subject under test is a verifier of
signed decision receipts in the envelope shape of `{SPEC_NAME}`, vendored at
`{SPEC_VENDORED}` and pinned by digest in the manifest.

This corpus is {total} vectors, of which {counts['accept']} a conformant verifier must not
fail closed on and {counts['reject']} it must reject. The remaining members test a SHOULD and
are graded as the README describes.

Each member is judged twice: with `{KEYS_WITH_WINDOWS}` and with
`{KEYS_WITHOUT_WINDOWS}`, the same keys without their validity windows. The
verifier contract is in `README.md`.

Regenerate byte-identically: `python3 gen_vectors.py`.
Self-check: `aee-verify vectors-receipt-signature/` from the repository root.

## Requirements

| id | section | level | sentence |
|---|---|---|---|
{reqs}

## Conditions

| id | what it requires | requirements |
|---|---|---|
{conditions}

## Vectors

| id | kind | conditions | with windows | without windows | if the SHOULD is not honoured |
|---|---|---|---|---|---|
{rows}

## Lifted members

Written by giskard09 and taken from `{UPSTREAM_REPOSITORY}` at `{UPSTREAM_COMMIT}`,
`{UPSTREAM_PATH}`. The generator reproduces each file and refuses unless its
SHA-256 is the digest recorded upstream.

| upstream file | id |
|---|---|
{lifted}
"""


def verify_tree(files: dict[str, bytes]) -> int:
    bad = []
    for rel, payload_bytes in sorted(files.items()):
        path = os.path.join(HERE, rel)
        if not os.path.exists(path):
            bad.append(f"{rel} is missing")
            continue
        with open(path, "rb") as handle:
            if handle.read() != payload_bytes:
                bad.append(f"{rel} differs from what the generator emits")
    for sub in ("receipts", "keys"):
        root = os.path.join(HERE, sub)
        if os.path.isdir(root):
            for name in sorted(os.listdir(root)):
                if f"{sub}/{name}" not in files:
                    bad.append(f"{sub}/{name} is on disk and the generator emits no such file")
    if bad:
        for line in bad:
            print("FAIL", line, file=sys.stderr)
        print("\nRun `python3 gen_vectors.py` to rebuild, and commit the diff.", file=sys.stderr)
        return 1
    print(f"OK generator reproduces {len(files)} file(s) byte-identically")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="refuse a tree this does not emit")
    check = parser.parse_args().check
    manifest, files = build_manifest()
    if check:
        return verify_tree(files)
    for sub in ("receipts", "keys"):
        os.makedirs(os.path.join(HERE, sub), exist_ok=True)
        for name in sorted(os.listdir(os.path.join(HERE, sub))):
            if f"{sub}/{name}" not in files:
                os.unlink(os.path.join(HERE, sub, name))
    for rel, payload_bytes in sorted(files.items()):
        with open(os.path.join(HERE, rel), "wb") as handle:
            handle.write(payload_bytes)
    counts = manifest["counts"]
    print(
        f"wrote {len(files)} file(s): {counts['accept']} accept, {counts['reject']} reject, "
        f"{counts['indeterminate']} indeterminate, corpus {manifest['corpusDigest'][:12]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
