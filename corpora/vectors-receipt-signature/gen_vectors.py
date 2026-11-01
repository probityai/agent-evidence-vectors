#!/usr/bin/env python3
"""Regenerate the receipt-signature corpus byte-identically.

    python3 gen_vectors.py            # write receipts/, context/, keys/, MANIFEST.json, INDEX.md
    python3 gen_vectors.py --check    # refuse when the tree on disk differs

The subject under test is a verifier of signed decision receipts in the
envelope shape of draft-farley-acta-signed-receipts-03 (vendored under
spec-vendored/ and pinned by digest in the manifest). Each member is one
receipt, optionally with a context: the receipts before it in a chain and an
external commitment to that chain. The verifier is handed the receipt and a JWK
Set that lives outside it, twice: once with the keys' validity windows and
revocation instants, and once with them removed.

Some members are lifted from two upstream suites at pinned commits:
giskard09/argentum-core and ScopeBlind/agent-governance-testvectors. They are
not copied: this generator derives the same test keys from the same public
recipes and signs the same payloads, Ed25519 is deterministic, and the build
refuses unless each lifted file and each upstream key set hashes to the digest
recorded for it upstream. The other members are this corpus's own.
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


def _load_digest() -> Any:
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
    return module


_DIGEST = _load_digest()
digest_of = _DIGEST.digest_of
member_id = _DIGEST.member_id

SUITE = "receipt-signature-conformance"
SPEC_NAME = "draft-farley-acta-signed-receipts-03"
SPEC_URL = "https://datatracker.ietf.org/doc/draft-farley-acta-signed-receipts/03/"
SPEC_VENDORED = "spec-vendored/draft-farley-acta-signed-receipts-03.txt"
KEYS_WITH_WINDOWS = "keys/jwks.json"
KEYS_WITHOUT_WINDOWS = "keys/jwks-no-window.json"
SEED_PREFIX = "agent-evidence-vectors/test-only/"

TESTVECTORS = "ScopeBlind/agent-governance-testvectors"
TESTVECTORS_COMMIT = "56801e37a0c9e668626959a267ac8cfa02e8c27d"

# Every upstream this corpus lifts from, at a pinned commit. `files` is the
# digest of each lifted file there, the key set included. The build refuses when
# the bytes it produces differ from any of them, which is what makes "lifted
# unchanged" a checked property rather than a sentence.
ORIGINS: dict[str, dict[str, Any]] = {
    "farley-receipt-signature": {
        "repository": "giskard09/argentum-core",
        "commit": "541ce84b4f970c1dd3d9e53f2a4562dbbc354e46",
        "path": "examples/conformance/farley-receipt-signature",
        "author": "giskard09",
        "indexSha256": "6b9460491cdf479a85d731b4a2c6fb4fef4dde862bba4c2ba3bb91b69e71e9ec",
        "license": "Apache-2.0",
        "files": {
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
        },
        "note": (
            "giskard09 wrote the signature-input-drift and superseded-key cases, each a "
            "reject and its conformant twin, for this corpus. superseded-key is the "
            "stale-external-key case. The second expected outcome on the window member "
            "follows the scoring his suite adopted at this commit."
        ),
    },
    "signing-input": {
        "repository": TESTVECTORS,
        "commit": TESTVECTORS_COMMIT,
        "path": "verifier-vectors/signing-input",
        "author": "tomjwxf",
        "pullRequest": f"https://github.com/{TESTVECTORS}/pull/28",
        "indexSha256": "ed261453923bf9e16809ebea8472e94bb5e3593ff482c38be9107610242182f8",
        "license": "Apache-2.0",
        "files": {
            "null-member.json": (
                "2e98d2f14251c8d650db34990ce3e2c7ff35932ae6f33d98f17f1ab5ac08b255"
            ),
            "empty-member.json": (
                "2c8c0aabb75e8aa05a9be71a864489b748ae0de97fb7b7f6afb09e4505533972"
            ),
            "string-member.json": (
                "3bb98f09b3068de56b076c70040d7f0d7283b107f15f62afe03b54e8bff86c95"
            ),
            "no-member.json": (
                "cc3cdb871ff270270354e67eceda3a2855ccdd941b151e6fb3919350edb8d7a4"
            ),
            "jwks.json": "8bac96b07bdfb2ad7b9ae81405275d6ab76b581a086f3fa6e0fd940d69e19e01",
        },
        "note": (
            "tomjwxf wrote the signing-input family from this corpus's null-member case: "
            "the same Section 6.6 rule with the member null, the empty string and a "
            "string, and the twin without it."
        ),
    },
    "revocation": {
        "repository": TESTVECTORS,
        "commit": TESTVECTORS_COMMIT,
        "path": "verifier-vectors/revocation",
        "author": "astrogilda",
        "pullRequest": f"https://github.com/{TESTVECTORS}/pull/27",
        "indexSha256": "449a7683e6fcfcc86e172833fc33cabc72fa2f8b38b41cacd4f188cf43569ef4",
        "license": "Apache-2.0",
        "files": {
            "before-revocation.json": (
                "2f0a83c1364e52bc3e43f56bffa3e2c802855d1f033dff1f3434b0f6a6ac0b37"
            ),
            "after-revocation.json": (
                "9f2a63a5186a2fa87a36a93c1b0236f605b90e11fd99b60139ae3d04df8be4a7"
            ),
            "jwks.json": "ae56eb25377e5f34d694acfebeacaf7eb528921dfa27f178fa8b0d74a7ad1dbf",
        },
        "note": (
            "The revocation pair, written for the upstream suite and carried here so one "
            "command runs it in both."
        ),
    },
    "timeliness": {
        "repository": TESTVECTORS,
        "commit": TESTVECTORS_COMMIT,
        "path": "verifier-vectors/timeliness",
        "author": "astrogilda",
        "pullRequest": f"https://github.com/{TESTVECTORS}/pull/27",
        "indexSha256": "bc22e9eaf1b0ea139e3e7a2f38585ca07deacdbd9223e54b7d892e243c68e4f8",
        "license": "Apache-2.0",
        "files": {
            "genesis.json": "0142580fad54af78b8aa87581c5db0d56862662e1832f0cb417c812a5a93e3cd",
            "receipt.json": "814de39bf68212fcac67e73f7a68f1440b429c50e00dd7e8c6580b69dc6260b2",
            "commitment.json": (
                "e0cdbb366659fa7cc657742bca35ee4423308ac46da01d7d1b90bff1292219cd"
            ),
            "jwks.json": "014f83c3792cbaba34a1c047452f04afadf333afaf662fed7e2a55df76ec4fe5",
        },
        "note": (
            "The timeliness case, written for the upstream suite: one receipt alone, and "
            "at chain position 2 against an issuer-signed commitment logged before or "
            "after its issued_at. Carried here so one command runs it in both."
        ),
    },
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
    {
        "id": "RS-R-006",
        "section": "6.7",
        "level": "MUST",
        "sentence": (
            "The previousReceiptHash field MUST be the string \"sha256:\" followed by the "
            "lowercase hex encoding of SHA-256(JCS(receipt)), where receipt is the entire "
            "signed receipt object including the signature member."
        ),
    },
]

# What the draft does not decide, stated so that a member can carry it. A gap
# member's verdict under the draft is its `expected`; `expectedIfGapClosed` is
# the verdict of a verifier that applies the closing rule. The rule is a
# proposal for the draft's next revision, recorded where it was proposed.
GAPS: list[dict[str, str]] = [
    {
        "id": "RS-G-001",
        "question": "Was the key revoked before the receipt was issued?",
        "draftSays": (
            "Nothing. No revision of the draft defines key revocation, so a revoked_at "
            "member on a key is read by no rule and a receipt signed after it verifies."
        ),
        "closingRule": (
            "A key in the external key set may carry revoked_at. A receipt whose issued_at "
            "is at or after its key's revoked_at is invalid."
        ),
        "code": "key_revoked",
        "proposedIn": f"https://github.com/{TESTVECTORS}/pull/27",
        "proposedFor": "draft-farley-acta-signed-receipts-05",
    },
    {
        "id": "RS-G-002",
        "question": (
            "Was the receipt issued after a commitment its issuer recorded where the issuer "
            "cannot rewrite it?"
        ),
        "draftSays": (
            "Section 9.7 defines a commitment, signed by the issuer, to the number of "
            "receipts in a chain and its terminal hash. No rule reads when the commitment "
            "was recorded, so the receipt's issued_at, which the signer asserts, is the "
            "only time it carries."
        ),
        "closingRule": (
            "A receipt at chain position p, with an issuer-signed commitment of count c "
            "less than p whose terminal_hash is the link to position c, recorded at "
            "commitmentLoggedAt somewhere the issuer cannot rewrite, was not issued before "
            "commitmentLoggedAt. If its issued_at is earlier, it is invalid."
        ),
        "code": "issued_at_precedes_excluding_commitment",
        "proposedIn": f"https://github.com/{TESTVECTORS}/pull/27",
        "proposedFor": "draft-farley-acta-signed-receipts-05",
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
            "A payload that carries a signature member, whatever its value (null, the empty "
            "string, a string), is refused even though a signature over its canonical "
            "bytes verifies."
        ),
        "requirements": ["RS-R-005"],
    },
    "rs-c-7": {
        "requires": (
            "A receipt signed inside its key's window and after the key's revoked_at "
            "verifies under the draft. A verifier that reads revoked_at refuses it; the "
            "same receipt issued before revoked_at verifies either way."
        ),
        "requirements": [],
        "gaps": ["RS-G-001"],
    },
    "rs-c-8": {
        "requires": (
            "A receipt presented at a chain position carries, in previousReceiptHash, the "
            "link to the receipt before it in that chain. A chain whose previous receipt "
            "is some other receipt is refused."
        ),
        "requirements": ["RS-R-006"],
    },
    "rs-c-9": {
        "requires": (
            "One receipt, alone and at chain position 2, against an issuer-signed "
            "commitment to a chain of one logged before or after its issued_at. The draft "
            "accepts all of them; a verifier that reads the commitment's time refuses the "
            "one the commitment contradicts."
        ),
        "requirements": [],
        "gaps": ["RS-G-002"],
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
    "chain_link_mismatch": (
        "previousReceiptHash is not \"sha256:\" and the hex of SHA-256(JCS(r)), where r is "
        "the receipt before it in the chain presented (Section 6.7)"
    ),
    "key_revoked": "issued_at is at or after the key's revoked_at (RS-G-001, proposed)",
    "issued_at_precedes_excluding_commitment": (
        "issued_at is before the time a commitment that excludes the receipt's chain "
        "position was recorded (RS-G-002, proposed)"
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
    "a failure. A gap member is one whose verdict the draft decides and whose decision "
    "is the gap: a verifier passes it by answering the draft's verdict in both passes, "
    "and is reported by name as closing the gap when it answers the closing rule's "
    "verdict in both passes instead. Any other answer fails."
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def jcs(value: Any) -> bytes:
    """RFC 8785 for the shapes this corpus signs: objects of ASCII strings, nulls
    and small integers.

    Member names and values are ASCII, so code-unit order and code-point order
    coincide and sort_keys is the RFC's order, and an integer below 2**53 is its
    own ECMAScript serialization. Anything else is refused rather than
    canonicalized by a routine that was never meant for it.
    """
    if isinstance(value, dict):
        for key, item in value.items():
            if not key.isascii():
                raise SystemExit(f"FAIL: non-ASCII member name {key!r}")
            jcs(item)
    elif isinstance(value, list):
        for item in value:
            jcs(item)
    elif isinstance(value, bool) or not (
        value is None
        or (isinstance(value, str) and value.isascii())
        or (isinstance(value, int) and abs(value) < 2**53)
    ):
        raise SystemExit(f"FAIL: {value!r} is not a value this canonicalization covers")
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
    """A test key derived from a public recipe: nothing it signs means anything.

    By default the seed is SHA-256 of a label under this corpus's prefix, and
    the kid is the Section 2.1.1 form. The upstream suite's keys instead take a
    fixed 32-byte seed and a kid of their own, and are rebuilt exactly so their
    receipts stay byte-identical.
    """

    def __init__(self, label: str, seed: bytes | None = None, kid: str | None = None) -> None:
        self.label = label
        if seed is None:
            seed = hashlib.sha256((SEED_PREFIX + label).encode()).digest()
        self.private = Ed25519PrivateKey.from_private_bytes(seed)
        self.public = self.private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        # Section 2.1.1: sb:issuer:<first 12 characters of base58(public key)>.
        self.kid = kid if kid is not None else "sb:issuer:" + b58(self.public)[:12]

    def sign(self, message: bytes) -> bytes:
        return self.private.sign(message)


def fixed_seed(last: int) -> bytes:
    """The upstream suite's recipe: 31 zero bytes and one distinguishing byte."""
    return bytes(31) + bytes([last])


KEY_A = TestKey("key-A-superseded")
KEY_B = TestKey("key-B-current")
KEY_REVOKED = TestKey("00..0c", fixed_seed(0x0C), "test:revoked:ed25519")
KEY_CHAINED = TestKey("00..0d", fixed_seed(0x0D), "test:chained:ed25519")
KEY_SIGNING_INPUT = TestKey("00..0e", fixed_seed(0x0E), "test:signing-input:ed25519")
WINDOW_A = {"valid_from": "2026-01-01T00:00:00Z", "valid_until": "2026-06-01T00:00:00Z"}
WINDOW_B = {"valid_from": "2026-06-01T00:00:00Z"}
WINDOW_YEAR = {"valid_from": "2026-01-01T00:00:00Z", "valid_until": "2027-01-01T00:00:00Z"}
REVOKED_AT = {"revoked_at": "2026-04-01T00:00:00Z"}
# The members a key's lifecycle is published in. The windowless key set drops
# all three: it is the key source of an issuer that publishes none of them.
LIFECYCLE = ("valid_from", "valid_until", "revoked_at")


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwk(key: TestKey, **lifecycle: str) -> dict[str, Any]:
    return {"kty": "OKP", "crv": "Ed25519", "kid": key.kid, "x": b64u(key.public),
            "use": "sig", **lifecycle}


# Each upstream key set, rebuilt from the recipe. The build refuses unless each
# serializes to the bytes of the jwks.json its origin records.
UPSTREAM_KEY_SETS: dict[str, list[dict[str, Any]]] = {
    "farley-receipt-signature": [jwk(KEY_A, **WINDOW_A), jwk(KEY_B, **WINDOW_B)],
    "revocation": [jwk(KEY_REVOKED, **WINDOW_YEAR, **REVOKED_AT)],
    "timeliness": [jwk(KEY_CHAINED, **WINDOW_YEAR)],
    "signing-input": [jwk(KEY_SIGNING_INPUT)],
}


def key_sets() -> tuple[dict[str, Any], dict[str, Any]]:
    """The external key set, with and without the keys' lifecycle.

    The windowed set is every upstream key set, concatenated in a fixed order.
    The windowless one is the same keys with valid_from, valid_until and
    revoked_at removed, which is the key source a verifier has when the issuer
    publishes no rotation metadata.
    """
    windowed = {"keys": [key for keys in UPSTREAM_KEY_SETS.values() for key in keys]}
    bare = {
        "keys": [
            {k: v for k, v in key.items() if k not in LIFECYCLE} for key in windowed["keys"]
        ]
    }
    return windowed, bare


POLICY_DIGEST = "sha256:" + sha(b"test-policy-v1")


def payload(key: TestKey, issued_at: str = "2026-07-15T12:00:00Z",
            tool_name: str = "payments.transfer") -> dict[str, Any]:
    """A protectmcp:decision payload (Section 3.1.1), in argentum-core's member order."""
    return {
        "type": "protectmcp:decision",
        "issued_at": issued_at,
        "issuer_id": key.kid,
        "tool_name": tool_name,
        "decision": "allow",
        "policy_digest": POLICY_DIGEST,
    }


def decision(key: TestKey, tool_name: str, issued_at: str) -> dict[str, Any]:
    """A protectmcp:decision payload in the upstream test-vector suite's member order."""
    return {
        "type": "protectmcp:decision",
        "tool_name": tool_name,
        "decision": "allow",
        "issued_at": issued_at,
        "issuer_id": key.kid,
        "policy_digest": POLICY_DIGEST,
    }


def envelope(body: dict[str, Any], key: TestKey, signature: bytes) -> dict[str, Any]:
    """The envelope shape of Section 2.1: exactly a payload and a signature object."""
    return {"payload": body, "signature": {"alg": "EdDSA", "kid": key.kid, "sig": signature.hex()}}


def signed(body: dict[str, Any], key: TestKey) -> dict[str, Any]:
    """An envelope signed over JCS(payload), as Section 6.6 requires."""
    return envelope(body, key, key.sign(jcs(body)))


def link(receipt: dict[str, Any]) -> str:
    """Section 6.7: "sha256:" and the hex of SHA-256 over the whole signed receipt."""
    return "sha256:" + sha(jcs(receipt))


VALID = {"verdict": "valid", "code": None}


def invalid(code: str) -> dict[str, Any]:
    return {"verdict": "invalid", "code": code}


def member(
    *,
    kind: str,
    conditions: list[str],
    key: TestKey,
    body: dict[str, Any],
    signed_input: bytes,
    expected: dict[str, Any],
    without_windows: dict[str, Any],
    cites: str,
    upstream: tuple[str, str] | None = None,
    if_not_honoured: dict[str, Any] | None = None,
    if_gap_closed: tuple[dict[str, Any], dict[str, Any]] | None = None,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {
        "kind": kind,
        "conditions": conditions,
        "receipt": envelope(body, key, key.sign(signed_input)),
        "signedInput": signed_input,
        "keyId": key.kid,
        "expected": expected,
        "expectedWithoutWindows": without_windows,
        "cites": cites,
    }
    if if_not_honoured is not None:
        out["expectedIfNotHonoured"] = if_not_honoured
    if if_gap_closed is not None:
        out["expectedIfGapClosed"], out["expectedIfGapClosedWithoutWindows"] = if_gap_closed
    if upstream is not None:
        out["upstream"] = upstream
    if context is not None:
        out["context"] = context
    return out


def argentum_members() -> list[dict[str, Any]]:
    """giskard09's two cases, each a defect and its conformant twin."""
    drift = payload(KEY_B)
    pretty = json.dumps(drift, indent=2).encode()
    old = payload(KEY_A)
    inside = payload(KEY_A, "2026-03-15T12:00:00Z")
    return [
        member(
            kind="reject", conditions=["rs-c-1"], key=KEY_B, body=drift, signed_input=pretty,
            expected=invalid("signature_invalid"),
            without_windows=invalid("signature_invalid"),
            upstream=("farley-receipt-signature", "signature-input-drift.reject.json"),
            cites=(
                "signed over the pretty-printed payload bytes, Python json.dumps(payload, "
                "indent=2), and not over JCS(payload). The signature verifies over the bytes "
                "it was made over and fails over the bytes a verifier must recompute."
            ),
        ),
        member(
            kind="accept", conditions=["rs-c-1"], key=KEY_B, body=drift, signed_input=jcs(drift),
            expected=VALID, without_windows=VALID,
            upstream=("farley-receipt-signature", "signature-input-drift.conformant.json"),
            cites="the same payload, signed over JCS(payload).",
        ),
        member(
            kind="indeterminate", conditions=["rs-c-2"], key=KEY_A, body=old, signed_input=jcs(old),
            expected=invalid("key_outside_validity_window"), without_windows=VALID,
            if_not_honoured=VALID,
            upstream=("farley-receipt-signature", "superseded-key.reject.json"),
            cites=(
                "a valid signature under key A with issued_at after key A's valid_until. "
                "issued_at is asserted by the signer, so this catches a key still in use "
                "after an honest rotation, not a compromised key dated into its window. "
                "This is the stale-external-key case."
            ),
        ),
        member(
            kind="accept", conditions=["rs-c-2"], key=KEY_A, body=inside,
            signed_input=jcs(inside), expected=VALID, without_windows=VALID,
            upstream=("farley-receipt-signature", "superseded-key.conformant.json"),
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
            kind="indeterminate", conditions=["rs-c-2"], key=KEY_A, body=before,
            signed_input=jcs(before), expected=invalid("key_outside_validity_window"),
            without_windows=VALID, if_not_honoured=VALID,
            cites=(
                "a valid signature under key A with issued_at a month before key A's "
                "valid_from: the other side of the window from the stale-external-key case."
            ),
        ),
        member(
            kind="indeterminate", conditions=["rs-c-3"], key=KEY_A, body=at_until,
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
            kind="accept", conditions=["rs-c-3"], key=KEY_A, body=at_from,
            signed_input=jcs(at_from), expected=VALID, without_windows=VALID,
            cites=(
                "issued_at exactly at key A's valid_from, the start of the window, which is "
                "inside it as with nbf in RFC 7519 Section 4.1.5."
            ),
        ),
        member(
            kind="reject", conditions=["rs-c-4"], key=KEY_B, body=hashed,
            signed_input=hashlib.sha256(jcs(hashed)).digest(),
            expected=invalid("signature_invalid"), without_windows=invalid("signature_invalid"),
            cites=(
                "signed over SHA-256(JCS(payload)) instead of JCS(payload). PureEdDSA hashes "
                "the message itself, and a pre-hashed signature verifies only for a verifier "
                "that pre-hashes too."
            ),
        ),
        member(
            kind="accept", conditions=["rs-c-4"], key=KEY_B, body=hashed, signed_input=jcs(hashed),
            expected=VALID, without_windows=VALID,
            cites="the same payload, with JCS(payload) given to Ed25519 unhashed.",
        ),
        member(
            kind="reject", conditions=["rs-c-5"], key=KEY_B, body=crossed,
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
            kind="accept", conditions=["rs-c-5"], key=KEY_B, body=crossed,
            signed_input=jcs(crossed), expected=VALID, without_windows=VALID,
            cites="the same payload, signed under the envelope rule over JCS(payload).",
        ),
        member(
            kind="reject", conditions=["rs-c-6"], key=KEY_B, body=carrying_null,
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
            kind="accept", conditions=["rs-c-6"], key=KEY_B, body=nulled, signed_input=jcs(nulled),
            expected=VALID, without_windows=VALID,
            cites="the same payload without the null signature member, signed over JCS(payload).",
        ),
    ]


def signing_input_members() -> list[dict[str, Any]]:
    """tomjwxf's signing-input family: the Section 6.6 member null, empty, a string."""
    fields = decision(KEY_SIGNING_INPUT, "records.share", "2026-07-15T12:00:00Z")
    out = []
    for name, value, cites in (
        ("null-member.json", None,
         "the payload carries \"signature\": null, under the upstream suite's key."),
        ("empty-member.json", "",
         "the payload carries \"signature\": \"\", which Section 6.6 names beside null. "
         "The signature over JCS(payload) verifies."),
        ("string-member.json", "not the signature",
         "the payload carries a signature member holding a string: any value is refused."),
    ):
        body = {**fields, "signature": value}
        out.append(member(
            kind="reject", conditions=["rs-c-6"], key=KEY_SIGNING_INPUT, body=body,
            signed_input=jcs(body), expected=invalid("signature_in_signing_input"),
            without_windows=invalid("signature_in_signing_input"),
            upstream=("signing-input", name), cites=cites,
        ))
    out.append(member(
        kind="accept", conditions=["rs-c-6"], key=KEY_SIGNING_INPUT, body=fields,
        signed_input=jcs(fields), expected=VALID, without_windows=VALID,
        upstream=("signing-input", "no-member.json"),
        cites="the twin of the three above: the same fields with no signature member.",
    ))
    return out


def revocation_members() -> list[dict[str, Any]]:
    """A key revoked inside its window, and a receipt on each side of revoked_at."""
    before = decision(KEY_REVOKED, "read_file", "2026-03-15T00:00:00Z")
    after = decision(KEY_REVOKED, "read_file", "2026-05-15T00:00:00Z")
    return [
        member(
            kind="accept", conditions=["rs-c-7"], key=KEY_REVOKED, body=before,
            signed_input=jcs(before), expected=VALID, without_windows=VALID,
            upstream=("revocation", "before-revocation.json"),
            cites="issued inside the key's window and before its revoked_at. Every verifier "
                  "accepts it.",
        ),
        member(
            kind="gap", conditions=["rs-c-7"], key=KEY_REVOKED, body=after,
            signed_input=jcs(after), expected=VALID, without_windows=VALID,
            if_gap_closed=(invalid("key_revoked"), VALID),
            upstream=("revocation", "after-revocation.json"),
            cites="issued inside the key's window and six weeks after its revoked_at. The "
                  "draft defines no revocation, so it verifies; a verifier that reads "
                  "revoked_at refuses it. issued_at is the signer's word, so a holder of the "
                  "revoked key who dates a receipt earlier passes either way: rs-c-9 is what "
                  "bounds it.",
        ),
    ]


def timeliness_members(before_revocation: dict[str, Any]) -> list[dict[str, Any]]:
    """One receipt alone, linked, mislinked, and against a commitment either side."""
    genesis_body = decision(KEY_CHAINED, "read_file", "2026-01-10T00:00:00Z")
    genesis = signed(genesis_body, KEY_CHAINED)
    body = {**decision(KEY_CHAINED, "payments.transfer", "2026-02-15T00:00:00Z"),
            "previousReceiptHash": link(genesis)}
    commitment = signed({
        "type": "x-agent-governance-testvectors:chain-commitment",
        "issuer_id": KEY_CHAINED.kid,
        "count": 1,
        "terminal_hash": link(genesis),
    }, KEY_CHAINED)

    def at_two(kind: str, conditions: list[str], chain: dict[str, Any], cites: str,
               logged_at: str | None = None, **rest: Any) -> dict[str, Any]:
        context: dict[str, Any] = {"chain": [chain]}
        if logged_at is not None:
            context.update(commitment=commitment, commitmentLoggedAt=logged_at,
                           commitmentUpstream=("timeliness", "commitment.json"))
        return member(kind=kind, conditions=conditions, key=KEY_CHAINED, body=body,
                      signed_input=jcs(body), cites=cites, context=context, **rest)

    return [
        member(
            kind="accept", conditions=["rs-c-8"], key=KEY_CHAINED, body=genesis_body,
            signed_input=jcs(genesis_body), expected=VALID, without_windows=VALID,
            upstream=("timeliness", "genesis.json"),
            cites="the first receipt of the chain, which carries no link.",
        ),
        member(
            kind="accept", conditions=["rs-c-9"], key=KEY_CHAINED, body=body,
            signed_input=jcs(body), expected=VALID, without_windows=VALID,
            upstream=("timeliness", "receipt.json"),
            cites="the receipt alone. Its signature verifies, and its issued_at is the "
                  "signer's word with nothing bounding it.",
        ),
        at_two(
            "accept", ["rs-c-8"], genesis, expected=VALID, without_windows=VALID,
            cites="the same receipt at chain position 2 after the receipt its link names.",
        ),
        at_two(
            "reject", ["rs-c-8"], before_revocation,
            expected=invalid("chain_link_mismatch"),
            without_windows=invalid("chain_link_mismatch"),
            cites="the same receipt at chain position 2 after a receipt that is not the one "
                  "its link names. Every signature verifies; only the Section 6.7 link "
                  "refuses the chain.",
        ),
        at_two(
            "gap", ["rs-c-9"], genesis, logged_at="2026-03-01T00:00:00Z",
            expected=VALID, without_windows=VALID,
            if_gap_closed=(invalid("issued_at_precedes_excluding_commitment"),
                           invalid("issued_at_precedes_excluding_commitment")),
            cites="position 2, and on 1 March the issuer committed to a chain of one, so "
                  "position 2 did not exist then. The receipt's issued_at of 15 February is "
                  "contradicted by the issuer's own commitment. The draft reads neither the "
                  "commitment nor its time, so it verifies.",
        ),
        at_two(
            "accept", ["rs-c-8", "rs-c-9"], genesis, logged_at="2026-02-01T00:00:00Z",
            expected=VALID, without_windows=VALID,
            cites="the conformant twin: the same receipt and the same signed commitment, "
                  "logged on 1 February, before issued_at. The receipt is now bounded below.",
        ),
    ]


def testvectors_members() -> list[dict[str, Any]]:
    signing = signing_input_members()
    revocation = revocation_members()
    return [*signing, *revocation, *timeliness_members(revocation[0]["receipt"])]


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


def upstream_key_sets() -> dict[str, bytes]:
    """Each upstream key set, rebuilt, checked against the digest its origin records."""
    out = {}
    for name, keys in UPSTREAM_KEY_SETS.items():
        body = file_bytes({"keys": keys})
        if sha(body) != ORIGINS[name]["files"]["jwks.json"]:
            raise SystemExit(f"FAIL: the {name} key set is not upstream's jwks.json byte for byte")
        out[name] = body
    return out


class Tree:
    """The files the build emits, with each receipt's path fixed by its bytes."""

    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.origin: dict[str, list[dict[str, str]]] = {name: [] for name in ORIGINS}
        self.lifted_files: set[str] = set()

    def put(self, rel: str, body: bytes) -> str:
        if self.files.get(rel, body) != body:
            raise SystemExit(f"FAIL: two different files at {rel}")
        self.files[rel] = body
        return rel

    def receipt(self, receipt: dict[str, Any]) -> str:
        body = file_bytes(receipt)
        return self.put(f"receipts/v{sha(body)[:16]}.json", body)

    def lifted(self, upstream: tuple[str, str], rel: str) -> None:
        name, upstream_file = upstream
        body = self.files[rel]
        if sha(body) != ORIGINS[name]["files"][upstream_file]:
            raise SystemExit(f"FAIL: {name}/{upstream_file} is not upstream's bytes")
        self.origin[name].append({"upstreamFile": upstream_file, "file": rel, "sha256": sha(body)})
        self.lifted_files.add(rel)

    def context(self, context: dict[str, Any]) -> dict[str, Any]:
        """The manifest form: each chain receipt by the member file it is, the
        commitment by a file named after its own bytes."""
        chain = []
        for receipt in context["chain"]:
            rel = f"receipts/v{sha(file_bytes(receipt))[:16]}.json"
            if rel not in self.files:
                raise SystemExit(f"FAIL: a chain names {rel}, which is not a member")
            chain.append(rel)
        out: dict[str, Any] = {"chain": chain}
        if "commitment" in context:
            body = file_bytes(context["commitment"])
            out["commitment"] = self.put(f"context/c{sha(body)[:16]}.json", body)
            out["commitmentLoggedAt"] = context["commitmentLoggedAt"]
            if "commitmentUpstream" in context and out["commitment"] not in self.lifted_files:
                self.lifted(context["commitmentUpstream"], out["commitment"])
        return out


OUTCOME_KEYS = ("expected", "expectedWithoutWindows", "expectedIfNotHonoured",
                "expectedIfGapClosed", "expectedIfGapClosedWithoutWindows")


def build_entries(tree: Tree) -> list[dict[str, Any]]:
    members = argentum_members() + own_members() + testvectors_members()
    # Every receipt file first, so a context can name a receipt that appears
    # later in the list.
    for m in members:
        tree.receipt(m["receipt"])
    entries = []
    for m in members:
        rel = tree.receipt(m["receipt"])
        entry: dict[str, Any] = {"id": "", "kind": m["kind"], "file": rel}
        if "context" in m:
            entry["context"] = tree.context(m["context"])
        entry["conditions"] = m["conditions"]
        entry["keyId"] = m["keyId"]
        entry.update({key: m[key] for key in OUTCOME_KEYS if key in m})
        entry["signedInputHex"] = m["signedInput"].hex()
        entry["cites"] = m["cites"]
        entry["id"] = member_id(entry, lambda path: tree.files[path])
        if "upstream" in m:
            tree.lifted(m["upstream"], rel)
        entries.append(entry)
    if len({e["id"] for e in entries}) != len(entries):
        raise SystemExit("FAIL: two members share an identifier")
    entries.sort(key=lambda entry: entry["id"])
    return entries


def origins(tree: Tree) -> list[dict[str, Any]]:
    out = []
    for name, origin in ORIGINS.items():
        record = {k: v for k, v in origin.items() if k not in ("files", "note")}
        record["members"] = sorted(tree.origin[name], key=lambda m: m["upstreamFile"])
        record["note"] = origin["note"]
        out.append(record)
    return out


def build_manifest() -> tuple[dict[str, Any], dict[str, bytes]]:
    windowed, bare = key_sets()
    upstream_key_sets()
    tree = Tree()
    tree.put(KEYS_WITH_WINDOWS, file_bytes(windowed))
    tree.put(KEYS_WITHOUT_WINDOWS, file_bytes(bare))
    entries = build_entries(tree)
    files = tree.files
    counts = {
        kind: sum(1 for entry in entries if entry["kind"] == kind)
        for kind in ("accept", "gap", "indeterminate", "reject")
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
            f"TEST ONLY. Keys A and B: each Ed25519 seed is SHA-256(\"{SEED_PREFIX}\" + "
            f"label), labels \"{KEY_A.label}\" and \"{KEY_B.label}\", argentum-core's recipe. "
            f"The keys {KEY_REVOKED.kid}, {KEY_CHAINED.kid} and {KEY_SIGNING_INPUT.kid}: seeds of "
            "31 zero bytes and then 0x0c, 0x0d and 0x0e, the upstream test-vector suite's "
            "recipe. Both are kept so the lifted receipts stay byte-identical."
        ),
        "origins": origins(tree),
        "grade": GRADE_NOTE,
        "codeRegistry": CODE_REGISTRY,
        "requirements": requirements(),
        "gaps": GAPS,
        "conditions": CONDITIONS,
        "counts": counts,
        "corpusDigest": digest_of(entries, lambda rel: files[rel]),
        "vectors": entries,
    }
    files["MANIFEST.json"] = json.dumps(manifest, indent=2).encode("utf-8") + b"\n"
    files["INDEX.md"] = render_index(manifest).encode("utf-8")
    return manifest, files


def outcome(expected: dict[str, Any] | None) -> str:
    if expected is None:
        return ""
    if expected["verdict"] == "valid":
        return "valid"
    return f"{expected['verdict']} `{expected['code']}`"


def context_cell(entry: dict[str, Any]) -> str:
    context = entry.get("context")
    if context is None:
        return ""
    chain = " ".join(f"`{rel.split('/')[-1][:-5]}`" for rel in context["chain"])
    cell = f"after {chain}"
    if "commitment" in context:
        cell += f"; commitment logged {context['commitmentLoggedAt']}"
    return cell


VECTOR_HEADER = (
    "| id | kind | conditions | context | with windows | without windows "
    "| if the SHOULD is not honoured | if the gap is closed (with / without windows) |\n"
    "|---|---|---|---|---|---|---|---|"
)


def render_index(manifest: dict[str, Any]) -> str:
    rows = "\n".join(
        "| `{id}` | {kind} | {cond} | {ctx} | {w} | {nw} | {nh} | {gc} |".format(
            id=e["id"],
            kind=e["kind"],
            cond=", ".join(e["conditions"]),
            ctx=context_cell(e),
            w=outcome(e["expected"]),
            nw=outcome(e["expectedWithoutWindows"]),
            nh=outcome(e.get("expectedIfNotHonoured")),
            gc=(f"{outcome(e['expectedIfGapClosed'])} / "
                f"{outcome(e['expectedIfGapClosedWithoutWindows'])}"
                if "expectedIfGapClosed" in e else ""),
        )
        for e in manifest["vectors"]
    )
    conditions = "\n".join(
        f"| `{key}` | {value['requires']} | "
        f"{', '.join(value['requirements'] + value.get('gaps', []))} |"
        for key, value in sorted(CONDITIONS.items())
    )
    reqs = "\n".join(
        f"| `{r['id']}` | {r['section']} | {r['level']} | {r['sentence']} |"
        for r in manifest["requirements"]
    )
    gaps = "\n".join(
        f"| `{g['id']}` | {g['question']} | {g['closingRule']} | `{g['code']}` |"
        for g in manifest["gaps"]
    )
    counts = manifest["counts"]
    total = len(manifest["vectors"])
    lifted = "\n".join(
        f"| {o['author']} | `{o['repository']}` `{o['path']}` at `{o['commit'][:12]}` | "
        f"`{m['upstreamFile']}` | `{m['file']}` |"
        for o in manifest["origins"] for m in o["members"]
    )
    return f"""# Conformance vectors (signed decision receipts)

Every member of this suite in one table. The subject under test is a verifier of
signed decision receipts in the envelope shape of `{SPEC_NAME}`, vendored at
`{SPEC_VENDORED}` and pinned by digest in the manifest.

This corpus is {total} vectors, of which {counts['accept']} a conformant verifier must not
fail closed on and {counts['reject']} it must reject. {counts['indeterminate']} test a SHOULD
and {counts['gap']} test a question the draft does not decide; both are graded as the README
describes.

Each member is judged twice: with `{KEYS_WITH_WINDOWS}` and with
`{KEYS_WITHOUT_WINDOWS}`, the same keys without their validity windows and
revocation instants. A member with a context is presented after the receipts
its chain names, and against the commitment it names. The verifier contract is
in `README.md`.

Regenerate byte-identically: `python3 gen_vectors.py`.
Self-check: `aee-verify vectors-receipt-signature/` from the repository root.

## Requirements

| id | section | level | sentence |
|---|---|---|---|
{reqs}

## Gaps

Questions the draft does not decide. The closing rule is a proposal for its next
revision, and a verifier that applies it is reported by name, never failed.

| id | question | closing rule | code |
|---|---|---|---|
{gaps}

## Conditions

| id | what it requires | requirements and gaps |
|---|---|---|
{conditions}

## Vectors

{VECTOR_HEADER}
{rows}

## Lifted files

Each file below was written upstream and is reproduced by the generator, which
refuses unless its SHA-256 is the digest recorded at that commit.

| author | upstream | upstream file | here |
|---|---|---|---|
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
    for sub in ("receipts", "context", "keys"):
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
    for sub in ("receipts", "context", "keys"):
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
        f"{counts['indeterminate']} indeterminate, {counts['gap']} gap, "
        f"corpus {manifest['corpusDigest'][:12]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
