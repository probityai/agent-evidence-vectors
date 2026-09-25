#!/usr/bin/env python3
"""Regenerate the AI generation predicate v0.1 corpus byte-identically.

    python3 gen_vectors.py            # write every member, MANIFEST.json and INDEX.md
    python3 gen_vectors.py --check    # refuse when the tree on disk differs

The subject under test is a verifier of the generation predicate
``https://open-fab.ai/attestation/generation/v0.1`` at specification revision
0.1.3, in its default attest-only mode: recompute the artifact digests, verify
the ed25519 signatures over the canonical statement, and read attribution from
the predicate without executing anything.

Every member is an attestation envelope, except one: the golden
canonicalization vector the upstream repository pins, transcribed here from the
test that pins it and checked against the upstream hash before anything is
written. The base attestation is that golden statement with real artifact
digests, signed with a fixed test key; every other member is one change to it.

Members are graded three ways. ``accept`` and ``reject`` are required by the
revision as written, and a reject cites the clause it breaks. ``proposed``
members depend on text the revision does not yet carry; each declares what the
revision as written says about it and what the proposal in
``docs/proposals/ai-generation-v01-findings.md`` says, and a verifier is never
failed on one.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import sys
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    PublicFormat,
)

# One preimage, one spelling. release-digests.py reaches the same function.
from digest import ordered_digest  # noqa: E402

SUITE = "ai-generation-v01-conformance"
PREDICATE_TYPE = "https://open-fab.ai/attestation/generation/v0.1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
TRACKS_UPSTREAM = "ossf/tac#628"
SPEC_UPSTREAM_REPO = "Open-fab-ai/openfab"
SPEC_UPSTREAM_COMMIT = "f558da05aae82a7d98f18287f2bcc17e2f1d8aee"
SPEC_REVISION = "0.1.3"
SPEC_VENDORED = "spec-vendored/generation-predicate-v0.1-f558da05.md"
SCHEMA_VENDORED = "spec-vendored/generation-predicate-schema-f558da05.json"
LICENSE_VENDORED = "spec-vendored/LICENSE-f558da05"
PROPOSED_TEXT = "docs/proposals/ai-generation-v01-findings.md"
ID_HEX = 16

# The golden vector as the upstream repository pins it. The statement below is
# transcribed from the Rust test named here; the length and the hash are the
# ones that test asserts, and build() refuses to write anything if the
# transcription does not reproduce them.
GOLDEN_SOURCE = {
    "repo": SPEC_UPSTREAM_REPO,
    "commit": SPEC_UPSTREAM_COMMIT,
    "path": "src/core/provenance.rs",
    "test": "canonical_encoding_golden_vector",
    "canonicalLength": 756,
    "canonicalSha256": "7051cb7073a3bee0a038255fd59d4679c95443bd6a81bb92d0ff3e765713bacd",
}


def golden_statement() -> dict[str, Any]:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": "golden-v1",
                "digest": {
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                },
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "spec_ref": "golden#v1",
            "builder": {"id": "openfab/0.1", "base": "golden"},
            "agent": {
                "did": "did:key:z6MkGOLDEN",
                "base": "golden",
                "model": "test-model",
                "id": "golden:test-model",
            },
            "prompt_sha256": "0" * 64,
            "params": {},
            "generated": [
                {
                    "path": 'app/中文 "quoted"\npath.js',
                    "lines": "1-1",
                    "sha256": "00",
                    "author": "ai",
                }
            ],
            "materials": [],
            "acceptance_passed": True,
            "acceptance": [{"id": "a1", "check": "js:true", "must_pass": True, "passed": True}],
            "timestamp": "2026-09-22T00:00:00Z",
        },
    }


# ---------------------------------------------------------------------------
# Conditions. `clause` quotes revision 0.1.3; a proposed condition names the gap
# instead, because the revision has no clause to quote.

CONDITIONS: dict[str, dict[str, str]] = {
    "ofg-c-1": {
        "requires": "The canonical form of the pinned golden statement is the pinned bytes.",
        "clause": "Envelope encoding: the golden conformance vector, whose canonical form "
        "the upstream repository pins by length and sha256.",
    },
    "ofg-c-2": {
        "requires": "payload_sha256 is the sha256 of the canonical statement bytes.",
        "clause": "Envelope encoding: the bytes the signatures cover, and that "
        "payload_sha256 digests, are the UTF-8 encoding of the canonical form of statement.",
    },
    "ofg-c-3": {
        "requires": "A signature covers the canonical bytes, not another serialization.",
        "clause": "Envelope encoding: objects carry no insignificant whitespace.",
    },
    "ofg-c-4": {
        "requires": "Non-ASCII characters are emitted as literal UTF-8.",
        "clause": "Envelope encoding: all other characters (including non-ASCII) emitted "
        "as literal UTF-8, not escaped.",
    },
    "ofg-c-5": {
        "requires": "String escaping is minimal; a solidus is not escaped.",
        "clause": "Envelope encoding: standard JSON escaping, minimal.",
    },
    "ofg-c-6": {
        "requires": "No floating-point number appears in the statement.",
        "clause": "Envelope encoding: the value domain contains no floating-point "
        "numbers. Producers MUST NOT introduce them.",
    },
    "ofg-c-7": {
        "requires": "No number of any kind appears in the statement.",
        "clause": "Envelope encoding: the value domain is strings, booleans, objects, arrays only.",
    },
    "ofg-c-8": {
        "requires": "An empty acceptance or signoffs array is omitted.",
        "clause": "Producer omission rule: empty acceptance / signoffs arrays are omitted "
        "entirely, never serialized as empty arrays.",
    },
    "ofg-c-9": {
        "requires": "An absent optional field is omitted, never serialized as null.",
        "clause": "Producer omission rule: absent optional fields (agent.id, agent.tools, "
        "materials[].sha256) are omitted entirely, never serialized as null.",
    },
    "ofg-c-10": {
        "requires": "The statement is canonicalized as received, so a member added after "
        "signing is covered and breaks the digest.",
        "clause": "Envelope encoding: verifiers canonicalize the statement as parsed.",
    },
    "ofg-c-11": {
        "requires": "Every ed25519 signature verifies over the canonical bytes.",
        "clause": "Verification step 2: verify the ed25519 signatures against their keyid.",
    },
    "ofg-c-12": {
        "requires": "A keyid is an ed25519 did:key.",
        "clause": "Verification step 2: signatures are verified against their keyid (did:key); "
        "the envelope algorithm is ed25519.",
    },
    "ofg-c-13": {
        "requires": "generated[].author is ai or human.",
        "clause": "Predicate fields: author is one of ai or human.",
    },
    "ofg-c-14": {
        "requires": "In attest-only mode acceptance_passed is reported as the producer's "
        "self-report and the verdict records its mode.",
        "clause": "Verification: in this mode acceptance_passed MUST be treated as the "
        "producer's self-report; a verifier MUST record which mode produced its verdict.",
    },
    "ofg-p-1": {
        "requires": "Each signature covers a stated part of the statement once sign-offs "
        "exist: the fab signature and payload_sha256 the statement without signoffs, the "
        "n-th sign-off signature the statement with the first n records.",
        "gap": "Revision 0.1.3 says every signature covers the canonical statement, so a "
        "verifier built from the text rejects every attestation that carries a sign-off.",
    },
    "ofg-p-2": {
        "requires": "Every sign-off record is covered by the signature of the key it names.",
        "gap": "Under the coverage both implementations use, the last record is covered "
        "by no signature and can be rewritten after signing.",
    },
    "ofg-p-3": {
        "requires": "There is exactly one sign-off signature per sign-off record.",
        "gap": "Nothing binds the number of records to the number of signatures.",
    },
    "ofg-p-4": {
        "requires": "signoffs[n].did is the keyid of the n-th sign-off signature.",
        "gap": "Nothing binds a record to the key that signed it.",
    },
    "ofg-p-5": {
        "requires": "N-of-M counts distinct signing keys, not records or names.",
        "gap": "The revision calls signoffs an N-of-M gate and never says what is counted.",
    },
    "ofg-p-6": {
        "requires": "Attribution ranges for one path do not overlap.",
        "gap": "The revision permits two ranges to claim different origins for one line.",
    },
    "ofg-p-7": {
        "requires": "A supplied Assisted-by trailer matches agent.id and agent.tools.",
        "gap": "The revision makes the cross-check a MAY, so a disagreeing trailer passes.",
    },
    "ofg-p-8": {
        "requires": "Member names are ordered by UTF-16 code units, as RFC 8785 orders them.",
        "gap": "The revision orders keys by code point and also says its form coincides "
        "with RFC 8785; for a member name outside the Basic Multilingual Plane the two "
        "orders differ.",
    },
    "ofg-p-9": {
        "requires": "An integer is permitted inside the I-JSON safe range and refused outside it.",
        "gap": "The revision's value domain has no numbers, while the reference tests sign "
        "an integer parameter.",
    },
    "ofg-p-10": {
        "requires": "A statement with a duplicate member name is refused.",
        "gap": "The revision does not say how a duplicate name is parsed, so two verifiers "
        "keeping different copies both conform.",
    },
}


# ---------------------------------------------------------------------------
# Keys. Fixed seeds, so Ed25519's deterministic signatures regenerate byte for
# byte. These are published test keys and sign nothing outside this directory.

KEY_NAMES = ("fab", "reviewer-a", "reviewer-b", "reviewer-c")


def key_for(name: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(b"agent-evidence-vectors ai-generation test key: " + name.encode())
    return Ed25519PrivateKey.from_private_bytes(seed.digest())


KEYS = {name: key_for(name) for name in KEY_NAMES}

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58btc(raw: bytes) -> str:
    number = int.from_bytes(raw, "big")
    out = ""
    while number:
        number, rest = divmod(number, 58)
        out = B58[rest] + out
    leading = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * leading + out


def raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def did_key(key: Ed25519PrivateKey, codec: bytes = b"\xed\x01") -> str:
    return "did:key:z" + base58btc(codec + raw_public(key))


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Canonical form. `order` is "utf16" for RFC 8785 and "codepoint" for the order
# revision 0.1.3's bullet states; they differ only for member names outside the
# Basic Multilingual Plane.


def sort_key(order: str) -> Any:
    if order == "utf16":
        return lambda name: name.encode("utf-16-be")
    return lambda name: name


def canonical_text(value: Any, order: str = "utf16", ascii_only: bool = False) -> str:
    if isinstance(value, dict):
        names = sorted(value, key=sort_key(order))
        return (
            "{"
            + ",".join(
                json.dumps(name, ensure_ascii=ascii_only)
                + ":"
                + canonical_text(value[name], order, ascii_only)
                for name in names
            )
            + "}"
        )
    if isinstance(value, list):
        return "[" + ",".join(canonical_text(item, order, ascii_only) for item in value) + "]"
    return json.dumps(value, ensure_ascii=ascii_only)


def canonical(value: Any, order: str = "utf16") -> bytes:
    return canonical_text(value, order).encode("utf-8")


# ---------------------------------------------------------------------------
# Artifacts. A generated range's digest is the sha256 of exactly the lines the
# range names, each with its line terminator; the subject's digest is the sha256
# of the whole file. The revision says neither, so this corpus states its reading.

GOLDEN_FILE = b'console.log("golden");\n'
OVERLAP_PATH = "app/fee.js"
OVERLAP_FILE = b"".join(f"export const line{n} = {n};\n".encode() for n in range(1, 31))


def range_digest(content: bytes, lines: str) -> str:
    start, end = (int(part) for part in lines.split("-"))
    return sha(b"".join(content.splitlines(keepends=True)[start - 1 : end]))


def artifact_rel(content: bytes) -> str:
    return f"artifacts/{sha(content)[:ID_HEX]}.txt"


def base_statement() -> dict[str, Any]:
    """The golden statement with real digests, so it passes attest-only step 1."""
    statement = golden_statement()
    statement["subject"][0]["digest"]["sha256"] = sha(GOLDEN_FILE)
    statement["predicate"]["generated"][0]["sha256"] = range_digest(GOLDEN_FILE, "1-1")
    return statement


def golden_artifacts(statement: dict[str, Any]) -> list[dict[str, str]]:
    rel = artifact_rel(GOLDEN_FILE)
    return [
        {"name": statement["subject"][0]["name"], "file": rel},
        {"name": statement["predicate"]["generated"][0]["path"], "file": rel},
    ]


# ---------------------------------------------------------------------------
# Envelopes.


def signature(key: str, message: bytes, role: str = "fab") -> dict[str, str]:
    private = KEYS[key]
    return {
        "keyid": did_key(private),
        "sig": base64.b64encode(private.sign(message)).decode("ascii"),
        "algo": "ed25519",
        "role": role,
    }


def envelope(statement: dict[str, Any], payload: bytes, signatures: list[Any]) -> dict[str, Any]:
    return {
        "payload_type": PAYLOAD_TYPE,
        "payload_sha256": sha(payload),
        "statement": statement,
        "signatures": signatures,
    }


def signed(statement: dict[str, Any], order: str = "utf16") -> dict[str, Any]:
    """The plain case: one fab signature over the canonical statement."""
    payload = canonical(statement, order)
    return envelope(statement, payload, [signature("fab", payload)])


def with_signoffs(statement: dict[str, Any], keep: int, records: list[Any]) -> dict[str, Any]:
    view = copy.deepcopy(statement)
    if keep:
        view["predicate"]["signoffs"] = copy.deepcopy(records[:keep])
    else:
        view["predicate"].pop("signoffs", None)
    return view


def signed_off(signers: list[tuple[str, str]], inclusive: bool) -> dict[str, Any]:
    """The base statement with human sign-offs.

    inclusive=True is the proposal: the n-th sign-off covers the first n records,
    its own included. inclusive=False is what both upstream implementations do:
    the n-th covers only the records before it, so the last record is unsigned.
    """
    statement = base_statement()
    records = [
        {"did": did_key(KEYS[key]), "name": name, "timestamp": "2026-09-22T00:05:00Z"}
        for key, name in signers
    ]
    statement["predicate"]["signoffs"] = records
    fab_payload = canonical(with_signoffs(statement, 0, records))
    sigs = [signature("fab", fab_payload)]
    for index, (key, _name) in enumerate(signers):
        keep = index + 1 if inclusive else index
        message = canonical(with_signoffs(statement, keep, records))
        sigs.append(signature(key, message, "human-signoff"))
    return envelope(statement, fab_payload, sigs)


def pretty(document: Any) -> bytes:
    return json.dumps(document, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"


# ---------------------------------------------------------------------------
# Members. Each is a dict the manifest builder turns into bytes and a row; `key`
# is a local handle so a row can name its parent before identifiers exist.


def member(key: str, kind: str, conditions: list[str], body: bytes, **extra: Any) -> dict[str, Any]:
    row: dict[str, Any] = {"key": key, "kind": kind, "conditions": conditions, "body": body}
    row.update(extra)
    return row


def valid() -> dict[str, str]:
    return {"verdict": "valid"}


def invalid(code: str) -> dict[str, str]:
    return {"verdict": "invalid", "code": code}


def proposed(rev013: dict[str, str], proposal: dict[str, str], **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"rev013": rev013, "proposal": proposal}
    out.update(extra)
    return out


def golden_member() -> dict[str, Any]:
    statement = golden_statement()
    text = canonical(statement)
    if (
        len(text) != GOLDEN_SOURCE["canonicalLength"]
        or sha(text) != GOLDEN_SOURCE["canonicalSha256"]
    ):
        raise SystemExit(
            "FAIL: the transcribed golden statement does not reproduce the pinned "
            f"canonical form (got {len(text)} bytes, sha256 {sha(text)})"
        )
    return member(
        "golden",
        "accept",
        ["ofg-c-1"],
        pretty(statement),
        form="statement",
        expected={
            "canonicalLength": GOLDEN_SOURCE["canonicalLength"],
            "canonicalSha256": GOLDEN_SOURCE["canonicalSha256"],
        },
        cites="the golden conformance vector, transcribed from the upstream test that pins "
        "it. A verifier's canonicalization must reproduce the pinned bytes exactly.",
    )


def attestation(
    key: str, kind: str, conditions: list[str], env: dict[str, Any], **extra: Any
) -> dict[str, Any]:
    """A member whose file is an envelope. `body` overrides the bytes written,
    for the one member whose defect JSON cannot represent as a value."""
    body = extra.pop("body", None) or pretty(env)
    extra.setdefault("artifacts", golden_artifacts(env["statement"]))
    return member(key, kind, conditions, body, form="attestation", **extra)


def base_members() -> list[dict[str, Any]]:
    base = signed(base_statement())
    without_acceptance = base_statement()
    del without_acceptance["predicate"]["acceptance"]
    without_id = base_statement()
    del without_id["predicate"]["agent"]["id"]
    self_report = base_statement()
    self_report["predicate"]["acceptance"][0]["check"] = "js:false"
    return [
        attestation(
            "base",
            "accept",
            ["ofg-c-2", "ofg-c-3", "ofg-c-4", "ofg-c-5", "ofg-c-10", "ofg-c-11"]
            + ["ofg-c-12", "ofg-c-13", "ofg-p-10"],
            base,
            expected=valid(),
            cites="the golden statement with real artifact digests, signed by the fab test "
            "key over its canonical bytes. Every required reject is one change to it.",
        ),
        attestation(
            "no-acceptance",
            "accept",
            ["ofg-c-8"],
            signed(without_acceptance),
            expected=valid(),
            cites="the base statement with no acceptance checks, the array omitted as the "
            "producer omission rule requires.",
        ),
        attestation(
            "no-agent-id",
            "accept",
            ["ofg-c-9"],
            signed(without_id),
            expected=valid(),
            cites="the base statement with agent.id absent, omitted rather than null.",
        ),
        attestation(
            "self-report",
            "accept",
            ["ofg-c-14"],
            signed(self_report),
            expected={"verdict": "valid", "mode": "attest-only", "acceptance": "self-reported"},
            cites="an embedded check that would fail if executed, with acceptance_passed "
            "true. Attest-only verification executes nothing, so the verdict is valid and "
            "the acceptance bit is reported as the producer's claim, never as conformance.",
        ),
    ]


def param_twin(key: str, condition: str, params: dict[str, Any], what: str) -> dict[str, Any]:
    statement = base_statement()
    statement["predicate"]["params"] = params
    return attestation(key, "accept", [condition], signed(statement), expected=valid(), cites=what)


def resign(env: dict[str, Any], payload: bytes) -> dict[str, Any]:
    """Re-sign an envelope's statement over the given bytes, digest included."""
    out = copy.deepcopy(env)
    out["payload_sha256"] = sha(payload)
    out["signatures"] = [signature("fab", payload)]
    return out


def flip_hex(digest: str) -> str:
    return digest[:-1] + ("0" if digest[-1] != "0" else "1")


def flip_signature(sig: str) -> str:
    raw = bytearray(base64.b64decode(sig))
    raw[0] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


def canonical_rejects() -> list[dict[str, Any]]:
    """Members whose statement is the base one and whose bytes-on-the-wire differ."""
    base = signed(base_statement())
    statement = base["statement"]
    wrong_digest = copy.deepcopy(base)
    wrong_digest["payload_sha256"] = flip_hex(base["payload_sha256"])
    spaced = resign(base, pretty_payload(statement))
    spaced["payload_sha256"] = base["payload_sha256"]
    escaped = resign(base, canonical_text(statement, ascii_only=True).encode("utf-8"))
    solidus_text = canonical(statement)
    if solidus_text.count(b'"app/') != 1:
        raise SystemExit("FAIL: the base path no longer carries exactly one solidus to escape")
    solidus = resign(base, solidus_text.replace(b'"app/', b'"app\\/'))
    return [
        attestation(
            "wrong-digest",
            "reject",
            ["ofg-c-2"],
            wrong_digest,
            parent="base",
            expected=invalid("payload-digest-mismatch"),
            cites="payload_sha256 with its last hex digit changed. The signature still "
            "verifies over the canonical bytes; the digest does not name them.",
        ),
        attestation(
            "spaced",
            "reject",
            ["ofg-c-3"],
            spaced,
            parent="base",
            expected=invalid("signature-invalid"),
            cites="a signature over the statement printed with indentation and sorted keys, "
            "while payload_sha256 names the canonical bytes. A verifier that hashes and "
            "verifies the canonical form refuses the signature.",
        ),
        attestation(
            "escaped-non-ascii",
            "reject",
            ["ofg-c-4"],
            escaped,
            parent="base",
            expected=invalid("payload-digest-mismatch"),
            cites="digest and signature computed over a form that writes the path's CJK "
            "characters as \\u escapes. The canonical form carries them as literal UTF-8.",
        ),
        attestation(
            "escaped-solidus",
            "reject",
            ["ofg-c-5"],
            solidus,
            parent="base",
            expected=invalid("payload-digest-mismatch"),
            cites="digest and signature computed over a form that escapes the path's solidus "
            "as \\/, an escape the minimal set does not include.",
        ),
    ]


def pretty_payload(statement: dict[str, Any]) -> bytes:
    return json.dumps(statement, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8")


def envelope_rejects() -> list[dict[str, Any]]:
    """Members whose envelope was changed after an honest signature."""
    base = signed(base_statement())
    added = copy.deepcopy(base)
    added["statement"]["predicate"]["generated"][0]["reviewed"] = True
    bad_sig = copy.deepcopy(base)
    bad_sig["signatures"][0]["sig"] = flip_signature(base["signatures"][0]["sig"])
    wrong_codec = copy.deepcopy(base)
    wrong_codec["signatures"][0]["keyid"] = did_key(KEYS["fab"], codec=b"\xe7\x01")
    return [
        attestation(
            "added-member",
            "reject",
            ["ofg-c-10"],
            added,
            parent="base",
            expected=invalid("payload-digest-mismatch"),
            cites="a member added to generated[0] after signing. Canonicalized as received "
            "it is covered, so the digest and the signature no longer hold; a verifier that "
            "drops unknown members before hashing accepts it.",
        ),
        attestation(
            "flipped-signature",
            "reject",
            ["ofg-c-11"],
            bad_sig,
            parent="base",
            expected=invalid("signature-invalid"),
            cites="the fab signature with one bit of its first byte flipped.",
        ),
        attestation(
            "wrong-key-codec",
            "reject",
            ["ofg-c-12"],
            wrong_codec,
            parent="base",
            expected=invalid("keyid-not-ed25519-did-key"),
            cites="the fab keyid re-encoded under the secp256k1 multicodec prefix. The key "
            "bytes are the fab key's, but the did:key does not name an ed25519 key.",
        ),
    ]


def statement_rejects() -> list[dict[str, Any]]:
    """Members whose statement breaks a rule and is signed consistently anyway."""
    floating = base_statement()
    floating["predicate"]["params"] = {"temperature": 0.7}
    integer = base_statement()
    integer["predicate"]["params"] = {"temperature": 0}
    empty = base_statement()
    empty["predicate"]["acceptance"] = []
    null_id = base_statement()
    null_id["predicate"]["agent"]["id"] = None
    shouting = base_statement()
    shouting["predicate"]["generated"][0]["author"] = "AI"
    return [
        attestation(
            "float-param",
            "reject",
            ["ofg-c-6"],
            signed(floating),
            parent="float-param-string",
            expected=invalid("floating-point-number"),
            cites="params.temperature as the number 0.7, signed consistently.",
        ),
        param_twin(
            "float-param-string",
            "ofg-c-6",
            {"temperature": "0.7"},
            'params.temperature carried as the string "0.7", inside the value domain.',
        ),
        attestation(
            "integer-param",
            "reject",
            ["ofg-c-7"],
            signed(integer),
            parent="integer-param-string",
            expected=invalid("number-outside-value-domain"),
            cites="params.temperature as the integer 0, signed consistently. The revision's "
            "value domain lists strings, booleans, objects and arrays only; the upstream "
            "implementation's own tests sign such an integer.",
        ),
        param_twin(
            "integer-param-string",
            "ofg-c-7",
            {"temperature": "0"},
            'params.temperature carried as the string "0", inside the value domain.',
        ),
        attestation(
            "empty-acceptance",
            "reject",
            ["ofg-c-8"],
            signed(empty),
            parent="no-acceptance",
            expected=invalid("empty-array-serialized"),
            cites="acceptance serialized as an empty array and signed that way.",
        ),
        attestation(
            "null-agent-id",
            "reject",
            ["ofg-c-9"],
            signed(null_id),
            parent="no-agent-id",
            expected=invalid("null-optional-serialized"),
            cites="agent.id serialized as null and signed that way.",
        ),
        attestation(
            "author-case",
            "reject",
            ["ofg-c-13"],
            signed(shouting),
            parent="base",
            expected=invalid("author-not-in-enum"),
            cites='generated[0].author as "AI", signed consistently.',
        ),
    ]


# ---------------------------------------------------------------------------
# Proposed members.

SIGNERS = [("reviewer-a", "reviewer-a"), ("reviewer-b", "reviewer-b")]


def distinct(env: dict[str, Any]) -> int:
    return len({s["keyid"] for s in env["signatures"] if s["role"] == "human-signoff"})


def signoff_members() -> list[dict[str, Any]]:
    good = signed_off(SIGNERS, inclusive=True)
    upstream = signed_off(SIGNERS, inclusive=False)
    renamed = copy.deepcopy(good)
    renamed["statement"]["predicate"]["signoffs"][1]["name"] = "reviewer-x"
    appended = copy.deepcopy(good)
    appended["statement"]["predicate"]["signoffs"].append(
        {
            "did": did_key(KEYS["reviewer-c"]),
            "name": "reviewer-c",
            "timestamp": "2026-09-22T00:05:00Z",
        }
    )
    swapped = copy.deepcopy(good)
    swapped["statement"]["predicate"]["signoffs"][1]["did"] = did_key(KEYS["reviewer-c"])
    one_key = signed_off([("reviewer-a", "reviewer-a"), ("reviewer-a", "reviewer-b")], True)
    stale = invalid("payload-digest-mismatch")
    rows = [
        (
            "signoffs",
            good,
            ["ofg-p-1", "ofg-p-2", "ofg-p-3", "ofg-p-4", "ofg-p-5"],
            None,
            valid(),
            "two sign-offs by two keys, each covering the records up to its own.",
        ),
        (
            "signoffs-upstream",
            upstream,
            ["ofg-p-1"],
            "signoffs",
            invalid("signoff-signature-invalid"),
            "two sign-offs built the way both upstream implementations build them: the n-th "
            "covers only the records before it, so the last record is signed by nobody.",
        ),
        (
            "signoff-renamed",
            renamed,
            ["ofg-p-2"],
            "signoffs",
            invalid("signoff-signature-invalid"),
            "the last sign-off record's name changed after signing.",
        ),
        (
            "signoff-appended",
            appended,
            ["ofg-p-3"],
            "signoffs",
            invalid("signoff-records-and-signatures-disagree"),
            "a third sign-off record appended with no signature behind it.",
        ),
        (
            "signoff-swapped",
            swapped,
            ["ofg-p-4"],
            "signoffs",
            invalid("signoff-signer-mismatch"),
            "the second record's did replaced by a key that did not sign it.",
        ),
        (
            "signoff-one-key",
            one_key,
            ["ofg-p-5"],
            "signoffs",
            valid(),
            "two sign-off records under two names, both signed by one key: one identity.",
        ),
    ]
    return [
        attestation(
            key,
            "proposed",
            conditions,
            env,
            **({"parent": parent} if parent else {}),
            expected=proposed(stale, outcome, distinctSignoffKeys=distinct(env)),
            cites=what + " Revision 0.1.3 says every signature covers the whole canonical "
            "statement, so a verifier built from its text refuses every signed-off member.",
        )
        for key, env, conditions, parent, outcome, what in rows
    ]


def overlap_statement(ranges: list[tuple[str, str]]) -> dict[str, Any]:
    statement = base_statement()
    statement["subject"][0]["digest"]["sha256"] = sha(OVERLAP_FILE)
    statement["predicate"]["generated"] = [
        {
            "path": OVERLAP_PATH,
            "lines": lines,
            "sha256": range_digest(OVERLAP_FILE, lines),
            "author": author,
        }
        for lines, author in ranges
    ]
    return statement


def overlap_artifacts() -> list[dict[str, str]]:
    rel = artifact_rel(OVERLAP_FILE)
    return [{"name": "golden-v1", "file": rel}, {"name": OVERLAP_PATH, "file": rel}]


TRAILER_AGREES = b"Add the golden file\n\nAssisted-by: golden:test-model\n"
TRAILER_DISAGREES = b"Add the golden file\n\nAssisted-by: golden:other-model\n"


def trailer_rel(content: bytes) -> str:
    return f"trailers/{sha(content)[:ID_HEX]}.txt"


def attribution_members() -> list[dict[str, Any]]:
    base = signed(base_statement())
    return [
        attestation(
            "ranges-disjoint",
            "accept",
            ["ofg-p-6"],
            signed(overlap_statement([("1-9", "human"), ("10-30", "ai")])),
            artifacts=overlap_artifacts(),
            expected=valid(),
            cites="two attribution ranges over one file that do not overlap.",
        ),
        attestation(
            "ranges-overlap",
            "proposed",
            ["ofg-p-6"],
            signed(overlap_statement([("1-20", "ai"), ("10-30", "human")])),
            artifacts=overlap_artifacts(),
            parent="ranges-disjoint",
            expected=proposed(valid(), invalid("attribution-ranges-overlap")),
            cites="lines 10 to 20 of one file claimed as both AI-generated and human-written. "
            "Revision 0.1.3 has no rule against it.",
        ),
        attestation(
            "trailer-agrees",
            "accept",
            ["ofg-p-7"],
            base,
            trailer=TRAILER_AGREES,
            expected=valid(),
            cites="the base attestation beside a commit whose Assisted-by trailer is agent.id.",
        ),
        attestation(
            "trailer-disagrees",
            "proposed",
            ["ofg-p-7"],
            base,
            trailer=TRAILER_DISAGREES,
            parent="trailer-agrees",
            expected=proposed(valid(), invalid("trailer-disagrees")),
            cites="the base attestation beside a commit whose Assisted-by trailer names a "
            "different model. The revision lets a verifier skip the cross-check.",
        ),
    ]


def encoding_members() -> list[dict[str, Any]]:
    astral = base_statement()
    astral["predicate"]["params"] = {"｡": "a", "\U0001f600": "b"}
    unsafe = base_statement()
    unsafe["predicate"]["params"] = {"seed": 9007199254740993}
    safe = base_statement()
    safe["predicate"]["params"] = {"seed": 9007199254740991}
    base = signed(base_statement())
    body = pretty(base)
    once = b'"author": "ai"'
    if body.count(once) != 1:
        raise SystemExit("FAIL: the base envelope no longer carries exactly one author member")
    duplicated = body.replace(once, b'"author": "human",\n          "author": "ai"')
    outside = invalid("number-outside-value-domain")
    return [
        attestation(
            "key-order-code-point",
            "proposed",
            ["ofg-p-8"],
            signed(astral, "codepoint"),
            parent="key-order-utf16",
            expected=proposed(valid(), invalid("payload-digest-mismatch")),
            cites="params names U+FF61 and U+1F600, signed in code-point order as the "
            "revision's bullet says. RFC 8785 puts U+1F600 first.",
        ),
        attestation(
            "key-order-utf16",
            "proposed",
            ["ofg-p-8"],
            signed(astral, "utf16"),
            parent="key-order-code-point",
            expected=proposed(invalid("payload-digest-mismatch"), valid()),
            cites="the same statement signed in RFC 8785 order, which the revision says its "
            "form coincides with.",
        ),
        attestation(
            "integer-unsafe",
            "proposed",
            ["ofg-p-9"],
            signed(unsafe),
            parent="integer-safe",
            expected=proposed(outside, invalid("unsafe-integer")),
            cites="params.seed as 2^53 + 1. JavaScript reads it as 2^53; a 64-bit integer "
            "reader keeps it, so two verifiers hash different bytes.",
        ),
        attestation(
            "integer-safe",
            "proposed",
            ["ofg-p-9"],
            signed(safe),
            expected=proposed(outside, valid()),
            cites="params.seed as 2^53 - 1, the largest I-JSON safe integer.",
        ),
        attestation(
            "duplicate-author",
            "proposed",
            ["ofg-p-10"],
            base,
            body=duplicated,
            parent="base",
            expected=proposed({"verdict": "indeterminate"}, invalid("duplicate-member")),
            cites="generated[0] carries author twice, human and then ai; the signature covers "
            "the ai reading. A parser keeping the first copy reads a human-written range.",
        ),
    ]


def build() -> list[dict[str, Any]]:
    return (
        [golden_member()]
        + base_members()
        + canonical_rejects()
        + envelope_rejects()
        + statement_rejects()
        + signoff_members()
        + attribution_members()
        + encoding_members()
    )


# ---------------------------------------------------------------------------
# Manifest, index and the files on disk.


def identify(m: dict[str, Any]) -> str:
    preimage = m["body"] if "trailer" not in m else m["body"] + b"\x00" + m["trailer"]
    return "v" + sha(preimage)[:ID_HEX]


def sidecars(members: list[dict[str, Any]]) -> dict[str, bytes]:
    files = {artifact_rel(GOLDEN_FILE): GOLDEN_FILE, artifact_rel(OVERLAP_FILE): OVERLAP_FILE}
    for m in members:
        if "trailer" in m:
            files[trailer_rel(m["trailer"])] = m["trailer"]
    return files


def row_for(m: dict[str, Any], vid: str, ids: dict[str, str]) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": vid,
        "kind": m["kind"],
        "form": m["form"],
        "file": f"statements/{vid}.json",
        "conditions": m["conditions"],
    }
    if "parent" in m:
        row["parent"] = ids[m["parent"]]
    if "artifacts" in m:
        row["artifacts"] = m["artifacts"]
    if "trailer" in m:
        row["trailer"] = trailer_rel(m["trailer"])
    row["expected"] = m["expected"]
    row["cites"] = m["cites"]
    return row


def vendored_digest(rel: str) -> str:
    with open(os.path.join(HERE, rel), "rb") as handle:
        return sha(handle.read())


def manifest_head() -> dict[str, Any]:
    return {
        "suite": SUITE,
        "predicateType": PREDICATE_TYPE,
        "tracksUpstream": TRACKS_UPSTREAM,
        "specUpstreamRepo": SPEC_UPSTREAM_REPO,
        "specUpstreamCommit": SPEC_UPSTREAM_COMMIT,
        "specRevision": SPEC_REVISION,
        "specAuthority": "specDigest",
        "specProvenanceNote": (
            "tracksUpstream names where the predicate is discussed for adoption. The "
            "specification text, its JSON Schema and its licence are vendored unchanged "
            "from specUpstreamRepo at specUpstreamCommit; the pin a verifier acts on is "
            "each file's digest, which aee-verify recomputes on every run."
        ),
        "specVendored": SPEC_VENDORED,
        "specDigest": vendored_digest(SPEC_VENDORED),
        "schemaVendored": SCHEMA_VENDORED,
        "schemaDigest": vendored_digest(SCHEMA_VENDORED),
        "licenseVendored": LICENSE_VENDORED,
        "licenseDigest": vendored_digest(LICENSE_VENDORED),
        "goldenSource": GOLDEN_SOURCE,
        "proposedText": PROPOSED_TEXT,
        "keys": {name: did_key(KEYS[name]) for name in KEY_NAMES},
        "keyNote": (
            "PUBLISHED TEST KEYS. Each seed is the sha256 of the ASCII string "
            "'agent-evidence-vectors ai-generation test key: ' followed by the key's name. "
            "They sign nothing outside this directory."
        ),
        "conditions": CONDITIONS,
    }


def build_manifest() -> tuple[dict[str, Any], dict[str, bytes]]:
    members = build()
    ids = {m["key"]: identify(m) for m in members}
    if len(set(ids.values())) != len(members):
        raise SystemExit("FAIL: two members share an identifier")
    files = sidecars(members)
    entries = []
    for m in members:
        files[f"statements/{ids[m['key']]}.json"] = m["body"]
        entries.append(row_for(m, ids[m["key"]], ids))
    entries.sort(key=lambda entry: entry["id"])
    manifest = manifest_head()
    manifest["counts"] = {
        kind: sum(1 for entry in entries if entry["kind"] == kind)
        for kind in ("accept", "reject", "proposed")
    }
    manifest["vectors"] = entries
    manifest["corpusDigest"] = digest_of(entries, files)
    manifest["note"] = (
        "accept and reject members are graded against revision 0.1.3 as written, and a "
        "reject names its conformant parent. A proposed member declares both what the "
        "revision says of it and what proposedText says; no verifier is failed on one."
    )
    files["MANIFEST.json"] = json.dumps(manifest, indent=2, ensure_ascii=False).encode() + b"\n"
    files["INDEX.md"] = render_index(manifest).encode("utf-8")
    return manifest, files


def digest_of(entries: list[dict[str, Any]], files: dict[str, bytes]) -> str:
    """The corpus digest over the bytes about to be written, through the one spelling."""
    return ordered_digest(entries, files.__getitem__)


def outcome_text(outcome: dict[str, Any]) -> str:
    if "code" in outcome:
        return f"{outcome['verdict']} `{outcome['code']}`"
    return str(outcome["verdict"])


def expectation(entry: dict[str, Any]) -> str:
    expected = entry["expected"]
    if entry["kind"] == "proposed":
        return (
            f"0.1.3: {outcome_text(expected['rev013'])}; "
            f"proposal: {outcome_text(expected['proposal'])}"
        )
    if "canonicalSha256" in expected:
        return f"canonical sha256 `{expected['canonicalSha256'][:12]}`"
    return outcome_text(expected)


def render_index(manifest: dict[str, Any]) -> str:
    rows = "\n".join(
        "| `{id}` | {kind} | {cond} | {exp} | {parent} |".format(
            id=entry["id"],
            kind=entry["kind"],
            cond=", ".join(entry["conditions"]),
            exp=expectation(entry),
            parent=f"`{entry['parent']}`" if "parent" in entry else "",
        )
        for entry in manifest["vectors"]
    )
    conditions = "\n".join(
        "| `{key}` | {requires} | {source} |".format(
            key=key,
            requires=value["requires"],
            source=value.get("clause") or "gap: " + value["gap"],
        )
        for key, value in sorted(CONDITIONS.items(), key=lambda item: condition_order(item[0]))
    )
    accept = manifest["counts"]["accept"]
    reject = manifest["counts"]["reject"]
    total = len(manifest["vectors"])
    return f"""# Conformance vectors (AI generation predicate v0.1)

Every member of this suite in one table. The subject under test is a verifier
of the generation predicate `{PREDICATE_TYPE}` at specification revision
{SPEC_REVISION}, in its default attest-only mode.

This corpus is {total} vectors, of which {accept} a conformant verifier must not
fail closed on and {reject} it must reject.

The remaining members are graded `proposed`: each declares what revision
{SPEC_REVISION} says about it and what `../{PROPOSED_TEXT}` proposes, and a
verifier is never failed on one.

The specification, its JSON Schema and its licence are vendored under
`spec-vendored/` and pinned by digest in the manifest. The golden member is
the upstream repository's pinned golden vector, transcribed from the test that
pins it.

Regenerate byte-identically: `python3 gen_vectors.py`.
Self-check: `aee-verify vectors-ai-generation/` from the repository root.

## Conditions

| id | what it requires | clause of revision {SPEC_REVISION}, or the gap |
|---|---|---|
{conditions}

## Vectors

| id | kind | conditions | expected | parent |
|---|---|---|---|---|
{rows}
"""


def condition_order(key: str) -> tuple[str, int]:
    family, _, number = key.rpartition("-")
    return family, int(number)


# ---------------------------------------------------------------------------

OWNED_DIRS = ("statements", "artifacts", "trailers")


def verify_tree(files: dict[str, bytes]) -> int:
    bad = []
    for rel, payload in sorted(files.items()):
        path = os.path.join(HERE, rel)
        if not os.path.exists(path):
            bad.append(f"{rel} is missing")
            continue
        with open(path, "rb") as handle:
            if handle.read() != payload:
                bad.append(f"{rel} differs from what the generator emits")
    for directory in OWNED_DIRS:
        root = os.path.join(HERE, directory)
        for name in sorted(os.listdir(root)) if os.path.isdir(root) else []:
            if f"{directory}/{name}" not in files:
                bad.append(f"{directory}/{name} is on disk and the generator emits no such file")
    if bad:
        for line in bad:
            print("FAIL", line, file=sys.stderr)
        print("\nRun `python3 gen_vectors.py` to rebuild, and commit the diff.", file=sys.stderr)
        return 1
    print(f"OK generator reproduces {len(files)} file(s) byte-identically")
    return 0


def write_tree(files: dict[str, bytes]) -> None:
    for directory in OWNED_DIRS:
        root = os.path.join(HERE, directory)
        os.makedirs(root, exist_ok=True)
        for name in sorted(os.listdir(root)):
            if f"{directory}/{name}" not in files:
                os.unlink(os.path.join(root, name))
    for rel, payload in sorted(files.items()):
        with open(os.path.join(HERE, rel), "wb") as handle:
            handle.write(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="refuse a tree this does not emit")
    check = parser.parse_args().check
    manifest, files = build_manifest()
    if check:
        return verify_tree(files)
    write_tree(files)
    counts = manifest["counts"]
    print(
        f"wrote {len(files)} file(s): {counts['accept']} accept, {counts['reject']} reject, "
        f"{counts['proposed']} proposed, corpus {manifest['corpusDigest'][:12]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
