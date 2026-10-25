#!/usr/bin/env python3
"""Build the Proof-of-Control conformance corpus.

Reads the specification's own reference implementation and validator, pinned at
build/spec-93d0e28 (the LFDT-ProofOfControl/ov-poc-standard tree at commit
93d0e282fc177d5df741de4cdd6a0d0dacf1955a), and writes one JSON file per case
under package/poc_evidence_vectors/corpus/<kind>/.

Every negative case is ONE mutation of a base artifact that the twin verifier
(package/poc_evidence_vectors/twin.py) accepts, so a rejection can only be for
the stated reason. Output is byte-reproducible: fixed key, fixed timestamp,
fixed nonces, sorted JSON.

    python3 build/proof-of-control-build.py            # write the corpus
    python3 build/proof-of-control-build.py --check    # exit 1 if the tree differs
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SPEC = HERE / "spec-93d0e28"
OUT = ROOT / "package" / "poc_evidence_vectors" / "corpus"
sys.path.insert(0, str(SPEC / "impl"))
sys.path.insert(0, str(SPEC / "schema"))
sys.path.insert(0, str(ROOT / "package"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from poc import Action, AttestingEnvironment, Grant, PolicyEngine  # noqa: E402
from poc.merkle import MerkleTree, leaf_hash, node_hash  # noqa: E402
from validate import jcs, signing_input  # noqa: E402

SPEC_COMMIT = "93d0e282fc177d5df741de4cdd6a0d0dacf1955a"
SEED = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
FROZEN_IAT = 1_754_400_000
AGENT = "did:web:example.org:agents:ref-1"
SK = Ed25519PrivateKey.from_private_bytes(SEED)
PK_HEX = SK.public_key().public_bytes_raw().hex()
L_ORDER = 2**252 + 27742317777372353535851937790883648493

CASES: list[dict] = []


def add(kind, cid, requirements, expect, klass, note, **body):
    CASES.append(
        {
            "id": cid,
            "kind": kind,
            "requirements": requirements,
            "class": klass,
            "expect": expect,
            "note": note,
            **body,
        }
    )


ACCEPT = {"result": "accept"}


def reject(*codes):
    return {"result": "reject", "code": list(codes)}


# ----------------------------------------------------------------- base chain
def resign(tok):
    tok = {k: v for k, v in tok.items() if k != "signature"}
    tok["iat"] = FROZEN_IAT
    tok["signature"] = SK.sign(signing_input(tok)).hex()
    return tok


def build_chain(actions):
    grant = Grant(
        "user:alice",
        frozenset({"db.read", "http.post"}),
        frozenset({"customers", "api.partner.com"}),
        max_spend=1000.0,
        max_sensitivity_egress="internal",
    )
    ae = AttestingEnvironment(PolicyEngine(grant, path_aware=True), signing_key=SK)
    toks = []
    for i, a in enumerate(actions):
        out = ae.evaluate_and_evidence(a, f"nonce-{i:08d}", AGENT)
        toks.append(resign(out["token"]))
    return ae, toks


ACTIONS = [
    Action("db.read", "customers", {"row": 1}, classification="confidential"),
    Action("http.post", "api.partner.com", {"body": "a"}),
    Action("db.read", "customers", {"row": 2}, classification="internal"),
    Action("db.read", "customers", {"row": 3}, classification="internal"),
    Action("http.post", "api.partner.com", {"body": "b"}),
    Action("db.read", "customers", {"row": 4}, classification="public"),
]
AE, CHAIN = build_chain(ACTIONS)
MEASURE_HEX = AE.measurement
BASE = CHAIN[0]


def dump(tok):
    return json.dumps(tok, indent=2, sort_keys=True) + "\n"


def token_case(
    cid, reqs, expect, klass, note, tok=None, text=None, key=True, ground=None
):
    extra = {"grounding": {"file": ground[0], "quote": ground[1]}} if ground else {}
    add(
        "token",
        cid,
        reqs,
        expect,
        klass,
        note,
        text=text if text is not None else dump(tok),
        public_key=PK_HEX if key else None,
        **extra,
    )


def mutated(fn, sign=True):
    t = copy.deepcopy(BASE)
    fn(t)
    return resign(t) if sign else t


# ------------------------------------------------------------------- tokens
def build_tokens():
    token_case(
        "TOK-P-base", ["7.7.1"], ACCEPT, "positive", "an ordinary ALLOW record", BASE
    )
    token_case(
        "TOK-P-deny",
        ["7.7.1"],
        ACCEPT,
        "positive",
        "a DENY record is evidence too",
        CHAIN[1],
    )
    token_case(
        "TOK-P-pretty-vs-compact",
        ["7.7.2"],
        ACCEPT,
        "positive",
        "a compact rendering of the same claims must validate: the "
        "signature is over the canonical form, not the received bytes",
        text=json.dumps(BASE, separators=(",", ":")) + "\n",
    )
    token_case(
        "TOK-P-crlf-whitespace",
        ["7.7.2"],
        ACCEPT,
        "positive",
        "insignificant whitespace and CRLF line ends change no meaning",
        text=json.dumps(BASE, indent=4).replace("\n", "\r\n") + "\r\n",
    )
    for hook in (
        "TASK_INITIALIZATION",
        "CONTEXT_ASSEMBLY",
        "PLAN_GENERATION",
        "POST_CALL_TOOL_RESULT",
        "MEMORY_WRITE",
        "SUBAGENT_DELEGATION",
        "TASK_COMPLETION",
    ):
        token_case(
            f"TOK-P-hook-{hook.lower().replace('_', '-')}",
            ["7.7.1"],
            ACCEPT,
            "positive",
            f"interception point {hook}",
            mutated(lambda t, h=hook: t["poc_claims"].update(interception_point=h)),
        )
    token_case(
        "TOK-P-escalate",
        ["7.7.1"],
        ACCEPT,
        "positive",
        "verdict ESCALATE",
        mutated(lambda t: t["poc_claims"].update(verdict="ESCALATE")),
    )
    token_case(
        "TOK-P-sha3-digest",
        ["7.7.3"],
        ACCEPT,
        "positive",
        "an algorithm-tagged sha3-256 digest where the schema allows it",
        mutated(
            lambda t: t["poc_claims"].update(
                agbom_digest="sha3-256:" + hashlib.sha3_256(b"x").hexdigest()
            )
        ),
    )
    token_case(
        "TOK-P-extension-ascii",
        ["7.7.2"],
        ACCEPT,
        "positive",
        "an extension claim with a lowercase tagged digest",
        mutated(
            lambda t: t["poc_claims"].update(
                vendor_context_digest="sha-256:" + hashlib.sha256(b"c").hexdigest()
            )
        ),
    )

    # --- missing required claim: one case per claim (requirement 7.7.1)
    top_required = ["iss", "iat", "nonce", "eat_profile", "submods"]
    claim_required = [
        "agent_id",
        "initiating_user",
        "agbom_digest",
        "interception_point",
        "step_index",
        "chain_head",
        "merkle_root",
        "tree_size",
        "policy_bundle_hash",
        "target_resource",
        "canonical_snapshot_hash",
        "path_summary_hash",
        "verdict",
        "alg",
    ]
    for k in top_required:

        def drop(t, k=k):
            del t[k]

        t = copy.deepcopy(BASE)
        drop(t)
        t = {x: v for x, v in t.items() if x != "signature"}
        if k != "iat":
            t["iat"] = FROZEN_IAT
        t["signature"] = SK.sign(signing_input(t)).hex()
        token_case(
            f"TOK-N-missing-{k.replace('_', '-')}",
            ["7.7.1"],
            reject("schema"),
            "negative",
            f"required member {k} absent",
            t,
        )
    for k in claim_required:
        token_case(
            f"TOK-N-missing-claim-{k.replace('_', '-')}",
            ["7.7.1"],
            reject("schema"),
            "negative",
            f"required claim {k} absent",
            mutated(lambda t, k=k: t["poc_claims"].pop(k)),
        )

    # --- digests: algorithm identifier is mandatory (7.7.3, 6.3.4)
    digest_claims = [
        "agbom_digest",
        "chain_head",
        "merkle_root",
        "policy_bundle_hash",
        "canonical_snapshot_hash",
        "path_summary_hash",
    ]
    for k in digest_claims:
        token_case(
            f"TOK-N-untagged-{k.replace('_', '-')}",
            ["7.7.3"],
            reject("schema"),
            "negative",
            f"{k} written as bare hex: the algorithm must not be guessed",
            mutated(
                lambda t, k=k: t["poc_claims"].update(
                    {k: t["poc_claims"][k].split(":", 1)[1]}
                )
            ),
        )
    token_case(
        "TOK-N-digest-unknown-alg",
        ["7.7.3"],
        reject("schema"),
        "negative",
        "digest tagged md5",
        mutated(lambda t: t["poc_claims"].update(chain_head="md5:" + "0" * 32)),
    )
    token_case(
        "TOK-N-digest-uppercase-tag",
        ["7.7.3", "7.7.2"],
        reject("schema"),
        "negative",
        "algorithm tag in upper case",
        mutated(
            lambda t: t["poc_claims"].update(
                chain_head=t["poc_claims"]["chain_head"].replace("sha-256", "SHA-256")
            )
        ),
    )
    token_case(
        "TOK-N-digest-short",
        ["7.7.3"],
        reject("schema"),
        "negative",
        "sha-256 digest with 63 hex characters",
        mutated(
            lambda t: t["poc_claims"].update(
                chain_head=t["poc_claims"]["chain_head"][:-1]
            )
        ),
    )
    token_case(
        "TOK-N-digest-width-sha256-as-sha512",
        ["7.7.3"],
        reject("schema"),
        "negative",
        "a 32-byte value tagged sha-512",
        mutated(
            lambda t: t["poc_claims"].update(
                chain_head="sha-512:" + t["poc_claims"]["chain_head"].split(":")[1]
            )
        ),
    )
    token_case(
        "TOK-N-digest-uppercase-hex-core-claim",
        ["7.7.2"],
        reject("schema", "hex-case"),
        "negative",
        "a core digest with upper-case hex",
        mutated(
            lambda t: t["poc_claims"].update(
                merkle_root="sha-256:"
                + t["poc_claims"]["merkle_root"].split(":")[1].upper()
            )
        ),
    )
    token_case(
        "TOK-N-digest-uppercase-hex-extension",
        ["7.7.2"],
        reject("hex-case"),
        "negative",
        "an extension claim with upper-case hex (open schema)",
        mutated(
            lambda t: t["poc_claims"].update(
                vendor_context_digest="sha-256:"
                + hashlib.sha256(b"c").hexdigest().upper()
            )
        ),
    )
    token_case(
        "TOK-N-digest-uppercase-hex-submod",
        ["7.7.2"],
        reject("schema", "hex-case"),
        "negative",
        "the attestation measurement with upper-case hex",
        mutated(
            lambda t: t["submods"]["attestation"].update(
                measurement="sha-256:"
                + t["submods"]["attestation"]["measurement"].split(":")[1].upper()
            )
        ),
    )

    # --- enumerations and algorithm agility (6.3.4, 7.7.1)
    for cid, patch, why in (
        ("verdict-lowercase", {"verdict": "allow"}, "verdict in lower case"),
        ("verdict-unknown", {"verdict": "PERMIT"}, "verdict outside the enumeration"),
        ("alg-none", {"alg": "none"}, "the none algorithm"),
        ("alg-hmac", {"alg": "HS256"}, "a symmetric algorithm"),
        ("step-index-negative", {"step_index": -1}, "negative step index"),
        ("tree-size-zero", {"tree_size": 0}, "empty tree"),
        ("initiating-user-empty", {"initiating_user": ""}, "empty principal"),
        ("agent-id-empty", {"agent_id": ""}, "empty agent identifier"),
    ):
        token_case(
            f"TOK-N-{cid}",
            ["6.3.4" if cid.startswith("alg") else "7.7.1"],
            reject("schema"),
            "negative",
            why,
            mutated(lambda t, p=patch: t["poc_claims"].update(p)),
        )
    token_case(
        "TOK-N-step-index-string",
        ["7.7.1"],
        reject("schema"),
        "negative",
        "step index as a string",
        mutated(lambda t: t["poc_claims"].update(step_index="0")),
    )
    token_case(
        "TOK-N-step-index-bool",
        ["7.7.1"],
        reject("schema"),
        "negative",
        "step index as a boolean",
        mutated(lambda t: t["poc_claims"].update(step_index=False)),
    )
    token_case(
        "TOK-N-step-index-float-integral",
        ["7.7.2", "7.7.1"],
        reject("float-in-claims", "schema"),
        "negative",
        "step index written 0.0: an integer valued float is still a float",
        text=dump(BASE).replace('"step_index": 0', '"step_index": 0.0'),
        key=False,
    )
    token_case(
        "TOK-N-nonce-short",
        ["7.7.1"],
        reject("schema"),
        "negative",
        "nonce under 8 characters",
        mutated(lambda t: t.update(nonce="short")),
    )
    token_case(
        "TOK-N-profile-trailing-slash",
        ["7.7.1"],
        reject("schema"),
        "negative",
        "profile URI with a trailing slash",
        mutated(
            lambda t: t.update(eat_profile="https://advancedaisociety.org/poc/v0.1/")
        ),
    )
    token_case(
        "TOK-N-reference-time-float",
        ["7.7.2"],
        reject("float-in-claims"),
        "negative",
        "iat with a fractional part",
        text=dump(BASE).replace(f'"iat": {FROZEN_IAT}', f'"iat": {FROZEN_IAT}.5'),
        key=False,
    )
    token_case(
        "TOK-N-null-for-optional",
        ["7.7.2"],
        reject("schema"),
        "negative",
        "an optional digest present as null: absent is not null",
        mutated(lambda t: t["poc_claims"].update(dispatched_snapshot_hash=None)),
    )

    # --- semantic checks
    token_case(
        "TOK-N-tree-size-equals-step-index",
        ["7.3.4"],
        reject("tree-size"),
        "negative",
        "tree_size equal to step_index: the record is not in its own tree",
        mutated(lambda t: t["poc_claims"].update(step_index=3, tree_size=3)),
    )
    token_case(
        "TOK-N-modify-without-dispatch-hash",
        ["7.1.4"],
        reject("modify-unbound"),
        "negative",
        "MODIFY that commits only to the proposal",
        mutated(lambda t: t["poc_claims"].update(verdict="MODIFY")),
    )
    token_case(
        "TOK-P-modify-dispatch-differs",
        ["7.1.4"],
        ACCEPT,
        "positive",
        "MODIFY whose dispatched digest differs from the proposal",
        mutated(
            lambda t: t["poc_claims"].update(
                verdict="MODIFY",
                dispatched_snapshot_hash="sha-256:"
                + hashlib.sha256(b"ran").hexdigest(),
            )
        ),
    )

    # --- signature layer
    token_case(
        "TOK-N-signature-flipped-bit",
        ["7.3.2"],
        reject("signature"),
        "negative",
        "one bit of the signature flipped",
        _flip_signature(BASE),
    )
    token_case(
        "TOK-N-signature-truncated",
        ["7.3.2"],
        reject("signature"),
        "negative",
        "signature cut to 63 bytes",
        _with_sig(BASE, BASE["signature"][:-2]),
    )
    token_case(
        "TOK-N-signature-uppercase",
        ["7.7.2"],
        reject("schema"),
        "negative",
        "a valid signature written in upper-case hex",
        _with_sig(BASE, BASE["signature"].upper()),
    )
    token_case(
        "TOK-N-signature-s-not-reduced",
        ["7.3.2", "7.7.2"],
        reject("signature"),
        "negative",
        "the same signature with S replaced by S + L (malleable encoding)",
        _with_sig(BASE, _malleate(BASE["signature"])),
    )
    token_case(
        "TOK-N-signature-absent-with-key",
        ["7.3.2"],
        reject("unsigned", "schema"),
        "negative",
        "no signature member although a key is supplied",
        {k: v for k, v in BASE.items() if k != "signature"},
    )
    token_case(
        "TOK-N-claim-altered-after-signing",
        ["7.3.2"],
        reject("signature"),
        "negative",
        "verdict changed from ALLOW to DENY after signing",
        _tamper(BASE, lambda t: t["poc_claims"].update(verdict="DENY")),
    )
    token_case(
        "TOK-N-signed-with-other-key",
        ["7.3.2"],
        reject("signature"),
        "negative",
        "validly signed by a key the verifier does not trust",
        _other_key(BASE),
    )

    # --- duplicate keys and parsing (7.7.5)
    base_text = dump(BASE)
    token_case(
        "TOK-N-dup-top-level",
        ["7.7.5"],
        reject("duplicate-key"),
        "negative",
        "duplicate top-level member",
        text=base_text.replace(
            '"iss":', '"iss": "https://other.example/",\n  "iss":', 1
        ),
    )
    token_case(
        "TOK-N-dup-nested-submods",
        ["7.7.5"],
        reject("duplicate-key"),
        "negative",
        "duplicate member inside submods.attestation",
        text=base_text.replace(
            '"platform": "SOFTWARE"',
            '"platform": "INTEL_TDX",\n      "platform": "SOFTWARE"',
            1,
        ),
    )
    token_case(
        "TOK-N-dup-escaped-equivalent",
        ["7.7.5"],
        reject("duplicate-key"),
        "negative",
        "the second 'verdict' member is spelled with a \\u0076 escape: "
        "the keys differ as bytes and are equal as strings",
        text=base_text.replace(
            '"verdict": "ALLOW"', '"verdict": "DENY",\n    "\\u0076erdict": "ALLOW"', 1
        ),
    )
    token_case(
        "TOK-N-parse-bom",
        ["7.7.2"],
        reject("parse"),
        "robustness",
        "a UTF-8 byte order mark before the token (rule 1)",
        text="﻿" + base_text,
        key=False,
    )
    token_case(
        "TOK-N-parse-trailing-comma",
        ["7.7.5"],
        reject("parse"),
        "robustness",
        "a trailing comma",
        text=base_text.rstrip()[:-1].rstrip() + ",\n}\n",
        key=False,
    )
    token_case(
        "TOK-N-parse-lone-surrogate",
        ["7.7.2"],
        reject("parse", "schema"),
        "robustness",
        "a string holding an unpaired surrogate (\\ud800): not UTF-8 "
        "encodable, so no canonical bytes exist for it",
        text=base_text.replace(
            '"reason": "within grant"', '"reason": "bad \\ud800 text"', 1
        ),
        key=False,
    )

    # --- findings: places where the requirement text says reject and the
    #     reference validator is expected to accept (measured by the report)
    token_case(
        "TOK-F-modify-same-as-proposed",
        ["7.1.4"],
        reject("modify-unbound", "schema", "semantic"),
        "finding",
        "MODIFY whose dispatched digest equals the proposed digest: the "
        "schema defines MODIFY as 'the dispatched action differs from the "
        "proposed one'",
        mutated(
            lambda t: t["poc_claims"].update(
                verdict="MODIFY",
                dispatched_snapshot_hash=t["poc_claims"]["canonical_snapshot_hash"],
            )
        ),
        ground=(
            "poc-evidence.schema.json",
            "MODIFY means the dispatched action differs from the proposed one",
        ),
    )
    token_case(
        "TOK-A-allow-with-dispatch-hash",
        ["7.1.4"],
        ACCEPT,
        "ambiguity",
        "dispatched_snapshot_hash on an ALLOW record: the schema says the "
        "claim is required when verdict is MODIFY and is silent on other "
        "verdicts; the reference accepts it and the editors should say which",
        mutated(
            lambda t: t["poc_claims"].update(
                dispatched_snapshot_hash="sha-256:" + hashlib.sha256(b"ran").hexdigest()
            )
        ),
    )
    for plat, width_tag in (("INTEL_TDX", "sha-256"), ("AMD_SEV_SNP", "sha-256")):
        token_case(
            f"TOK-F-{plat.lower().replace('_', '-')}-measurement-sha256",
            ["7.2.4", "6.2.2"],
            reject("semantic", "schema"),
            "platform-fact",
            f"{plat} attestation carrying a 32-byte measurement; this "
            f"platform measures with SHA-384, and the specification's own "
            f"generator records that a 32-byte value in an INTEL_TDX vector "
            f"was a defect",
            mutated(lambda t, p=plat: t["submods"]["attestation"].update(platform=p)),
        )
    token_case(
        "TOK-F-reason-empty-string",
        ["7.7.2"],
        reject("schema", "semantic"),
        "finding",
        "reason present as the empty string: canonicalization rule 7 says an "
        "optional claim that does not apply is omitted, never present empty",
        mutated(lambda t: t["poc_claims"].update(reason="")),
        ground=(
            "canonicalization.md",
            "It is not present with an empty string, an empty object, or `null`.",
        ),
    )
    token_case(
        "TOK-F-reference-values-uri-empty",
        ["7.7.2"],
        reject("schema", "semantic"),
        "finding",
        "reference_values_uri present as the empty string",
        mutated(lambda t: t["submods"]["attestation"].update(reference_values_uri="")),
        ground=(
            "canonicalization.md",
            "It is not present with an empty string, an empty object, or `null`.",
        ),
    )
    token_case(
        "TOK-F-integer-beyond-2-53",
        ["7.7.2"],
        reject("schema", "canonical", "semantic"),
        "interop",
        "tree_size 2^53 + 1: no ECMAScript implementation can read this "
        "integer back exactly, so two implementations canonicalize it "
        "differently",
        mutated(lambda t: t["poc_claims"].update(tree_size=2**53 + 1)),
    )
    token_case(
        "TOK-F-trailing-garbage",
        ["7.7.5"],
        reject("parse"),
        "robustness",
        "a complete token followed by a second JSON value",
        text=base_text + "{}\n",
        key=False,
    )

    # --- the canonicalization ambiguity: code point vs UTF-16 order for claim
    #     set keys. Rule 2 of canonicalization.md says code point; validate.py
    #     sorts by UTF-16 code unit. Extension claims are open, so a claim set
    #     can carry non-BMP keys. Two correctly formed tokens, each signed over
    #     one ordering. The class is "ambiguity": expectations follow the
    #     reference validator and the report says so.
    ext = {"\U0001f600": "astral", "＀": "bmp"}
    t = copy.deepcopy(BASE)
    t["poc_claims"]["vendor_ext"] = ext
    t = resign(t)
    token_case(
        "TOK-A-nonbmp-extension-key-utf16-order",
        ["7.7.2"],
        ACCEPT,
        "ambiguity",
        "extension claim with a non-BMP key, signed over RFC 8785 (UTF-16 "
        "code unit) order, as validate.py does",
        t,
    )
    body = {k: v for k, v in t.items() if k != "signature"}
    cp = json.dumps(
        body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    t2 = dict(body)
    t2["signature"] = SK.sign(cp).hex()
    token_case(
        "TOK-A-nonbmp-extension-key-codepoint-order",
        ["7.7.2"],
        reject("signature"),
        "ambiguity",
        "the same token signed over code point order, which is what rule 2 "
        "of canonicalization.md literally says; validate.py rejects it",
        t2,
    )


def _with_sig(tok, sig):
    t = copy.deepcopy(tok)
    t["signature"] = sig
    return t


def _flip_signature(tok):
    s = tok["signature"]
    flipped = s[:10] + format(int(s[10], 16) ^ 1, "x") + s[11:]
    return _with_sig(tok, flipped)


def _malleate(sig_hex):
    raw = bytes.fromhex(sig_hex)
    s = int.from_bytes(raw[32:], "little") + L_ORDER
    return (raw[:32] + s.to_bytes(32, "little")).hex()


def _tamper(tok, fn):
    t = copy.deepcopy(tok)
    fn(t)
    return t


def _other_key(tok):
    other = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    t = {k: v for k, v in tok.items() if k != "signature"}
    t["signature"] = other.sign(signing_input(t)).hex()
    return t


# -------------------------------------------------------------- merkle trees
def tree_of(n, salt="a"):
    t = MerkleTree()
    recs = []
    for i in range(n):
        r = json.dumps(
            {
                "snapshot": hashlib.sha256(f"{salt}{i}".encode()).hexdigest(),
                "verdict": "ALLOW",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        recs.append(r)
        t.append(r)
    return t, recs


def inc_case(
    cid, klass, expect, note, index, size, record, proof, root, reqs=("7.3.4",)
):
    add(
        "inclusion",
        cid,
        list(reqs),
        expect,
        klass,
        note,
        index=index,
        tree_size=size,
        record_hex=record.hex(),
        proof=[p.hex() for p in proof],
        root=root.hex(),
    )


def build_inclusion():
    for n in (1, 2, 3, 4, 5, 7, 8, 9):
        t, recs = tree_of(n)
        for i in sorted({0, n // 2, n - 1}):
            inc_case(
                f"INC-P-n{n}-i{i}",
                "positive",
                ACCEPT,
                f"record {i} of a {n}-leaf tree",
                i,
                n,
                recs[i],
                t.inclusion_proof(i),
                t.root(),
            )
    t, recs = tree_of(7)
    root, i = t.root(), 4
    proof = t.inclusion_proof(i)
    inc_case(
        "INC-N-wrong-index",
        "negative",
        reject("not-included"),
        "the proof for index 4 presented at index 3",
        3,
        7,
        recs[i],
        proof,
        root,
    )
    inc_case(
        "INC-N-wrong-tree-size",
        "negative",
        reject("not-included"),
        "a size-7 proof presented against size 16",
        i,
        16,
        recs[i],
        proof,
        root,
    )
    inc_case(
        "INC-O-size-not-bound-by-root",
        "observation",
        ACCEPT,
        "a size-7 proof presented against size 8 still reconstructs the "
        "size-7 root: an RFC 6962 root does not commit to its tree size, so "
        "tree_size must be authenticated by the signed token, not inferred "
        "from the root",
        i,
        8,
        recs[i],
        proof,
        root,
    )
    inc_case(
        "INC-N-record-altered",
        "negative",
        reject("not-included"),
        "one byte of the record changed",
        i,
        7,
        recs[i].replace(b"ALLOW", b"DENY!"),
        proof,
        root,
    )
    inc_case(
        "INC-N-root-altered",
        "negative",
        reject("not-included"),
        "the published root with one bit flipped",
        i,
        7,
        recs[i],
        proof,
        bytes([root[0] ^ 1]) + root[1:],
    )
    inc_case(
        "INC-N-proof-extra-hash",
        "negative",
        reject("not-included"),
        "a proof with one hash too many",
        i,
        7,
        recs[i],
        proof + [proof[0]],
        root,
    )
    inc_case(
        "INC-N-proof-missing-hash",
        "negative",
        reject("not-included"),
        "a proof with the last hash removed",
        i,
        7,
        recs[i],
        proof[:-1],
        root,
    )
    inc_case(
        "INC-N-proof-empty",
        "negative",
        reject("not-included"),
        "an empty proof for a record of a 7-leaf tree",
        i,
        7,
        recs[i],
        [],
        root,
    )
    sw = list(proof)
    sw[0], sw[1] = sw[1], sw[0]
    inc_case(
        "INC-N-proof-order-swapped",
        "negative",
        reject("not-included"),
        "the first two proof hashes exchanged",
        i,
        7,
        recs[i],
        sw,
        root,
    )
    inc_case(
        "INC-N-index-equals-size",
        "negative",
        reject("not-included"),
        "index equal to tree_size",
        7,
        7,
        recs[i],
        proof,
        root,
    )
    inc_case(
        "INC-N-index-negative",
        "negative",
        reject("not-included"),
        "negative index",
        -1,
        7,
        recs[i],
        proof,
        root,
    )
    inc_case(
        "INC-N-size-zero",
        "negative",
        reject("not-included"),
        "tree_size zero",
        0,
        0,
        recs[i],
        [],
        root,
    )
    other, orecs = tree_of(7, salt="b")
    inc_case(
        "INC-N-record-from-other-tree",
        "negative",
        reject("not-included"),
        "a record and proof from a different 7-leaf tree against this root",
        i,
        7,
        orecs[i],
        other.inclusion_proof(i),
        root,
    )
    # odd-leaf duplication (CVE-2012-2459): a tree that pairs an odd last node
    # with itself roots [a, b, c] at H(node(a, b), node(c, c)). RFC 6962 roots
    # it at node(node(a, b), c). The proof is the one the duplicating tree
    # issues for c: one hash, the duplication being implicit.
    t3, r3 = tree_of(3)
    nc = node_hash(leaf_hash(r3[2]), leaf_hash(r3[2]))
    naive_root3 = node_hash(t3._range_root(0, 2), nc)
    inc_case(
        "INC-N-odd-leaf-duplication",
        "adversarial",
        reject("not-included"),
        "record 2 of 3 proved against the root a tree that duplicates an odd "
        "last node would publish; an RFC 6962 verifier recomputes a different "
        "root, so the two trees cannot be confused",
        2,
        3,
        r3[2],
        [t3._range_root(0, 2)],
        naive_root3,
    )
    # second preimage: an interior node presented as a leaf. A tree with no
    # domain separation accepts this; RFC 6962 prefixes make it fail.
    t8, _ = tree_of(8)
    lroot = t8._range_root(0, 4)
    rroot = t8._range_root(4, 8)
    inc_case(
        "INC-N-interior-node-as-leaf",
        "adversarial",
        reject("not-included"),
        "the byte string 0x01 || left || right, which is how an interior "
        "node is hashed, presented as the only leaf of a size-1 tree whose "
        "root is the real size-8 root; a verifier that hashes leaves "
        "without the 0x00 prefix accepts it",
        0,
        1,
        b"\x01" + lroot + rroot,
        [],
        t8.root(),
    )
    # leaf hash used directly as the record: the same attack one level down
    h = leaf_hash(recs[0])
    inc_case(
        "INC-N-leaf-hash-as-record",
        "adversarial",
        reject("not-included"),
        "the leaf HASH of record 0 presented as the record itself (a "
        "verifier that hashes twice, or never, agrees with the wrong value)",
        0,
        7,
        h,
        t.inclusion_proof(0),
        root,
    )


def cons_case(cid, klass, expect, note, m, n, rm, rn, proof):
    add(
        "consistency",
        cid,
        ["7.3.5"],
        expect,
        klass,
        note,
        old_size=m,
        new_size=n,
        old_root=rm.hex(),
        new_root=rn.hex(),
        proof=[p.hex() for p in proof],
    )


def build_consistency():
    t, _ = tree_of(9)
    for m, n in (
        (1, 2),
        (2, 5),
        (3, 7),
        (4, 8),
        (6, 9),
        (5, 5),
        (8, 9),
        (1, 9),
        (7, 8),
        (2, 4),
    ):
        cons_case(
            f"CON-P-{m}-{n}",
            "positive",
            ACCEPT,
            f"size {n} extends size {m}",
            m,
            n,
            t.root_at(m),
            t.root_at(n),
            t.consistency_proof(m, n),
        )
    m, n = 3, 7
    proof = t.consistency_proof(m, n)
    rm, rn = t.root_at(m), t.root_at(n)
    # a forked history: the operator rewrote leaf 1 and publishes the new tree
    forked = MerkleTree()
    for i in range(9):
        forked.append(
            json.dumps(
                {
                    "snapshot": hashlib.sha256(
                        (("x" if i == 1 else "a") + str(i)).encode()
                    ).hexdigest(),
                    "verdict": "ALLOW",
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        )
    cons_case(
        "CON-N-forked-history",
        "negative",
        reject("not-consistent"),
        "size 7 of a history in which leaf 1 was rewritten, proven against "
        "the size 3 root already published",
        m,
        n,
        rm,
        forked.root_at(n),
        forked.consistency_proof(m, n),
    )
    reordered = MerkleTree()
    order = [1, 0, 2, 3, 4, 5, 6, 7, 8]
    for i in order:
        reordered.append(
            json.dumps(
                {
                    "snapshot": hashlib.sha256(f"a{i}".encode()).hexdigest(),
                    "verdict": "ALLOW",
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        )
    cons_case(
        "CON-N-history-reordered",
        "adversarial",
        reject("not-consistent"),
        "the first two records exchanged in a larger tree: the same set of "
        "records, a different order; a tree built over sorted or unordered "
        "leaves cannot tell the two histories apart",
        3,
        9,
        rm,
        reordered.root_at(9),
        reordered.consistency_proof(3, 9),
    )
    cons_case(
        "CON-N-old-root-altered",
        "negative",
        reject("not-consistent"),
        "the previously published root with one bit flipped",
        m,
        n,
        bytes([rm[0] ^ 1]) + rm[1:],
        rn,
        proof,
    )
    cons_case(
        "CON-N-new-root-altered",
        "negative",
        reject("not-consistent"),
        "the new root with one bit flipped",
        m,
        n,
        rm,
        bytes([rn[0] ^ 1]) + rn[1:],
        proof,
    )
    cons_case(
        "CON-N-roots-swapped",
        "negative",
        reject("not-consistent"),
        "old and new roots exchanged",
        m,
        n,
        rn,
        rm,
        proof,
    )
    cons_case(
        "CON-N-proof-extra-hash",
        "negative",
        reject("not-consistent"),
        "a proof with one extra hash",
        m,
        n,
        rm,
        rn,
        proof + [proof[0]],
    )
    cons_case(
        "CON-N-proof-missing-hash",
        "negative",
        reject("not-consistent"),
        "a proof with the last hash removed",
        m,
        n,
        rm,
        rn,
        proof[:-1],
    )
    cons_case(
        "CON-N-proof-empty",
        "negative",
        reject("not-consistent"),
        "an empty proof between two different sizes",
        m,
        n,
        rm,
        rn,
        [],
    )
    cons_case(
        "CON-N-shrinking",
        "negative",
        reject("not-consistent"),
        "old size greater than new size (truncation)",
        7,
        3,
        rn,
        rm,
        [],
    )
    cons_case(
        "CON-N-old-size-zero",
        "negative",
        reject("not-consistent"),
        "old size zero",
        0,
        7,
        rm,
        rn,
        proof,
    )
    cons_case(
        "CON-N-same-size-different-root",
        "negative",
        reject("not-consistent"),
        "equal sizes with different roots",
        7,
        7,
        rn,
        forked.root_at(7),
        [],
    )
    cons_case(
        "CON-N-same-size-with-proof",
        "negative",
        reject("not-consistent"),
        "equal sizes with a non-empty proof",
        7,
        7,
        rn,
        rn,
        proof,
    )
    cons_case(
        "CON-N-proof-of-other-pair",
        "negative",
        reject("not-consistent"),
        "the proof for (2, 5) offered for (3, 7)",
        m,
        n,
        rm,
        rn,
        t.consistency_proof(2, 5),
    )


# -------------------------------------------------------------------- chains
def chain_case(cid, klass, expect, note, records, anchor, reqs):
    add(
        "chain",
        cid,
        reqs,
        expect,
        klass,
        note,
        records=records,
        public_key=PK_HEX,
        measurement=MEASURE_HEX,
        anchor=anchor,
    )


def build_chains():
    full = [copy.deepcopy(r) for r in CHAIN]
    head6 = full[-1]["poc_claims"]["chain_head"].split(":", 1)[1]
    anchor6 = {"index": 6, "root": head6}
    chain_case(
        "CHN-P-six-steps",
        "positive",
        ACCEPT,
        "six steps, no anchor",
        full,
        None,
        ["7.3.1", "7.6.2"],
    )
    chain_case(
        "CHN-P-six-steps-anchored",
        "positive",
        ACCEPT,
        "six steps, anchor published at step 6",
        full,
        anchor6,
        ["7.3.1", "7.6.6"],
    )
    chain_case(
        "CHN-P-prefix-of-anchored",
        "positive",
        ACCEPT,
        "a verifier holding only the first three records and an anchor at step 3",
        full[:3],
        {"index": 3, "root": full[2]["poc_claims"]["chain_head"].split(":", 1)[1]},
        ["7.3.1"],
    )

    def mut(fn):
        c = copy.deepcopy(full)
        fn(c)
        return c

    def alter_verdict(c):
        c[2]["poc_claims"]["verdict"] = (
            "ALLOW" if c[2]["poc_claims"]["verdict"] == "DENY" else "DENY"
        )
        c[2] = resign(c[2])

    chain_case(
        "CHN-N-altered-verdict-resigned",
        "negative",
        reject("chain-break"),
        "record 2's verdict changed and the record re-signed",
        mut(alter_verdict),
        None,
        ["7.3.1"],
    )

    def alter_snapshot(c):
        c[3]["poc_claims"]["canonical_snapshot_hash"] = "sha-256:" + "ab" * 32
        c[3] = resign(c[3])

    chain_case(
        "CHN-N-altered-snapshot-resigned",
        "negative",
        reject("chain-break"),
        "record 3's snapshot digest replaced and the record re-signed",
        mut(alter_snapshot),
        None,
        ["7.3.1"],
    )

    def delete_mid(c):
        del c[3]

    chain_case(
        "CHN-N-record-deleted",
        "negative",
        reject("sequence-gap", "chain-break"),
        "record 3 removed",
        mut(delete_mid),
        None,
        ["7.3.1", "7.6.2"],
    )

    def insert_dup(c):
        c.insert(2, copy.deepcopy(c[1]))

    chain_case(
        "CHN-N-record-inserted",
        "negative",
        reject("sequence-gap", "chain-break"),
        "a copy of record 1 inserted at position 2",
        mut(insert_dup),
        None,
        ["7.3.1"],
    )

    def reorder(c):
        c[1], c[2] = c[2], c[1]

    chain_case(
        "CHN-N-records-reordered",
        "negative",
        reject("sequence-gap", "chain-break"),
        "records 1 and 2 exchanged",
        mut(reorder),
        None,
        ["7.3.1"],
    )

    def start_at_one(c):
        del c[0]

    chain_case(
        "CHN-N-first-record-missing",
        "negative",
        reject("sequence-gap", "chain-break"),
        "the genesis record removed",
        mut(start_at_one),
        None,
        ["7.6.2", "7.3.1"],
    )

    def tail_dropped(c):
        del c[-1]

    chain_case(
        "CHN-N-tail-truncated-with-anchor",
        "negative",
        reject("truncation"),
        "the last two records withheld; an anchor at step 6 exists",
        mut(lambda c: (c.pop(), c.pop())),
        anchor6,
        ["7.6.6", "7.3.3"],
    )
    chain_case(
        "CHN-N-tail-truncated-no-anchor",
        "adversarial",
        ACCEPT,
        "the same truncation with no anchor: the chain alone cannot detect "
        "it, which is why 7.6.6 requires an anchor and an interval",
        mut(lambda c: (c.pop(), c.pop())),
        None,
        ["7.6.6"],
    )

    def sig_bad(c):
        t = copy.deepcopy(c[4])
        t["signature"] = (
            t["signature"][:10]
            + format(int(t["signature"][10], 16) ^ 1, "x")
            + t["signature"][11:]
        )
        c[4] = t

    chain_case(
        "CHN-N-bad-signature-mid-chain",
        "negative",
        reject("signature"),
        "record 4's signature has a flipped bit",
        mut(sig_bad),
        None,
        ["7.3.2"],
    )

    def bad_measure(c):
        t = copy.deepcopy(c[1])
        t["submods"]["attestation"]["measurement"] = "sha-256:" + "cd" * 32
        c[1] = resign(t)

    chain_case(
        "CHN-N-measurement-changed",
        "negative",
        reject("measurement"),
        "record 1 carries a different attested measurement",
        mut(bad_measure),
        None,
        ["7.2.3", "7.3.1"],
    )

    # history rewrite: the key holder replays a different step 2 and re-signs
    # everything after it. Length, signatures and chain all verify; only the
    # anchor published before the rewrite exposes it.
    rewritten_actions = list(ACTIONS)
    rewritten_actions[2] = Action(
        "db.read", "customers", {"row": 999}, classification="internal"
    )
    _, alt = build_chain(rewritten_actions)
    chain_case(
        "CHN-N-history-rewritten-resigned",
        "adversarial",
        reject("history-rewritten"),
        "step 2 replaced and every later record re-signed by the key "
        "holder: a perfect chain of the right length, caught only by the "
        "anchor published before the rewrite",
        alt,
        anchor6,
        ["7.3.3", "7.3.5"],
    )
    chain_case(
        "CHN-N-history-rewritten-no-anchor",
        "adversarial",
        ACCEPT,
        "the same rewrite with no anchor: undetectable from the records",
        alt,
        None,
        ["7.3.3"],
    )


# ---------------------------------------------------------------- canonical
def build_canonical():
    cases = {
        "escapes-and-controls": {
            "q": 'a"b',
            "bs": "a\\b",
            "nl": "x\ny",
            "tab": "x\ty",
            "c1": "\x01\x1f",
            "del": "\x7f",
            "slash": "a/b",
        },
        "unicode-line-separators": {"ls": " ", "ps": " ", "bom": "﻿"},
        "nested-key-order": {"b": {"d": 1, "c": 2}, "a": [3, {"z": 1, "y": 2}]},
        "numbers-integers": {
            "zero": 0,
            "neg": -7,
            "big": 9007199254740991,
            "e5": 100000,
        },
        "empty-containers": {"o": {}, "a": [], "s": ""},
        "astral-values": {"k": "\U0001f5dd \U0001f600"},
        "key-order-bmp-above-surrogates": {"": 1, "\U00010000": 2, "a": 3},
        "key-order-digits-upper-lower": {
            "b": 1,
            "B": 2,
            "a": 3,
            "A": 4,
            "1": 5,
            "10": 6,
            "2": 7,
        },
        "combining-vs-precomposed": {"é": "decomposed", "é": "precomposed"},
    }
    for name, obj in cases.items():
        text = json.dumps(obj, ensure_ascii=False, indent=1) + "\n"
        add(
            "canonical",
            f"CAN-P-{name}",
            ["7.7.2", "7.7.4"],
            ACCEPT,
            "positive",
            f"published canonical digest for {name}",
            text=text,
            canonical_sha256=hashlib.sha256(jcs(obj)).hexdigest(),
            canonical_len=len(jcs(obj)),
        )


# ---------------------------------------------------------------------- main
def write_all():
    if OUT.exists():
        shutil.rmtree(OUT)
    for c in CASES:
        d = OUT / c["kind"]
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{c['id']}.json").write_text(
            json.dumps(c, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )
    kinds = {}
    for c in CASES:
        kinds[c["kind"]] = kinds.get(c["kind"], 0) + 1
    manifest = {
        "corpus": "poc-evidence-vectors",
        "specification": {
            "repository": "https://github.com/LFDT-ProofOfControl/ov-poc-standard",
            "commit": SPEC_COMMIT,
            "version": "v1.0 public comment draft",
        },
        "signing_public_key": PK_HEX,
        "signing_key_note": "The seed is the specification's own published test seed.",
        "expected_measurement_hex": MEASURE_HEX,
        "case_count": len(CASES),
        "by_kind": kinds,
        "files": {},
    }
    for p in sorted(OUT.rglob("*.json")):
        manifest["files"][str(p.relative_to(OUT))] = hashlib.sha256(
            p.read_bytes()
        ).hexdigest()
    digest = hashlib.sha256(
        json.dumps(manifest["files"], sort_keys=True).encode()
    ).hexdigest()
    manifest["corpus_sha256"] = digest
    (OUT.parent / "CORPUS-MANIFEST.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return manifest


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    build_tokens()
    build_inclusion()
    build_consistency()
    build_chains()
    build_canonical()
    ids = [c["id"] for c in CASES]
    assert len(ids) == len(set(ids)), "duplicate case id"
    if args.check:
        snap = OUT.parent / "CORPUS-MANIFEST.json"
        before = snap.read_bytes() if snap.exists() else b""
        write_all()
        return 0 if snap.read_bytes() == before else 1
    m = write_all()
    print(f"{m['case_count']} cases {m['by_kind']} corpus_sha256={m['corpus_sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
