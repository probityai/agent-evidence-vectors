#!/usr/bin/env python3
"""Generate the SCITT/COSE carriage conformance vector suite for the AEE predicate.

Regenerate byte-identically:

    uv run --extra generators python vectors-scitt-cose/gen_vectors.py

Every member is a complete RFC 9943 Transparent Statement: a COSE_Sign1 Signed
Statement carrying an Adversarial Execution Evidence in-toto Statement as its
payload, with one or more RFC 9942 Receipts in its unprotected header. The
vector file carries the bytes and the trust inputs a verifier needs and nothing
else. What the verifier is supposed to DECIDE lives in MANIFEST.json, never
beside the input, for the reason the sibling corpora record: a file that carries
its own answer is scoreable without being read.

WHY THIS SUITE EXISTS AT ALL
----------------------------
RFC 9943, Section 6 says of Signed Statements: "Profiles and implementation-
specific choices should be used to determine admissibility of conforming
messages. This specification is left intentionally open to allow implementations
to make Registration restrictions that make the most sense for their operational
use cases." That openness is deliberate and it is also the whole gap. Two
implementations can both conform to RFC 9943 and disagree about every question
this corpus asks, because the architecture states the mandatory labels and
leaves admissibility to a profile that nobody had written for execution
evidence. profiles/scitt-cose.md is that profile; this directory is what makes
it testable.

DETERMINISM, AND THE ONE THING THAT FORCED THE ALGORITHM CHOICE
---------------------------------------------------------------
scripts/regenerability-gate.py re-runs this generator into a scratch tree and
diffs every file it owns, so a member has to come out byte-identical on every
machine. That rules out randomized signatures: ECDSA draws a per-signature
nonce, so an ES256 corpus would differ on every run and the gate could not tell
a regenerated file from a rewritten one.

Ed25519 signatures are deterministic (RFC 8032), so the corpus is signed with
Ed25519 throughout and the private keys are derived from fixed seeds in this
file. The algorithm IDENTIFIER is -19, the fully-specified Ed25519 registration
of RFC 9864, Section 4.2.1 ("Name: Ed25519, Value: -19, Recommended: Yes"), and
NOT -8. RFC 9864, Section 4.2.2 has IANA update -8 EdDSA and -7 ES256 alike to
"Recommended: Deprecated", which is worth saying plainly because every worked
example in RFC 9943 and RFC 9942 carries `1: -7`: the published examples of the
architecture this profile targets are all on a deprecated identifier.

pycose 1.1.0 ships no -19, so this file registers it through the library's own
extension mechanism (`@CoseAlgorithm.register_attribute()`), reusing EdDSA's
sign and verify. The library still builds every Sig_structure, sorts nothing,
and does all CBOR encoding; what is added here is one registry entry, which is
the difference between extending a COSE library and hand-rolling COSE.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

# The preimage lives in a standard-library-only module beside this one so that
# scripts/release-digests.py can reach it without importing the COSE stack below.
# Imported rather than restated: one preimage, one spelling.
from digest import corpus_digest

import cbor2
from pycose.algorithms import CoseAlgorithm, EdDSA
from pycose.keys.okp import OKPKey
from pycose.messages.sign1message import Sign1Message

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

SUITE = "scitt-cose-carriage-conformance"
PROFILE = "aee-scitt-cose/v0.1"

# The AEE predicate version is READ, never typed. It belongs to a specification
# in in-toto and it moves; a copy of it in this file would be a cache with no
# invalidation, which is the defect scripts/count-gate.py exists to refuse.
with open(os.path.join(REPO, "vectors", "MANIFEST.json"), encoding="utf-8") as fh:
    AEE_PREDICATE_TYPE: str = json.load(fh)["predicateType"]

# The profile's own media type sits in RFC 6838's unregistered tree on purpose.
# Section 3.4 of that document reserves the `x.` prefix for types that have not
# been registered, and this profile has registered none. Registration is named
# as open work in README.md rather than pre-empted by a value chosen here.
CONTENT_TYPE = "application/x.aee-scitt-cose-statement+cose"

# ---------------------------------------------------------------------------
# COSE header labels this suite writes, each with the document that defines it.
# ---------------------------------------------------------------------------
#: RFC 9052, Section 3.1, Table 3: alg.
LBL_ALG = 1
#: RFC 9052, Section 3.1. MUST be in the protected bucket, at least one value.
LBL_CRIT = 2
#: RFC 9052, Section 3.1.
LBL_CONTENT_TYPE = 3
#: RFC 9052, Section 3.1, Table 3: kid.
LBL_KID = 4
#: RFC 9597, Section 2, as required by RFC 9943, Section 6.
LBL_CWT_CLAIMS = 15
#: RFC 9596. RFC 9942, Section 4.4 names `typ` as one way for a profile to make
#: its own semantics explicit in the COSE structure.
LBL_TYP = 16
#: RFC 9942, Section 2: "receipts", an array of one or more COSE Receipts.
LBL_RECEIPTS = 394
#: RFC 9942, Section 2: "vds", the Verifiable Data Structure algorithm.
LBL_VDS = 395
#: RFC 9942, Section 2: "vdp", a map of proofs organized by Proof Type.
LBL_VDP = 396
#: RFC 9942, Section 4.2: RFC9162_SHA256 supports (-1) inclusion proofs and
#: (-2) consistency proofs.
PROOF_INCLUSION = -1
PROOF_CONSISTENCY = -2

#: The observer position, in the COSE header parameter Private Use range. The
#: "COSE Header Parameters" registry allocates values below -65536 to Private
#: Use, so a profile can carry a field there without an IANA action and without
#: colliding with a future registration. It is placed in the PROTECTED bucket
#: and named in `crit`, which is what makes it fail-closed: RFC 9052,
#: Section 3.1 requires a processor to understand every parameter `crit` lists,
#: so a verifier that does not know this field refuses the statement instead of
#: ignoring the one column that says who saw the execution and from where.
LBL_OBSERVER_POSITION = -70001

#: CWT claim labels, from the IANA "CBOR Web Token (CWT) Claims" registry as
#: cited by RFC 8392, Section 3.1.
CWT_ISS = 1
CWT_SUB = 2
CWT_EXP = 4
CWT_NBF = 5
CWT_IAT = 6

VDS_RFC9162_SHA256 = 1
#: Not in the "COSE Verifiable Data Structure Algorithms" registry, whose
#: initial contents are 0 Reserved and 1 RFC9162_SHA256 (RFC 9942, Table 2).
VDS_UNREGISTERED = 2

ALG_ED25519 = -19
ALG_EDDSA_DEPRECATED = -8
ALG_ES256_DEPRECATED = -7


@CoseAlgorithm.register_attribute()
class Ed25519Alg(EdDSA):
    """RFC 9864, Section 4.2.1: Ed25519, value -19, Recommended: Yes.

    Sign and verify are EdDSA's, unchanged: the fully-specified identifier
    names the same Ed25519 operation the polymorphic one named, and the point
    of the registration is that a verifier no longer has to infer the curve
    from the key.
    """

    identifier = ALG_ED25519
    fullname = "ED25519"


@CoseAlgorithm.register_attribute()
class EdDSADeprecated(EdDSA):
    """RFC 9864, Section 4.2.2: EdDSA, value -8, Recommended: Deprecated.

    Registered here so a reject member can CARRY it. A vector that could not
    express the deprecated identifier could not test that a verifier refuses
    it, and refusing it is one of this profile's requirements.
    """

    identifier = ALG_EDDSA_DEPRECATED
    fullname = "EDDSA_DEPRECATED"


# ---------------------------------------------------------------------------
# Keys. Fixed seeds, because the corpus has to regenerate byte-identically.
# ---------------------------------------------------------------------------
def key_from_seed(seed: bytes) -> OKPKey:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sk = Ed25519PrivateKey.from_private_bytes(seed)
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    d = sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    x = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return OKPKey(crv="ED25519", d=d, x=x)


ISSUER_SEED = bytes.fromhex(
    "5343495454414545636f6e666f726d616e63656973737565727365656430303031"[:64]
)
TS_SEED = bytes.fromhex(
    "5343495454414545636f6e666f726d616e63657473736572766963657365656430"[:64]
)
OTHER_TS_SEED = bytes.fromhex(
    "5343495454414545636f6e666f726d616e6365756e74727573746564747373656564"[:64]
)

ISSUER_KEY = key_from_seed(ISSUER_SEED)
TS_KEY = key_from_seed(TS_SEED)
OTHER_TS_KEY = key_from_seed(OTHER_TS_SEED)

ISSUER_KID = b"aee-observer-1"
TS_KID = b"transparency-service-1"
OTHER_TS_KID = b"transparency-service-2"

ISSUER_IDENTITY = "observer.example"
OTHER_IDENTITY = "impostor.example"

VERIFICATION_TIME = "2026-09-09T12:00:00Z"
#: Seconds since the epoch for VERIFICATION_TIME, written out rather than
#: computed from a clock: a generator that read the wall clock would emit a
#: different corpus every run and the regenerability gate would refuse it.
NOW_EPOCH = 1789041600
ONE_HOUR = 3600
ONE_YEAR = 31_536_000


# ---------------------------------------------------------------------------
# RFC 9162 Merkle tree, Section 2.1.1, and its inclusion proof, Section 2.1.3.
# ---------------------------------------------------------------------------
def mth(entries: list[bytes]) -> bytes:
    """The Merkle Tree Hash of RFC 9162, Section 2.1.1.

    MTH({}) is the hash of the empty string, MTH({d0}) is SHA-256(0x00 || d0),
    and an interior node is SHA-256(0x01 || left || right) split at the largest
    power of two strictly below n. The prefixes are what stop a leaf being
    read as an interior node.
    """
    if not entries:
        return hashlib.sha256(b"").digest()
    if len(entries) == 1:
        return hashlib.sha256(b"\x00" + entries[0]).digest()
    k = 1
    while k * 2 < len(entries):
        k *= 2
    return hashlib.sha256(b"\x01" + mth(entries[:k]) + mth(entries[k:])).digest()


def inclusion_path(entries: list[bytes], index: int) -> list[bytes]:
    """The audit path of RFC 9162, Section 2.1.3.1, leaf to root."""
    if len(entries) <= 1:
        return []
    k = 1
    while k * 2 < len(entries):
        k *= 2
    if index < k:
        return inclusion_path(entries[:k], index) + [mth(entries[k:])]
    return inclusion_path(entries[k:], index - k) + [mth(entries[:k])]


# ---------------------------------------------------------------------------
# The AEE payload. An in-toto Statement, canonicalized with RFC 8785.
# ---------------------------------------------------------------------------
def jcs(obj: Any) -> bytes:
    """RFC 8785 for the value space this suite uses.

    Every member name here is BMP and ASCII and every number is a safe
    integer, so lexicographic member sorting on the Python string coincides
    with the RFC's UTF-16 code-unit order. The sibling corpus keeps a second
    serializer for the supplementary-plane case; this one has no member that
    reaches it, and a member that did would be a different vector.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


SUBJECT_NAME = "run/2026-09-09/photometric-regrade"
SUBJECT_DIGEST = "b" * 64


def aee_statement(subject_digest: str = SUBJECT_DIGEST) -> dict[str, Any]:
    """A minimal in-toto Statement carrying the AEE predicate.

    The predicate body is deliberately small. What this corpus tests is the
    CARRIAGE -- whether the COSE_Sign1 around it, the CWT claims inside its
    protected header and the receipt in its unprotected header hold together
    -- and vectors/ already tests the predicate itself across its own corpus.
    A large predicate here would move the failure surface without adding a
    single carriage condition.
    """
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {"name": SUBJECT_NAME, "digest": {"sha256": subject_digest}},
        ],
        "predicateType": AEE_PREDICATE_TYPE,
        "predicate": {
            "observation": {
                "source": "host_vmi",
                "observedAt": VERIFICATION_TIME,
            },
            "result": "fail",
        },
    }


def subject_claim(statement: dict[str, Any]) -> str:
    """The CWT Subject Claim this profile derives from the in-toto subject.

    RFC 9943, Section 6: "The iss and sub Claims, within the CWT Claims
    protected header, are used to identify the Artifact the Statement pertains
    to." The architecture does not say how, so a profile has to, or two
    conforming producers name the same artifact differently and a relying party
    cannot tell a mismatch from a naming convention. This profile binds sub to
    the subject's own digest, so the binding is recomputable from the payload
    rather than asserted beside it.
    """
    entry = statement["subject"][0]
    return f"sha256:{entry['digest']['sha256']}"


# ---------------------------------------------------------------------------
# Building the messages.
# ---------------------------------------------------------------------------
def deterministic_phdr(pairs: list[tuple[int, Any]]) -> dict[int, Any]:
    """Insertion-ordered so pycose emits RFC 8949 Section 4.2.1 map order.

    pycose encodes a protected header in the order the mapping was built, and
    RFC 8949's Core Deterministic Encoding Requirements want map keys sorted in
    bytewise lexicographic order of their deterministic encodings. Sorting here
    is what makes the two agree; check_vectors.py re-derives the order from the
    bytes on disk rather than trusting that this function ran.
    """
    return {label: value for label, value in sorted(pairs, key=lambda kv: cbor2.dumps(kv[0]))}


def sign1(
    phdr: dict[int, Any],
    uhdr: dict[int, Any],
    payload: bytes,
    key: OKPKey,
    detach: bool = False,
) -> bytes:
    """Sign `payload`, then optionally remove it from the wire form.

    The payload is passed to the signer in BOTH cases and the detach happens
    after, because RFC 9052 Section 4.4 puts "the full payload ... independent
    of how it is transported" into the Sig_structure. Signing an empty payload
    and detaching afterwards produces a message that verifies against nothing,
    which is what the first version of this function did: every detached member
    was silently signed over zero bytes and the corpus still built.
    """
    message = Sign1Message(phdr=dict(phdr), uhdr=dict(uhdr), payload=payload)
    message.key = key
    # pycose types Sign1Message as type[CoseMessage], and that is the library's
    # defect rather than this file's. `@CoseMessage.record_cbor_tag(18)` wraps
    # the class in an unannotated `decorator(the_class)` whose body narrows its
    # argument with `issubclass(the_class, CoseMessage)`, so a checker infers
    # the decorated name as the base class. The base's `encode` takes a
    # `message` argument and `verify_signature` does not exist on it, while the
    # subclass method actually bound at runtime takes neither and does. Verified
    # against `inspect.signature(Sign1Message.encode)`, which reports
    # `(self, tag=True, sign=True, detached_payload=None, *args, **kwargs)`.
    encoded = message.encode()  # pyright: ignore[reportCallIssue]
    if detach:
        # A detached payload is `nil` in the COSE_Sign1, and the signature is
        # still over the full payload (RFC 9052, Section 4.4, field 5: "The
        # full payload is used here, independent of how it is transported").
        # pycose has no detach switch, so the encoded array's third slot is
        # replaced and the signature left alone -- which is exactly what
        # detaching means and is why the byte the verifier needs is supplied
        # in the vector's detachedPayload rather than inferred.
        tagged = cbor2.loads(encoded)
        body = list(tagged.value)
        body[2] = None
        encoded = cbor2.dumps(cbor2.CBORTag(tagged.tag, body))
    return encoded


def signed_statement(
    *,
    statement: dict[str, Any],
    alg: int = ALG_ED25519,
    kid: bytes = ISSUER_KID,
    iss: str = ISSUER_IDENTITY,
    sub: str | None = None,
    observer_position: dict[str, Any] | None = None,
    crit: list[int] | None = None,
    extra_protected: list[tuple[int, Any]] | None = None,
    extra_unprotected: dict[int, Any] | None = None,
    cwt_extra: list[tuple[int, Any]] | None = None,
    omit_cwt_claims: bool = False,
    cwt_claims_also_unprotected: bool = False,
    content_type: str | None = CONTENT_TYPE,
    detached: bool = False,
    key: OKPKey = ISSUER_KEY,
) -> tuple[bytes, bytes]:
    """One Signed Statement, returned as (encoded bytes, payload bytes).

    Every keyword here exists because one member needs it. The base call takes
    none of them, so a reader can see what a conforming statement is before
    seeing what each mutation does to it.
    """
    payload = jcs(statement)
    cwt: dict[int, Any] = {
        CWT_ISS: iss,
        CWT_SUB: sub if sub is not None else subject_claim(statement),
    }
    for label, value in cwt_extra or []:
        cwt[label] = value
    cwt = {label: cwt[label] for label in sorted(cwt, key=lambda k: cbor2.dumps(k))}

    pairs: list[tuple[int, Any]] = [(LBL_ALG, alg), (LBL_KID, kid)]
    if content_type is not None:
        pairs.append((LBL_CONTENT_TYPE, content_type))
    if not omit_cwt_claims:
        pairs.append((LBL_CWT_CLAIMS, cwt))
    pairs.append((LBL_TYP, PROFILE))
    if observer_position is not None:
        pairs.append((LBL_OBSERVER_POSITION, observer_position))
    if crit is not None:
        pairs.append((LBL_CRIT, crit))
    for label, value in extra_protected or []:
        pairs.append((label, value))

    uhdr: dict[int, Any] = dict(extra_unprotected or {})
    if cwt_claims_also_unprotected:
        uhdr[LBL_CWT_CLAIMS] = cwt

    encoded = sign1(deterministic_phdr(pairs), uhdr, payload, key, detach=detached)
    return encoded, payload


def sign1_declaring(
    phdr_pairs: list[tuple[int, Any]],
    uhdr: dict[int, Any],
    payload: bytes,
    key: OKPKey,
) -> bytes:
    """Assemble a COSE_Sign1 whose declared algorithm is not the one that signed.

    Built at the Sig_structure level, and that is the point rather than a
    shortcut. A COSE library honours its own protected header: ask pycose to
    sign under -7 and it selects the ECDSA signer, which is not the object an
    algorithm-confusion vector needs. The object needed here is a GOOD Ed25519
    signature over a Sig_structure whose protected header says ECDSA, because
    that is what a verifier dispatching on the key type instead of the declared
    identifier will accept.

    The Sig_structure is RFC 9052 Section 4.4 verbatim for COSE_Sign1: the
    context string "Signature1", the body's protected attributes as a bstr, the
    externally supplied data (absent, so a zero-length bstr), and the full
    payload. The sign_protected field of that list is omitted, which the same
    section requires: "This field is omitted for the COSE_Sign1 signature
    structure."
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    protected = cbor2.dumps(deterministic_phdr(phdr_pairs))
    tbs = cbor2.dumps(["Signature1", protected, b"", payload])
    signature = Ed25519PrivateKey.from_private_bytes(key.d).sign(tbs)
    return cbor2.dumps(cbor2.CBORTag(18, [protected, uhdr, payload, signature]))


OBSERVER_POSITION = {
    "vantage": "host_vmi",
    "observedFrom": "hypervisor",
    "reachableByObserved": False,
}


def receipt(
    *,
    leaf: bytes,
    tree_size: int,
    leaf_index: int,
    other_entries: list[bytes] | None = None,
    alg: int = ALG_ED25519,
    kid: bytes = TS_KID,
    vds: int | None = VDS_RFC9162_SHA256,
    proof_type: int = PROOF_INCLUSION,
    include_vdp: bool = True,
    key: OKPKey = TS_KEY,
    root_override: bytes | None = None,
    iat: int | None = NOW_EPOCH,
) -> bytes:
    """One RFC 9942 Receipt of inclusion over `leaf`.

    The payload is DETACHED, per RFC 9942, Section 4.4: "The payload in such
    definitions SHOULD be detached. Detached payloads force verifiers to
    recompute the root from the proof and protect against implementation errors
    where the signature is verified but the payload is incompatible with the
    proof." That sentence is the reason this corpus can express a receipt over
    a different statement at all: the root is never handed to the verifier, so
    a substituted leaf changes what the verifier recomputes and the signature
    over the real root then fails.
    """
    filler = other_entries if other_entries is not None else [
        f"unrelated-entry-{i}".encode() for i in range(tree_size)
    ]
    entries = list(filler[:tree_size])
    if leaf_index < len(entries):
        entries[leaf_index] = leaf
    root = root_override if root_override is not None else mth(entries)
    path = inclusion_path(entries, leaf_index) if leaf_index < len(entries) else []

    pairs: list[tuple[int, Any]] = [(LBL_ALG, alg), (LBL_KID, kid)]
    if vds is not None:
        pairs.append((LBL_VDS, vds))
    if iat is not None:
        pairs.append((LBL_CWT_CLAIMS, {CWT_IAT: iat}))

    uhdr: dict[int, Any] = {}
    if include_vdp:
        if proof_type == PROOF_INCLUSION:
            proof = cbor2.dumps([tree_size, leaf_index, path])
        else:
            proof = cbor2.dumps([tree_size, tree_size + 8, path])
        uhdr[LBL_VDP] = {proof_type: [proof]}

    message = Sign1Message(
        phdr=deterministic_phdr(pairs), uhdr=uhdr, payload=root
    )
    message.key = key
    # Same library typing defect as in sign1 above.
    encoded = message.encode()  # pyright: ignore[reportCallIssue]
    tagged = cbor2.loads(encoded)
    body = list(tagged.value)
    body[2] = None
    return cbor2.dumps(cbor2.CBORTag(tagged.tag, body))


def receipt_declaring(*, leaf: bytes, tree_size: int, leaf_index: int) -> bytes:
    """A receipt whose protected header declares ECDSA over an Ed25519 signature.

    The same construction as sign1_declaring and for the same reason, one level
    down. A verifier that checks the outer envelope's algorithm strictly and
    reads the receipt's only for display passes the statement member above and
    accepts this one.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    entries = [f"unrelated-entry-{i}".encode() for i in range(tree_size)]
    entries[leaf_index] = leaf
    root = mth(entries)
    path = inclusion_path(entries, leaf_index)
    protected = cbor2.dumps(
        deterministic_phdr(
            [
                (LBL_ALG, ALG_ES256_DEPRECATED),
                (LBL_KID, TS_KID),
                (LBL_VDS, VDS_RFC9162_SHA256),
                (LBL_CWT_CLAIMS, {CWT_IAT: NOW_EPOCH}),
            ]
        )
    )
    tbs = cbor2.dumps(["Signature1", protected, b"", root])
    signature = Ed25519PrivateKey.from_private_bytes(TS_KEY.d).sign(tbs)
    uhdr = {LBL_VDP: {PROOF_INCLUSION: [cbor2.dumps([tree_size, leaf_index, path])]}}
    return cbor2.dumps(cbor2.CBORTag(18, [protected, uhdr, None, signature]))


def transparent(signed: bytes, receipts: list[bytes]) -> bytes:
    """A Transparent Statement: the Signed Statement plus receipts in label 394.

    RFC 9943, Section 7: "The Client ... that registers a Signed Statement and
    receives a Receipt can produce a Transparent Statement by adding the
    Receipt to the unprotected header of the Signed Statement."

    THE LEAF IS THE SIGNED STATEMENT, NOT THIS. A Transparent Statement
    contains its own receipts, so a proof over its bytes could never be
    checked; RFC 9943 leaves that unsaid because the construction makes it
    obvious in one direction only. The profile states it as a requirement:
    the registered entry is this object with label 394 removed from its
    unprotected header, which is well defined precisely because receipts live
    in the unprotected bucket and the signature does not cover them.
    """
    tagged = cbor2.loads(signed)
    body = list(tagged.value)
    uhdr = dict(body[1])
    uhdr[LBL_RECEIPTS] = receipts
    body[1] = uhdr
    return cbor2.dumps(cbor2.CBORTag(tagged.tag, body))


# ---------------------------------------------------------------------------
# The corpus.
# ---------------------------------------------------------------------------
DRAFTS: list[dict[str, Any]] = []
ID_HEX = 16


def add(
    slug: str,
    kind: str,
    *,
    statement_bytes: bytes,
    payload: bytes,
    detached: bool,
    conditions: list[str],
    expected: dict[str, Any],
    cites: str,
    parent: str | None = None,
    trust_issuer_identity: str = ISSUER_IDENTITY,
    trust_ts_keys: list[tuple[bytes, OKPKey]] | None = None,
) -> None:
    """Record what a vector IS. Naming it is emit()'s job, once it has bytes.

    `slug` is the authoring name and reaches no artifact: it orders the build,
    makes a duplicate obvious and is dropped at emit(). The sibling corpus
    records why, and the reason holds here: an `ok-`/`bad-` prefix on the
    input's own name hands the rail the answer along with the question.

    An indeterminate member carries its readings and no verdict: its readings
    span accepting and refusing, and any single verdict in the manifest would
    score a verifier that takes another listed reading as wrong.
    """
    if kind == "indeterminate" and "verdict" in expected:
        raise SystemExit(f"{slug}: an indeterminate member carries readings and no verdict")
    DRAFTS.append(
        {
            "slug": slug,
            "kind": kind,
            "vector": {
                "profile": PROFILE,
                "transparentStatement": statement_bytes.hex(),
                "detachedPayload": payload.hex() if detached else None,
                "verificationTime": VERIFICATION_TIME,
                "trust": {
                    "issuers": [
                        {
                            "kid": ISSUER_KID.hex(),
                            "iss": trust_issuer_identity,
                            "key": {
                                "kty": "OKP",
                                "crv": "Ed25519",
                                "x": ISSUER_KEY.x.hex(),
                            },
                        }
                    ],
                    "transparencyServices": [
                        {
                            "kid": kid.hex(),
                            "key": {"kty": "OKP", "crv": "Ed25519", "x": key.x.hex()},
                        }
                        for kid, key in (trust_ts_keys or [(TS_KID, TS_KEY)])
                    ],
                },
            },
            "conditions": conditions,
            "expected": expected,
            "cites": cites,
            "parent": parent,
        }
    )


def vector_id(body: bytes) -> str:
    return "v" + hashlib.sha256(body).hexdigest()[:ID_HEX]


def write(rel: str, data: bytes) -> None:
    with open(os.path.join(HERE, rel), "wb") as fh:
        fh.write(data)


MANIFEST: list[dict[str, Any]] = []


def emit() -> None:
    """Serialize every draft, name it after its own bytes, write it, prune.

    The prune is not tidiness. A statement file left behind by an earlier build
    is a vector with no builder: it survives every replay, it is counted by
    anything that reads the directory, and nothing regenerates it. That is the
    exact shape scripts/regenerability-gate.py exists to catch, and a generator
    that leaves them behind hands that gate a tree it has to clean first.
    """
    seen: dict[str, str] = {}
    slug_to_id: dict[str, str] = {}
    bodies: list[tuple[dict[str, Any], bytes, str]] = []
    for draft in DRAFTS:
        body = (
            json.dumps(draft["vector"], indent=2, sort_keys=True, ensure_ascii=False).encode()
            + b"\n"
        )
        vid = vector_id(body)
        if vid in seen:
            raise SystemExit(
                f"{draft['slug']} and {seen[vid]} are the same vector: identical "
                f"bytes, so they share the identifier {vid}. A content-addressed "
                "corpus cannot give one statement two names, and one of them is "
                "a copy of the other."
            )
        seen[vid] = draft["slug"]
        slug_to_id[draft["slug"]] = vid
        bodies.append((draft, body, vid))

    for draft, body, vid in bodies:
        rel = f"statements/{vid}.json"
        write(rel, body)
        entry: dict[str, Any] = {
            "id": vid,
            "kind": draft["kind"],
            "file": rel,
            "conditions": draft["conditions"],
            "expected": draft["expected"],
            "cites": draft["cites"],
        }
        if draft["parent"] is not None:
            if draft["parent"] not in slug_to_id:
                raise SystemExit(
                    f"{draft['slug']} declares parent {draft['parent']!r}, which no "
                    "vector in this build produced. A reject member whose parent "
                    "does not exist has no condition-removed twin, and a corpus of "
                    "refusals alone gives full marks to a verifier that refuses "
                    "everything."
                )
            entry["parent"] = slug_to_id[draft["parent"]]
        MANIFEST.append(entry)

    written = {os.path.basename(entry["file"]) for entry in MANIFEST}
    directory = os.path.join(HERE, "statements")
    for name in sorted(os.listdir(directory)):
        if name.endswith(".json") and name not in written:
            os.remove(os.path.join(directory, name))


# ---------------------------------------------------------------------------
# Accept members. The first is the base every reject member mutates.
# ---------------------------------------------------------------------------
BASE_STATEMENT = aee_statement()
BASE_PAYLOAD = jcs(BASE_STATEMENT)


def build_accept() -> None:
    base, payload = signed_statement(
        statement=BASE_STATEMENT,
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
    )
    base_receipt = receipt(leaf=base, tree_size=8, leaf_index=3)
    add(
        "base",
        "accept",
        statement_bytes=transparent(base, [base_receipt]),
        payload=payload,
        detached=False,
        conditions=[
            "sc-c-1",
            "sc-c-2",
            "sc-c-3",
            "sc-c-4",
            "sc-c-5",
            "sc-c-6",
            "sc-c-7",
            "sc-c-8",
            "sc-c-9",
            "sc-c-10",
            "sc-c-11",
            "sc-c-12",
            "sc-c-13",
            "sc-c-14",
        ],
        expected={"verdict": "valid", "observerPosition": "host_vmi"},
        cites=(
            "RFC 9943 Section 6 and Section 7: a COSE_Sign1 Signed Statement with "
            "protected CWT Claims carrying iss and sub, and a Receipt in label 394 "
            "of its unprotected header. Every reject member below is these bytes "
            "with one mutation."
        ),
    )

    size_one, payload_one = signed_statement(
        statement=aee_statement("c" * 64),
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
    )
    add(
        "tree-size-one",
        "accept",
        statement_bytes=transparent(
            size_one, [receipt(leaf=size_one, tree_size=1, leaf_index=0)]
        ),
        payload=payload_one,
        detached=False,
        conditions=["sc-c-2", "sc-c-14"],
        expected={"verdict": "valid", "observerPosition": "host_vmi"},
        cites=(
            "RFC 9162 Section 2.1.1: MTH({d0}) is SHA-256(0x00 || d0), so a log of "
            "one entry has an empty inclusion path. The boundary a proof-checker "
            "written for the interior case gets wrong."
        ),
    )

    two, payload_two = signed_statement(
        statement=aee_statement("d" * 64),
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
    )
    add(
        "two-receipts",
        "accept",
        statement_bytes=transparent(
            two,
            [
                receipt(leaf=two, tree_size=8, leaf_index=3),
                receipt(
                    leaf=two,
                    tree_size=6,
                    leaf_index=5,
                    kid=OTHER_TS_KID,
                    key=OTHER_TS_KEY,
                ),
            ],
        ),
        payload=payload_two,
        detached=False,
        conditions=["sc-c-2", "sc-c-3"],
        expected={"verdict": "valid", "observerPosition": "host_vmi"},
        cites=(
            "RFC 9943 Section 7: label 394 is an array that can carry more than "
            "one Receipt, and Section 7.1 lets a Relying Party \"decide to verify "
            "only a single Receipt that is acceptable to them\". Both are "
            "verifiable here, so a verifier that requires all of them and one "
            "that requires one both accept."
        ),
        trust_ts_keys=[(TS_KID, TS_KEY), (OTHER_TS_KID, OTHER_TS_KEY)],
    )

    det, payload_det = signed_statement(
        statement=aee_statement("e" * 64),
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
        detached=True,
    )
    add(
        "detached-payload",
        "accept",
        statement_bytes=transparent(
            det, [receipt(leaf=det, tree_size=8, leaf_index=3)]
        ),
        payload=payload_det,
        detached=True,
        conditions=["sc-c-1", "sc-c-13"],
        expected={"verdict": "valid", "observerPosition": "host_vmi"},
        cites=(
            "RFC 9943 Section 6.2: \"Statement payloads might be too large or too "
            "sensitive to be sent to a remote TS.\" The signature still covers the "
            "full payload (RFC 9052 Section 4.4, field 5), so the verifier has to "
            "be handed the bytes out of band and reattach them."
        ),
    )

    ignored, payload_ignored = signed_statement(
        statement=aee_statement("f" * 64),
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
        extra_protected=[(-70009, {"note": "a parameter this profile never defined"})],
    )
    add(
        "unknown-header-not-critical",
        "accept",
        statement_bytes=transparent(
            ignored, [receipt(leaf=ignored, tree_size=8, leaf_index=3)]
        ),
        payload=payload_ignored,
        detached=False,
        conditions=["sc-c-5", "sc-c-6"],
        expected={"verdict": "valid", "observerPosition": "host_vmi"},
        cites=(
            "RFC 9052 Section 3.1 makes only a crit-listed parameter mandatory to "
            "understand, so an unlisted one is ignored. This is the twin that "
            "stops a verifier scoring full marks by refusing every extension it "
            "does not recognize."
        ),
    )

    deep, payload_deep = signed_statement(
        statement=aee_statement("a" * 64),
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
    )
    add(
        "deep-path",
        "accept",
        statement_bytes=transparent(
            deep, [receipt(leaf=deep, tree_size=8, leaf_index=7)]
        ),
        payload=payload_deep,
        detached=False,
        conditions=["sc-c-2", "sc-c-14"],
        expected={"verdict": "valid", "observerPosition": "host_vmi"},
        cites=(
            "RFC 9943 Figure 11 is an inclusion proof of tree size 8 at leaf index "
            "7 with three intermediate hashes. This is that shape, so a verifier "
            "that only ever walks a left spine fails here and passes the base."
        ),
    )


# ---------------------------------------------------------------------------
# Reject members. Each is the base with one mutation and declares it.
# ---------------------------------------------------------------------------
def build_reject() -> None:
    wrong_sub, payload = signed_statement(
        statement=BASE_STATEMENT,
        sub="sha256:" + "0" * 64,
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
    )
    add(
        "subject-digest-mismatch",
        "reject",
        statement_bytes=transparent(
            wrong_sub, [receipt(leaf=wrong_sub, tree_size=8, leaf_index=3)]
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-1"],
        expected={"verdict": "invalid", "codes": ["subject-digest-mismatch"]},
        cites=(
            "RFC 9943 Section 6: iss and sub \"are used to identify the Artifact "
            "the Statement pertains to\". Here sub names a digest the payload does "
            "not carry, so the signed claim about which artifact this is "
            "contradicts the artifact itself."
        ),
        parent="base",
    )

    no_proof, payload = signed_statement(
        statement=BASE_STATEMENT,
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
    )
    add(
        "inclusion-proof-absent",
        "reject",
        statement_bytes=transparent(
            no_proof,
            [receipt(leaf=no_proof, tree_size=8, leaf_index=3, include_vdp=False)],
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-2"],
        expected={"verdict": "invalid", "codes": ["inclusion-proof-absent"]},
        cites=(
            "RFC 9942 Section 5.2.1: \"vdp (label: 396): REQUIRED\" and "
            "\"inclusion-proof (label: -1): REQUIRED\". A receipt with a signature "
            "and no proof establishes that a transparency service signed "
            "something, and nothing about this statement being in its log."
        ),
        parent="base",
    )

    other, _ = signed_statement(
        statement=aee_statement("9" * 64),
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
    )
    mine, payload = signed_statement(
        statement=BASE_STATEMENT,
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
    )
    add(
        "receipt-over-another-statement",
        "reject",
        statement_bytes=transparent(
            mine, [receipt(leaf=other, tree_size=8, leaf_index=3)]
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-3"],
        expected={"verdict": "invalid", "codes": ["receipt-subject-mismatch"]},
        cites=(
            "RFC 9942 Section 4.4: a detached payload \"force[s] verifiers to "
            "recompute the root from the proof\". The receipt is genuine and its "
            "signature is valid over the root of a log that contains a DIFFERENT "
            "statement, so a verifier that checks the signature without "
            "recomputing from this statement's bytes accepts a receipt for "
            "somebody else's execution."
        ),
        parent="base",
    )

    crit_unprotected, payload = signed_statement(
        statement=BASE_STATEMENT,
        crit=[LBL_OBSERVER_POSITION],
        extra_unprotected={LBL_OBSERVER_POSITION: OBSERVER_POSITION},
    )
    add(
        "critical-parameter-unprotected",
        "reject",
        statement_bytes=transparent(
            crit_unprotected,
            [receipt(leaf=crit_unprotected, tree_size=8, leaf_index=3)],
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-4"],
        expected={"verdict": "invalid", "codes": ["critical-parameter-unprotected"]},
        cites=(
            "RFC 9052 Section 3.1: \"If the 'crit' value list includes a label for "
            "which the header parameter is not in the protected-header-parameters "
            "bucket, this is a fatal error in processing the message.\" The "
            "observer position is in the bucket the signature does not cover, so "
            "it can be swapped without breaking anything."
        ),
        parent="base",
    )

    crit_unknown, payload = signed_statement(
        statement=BASE_STATEMENT,
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION, -70055],
        extra_protected=[(-70055, {"unknown": True})],
    )
    add(
        "critical-parameter-unprocessable",
        "reject",
        statement_bytes=transparent(
            crit_unknown, [receipt(leaf=crit_unknown, tree_size=8, leaf_index=3)]
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-5"],
        expected={"verdict": "invalid", "codes": ["critical-parameter-unprocessable"]},
        cites=(
            "RFC 9052 Section 3.1: crit \"is used to indicate which protected "
            "header parameters an application that is processing a message is "
            "required to understand\". This profile defines no parameter at "
            "-70055, so a conforming verifier cannot understand it and must "
            "refuse rather than proceed on the part it did understand."
        ),
        parent="unknown-header-not-critical",
    )

    obs_not_crit, payload = signed_statement(
        statement=BASE_STATEMENT,
        observer_position=OBSERVER_POSITION,
        crit=None,
    )
    add(
        "observer-position-not-critical",
        "reject",
        statement_bytes=transparent(
            obs_not_crit, [receipt(leaf=obs_not_crit, tree_size=8, leaf_index=3)]
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-6"],
        expected={"verdict": "invalid", "codes": ["observer-position-not-critical"]},
        cites=(
            "The profile's own requirement, and the reason it exists. The field is "
            "present and correct and no crit array lists it, so a verifier that "
            "does not implement this profile ignores the one column that says the "
            "observation came from a vantage the observed party could not reach, "
            "and reports the statement valid anyway. Fail-closed is a property of "
            "the crit listing, not of the field."
        ),
        parent="base",
    )

    payload = jcs(BASE_STATEMENT)
    alg_conf = sign1_declaring(
        [
            (LBL_ALG, ALG_ES256_DEPRECATED),
            (LBL_KID, ISSUER_KID),
            (LBL_CONTENT_TYPE, CONTENT_TYPE),
            (
                LBL_CWT_CLAIMS,
                {CWT_ISS: ISSUER_IDENTITY, CWT_SUB: subject_claim(BASE_STATEMENT)},
            ),
            (LBL_TYP, PROFILE),
            (LBL_OBSERVER_POSITION, OBSERVER_POSITION),
            (LBL_CRIT, [LBL_OBSERVER_POSITION]),
        ],
        {},
        payload,
        ISSUER_KEY,
    )
    add(
        "algorithm-confusion-statement",
        "reject",
        statement_bytes=transparent(
            alg_conf, [receipt(leaf=alg_conf, tree_size=8, leaf_index=3)]
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-7"],
        expected={"verdict": "invalid", "codes": ["algorithm-mismatch"]},
        cites=(
            "The protected header declares -7, ECDSA with SHA-256, and the "
            "signature is Ed25519 over the same Sig_structure. RFC 9052 "
            "Section 4.4 has a verifier pass alg to the verification algorithm, "
            "so a verifier that reads the key type instead of the declared "
            "algorithm accepts it. RFC 9864 Section 4.2.2 also marks -7 "
            "Deprecated."
        ),
        parent="base",
    )

    deprecated_alg, payload = signed_statement(
        statement=BASE_STATEMENT,
        alg=ALG_EDDSA_DEPRECATED,
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
    )
    add(
        "deprecated-polymorphic-algorithm",
        "reject",
        statement_bytes=transparent(
            deprecated_alg,
            [receipt(leaf=deprecated_alg, tree_size=8, leaf_index=3)],
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-8"],
        expected={"verdict": "invalid", "codes": ["algorithm-deprecated"]},
        cites=(
            "RFC 9864 Section 4.2.2: \"Name: EdDSA, Value: -8, ... Recommended: "
            "Deprecated.\" The signature here verifies. What the profile refuses "
            "is the polymorphic identifier, because -8 does not say which curve "
            "was used and leaves the verifier to infer it from the key."
        ),
        parent="base",
    )

    recv_alg, payload = signed_statement(
        statement=BASE_STATEMENT,
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
    )
    add(
        "algorithm-confusion-receipt",
        "reject",
        statement_bytes=transparent(
            recv_alg, [receipt_declaring(leaf=recv_alg, tree_size=8, leaf_index=3)]
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-7"],
        expected={"verdict": "invalid", "codes": ["receipt-algorithm-mismatch"]},
        cites=(
            "RFC 9942 Section 5.2.1: \"alg (label: 1): REQUIRED. Signature "
            "algorithm identifier.\" The same confusion as the statement member, "
            "one level down, and a verifier that checks the outer envelope "
            "strictly and the receipt loosely passes the first and fails here."
        ),
        parent="base",
    )

    expired, payload = signed_statement(
        statement=BASE_STATEMENT,
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
        cwt_extra=[(CWT_EXP, NOW_EPOCH - ONE_HOUR)],
    )
    add(
        "expired-statement",
        "reject",
        statement_bytes=transparent(
            expired, [receipt(leaf=expired, tree_size=8, leaf_index=3)]
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-9"],
        expected={"verdict": "invalid", "codes": ["statement-expired"]},
        cites=(
            "RFC 8392 Section 3.1.4 defines exp, and RFC 9942 Section 7.2 points "
            "at it: \"See the iat, nbf, and exp claims in [RFC8392] for one way to "
            "accomplish this.\" The claim is present, it is in the past at the "
            "verification time the vector declares, and this profile makes a "
            "present exp binding rather than advisory."
        ),
        parent="base",
    )

    future, payload = signed_statement(
        statement=BASE_STATEMENT,
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
        cwt_extra=[(CWT_NBF, NOW_EPOCH + ONE_YEAR)],
    )
    add(
        "not-yet-valid-statement",
        "reject",
        statement_bytes=transparent(
            future, [receipt(leaf=future, tree_size=8, leaf_index=3)]
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-10"],
        expected={"verdict": "invalid", "codes": ["statement-not-yet-valid"]},
        cites=(
            "RFC 8392 Section 3.1.5 defines nbf. RFC 9942 Section 7.2 asks for "
            "\"activation not too far in the future\" and leaves the mechanism to "
            "a profile. A statement about an execution that has not started yet "
            "is the one direction a monotonic clock check catches and a "
            "not-after-only check does not."
        ),
        parent="base",
    )

    wrong_iss, payload = signed_statement(
        statement=BASE_STATEMENT,
        iss=OTHER_IDENTITY,
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
    )
    add(
        "issuer-identity-mismatch",
        "reject",
        statement_bytes=transparent(
            wrong_iss, [receipt(leaf=wrong_iss, tree_size=8, leaf_index=3)]
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-11"],
        expected={"verdict": "invalid", "codes": ["issuer-identity-mismatch"]},
        cites=(
            "RFC 9943 Section 7.1: \"A Relying Party MUST trust the verification "
            "key or certificate and the associated identity of at least one "
            "Issuer of a Receipt.\" The signature verifies under the trusted key "
            "and the iss claim names a different party, so a verifier that checks "
            "the key and ignores the identity attributes the statement to whoever "
            "the header says."
        ),
        parent="base",
        trust_issuer_identity=ISSUER_IDENTITY,
    )

    no_cwt, payload = signed_statement(
        statement=BASE_STATEMENT,
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
        omit_cwt_claims=True,
    )
    add(
        "cwt-claims-absent",
        "reject",
        statement_bytes=transparent(
            no_cwt, [receipt(leaf=no_cwt, tree_size=8, leaf_index=3)]
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-12"],
        expected={"verdict": "invalid", "codes": ["cwt-claims-absent"]},
        cites=(
            "RFC 9943 Section 6: \"The protected header of a Signed Statement and "
            "a Receipt MUST include the CWT Claims header parameter as specified "
            "in Section 2 of [RFC9597]. The CWT Claims value MUST include the "
            "Issuer Claim (Claim label 1) and the Subject Claim (Claim label 2).\" "
            "Without them the object is a signed blob that no transparency "
            "service can register and no relying party can attribute."
        ),
        parent="base",
    )

    both_buckets, payload = signed_statement(
        statement=BASE_STATEMENT,
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
        cwt_claims_also_unprotected=True,
    )
    add(
        "cwt-claims-in-both-buckets",
        "reject",
        statement_bytes=transparent(
            both_buckets, [receipt(leaf=both_buckets, tree_size=8, leaf_index=3)]
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-12"],
        expected={"verdict": "invalid", "codes": ["cwt-claims-duplicated"]},
        cites=(
            "RFC 9597 Section 2 permits the CWT Claims header parameter in either "
            "bucket and not in both. The copies here agree, which is the point: a "
            "verifier that prefers one bucket accepts a message whose unprotected "
            "copy an attacker can rewrite, and the agreeing copy is what makes "
            "that preference invisible in testing."
        ),
        parent="base",
    )

    no_vds, payload = signed_statement(
        statement=BASE_STATEMENT,
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
    )
    add(
        "receipt-vds-absent",
        "reject",
        statement_bytes=transparent(
            no_vds, [receipt(leaf=no_vds, tree_size=8, leaf_index=3, vds=None)]
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-13"],
        expected={"verdict": "invalid", "codes": ["receipt-vds-absent"]},
        cites=(
            "RFC 9942 Section 5.2.1: \"vds (label: 395): REQUIRED. VDS algorithm "
            "identifier.\" Section 5.2.1 also says why: \"The VDS in the protected "
            "header is necessary to understand the inclusion proof structure in "
            "the unprotected header.\" Absent, the proof bytes are an array whose "
            "meaning the verifier has to guess."
        ),
        parent="base",
    )

    bad_vds, payload = signed_statement(
        statement=BASE_STATEMENT,
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
    )
    add(
        "receipt-vds-unregistered",
        "reject",
        statement_bytes=transparent(
            bad_vds,
            [receipt(leaf=bad_vds, tree_size=8, leaf_index=3, vds=VDS_UNREGISTERED)],
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-13"],
        expected={"verdict": "invalid", "codes": ["receipt-vds-unregistered"]},
        cites=(
            "RFC 9942 Section 4.3: \"When the 'receipts' header parameter is "
            "present, the verifier MUST confirm that the associated VDS and VDPs "
            "match entries present in the registries established in this "
            "specification.\" Table 2 registers 0 Reserved and 1 RFC9162_SHA256 "
            "and nothing else, so 2 names a structure whose proof format is "
            "undefined."
        ),
        parent="base",
    )

    oob, payload = signed_statement(
        statement=BASE_STATEMENT,
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
    )
    oob_receipt = receipt(leaf=oob, tree_size=8, leaf_index=3)
    tagged = cbor2.loads(oob_receipt)
    body = list(tagged.value)
    uhdr = dict(body[1])
    uhdr[LBL_VDP] = {PROOF_INCLUSION: [cbor2.dumps([8, 9, []])]}
    body[1] = uhdr
    add(
        "leaf-index-outside-tree",
        "reject",
        statement_bytes=transparent(
            oob, [cbor2.dumps(cbor2.CBORTag(tagged.tag, body))]
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-14"],
        expected={"verdict": "invalid", "codes": ["inclusion-proof-unapplicable"]},
        cites=(
            "RFC 9942 Section 5.2 quotes RFC 9162 as a normative block: \"If "
            "leaf_index is greater than or equal to tree_size, then fail the proof "
            "verification.\" A proof-checker that walks the path without the bound "
            "returns a root here, and the root it returns is a function of nothing."
        ),
        parent="deep-path",
    )


# ---------------------------------------------------------------------------
# Indeterminate members. Each names a question the documents leave open, and
# the readings a conforming verifier could take. The point is not that a
# verifier is wrong; it is that two conforming verifiers disagree and neither
# document chooses, so the corpus records the fork instead of inventing a rule.
# ---------------------------------------------------------------------------
def build_indeterminate() -> None:
    consistency, payload = signed_statement(
        statement=aee_statement("1" * 64),
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
    )
    add(
        "consistency-receipt-only",
        "indeterminate",
        statement_bytes=transparent(
            consistency,
            [
                receipt(
                    leaf=consistency,
                    tree_size=8,
                    leaf_index=3,
                    proof_type=PROOF_CONSISTENCY,
                )
            ],
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-15"],
        expected={
            "family": "receipt-carries-no-inclusion-proof-type",
            "readings": {
                "inclusion-required": "receipt-not-of-inclusion",
                "any-registered-proof": "valid",
                "unsupported-proof-type": "receipt-proof-type-unsupported",
            },
        },
        cites=(
            "RFC 9943 Section 7 says a Receipt \"contains inclusion proofs\" while "
            "the CDDL of RFC 9942 Section 4.3 admits Receipt_For_Consistency as a "
            "Receipt. A consistency proof establishes that the log is append-only "
            "and says nothing about this statement being in it. Neither document "
            "says what a Relying Party concludes from a Transparent Statement "
            "whose only receipt is a consistency receipt."
        ),
    )

    no_ct, payload = signed_statement(
        statement=aee_statement("2" * 64),
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
        content_type=None,
    )
    add(
        "content-type-absent",
        "indeterminate",
        statement_bytes=transparent(
            no_ct, [receipt(leaf=no_ct, tree_size=8, leaf_index=3)]
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-16"],
        expected={
            "family": "payload-format-undeclared",
            "readings": {
                "typ-sufficient": "valid",
                "content-type-required": "content-type-absent",
                "sniff-payload": "valid",
            },
        },
        cites=(
            "RFC 9052 Section 3.1: \"Applications SHOULD provide this header "
            "parameter if the content structure is potentially ambiguous.\" The "
            "CDDL of RFC 9943 Section 6.1 marks content_type optional and this "
            "profile has registered no media type, so a service that dispatches "
            "policy on content type and one that reads typ reach different "
            "answers about the same bytes."
        ),
    )

    no_iat, payload = signed_statement(
        statement=aee_statement("3" * 64),
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
    )
    add(
        "registration-time-unexpressed",
        "indeterminate",
        statement_bytes=transparent(
            no_iat, [receipt(leaf=no_iat, tree_size=8, leaf_index=3, iat=None)]
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-17"],
        expected={
            "family": "registration-time-not-carried",
            "readings": {
                "time-not-required": "valid",
                "freshness-required": "registration-time-absent",
                "iat-required-by-policy": "receipt-iat-absent",
            },
        },
        cites=(
            "RFC 9943 Section 7: \"The Registration time is recorded as the "
            "timestamp when the TS added the Signed Statement to its VDS.\" No "
            "header carries it, and RFC 9942 Section 7.2 states \"The details of "
            "expressing validity periods are out of scope for this document.\" So "
            "a receipt can be complete and still place the registration nowhere "
            "in time."
        ),
    )

    equiv, payload = signed_statement(
        statement=aee_statement("4" * 64),
        observer_position=OBSERVER_POSITION,
        crit=[LBL_OBSERVER_POSITION],
    )
    add(
        "same-tree-size-two-roots",
        "indeterminate",
        statement_bytes=transparent(
            equiv,
            [
                receipt(leaf=equiv, tree_size=8, leaf_index=3),
                receipt(
                    leaf=equiv,
                    tree_size=8,
                    leaf_index=3,
                    other_entries=[f"forked-entry-{i}".encode() for i in range(8)],
                ),
            ],
        ),
        payload=payload,
        detached=False,
        conditions=["sc-c-18"],
        expected={
            "family": "two-roots-at-one-tree-size",
            "readings": {
                "verify-any-one": "valid",
                "verify-all": "receipt-root-divergence",
                "equivocation-detected": "log-equivocation",
            },
        },
        cites=(
            "Both receipts verify, both are signed by the same transparency "
            "service, both declare tree size 8, and their roots differ, which is "
            "an append-only log presenting two histories. RFC 9943 Section 7.1 "
            "permits a Relying Party to \"verify only a single Receipt that is "
            "acceptable to them\", so the reading that accepts is conforming and "
            "the reading that detects the fork is conforming, and detecting it at "
            "all needs consistency proofs and monitoring that no relying-party "
            "requirement in either document asks for."
        ),
    )


# ---------------------------------------------------------------------------
CONDITIONS: dict[str, str] = {
    "sc-c-1": "sub is the digest the in-toto subject carries",
    "sc-c-2": "the receipt carries an inclusion proof",
    "sc-c-3": "the recomputed root is the root the receipt signs",
    "sc-c-4": "every crit-listed parameter sits in the protected bucket",
    "sc-c-5": "every crit-listed parameter is one the verifier can process",
    "sc-c-6": "the observer position is protected and crit-listed",
    "sc-c-7": "the declared algorithm is the algorithm that signed",
    "sc-c-8": "the algorithm identifier is fully specified",
    "sc-c-9": "exp, where present, is in the future",
    "sc-c-10": "nbf, where present, is in the past",
    "sc-c-11": "iss is the identity bound to the verification key",
    "sc-c-12": "protected CWT Claims are present exactly once",
    "sc-c-13": "vds names a registered verifiable data structure",
    "sc-c-14": "the inclusion proof is applicable to the tree it declares",
    "sc-c-15": "which proof types a receipt must carry",
    "sc-c-16": "how the payload format is declared",
    "sc-c-17": "how registration time reaches a verifier",
    "sc-c-18": "what two roots at one tree size mean to a relying party",
}


def main() -> None:
    build_accept()
    build_reject()
    build_indeterminate()
    emit()
    counts = {
        kind: sum(1 for entry in MANIFEST if entry["kind"] == kind)
        for kind in ("accept", "reject", "indeterminate")
    }
    corpus = corpus_digest({"vectors": MANIFEST}, HERE)
    manifest = {
        "suite": SUITE,
        "profile": PROFILE,
        "profileText": "profiles/scitt-cose.md",
        "predicateType": AEE_PREDICATE_TYPE,
        "carries": {
            "architecture": "RFC 9943",
            "receipts": "RFC 9942",
            "cose": "RFC 9052",
            "coseAlgorithms": "RFC 9053",
            "fullySpecifiedAlgorithms": "RFC 9864",
            "cwtClaimsHeader": "RFC 9597",
            "verifiableDataStructure": "RFC 9162",
        },
        "algorithm": {
            "statement": ALG_ED25519,
            "receipt": ALG_ED25519,
            "note": "Ed25519 (-19), the fully-specified registration of RFC 9864 "
            "Section 4.2.1. Deterministic signatures, so the corpus regenerates "
            "byte-identically; -8 and -7 are Deprecated per RFC 9864 "
            "Section 4.2.2 and appear only in reject members.",
        },
        "vds": VDS_RFC9162_SHA256,
        "observerPositionLabel": LBL_OBSERVER_POSITION,
        "counts": counts,
        "corpusDigest": corpus,
        "note": "Every reject member declares the accept member it is one "
        "mutation from, so a verifier that refuses everything scores zero "
        "rather than full marks. An indeterminate member declares the readings "
        "a conforming verifier could take, because the documents cited do not "
        "choose between them; scoring one of those readings wrong would be "
        "this corpus inventing a rule the standards do not carry.",
        "conditions": CONDITIONS,
        "vectors": sorted(MANIFEST, key=lambda e: e["id"]),
    }
    write(
        "MANIFEST.json",
        json.dumps(manifest, indent=2, ensure_ascii=False).encode() + b"\n",
    )
    write("INDEX.md", index_markdown(manifest).encode())
    print(json.dumps(counts), "corpusDigest", corpus)


def index_markdown(manifest: dict[str, Any]) -> str:
    """One table row per member, emitted rather than authored.

    Emitted because a hand-written index drifts from the corpus it indexes and
    both halves still look authoritative, which is a defect this repository has
    already paid for once in its other suite. The verdict column is here and
    not in any filename, so a reader can see what each member is for while a
    scoring harness still has to open MANIFEST.json to learn the answer.
    """
    lines = [
        "# SCITT/COSE carriage vectors for adversarial execution evidence",
        "",
        "Emitted by `gen_vectors.py`. Do not edit: an edit here is overwritten on",
        "the next build and `scripts/regenerability-gate.py` refuses the push that",
        "makes one.",
        "",
        f"Profile: `{manifest['profile']}`, specified in `{manifest['profileText']}`.",
        f"Payload predicate: `{manifest['predicateType']}`.",
        "",
        "Each member is a Transparent Statement as RFC 9943 Section 7 defines one.",
        "The `parent` column names the conforming member a refusal is one mutation",
        "from. An indeterminate member has no parent because there is no conforming",
        "form of a question the documents do not answer.",
        "",
        "| vector | verdict | conditions | what it carries | parent |",
        "| --- | --- | --- | --- | --- |",
    ]
    for record in manifest["vectors"]:
        verdict = record["kind"]
        conditions = " ".join(f"`{c}`" for c in record["conditions"])
        # The whole citation, pipes escaped for the table. An earlier version
        # cut at the first sentence boundary, which sliced a quotation in half
        # and turned "0x00 || d0" into a different expression; a table that
        # misquotes the document it cites is worse than one with long rows.
        summary = record["cites"].replace("|", "\\|")
        parent = f"`{record['parent']}`" if "parent" in record else ""
        lines.append(
            f"| `{record['id']}` | {verdict} | {conditions} | {summary} | {parent} |"
        )
    lines += ["", "## Conditions", "", "| id | what it requires |", "| --- | --- |"]
    for cid, text in manifest["conditions"].items():
        lines.append(f"| `{cid}` | {text} |")
    lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    main()
