#!/usr/bin/env python3
"""Deterministic generator for the AEE v0.7 ACCEPT (valid) conformance vectors.

Emits ok-001 .. ok-039 (ok-037 is reserved) as complete, unwrapped in-toto
Statement JSON files that a conforming verifier MUST accept, into the directory
containing this script.

Determinism recipe (normative for this suite):
  - Ed25519/RFC 8032 keys with seeds DERIVED from published constants:
        seed(role) = SHA-256("in-toto-aee-test-key/<role>/v1")
    roles: substrate-observation-test, wrong-signer-test, statement-test.
    Only PUBLIC keys are ever published; anyone re-derives the seeds.
  - Fixed timestamps: issuedAt 2026-01-01T00:00:00Z, armedAt 2025-12-31T23:59:00Z.
  - Subject name: example-agent-bundle. Attack ids: XA-EXAMPLE-*, XB-EXAMPLE-*.
  - Every digest is DERIVED from a committed synthetic one-line preimage
    (see PREIMAGES below); nothing is hand-typed.
  - Committed files: UTF-8, LF, 2-space indent, JCS (lexicographic) member
    ordering, standard base64 with padding, trailing newline.

All content is synthetic. The producer vocabulary uses only strings the public
predicate specification itself publishes (e.g. policy.egress_sinkhole, none,
sinkhole, egress_captured, no_egress) or obviously synthetic example values.
"""

import base64
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

OUT_DIR = Path(__file__).resolve().parent

# Every vector in this corpus, accepted and rejected alike, is written here and
# named after a digest of its own bytes. There is no directory per verdict and
# no prefix, because both of those told a rail the answer before it read the
# statement: measured over the whole manifest-relative path, the identifier
# predicted accept-or-reject with a separability of 1.0000.
STATEMENTS_DIR = OUT_DIR.parent / "statements"

# The authoring slug of each accept vector, mapped to the identifier it was
# published under. The reject generator needs this to resolve the parent every
# reject vector declares, and it is DELIBERATELY NOT COMMITTED.
#
# That is measured rather than cautious. Run through the same classifier and the
# same permutation null as every other surface, the slug surface scores 0.9936
# as it stands, 0.7260 with the ok-/bad- family token removed, and 0.7307 on the
# description words alone -- each against a null near 0.585. So the leak is not
# the prefix, it is the vocabulary: a slug says `missing`, `mismatch`,
# `duplicate` and `wrong` on one side and `clean`, `canonical` and `pass` on the
# other. There is no spelling of a committed slug-to-identifier map that carries
# no label, which makes this an intermediate like an object file rather than
# anything the corpus may ship.
BUILD_IDS = OUT_DIR.parent.parent / ".build" / "aee-accept-ids.json"

# Sixteen hex characters of SHA-256 over the vector's own bytes. Sixty-four bits
# is far beyond what a corpus this size needs, and a collision is refused rather
# than trusted to arithmetic.
ID_HEX = 16


def vector_id(body: bytes) -> str:
    return "v" + hashlib.sha256(body).hexdigest()[:ID_HEX]

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://in-toto.io/attestation/adversarial-execution-evidence/v0.7"
PAYLOAD_TYPE = "application/vnd.example.aee-observation.v1+json"
ISSUED_AT = "2026-01-01T00:00:00Z"
ARMED_AT = "2025-12-31T23:59:00Z"
SUBJECT_NAME = "example-agent-bundle"

# ---------------------------------------------------------------------------
# canonicalization + hashing
# ---------------------------------------------------------------------------


def jcs(obj: Any) -> bytes:
    """RFC 8785 canonical JSON for the value space this suite uses.

    The suite restricts itself to ASCII strings, small integers, booleans,
    arrays and objects, for which JCS coincides with minimal-separator,
    code-point-sorted JSON.
    """
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE PAEv1 over (payloadType, payload)."""
    pt = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(pt), pt, len(payload), payload)


def rfc6962_root(leaves: list[bytes]) -> str:
    """RFC 6962 Merkle root; leaf = H(0x00||PAE), node = H(0x01||l||r),
    recursive split at the largest power of two strictly less than n."""

    def mth(entries: list[bytes]) -> bytes:
        n = len(entries)
        if n == 1:
            return hashlib.sha256(b"\x00" + entries[0]).digest()
        k = 1
        while k * 2 < n:
            k *= 2
        return hashlib.sha256(b"\x01" + mth(entries[:k]) + mth(entries[k:])).digest()

    return mth(leaves).hex()


# ---------------------------------------------------------------------------
# derived test keys (public halves only are ever published)
# ---------------------------------------------------------------------------


def derive_key(role: str) -> tuple[Ed25519PrivateKey, bytes, str]:
    seed = hashlib.sha256(f"in-toto-aee-test-key/{role}/v1".encode()).digest()
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub = priv.public_key().public_bytes_raw()
    keyid = sha256_hex(pub)
    return priv, pub, keyid


SUB_PRIV, SUB_PUB, SUB_KEYID = derive_key("substrate-observation-test")
WRONG_PRIV, WRONG_PUB, WRONG_KEYID = derive_key("wrong-signer-test")
STMT_PRIV, STMT_PUB, STMT_KEYID = derive_key("statement-test")

# ---------------------------------------------------------------------------
# synthetic one-line preimages -> every digest in the suite
# ---------------------------------------------------------------------------

PREIMAGES: dict[str, Any] = {
    "subject": "example-agent-bundle-content/v1",
    "substrate": "example-substrate-image-content/v1",
    "catch-policy": {"exampleCatchPolicy": {"mode": "enforce"}},
    "network-posture": {"exampleNetworkPosture": {"posture": "sinkhole"}},
    "run-entropy": "example-run-start-checkpoint/v1",
    "unchecked-binding": "example-unchecked-binding/v1",
    # Two distinct admission receipts, A and B, and a second observation
    # substrate. The two receipts exist so that a vector can hold one admission
    # identity against ANOTHER admission identity rather than against an
    # executed artifact: those are different object categories and a digest
    # that differs because the categories differ demonstrates nothing. The
    # second substrate is the substituted observation-substrate identity the
    # vate-3* vectors move; it is a runtime image in the world, but what this
    # predicate reads it as is the substrate anchor, and naming it after the
    # field keeps the vectors from reading as a runtime comparison they do not
    # perform. All three are derived from a published one-line preimage exactly
    # as every other digest here is, so a reader re-derives them rather than
    # trusting a constant somebody typed.
    "admission-receipt-a": "example-admission-receipt-a/v1",
    "admission-receipt-b": "example-admission-receipt-b/v1",
    "second-substrate-image": "example-second-substrate-image/v1",
}

SUBJECT_DIGEST = sha256_hex(PREIMAGES["subject"].encode())
SUBSTRATE_DIGEST = sha256_hex(PREIMAGES["substrate"].encode())
RECEIPT_A_NAME = "example-admission-receipt-a"
RECEIPT_A_DIGEST = sha256_hex(PREIMAGES["admission-receipt-a"].encode())
RECEIPT_B_DIGEST = sha256_hex(PREIMAGES["admission-receipt-b"].encode())
SECOND_SUBSTRATE_DIGEST = sha256_hex(PREIMAGES["second-substrate-image"].encode())
CATCH_POLICY_DIGEST = sha256_hex(jcs(PREIMAGES["catch-policy"]))
POSTURE_DIGEST = sha256_hex(jcs(PREIMAGES["network-posture"]))
RUN_ENTROPY_DIGEST = sha256_hex(PREIMAGES["run-entropy"].encode())
UNCHECKED_BINDING = sha256_hex(PREIMAGES["unchecked-binding"].encode())

DEFAULT_LABELS = ["egress_captured", "no_egress"]
DEFAULT_CAUGHT = ["egress_captured"]

# The result vocabulary, in the order the recompute takes its minimum over.
RESULT_ORDER = {"fail": 0, "degraded": 1, "pass_indirect": 2, "pass": 3}

# The networkPosture object as it travels on the wire. Version 2 of the run
# binding folds in the JCS digest of this WHOLE object rather than the value of
# its own digest member, so the posture string and every further member a
# producer carries here are inside every record's signature.
DEFAULT_POSTURE = {"posture": "sinkhole", "digest": {"sha256": POSTURE_DIGEST}}

# The closed registry of substrate-authoritative egress postures.
EGRESS_POSTURES = frozenset(
    {"no_network", "allowlist", "sinkhole", "unsafe_bypass_egress"}
)


def vocab_obj(labels: list[str], caught: list[str]) -> dict[str, Any]:
    return {
        "digest": {"sha256": sha256_hex(jcs({"caught": caught, "labels": labels}))},
        "labels": labels,
        "caught": caught,
    }


def vocab_digest(labels: list[str], caught: list[str]) -> str:
    return sha256_hex(jcs({"caught": caught, "labels": labels}))


# The corpus identity every statement in this suite carries. Named constants
# rather than literals inside corpus_obj because the reject generator imports
# them: a reject vector is its accept parent plus one mutation, and a corpus
# name spelled twice is a second difference between the two that no mutation
# accounts for. That is how the pair drifted apart before -- see the module
# docstring of vectors/reject/gen_invalid_vectors.py.
CORPUS_NAME = "example-adversarial-corpus"
CORPUS_URI = "pkg:example/adversarial-corpus@1.0.0"


def corpus_obj(manifest: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": CORPUS_NAME,
        "uri": CORPUS_URI,
        "digest": {"sha256": sha256_hex(jcs(manifest))},
        "manifest": manifest,
    }


def run_binding(
    corpus_digest: str,
    labels: list[str] | None = None,
    caught: list[str] | None = None,
    posture: dict[str, Any] | None = None,
    subject: str | None = None,
    substrate: str | None = None,
) -> str:
    """The version-2 run binding: eight ASCII members in JCS order.

    The two inputs version 2 added are both material the statement already
    carries. ``observationVocabulary`` is the carried vocabulary digest, so a
    caught set narrowed after the run derives a binding no record carries.
    ``networkPosture`` is the JCS digest of the carried posture OBJECT, so the
    posture string travels inside the signature that used to sit beside it.

    ``subject`` and ``substrate`` default to this suite's constants and are
    parameters rather than constants for one reason: a vector that means to ask
    what the binding does when one of those two inputs is a different identity
    has to derive the binding over that identity, and the alternative is a
    second copy of this pre-image somewhere else. Two copies of a pre-image
    diverge, and the divergence is invisible until a rail disagrees.
    """
    labels = DEFAULT_LABELS if labels is None else labels
    caught = DEFAULT_CAUGHT if caught is None else caught
    pre = {
        "aeeBindingVersion": "2",
        "catchPolicy": CATCH_POLICY_DIGEST,
        "corpus": corpus_digest,
        "networkPosture": sha256_hex(jcs(DEFAULT_POSTURE if posture is None else posture)),
        "observationVocabulary": vocab_digest(labels, caught),
        "runEntropy": RUN_ENTROPY_DIGEST,
        "subject": SUBJECT_DIGEST if subject is None else subject,
        "substrate": SUBSTRATE_DIGEST if substrate is None else substrate,
    }
    return sha256_hex(jcs(pre))


# ---------------------------------------------------------------------------
# observation record construction
# ---------------------------------------------------------------------------


def commitment_for(note: str) -> str:
    """The commitment value an interception record carries for one observation.

    Derived, never typed, from the same published-constant recipe every other
    digest in this suite uses. What a substrate commits to is its own choice
    and the specification does not constrain it; what matters here is that the
    value is reproducible by anyone re-running this generator, and that the
    corpus manifest can declare the same value in advance -- which is the whole
    of what makes a row's attribution checkable.
    """
    return sha256_hex(f"in-toto-aee-test-commitment/{note}/v1".encode())


# The sentinel a sealed record's aeeObservedSet carries until make_statement
# knows the record set the seal is committing to. It is never emitted: a seal
# whose value is still the sentinel when the statement is assembled has not
# been finalized, and finalize_records asserts that.
OBSERVED_SET_PENDING = "PENDING"

# The same device on the arming record. A run-start declaration has to be a
# superset of the assessed set the statement ends up carrying, and only
# make_statement knows what that is, so the record is built with a sentinel
# and filled once the coverage is fixed.
ASSESSED_ATTACKS_PENDING = ["PENDING"]


def make_record(  # noqa: C901 -- one guarded branch per record kind and per independent option field; see docs/complexity-rationales.toml
    kind: str,
    binding: str,
    method: str | None = None,
    note: str | None = None,
    drop_count: int = 0,
    drop_bound: int | None = None,
    extra: dict[str, Any] | None = None,
    signer: str = "substrate",
    keyid_mode: str = "normal",  # normal | garbage | absent
    sig_mode: str = "pae",  # pae | raw
    commitment: list[str] | None = None,
    assessed_attacks: list[str] | None = None,
    observed_attacks: list[str] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any]
    if kind == "interception":
        payload = {
            "aeeKind": "interception",
            "aeeMethod": method or "intercepted",
            "aeePayloadCommitment": commitment
            if commitment is not None
            else [commitment_for(note or "default")],
            "aeeRunBinding": binding,
        }
    elif kind == "arming":
        payload = {
            "aeeAssessedAttacks": ASSESSED_ATTACKS_PENDING
            if assessed_attacks is None
            else assessed_attacks,
            "aeeKind": "arming",
            "aeeMethod": "intercepted",
            "aeePostureDigest": POSTURE_DIGEST,
            "aeeRunBinding": binding,
            "armedAt": ARMED_AT,
        }
    elif kind == "sealed":
        payload = {
            "aeeDropCount": drop_count,
            "aeeKind": "sealed",
            "aeeMethod": "intercepted",
            # The empty array is the honest value and is required rather than
            # omissible: a substrate holding no probe-to-record correspondence
            # says so on the wire instead of leaving an absence nothing records.
            "aeeObservedAttacks": observed_attacks or [],
            "aeeObservedSet": OBSERVED_SET_PENDING,
            "aeePostureDigest": POSTURE_DIGEST,
            "aeeRunBinding": binding,
            "aeeStillArmed": True,
        }
        if drop_bound is not None:
            payload["aeeDropBound"] = drop_bound
    elif kind == "examination":
        payload = {
            "aeeKind": "examination",
            "aeeMethod": "reconstructed",
            "aeeRunBinding": binding,
        }
    else:  # forward-compat unknown kind
        payload = {
            "aeeKind": kind,
            "aeeMethod": method or "intercepted",
            "aeeRunBinding": binding,
        }
    if note is not None:
        payload["producerNote"] = note
    if extra:
        payload.update(extra)
    return sign_payload(payload, signer, keyid_mode, sig_mode)


def sign_payload(
    payload: dict[str, Any],
    signer: str = "substrate",
    keyid_mode: str = "normal",
    sig_mode: str = "pae",
) -> dict[str, Any]:
    """Canonicalize, sign and envelope one record payload.

    Split out of make_record because a sealed record is signed TWICE: once when
    it is built, and again after make_statement fills in the record set it
    commits to. The signing options travel with the record so the second
    signing reproduces the first one's choices rather than silently normalizing
    a deliberately odd signature back to the default.
    """
    payload_bytes = jcs(payload)
    priv = SUB_PRIV if signer == "substrate" else WRONG_PRIV
    keyid = SUB_KEYID if signer == "substrate" else WRONG_KEYID
    signed_bytes = (
        pae(PAYLOAD_TYPE, payload_bytes) if sig_mode == "pae" else payload_bytes
    )
    sig = base64.b64encode(priv.sign(signed_bytes)).decode()

    entry: dict[str, str] = {"sig": sig}
    if keyid_mode == "normal":
        entry["keyid"] = keyid
    elif keyid_mode == "garbage":
        entry["keyid"] = "deadbeef" * 8

    return {
        "payload": base64.b64encode(payload_bytes).decode(),
        "payloadType": PAYLOAD_TYPE,
        "signatures": [entry],
        "_opts": {"signer": signer, "keyid_mode": keyid_mode, "sig_mode": sig_mode},
    }


def observed_set_digest(records: list[dict[str, Any]]) -> str:
    """The value a seal's aeeObservedSet commits to.

    SHA-256 of the RFC 8785 canonicalization of the duplicate-free array,
    sorted ascending by UTF-16 code unit, of the leaf hashes of every
    interception and examination record. The entries are lowercase hex and
    therefore ASCII, so a byte sort IS the UTF-16 code-unit sort here.
    """
    leaves = set()
    for r in records:
        payload = base64.b64decode(r["payload"])
        try:
            kind = json.loads(payload).get("aeeKind")
        except ValueError:
            continue
        if kind in ("interception", "examination"):
            leaves.add(
                hashlib.sha256(b"\x00" + pae(r["payloadType"], payload)).hexdigest()
            )
    return sha256_hex(jcs(sorted(leaves)))


def finalize_records(
    records: list[dict[str, Any]], declared: list[str] | None = None
) -> list[dict[str, Any]]:
    """Fill in every sealed record's aeeObservedSet and strip the build options.

    The seal commits to the leaf hashes of the interception and examination
    records the statement carries, and the seal is not one of them, so there is
    no circularity: the set is computed over the records as built, then each
    seal is rewritten and re-signed. A seal that reaches here already carrying a
    concrete value keeps it -- that is how a vector that deliberately commits to
    the wrong set is written -- and one still carrying the sentinel is filled.
    """
    digest = observed_set_digest(records)
    out: list[dict[str, Any]] = []
    for r in records:
        opts = r.get("_opts", {})
        payload = json.loads(base64.b64decode(r["payload"]))
        changed = False
        if payload.get("aeeObservedSet") == OBSERVED_SET_PENDING:
            payload["aeeObservedSet"] = digest
            changed = True
        if payload.get("aeeAssessedAttacks") == ASSESSED_ATTACKS_PENDING:
            payload["aeeAssessedAttacks"] = sorted(declared or [])
            changed = True
        if changed:
            r = sign_payload(payload, **opts)
        out.append({k: v for k, v in r.items() if k != "_opts"})
    for r in out:
        payload = base64.b64decode(r["payload"])
        assert b"PENDING" not in payload, (
            "a run-level record reached the statement still carrying a build "
            "sentinel"
        )
    return out


def make_row(
    attack_id: str,
    observed: str,
    basis: str | None,
    method: str | None,
    layer: str,
    refs: list[int] | None,
    selectors: list[str] | None = None,
    attribution: str | None = "paired",
) -> dict[str, Any]:
    """One attackResults row.

    attribution defaults to `paired`, which is the floor a producer may always
    truthfully declare: it says this row does not carry the stronger binding,
    never that the producer had one and withheld it. A vector that means to
    exercise the stronger value passes `pinned` and carries the corpus
    expectation and the record commitment that make it true.
    """
    row: dict[str, Any] = {"attackId": attack_id, "containmentObserved": observed}
    if basis is not None:
        row["basis"] = basis
    if method is not None:
        row["method"] = method
    if attribution is not None:
        row["attribution"] = attribution
    row["actualLayer"] = layer
    if refs is not None:
        row["observationRefs"] = refs
    if selectors is not None:
        row["observationSelectors"] = selectors
    return row


def make_statement(  # noqa: C901 -- one guarded branch per independent option field; see docs/complexity-rationales.toml
    manifest: dict[str, Any],
    rows: list[dict[str, Any]],
    records: list[dict[str, Any]] | None = None,
    assessed: list[str] | None = None,
    out_of_scope: dict[str, Any] | None = None,
    routed_elsewhere: dict[str, Any] | None = None,
    labels: list[str] | None = None,
    caught: list[str] | None = None,
    with_entropy: bool = True,
    does_not_assert: list[str] | None = None,
    predicate_extra: dict[str, Any] | None = None,
    posture: dict[str, Any] | None = None,
    subject: dict[str, Any] | None = None,
    substrate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    labels = DEFAULT_LABELS if labels is None else labels
    caught = DEFAULT_CAUGHT if caught is None else caught
    corpus = corpus_obj(manifest)
    env = {
        "substrate": substrate
        if substrate is not None
        else {
            "name": "example-substrate-image",
            "digest": {"sha256": SUBSTRATE_DIGEST},
        },
        "corpus": corpus,
        "catchPolicy": {"digest": {"sha256": CATCH_POLICY_DIGEST}},
        "networkPosture": DEFAULT_POSTURE if posture is None else posture,
        "observationVocabulary": vocab_obj(labels, caught),
    }
    if with_entropy:
        env["runEntropy"] = {"digest": {"sha256": RUN_ENTROPY_DIGEST}}

    caught_set = set(caught)
    label_set = set(labels)

    def carried_result() -> str:
        forced_fail = False
        indirect = False
        for r in rows:
            lab = r.get("containmentObserved")
            if lab in caught_set or lab not in label_set:
                forced_fail = True
            elif r.get("basis") not in ("substrate", "artifact"):
                forced_fail = True
            elif r.get("method") not in ("intercepted", "reconstructed"):
                forced_fail = True
            elif r.get("attribution") not in ("pinned", "paired"):
                forced_fail = True
            elif r.get("basis") != "substrate" or r.get("method") != "intercepted":
                indirect = True
        candidates = [
            "fail" if forced_fail else "pass",
            "degraded" if ((out_of_scope or {}) or (routed_elsewhere or {})) else "pass",
            "pass_indirect" if indirect else "pass",
        ]
        return min(candidates, key=RESULT_ORDER.__getitem__)

    predicate: dict[str, Any] = {
        "result": carried_result(),
        "observationEnvironment": env,
        "coverage": {
            "assessedClasses": assessed
            if assessed is not None
            else sorted(manifest["classes"]),
            "outOfScope": out_of_scope or {},
            "routedElsewhere": routed_elsewhere or {},
        },
        "attackResults": rows,
        "issuedAt": ISSUED_AT,
    }
    if records:
        # The run-start declaration defaults to the whole manifest: a producer
        # that declares every attack the corpus names has committed to the
        # largest set the manifest permits and is bounded there by coverage
        # integrity alone, which is the shape the subset comparison exists to
        # leave available.
        records = finalize_records(
            records, [a for ids in manifest["classes"].values() for a in ids]
        )
        predicate["observationRecords"] = records
        leaves = [
            pae(r["payloadType"], base64.b64decode(r["payload"])) for r in records
        ]
        predicate["batchRoot"] = rfc6962_root(leaves)
    if does_not_assert is not None:
        predicate["doesNotAssert"] = does_not_assert
    if predicate_extra:
        predicate.update(predicate_extra)

    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            subject
            if subject is not None
            else {"name": SUBJECT_NAME, "digest": {"sha256": SUBJECT_DIGEST}}
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


# ---------------------------------------------------------------------------
# the accept vectors
# ---------------------------------------------------------------------------


def build_vectors() -> dict[str, dict[str, Any]]:
    v: dict[str, dict[str, Any]] = {}

    man_1 = {"classes": {"XA": ["XA-EXAMPLE-1"]}}
    b_1 = run_binding(sha256_hex(jcs(man_1)))
    man_2 = {"classes": {"XA": ["XA-EXAMPLE-1", "XA-EXAMPLE-2"]}}
    b_2 = run_binding(sha256_hex(jcs(man_2)))
    man_ab = {"classes": {"XA": ["XA-EXAMPLE-1"], "XB": ["XB-EXAMPLE-1"]}}
    b_ab = run_binding(sha256_hex(jcs(man_ab)))
    man_2b = {"classes": {"XA": ["XA-EXAMPLE-1", "XA-EXAMPLE-2"], "XB": ["XB-EXAMPLE-1"]}}
    b_2b = run_binding(sha256_hex(jcs(man_2b)))
    man_2b2 = {
        "classes": {
            "XA": ["XA-EXAMPLE-1", "XA-EXAMPLE-2"],
            "XB": ["XB-EXAMPLE-1", "XB-EXAMPLE-2"],
        }
    }
    b_2b2 = run_binding(sha256_hex(jcs(man_2b2)))

    # ok-001 canonical caught row; single-leaf tree (root == leaf hash)
    v["ok-001-caught-intercepted-fail"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0],
            )
        ],
        records=[
            make_record("interception", b_1, note="example interception observation a"),
            make_record("sealed", b_1),
        ],
    )

    # ok-002 canonical clean pass, arming + sealed, dropCount 0
    v["ok-002-clean-pass-armed-sealed"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[make_record("arming", b_1), make_record("sealed", b_1)],
    )

    # ok-003 sealed with self-bounded non-zero drop count
    v["ok-003-clean-pass-bounded-drops"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[
            make_record("arming", b_1),
            make_record("sealed", b_1, drop_count=3, drop_bound=5),
        ],
    )

    # ok-004 degraded via outOfScope
    v["ok-004-degraded-out-of-scope"] = make_statement(
        man_ab,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[make_record("arming", b_ab), make_record("sealed", b_ab)],
        assessed=["XA"],
        out_of_scope={"XB": "example: class not assessed in this run"},
    )

    # ok-005 degraded via routedElsewhere
    v["ok-005-degraded-routed-elsewhere"] = make_statement(
        man_ab,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[make_record("arming", b_ab), make_record("sealed", b_ab)],
        assessed=["XA"],
        routed_elsewhere={"XB": "example: class assessed under a separate statement"},
    )

    # ok-006 clean (substrate, reconstructed) covered by examination
    v["ok-006-clean-reconstructed"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "reconstructed", "none", [0]
            )
        ],
        records=[
            make_record("examination", b_1, note="example state comparison a-to-b"),
            make_record("sealed", b_1),
        ],
    )

    # ok-007 artifact-only, recordless: no records, no batchRoot, no runEntropy
    v["ok-007-artifact-only-recordless"] = make_statement(
        man_1,
        [make_row("XA-EXAMPLE-1", "no_egress", "artifact", "reconstructed", "none", [])],
        with_entropy=False,
    )

    # ok-008 artifact row with unknown method: fail-closed row, carried fail, VALID
    v["ok-008-artifact-fail-closed-method"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "no_egress",
                "artifact",
                "example_unknown_method",
                "none",
                [],
            )
        ],
        with_entropy=False,
    )

    # ok-009 artifact row with out-of-vocabulary label: fail-closed, VALID
    v["ok-009-artifact-oov-label-fail"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "example_label_a",
                "artifact",
                "reconstructed",
                "none",
                [],
            )
        ],
        with_entropy=False,
    )

    # ok-010 retired 0.4 basis value: out-of-vocabulary, fail-closed, no alias
    v["ok-010-artifact-retired-basis-fail"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "no_egress",
                "substrate_observed",
                "reconstructed",
                "none",
                [],
            )
        ],
        with_entropy=False,
    )

    # ok-011 two clean rows share one arming+sealed pair
    v["ok-011-shared-run-records"] = make_statement(
        man_2,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            ),
            make_row(
                "XA-EXAMPLE-2", "no_egress", "substrate", "intercepted", "none", [0, 1]
            ),
        ],
        records=[make_record("arming", b_2), make_record("sealed", b_2)],
    )

    # ok-012 observationSelectors parallel to refs; advisory only
    v["ok-012-selectors-present"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "no_egress",
                "substrate",
                "intercepted",
                "none",
                [0, 1],
                selectors=["example-selector-a", "example-selector-b"],
            )
        ],
        records=[make_record("arming", b_1), make_record("sealed", b_1)],
    )

    # ok-013 unknown record kind: covers nothing, still contributes its leaf
    v["ok-013-unknown-kind-extra-record"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[
            make_record("arming", b_1),
            make_record("sealed", b_1),
            make_record("aee-future-x", b_1, note="example future observation"),
        ],
    )

    # ok-014 three records: RFC 6962 recursive split (2+1), no padding
    v["ok-014-three-record-odd-split"] = make_statement(
        man_2,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0],
            ),
            make_row(
                "XA-EXAMPLE-2", "no_egress", "substrate", "intercepted", "none", [1, 2]
            ),
        ],
        records=[
            make_record("interception", b_2, note="example interception observation a"),
            make_record("arming", b_2),
            make_record("sealed", b_2),
        ],
    )

    # ok-015 four-record balanced tree
    v["ok-015-four-record-tree"] = make_statement(
        man_2b,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0],
            ),
            make_row(
                "XA-EXAMPLE-2",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [1],
            ),
            make_row(
                "XB-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [2, 3]
            ),
        ],
        records=[
            make_record("interception", b_2b, note="example interception observation a"),
            make_record("interception", b_2b, note="example interception observation b"),
            make_record("arming", b_2b),
            make_record("sealed", b_2b),
        ],
    )

    # ok-016 caught row with actualLayer none: observed-but-not-enforced
    v["ok-016-caught-actuallayer-none"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "egress_captured", "substrate", "intercepted", "none", [0]
            )
        ],
        records=[
            make_record("interception", b_1, note="example interception observation a"),
            make_record("sealed", b_1),
        ],
    )

    # ok-017 method cap is one-directional: reconstructed row may reference an
    # intercepted-signed record (examination satisfies class-match)
    v["ok-017-method-weakening-allowed"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "reconstructed",
                "policy.egress_sinkhole",
                [0, 1],
            )
        ],
        records=[
            make_record("examination", b_1, note="example state comparison a-to-b"),
            make_record("interception", b_1, note="example interception observation a"),
            make_record("sealed", b_1),
        ],
    )

    # ok-018 reserved-prefix predicate members MUST be ignored
    v["ok-018-aee-prefix-ignored"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[make_record("arming", b_1), make_record("sealed", b_1)],
        predicate_extra={"evidenceTier": "attested", "aeeInjected": "x"},
    )

    # ok-019 keyid is a hint, never the check: garbage keyid + absent keyid,
    # both signatures verify against the pinned substrate key
    v["ok-019-wrong-keyid-sig-verifies"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[
            make_record("arming", b_1, keyid_mode="garbage"),
            make_record("sealed", b_1, keyid_mode="absent"),
        ],
    )

    # ok-020 signature over raw payload (no PAE): tier fault, never validity
    v["ok-020-non-pae-signature"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0],
            )
        ],
        records=[
            make_record(
                "interception",
                b_1,
                note="example interception observation a",
                sig_mode="raw",
            ),
            make_record("sealed", b_1),
        ],
    )

    # ok-021 producer extra members in a covering payload still cover
    v["ok-021-producer-extra-members"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0],
            )
        ],
        records=[
            make_record(
                "interception",
                b_1,
                note="example interception observation a",
                extra={"extraA": "example-extra-value"},
            ),
            make_record("sealed", b_1),
        ],
    )

    # ok-022 two independent arming records + one sealed
    v["ok-022-two-arming-records"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "no_egress",
                "substrate",
                "intercepted",
                "none",
                [0, 1, 2],
            )
        ],
        records=[
            make_record("arming", b_1, note="example arming vantage a"),
            make_record("arming", b_1, note="example arming vantage b"),
            make_record("sealed", b_1),
        ],
    )

    # ok-023 payload embeds a tempting public key; consumer MUST NOT TOFU it
    v["ok-023-no-tofu-embedded-key"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[
            make_record(
                "arming", b_1, extra={"embeddedVerificationKey": SUB_PUB.hex()}
            ),
            make_record("sealed", b_1),
        ],
    )

    # ok-024 exactly three rows: substrate/attested, substrate/unattested
    # (valid signature by the wrong-signer test key), artifact/declared
    v["ok-024-mixed-basis-rows"] = make_statement(
        man_2b,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0],
            ),
            make_row(
                "XA-EXAMPLE-2",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [1],
            ),
            make_row("XB-EXAMPLE-1", "no_egress", "artifact", "reconstructed", "none", []),
        ],
        records=[
            make_record("interception", b_2b, note="example interception observation a"),
            make_record(
                "interception",
                b_2b,
                note="example interception observation b",
                signer="wrong",
            ),
            make_record("sealed", b_2b),
        ],
    )

    # ok-025 doesNotAssert present: advisory, never required, never weakening
    v["ok-025-does-not-assert-present"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[make_record("arming", b_1), make_record("sealed", b_1)],
        does_not_assert=[
            "example: no claim is made about behavior outside the thrown corpus",
            "example: no claim is made about host integrity beyond the substrate attestation",
        ],
    )

    # ok-026 five records: unbalanced RFC 6962 split (4+1)
    v["ok-026-five-record-tree"] = make_statement(
        man_2b2,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0],
            ),
            make_row(
                "XA-EXAMPLE-2",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [1],
            ),
            make_row(
                "XB-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [2],
            ),
            make_row(
                "XB-EXAMPLE-2", "no_egress", "substrate", "intercepted", "none", [3, 4]
            ),
        ],
        records=[
            make_record("interception", b_2b2, note="example interception observation a"),
            make_record("interception", b_2b2, note="example interception observation b"),
            make_record("interception", b_2b2, note="example interception observation c"),
            make_record("arming", b_2b2),
            make_record("sealed", b_2b2),
        ],
    )

    # ok-027 artifact row with method member ABSENT: fail-closed, carried fail, VALID
    v["ok-027-artifact-missing-method"] = make_statement(
        man_1,
        [make_row("XA-EXAMPLE-1", "no_egress", "artifact", None, "none", [])],
        with_entropy=False,
    )

    # ok-028 empty caught set: vacuously no caught rows, clean pass. The caught
    # set is a binding input under version 2, so this vector's records carry a
    # binding of their own rather than b_1: an empty caught array derives a
    # different vocabulary digest and therefore a different run.
    b_1_no_caught = run_binding(sha256_hex(jcs(man_1)), caught=[])
    v["ok-028-empty-caught-pass"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[
            make_record("arming", b_1_no_caught),
            make_record("sealed", b_1_no_caught),
        ],
        caught=[],
    )

    # ok-029 artifact rows + unreferenced records + CORRECT batchRoot; no
    # substrate rows => no derived binding, record binding values are unchecked
    v["ok-029-artifact-with-records"] = make_statement(
        man_1,
        [make_row("XA-EXAMPLE-1", "no_egress", "artifact", "reconstructed", "none", [])],
        records=[
            make_record(
                "examination",
                UNCHECKED_BINDING,
                note="example state comparison a-to-b",
            ),
            make_record(
                "examination",
                UNCHECKED_BINDING,
                note="example state comparison c-to-d",
            ),
        ],
        with_entropy=False,
    )

    # ok-030 min-composition accept half: row method equals the WEAKEST signed
    # aeeMethod across its referenced records {reconstructed, intercepted,
    # reconstructed} = reconstructed
    v["ok-030-method-min-multirecord"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "reconstructed",
                "none",
                [0, 1, 2],
            )
        ],
        records=[
            make_record("examination", b_1, note="example state comparison a-to-b"),
            make_record(
                "interception",
                b_1,
                method="intercepted",
                note="example interception observation a",
            ),
            make_record(
                "interception",
                b_1,
                method="reconstructed",
                note="example interception observation b",
            ),
            make_record("sealed", b_1),
        ],
    )

    # ok-031 caught (substrate, reconstructed) row covered by examination
    v["ok-031-caught-reconstructed"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "reconstructed",
                "none",
                [0],
            )
        ],
        records=[
            make_record("examination", b_1, note="example state comparison a-to-b"),
            make_record("sealed", b_1),
        ],
    )

    # ok-032 retired 0.4 method value "inferred": out-of-vocabulary, fail-closed
    v["ok-032-method-inferred-retired"] = make_statement(
        man_1,
        [make_row("XA-EXAMPLE-1", "no_egress", "artifact", "inferred", "none", [])],
        with_entropy=False,
    )

    # ok-033 artifact-only degraded: recordless parent for coverage-family rejects
    v["ok-033-artifact-degraded"] = make_statement(
        man_ab,
        [make_row("XA-EXAMPLE-1", "no_egress", "artifact", "reconstructed", "none", [])],
        assessed=["XA"],
        out_of_scope={"XB": "example: class not assessed in this run"},
        with_entropy=False,
    )

    # ok-034 arming payload carrying the optional run-chaining members in
    # genesis form: aeeRunSeq 1, aeeChainScope present, no aeePrevRunBinding.
    # The members are syntax-checked in the reserved-member walk and nothing
    # else normative reads them, so the record still covers.
    v["ok-034-arming-chain-genesis"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[
            make_record(
                "arming",
                b_1,
                extra={
                    "aeeRunSeq": 1,
                    "aeeChainScope": ["subject"],
                },
            ),
            make_record("sealed", b_1),
        ],
    )

    # ok-035 an unknown-kind record signed aeeMethod "reconstructed", REFERENCED
    # by a clean intercepted row. An unrecognized aeeKind covers nothing and is
    # OTHERWISE IGNORED (spec:req-fields-arming-record-s-payload-additionally-2@5a96403832635f13):
    # it neither invalidates the row (the
    # arming+sealed cover satisfies class-match) nor participates in the method
    # cap, which reads only COVERING records
    # (spec:req-fields-observationrefs-non-empty-index-range@03ce53b6ce12e42c). A rail that folded
    # the ignored record's weaker aeeMethod into the cap would wrongly flag
    # method-cap-exceeded; this locks the exclusion. Distinct from ok-013, whose
    # unknown record is unreferenced and intercepted, so its cap is never tested.
    v["ok-035-unknown-kind-excluded-from-cap"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1, 2]
            )
        ],
        records=[
            make_record("arming", b_1),
            make_record("sealed", b_1),
            make_record(
                "aee-future-x",
                b_1,
                method="reconstructed",
                note="example unknown-kind record signed reconstructed",
            ),
        ],
    )

    # ok-036 a covering payload nested exactly TO the bound: a producer member
    # whose deepest open container sits at open-container depth 128, one inside the
    # normative maximum, with a scalar leaf. Valid, and the discriminating twin of
    # the reject vectors bad-741/bad-742: it is the one depth the corpus otherwise
    # never touches, and the depth where a per-parsed-value counter and a per-open-
    # container counter can disagree. A rail that mistakenly rejects AT the bound (an
    # over-tightened fix) fails here, while both a correct counter and a buggy
    # empty-container counter accept it -- so it pins "128 is accepted" independently
    # of the empty-container reject.
    _deep: Any = 1
    for _ in range(127):  # payload depth 1 + 127 wrapping objects => deepest container at depth 128
        _deep = {"a": _deep}
    v["ok-036-payload-nesting-at-bound"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[make_record("arming", b_1, extra={"aaDeep": _deep}), make_record("sealed", b_1)],
    )

    # ok-038 issuedAt spelled with the negative zero offset. The timestamp
    # profile admits `Z`, `+00:00` and `-00:00` and nothing else, and `-00:00`
    # is the member of that set no prose named before the profile was written,
    # so every rail accepted it without a rule and none of them recorded that it
    # had. RFC 3339 section 4.3 gives `-00:00` the meaning that the instant in
    # UTC is known while the offset to local time is not, which says nothing
    # about the instant, and the instant is all the predicate reads. Same
    # instant as ok-007, so the only variable is the spelling: a rail that reads
    # "zero offset" as "Z or +00:00 only" is silently stricter than its peers
    # and fails here rather than at a third party.
    v["ok-038-issuedat-negative-zero-offset"] = make_statement(
        man_1,
        [make_row("XA-EXAMPLE-1", "no_egress", "artifact", "reconstructed", "none", [])],
        with_entropy=False,
        predicate_extra={"issuedAt": "2026-01-01T00:00:00-00:00"},
    )

    # ok-039 the same spelling on armedAt, inside a substrate-signed payload.
    # The record is re-signed and the batch root recomputed over it, so the only
    # fault under test is the zone spelling; the arming record must still cover
    # the clean row and the statement must still recompute to pass.
    v["ok-039-armedat-negative-zero-offset"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[
            make_record("arming", b_1, extra={"armedAt": "2025-12-31T23:59:00-00:00"}),
            make_record("sealed", b_1),
        ],
    )

    # ok-040 .. ok-042 the three registered postures the corpus otherwise never
    # carries. Every other vector in this suite says "sinkhole", so the closed
    # posture registry was untested by construction: a rail that admitted only
    # the one string the corpus happens to use passed all 165 vectors of
    # suiteRevision 11, and so
    # did a rail that admitted any string at all. These three are byte-identical
    # to ok-002 apart from the posture string and everything that string moves,
    # which is now the run binding as well, since version 2 of the binding
    # covers the carried posture object. Their pinned digest member is
    # unchanged, so the arming and sealed cover conditions still compare equal
    # and the posture string is the only variable.
    for _slug, _posture in (
        ("ok-040-posture-no-network", "no_network"),
        ("ok-041-posture-allowlist", "allowlist"),
        ("ok-042-posture-unsafe-bypass-egress", "unsafe_bypass_egress"),
    ):
        _obj = {"posture": _posture, "digest": {"sha256": POSTURE_DIGEST}}
        _b = run_binding(sha256_hex(jcs(man_1)), posture=_obj)
        v[_slug] = make_statement(
            man_1,
            [
                make_row(
                    "XA-EXAMPLE-1",
                    "no_egress",
                    "substrate",
                    "intercepted",
                    "none",
                    [0, 1],
                )
            ],
            records=[make_record("arming", _b), make_record("sealed", _b)],
            posture=_obj,
        )

    # ok-043 the accept half of the extension pair. A producer carries an extra
    # member inside networkPosture, and the records commit to the posture object
    # that member is part of, so the statement verifies. The reject twin
    # (bad-307) carries the same extra member with records that do not commit to
    # it, which is what a member added AFTER the arming record was signed looks
    # like on the wire. Together they state the consequence the binding change
    # makes normative: the object the binding covers is the carried one, so the
    # posture is not a place to add members casually.
    _posture_extended = {
        "posture": "sinkhole",
        "digest": {"sha256": POSTURE_DIGEST},
        "producerNote": "example posture annotation",
    }
    _b_extended = run_binding(sha256_hex(jcs(man_1)), posture=_posture_extended)
    v["ok-043-posture-producer-member-bound"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[
            make_record("arming", _b_extended),
            make_record("sealed", _b_extended),
        ],
        posture=_posture_extended,
    )

    # ok-044 the shape the artifact downgrade produces, and the one pairing the
    # closed vocabularies permit that nothing in this suite exercised: a clean
    # row that is indirect in VANTAGE while claiming a live method. It carries
    # no substrate row, so it carries no records, no batch root and no run
    # entropy, and it is well formed without them. Its result is pass_indirect
    # rather than pass, which is the whole of the control: the party that holds
    # the enclosing envelope key and not the observation key can still write
    # this statement, and it no longer reads at the top of the ordering.
    v["ok-044-clean-artifact-intercepted-indirect"] = make_statement(
        man_1,
        [make_row("XA-EXAMPLE-1", "no_egress", "artifact", "intercepted", "none", [])],
        with_entropy=False,
    )

    # ok-045 pins the quantifier. The rule fires on SOME clean row, never on
    # every one, so a statement whose first clean row is a live interception
    # covered by its arming and sealed records is still pass_indirect once a
    # second clean row rests on the artifact's own account. Read the other way,
    # this is what stops a producer from burying an indirect row behind a direct
    # one and keeping the top token.
    v["ok-045-mixed-clean-rows-indirect"] = make_statement(
        man_ab,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            ),
            make_row("XB-EXAMPLE-1", "no_egress", "artifact", "reconstructed", "none", []),
        ],
        records=[
            make_record("arming", b_ab),
            make_record("sealed", b_ab),
        ],
    )

    # ok-900 the composition law that decides every mixed run, which nothing
    # here exercised: a caught row forcing `fail` in the same statement as a
    # disclosed coverage gap forcing `degraded`. The recompute takes the
    # minimum, so the carried token is `fail`. Measured rather than argued: a
    # mutation dropping `degraded` below `fail` in the rail's result ordering
    # was invisible to the whole corpus, because no vector carried both halves
    # at once and a rail that ranked them the wrong way round reported the
    # softer verdict on every mixed run and still passed.
    v["ok-900-fail-outranks-degraded"] = make_statement(
        man_ab,
        [
            make_row(
                "XA-EXAMPLE-1", "egress_captured", "artifact", "reconstructed", "none", []
            )
        ],
        assessed=["XA"],
        out_of_scope={"XB": "example: class not assessed in this run"},
        with_entropy=False,
    )

    # ok-901 a row carrying no `basis` at all. Absence is not a value, so the
    # row cannot be classified and fail-closes exactly as an out-of-vocabulary
    # one does; the statement stays VALID and carries `fail`. Recordless and
    # artifact-shaped, so nothing cascades. The rail's basis branch had no
    # vector behind it in either direction: removing it is a panic rather than a
    # wrong answer, and nothing in the corpus reached it.
    v["ok-901-row-missing-basis"] = make_statement(
        man_1,
        [make_row("XA-EXAMPLE-1", "no_egress", None, "reconstructed", "none", [])],
        with_entropy=False,
    )

    # ok-046 pins the DIRECTION of the seal's attack set, and it is the vector
    # that stops a rail from reading a lower bound as an equality. The run
    # caught two attacks and the seal names one of them. A seal naming an
    # attack obliges a caught row for it; a seal OMITTING one licenses nothing,
    # because an observation the substrate could not attribute subtracts from
    # what the seal claims and can never add a claim that is false. Without
    # this vector a rail demanding the sets match passes the whole corpus.
    v["ok-046-seal-attacks-lower-bound"] = make_statement(
        man_2,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0],
            ),
            make_row(
                "XA-EXAMPLE-2",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [1],
            ),
        ],
        records=[
            make_record("interception", b_2, note="example interception observation a"),
            make_record("interception", b_2, note="example interception observation b"),
            make_record("sealed", b_2, observed_attacks=["XA-EXAMPLE-1"]),
        ],
    )

    # ok-047 the satisfied form of the stronger attribution, in all three of its
    # parts at once: the row resolves an interception, the manifest declares an
    # expectation for the row's attack, and the record it resolves carries a
    # value from that entry. The corpus needs this beside the three refusals
    # below it, because a rail that rejects every `pinned` row satisfies each
    # refusal and is wrong.
    man_pin = {
        "classes": {"XA": ["XA-EXAMPLE-1"]},
        "expectedPayloads": {
            "XA-EXAMPLE-1": [commitment_for("example interception observation a")]
        },
    }
    b_pin = run_binding(sha256_hex(jcs(man_pin)))
    v["ok-047-attribution-pinned"] = make_statement(
        man_pin,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0],
                attribution="pinned",
            )
        ],
        records=[
            make_record(
                "interception", b_pin, note="example interception observation a"
            ),
            make_record("sealed", b_pin),
        ],
    )

    # ok-048 `paired` is a floor rather than a confession. The corpus declares
    # an expectation for this attack and the record carries the matching value,
    # so the producer COULD have declared `pinned` truthfully and did not. That
    # is permitted: what a consumer learns from `paired` is that this row does
    # not carry the stronger binding, never that the producer had one and
    # withheld it. A rail that infers the stronger value from the corpus, or
    # that refuses a truthful weaker one, fails here and nowhere else.
    v["ok-048-attribution-paired-despite-expectation"] = make_statement(
        man_pin,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0],
            )
        ],
        records=[
            make_record(
                "interception", b_pin, note="example interception observation a"
            ),
            make_record("sealed", b_pin),
        ],
    )

    # ok-049 the satisfied form of the seal's attack obligation: the seal names
    # an attack and the statement carries a caught row for it. ok-046 pins that
    # the rule does not fire on omission; this pins that it is a rule at all,
    # rather than a member nothing reads.
    v["ok-049-seal-names-caught-attack"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0],
            )
        ],
        records=[
            make_record("interception", b_1, note="example interception observation a"),
            make_record("sealed", b_1, observed_attacks=["XA-EXAMPLE-1"]),
        ],
    )

    # ok-050 the two kinds the document registers as non-covering, referenced by
    # a clean intercepted row and signed with the weaker aeeMethod. Both cover
    # nothing in every state, so the row is covered by the arming and sealed
    # pair beside them; neither participates in the method cap, which reads only
    # COVERING records; neither enters the seal's aeeObservedSet, which is
    # defined over interception and examination records alone; and neither is
    # owed a caught row, which only an interception is. Every leaf is still in
    # the batch root.
    #
    # Distinct from ok-035, whose record carries a kind no version registers. A
    # rail that gave either of these names covering semantics -- the reading a
    # producer emitting them invites, since both describe something real that
    # happened -- passes ok-035 and fails here.
    v["ok-050-registered-noncovering-kinds"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "no_egress",
                "substrate",
                "intercepted",
                "none",
                [0, 1, 2, 3],
            )
        ],
        records=[
            make_record("arming", b_1),
            make_record("sealed", b_1),
            make_record(
                "moat-drop",
                b_1,
                method="reconstructed",
                note="example containment-layer drop the substrate observed",
            ),
            make_record(
                "uncommitted-observation",
                b_1,
                method="reconstructed",
                note="example run-bound observation carrying no commitment",
            ),
        ],
    )

    # ok-051 two rows declaring the stronger attribution at once, each resolving
    # its OWN interception, whose committed value the manifest declared for that
    # row's attack. Every pinned vector before this one carries a single row, and
    # permuting one row is the identity, so the corpus could not reach the arm
    # where the rule decides which record belongs to which attack: the kill was
    # proven against a statement built outside the corpus and no vendored copy
    # was measured against it. bad-982 is this statement with the assignment
    # exchanged and nothing else touched.
    #
    # The two attacks sit in different coverage classes deliberately. A consumer
    # policy keyed on attack class is the cheapest example of one that reads the
    # assignment, so the splice below is a permutation a policy would act on
    # rather than a relabelling nothing consumes.
    man_pin2 = {
        "classes": {"XA": ["XA-EXAMPLE-1"], "XB": ["XB-EXAMPLE-1"]},
        "expectedPayloads": {
            "XA-EXAMPLE-1": [commitment_for("example interception observation a")],
            "XB-EXAMPLE-1": [commitment_for("example interception observation b")],
        },
    }
    b_pin2 = run_binding(sha256_hex(jcs(man_pin2)))
    v["ok-051-two-pinned-rows"] = make_statement(
        man_pin2,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0],
                attribution="pinned",
            ),
            make_row(
                "XB-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [1],
                attribution="pinned",
            ),
        ],
        records=[
            make_record(
                "interception", b_pin2, note="example interception observation a"
            ),
            make_record(
                "interception", b_pin2, note="example interception observation b"
            ),
            make_record("sealed", b_pin2),
        ],
    )

    # ok-055 one pinned row resolving TWO interceptions, both predicted.
    #
    # The third part of the pinned rule is quantified over EVERY interception a
    # row resolves, and until this vector the corpus never handed it more than
    # one. Every pinned row this corpus shipped -- 23 of them -- resolved exactly
    # one interception record, and a universal quantifier evaluated only at
    # cardinality one is indistinguishable from an existential: a rail that
    # compares the first resolved interception and stops passes the entire
    # corpus. This is the accept side of that boundary -- a row with two probes
    # planted against one attack, the corpus predicting both, and the substrate
    # committing to both -- and `bad-986` is this statement with the second
    # commitment replaced by the OTHER attack's declared value and nothing else
    # touched.
    #
    # Two values under one attack rather than two attacks, because the point is
    # the quantifier inside a single row. XB is carried alongside so that the
    # refusal derived from this vector has a value the corpus genuinely declared
    # for a DIFFERENT attack to reach for: a commitment the corpus declared
    # nowhere is already `bad-960`, and it is the weaker case. A statement whose
    # evidence corresponds to a real, declared, other attack is the one a rail
    # reading the quantifier existentially calls conformant.
    exp_multi = sorted(
        [
            commitment_for("example interception observation a"),
            commitment_for("example interception observation a2"),
        ]
    )
    man_pin_multi = {
        "classes": {"XA": ["XA-EXAMPLE-1"], "XB": ["XB-EXAMPLE-1"]},
        "expectedPayloads": {
            "XA-EXAMPLE-1": exp_multi,
            "XB-EXAMPLE-1": [commitment_for("example interception observation b")],
        },
    }
    b_pin_multi = run_binding(sha256_hex(jcs(man_pin_multi)))
    v["ok-055-pinned-row-two-interceptions"] = make_statement(
        man_pin_multi,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0, 1],
                attribution="pinned",
            ),
            make_row(
                "XB-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [2],
                attribution="pinned",
            ),
        ],
        records=[
            make_record(
                "interception", b_pin_multi, note="example interception observation a"
            ),
            make_record(
                "interception", b_pin_multi, note="example interception observation a2"
            ),
            make_record(
                "interception", b_pin_multi, note="example interception observation b"
            ),
            make_record("sealed", b_pin_multi),
        ],
    )

    # ok-052 / ok-053 detector liveness, as a construction over carried bytes.
    #
    # A detector that never fires is indistinguishable from outside from a
    # boundary nothing ever reached: both emit a clean run. The only way to
    # separate them is to plant something the detector MUST catch and then
    # check, from the bytes, that it did. Every member that construction needs
    # is already normative at this version and no new one is added here:
    # `classes` says which attack belongs to which channel,
    # `expectedPayloads` is the planted stimulus -- the value a corpus author
    # computed in advance for what that attack looks like on the wire --
    # `aeePayloadCommitment` on the interception is what the substrate actually
    # committed to, `attribution: pinned` is the row asserting the two are
    # comparable, and `aeeObservedAttacks` on the run-end seal is the
    # substrate's own signed list of what it attributed. A channel is
    # demonstrated live when all five line up for at least one attack in it.
    #
    # The claim is strictly per channel. A probe caught on the egress channel
    # says nothing whatever about the channel next to it, so a corpus that
    # plants one probe and reports a live detector is measuring a sample and
    # calling it a census. THREE channels here rather than two, because a rail
    # that evaluates the first and the last passes a two-channel statement
    # while skipping everything between.
    man_live = {
        "classes": {
            "XA": ["XA-EXAMPLE-1"],
            "XB": ["XB-EXAMPLE-1"],
            "XC": ["XC-EXAMPLE-1"],
        },
        "expectedPayloads": {
            "XA-EXAMPLE-1": [commitment_for("example planted probe channel a")],
            "XB-EXAMPLE-1": [commitment_for("example planted probe channel b")],
            "XC-EXAMPLE-1": [commitment_for("example planted probe channel c")],
        },
    }
    b_live = run_binding(sha256_hex(jcs(man_live)))

    def probe_row(attack: str, ref: int) -> dict[str, Any]:
        return make_row(
            attack,
            "egress_captured",
            "substrate",
            "intercepted",
            "policy.egress_sinkhole",
            [ref],
            attribution="pinned",
        )

    # ok-052 the satisfied form on every claimed channel at once: three planted
    # probes, three caught rows carrying the stronger attribution, three
    # interceptions each committing to the value its own channel's probe was
    # predicted to produce, and a seal naming all three. This is the accept
    # anchor the three refusals below it are measured against: a rail that
    # rejects any statement declaring `pinned` on more than one channel, or
    # that stops checking after the first satisfied row, satisfies every one of
    # those refusals and is wrong.
    v["ok-052-liveness-probe-per-channel"] = make_statement(
        man_live,
        [
            probe_row("XA-EXAMPLE-1", 0),
            probe_row("XB-EXAMPLE-1", 1),
            probe_row("XC-EXAMPLE-1", 2),
        ],
        records=[
            make_record(
                "interception", b_live, note="example planted probe channel a"
            ),
            make_record(
                "interception", b_live, note="example planted probe channel b"
            ),
            make_record(
                "interception", b_live, note="example planted probe channel c"
            ),
            make_record(
                "sealed",
                b_live,
                observed_attacks=[
                    "XA-EXAMPLE-1",
                    "XB-EXAMPLE-1",
                    "XC-EXAMPLE-1",
                ],
            ),
        ],
    )

    # ok-053 the same three planted probes and the same corpus, and the middle
    # channel's probe produced no interception at all: its row is clean, its
    # attribution is the honest floor, and the seal names the two channels the
    # substrate did attribute and not the third.
    #
    # This statement MUST be accepted, and that is the whole point of shipping
    # it. Liveness is not a validity requirement at this version and this
    # vector is what stops a rail from quietly making it one -- a producer
    # whose detector genuinely did not fire on one channel emits exactly these
    # bytes, and refusing them refuses the honest report along with the
    # dishonest one. What the format does instead is make the difference
    # legible: the three probes are declared, the seal names two, and the gap
    # between those sets is the one channel this run cannot show a live
    # detector for. A consumer that demands per-channel liveness reads that gap
    # and declines the run under its own policy; nothing here decides it for
    # them. `scripts/liveness-probe.py` computes exactly that comparison.
    v["ok-053-liveness-probe-uncaught-on-one-channel"] = make_statement(
        man_live,
        [
            probe_row("XA-EXAMPLE-1", 0),
            make_row(
                "XB-EXAMPLE-1",
                "no_egress",
                "substrate",
                "intercepted",
                "none",
                [2, 3],
            ),
            probe_row("XC-EXAMPLE-1", 1),
        ],
        records=[
            make_record(
                "interception", b_live, note="example planted probe channel a"
            ),
            make_record(
                "interception", b_live, note="example planted probe channel c"
            ),
            make_record("arming", b_live),
            make_record(
                "sealed",
                b_live,
                observed_attacks=["XA-EXAMPLE-1", "XC-EXAMPLE-1"],
            ),
        ],
    )

    # ok-054 producer territory is inert even when it is ORDERED. ok-021
    # already carries producer members in a covering payload, but its values
    # are content-free strings: nothing about them invites a verifier to rank
    # them, so it forces only the half of the rule that says such a member
    # does not stop the record covering. The half nobody could reach is the
    # one the document names as the tempting case -- a member whose values a
    # reader might order, carrying a token this predicate itself orders. A
    # verifier that folds it into the weakest-input composition caps the row
    # at `reconstructed` and refuses a statement no requirement refuses. The
    # signed `aeeMethod` on the same record says `intercepted`, so the two
    # readings differ on this statement and on nothing else in the corpus.
    v["ok-054-producer-ordered-axis-inert"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1",
                "egress_captured",
                "substrate",
                "intercepted",
                "policy.egress_sinkhole",
                [0],
            )
        ],
        records=[
            make_record(
                "interception",
                b_1,
                note="example interception observation a",
                extra={"exampleFidelity": "reconstructed"},
            ),
            make_record("sealed", b_1),
        ],
    )

    # -----------------------------------------------------------------------
    # vate-* : what this predicate deliberately does NOT read across an
    # external admission boundary.
    #
    # Provenance, stated once and carried in accept/INDEX.md and
    # reject/INDEX.md beside every one of these vectors. They were prompted by
    # three conformance cases from the Verifiable Agent Trust Envelope (VATE)
    # discussion draft, read at VATE commit
    # ce00121d7bd658c7a1fcd861b386ea9ea7ce66be, corpus
    # VATE-AL2-Verifier-Admission-v0.3, corpus digest
    # sha-256:0eb1969ea3763e0fec123de5ea0dacb225eb48a28d76866bbec56dc61d16cf8f:
    #
    #   post-execution-admission-digest-mismatch                  -> vate-1*
    #   post-execution-effective-constraints-aggregate-exceeded   -> vate-2*
    #   post-execution-runtime-mismatch                           -> vate-3*
    #
    # These are AEE-native boundary vectors prompted by those cases. They are
    # NOT VATE conformance results, they carry no VATE verdict, and no vector
    # here is evidence about any VATE implementation. Every expectation below
    # is this predicate's own, decided by this suite's own rails.
    #
    # The accepts are the load-bearing half. Each carries exactly the fault its
    # case is about and is VALID anyway, because the recompute reads the rows,
    # the carried vocabulary and the coverage maps and nothing else. An accept
    # that pins what a predicate declines to read is a negative pin, and it is
    # a more precise statement of a boundary than any sentence.

    # The A-bound shape the whole of case 1 is built on: admission receipt A in
    # the sole subject slot, with the run binding derived over A and every
    # record signed under that binding. vate-1d ships it unchanged, vate-1b
    # carries receipt B's digest beside it in producer territory, and the
    # reject-side vate-1a substitutes B for A in the subject and leaves the
    # A-bound records exactly as the producer signed them. Deriving all three
    # from one shape is what makes the pair a receipt-against-receipt relation
    # rather than an artifact-against-receipt one: the pinned VATE case hashes
    # a referenced admission receipt and compares it with the admission digest
    # a post-execution receipt asserts, and both objects in that comparison are
    # admission receipts.
    b_receipt_a = run_binding(sha256_hex(jcs(man_1)), subject=RECEIPT_A_DIGEST)

    def receipt_a_subject() -> dict[str, Any]:
        # A fresh object per call. make_statement puts the descriptor straight
        # into the statement it builds, so a shared literal would alias two
        # statements through one nested digest dict.
        return {"name": RECEIPT_A_NAME, "digest": {"sha256": RECEIPT_A_DIGEST}}

    # vate-1b receipt A is the sole subject and every record is correctly bound
    # and signed for A, while the arming payload carries receipt B's admission
    # digest and the reference that names B. The two admission identities
    # disagree and the statement is valid and recomputes pass, because AEE
    # never performs that comparison: the carried digest and reference are
    # producer vocabulary inside a covering payload, and the subject is read
    # only as a binding input.
    v["vate-1b-carried-admission-digest-unread"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[
            make_record(
                "arming",
                b_receipt_a,
                extra={
                    "vateAdmissionDigest": RECEIPT_B_DIGEST,
                    "vateAdmissionRef": "urn:example:vate:admission-receipt/b",
                },
            ),
            make_record("sealed", b_receipt_a),
        ],
        subject=receipt_a_subject(),
    )

    # vate-1d the price of the case-1 anti-splice, paid in full. Admission
    # receipt A is the SOLE subject, so the binding genuinely covers the
    # admission identity and a record signed under receipt A cannot be
    # presented under receipt B (that is vate-1a). The predicate requires
    # exactly one subject entry, and the binding reads only the first, so
    # buying that anti-splice DISPLACES the executed artifact rather than
    # adding to it: this statement is valid, recomputes pass, and names no
    # executed artifact anywhere. A consumer learns which admission the run
    # happened under and cannot learn what was run.
    v["vate-1d-admission-receipt-as-sole-subject"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[
            make_record("arming", b_receipt_a),
            make_record("sealed", b_receipt_a),
        ],
        subject=receipt_a_subject(),
    )

    # vate-2a two clean rows whose carried side-effect amounts are each below
    # the carried maximum and whose total exceeds it. No row carries a
    # quantity, the composition law is a minimum over three booleans, and there
    # is nothing to aggregate: valid, pass. The amounts travel on ONE arming
    # record rather than two, because two records with identical payloads are
    # duplicates and would be refused before the statement could say anything
    # about aggregation.
    v["vate-2a-aggregate-overrun-unread"] = make_statement(
        man_2,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            ),
            make_row(
                "XA-EXAMPLE-2", "no_egress", "substrate", "intercepted", "none", [0, 1]
            ),
        ],
        records=[
            make_record(
                "arming",
                b_2,
                extra={
                    "vateEffectiveMaxAmount": {"currency": "USD", "value": "100.00"},
                    "vateSideEffectAmounts": [
                        {"currency": "USD", "value": "60.00"},
                        {"currency": "USD", "value": "60.00"},
                    ],
                },
            ),
            make_record("sealed", b_2),
        ],
    )

    # vate-3b an admitted runtime and an observed runtime that differ, declared
    # side by side on the arming record. A statement carries exactly one
    # observationEnvironment, so there is no second runtime for any rule to
    # compare against, and both members are producer vocabulary. Valid, pass.
    v["vate-3b-admitted-vs-observed-runtime-unread"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[
            make_record(
                "arming",
                b_1,
                extra={
                    "vateAdmittedRuntime": "urn:example:runtime/admitted-image@v1",
                    "vateObservedRuntime": "urn:example:runtime/observed-image@v2",
                },
            ),
            make_record("sealed", b_1),
        ],
    )

    # vate-3c the vector that bounds vate-1a and vate-3a, and the reason it is
    # here is that it refutes the strongest reading of both. The whole run is
    # re-bound to the substituted substrate digest and re-signed: the binding
    # is recomputed over the second observation substrate and every record is
    # signed under the published substrate-observation test key. Nothing is
    # spliced, so nothing is detected, and the statement is valid and
    # recomputes pass. The binding is anti-splice and explicitly not
    # anti-forge, so vate-1a and vate-3a establish that records were not MOVED,
    # never that the identity they name is the true one. That separation
    # belongs to the substrate key and the evidence tier.
    b_other_substrate = run_binding(
        sha256_hex(jcs(man_1)), substrate=SECOND_SUBSTRATE_DIGEST
    )
    v["vate-3c-substrate-substituted-and-resigned"] = make_statement(
        man_1,
        [
            make_row(
                "XA-EXAMPLE-1", "no_egress", "substrate", "intercepted", "none", [0, 1]
            )
        ],
        records=[
            make_record("arming", b_other_substrate),
            make_record("sealed", b_other_substrate),
        ],
        substrate={
            "name": "example-substrate-image",
            "digest": {"sha256": SECOND_SUBSTRATE_DIGEST},
        },
    )

    return v


# ---------------------------------------------------------------------------
# independent-ish self-verifier (mirrors the spec's gates; asserts every
# vector is VALID and its carried result recomputes)
# ---------------------------------------------------------------------------

METHOD_RANK = {"reconstructed": 1, "intercepted": 2}


def verify(stmt: dict[str, Any]) -> list[str]:  # noqa: C901 -- mirrors the full spec gate logic; see docs/complexity-rationales.toml
    errs: list[str] = []
    pred = stmt["predicate"]
    env = pred["observationEnvironment"]
    vocab = env["observationVocabulary"]
    labels, caught = vocab["labels"], vocab["caught"]

    # the closed posture registry
    if env["networkPosture"].get("posture") not in EGRESS_POSTURES:
        errs.append("posture not in the closed registry")

    # vocabulary shape + digest
    if sorted(labels) != labels or sorted(caught) != caught:
        errs.append("vocab not sorted")
    if not set(caught) <= set(labels):
        errs.append("caught not subset")
    if vocab["digest"]["sha256"] != sha256_hex(
        jcs({"caught": caught, "labels": labels})
    ):
        errs.append("vocab digest mismatch")
    # corpus digest
    if env["corpus"]["digest"]["sha256"] != sha256_hex(jcs(env["corpus"]["manifest"])):
        errs.append("corpus digest mismatch")

    rows = pred["attackResults"]
    records = pred.get("observationRecords", [])
    substrate_rows = [r for r in rows if r.get("basis") == "substrate"]

    # batchRoot
    if records:
        leaves = [pae(r["payloadType"], base64.b64decode(r["payload"])) for r in records]
        if len(set(leaves)) != len(leaves):
            errs.append("duplicate record")
        if pred.get("batchRoot") != rfc6962_root(leaves):
            errs.append("batchRoot mismatch")
    elif "batchRoot" in pred:
        errs.append("orphan batchRoot")

    # run binding (derivable only for substrate-carrying statements)
    binding = None
    if substrate_rows:
        if "runEntropy" not in env:
            errs.append("runEntropy missing")
        else:
            binding = sha256_hex(
                jcs(
                    {
                        "aeeBindingVersion": "2",
                        "catchPolicy": env["catchPolicy"]["digest"]["sha256"],
                        "corpus": env["corpus"]["digest"]["sha256"],
                        "networkPosture": sha256_hex(jcs(env["networkPosture"])),
                        "observationVocabulary": vocab["digest"]["sha256"],
                        "runEntropy": env["runEntropy"]["digest"]["sha256"],
                        "subject": stmt["subject"][0]["digest"]["sha256"],
                        "substrate": env["substrate"]["digest"]["sha256"],
                    }
                )
            )

    def payload_of(i: int) -> Any:
        raw = base64.b64decode(records[i]["payload"])
        obj = json.loads(raw)
        if jcs(obj) != raw:
            errs.append(f"record {i} payload not canonical")
        return obj

    for r in substrate_rows:
        refs = r.get("observationRefs")
        if not refs:
            errs.append(f"row {r['attackId']}: empty refs")
            continue
        if any(not isinstance(i, int) or i < 0 or i >= len(records) for i in refs):
            errs.append(f"row {r['attackId']}: ref out of range")
            continue
        payloads = {i: payload_of(i) for i in refs}
        for i, p in payloads.items():
            for m in ("aeeRunBinding", "aeeKind", "aeeMethod"):
                if m not in p:
                    errs.append(f"record {i}: missing {m}")
            if binding is not None and p.get("aeeRunBinding") != binding:
                errs.append(f"record {i}: run binding mismatch")
            if not records[i]["payloadType"].endswith("+json"):
                errs.append(f"record {i}: media type")

        kinds = {i: payloads[i].get("aeeKind") for i in refs}
        lab = r.get("containmentObserved")
        is_caught = lab in caught
        is_clean = lab in labels and lab not in caught
        meth = r.get("method")

        def chain_ok(p: dict[str, Any]) -> bool:
            # Optional run-chaining member syntax: positive integer aeeRunSeq
            # with an aeeChainScope that is a duplicate-free array of tokens
            # from the closed vocabulary {subject, corpus, networkPosture},
            # sorted in canonical (UTF-16 code-unit) order; aeePrevRunBinding
            # (lowercase 64-hex) present exactly when aeeRunSeq exceeds 1.
            chain_vocab = {"subject", "corpus", "networkPosture"}
            if "aeeRunSeq" not in p:
                return "aeePrevRunBinding" not in p and "aeeChainScope" not in p
            seq = p.get("aeeRunSeq")
            if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
                return False
            scope = p.get("aeeChainScope")
            if not isinstance(scope, list):
                return False
            if any(tok not in chain_vocab for tok in scope):
                return False
            if scope != sorted(scope) or len(set(scope)) != len(scope):
                return False
            if seq == 1:
                return "aeePrevRunBinding" not in p
            prev = p.get("aeePrevRunBinding")
            return isinstance(prev, str) and len(prev) == 64 and all(
                c in "0123456789abcdef" for c in prev
            )

        def arming_ok(p: dict[str, Any]) -> bool:
            return (
                p.get("armedAt") is not None
                and p.get("armedAt") <= pred["issuedAt"]
                and p.get("aeePostureDigest") == env["networkPosture"]["digest"]["sha256"]
                and p.get("aeeMethod") == "intercepted"
                and chain_ok(p)
            )

        def sealed_ok(p: dict[str, Any]) -> bool:
            dc = p.get("aeeDropCount")
            bound_ok = dc == 0 or (
                isinstance(p.get("aeeDropBound"), int) and dc <= p["aeeDropBound"]
            )
            return (
                p.get("aeeStillArmed") is True
                and isinstance(dc, int)
                and bound_ok
                and p.get("aeePostureDigest") == env["networkPosture"]["digest"]["sha256"]
                and p.get("aeeMethod") == "intercepted"
            )

        if meth == "reconstructed":
            if not any(kinds[i] == "examination" for i in refs):
                errs.append(f"row {r['attackId']}: no examination cover")
        elif meth == "intercepted":
            if is_caught and not any(kinds[i] == "interception" for i in refs):
                errs.append(f"row {r['attackId']}: no interception cover")
            if is_clean:
                if not any(
                    kinds[i] == "arming" and arming_ok(payloads[i]) for i in refs
                ):
                    errs.append(f"row {r['attackId']}: no covering arming")
                if not any(
                    kinds[i] == "sealed" and sealed_ok(payloads[i]) for i in refs
                ):
                    errs.append(f"row {r['attackId']}: no covering sealed")

        # method cap: row no stronger than weakest signed aeeMethod across refs
        ranks = [
            METHOD_RANK.get(payloads[i].get("aeeMethod"), 0)
            for i in refs
            if kinds[i] in ("interception", "arming", "sealed", "examination")
        ]
        if ranks and METHOD_RANK.get(meth, 0) > min(ranks):
            errs.append(f"row {r['attackId']}: method cap exceeded")

    # result recompute, re-derived here rather than reused from the builder, so
    # the self-check is a second reading of the rule and not an echo of the first
    def _forced(r: dict[str, Any]) -> bool:
        return (
            r.get("containmentObserved") in caught
            or r.get("containmentObserved") not in labels
            or r.get("basis") not in ("substrate", "artifact")
            or r.get("method") not in ("intercepted", "reconstructed")
        )

    forced = any(_forced(r) for r in rows)
    indirect = any(
        not _forced(r)
        and (r.get("basis") != "substrate" or r.get("method") != "intercepted")
        for r in rows
    )
    cov = pred["coverage"]
    expect = min(
        [
            "fail" if forced else "pass",
            "degraded" if (cov["outOfScope"] or cov["routedElsewhere"]) else "pass",
            "pass_indirect" if indirect else "pass",
        ],
        key=RESULT_ORDER.__getitem__,
    )
    if pred["result"] != expect:
        errs.append(f"result recompute {expect} != carried {pred['result']}")

    # coverage integrity at attack granularity
    manifest = env["corpus"]["manifest"]["classes"]
    by_class: dict[str, set[str]] = {}
    for r in rows:
        cls = next((c for c, ids in manifest.items() if r["attackId"] in ids), None)
        if cls is None:
            errs.append(f"row attack {r['attackId']} not in manifest")
        else:
            by_class.setdefault(cls, set()).add(r["attackId"])
    for c in cov["assessedClasses"]:
        if by_class.get(c, set()) != set(manifest.get(c, [])):
            errs.append(f"class {c}: coverage incomplete")
    for c in list(cov["outOfScope"]) + list(cov["routedElsewhere"]):
        if c in by_class:
            errs.append(f"class {c}: rows present for non-assessed class")

    errs.extend(verify_commitments(pred, set(labels), set(caught)))
    return errs


def verify_commitments(  # noqa: C901 -- one branch per independent requirement; see docs/complexity-rationales.toml
    pred: dict[str, Any],
    labels: set[str],
    caught: set[str],
) -> list[str]:
    """The coverage validity requirements this version adds, read a SECOND time.

    Every one of them is already satisfied by construction, which is exactly why
    it is asserted here: a builder and a checker that share a derivation share
    its mistakes, so this reads the finished statement rather than the inputs it
    was assembled from. Nine accept vectors and one whole record set moved when
    these requirements landed, and nothing in this file could see any of it.
    """
    errs: list[str] = []
    rows = pred["attackResults"]
    records = pred.get("observationRecords") or []
    payloads = [json.loads(base64.b64decode(r["payload"])) for r in records]
    kinds = [pl.get("aeeKind") for pl in payloads]
    env = pred["observationEnvironment"]
    classes = env["corpus"]["manifest"]["classes"]
    expected = env["corpus"]["manifest"].get("expectedPayloads") or {}
    declared = {a for ids in classes.values() for a in ids}

    def refs_of(r: dict[str, Any]) -> list[int]:
        return [
            i
            for i in (r.get("observationRefs") or [])
            if isinstance(i, int) and 0 <= i < len(records)
        ]

    for r in rows:
        if r.get("attribution") not in ("pinned", "paired"):
            errs.append(f"row {r['attackId']}: attribution is required on every row")
        lab = r.get("containmentObserved")
        if lab in labels and lab not in caught:
            if any(kinds[i] == "interception" for i in refs_of(r)):
                errs.append(f"row {r['attackId']}: a clean row resolves an interception")

    resolved: set[int] = set()
    for r in rows:
        if r.get("containmentObserved") in caught:
            resolved.update(refs_of(r))
    for i, kind in enumerate(kinds):
        if kind == "interception":
            if i not in resolved:
                errs.append(f"record {i}: an interception no caught row resolves")
            values = payloads[i].get("aeePayloadCommitment")
            if not isinstance(values, list) or not values or values != sorted(set(values)):
                errs.append(f"record {i}: aeePayloadCommitment absent or not canonical")

    for r in rows:
        if r.get("attribution") != "pinned":
            continue
        inters = [i for i in refs_of(r) if kinds[i] == "interception"]
        if not inters:
            errs.append(f"row {r['attackId']}: pinned and resolves no interception")
            continue
        want = expected.get(r["attackId"])
        if not want:
            errs.append(f"row {r['attackId']}: pinned with no corpus expectation")
            continue
        for i in inters:
            if not set(payloads[i].get("aeePayloadCommitment") or []) & set(want):
                errs.append(f"row {r['attackId']}: record {i} carries no expected value")

    if not any(r.get("basis") == "substrate" for r in rows):
        return errs

    caught_ids = {r["attackId"] for r in rows if r.get("containmentObserved") in caught}
    assessed = {a for c in pred["coverage"]["assessedClasses"] for a in classes.get(c, [])}
    observed = observed_set_digest(records)
    seals = 0
    for i, kind in enumerate(kinds):
        if kind == "sealed":
            seals += 1
            if payloads[i].get("aeeObservedSet") != observed:
                errs.append(f"record {i}: the seal does not commit to the carried set")
            attacks = payloads[i].get("aeeObservedAttacks")
            if not isinstance(attacks, list) or attacks != sorted(set(attacks)):
                errs.append(f"record {i}: aeeObservedAttacks absent or not canonical")
            elif not set(attacks) <= declared:
                errs.append(f"record {i}: the seal names an undeclared attack")
            elif not set(attacks) <= caught_ids:
                errs.append(f"record {i}: the seal names an attack with no caught row")
        if kind == "arming":
            decl = payloads[i].get("aeeAssessedAttacks")
            if not isinstance(decl, list) or decl != sorted(set(decl)):
                errs.append(f"record {i}: aeeAssessedAttacks absent or not canonical")
            elif not assessed <= set(decl):
                errs.append(f"record {i}: the assessed set exceeds the declaration")
    if seals == 0:
        errs.append("a substrate row and no sealed record")
    return errs


def verify_signatures(stmt: dict[str, Any]) -> dict[int, str]:
    """Tier-plane check (informative): which records verify under which key."""
    out: dict[int, str] = {}
    pubs = {
        "substrate-observation-test": Ed25519PublicKey.from_public_bytes(SUB_PUB),
        "wrong-signer-test": Ed25519PublicKey.from_public_bytes(WRONG_PUB),
    }
    for i, rec in enumerate(stmt["predicate"].get("observationRecords", [])):
        raw = base64.b64decode(rec["payload"])
        signed = pae(rec["payloadType"], raw)
        sig = base64.b64decode(rec["signatures"][0]["sig"])
        for name, pub in pubs.items():
            try:
                pub.verify(sig, signed)
                out[i] = name
                break
            except InvalidSignature:
                continue
        else:
            out[i] = "no-pae-verify"
    return out


def write_build_ids(ids: dict[str, str]) -> None:
    """Record slug -> published identifier for the reject generator to read.

    Written, never committed. See BUILD_IDS above for the measurement that
    decided that.
    """
    BUILD_IDS.parent.mkdir(exist_ok=True)
    BUILD_IDS.write_text(
        json.dumps(ids, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


# The accept index, emitted rather than hand-written.
#
# It used to be authored by hand AND read by vectors/gen_manifest.py to derive
# every accept vector's id, kind, conditions and expectations. That is fine
# while an identifier is something a person chooses, and impossible once it is
# a digest of the vector's own bytes: nobody can write a content digest into a
# markdown table by hand. So the prose moved here, beside the vectors it
# describes, which is where the reject generator has always kept its own.
#
# The prose blocks are carried verbatim, with the predicate type URI templated
# so a re-vendor moves it here too rather than leaving a constant behind in a
# file nobody regenerates.
ACCEPT_INDEX_PREAMBLE: tuple[str, ...] = (
    '# AEE v0.7 conformance vectors: VALID (accept) set',
    '',
    'Each file in this directory is a complete, unwrapped in-toto Statement (no outer '
    'DSSE) for',
    'predicate type `{predicate_type}`',
    'that a conforming verifier MUST accept: the statement is well-formed, every',
    '`basis: substrate` row satisfies the byte-checkable validity gate (refs resolve',
    'and are in range, referenced records class-match, every covering payload is',
    'canonical RFC 8785 / RFC 7493 `+json` carrying the reserved members with',
    '`aeeRunBinding` equal to the binding derived from the statement, row `method`',
    'capped by the weakest signed `aeeMethod`, `batchRoot` recomputes under RFC 6962),',
    'and the carried `result` equals the recompute. Condition ids below are stable',
    '`aee-c-NN` ids; the suite README maps them to spec line ranges at the pinned',
    'spec commit. Verdict for every vector here: **valid**; the per-row evidence tier',
    '(attested / unattested / declared) is trust-relative and never alters validity',
    'or `result`.',
    '',
    'That type URI does not resolve. The in-toto attestation catalog redirects the',
    'URIs of vetted predicates whose specification is merged, and this predicate is',
    'in review as `in-toto/attestation#570`, so a request for the URI returns 404.',
    'The URI identifies the predicate type, and dereferencing it is not part of',
    'verifying any vector here. Read the specification in the copy this repository',
    'carries, at',
    '[`spec/predicates/adversarial-execution-evidence.md`](../../spec/predicates/adversarial-execution-evidence.md).',
    '',
    '## Determinism recipe',
    '',
    'Regenerate the set byte-identically with `python3 gen_valid_vectors.py`',
    '(stdlib + `cryptography`). Committed files are UTF-8, LF, 2-space indent, JCS',
    '(lexicographic) member ordering, standard base64 with padding.',
    '',
    'Signing uses TEST keys (Ed25519/RFC 8032) whose seeds derive from published',
    'constants: `seed(role) = SHA-256("in-toto-aee-test-key/<role>/v1")`. Only the',
    'PUBLIC halves are published, and because the derivation is open, these keys',
    'are TEST-ONLY by construction; anyone can re-derive them. The',
    '`substrate-observation-test` keyid is',
    '`7e2b0652d86716f47e35573ae0082d670706b7a548dcb685df7bf103923dcb9c`, and the',
    '`wrong-signer-test` keyid is',
    '`a0667d352125206443e3005accb7223ef487f505d5fc3d392b629b6619177e0c`.',
    '',
    'Timestamps are fixed at `issuedAt` 2026-01-01T00:00:00Z and `armedAt`',
    '2025-12-31T23:59:00Z, the subject is `example-agent-bundle`, and attack ids',
    'follow `XA-EXAMPLE-*` / `XB-EXAMPLE-*`. All digests derive from committed',
    "synthetic one-line preimages (in `gen_valid_vectors.py`'s `PREIMAGES`): subject",
    '`example-agent-bundle-content/v1`, substrate',
    '`example-substrate-image-content/v1`, catch policy',
    '`{"exampleCatchPolicy":{"mode":"enforce"}}`, network posture',
    '`{"exampleNetworkPosture":{"posture":"sinkhole"}}`, run entropy',
    '`example-run-start-checkpoint/v1`, and unchecked binding',
    '`example-unchecked-binding/v1`. Corpus and vocabulary digests are JCS digests',
    'of the embedded manifest and vocabulary objects.',
    '',
    '## Construction checkpoint resolution (ok-017 / ok-030)',
    '',
    'Pinned reading: "covering" records are the referenced records of the class(es)',
    "the row's class-match rule requires; extra referenced records are",
    'payload-checked but neither cap `method` nor gate the tier. Because',
    '`examination` is method-pinned (`reconstructed`) and `interception` is the only',
    'method-unconstrained kind, the min-composition accept half (ok-030) uses the',
    'cross-kind mechanism: a reconstructed caught row referencing an examination',
    'record (class cover) plus interception records signed `intercepted` and',
    "`reconstructed`. The row's method equals the weakest signed `aeeMethod`",
    '(`reconstructed`), so the vector is accepted under both the required-class and',
    'the all-referenced covering readings, keeping it stable across the pending',
    'tier-2 spec question.',
    '',
    '## Vector index (one line per vector: which gate it exercises)',
    '',
)

ACCEPT_INDEX_TAIL: tuple[str, ...] = (
    '',
    '## The vate-* boundary vectors',
    '',
    'Eight vectors carry a `vate-` prefix: `vate-1b`, `vate-1d`, `vate-2a`, `vate-3b` '
    'and `vate-3c` here, and `vate-1a`, `vate-1c` and `vate-3a` in the reject set. '
    'They exist because three conformance cases from the Verifiable Agent Trust '
    'Envelope (VATE) discussion draft asked what this predicate natively establishes '
    'across an external admission, and a boundary claim with nothing executable behind '
    'it is only an opinion.',
    '',
    'The pins those cases were read at, preserved here because a reader has to be able '
    'to go back to them: VATE commit `ce00121d7bd658c7a1fcd861b386ea9ea7ce66be`, '
    'corpus `VATE-AL2-Verifier-Admission-v0.3`, corpus digest '
    '`sha-256:0eb1969ea3763e0fec123de5ea0dacb225eb48a28d76866bbec56dc61d16cf8f`. The '
    'three case identifiers are `post-execution-admission-digest-mismatch`, '
    '`post-execution-effective-constraints-aggregate-exceeded` and '
    '`post-execution-runtime-mismatch`. A commit hash and a case identifier stop '
    "resolving once this repository is no longer the reader's entry point, so the "
    'source repository and the three case files are named by URL at that commit in '
    '[`../CHANGES.md`](../CHANGES.md), once for the whole family.',
    '',
    'What these vectors are, stated so it cannot be read as anything else: they are '
    'AEE-native boundary vectors prompted by those cases. They are not VATE '
    'conformance results, they carry no VATE verdict, they are not a projection into '
    'any other format, and no vector here is evidence about any implementation other '
    "than a rail run against this corpus. Every expectation is this predicate's own, "
    "decided by this suite's own rails, and the corpus digest above is recorded as a "
    'pin rather than reproduced as a validation of any canonicalization profile.',
    '',
    'The five accepts are the load-bearing half. Each carries exactly the fault its '
    'case is about and is valid anyway, which is a more precise statement of what this '
    'predicate declines to read than any sentence. The three rejects are narrow on '
    'purpose: `vate-1a` and `vate-3a` refuse a splice and say nothing about whether '
    'the identity a statement names is the true one, which `vate-3c` demonstrates from '
    'the other side, and `vate-1c` extends no rule that `bad-607` and `bad-728` do not '
    'already carry -- what it adds is the price of the case-1 anti-splice, made '
    'executable.',
    '',
    'Case 3 needs one distinction stated, and it is stated here once rather than '
    "repeated per vector. `vate-3b` demonstrates the case's own comparison directly: a "
    'producer-declared admitted runtime and a producer-declared observed runtime, side '
    'by side and differing, and neither read. `vate-3a` and `vate-3c` exercise a '
    'different field, `observationEnvironment.substrate.digest.sha256`, which is the '
    'observation-substrate identity -- the substrate anchor this predicate binds a run '
    'to. That is an ADJACENT AEE binding surface, not a semantic equivalent of the '
    "source case's `admission_receipt.subject.runtime` against "
    '`post_execution_receipt.execution.runtime` comparison. `vate-3a` shows the anchor '
    'cannot be moved under records already signed; `vate-3c` shows that a run re-bound '
    'to the substituted substrate digest and re-signed is accepted. Neither is '
    'evidence about the runtime comparison, and neither is offered as such.',
    '',
    'The case-1 trio is built on one shape so that the relation it instantiates is the '
    "source case's. Two synthetic admission receipts, A and B, are derived from "
    'published one-line preimages. `vate-1d` is receipt A in the sole subject slot '
    'with the records bound and signed for A; `vate-1a` is that statement with the '
    'subject digest moved from A to B and the records left exactly as they were '
    "signed; `vate-1b` is that statement with the arming payload carrying receipt B's "
    'digest and reference beside subject A. Both objects in the relation are admission '
    'receipts, as they are in the pinned case, which hashes a referenced admission '
    'receipt and compares the value with the digest a post-execution receipt asserts. '
    'The conclusion the trio makes executable is one sentence: AEE binds its sole '
    "subject against record splicing, and does not perform VATE's "
    'referenced-admission-receipt digest comparison.',
    '',
    '## Coverage notes',
    '',
    'The result vocabulary spans `fail` (ok-001), `pass` (ok-002), `degraded`',
    '(ok-004), and `pass_indirect` (ok-006/007/029/038/044/045);',
    '`doesNotAssert` appears only in ok-025. The minimum the recompute takes is',
    'witnessed by ok-033, whose clean row is indirect AND whose coverage',
    'discloses a gap: it reads `degraded`, the lower of the two, which is what',
    'distinguishes a minimum from a cascade written in the other order. On the basis '
    'axis, the set',
    'covers substrate (ok-001 family), artifact',
    '(ok-007/008/009/027/029/032/033), retired/out-of-vocabulary (ok-010), and',
    'mixed (ok-024) rows. The method axis covers intercepted (ok-001/002),',
    'reconstructed (ok-006/017/030/031), absent (ok-027), unknown (ok-008), and',
    'retired (ok-032). Record kinds exercised include interception, arming,',
    'sealed, examination, unknown-forward (ok-013), and the two registered',
    'non-covering kinds (ok-050), across trees of 1, 2, 3,',
    '4, and 5 leaves. On the signature plane, the set exercises pinned-key',
    'verifying (the default), wrong-signer-valid (ok-024), garbage/absent keyid',
    '(ok-019), non-PAE (ok-020), and embedded-key bait (ok-023).',
    '',
    'Every vector re-parses as JSON, regenerates byte-identically, and passes the',
    "generator's built-in gate and recompute self-verifier (`python3",
    'gen_valid_vectors.py` exits non-zero on any self-check failure).',
    '',
    'All content is synthetic: producer vocabulary is spec-verbatim',
    '(`policy.egress_sinkhole`, `none`, `sinkhole`, `egress_captured`, `no_egress`)',
    'or obviously synthetic (`example*`, `XA-EXAMPLE-*`); payload type',
    '`application/vnd.example.aee-observation.v1+json`; producer members are',
    'content-free (`producerNote`, `extraA`) or deliberately rankable and still inert '
    '(`exampleFidelity`, ok-054). Nothing here derives from, or',
    'describes, any real execution or production signing key.',
    '',
)

# The specification span each accept row cites, keyed by the SAME slug
# ACCEPT_INDEX uses. Kept as its own map rather than a fourth tuple element
# because sixty-one rows would have to be rewritten to add one anchor, and every
# one of those edits is a chance to move a cell.
#
# A row with no entry here emits an empty cell, which is why write_index refuses
# a key that names no row: an anchor map read with .get and never reconciled is
# exactly the shape TIER_EXPECTATIONS had when a mistyped key stopped pinning
# anything and said nothing at all. A missing anchor is invisible by
# construction -- the reject index's anchors are what the coverage measure reads,
# so an accept anchor that silently stopped emitting would show up only as an
# obligation quietly going uncited again.
#
# The anchors below are pinned. This file is in the AUTHORED list of
# scripts/spec-anchor-gate.py and vectors/accept/INDEX.md is in its GENERATED
# list, so each entry here is held against a digest of the prose it addresses
# and the index row built from it is compared against this entry rather than
# against the file as a whole. scripts/vendor-spec.py remaps this file too.
#
# All of those were missing at once and none of them announced itself. The
# gate collected from neither list, so the anchor had no pin; the re-vendor's
# own path list omitted this file, so a moved line would have left the anchor
# behind; and the index row was matched by a selector still spelled for the
# retired slug identifiers, so it was compared by a weaker question that passes
# whenever some unrelated entry happens to cite the same line.
ACCEPT_SPEC_ANCHORS: dict[str, str] = {
    # L1700-1703: a verifier MUST NOT rank the values of a producer-defined
    # ordered axis nor compose it by weakest input. This vector is the
    # instrument, and until the accept index carried a column there was nowhere
    # to say so: the obligation was declared `forcible-but-unforced` in
    # spec/READINGS.toml while the vector that forces it was already shipping.
    #
    # The span is the whole rule and was once its opening line alone. That line
    # carries only the sentence's subject -- "A producer that defines an ordered
    # axis there, meaning any member" -- while both of the sentence's MUST NOTs
    # sit two and three lines below it, outside the old span. An anchor drawn
    # that way reads as covering a rule it stops short of, which is the defect
    # suiteRevision 25 widened four anchors to close: a rule enforced while the
    # anchor names a different line. Swept across all three indexes when this
    # was drawn, no other span opened a sentence bearing a normative keyword and
    # closed before the keyword landed. The lines are named by their words
    # rather than by their numbers on purpose: a number here is remapped on
    # every re-vendor, which is why the pin ledger records prose too.
    'ok-054-producer-ordered-axis-inert': 'L1700-1703',
}

ACCEPT_INDEX: dict[str, tuple[str, str, str]] = {
    'ok-001-caught-intercepted-fail': (
        'fail',
        'aee-c-1, aee-c-3, aee-c-12, aee-c-28, aee-c-50',
        'canonical caught substrate/intercepted row covered by one interception '
        'record; single-leaf tree (root == leaf hash); producer layer name',
    ),
    'ok-002-clean-pass-armed-sealed': (
        'pass',
        'aee-c-7, aee-c-14, aee-c-26, aee-c-48, aee-c-63, aee-c-64, aee-c-65',
        'flagship clean row covered by arming + sealed (`aeeDropCount` 0), '
        '`actualLayer` "none", two-record tree',
    ),
    'ok-003-clean-pass-bounded-drops': (
        'pass',
        'aee-c-65',
        'sealed record with non-zero `aeeDropCount` 3 within self-declared '
        '`aeeDropBound` 5 still covers',
    ),
    'ok-004-degraded-out-of-scope': (
        'degraded',
        'aee-c-1, aee-c-6',
        'non-empty `coverage.outOfScope` forces recompute to `degraded`',
    ),
    'ok-005-degraded-routed-elsewhere': (
        'degraded',
        'aee-c-6',
        'non-empty `coverage.routedElsewhere` forces `degraded`',
    ),
    'ok-006-clean-reconstructed': (
        'pass_indirect',
        'aee-c-2, aee-c-13, aee-c-66',
        'clean (substrate, reconstructed) row class-matched by an examination record; '
        'indirect in time rather than in vantage, so the recompute floors it below '
        '`pass`',
    ),
    'ok-007-artifact-only-recordless': (
        'pass_indirect',
        'aee-c-2, aee-c-31, aee-c-57',
        'artifact-only statement: no records, no `batchRoot`, no `runEntropy`; '
        'over-strictness discriminator. The honest producer whose attack classes have '
        'no substrate vantage at all: it stays VALID and reaches the best result its '
        'evidence supports, which is the whole reason the rule prices rather than '
        'refuses',
    ),
    'ok-008-artifact-fail-closed-method': (
        'fail',
        'aee-c-5, aee-c-44',
        'artifact row with unknown `method` value fail-closes the row; carried `fail` '
        'recomputes; statement VALID',
    ),
    'ok-009-artifact-oov-label-fail': (
        'fail',
        'aee-c-4',
        'artifact row label outside carried `observationVocabulary.labels` '
        'fail-closes; VALID',
    ),
    'ok-010-artifact-retired-basis-fail': (
        'fail',
        'aee-c-43',
        'retired 0.4 `basis` value `substrate_observed` is out-of-vocabulary, no '
        'alias; fail-closed, VALID',
    ),
    'ok-011-shared-run-records': (
        'pass',
        'aee-c-15',
        'two clean rows legally share one arming + sealed record pair',
    ),
    'ok-012-selectors-present': (
        'pass',
        'aee-c-16',
        '`observationSelectors` positionally parallel to refs; advisory, result '
        'unchanged',
    ),
    'ok-013-unknown-kind-extra-record': (
        'pass',
        'aee-c-32, aee-c-71',
        'unrecognized `aeeKind` "aee-future-x" covers nothing, is ignored, still '
        'contributes its `batchRoot` leaf',
    ),
    'ok-014-three-record-odd-split': (
        'fail',
        'aee-c-26',
        '3-leaf RFC 6962 recursive split (2+1), never duplicate-pad; parent of '
        'root-family rejects',
    ),
    'ok-015-four-record-tree': (
        'fail',
        'aee-c-26',
        '4-leaf balanced RFC 6962 tree; two interceptions + arming + sealed',
    ),
    'ok-016-caught-actuallayer-none': (
        'fail',
        'aee-c-49',
        'caught row with `actualLayer` "none": observed-but-not-enforced (monitor-only '
        'vantage)',
    ),
    'ok-017-method-weakening-allowed': (
        'fail',
        'aee-c-23',
        'method cap is one-directional: reconstructed row referencing an '
        'intercepted-signed record is accepted',
    ),
    'ok-018-aee-prefix-ignored': (
        'pass',
        'aee-c-38, aee-c-61',
        'carried `evidenceTier` member and reserved-prefix `aeeInjected` member MUST '
        'be ignored',
    ),
    'ok-019-wrong-keyid-sig-verifies': (
        'pass',
        'aee-c-35',
        'keyid is a hint, never the check: garbage keyid on arming, ABSENT keyid on '
        'sealed, both sigs verify under the pinned key; tierWithPinnedKey '
        '["attested"], tierWithoutKey ["unattested"]',
    ),
    'ok-020-non-pae-signature': (
        'fail',
        'aee-c-36',
        'record signed over raw payload bytes (no PAE): tier fault (row unattested), '
        'never a validity fault; tierWithPinnedKey ["unattested"], tierWithoutKey '
        '["unattested"]',
    ),
    'ok-021-producer-extra-members': (
        'fail',
        'aee-c-73',
        'covering payload with extra non-`aee` producer members still covers',
    ),
    'ok-022-two-arming-records': (
        'pass',
        'aee-c-68',
        'two independent arming records + one sealed; each referenced record '
        'independently satisfies class constraints',
    ),
    'ok-023-no-tofu-embedded-key': (
        'pass',
        'aee-c-34',
        'payload embeds a tempting public key; consumer MUST NOT TOFU; expected tier '
        'without out-of-band pin is unattested; tierWithPinnedKey ["attested"], '
        'tierWithoutKey ["unattested"]',
    ),
    'ok-024-mixed-basis-rows': (
        'fail',
        'aee-c-33, aee-c-41',
        'pinned three rows: substrate covered by the substrate test key (attested), '
        'substrate covered by the wrong-signer test key (unattested), artifact '
        '(declared); tierWithPinnedKey ["attested","unattested","declared"], '
        'tierWithoutKey ["unattested","unattested","declared"]',
    ),
    'ok-025-does-not-assert-present': (
        'pass',
        'aee-c-84',
        '`doesNotAssert` present: advisory, never required, ignored for result',
    ),
    'ok-026-five-record-tree': (
        'fail',
        'aee-c-26',
        '5-leaf unbalanced RFC 6962 split (4+1): deep-split discriminator',
    ),
    'ok-027-artifact-missing-method': (
        'fail',
        'aee-c-5, aee-c-42, aee-c-44',
        'artifact row with `method` member ABSENT: absence == unknown, fail-closed; '
        'carried `fail`; VALID',
    ),
    'ok-028-empty-caught-pass': (
        'pass',
        'aee-c-3, aee-c-52',
        '`caught: []` edge: vacuously no caught rows; vocabulary digest over the '
        'empty-caught object',
    ),
    'ok-029-artifact-with-records': (
        'pass_indirect',
        'aee-c-2, aee-c-24, aee-c-29, aee-c-30, aee-c-32',
        'artifact-only rows + 2 unreferenced records + CORRECT `batchRoot`; no '
        'substrate rows so no derived binding, and record `aeeRunBinding` values are '
        'unchecked bytes. The records are the point of the tier pin: verifiable '
        'material sits beside the row and the row is declared anyway, under both '
        'policies, because basis and not availability decides. tierWithPinnedKey '
        '["declared"], tierWithoutKey ["declared"]',
    ),
    'ok-030-method-min-multirecord': (
        'fail',
        'aee-c-23, aee-c-45',
        'min-composition accept half: row method `reconstructed` equals the weakest '
        'signed `aeeMethod` across three referenced records {reconstructed, '
        'intercepted, reconstructed}; pairs with the cap-exceeded reject',
    ),
    'ok-031-caught-reconstructed': (
        'fail',
        'aee-c-13',
        'caught (substrate, reconstructed) row class-matched by an examination record: '
        'class-match keys on method, not caught-ness',
    ),
    'ok-032-method-inferred-retired': (
        'fail',
        'aee-c-5, aee-c-43',
        'retired 0.4 `method` value `inferred` is out-of-vocabulary, fail-closed; VALID',
    ),
    'ok-033-artifact-degraded': (
        'degraded',
        'aee-c-6',
        'artifact-only recordless degraded statement: parent for coverage-family '
        'rejects with no digest/binding cascade',
    ),
    'ok-034-arming-chain-genesis': (
        'pass',
        'aee-c-89',
        'arming payload carrying the optional run-chaining members in genesis form '
        '(`aeeRunSeq` 1, `aeeChainScope` present, no `aeePrevRunBinding`): '
        'syntax-checked in the reserved-member walk, nothing else normative reads '
        'them, and the record still covers',
    ),
    'ok-035-unknown-kind-excluded-from-cap': (
        'pass',
        'aee-c-23, aee-c-45, aee-c-71',
        'clean intercepted row referencing an unknown-`aeeKind` record signed '
        '`aeeMethod` "reconstructed": the record covers nothing and is otherwise '
        'ignored, so it neither invalidates the row (arming + sealed satisfy '
        'class-match) nor participates in the method cap, which reads only covering '
        'records',
    ),
    'ok-036-payload-nesting-at-bound': (
        'pass',
        'aee-c-18',
        'covering payload carrying a producer member nested exactly TO the bound '
        '(deepest open container at depth 128, scalar leaf): valid, and the '
        'discriminating twin of bad-741/bad-742 -- the one depth the corpus otherwise '
        'never touches, where a per-open-container counter and a per-parsed-value '
        'counter can disagree',
    ),
    'ok-038-issuedat-negative-zero-offset': (
        'pass_indirect',
        'aee-c-2, aee-c-85',
        '`issuedAt` spelled `2026-01-01T00:00:00-00:00`: the member of the timestamp '
        'profile no prose named before the profile was written, admitted because RFC '
        "3339 section 4.3 makes `-00:00` a statement about the producer's locale and "
        'not about the instant. Same instant as ok-007, so a rail reading "zero '
        'offset" as "Z or +00:00 only" is caught here rather than at a third party',
    ),
    'ok-039-armedat-negative-zero-offset': (
        'pass',
        'aee-c-63, aee-c-85',
        'the same spelling on `armedAt`, inside the substrate-signed arming payload, '
        're-signed with the batch root recomputed: the arming record must still cover '
        'the clean row and the statement must still recompute to `pass`',
    ),
    'ok-040-posture-no-network': (
        'pass',
        'aee-c-93',
        '`networkPosture.posture` "no_network": one of the three registered postures '
        'the rest of the corpus never carries, so the registry stopped being a set the '
        'corpus only claims to test',
    ),
    'ok-041-posture-allowlist': (
        'pass',
        'aee-c-93',
        '`networkPosture.posture` "allowlist": the registered value bad-305 swaps to, '
        'which is why the swap is invisible to any vocabulary rule and has to be '
        'caught by the run binding',
    ),
    'ok-042-posture-unsafe-bypass-egress': (
        'pass',
        'aee-c-93',
        '`networkPosture.posture` "unsafe_bypass_egress": the registered value the '
        'upstream prose omits from its list, admitted here because the schema beside '
        'that prose has always carried it',
    ),
    'ok-043-posture-producer-member-bound': (
        'pass',
        'aee-c-60',
        '`networkPosture` carrying a producer member the records commit to: valid, and '
        'the accepted half of the pair whose rejected half (bad-307) carries the same '
        'member with records that do not. The pair says the rule is about when the '
        'member was added, not about whether the posture may carry one',
    ),
    'ok-044-clean-artifact-intercepted-indirect': (
        'pass_indirect',
        'aee-c-2, aee-c-31',
        'the shape the artifact downgrade produces, and the one basis/method pairing '
        'the closed vocabularies permit that nothing else here exercised: a clean row '
        'indirect in vantage while claiming a live method. Recordless, so it needs no '
        'substrate participation to write, and `pass_indirect` is what stops it '
        'reading at the top of the ordering',
    ),
    'ok-045-mixed-clean-rows-indirect': (
        'pass_indirect',
        'aee-c-2, aee-c-14',
        'two clean rows, the first a live interception covered by its arming and '
        "sealed records and the second resting on the artifact's own account. Pins the "
        'quantifier: the rule fires on SOME clean row, so a direct row cannot carry an '
        'indirect one back up to `pass`. Second mixed-basis tier column beside ok-024, '
        'so neither the substrate half nor the artifact half of the partition rests on '
        'one vector: tierWithPinnedKey ["attested","declared"], tierWithoutKey '
        '["unattested","declared"]',
    ),
    'ok-046-seal-attacks-lower-bound': (
        'fail',
        'aee-c-98',
        'two caught rows and a seal that names only one of their attacks. Pins the '
        'DIRECTION of the rule: a seal naming an attack obliges a caught row for it, '
        'and a seal omitting one licenses nothing, because an observation the '
        'substrate could not attribute subtracts from what the seal claims and can '
        'never add a false one. Without this vector a rail reading the sets as equal '
        'passes the whole corpus',
    ),
    'ok-047-attribution-pinned': (
        'fail',
        'aee-c-100, aee-c-101, aee-c-102, aee-c-103',
        'the satisfied form of the stronger attribution in all three of its parts at '
        'once: the row resolves an interception, the manifest declares an '
        "`expectedPayloads` entry for the row's attack, and the record it resolves "
        'carries a value from that entry. Needed beside the three refusals, because a '
        'rail that rejects every `pinned` row satisfies each refusal and is wrong',
    ),
    'ok-048-attribution-paired-despite-expectation': (
        'fail',
        'aee-c-105',
        'the corpus declares an expectation for this attack and the record carries the '
        'matching value, so the producer COULD have declared `pinned` truthfully and '
        'did not. `paired` is a floor rather than a confession: what a consumer learns '
        'from it is that this row does not carry the stronger binding, never that the '
        'producer had one and withheld it. A rail that infers the stronger value from '
        'the corpus, or refuses a truthful weaker one, fails here and nowhere else',
    ),
    'ok-049-seal-names-caught-attack': (
        'fail',
        'aee-c-98',
        'a seal that names an attack the statement carries a caught row for. ok-046 '
        'pins that the rule does not fire on omission; this pins that it is a rule at '
        'all rather than a member nothing reads',
    ),
    'ok-050-registered-noncovering-kinds': (
        'pass',
        'aee-c-23, aee-c-45, aee-c-106, aee-c-107',
        'a clean intercepted row referencing a `moat-drop` and an '
        '`uncommitted-observation` record, both signed `aeeMethod` "reconstructed". '
        'The document registers both as covering nothing in every state, so neither '
        'invalidates the row (arming + sealed satisfy class-match), neither '
        "participates in the method cap, neither enters the seal's `aeeObservedSet`, "
        'and neither is owed a caught row; both leaves stay in the batch root. ok-035 '
        'says the same of a kind no version registers, and a rail that gives either of '
        'these names covering semantics passes that vector and fails this one',
    ),
    'ok-051-two-pinned-rows': (
        'fail',
        'aee-c-100, aee-c-101, aee-c-102, aee-c-103',
        'two rows declaring the stronger attribution at once, each resolving its own '
        "interception whose committed value the manifest declared for that row's "
        'attack. Every earlier pinned vector carries a single row, and permuting one '
        'row is the identity, so the corpus could not reach the arm that decides which '
        'record belongs to which attack: `bad-982` is this statement with the '
        'assignment exchanged and nothing else touched. The two attacks sit in '
        'different coverage classes, because a consumer policy keyed on attack class '
        'is the cheapest example of one that reads the assignment',
    ),
    'ok-052-liveness-probe-per-channel': (
        'fail',
        'aee-c-98, aee-c-100, aee-c-101, aee-c-102, aee-c-103, aee-c-104',
        'detector liveness demonstrated on every claimed channel at once, built from '
        'members this version already has: `classes` assigns each attack to a channel, '
        '`expectedPayloads` is the stimulus a corpus author planted and predicted, '
        '`aeePayloadCommitment` is what the substrate committed to on the wire, '
        "`pinned` is the row asserting the two are comparable, and the seal's "
        '`aeeObservedAttacks` names all three. A check that never fires is '
        'indistinguishable from outside from a boundary nothing reached, and this is '
        'the shape that separates them. Three channels rather than two, because a rail '
        'that evaluates the first row and the last passes a two-channel statement '
        'while skipping everything between; it is the accept anchor `bad-983`, '
        '`bad-984` and `bad-985` are measured against, since a rail refusing every '
        'multi-channel `pinned` statement satisfies all three refusals and is wrong',
    ),
    'ok-053-liveness-probe-uncaught-on-one-channel': (
        'fail',
        'aee-c-14, aee-c-98, aee-c-100, aee-c-102, aee-c-103',
        "the same three planted probes, and the middle channel's probe produced no "
        'interception: its row is clean, its attribution is the honest floor, and the '
        'seal names the two channels the substrate did attribute and not the third. '
        'This MUST be accepted. Liveness is not a validity requirement at this '
        'version, and a producer whose detector genuinely did not fire emits exactly '
        'these bytes, so a rail that hard-codes the demand refuses the honest report '
        'along with the dishonest one. What the format does instead is make the '
        'difference legible: three probes declared, two named on the seal, and the gap '
        'between those sets is the channel this run cannot show a live detector for -- '
        'which `scripts/liveness-probe.py` computes and a consumer decides on. '
        '`bad-985` is the dishonest report of the same run',
    ),
    'ok-054-producer-ordered-axis-inert': (
        'fail',
        'aee-c-23, aee-c-45, aee-c-73',
        'a covering interception payload carrying a producer-defined member whose '
        'value is a token this predicate itself orders (`exampleFidelity: '
        '"reconstructed"`) beside a signed `aeeMethod` of `intercepted`. Producer '
        'territory is inert to a verifier, and the ordered case is the one a verifier '
        'is tempted to read: a rail that folds the member into the weakest-input '
        'method composition caps the row at `reconstructed` and reports '
        '`method-cap-exceeded` on a statement no requirement refuses. ok-021 carries '
        'producer members too, but content-free ones, so it forces only that such a '
        'member does not stop the record covering; this is the vector the ranking rail '
        'fails',
    ),
    'ok-055-pinned-row-two-interceptions': (
        'fail',
        'aee-c-100, aee-c-101, aee-c-102, aee-c-103',
        'one pinned row resolving TWO interceptions, both committing to values the '
        "corpus declared for that row's attack. The third part of the pinned rule is "
        'quantified over EVERY interception a row resolves, and every pinned row '
        'shipped before this one resolves exactly one, so the quantifier was only ever '
        'evaluated at cardinality one -- where a universal and an existential agree, '
        'and a rail that compares the first resolved interception and stops clears the '
        'whole corpus. Two predicted values under ONE attack, because the boundary is '
        'inside a single row; XB rides alongside so the refusal derived from this '
        'vector has a value the corpus genuinely declared for a DIFFERENT attack to '
        'reach for. `bad-986` is this statement with the second commitment replaced by '
        'that value and nothing else touched',
    ),
    'ok-900-fail-outranks-degraded': (
        'fail',
        'aee-c-1',
        'the composition law that decides every mixed run, and the one shape nothing '
        'else here carries: a caught row forcing `fail` in the same statement as a '
        'disclosed coverage gap forcing `degraded`. The recompute takes the minimum, '
        'so the carried token is `fail`, and a rail that ranks a real failure below a '
        'disclosed gap reports the softer verdict on every mixed run. Measured rather '
        'than argued: the ordering was invisible to the whole corpus until this vector',
    ),
    'ok-901-row-missing-basis': (
        'fail',
        'aee-c-1',
        'a row carrying no `basis` member at all. Absence is not a value, so the row '
        'cannot be classified and fail-closes exactly as an out-of-vocabulary one '
        'does; the statement stays VALID and carries `fail`. Recordless and '
        'artifact-shaped, so no digest or binding cascades. This resolves, in the '
        'accept direction, the reading the reject set had deferred: the reject-side '
        'twin is still deferred, and the reject index says so and says why',
    ),
    'vate-1b-carried-admission-digest-unread': (
        'pass',
        'aee-c-73',
        'prompted by VATE case `post-execution-admission-digest-mismatch` at VATE '
        'commit `ce00121d7bd658c7a1fcd861b386ea9ea7ce66be`, corpus '
        '`VATE-AL2-Verifier-Admission-v0.3`, corpus digest '
        '`sha-256:0eb1969ea3763e0fec123de5ea0dacb225eb48a28d76866bbec56dc61d16cf8f`. '
        'An AEE-native boundary vector prompted by that case, not a VATE conformance '
        'result. Admission receipt A is the sole subject and every record is correctly '
        'bound and signed for A, while the arming payload carries admission receipt '
        "B's digest and the reference naming B. Two admission receipts disagree -- the "
        'relation the pinned case tests, receipt against receipt rather than executed '
        'artifact against receipt -- and the statement is valid and recomputes `pass`, '
        'because AEE never performs that comparison: the carried digest and reference '
        'are producer territory and the subject is read only as a binding input. A '
        'negative pin on the comparison this predicate does not perform',
    ),
    'vate-1d-admission-receipt-as-sole-subject': (
        'pass',
        'aee-c-22, aee-c-60',
        'prompted by VATE case `post-execution-admission-digest-mismatch` at VATE '
        'commit `ce00121d7bd658c7a1fcd861b386ea9ea7ce66be`, corpus '
        '`VATE-AL2-Verifier-Admission-v0.3`, corpus digest '
        '`sha-256:0eb1969ea3763e0fec123de5ea0dacb225eb48a28d76866bbec56dc61d16cf8f`. '
        'An AEE-native boundary vector prompted by that case, not a VATE conformance '
        'result. Admission receipt A is the SOLE subject, so the binding covers the '
        'admission identity and the case-1 anti-splice genuinely bites: `vate-1a` is '
        "this statement with receipt B's digest in the subject slot and the A-bound "
        'records untouched. It is also the whole price: exactly one subject entry is '
        'permitted and the pre-image reads the first, so the receipt DISPLACES the '
        'executed artifact. Valid, `pass`, and naming no executed artifact anywhere -- '
        'a consumer learns which admission the run happened under and cannot learn '
        'what was run',
    ),
    'vate-2a-aggregate-overrun-unread': (
        'pass',
        'aee-c-73',
        'prompted by VATE case '
        '`post-execution-effective-constraints-aggregate-exceeded` at VATE commit '
        '`ce00121d7bd658c7a1fcd861b386ea9ea7ce66be`, corpus '
        '`VATE-AL2-Verifier-Admission-v0.3`, corpus digest '
        '`sha-256:0eb1969ea3763e0fec123de5ea0dacb225eb48a28d76866bbec56dc61d16cf8f`. '
        'An AEE-native boundary vector prompted by that case, not a VATE conformance '
        'result. Two carried side-effect amounts are each below the carried maximum '
        'and sum above it; the recompute reads the rows, the carried vocabulary and '
        'the two coverage maps and nothing else, no row carries a quantity, and there '
        'is no arithmetic to perform. Valid, `pass`. The amounts travel on ONE arming '
        'record because two records with identical payloads are duplicates and would '
        'be refused before aggregation could be reached',
    ),
    'vate-3b-admitted-vs-observed-runtime-unread': (
        'pass',
        'aee-c-73',
        'prompted by VATE case `post-execution-runtime-mismatch` at VATE commit '
        '`ce00121d7bd658c7a1fcd861b386ea9ea7ce66be`, corpus '
        '`VATE-AL2-Verifier-Admission-v0.3`, corpus digest '
        '`sha-256:0eb1969ea3763e0fec123de5ea0dacb225eb48a28d76866bbec56dc61d16cf8f`. '
        'An AEE-native boundary vector prompted by that case, not a VATE conformance '
        'result. An admitted runtime and an observed runtime are declared side by side '
        'and differ. A statement carries exactly one `observationEnvironment`, so '
        'there is no second runtime for any rule to compare against, and both members '
        'are producer territory. Valid, `pass`',
    ),
    'vate-3c-substrate-substituted-and-resigned': (
        'pass',
        'aee-c-22, aee-c-60',
        'prompted by VATE case `post-execution-runtime-mismatch` at VATE commit '
        '`ce00121d7bd658c7a1fcd861b386ea9ea7ce66be`, corpus '
        '`VATE-AL2-Verifier-Admission-v0.3`, corpus digest '
        '`sha-256:0eb1969ea3763e0fec123de5ea0dacb225eb48a28d76866bbec56dc61d16cf8f`. '
        'An AEE-native boundary vector prompted by that case, not a VATE conformance '
        'result. The bound on `vate-1a` and `vate-3a`, and the reason both are stated '
        'narrowly: the whole run is re-bound to the substituted substrate digest and '
        're-signed, the binding recomputed over the second observation-substrate '
        'identity and every record re-signed under the published substrate-observation '
        'test key. Nothing is spliced, so nothing is detected, and the statement is '
        'valid and recomputes `pass`. The binding is anti-splice and explicitly not '
        'anti-forge, so those two vectors establish that records were not MOVED, never '
        'that the identity they name is the true one',
    ),
}


def write_index(vectors: dict[str, Any], ids: dict[str, str]) -> None:
    """Emit accept/INDEX.md: the prose, then one row per vector.

    Every row's identifier comes from the corpus that was just built rather than
    from anything typed here, which is the whole point of moving this out of a
    hand-written file. The reconciliation below is the other half: a row
    describing a vector that was not built, or a vector built with no row, stops
    the generator instead of producing an index that quietly disagrees with the
    directory beside it.
    """
    described = set(ACCEPT_INDEX)
    built = set(vectors)
    missing = sorted(built - described)
    orphaned = sorted(described - built)
    if missing or orphaned:
        raise SystemExit(
            "the accept index and the accept corpus disagree:"
            + ("".join(f"\n  built with no row: {m}" for m in missing))
            + ("".join(f"\n  row with nothing built: {o}" for o in orphaned))
        )
    if unclaimed := sorted(set(ACCEPT_SPEC_ANCHORS) - described):
        raise SystemExit(
            "ACCEPT_SPEC_ANCHORS names row(s) that do not exist: "
            f"{unclaimed}. The map is read per row, so a key that matches nothing "
            "emits no anchor and reports no error, and the obligation it was "
            "written to cite goes back to being uncited with every gate green."
        )

    out: list[str] = [line.replace("{predicate_type}", PREDICATE_TYPE)
                      for line in ACCEPT_INDEX_PREAMBLE]
    out.append("| vector | result | conditions (aee-c ids) | exercises | spec |")
    out.append("|---|---|---|---|---|")
    # ACCEPT_INDEX's order, not the build order: the two differ, and this table
    # is read by people as well as by gen_manifest.py, so it keeps the order it
    # was written in. The reconciliation above has already established that the
    # two describe the same set, so iterating either is safe; iterating this one
    # is what makes the emitted file identical to the one it replaces.
    for slug in ACCEPT_INDEX:
        result, conditions, exercises = ACCEPT_INDEX[slug]
        declared = vectors[slug]["predicate"]["result"]
        if declared != result:
            raise SystemExit(
                f"{slug}: the index says result {result!r} and the statement "
                f"carries {declared!r}. The index is emitted from the corpus, so "
                "the two cannot be allowed to differ."
            )
        anchor = ACCEPT_SPEC_ANCHORS.get(slug, "")
        out.append(
            f"| {ids[slug]} | {result} | {conditions} | {exercises} | {anchor} |"
        )
    out.extend(line.replace("{predicate_type}", PREDICATE_TYPE)
               for line in ACCEPT_INDEX_TAIL)
    (OUT_DIR / "INDEX.md").write_text("\n".join(out), encoding="utf-8")


def main() -> int:
    vectors = build_vectors()
    failures = 0
    STATEMENTS_DIR.mkdir(exist_ok=True)
    ids: dict[str, str] = {}
    minted: dict[str, str] = {}
    for name, stmt in vectors.items():
        errs = verify(stmt)
        if errs:
            failures += 1
            print(f"INVALID {name}: {errs}")
        body = (json.dumps(stmt, sort_keys=True, indent=2, ensure_ascii=False)
                + "\n").encode("utf-8")
        vid = vector_id(body)
        if vid in minted:
            raise SystemExit(
                f"{name} and {minted[vid]} serialize to identical bytes, so they "
                f"share the identifier {vid}. A content-addressed corpus cannot "
                "give one statement two names, and should not want to: one of "
                "them is a copy of the other."
            )
        minted[vid] = name
        path = STATEMENTS_DIR / f"{vid}.json"
        path.write_bytes(body)
        json.loads(path.read_text())  # parse check
        ids[name] = vid
        print(f"wrote {path.name}  result={stmt['predicate']['result']}")
    write_build_ids(ids)
    write_index(vectors, ids)
    # The count tripwire that used to live here counted ok-*.json files beside
    # this generator. It cannot survive the flattening: every corpus now shares
    # one directory, so no generator can tell a file it did not write from a
    # stray one. The question moved to vectors/gen_manifest.py, which sees the
    # whole corpus and can answer it properly in both directions.
    print(f"keyids: substrate-observation-test={SUB_KEYID}")
    print(f"        wrong-signer-test={WRONG_KEYID}")
    print(f"        statement-test={STMT_KEYID}")
    sig_map = verify_signatures(vectors["ok-024-mixed-basis-rows"])
    print(f"ok-024 signer map (expect substrate,wrong): {sig_map}")
    sig_map20 = verify_signatures(vectors["ok-020-non-pae-signature"])
    print(f"ok-020 signer map (expect no-pae-verify): {sig_map20}")
    if failures:
        print(f"FAIL: {failures} vectors invalid")
        return 1
    print(f"all {len(vectors)} vectors VALID under self-verifier")
    return 0


if __name__ == "__main__":
    sys.exit(main())
