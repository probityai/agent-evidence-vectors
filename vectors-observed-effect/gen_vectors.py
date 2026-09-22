#!/usr/bin/env python3
"""Generate the Observed Effect conformance vector suite.

Regenerate byte-identically:

    uv run --extra generators python vectors-observed-effect/gen_vectors.py

Every member is a complete DSSE envelope whose payload is an in-toto Statement
v1 carrying an Observed Effect predicate (spec/predicates/observed-effect.md).
The vector file carries the bytes and nothing else. What a verifier is supposed
to DECIDE lives in MANIFEST.json, for the reason the sibling corpora record: a
file that carries its own answer is scoreable without being read.

WHY THIS SUITE EXISTS
---------------------
The predicate states nineteen rules, of which six close an attack this
repository's own attack section constructs. A rule nothing exercises is a
sentence, not a gate. This corpus is the difference, and one member of it is a
shape no other corpus in this repository has: a claim whose own carried evidence
refutes it. research/442's teardown found that gap by finding
the same defect in somebody else's verifier -- an evidence shape that only runs
when a producer-set list is non-empty -- and a corpus with no such member cannot
tell a verifier that reads claims from one that recomputes over evidence.

DETERMINISM
-----------
Ed25519 signatures are deterministic (RFC 8032), so every key below is derived
from a fixed seed in this file and every timestamp is a literal. The corpus comes
out byte-identical on every machine, which is what lets a regenerability gate
tell a regenerated file from a rewritten one.

The keys are PUBLISHED TEST KEYS. The corpus is rebuildable by a stranger, which
is the point: a suite nobody else can rebuild is one they have to trust.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from canonical import canonical_bytes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)

# One preimage, one spelling. release-digests.py reaches the same function.
from digest import corpus_digest  # noqa: E402

SUITE = "observed-effect-conformance"
PREDICATE_TYPE = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/observed-effect"
PREDICATE_SPEC = "spec/predicates/observed-effect.md"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
ID_HEX = 16

# The empty tree object name under each algorithm, COMPUTED rather than typed.
# The sha1 value is the constant ASQAV Section 8.2(c) names; the sha256 value is
# the one a sha256 store actually holds, and a specification that says "the git
# empty tree constant" without naming the algorithm carries a latent
# wrong-constant bug. Both are the digest of the bytes `tree 0\0`.
EMPTY_TREE = {
    "sha1": hashlib.sha1(b"tree 0\x00").hexdigest(),
    "sha256": hashlib.sha256(b"tree 0\x00").hexdigest(),
}

OBSERVER_SEED = bytes.fromhex("00" * 31 + "11")
OBSERVED_SEED = bytes.fromhex("00" * 31 + "22")

OBSERVER_KEY = Ed25519PrivateKey.from_private_bytes(OBSERVER_SEED)
OBSERVED_KEY = Ed25519PrivateKey.from_private_bytes(OBSERVED_SEED)


def raw_public(key: Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


OBSERVER_PUB = raw_public(OBSERVER_KEY).hex()
OBSERVED_PUB = raw_public(OBSERVED_KEY).hex()
# A keyid is the digest of the raw public key, so it is derived and not chosen.
OBSERVER_KEYID = hashlib.sha256(raw_public(OBSERVER_KEY)).hexdigest()[:32]
OBSERVED_KEYID = hashlib.sha256(raw_public(OBSERVED_KEY)).hexdigest()[:32]


# ---------------------------------------------------------------------------
# The state tree this corpus narrates.
#
# Roots are literal digests over literal bytes rather than magic hex, so a
# reader can recompute every one of them and a reject twin cannot be mistaken
# for a typo.
# ---------------------------------------------------------------------------
def root(label: str) -> str:
    return hashlib.sha256(f"observed-effect/root/{label}".encode()).hexdigest()


R0 = root("before")
R1 = root("after-write-1")
R2 = root("after-write-2")
R_ELSEWHERE = root("unrelated-interval")

BLOB = b"port: 8080\nmode: strict\n" * 8
BLOB_DIGEST = hashlib.sha256(BLOB).hexdigest()
NONCE = hashlib.sha256(b"observed-effect/witness-nonce/1").hexdigest()

AUTHORITY_DIGEST = hashlib.sha256(
    canonical_bytes({"grant": "write:/srv/app/", "issuer": "deploy-authority"})
).hexdigest()

T_COMMIT = "2026-09-18T23:59:58Z"
T_OPEN = "2026-09-19T00:00:00Z"
T_SEAL = "2026-09-19T00:00:04Z"
T_ISSUE = "2026-09-19T00:00:05Z"


def range_digest(blob: bytes, start: int, end: int) -> str:
    """The predicate's range preimage: length and both offsets are inside it.

    A digest over the range bytes alone is reproducible from any blob containing
    those bytes at any position, so it binds the bytes and not the read. Attack
    A3 in the predicate is closed here and nowhere else.
    """
    pre = (
        f"{len(blob)}\0".encode()
        + f"{start}\0".encode()
        + f"{end}\0".encode()
        + blob[start:end]
    )
    return hashlib.sha256(pre).hexdigest()


def commitment_body(
    authority_digest: str, before_root: str, interval_id: str, nonce: str
) -> dict[str, str]:
    """The commitment preimage: four members, each closing a named attack.

    beforeRoot and witnessNonce alone left authority substitution (A8) and
    commitment replay across intervals (A9) open. Both are closed here rather than
    in a verifier rule, because the fix is what the observer signs.
    """
    return {
        "authorityDigest": authority_digest,
        "beforeRoot": before_root,
        "intervalId": interval_id,
        "witnessNonce": nonce,
    }


def commitment_digest(
    authority_digest: str, before_root: str, interval_id: str, nonce: str
) -> str:
    return hashlib.sha256(
        canonical_bytes(commitment_body(authority_digest, before_root, interval_id, nonce))
    ).hexdigest()


def commitment(
    before_root: str = R0,
    nonce: str = NONCE,
    keyid: str = OBSERVER_KEYID,
    committed_at: str = T_COMMIT,
    signing_key: Ed25519PrivateKey | None = None,
    override_digest: str | None = None,
    anchor: dict[str, Any] | None = None,
    authority_digest: str = "",
    interval_id: str = "iv-0001",
) -> dict[str, Any]:
    body = commitment_body(
        authority_digest or AUTHORITY_DIGEST, before_root, interval_id, nonce
    )
    sig = (signing_key or OBSERVER_KEY).sign(canonical_bytes(body))
    out: dict[str, Any] = {
        "committedAt": committed_at,
        "witnessNonce": nonce,
        "commitmentDigest": override_digest
        or commitment_digest(
            authority_digest or AUTHORITY_DIGEST, before_root, interval_id, nonce
        ),
        "keyid": keyid,
        "sig": sig.hex(),
    }
    if anchor is not None:
        out["externalAnchor"] = anchor
    return out


def read_row(
    path: str = "/srv/app/config.yaml",
    pre: str = R0,
    blob: bytes = BLOB,
    start: int = 0,
    end: int = 64,
    state: str = "bytes-read",
    override_range_digest: str | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "path": path,
        "preStateDigest": pre,
        "blobDigest": hashlib.sha256(blob).hexdigest(),
        "readState": state,
    }
    if state == "bytes-read":
        row["byteRange"] = {"start": start, "end": end}
        row["rangeDigest"] = override_range_digest or range_digest(blob, start, end)
    return row


def write_row(path: str, pre: str, post: str, in_scope: bool = True) -> dict[str, Any]:
    return {
        "path": path,
        "preStateDigest": pre,
        "postStateDigest": post,
        "inScope": in_scope,
    }


def dual(fact: str, observed: str, reported: str, agreement: str) -> dict[str, Any]:
    return {
        "fact": fact,
        "observedValue": observed,
        "reportedValue": reported,
        "agreement": agreement,
    }


def predicate(**over: Any) -> dict[str, Any]:
    """The baseline authoritative record. Every reject twin is this, mutated once."""
    base: dict[str, Any] = {
        "intervalId": "iv-0001",
        "tier": "authoritative",
        "mutation": "observed",
        "hashAlgorithm": "sha256",
        "interval": {
            "beforeRoot": R0,
            "afterRoot": R2,
            "baseResolution": "supplied",
            "openedAt": T_OPEN,
            "sealedAt": T_SEAL,
        },
        "pathScope": ["/srv/app/"],
        "authorityDigest": AUTHORITY_DIGEST,
        # observation is filled in AFTER the overrides, because the commitment is a
        # function of the record it sits in: it binds intervalId, authorityDigest
        # and beforeRoot. Built here it would carry the BASELINE's identifiers into
        # every member that overrides them, and six members refused on a digest
        # mismatch they were not written to test. A default that is stale for the
        # record it lands in is the same class of defect as the merging override.
        "observation": None,
        "reads": [read_row()],
        "writes": [
            write_row("/srv/app/main.py", R0, R1),
            write_row("/srv/app/handler.py", R1, R2),
        ],
        "dualValues": [dual("writes.count", "2", "2", "agree")],
        "doesNotAssert": [
            "that the observed party performed no action outside pathScope",
            "that the authority document permits what the writes did",
        ],
        "issuedAt": T_ISSUE,
    }
    # REPLACE, never merge. A merging override silently kept the baseline's
    # priorCommitment in the member built to omit it, so a rule with no exercising
    # vector reported a pass. Every caller passes a complete object.
    for key, value in over.items():
        if key not in base:
            raise SystemExit(f"override names a member the baseline does not have: {key}")
        if isinstance(value, _Omit):
            del base[key]
        else:
            base[key] = value
    if base.get("observation") is None:
        base["observation"] = {
            "vantage": "below-observed",
            "origin": "first-hand",
            "coverage": {"scopeComplete": True, "gaps": []},
            "observedSigners": [OBSERVED_KEYID],
            "priorCommitment": commitment(
                before_root=base["interval"]["beforeRoot"],
                authority_digest=base["authorityDigest"],
                interval_id=base["intervalId"],
            ),
        }
    return base


def statement(pred: dict[str, Any], subject_digest: str | None = None) -> dict[str, Any]:
    return {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": pred["intervalId"],
                "digest": {"sha256": subject_digest or pred["interval"]["afterRoot"]},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": pred,
    }


def pae(payload_type: str, payload: bytes) -> bytes:
    return b"DSSEv1 %d %s %d %s" % (
        len(payload_type),
        payload_type.encode(),
        len(payload),
        payload,
    )


def envelope(stmt: dict[str, Any], raw_payload: bytes | None = None) -> dict[str, Any]:
    payload = raw_payload if raw_payload is not None else canonical_bytes(stmt)
    sig = OBSERVER_KEY.sign(pae(PAYLOAD_TYPE, payload))
    import base64

    return {
        "payload": base64.b64encode(payload).decode(),
        "payloadType": PAYLOAD_TYPE,
        "signatures": [{"keyid": OBSERVER_KEYID, "sig": base64.b64encode(sig).decode()}],
    }


# ---------------------------------------------------------------------------
# The conditions. One per predicate rule this corpus exercises, each naming the
# section of spec/predicates/observed-effect.md that carries it. A condition
# with no accept member and a condition with no reject member are both reported
# by check_vectors.py, because either one is an unexercised rule.
# ---------------------------------------------------------------------------
CONDITIONS: dict[str, str] = {
    "oe-tier-vantage": "tier: a record is authoritative only where vantage is below-observed",
    "oe-tier-commitment": (
        "priorCommitment: required wherever vantage is below-observed, which is why "
        "the tier recompute carries no clause for it"
    ),
    "oe-tier-scope": "tier: authoritative requires a non-empty pathScope (attack A2)",
    "oe-chain": "writes: the ordered chain must reproduce afterRoot from beforeRoot",
    "oe-mutation-none": "mutation: none requires beforeRoot == afterRoot and empty writes",
    "oe-self-refuting": (
        "mutation: a record whose own writes refute its own claim is malformed (attack A6)"
    ),
    "oe-empty-tree": (
        "baseResolution: empty-tree requires the constant for the declared hashAlgorithm"
    ),
    "oe-base-vocab": "baseResolution: closed vocabulary, fail-closed on an unknown value",
    "oe-range-nonempty": "reads: a zero-length byteRange is malformed (attack A3)",
    "oe-range-preimage": "reads: rangeDigest binds blob length and both offsets (attack A3)",
    "oe-scope-glob": (
        "pathScope: no glob metacharacter; a universal scope is the literal / (attack A4)"
    ),
    "oe-commitment-keyid": "priorCommitment: keyid must not appear in observedSigners (attack A1)",
    "oe-commitment-order": "priorCommitment: committedAt strictly before interval.openedAt",
    "oe-commitment-digest": (
        "priorCommitment: commitmentDigest recomputes over beforeRoot and witnessNonce"
    ),
    "oe-agreement": "dualValues: agreement must be derivable from the two carried values",
    "oe-coverage-contradiction": (
        "coverage: scopeComplete true with a gap inside pathScope is malformed"
    ),
    "oe-write-scope": "writes: a write outside pathScope invalidates the authoritative tier",
    "oe-write-scope-label": (
        "writes: inScope is derived from path and pathScope, never a producer opinion"
    ),
    "oe-read-chain": (
        "reads: preStateDigest must equal beforeRoot or the preceding write's postStateDigest"
    ),
    "oe-ijson-duplicate": "parsing: a duplicate member anywhere makes the statement malformed",
    "oe-anchor-unruled": (
        "priorCommitment.externalAnchor: the predicate defines no offline token rule"
    ),
    "oe-required-members": "parsing: no member has a default and no verifier may supply one",
    "oe-vocabulary": "parsing: fail-closed on an unknown value in any closed vocabulary",
    "oe-interval-order": (
        "interval: openedAt strictly before sealedAt, issuedAt at or after sealedAt"
    ),
    "oe-ijson-integer": (
        "parsing: an integer at or above 2**53 is refused on the way IN, not only out"
    ),
    "oe-predicate-type": "parsing: the statement must carry this predicate's own type URI",
    "oe-subject-binding": (
        "subject: the single subject digest is the interval's afterRoot under "
        "hashAlgorithm (attack A20)"
    ),
    "oe-timestamp-grammar": (
        "timestamps: RFC 3339 UTC with Z and no fractional second, so a lexical "
        "comparison is an instant comparison (attack A21)"
    ),
    "oe-path-normalized": (
        "paths: absolute and normalized, with no dot or dot-dot segment (attack A22)"
    ),
    "oe-scope-boundary": (
        "pathScope: containment is at a segment boundary, never a string prefix "
        "(attack A23)"
    ),
    "oe-empty-tree-read": (
        "reads: no bytes are read at a beforeRoot that is the empty tree (attack A24)"
    ),
    "oe-coverage-named": (
        "coverage: an incomplete observation names where it was blind (attack A25)"
    ),
    "oe-keyid-form": (
        "keyids: one lowercase hex spelling, so the disjointness check cannot be "
        "dodged by case (attack A26)"
    ),
    "oe-commitment-signature": (
        "priorCommitment: the signature is verified against the anchored observer "
        "key (attack A27)"
    ),
    "oe-dual-recompute": (
        "dualValues: for a fact the statement can compute about itself, the observed "
        "side is that value (attack A28)"
    ),
    "oe-dual-values-absent": "dualValues: a row carrying neither value is not a comparison",
    "oe-origin-platform": (
        "observation.runtime: an imported record declares a software-only platform, "
        "because an importer has no quote to present"
    ),
    "oe-origin-vantage": (
        "observation.origin: only a first-hand producer may claim below-observed "
        "(attack A31)"
    ),
    "oe-authoritative-rows": (
        "tier: an authoritative record carries at least one read or one write "
        "(attack A2, second spelling)"
    ),
}

class _Omit:
    """Sentinel: delete this member rather than override it.

    A member built to LACK something cannot be expressed by an override that
    replaces, and hand-editing the bytes is how a corpus stops being regenerable.
    """

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "OMIT"


OMIT = _Omit()

DRAFTS: list[dict[str, Any]] = []

#: A blob this corpus narrates and does NOT publish, for the read row that no
#: verifier can check. check_vectors.py holds only the published blob, so the
#: range preimage rule skips this row exactly as a stranger's verifier would.
_INVENTED_BLOB = b"a blob no other party holds"
_INVENTED_BLOB_DIGEST = hashlib.sha256(_INVENTED_BLOB).hexdigest()


def _typed_statement(predicate_type: str) -> dict[str, Any]:
    """A statement carrying somebody else's predicateType over our predicate."""
    stmt = statement(predicate(intervalId="iv-0202"))
    stmt["predicateType"] = predicate_type
    return stmt


def _unsigned_commitment(interval_id: str) -> dict[str, Any]:
    """A commitment whose signature is sixty-four zero bytes."""
    out = commitment(interval_id=interval_id)
    out["sig"] = "00" * 64
    return out


def add(
    slug: str,
    kind: str,
    stmt: dict[str, Any],
    conditions: list[str],
    verdict: str,
    codes: list[str],
    cites: str,
    parent: str | None = None,
    raw_payload: bytes | None = None,
    readings: list[dict[str, Any]] | None = None,
) -> None:
    DRAFTS.append(
        {
            "slug": slug,
            "kind": kind,
            "envelope": envelope(stmt, raw_payload=raw_payload),
            "conditions": conditions,
            "verdict": verdict,
            "codes": codes,
            "cites": cites,
            "parent": parent,
            "readings": readings,
        }
    )


# --- accept members --------------------------------------------------------

add(
    "authoritative-baseline",
    "accept",
    statement(predicate()),
    [
        "oe-tier-vantage",
        "oe-tier-commitment",
        "oe-tier-scope",
        "oe-chain",
        "oe-range-nonempty",
        "oe-range-preimage",
        "oe-scope-glob",
        "oe-commitment-keyid",
        "oe-commitment-order",
        "oe-commitment-digest",
        "oe-agreement",
        "oe-coverage-contradiction",
        "oe-write-scope",
        "oe-write-scope-label",
        "oe-read-chain",
        "oe-ijson-duplicate",
        "oe-required-members",
        "oe-vocabulary",
        "oe-interval-order",
        "oe-self-refuting",
        "oe-ijson-integer",
        "oe-predicate-type",
        "oe-subject-binding",
        "oe-timestamp-grammar",
        "oe-path-normalized",
        "oe-scope-boundary",
        "oe-coverage-named",
        "oe-keyid-form",
        "oe-commitment-signature",
        "oe-dual-recompute",
        "oe-dual-values-absent",
        "oe-origin-vantage",
        "oe-authoritative-rows",
    ],
    "valid",
    [],
    "The baseline every reject member below is one mutation from. It is the shape "
    "the predicate's tier recompute grades authoritative: vantage below-observed, a "
    "prior commitment signed before the interval opened under a key the observed "
    "party does not hold, a non-empty literal path scope, and a write chain that "
    "reproduces afterRoot.",
)

add(
    "mutation-none-read-only",
    "accept",
    statement(
        predicate(
            intervalId="iv-0002",
            mutation="none",
            interval={
                "beforeRoot": R0,
                "afterRoot": R0,
                "baseResolution": "supplied",
                "openedAt": T_OPEN,
                "sealedAt": T_SEAL,
            },
            writes=[],
            dualValues=[dual("writes.count", "0", "0", "agree")],
        )
    ),
    ["oe-mutation-none", "oe-tier-scope", "oe-self-refuting"],
    "valid",
    [],
    "A read-only interval: the observer watched and saw no mutation inside scope. "
    "This is a positive claim about an interval, not the absence of a record, and it "
    "is the case an artifact-subject rule cannot express. The in-toto/attestation#554 "
    "thread reached the same conclusion from the other side, where a published "
    "production case study was a session whose whole evidentiary value was that it "
    "produced nothing.",
)

add(
    "empty-tree-base-sha256",
    "accept",
    statement(
        predicate(
            intervalId="iv-0003",
            interval={
                "beforeRoot": EMPTY_TREE["sha256"],
                "afterRoot": R1,
                "baseResolution": "empty-tree",
                "openedAt": T_OPEN,
                "sealedAt": T_SEAL,
            },
            observation={
                "vantage": "below-observed",
                "origin": "first-hand",
                "coverage": {"scopeComplete": True, "gaps": []},
                "observedSigners": [OBSERVED_KEYID],
                "priorCommitment": commitment(
                    before_root=EMPTY_TREE["sha256"], interval_id="iv-0003"
                ),
            },
            # The read is taken at R1, AFTER the write that creates the file. It
            # was taken at the empty-tree root, and an accept member of this corpus
            # therefore required a conforming verifier to accept 64 bytes read out
            # of a tree that holds nothing. The interval that opens on nothing is
            # the shape most worth getting right, because it is the one claim a
            # producer can make about the past that no later state can contradict.
            reads=[read_row(path="/srv/app/main.py", pre=R1)],
            writes=[write_row("/srv/app/main.py", EMPTY_TREE["sha256"], R1)],
            dualValues=[dual("writes.count", "1", "1", "agree")],
        )
    ),
    ["oe-empty-tree", "oe-base-vocab", "oe-empty-tree-read"],
    "valid",
    [],
    "The terminal case of base resolution, which is what makes beforeRoot "
    "unconditionally required rather than optional-when-unknown. ASQAV Section 8.2 "
    "resolves a base in the order supplied, recorded-parent, empty tree, and then "
    "rules that where none yields a base the platform 'MUST refuse to emit an "
    "authoritative attestation rather than infer a base from the commit parents, "
    "which are ambiguous for merge and squash commits'. The constant here is the "
    "sha256 empty tree object name, because this record's hashAlgorithm is sha256.",
)

add(
    "voluntary-self-vantage",
    "accept",
    statement(
        predicate(
            intervalId="iv-0004",
            tier="voluntary",
            observation={
                "vantage": "self",
                "origin": "self",
                "coverage": {"scopeComplete": False, "gaps": ["/srv/app/vendor/"]},
                "observedSigners": [OBSERVED_KEYID],
            },
            dualValues=[dual("writes.count", "2", "", "one-sided")],
            doesNotAssert=[
                "that the observation was made independently of the observed party",
                "that the write set is complete",
            ],
        )
    ),
    ["oe-tier-vantage", "oe-agreement"],
    "valid",
    [],
    "A valid record at the weaker tier. ASQAV Section 8.1 carries the prohibition "
    "this member exists to make testable: 'A verifier MUST NOT read a voluntary "
    "attestation as evidence that the attested content corresponds to any "
    "independently observed fact.' The record is well-formed and it is not evidence "
    "of an independently observed fact, and a verifier that conflates those two "
    "readings scores this member and its authoritative twin identically.",
)

add(
    "disagreement-is-the-record-working",
    "accept",
    statement(
        predicate(
            intervalId="iv-0005",
            dualValues=[
                dual("writes.count", "2", "1", "disagree"),
                dual("interval.afterRoot", R2, R_ELSEWHERE, "disagree"),
            ],
        )
    ),
    ["oe-agreement"],
    "valid",
    [],
    "Two facts on which the observer and the observed party disagree. A verifier "
    "MUST NOT reject on a disagreement: this is the one field in the predicate that "
    "catches a lying producer without trusting anyone, and rejecting the record "
    "would delete the finding. A verifier that treats disagree as a fault scores "
    "zero on this member while a verifier that ignores dualValues entirely scores "
    "zero on its reject twin.",
)

# --- reject members, each one mutation from a named accept -----------------

BASELINE = "authoritative-baseline"

add(
    "self-refuting-mutation-none",
    "reject",
    statement(
        predicate(
            intervalId="iv-0101",
            mutation="none",
            interval={
                "beforeRoot": R0,
                "afterRoot": R0,
                "baseResolution": "supplied",
                "openedAt": T_OPEN,
                "sealedAt": T_SEAL,
            },
            writes=[write_row("/srv/app/main.py", R0, R1)],
            dualValues=[dual("writes.count", "0", "0", "agree")],
        ),
        subject_digest=R0,
    ),
    ["oe-self-refuting", "oe-mutation-none"],
    "malformed",
    ["mutation-contradicted-by-writes"],
    "THE SHAPE THIS REPOSITORY DID NOT HAVE: a claim whose own carried evidence "
    "refutes it. The record claims mutation none and carries a write that moved the "
    "root. A verifier that reads the claim and does not recompute over the evidence "
    "accepts it, which is exactly the defect research/442 found in a third party's "
    "gate, where an evidence shape only ran when a producer-set list was non-empty. "
    "Both readings are present in the bytes and they contradict.",
    parent="mutation-none-read-only",
)

add(
    "broken-write-chain",
    "reject",
    statement(
        predicate(
            intervalId="iv-0102",
            writes=[
                write_row("/srv/app/main.py", R0, R1),
                write_row("/srv/app/handler.py", R_ELSEWHERE, R2),
            ],
        )
    ),
    ["oe-chain"],
    "malformed",
    ["write-chain-broken"],
    "The second write's preStateDigest is not the first write's postStateDigest, so "
    "the ordered composition does not carry beforeRoot to afterRoot. The statement "
    "asserts an interval its own rows cannot produce.",
    parent=BASELINE,
)

add(
    "chain-does-not-reach-after-root",
    "reject",
    statement(
        predicate(
            intervalId="iv-0103",
            writes=[write_row("/srv/app/main.py", R0, R1)],
        )
    ),
    ["oe-chain"],
    "malformed",
    ["write-chain-does-not-reach-after-root"],
    "Every link is sound and the last postStateDigest is not afterRoot. A verifier "
    "that checks link-to-link continuity and not the endpoint accepts a record that "
    "under-reports the interval, which is the direction an honest-looking producer "
    "drifts in.",
    parent=BASELINE,
)

add(
    "vacuous-authoritative",
    "reject",
    statement(
        predicate(
            intervalId="iv-0104",
            mutation="none",
            interval={
                "beforeRoot": R0,
                "afterRoot": R0,
                "baseResolution": "supplied",
                "openedAt": T_OPEN,
                "sealedAt": T_SEAL,
            },
            pathScope=[],
            reads=[],
            writes=[],
            dualValues=[],
        ),
        subject_digest=R0,
    ),
    ["oe-tier-scope"],
    "invalid",
    ["authoritative-empty-path-scope"],
    "Attack A2. A record that asserts nothing and grades as the strongest tier: "
    "empty scope, no reads, no writes, roots equal. Clause 3 of the tier recompute "
    "refuses it, and the refusal is invalid rather than a downgrade to voluntary, "
    "because relabelling would let a producer emit an authoritative-shaped record "
    "and rely on the verifier to fix it.",
    parent="mutation-none-read-only",
)

add(
    "authoritative-with-self-vantage",
    "reject",
    statement(
        predicate(
            intervalId="iv-0105",
            observation={
                "vantage": "self",
                "origin": "self",
                "coverage": {"scopeComplete": True, "gaps": []},
                "observedSigners": [OBSERVED_KEYID],
                "priorCommitment": commitment(interval_id="iv-0105"),
            },
        )
    ),
    ["oe-tier-vantage"],
    "invalid",
    ["authoritative-vantage-not-independent"],
    "The tier recompute's first clause. A record that observed itself cannot grade "
    "authoritative no matter what else it carries, and the record still carries a "
    "complete prior commitment, so a verifier checking only for the commitment's "
    "presence accepts it.",
    parent=BASELINE,
)

add(
    "authoritative-without-commitment",
    "reject",
    statement(
        predicate(
            intervalId="iv-0106",
            observation={
                "vantage": "below-observed",
                "origin": "first-hand",
                "coverage": {"scopeComplete": True, "gaps": []},
                "observedSigners": [OBSERVED_KEYID],
            },
        )
    ),
    ["oe-tier-commitment"],
    "malformed",
    ["prior-commitment-absent-for-vantage"],
    "A bare vantage assertion with nothing binding it. The commitment is the only "
    "member that fixes an input to the record before the interval opened, so without "
    "it the vantage claim is a string the producer typed. It is refused in stage one "
    "rather than downgraded, because the Fields section makes the commitment REQUIRED "
    "at this vantage; refusing it there is what leaves the tier recompute with no "
    "reachable input for a commitment clause, and the clause is gone rather than kept "
    "as a sentence no vector can reach.",
    parent=BASELINE,
)

add(
    "commitment-keyid-is-an-observed-signer",
    "reject",
    statement(
        predicate(
            intervalId="iv-0107",
            observation={
                "vantage": "below-observed",
                "origin": "first-hand",
                "coverage": {"scopeComplete": True, "gaps": []},
                "observedSigners": [OBSERVED_KEYID, OBSERVER_KEYID],
                "priorCommitment": commitment(interval_id="iv-0107"),
            },
        )
    ),
    ["oe-commitment-keyid"],
    "invalid",
    ["commitment-keyid-not-disjoint"],
    "Attack A1's discriminator, exercised in the direction that is catchable. The "
    "commitment is signed by a key the record itself names as one the observed party "
    "signs with, so the record declares its own independence and denies it in the "
    "next member. The predicate is explicit that the reverse case -- a second key "
    "the producer simply never declares -- is NOT closed by this check.",
    parent=BASELINE,
)

add(
    "commitment-after-interval-opened",
    "reject",
    statement(
        predicate(
            intervalId="iv-0108",
            observation={
                "vantage": "below-observed",
                "origin": "first-hand",
                "coverage": {"scopeComplete": True, "gaps": []},
                "observedSigners": [OBSERVED_KEYID],
                "priorCommitment": commitment(
                    interval_id="iv-0108", committed_at="2026-09-19T00:00:02Z"
                ),
            },
        )
    ),
    ["oe-commitment-order"],
    "invalid",
    ["commitment-not-prior"],
    "A commitment made two seconds after the interval opened, with a valid signature "
    "over a correct digest. It commits to nothing the observer could not have learned "
    "from the observed party, which is the whole property the member exists to carry.",
    parent=BASELINE,
)

add(
    "commitment-digest-mismatch",
    "reject",
    statement(
        predicate(
            intervalId="iv-0109",
            observation={
                "vantage": "below-observed",
                "origin": "first-hand",
                "coverage": {"scopeComplete": True, "gaps": []},
                "observedSigners": [OBSERVED_KEYID],
                "priorCommitment": commitment(
                    interval_id="iv-0109",
                    override_digest=commitment_digest(
                        AUTHORITY_DIGEST, R_ELSEWHERE, "iv-0109", NONCE
                    ),
                ),
            },
        )
    ),
    ["oe-commitment-digest"],
    "malformed",
    ["commitment-digest-mismatch"],
    "The commitment digest is over a different before-root than the interval names. "
    "The signature over the commitment body still verifies, so a verifier that checks "
    "the signature and not the recomputation accepts a commitment to another "
    "interval's state.",
    parent=BASELINE,
)

add(
    "wrong-empty-tree-constant",
    "reject",
    statement(
        predicate(
            intervalId="iv-0110",
            interval={
                "beforeRoot": EMPTY_TREE["sha1"],
                "afterRoot": R1,
                "baseResolution": "empty-tree",
                "openedAt": T_OPEN,
                "sealedAt": T_SEAL,
            },
            observation={
                "vantage": "below-observed",
                "origin": "first-hand",
                "coverage": {"scopeComplete": True, "gaps": []},
                "observedSigners": [OBSERVED_KEYID],
                "priorCommitment": commitment(
                    before_root=EMPTY_TREE["sha1"], interval_id="iv-0110"
                ),
            },
            reads=[read_row(pre=EMPTY_TREE["sha1"])],
            writes=[write_row("/srv/app/main.py", EMPTY_TREE["sha1"], R1)],
            dualValues=[dual("writes.count", "1", "1", "agree")],
        )
    ),
    ["oe-empty-tree"],
    "malformed",
    ["empty-tree-constant-wrong-algorithm"],
    "The sha1 empty tree object name 4b825dc642cb6eb9a060e54bf8d69288fbee4904 in a "
    "record whose hashAlgorithm is sha256. This is the latent bug in adopting 'the "
    "git empty tree constant' without naming the hash function, and it is a "
    "specific, catchable defect rather than a style point: the value names a root no "
    "sha256 store can hold.",
    parent="empty-tree-base-sha256",
)

add(
    "unknown-base-resolution",
    "reject",
    statement(
        predicate(
            intervalId="iv-0111",
            interval={
                "beforeRoot": R0,
                "afterRoot": R2,
                "baseResolution": "inferred-from-parents",
                "openedAt": T_OPEN,
                "sealedAt": T_SEAL,
            },
        )
    ),
    ["oe-base-vocab"],
    "malformed",
    ["base-resolution-unknown"],
    "A value outside the closed vocabulary, and the one a producer reaches for when "
    "the ordered resolution yields nothing. ASQAV Section 8.2 requires a refusal "
    "there rather than an inference, so a record that names the inference is refused "
    "by the vocabulary itself.",
    parent=BASELINE,
)

add(
    "zero-length-byte-range",
    "reject",
    statement(
        predicate(
            intervalId="iv-0112",
            reads=[
                read_row(
                    start=0,
                    end=0,
                    override_range_digest=range_digest(BLOB, 0, 0),
                )
            ],
        )
    ),
    ["oe-range-nonempty"],
    "malformed",
    ["byte-range-empty"],
    "Attack A3's first half. A zero-length range whose digest is internally "
    "consistent and binds nothing, because the digest of an empty range verifies "
    "against every blob. A read that returned nothing is spelled no-bytes-read.",
    parent=BASELINE,
)

add(
    "range-digest-over-bytes-alone",
    "reject",
    statement(
        predicate(
            intervalId="iv-0113",
            reads=[
                read_row(
                    override_range_digest=hashlib.sha256(BLOB[0:64]).hexdigest(),
                )
            ],
        )
    ),
    ["oe-range-preimage"],
    "malformed",
    ["range-digest-preimage-wrong"],
    "Attack A3's second half, and the one a reimplementation gets wrong by being "
    "reasonable: the digest is sha256 over the range bytes themselves, which is what "
    "a reader assumes 'the digest of the range' means. It is reproducible from any "
    "blob containing those bytes at any offset, so it binds the bytes and not the "
    "read. The predicate's preimage carries the blob length and both offsets.",
    parent=BASELINE,
)

add(
    "glob-path-scope",
    "reject",
    statement(
        predicate(
            intervalId="iv-0114",
            mutation="none",
            interval={
                "beforeRoot": R0,
                "afterRoot": R0,
                "baseResolution": "supplied",
                "openedAt": T_OPEN,
                "sealedAt": T_SEAL,
            },
            pathScope=["/srv/app/**"],
            writes=[],
            dualValues=[dual("writes.count", "0", "0", "agree")],
        ),
        subject_digest=R0,
    ),
    ["oe-scope-glob"],
    "malformed",
    ["path-scope-glob-metacharacter"],
    "Attack A4. A glob makes every write in-scope and the scope check never refuses. "
    "The predicate forbids metacharacters so that a universal scope has to be spelled "
    "as the literal / , where a policy comparing scope against its own expectation "
    "can see it. This closes the legibility half; the predicate is explicit that a "
    "broad honest scope and a broad self-serving one are not separable by any "
    "function of the statement.",
    parent=BASELINE,
)

add(
    "write-outside-scope-marked-in-scope",
    "reject",
    statement(
        predicate(
            intervalId="iv-0115",
            writes=[
                write_row("/srv/app/main.py", R0, R1),
                write_row("/etc/shadow", R1, R2, in_scope=False),
            ],
        )
    ),
    ["oe-write-scope"],
    "invalid",
    ["write-outside-path-scope"],
    "A write to a path no member of pathScope covers, correctly labelled inScope "
    "false, in a record still claiming the authoritative tier. The write chain is "
    "intact and the roots reproduce, so every structural check passes and only the "
    "scope comparison refuses. This is the member that makes pathScope a gate rather "
    "than a label, and the honest label is what isolates it from the mislabel case "
    "below: a producer admitting the write is out of scope may not also claim the "
    "tier that asserts scope coverage.",
    parent=BASELINE,
)

add(
    "write-scope-label-inverted",
    "reject",
    statement(
        predicate(
            intervalId="iv-0120",
            writes=[
                write_row("/srv/app/main.py", R0, R1),
                write_row("/etc/shadow", R1, R2, in_scope=True),
            ],
        )
    ),
    ["oe-write-scope-label"],
    "invalid",
    ["write-in-scope-mislabelled"],
    "The same out-of-scope write, this time labelled inScope true. inScope is not a "
    "producer opinion: it is derivable from path and pathScope, and a label that "
    "contradicts the derivation is how a coverage admission gets deleted while the "
    "record still looks complete. Refused on the label before the scope rule is "
    "reached, which is why the two cases need separate members.",
    parent=BASELINE,
)

add(
    "read-not-chained",
    "reject",
    statement(
        predicate(
            intervalId="iv-0116",
            reads=[read_row(pre=R_ELSEWHERE)],
        )
    ),
    ["oe-read-chain"],
    "malformed",
    ["read-pre-state-not-in-interval"],
    "A read taken against a state root that is neither beforeRoot nor any write's "
    "postStateDigest, so the record claims a read from outside the interval it "
    "attests. Three of the read's four bindings still check out, which is the point: "
    "the fourth is what the interval is for.",
    parent=BASELINE,
)

add(
    "coverage-contradiction",
    "reject",
    statement(
        predicate(
            intervalId="iv-0117",
            observation={
                "vantage": "below-observed",
                "origin": "first-hand",
                "coverage": {"scopeComplete": True, "gaps": ["/srv/app/vendor/"]},
                "observedSigners": [OBSERVED_KEYID],
                "priorCommitment": commitment(interval_id="iv-0117"),
            },
        )
    ),
    ["oe-coverage-contradiction"],
    "malformed",
    ["coverage-self-contradictory"],
    "scopeComplete true beside a gap that lies inside pathScope. The two members "
    "contradict and a verifier MUST NOT prefer either, because preferring one is the "
    "verifier deciding a question the statement left in conflict.",
    parent=BASELINE,
)

add(
    "agreement-not-derivable",
    "reject",
    statement(
        predicate(
            intervalId="iv-0118",
            dualValues=[dual("writes.count", "2", "1", "agree")],
        )
    ),
    ["oe-agreement"],
    "malformed",
    ["agreement-not-derivable"],
    "Two unequal values labelled agree. The label is the producer's and the "
    "comparison is the verifier's, so a record whose label contradicts its own "
    "numbers is the cheapest way to make a disagreement disappear.",
    parent="disagreement-is-the-record-working",
)

_dup_payload = canonical_bytes(statement(predicate(intervalId="iv-0119")))
_dup_payload = _dup_payload.replace(
    b'"intervalId":"iv-0119"',
    b'"intervalId":"iv-0119","intervalId":"iv-0001"',
    1,
)

add(
    "duplicate-member",
    "reject",
    statement(predicate(intervalId="iv-0119")),
    ["oe-ijson-duplicate"],
    "malformed",
    ["duplicate-member"],
    "intervalId appears twice, and the DSSE signature is valid over the bytes that "
    "carry the duplicate. RFC 7493 forbids it and a lenient parser keeps the last "
    "occurrence, so two rails reading identical bytes reach different records. The "
    "signature verifying is what makes this member worth having: the defect is inside "
    "the signed bytes, not around them.",
    parent=BASELINE,
    raw_payload=_dup_payload,
)

add(
    "mutation-none-with-a-null-write",
    "reject",
    statement(
        predicate(
            intervalId="iv-0121",
            mutation="none",
            interval={
                "beforeRoot": R0,
                "afterRoot": R0,
                "baseResolution": "supplied",
                "openedAt": T_OPEN,
                "sealedAt": T_SEAL,
            },
            writes=[write_row("/srv/app/main.py", R0, R0)],
            dualValues=[dual("writes.count", "0", "1", "disagree")],
        ),
        subject_digest=R0,
    ),
    ["oe-self-refuting"],
    "malformed",
    ["mutation-contradicted-by-writes"],
    "The self-refutation in its sharpest form, and the member the mutation sweep "
    "forced into existence. A write that rewrote a file with identical bytes leaves "
    "the root where it was, so the write chain is INTACT and reaches afterRoot: every "
    "structural rule passes and only the mutation claim contradicts the carried row. "
    "The first attempt at this vector moved the root, which the chain rule caught "
    "first, leaving the coherence rule unreachable and therefore unmeasured. Its own "
    "dualValues carry the disagreement, which is the record reporting the "
    "contradiction it contains.",
    parent="mutation-none-read-only",
)

add(
    "mutation-observed-without-writes",
    "reject",
    statement(
        predicate(
            intervalId="iv-0122",
            interval={
                "beforeRoot": R0,
                "afterRoot": R0,
                "baseResolution": "supplied",
                "openedAt": T_OPEN,
                "sealedAt": T_SEAL,
            },
            writes=[],
            dualValues=[dual("writes.count", "0", "0", "agree")],
        ),
        subject_digest=R0,
    ),
    ["oe-self-refuting"],
    "malformed",
    ["mutation-observed-without-writes"],
    "The refutation in the other direction: a record claiming it observed a mutation "
    "and carrying no row that is one. The chain rule returns early on an empty write "
    "set, so nothing but the coherence rule refuses this, which is what makes the two "
    "directions separate members rather than one.",
    parent=BASELINE,
)

add(
    "required-member-absent",
    "reject",
    statement(predicate(intervalId="iv-0123", doesNotAssert=OMIT)),
    ["oe-required-members"],
    "malformed",
    ["required-member-absent:doesNotAssert"],
    "doesNotAssert is missing. It is required precisely because the absence of a "
    "claim has to be written down rather than inferred from silence, and a verifier "
    "that supplies an empty list for it has invented the one member whose job is to "
    "stop a reader inventing things.",
    parent=BASELINE,
)

add(
    "unknown-vantage-at-voluntary-tier",
    "reject",
    statement(
        predicate(
            intervalId="iv-0124",
            tier="voluntary",
            observation={
                "vantage": "kernel",
                "origin": "first-hand",
                "coverage": {"scopeComplete": True, "gaps": []},
                "observedSigners": [OBSERVED_KEYID],
            },
        )
    ),
    ["oe-vocabulary"],
    "malformed",
    ["vantage-unknown"],
    "A vantage outside the closed set, declared at the voluntary tier so that the "
    "tier recompute agrees with the record and the vocabulary rule is the only one "
    "left to refuse it. At the authoritative tier this input is refused for a "
    "different reason, which would leave the vocabulary rule unmeasured: a plausible "
    "new value is exactly what a producer invents, and fail-closed is the only reading "
    "under which an unrecognised vantage does not silently become a weaker one.",
    parent=BASELINE,
)

add(
    "interval-not-ordered",
    "reject",
    statement(
        predicate(
            intervalId="iv-0125",
            interval={
                "beforeRoot": R0,
                "afterRoot": R2,
                "baseResolution": "supplied",
                "openedAt": T_SEAL,
                "sealedAt": T_SEAL,
            },
        )
    ),
    ["oe-interval-order"],
    "malformed",
    ["interval-not-ordered"],
    "An interval that opened and sealed at the same instant. Nothing else in the "
    "predicate reads sealedAt, so this is the one input the ordering rule refuses, "
    "and a zero-width interval is the shape a producer emits when it is stamping a "
    "record rather than watching an interval.",
    parent=BASELINE,
)

# --- indeterminate member -------------------------------------------------

add(
    "anchor-with-no-offline-rule",
    "indeterminate",
    statement(
        predicate(
            intervalId="iv-0201",
            observation={
                "vantage": "below-observed",
                "origin": "first-hand",
                "coverage": {"scopeComplete": True, "gaps": []},
                "observedSigners": [OBSERVED_KEYID],
                "priorCommitment": commitment(
                    interval_id="iv-0201",
                    anchor={
                        "kind": "rfc3161",
                        "digest": hashlib.sha256(b"a token this corpus does not carry").hexdigest(),
                    }
                ),
            },
        )
    ),
    ["oe-anchor-unruled"],
    "indeterminate",
    [],
    "externalAnchor is optional and the predicate says a verifier MAY check the "
    "token's timestamp, while defining no offline validation rule and carrying no "
    "token. A verifier that ignores the member and one that refuses for an "
    "unresolvable anchor are both conforming, so scoring either reading wrong would "
    "be this corpus inventing a rule the predicate does not carry. The predicate's "
    "changelog names the version at which the member acquires a normative reader.",
    readings=[
        {"verdict": "valid", "rationale": "the member is optional and MAY is not MUST"},
        {
            "verdict": "not-established",
            "rationale": "the anchor cannot be resolved from the carried bytes",
        },
    ],
)


def vector_id(body: bytes) -> str:
    return "v" + hashlib.sha256(body).hexdigest()[:ID_HEX]


# --- members added by the adversarial pass --------------------------------
# Each one is a record that satisfied every rule this verifier implemented and
# still misrepresented what executed. They are pinned here rather than described
# in a report, because a report expires and a corpus member runs on every push.

add(
    "subject-is-not-the-after-root",
    "reject",
    statement(predicate(intervalId="iv-0201"), subject_digest=R_ELSEWHERE),
    ["oe-subject-binding"],
    "malformed",
    ["subject-not-the-after-root"],
    "The record an admission controller would admit. Every predicate member is "
    "honest and the subject names a state this interval never reached, so the "
    "evidence describes one thing and the decision is taken about another. Nothing "
    "in the predicate bound the two while the subject was unread.",
    parent=BASELINE,
)

add(
    "predicate-type-is-another-predicates",
    "reject",
    _typed_statement("https://in-toto.io/attestation/runtime-trace/v0.1"),
    ["oe-predicate-type"],
    "malformed",
    ["predicate-type-unexpected"],
    "An observed-effect body wearing somebody else's predicate type. A consumer "
    "routes by predicateType and then applies that predicate's rules to these "
    "members, so the record means whatever the other predicate says these names mean.",
    parent=BASELINE,
)

add(
    "commitment-timestamp-with-an-offset",
    "reject",
    statement(
        predicate(
            intervalId="iv-0203",
            observation={
                "vantage": "below-observed",
                "origin": "first-hand",
                "coverage": {"scopeComplete": True, "gaps": []},
                "observedSigners": [OBSERVED_KEYID],
                "priorCommitment": commitment(
                    interval_id="iv-0203", committed_at="2026-09-18T20:00:00-05:00"
                ),
            },
        )
    ),
    ["oe-timestamp-grammar"],
    "malformed",
    ["timestamp-not-utc-basic:priorCommitment.committedAt"],
    "2026-09-18T20:00:00-05:00 is 2026-09-19T01:00:00Z, an hour after this interval "
    "opened. It sorts before openedAt as a string, so the ordering gate that makes "
    "the commitment PRIOR passed on a commitment made afterwards. One grammar is "
    "what makes a lexical comparison a comparison of instants.",
    parent=BASELINE,
)

add(
    "write-path-escapes-with-dot-dot",
    "reject",
    statement(
        predicate(
            intervalId="iv-0204",
            writes=[
                write_row("/srv/app/main.py", R0, R1),
                write_row("/srv/app/../../../etc/shadow", R1, R2),
            ],
        )
    ),
    ["oe-path-normalized"],
    "malformed",
    ["path-not-normalized"],
    "A write to /etc/shadow that starts with /srv/app/ and travels as in-scope. "
    "Containment was a string prefix, so the traversal did the work; the path is "
    "refused before any scope question is asked.",
    parent=BASELINE,
)

add(
    "write-under-a-sibling-prefix",
    "reject",
    statement(
        predicate(
            intervalId="iv-0205",
            pathScope=["/srv/app"],
            writes=[
                write_row("/srv/app/main.py", R0, R1),
                write_row("/srv/application-secrets/id_ed25519", R1, R2),
            ],
        )
    ),
    ["oe-scope-boundary"],
    "invalid",
    ["write-in-scope-mislabelled"],
    "/srv/application-secrets/id_ed25519 starts with /srv/app and is not under it. "
    "A policy that compares pathScope against its own expectation reads /srv/app and "
    "admits a write to a different directory, which is the scope check agreeing with "
    "the producer about where the producer was.",
    parent=BASELINE,
)

add(
    "bytes-read-from-the-empty-tree",
    "reject",
    statement(
        predicate(
            intervalId="iv-0206",
            interval={
                "beforeRoot": EMPTY_TREE["sha256"],
                "afterRoot": R1,
                "baseResolution": "empty-tree",
                "openedAt": T_OPEN,
                "sealedAt": T_SEAL,
            },
            observation={
                "vantage": "below-observed",
                "origin": "first-hand",
                "coverage": {"scopeComplete": True, "gaps": []},
                "observedSigners": [OBSERVED_KEYID],
                "priorCommitment": commitment(
                    before_root=EMPTY_TREE["sha256"], interval_id="iv-0206"
                ),
            },
            reads=[read_row(pre=EMPTY_TREE["sha256"])],
            writes=[write_row("/srv/app/main.py", EMPTY_TREE["sha256"], R1)],
            dualValues=[dual("writes.count", "1", "1", "agree")],
        )
    ),
    ["oe-empty-tree-read"],
    "malformed",
    ["bytes-read-from-the-empty-tree"],
    "There was nothing before, and here are 64 bytes read out of the nothing. The "
    "empty-tree terminal case is the strongest claim a producer can make about the "
    "past, which is what makes it the one worth dressing a populated tree in.",
    parent="empty-tree-base-sha256",
)

add(
    "incomplete-coverage-naming-no-gap",
    "reject",
    statement(
        predicate(
            intervalId="iv-0207",
            observation={
                "vantage": "below-observed",
                "origin": "first-hand",
                "coverage": {"scopeComplete": False, "gaps": []},
                "observedSigners": [OBSERVED_KEYID],
                "priorCommitment": commitment(interval_id="iv-0207"),
            },
        )
    ),
    ["oe-coverage-named"],
    "malformed",
    ["coverage-incomplete-without-gaps"],
    "The observation admits it did not cover its own scope and names no gap, and it "
    "graded authoritative: clause 4 of the tier recompute asks whether every member "
    "of gaps lies outside pathScope, and an empty list satisfies that vacuously. The "
    "gap a producer declines to name is where the writes went.",
    parent=BASELINE,
)

add(
    "observed-signer-in-another-case",
    "reject",
    statement(
        predicate(
            intervalId="iv-0208",
            observation={
                "vantage": "below-observed",
                "origin": "first-hand",
                "coverage": {"scopeComplete": True, "gaps": []},
                "observedSigners": [OBSERVER_KEYID.upper()],
                "priorCommitment": commitment(interval_id="iv-0208"),
            },
        )
    ),
    ["oe-keyid-form"],
    "malformed",
    ["keyid-not-lowercase-hex"],
    "observedSigners names the committing key itself, uppercased, and the "
    "commitment carries it lowercased. The record therefore SAYS the key that made "
    "the prior commitment is a key the observed party signs with, and the "
    "disjointness check -- the predicate's offline discriminator -- passed, because "
    "it is a string comparison and two spellings of one key are two strings. No "
    "second key was needed.",
    parent=BASELINE,
)

add(
    "commitment-signed-by-nobody",
    "reject",
    statement(
        predicate(
            intervalId="iv-0209",
            observation={
                "vantage": "below-observed",
                "origin": "first-hand",
                "coverage": {"scopeComplete": True, "gaps": []},
                "observedSigners": [OBSERVED_KEYID],
                "priorCommitment": _unsigned_commitment("iv-0209"),
            },
        )
    ),
    ["oe-commitment-signature"],
    "invalid",
    ["commitment-signature-invalid"],
    "Sixty-four zero bytes where the commitment signature goes. The commitment is "
    "the whole basis of the authoritative tier and its signature was never checked, "
    "so the member that carries the vantage claim was carrying it unsigned.",
    parent=BASELINE,
)

add(
    "dual-value-the-record-refutes",
    "reject",
    statement(
        predicate(
            intervalId="iv-0210",
            dualValues=[dual("writes.count", "7", "7", "agree")],
        )
    ),
    ["oe-dual-recompute"],
    "malformed",
    ["dual-value-not-recomputable"],
    "The record carries two writes and reports having observed seven, and agrees "
    "with itself about it. dualValues is the member the predicate offers as the one "
    "that catches a lying producer without trusting anyone, and the observed side "
    "was a free string, so the cross-check could be set to any number including one "
    "the same signed bytes refute.",
    parent=BASELINE,
)

add(
    "dual-value-with-no-values",
    "reject",
    statement(
        predicate(
            intervalId="iv-0211",
            dualValues=[dual("observed.session", "", "", "one-sided")],
        )
    ),
    ["oe-dual-values-absent"],
    "malformed",
    ["dual-value-carries-no-value"],
    "A comparison of nothing against nothing, labelled one-sided. A consumer that "
    "counts dual values as corroboration counts this one, and a record can carry as "
    "many of them as it likes.",
    parent=BASELINE,
)

add(
    "vacuous-authoritative-universal-scope",
    "reject",
    statement(
        predicate(
            intervalId="iv-0212",
            mutation="none",
            interval={
                "beforeRoot": EMPTY_TREE["sha256"],
                "afterRoot": EMPTY_TREE["sha256"],
                "baseResolution": "empty-tree",
                "openedAt": T_OPEN,
                "sealedAt": T_SEAL,
            },
            observation={
                "vantage": "below-observed",
                "origin": "first-hand",
                "coverage": {"scopeComplete": True, "gaps": []},
                "observedSigners": [OBSERVED_KEYID],
                "priorCommitment": commitment(
                    before_root=EMPTY_TREE["sha256"], interval_id="iv-0212"
                ),
            },
            pathScope=["/"],
            reads=[],
            writes=[],
            dualValues=[],
        ),
        subject_digest=EMPTY_TREE["sha256"],
    ),
    ["oe-authoritative-rows"],
    "invalid",
    ["authoritative-without-observed-rows"],
    "Attack A2 with two characters changed. The predicate records A2 as closed by "
    "the non-empty pathScope clause, and the vacuous record spelled its scope as the "
    "literal / instead of the empty list: the whole filesystem was empty, nothing "
    "happened anywhere, graded the strongest tier. A positive claim about an interval "
    "needs a row to be a claim about anything.",
    parent="empty-tree-base-sha256",
)

_ijson_statement = statement(
    predicate(
        intervalId="iv-0213",
        reads=[
            {
                "path": "/srv/app/config.yaml",
                "preStateDigest": R0,
                # An unpublished blob, so the range preimage rule SKIPS this row.
                # With the published blob the edited offset also broke the preimage
                # and the mutation sweep reported the integer rule as inert: two
                # rules refused one member and neither was measured.
                "blobDigest": _INVENTED_BLOB_DIGEST,
                "readState": "bytes-read",
                "byteRange": {"start": 0, "end": 27},
                "rangeDigest": range_digest(_INVENTED_BLOB, 0, 27),
            }
        ],
    )
)
# canonical.py REFUSES to encode an unsafe integer, which is the producer side of
# the I-JSON rule working. The bytes are edited afterwards because a hostile rail
# does not call our encoder, and the open question was only ever whether this
# verifier CONSUMES what such a rail emits.
_ijson_payload = canonical_bytes(_ijson_statement).replace(
    b'"end":27', b'"end":9007199254740993', 1
)
if b"9007199254740993" not in _ijson_payload:
    raise SystemExit("the I-JSON member's byte edit did not apply")

add(
    "byte-range-past-the-ijson-bound",
    "reject",
    _ijson_statement,
    ["oe-ijson-integer"],
    "malformed",
    ["integer-not-ijson-safe"],
    "A byte range ending at 9007199254740993. The Prerequisites section states the "
    "RFC 7493 bound as a MUST and canonical.py enforces it on the way out, so the "
    "rule was measured on the producer and unmeasured on the verifier. A rail that "
    "reads this into a double reads 9007199254740992 and two rails disagree about "
    "identical signed bytes.",
    parent=BASELINE,
    raw_payload=_ijson_payload,
)

add(
    "log-import-wearing-a-vantage",
    "reject",
    statement(
        predicate(
            intervalId="iv-0215",
            observation={
                "vantage": "below-observed",
                "origin": "log-import",
                # software-only on purpose, and this member is the reason the
                # vector isolates one rule. Without it the platform rule below
                # refuses this record as well, both rules answer malformed, and a
                # harness comparing verdicts sees removing the vantage rule change
                # nothing -- which is how it reported the vantage rule INERT while
                # the rule was the only thing refusing the record for the right
                # reason. The importer here declares its platform honestly and
                # lies about one thing only.
                "runtime": {"platform": "software-only"},
                "coverage": {"scopeComplete": True, "gaps": []},
                "observedSigners": [OBSERVED_KEYID],
                "priorCommitment": commitment(interval_id="iv-0215"),
            },
        )
    ),
    ["oe-origin-vantage"],
    "malformed",
    ["origin-cannot-carry-below-observed-vantage"],
    "A record assembled from another vendor's exported log and emitted as a "
    "first-hand observation made below the party it describes. Before the origin "
    "member existed, this record was the honest baseline with a different "
    "narrator: no field in it was false, because there was no field in which an "
    "importer had to say it imported. The sibling vocabulary registers the enum "
    "and the rule that binds the vantage to it. The platform declaration is "
    "correct here, which is what leaves the vantage as the only lie and the "
    "vantage rule as the only thing refusing it.",
    parent=BASELINE,
)

add(
    "read-row-nobody-can-check",
    "accept",
    statement(
        predicate(
            intervalId="iv-0214",
            reads=[
                {
                    "path": "/srv/app/secrets.env",
                    "preStateDigest": R0,
                    "blobDigest": _INVENTED_BLOB_DIGEST,
                    "readState": "bytes-read",
                    "byteRange": {"start": 0, "end": 27},
                    "rangeDigest": range_digest(_INVENTED_BLOB, 0, 27),
                }
            ],
        )
    ),
    ["oe-range-preimage", "oe-read-chain"],
    "valid",
    [],
    "ACCEPTED, and pinned because it is accepted. Path, pre-state, blob digest, "
    "offsets and range digest are internally consistent over a blob no other party "
    "holds, so a verifier without the blob checks three bindings that all hold and "
    "the fourth is the one that matters. The predicate says this in its own residual "
    "section; the member is here so that a later change which starts refusing it is "
    "visible as a change rather than as a fix.",
)


_IMPORTED_OBSERVATION: dict[str, Any] = {
    "vantage": "peer",
    "origin": "log-import",
    "runtime": {"platform": "software-only"},
    "coverage": {"scopeComplete": True, "gaps": []},
    "observedSigners": [OBSERVED_KEYID],
}


def _imported(**over: Any) -> dict[str, Any]:
    """The imported observation with one member replaced, never merged."""
    out = dict(_IMPORTED_OBSERVATION)
    for key, value in over.items():
        if isinstance(value, _Omit):
            del out[key]
        else:
            out[key] = value
    return out


add(
    "imported-log-software-only",
    "accept",
    statement(predicate(intervalId="iv-0216", tier="voluntary", observation=_imported())),
    ["oe-origin-platform"],
    "valid",
    [],
    "The honest importer. A control plane exported its log, this party holds it, and "
    "the record says so: the origin names the import, the vantage is peer rather than "
    "below the observed party, the tier recomputes to voluntary, and the runtime is "
    "software-only because the importing party has no quote to present for whatever "
    "the exporting platform measured. This is the member the two refusals below are "
    "one mutation from, and it is why refusing every imported record scores zero "
    "rather than full marks.",
)

add(
    "imported-log-claiming-hardware",
    "reject",
    statement(
        predicate(
            intervalId="iv-0217",
            tier="voluntary",
            observation=_imported(runtime={"platform": "tpm2"}),
        )
    ),
    ["oe-origin-platform"],
    "malformed",
    ["import-origin-requires-software-only-platform"],
    "An imported log wearing the exporting platform's hardware root. The importer "
    "cannot present the quote, so the platform claim is a report about somebody "
    "else's machine carried as if it were a measurement of this one. Every other "
    "field in the record is the accepted member's.",
    parent="imported-log-software-only",
)

add(
    "imported-log-with-no-platform",
    "reject",
    statement(
        predicate(
            intervalId="iv-0218",
            tier="voluntary",
            observation=_imported(runtime=OMIT),
        )
    ),
    ["oe-origin-platform"],
    "malformed",
    ["import-origin-requires-software-only-platform"],
    "The same import with the platform declaration left out. Silence is the shape "
    "the rule has to refuse as well, because a consumer reading a record with no "
    "platform member has no way to tell an importer from a party that stood on the "
    "machine, and the absent member is the cheaper forgery of the two.",
    parent="imported-log-software-only",
)


def emit() -> None:
    """Serialize every draft, name it after its own bytes, write it, prune.

    The prune is not tidiness. A statement file left behind by an earlier build is
    a vector with no builder: it survives every replay, anything reading the
    directory counts it, and nothing regenerates it.
    """
    statements_dir = os.path.join(HERE, "statements")
    os.makedirs(statements_dir, exist_ok=True)

    slug_to_id: dict[str, str] = {}
    bodies: list[tuple[dict[str, Any], bytes, str]] = []
    for draft in DRAFTS:
        body = json.dumps(draft["envelope"], indent=2, sort_keys=True).encode() + b"\n"
        ident = vector_id(body)
        if ident in slug_to_id.values():
            raise SystemExit(f"identifier collision on {draft['slug']}")
        slug_to_id[draft["slug"]] = ident
        bodies.append((draft, body, ident))

    vectors: list[dict[str, Any]] = []
    keep: set[str] = set()
    for draft, body, ident in bodies:
        rel = f"statements/{ident}.json"
        with open(os.path.join(HERE, rel), "wb") as fh:
            fh.write(body)
        keep.add(f"{ident}.json")
        entry: dict[str, Any] = {
            "id": ident,
            "slug": draft["slug"],
            "kind": draft["kind"],
            "file": rel,
            "conditions": draft["conditions"],
            "expected": {"verdict": draft["verdict"], "codes": draft["codes"]},
            "cites": draft["cites"],
        }
        if draft["parent"] is not None:
            entry["parent"] = slug_to_id[draft["parent"]]
        if draft["readings"] is not None:
            entry["readings"] = draft["readings"]
        vectors.append(entry)

    for stale in sorted(os.listdir(statements_dir)):
        if stale.endswith(".json") and stale not in keep:
            os.remove(os.path.join(statements_dir, stale))

    counts = {
        "accept": sum(1 for v in vectors if v["kind"] == "accept"),
        "reject": sum(1 for v in vectors if v["kind"] == "reject"),
        "indeterminate": sum(1 for v in vectors if v["kind"] == "indeterminate"),
    }

    manifest: dict[str, Any] = {
        "suite": SUITE,
        "predicateType": PREDICATE_TYPE,
        "predicateSpec": PREDICATE_SPEC,
        "payloadType": PAYLOAD_TYPE,
        "algorithm": {"envelope": "ed25519", "digest": "sha256"},
        "keys": {
            "observer": {"keyid": OBSERVER_KEYID, "publicKey": OBSERVER_PUB},
            "observedParty": {"keyid": OBSERVED_KEYID, "publicKey": OBSERVED_PUB},
        },
        "keyNote": (
            "PUBLISHED TEST KEYS, derived from fixed seeds in gen_vectors.py. The "
            "observedParty key signs nothing in this corpus: it exists so that "
            "observedSigners names a real key identifier and the disjointness check "
            "has something to be disjoint from."
        ),
        "emptyTree": EMPTY_TREE,
        "counts": counts,
        "conditions": CONDITIONS,
        "note": (
            "Every reject member declares the accept member it is one mutation from, "
            "so a verifier that refuses everything scores zero rather than full "
            "marks. The indeterminate member declares the readings a conforming "
            "verifier could take, because the predicate does not choose between them."
        ),
        "vectors": vectors,
    }
    manifest["corpusDigest"] = corpus_digest(manifest)

    with open(os.path.join(HERE, "MANIFEST.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")

    lines = [
        "# Observed Effect conformance vectors",
        "",
        "Generated by `gen_vectors.py`. Do not edit: every regeneration rewrites it.",
        "",
        f"Predicate: [{PREDICATE_TYPE}](../{PREDICATE_SPEC})",
        "",
        f"Corpus digest: `{manifest['corpusDigest']}`",
        "",
        # This line used to restate the accept and the reject counts beside the
        # two quantities the registration sentence below does not carry. Once the
        # corpus was registered in scripts/count-gate.py those two became derived
        # and published, and a second sentence publishing the same two is the
        # drift that gate exists to refuse: two sentences about one corpus, going
        # stale at two rates, both looking authoritative. So this line now carries
        # only what nothing else does.
        f"{counts['indeterminate']} member(s) are indeterminate, and the corpus "
        f"exercises {len(CONDITIONS)} conditions.",
        "",
        # The sentence scripts/count-gate.py checks a registered corpus's counts
        # against, in the wording that gate fixes. It is emitted here rather than
        # written into INDEX.md because this file rewrites INDEX.md on every run,
        # so a hand-added sentence would vanish on the next regeneration and the
        # gate would then fail on a claim site that had silently disappeared.
        # The wording says "of which" rather than equating the total to the sum:
        # this corpus carries a third bucket for the member whose reading the
        # predicate does not choose between, so accept plus reject is less than
        # the total by exactly that one.
        f"This corpus is {len(vectors)} vectors, of which {counts['accept']} a "
        f"conformant verifier must not fail closed on and {counts['reject']} it "
        "must reject.",
        "",
        "| id | kind | verdict | slug | conditions |",
        "| --- | --- | --- | --- | --- |",
    ]
    for entry in vectors:
        lines.append(
            f"| `{entry['id']}` | {entry['kind']} | {entry['expected']['verdict']} "
            f"| {entry['slug']} | {', '.join(entry['conditions'])} |"
        )
    lines.append("")
    with open(os.path.join(HERE, "INDEX.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    print(
        f"wrote {len(vectors)} members "
        f"({counts['accept']} accept, {counts['reject']} reject, "
        f"{counts['indeterminate']} indeterminate), "
        f"corpus {manifest['corpusDigest'][:12]}"
    )


if __name__ == "__main__":
    emit()
