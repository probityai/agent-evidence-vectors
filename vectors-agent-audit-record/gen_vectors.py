#!/usr/bin/env python3
"""Generate the agent audit record conformance corpus.

Regenerate byte-identically:

    uv run --extra generators python vectors-agent-audit-record/gen_vectors.py

The corpus is Appendix B of the Internet-Draft
draft-gilda-wimse-agent-audit-record-03, member for member. Every member is a
complete DSSE envelope whose payload is an in-toto Statement v1 carrying an agent
audit record. The vector file carries the bytes and nothing else; the verdict a
verifier must reach, and the Appendix B identifier the member answers to, live in
MANIFEST.json.

Each reject member is built from the accept member the Appendix B `from` column
names, by the one mutation its row describes, so a verifier that refuses every
input scores nothing here. Where a mutation moves a value another member is a
function of (a root, a request digest), the dependent value moves with it, which
is what "roots and chain moved to match" means in the rows that say it.

Ed25519 signatures are deterministic (RFC 8032) and every key below comes from a
fixed seed, so the corpus is byte-identical on every machine. The keys are
PUBLISHED TEST KEYS.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import sys
from collections.abc import Callable
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from canonical import canonical_bytes, digest  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: E402
    Ed25519PrivateKey,
)
from digest import corpus_digest  # noqa: E402

SUITE = "agent-audit-record-conformance"
PREDICATE_TYPE = (
    "https://probityai.github.io/agent-evidence-vectors/predicate/v1/agent-audit-record"
)
PREDICATE_DOCUMENT = "https://datatracker.ietf.org/doc/draft-gilda-wimse-agent-audit-record/03/"
DRAFT = "draft-gilda-wimse-agent-audit-record-03"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
ID_HEX = 16

EMPTY_TREE = {
    "sha1": hashlib.sha1(b"tree 0\x00", usedforsecurity=False).hexdigest(),
    "sha256": hashlib.sha256(b"tree 0\x00").hexdigest(),
}

OBSERVER_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("00" * 31 + "33"))
AGENT_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("00" * 31 + "44"))


def raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


OBSERVER_PUB = raw_public(OBSERVER_KEY).hex()
AGENT_PUB = raw_public(AGENT_KEY).hex()
OBSERVER_KEYID = hashlib.sha256(raw_public(OBSERVER_KEY)).hexdigest()[:32]
AGENT_KEYID = hashlib.sha256(raw_public(AGENT_KEY)).hexdigest()[:32]


def h(label: str) -> str:
    """A literal digest over literal bytes, so a reader can recompute every one."""
    return hashlib.sha256(("agent-audit-record/" + label).encode()).hexdigest()


# ---------------------------------------------------------------------------
# The baseline, A1: every member present, permit beside occurred, all five tier
# clauses met.
# ---------------------------------------------------------------------------

CORRELATION_ID = "urn:example:corr:7f3a91c4"
RECORD_ID = "urn:example:record:7f3a91c4"
BEFORE = h("root/before")
AFTER = h("root/after-settlement-write")
LEDGER_PATH = "/srv/ledger/settlements.jsonl"
OTHER_REQUEST = h("request/another-call-in-the-same-interval")


def request_digest(pred: dict[str, Any]) -> str:
    """RFC 8785 digest over action, argumentsDigest, resourceId and resourceKind;
    under not-bindable the object holds no argumentsDigest member at all."""
    resource = pred["resource"]
    body: dict[str, Any] = {
        "action": pred["decision"]["action"],
        "resourceId": resource["id"],
        "resourceKind": resource["kind"],
    }
    if resource["binding"] == "digest-bound":
        body["argumentsDigest"] = resource["argumentsDigest"]
    return digest(body)


def commitment_digest(pred: dict[str, Any]) -> str:
    return digest(
        {
            "authorityDigest": pred["delegation"]["authorityDigest"],
            "beforeRoot": pred["effect"]["interval"]["beforeRoot"],
            "recordId": pred["recordId"],
            "witnessNonce": pred["observation"]["priorCommitment"]["witnessNonce"],
        }
    )


def seal_commitment(pred: dict[str, Any]) -> None:
    """Derive the commitment digest from the finished record and sign it.

    The draft defines no preimage for ``sig``, so no rule reads it and no member
    tests it; it is carried so the commitment has all five of its members.
    """
    commitment = pred["observation"]["priorCommitment"]
    commitment["commitmentDigest"] = commitment_digest(pred)
    signed = OBSERVER_KEY.sign(commitment["commitmentDigest"].encode("ascii"))
    commitment["sig"] = base64.b64encode(signed).decode()


def baseline() -> dict[str, Any]:
    pred: dict[str, Any] = {
        "recordId": RECORD_ID,
        "tier": "authoritative",
        "hashAlgorithm": "sha256",
        "agent": {
            "id": "spiffe://prod.example.org/ns/payments/sa/reconciler",
            "credentialDigest": h("credential/reconciler-wpt"),
            "authentication": "wimse-wpt",
            "signers": [AGENT_KEYID],
        },
        "delegation": {
            "subject": "user:alice@example.org",
            "subjectKind": "user",
            "authorityDigest": h("authority/alice-grants-reconciler-ledger-write"),
        },
        "resource": {
            "kind": "tool",
            "id": "mcp://files/write",
            "binding": "digest-bound",
            "argumentsDigest": h("arguments/settlements-append"),
        },
        "decision": {
            "action": "write",
            "requestDigest": "",
            "reported": "permit",
            "decisionPointId": "pdp://prod.example.org/authz-1",
            "policyDigest": h("policy/ledger-writers"),
            "reportedAt": "2026-09-19T11:04:02Z",
        },
        "effect": {
            "observed": "occurred",
            "interval": {
                "beforeRoot": BEFORE,
                "afterRoot": AFTER,
                "baseResolution": "supplied",
                "openedAt": "2026-09-19T11:04:01Z",
                "sealedAt": "2026-09-19T11:04:06Z",
            },
            "pathScope": ["/srv/ledger/"],
            "writes": [],
        },
        "agreement": "agree",
        "correlation": {
            "id": CORRELATION_ID,
            "scope": "cross-party",
            "timeBasis": "asserted",
        },
        "posture": {
            "reported": "allowlist",
            "reportedDigest": h("posture/allowlist"),
            "observed": "allowlist",
            "observedDigest": h("posture/allowlist"),
            "assessedAt": "2026-09-19T06:00:00Z",
            "agreement": "agree",
        },
        "remediation": [],
        "observation": {
            "vantage": "below-observed",
            "coverage": {"scopeComplete": True, "gaps": []},
            "priorCommitment": {
                "committedAt": "2026-09-19T11:03:58Z",
                "witnessNonce": h("nonce/observer-chosen"),
                "commitmentDigest": "",
                "keyid": OBSERVER_KEYID,
                "sig": "",
            },
        },
        "fieldEvidence": {
            "agent": "producer-asserted",
            "correlation": "producer-asserted",
            "decision": "producer-asserted",
            "delegation": "producer-asserted",
            "posture": "substrate-covered",
            "remediation": "substrate-covered",
            "resource": "substrate-covered",
        },
        "doesNotAssert": [
            "that this record has been or will be retained for any period",
            "that the reported decision is the decision the policy engine evaluated",
        ],
        "issuedAt": "2026-09-19T11:04:11Z",
        "evaluation": {"status": "evaluated"},
    }
    request = request_digest(pred)
    pred["decision"]["requestDigest"] = request
    pred["effect"]["writes"] = [write(LEDGER_PATH, BEFORE, AFTER, request)]
    seal_commitment(pred)
    return pred


def write(path: str, pre: str, post: str, request: str, in_scope: bool = True) -> dict[str, Any]:
    return {
        "path": path,
        "preStateDigest": pre,
        "postStateDigest": post,
        "requestDigest": request,
        "inScope": in_scope,
    }


def statement(pred: dict[str, Any], *, second_subject: bool = True) -> dict[str, Any]:
    subject = [{"name": CORRELATION_ID, "digest": {"sha256": pred["decision"]["requestDigest"]}}]
    if second_subject:
        after = pred["effect"]["interval"]["afterRoot"]
        subject.append({"name": CORRELATION_ID + "/after", "digest": {"sha256": after}})
    return {
        "_type": STATEMENT_TYPE,
        "subject": subject,
        "predicateType": PREDICATE_TYPE,
        "predicate": pred,
    }


def pae(payload: bytes) -> bytes:
    kind = PAYLOAD_TYPE.encode()
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


def envelope(payload: bytes) -> dict[str, Any]:
    sig = OBSERVER_KEY.sign(pae(payload))
    return {
        "payload": base64.b64encode(payload).decode(),
        "payloadType": PAYLOAD_TYPE,
        "signatures": [{"keyid": OBSERVER_KEYID, "sig": base64.b64encode(sig).decode()}],
    }


# ---------------------------------------------------------------------------
# The members. Each is (draft id, kind, from, what the row says, how it is
# built, expected verdict, expected codes, derived tier, readings).
#
# A row the draft leaves open (N1, N2) has readings and NO expected verdict.
# Appendix B's column prints "indeterminate" for those rows, and that word is
# the row's kind, not a verdict: one of the readings is also called
# indeterminate, but the other is valid, and a single expected verdict would
# score a verifier taking either listed reading as wrong. Revision 01 shipped
# exactly that, found by an outside reader before a second implementation ran.
# ---------------------------------------------------------------------------

Built = dict[str, Any]
Member = dict[str, Any]
MEMBERS: list[Member] = []
PREDICATES: dict[str, dict[str, Any]] = {}


def member(
    draft_id: str,
    slug: str,
    parent: str | None,
    row: str,
    build: Callable[[], Built],
    verdict: str | None,
    codes: list[str] | None = None,
    tier: str | None = None,
    readings: list[dict[str, str]] | None = None,
) -> None:
    if (verdict is None) == (readings is None):
        raise SystemExit(
            f"{draft_id}: a settled row carries one expected verdict and an open row "
            "carries readings, never both and never neither"
        )
    if readings is not None and len({r["verdict"] for r in readings}) < 2:
        raise SystemExit(f"{draft_id}: an open row lists at least two distinct verdicts")
    kinds = {"valid": "accept", "malformed": "reject"}
    kind = "indeterminate" if verdict is None else kinds[verdict]
    MEMBERS.append(
        {
            "draftId": draft_id,
            "slug": slug,
            "kind": kind,
            "parent": parent,
            "row": row,
            "build": build,
            "verdict": verdict,
            "codes": codes or [],
            "tier": tier,
            "readings": readings,
        }
    )


def signed(pred: dict[str, Any], *, second_subject: bool = True) -> Built:
    """A member whose payload is the RFC 8785 bytes of its Statement."""
    return {"payload": canonical_bytes(statement(pred, second_subject=second_subject))}


def from_pred(name: str) -> dict[str, Any]:
    return copy.deepcopy(PREDICATES[name])


def accept(name: str, pred: dict[str, Any]) -> Built:
    PREDICATES[name] = copy.deepcopy(pred)
    return signed(pred)


def rebind_request(pred: dict[str, Any]) -> None:
    """Move every value that is a function of the request digest."""
    old = pred["decision"]["requestDigest"]
    new = request_digest(pred)
    pred["decision"]["requestDigest"] = new
    for w in pred["effect"]["writes"]:
        if w["requestDigest"] == old:
            w["requestDigest"] = new


# --- accept members -------------------------------------------------------


def build_a1() -> Built:
    return accept("A1", baseline())


def build_a2() -> Built:
    pred = baseline()
    pred["decision"]["reported"] = "deny"
    pred["effect"]["observed"] = "none"
    pred["effect"]["writes"] = []
    pred["effect"]["interval"]["afterRoot"] = BEFORE
    return accept("A2", pred)


def build_a3() -> Built:
    pred = baseline()
    pred["decision"]["reported"] = "deny"
    pred["agreement"] = "disagree"
    return accept("A3", pred)


def build_a4() -> Built:
    pred = baseline()
    pred["remediation"] = [
        {
            "cause": "session-revoked",
            "signalReceivedAt": "2026-09-19T11:04:07Z",
            "enforcedAt": "2026-09-19T11:04:09Z",
            "enforcement": "not-enforced",
            "postEnforcementEffect": "occurred",
            "postEnforcementRoot": h("root/after-post-revocation-write"),
        }
    ]
    return accept("A4", pred)


def build_a5() -> Built:
    pred = baseline()
    pred["tier"] = "voluntary"
    pred["observation"]["vantage"] = "self"
    del pred["observation"]["priorCommitment"]
    pred["fieldEvidence"] = {key: "producer-asserted" for key in pred["fieldEvidence"]}
    return accept("A5", pred)


def build_a6() -> Built:
    pred = baseline()
    pred["tier"] = "voluntary"
    pred["resource"]["binding"] = "not-bindable"
    del pred["resource"]["argumentsDigest"]
    rebind_request(pred)
    return accept("A6", pred)


def build_a7() -> Built:
    pred = from_pred("A2")
    after = h("root/after-another-requests-write")
    pred["effect"]["writes"] = [write(LEDGER_PATH, BEFORE, after, OTHER_REQUEST)]
    pred["effect"]["interval"]["afterRoot"] = after
    return accept("A7", pred)


def build_a8() -> Built:
    pred = from_pred("A2")
    after = h("root/after-unattributed-write")
    pred["effect"]["writes"] = [write(LEDGER_PATH, BEFORE, after, "unattributed")]
    pred["effect"]["interval"]["afterRoot"] = after
    pred["effect"]["observed"] = "unknown"
    pred["agreement"] = "indeterminate"
    return accept("A8", pred)


def build_a9() -> Built:
    pred = baseline()
    pred["effect"]["writes"] = []
    pred["effect"]["interval"]["afterRoot"] = BEFORE
    pred["effect"]["observed"] = "none"
    pred["agreement"] = "not-exercised"
    return accept("A9", pred)


def build_a10() -> Built:
    """A2's bytes with one difference: the decision point could not evaluate,
    because its standing source was unavailable, and enforced a deny. Under -01
    this record and A2 were the same record."""
    pred = from_pred("A2")
    pred["evaluation"] = {"status": "not-evaluated", "unavailableInput": ["standing-source"]}
    return accept("A10", pred)


def build_a11() -> Built:
    pred = baseline()
    pred["oversight"] = {"act": "check", "recordDigest": h("overseer/signed-record")}
    return accept("A11", pred)


def build_a12() -> Built:
    """A1's bytes with one difference: the decision point could not load its
    policy and permitted anyway. A decision point failing open is a fact the
    record exists to carry, so a verifier accepts it; what it means for
    admission is the consumer's call."""
    pred = from_pred("A1")
    pred["evaluation"] = {"status": "not-evaluated", "unavailableInput": ["policy-source"]}
    # policyDigest names the policy the decision point enforced. It never read
    # its policy, so what it enforced was the allow-all fallback it fell back to.
    pred["decision"]["policyDigest"] = h("policy/fallback-allow-all")
    return accept("A12", pred)


def build_a13() -> Built:
    """A3's bytes with one difference: the deny that leaked was enforced while
    two inputs were unavailable. Evaluation is not an input to agreement, so a
    leak during an outage still derives disagree."""
    pred = from_pred("A3")
    pred["evaluation"] = {
        "status": "not-evaluated",
        "unavailableInput": ["key-source", "consumption-state"],
    }
    return accept("A13", pred)


def build_a14() -> Built:
    """A2's decision taken without the policy: the request names a profile the
    receiving decision point does not hold, so it could not compare, and it
    enforced its deny-all fallback. A2 is the same deny taken under a profile
    the decision point holds and that grants no comparison, which no retry can
    change. The two records differ only in evaluation and policyDigest."""
    pred = from_pred("A2")
    pred["evaluation"] = {"status": "not-evaluated", "unavailableInput": ["policy-source"]}
    pred["decision"]["policyDigest"] = h("policy/fallback-deny-all")
    return accept("A14", pred)


# --- reject members -------------------------------------------------------


def mutate(parent: str, change: Callable[[dict[str, Any]], None]) -> Callable[[], Built]:
    def build() -> Built:
        pred = from_pred(parent)
        change(pred)
        return signed(pred)

    return build


def _set(dotted: str, value: Any) -> Callable[[dict[str, Any]], None]:
    def change(pred: dict[str, Any]) -> None:
        node = pred
        parts = dotted.split(".")
        for part in parts[:-1]:
            node = node[part]
        node[parts[-1]] = value

    return change


def _drop(dotted: str) -> Callable[[dict[str, Any]], None]:
    def change(pred: dict[str, Any]) -> None:
        node = pred
        parts = dotted.split(".")
        for part in parts[:-1]:
            node = node[part]
        del node[parts[-1]]

    return change


def build_t2() -> Built:
    """Serialized in declaration order, not RFC 8785 order, and signed over those
    bytes: a verifier that checks the signature over the carried bytes accepts it,
    and one that derives the canonical bytes itself does not."""
    stmt = statement(from_pred("A1"))
    return {"payload": json.dumps(stmt, separators=(",", ":"), ensure_ascii=False).encode()}


def build_t3() -> Built:
    """``agent.id`` repeated at depth three: Statement, predicate, agent."""
    body = canonical_bytes(statement(from_pred("A1")))
    needle = b'"agent":{'
    assert body.count(needle) == 1
    injected = b'"agent":{"id":"spiffe://prod.example.org/ns/payments/sa/other",'
    return {"payload": body.replace(needle, injected)}


def build_t4() -> Built:
    """Nesting 129 levels deep: Statement (1), predicate (2), doesNotAssert (3),
    then 126 nested arrays inside it."""
    pred = from_pred("A1")
    nested: list[Any] = []
    for _ in range(125):
        nested = [nested]
    pred["doesNotAssert"].append(nested)
    stmt = statement(pred)
    assert depth(stmt) == 129
    return {"payload": canonical_bytes(stmt)}


def build_t5() -> Built:
    """An integer of magnitude exactly 2**53. RFC 8785 cannot serialize it under
    the I-JSON profile, so the bytes are written with sorted keys by hand."""
    stmt = statement(from_pred("A1"))
    stmt["predicate"]["effect"]["writes"][0]["size"] = 2**53
    return {
        "payload": json.dumps(
            stmt, separators=(",", ":"), sort_keys=True, ensure_ascii=False
        ).encode()
    }


def depth(node: Any) -> int:
    if isinstance(node, dict):
        return 1 + max((depth(v) for v in node.values()), default=0)
    if isinstance(node, list):
        return 1 + max((depth(v) for v in node), default=0)
    return 0


def _e1(pred: dict[str, Any]) -> None:
    after = h("root/after-own-write-under-deny")
    request = pred["decision"]["requestDigest"]
    pred["effect"]["writes"] = [write(LEDGER_PATH, BEFORE, after, request)]
    pred["effect"]["interval"]["afterRoot"] = after


def _e2(pred: dict[str, Any]) -> None:
    request = pred["decision"]["requestDigest"]
    stray = h("root/state-no-write-produced")
    pred["effect"]["writes"].append(write("/srv/ledger/index.jsonl", stray, AFTER, request))


def _e3(pred: dict[str, Any]) -> None:
    pred["effect"]["interval"]["baseResolution"] = "empty-tree"
    pred["effect"]["interval"]["beforeRoot"] = EMPTY_TREE["sha1"]


# E2, E4, E5 and E6 pin the replay one part at a time. The running root starts at
# beforeRoot, each write's preStateDigest must equal it and its postStateDigest
# replaces it, and the root after the last write must be afterRoot. E2 breaks a
# link between two writes with both ends intact, E4 breaks only the start, E5
# only the end, and E6 is the case with no write at all. A reader that drops any
# one of those comparisons accepts exactly one of the four, which
# scripts/write-chain-replay-test.py checks against weakened copies of both
# packaged readers.


def _e4(pred: dict[str, Any]) -> None:
    pred["effect"]["writes"][0]["preStateDigest"] = h("root/state-before-the-interval")


def _e5(pred: dict[str, Any]) -> None:
    pred["effect"]["writes"][0]["postStateDigest"] = h("root/state-after-the-write")


def _e6(pred: dict[str, Any]) -> None:
    pred["effect"]["interval"]["afterRoot"] = h("root/after-with-no-write")


def _v3(pred: dict[str, Any]) -> None:
    pred["effect"]["writes"][0]["path"] = "/srv/reports/settlements.jsonl"


def _fe1(pred: dict[str, Any]) -> None:
    del pred["fieldEvidence"]["remediation"]


def _f6(pred: dict[str, Any]) -> None:
    pred["posture"]["observed"] = "sinkhole"
    pred["posture"]["observedDigest"] = h("posture/sinkhole")


def _c1(pred: dict[str, Any]) -> None:
    pred["agent"]["signers"].append(OBSERVER_KEYID)


def _n1(pred: dict[str, Any]) -> None:
    pred["correlation"]["timeBasis"] = "beacon-anchored"
    pred["correlation"]["externalAnchor"] = {"kind": "rfc3161", "digest": h("anchor/tsa-token")}


def _ti4(pred: dict[str, Any]) -> None:
    pred["observation"]["coverage"] = {"scopeComplete": False, "gaps": ["/srv/ledger/archive/"]}


def build_s1() -> Built:
    return signed(from_pred("A1"), second_subject=False)


def build_i1r() -> Built:
    pred = from_pred("A1")
    stmt = statement(pred)
    del stmt["predicate"]["effect"]["interval"]
    return {"payload": canonical_bytes(stmt)}


def build_s2() -> Built:
    stmt = statement(from_pred("A1"))
    stmt["subject"][1]["digest"]["sha256"] = BEFORE
    return {"payload": canonical_bytes(stmt)}


TWO_READINGS_N1 = [
    {
        "verdict": "valid",
        "rationale": "the draft defines no offline validation rule for an anchor token, "
        "so a verifier that carries the digest without reading it is conforming",
    },
    {
        "verdict": "indeterminate",
        "rationale": "the anchor cannot be resolved from the carried bytes, and a "
        "verifier that declines to rule on it is conforming",
    },
]
TWO_READINGS_N2 = [
    {
        "verdict": "valid",
        "rationale": "Section 11 carries no unit for undue delay and the draft defines "
        "no bound, so the ordering rule is all a verifier checks",
    },
    {
        "verdict": "indeterminate",
        "rationale": "whether forty days is undue is a consumer policy the record cannot settle",
    },
]


def define() -> None:
    member(
        "A1",
        "a1-permit-beside-occurred",
        None,
        "every member present, permit beside occurred, all five tier clauses met",
        build_a1,
        "valid",
        tier="authoritative",
    )
    member(
        "A2",
        "a2-deny-beside-none",
        None,
        "deny beside none, equal roots, empty write set",
        build_a2,
        "valid",
        tier="authoritative",
    )
    member(
        "A3",
        "a3-deny-beside-occurred-disagree",
        None,
        "A1 with deny beside occurred and agreement of disagree",
        build_a3,
        "valid",
        tier="authoritative",
    )
    member(
        "A4",
        "a4-remediation-not-enforced",
        None,
        "A1 plus a remediation event with enforcement of not-enforced",
        build_a4,
        "valid",
        tier="authoritative",
    )
    member(
        "A5",
        "a5-self-vantage-voluntary",
        None,
        "A1 with vantage of self, no prior commitment, tier of voluntary",
        build_a5,
        "valid",
        tier="voluntary",
    )
    member(
        "A6",
        "a6-not-bindable-three-member-preimage",
        None,
        "A1 with binding of not-bindable, argumentsDigest absent from the record and "
        "from the request-digest preimage, tier of voluntary",
        build_a6,
        "valid",
        tier="voluntary",
    )
    member(
        "A7",
        "a7-other-requests-write-in-interval",
        None,
        "A2 plus one in-scope write inside the interval attributed to a different "
        "request, roots and chain moved to match",
        build_a7,
        "valid",
        tier="authoritative",
    )
    member(
        "A8",
        "a8-unattributed-write-indeterminate",
        None,
        "A2 plus one in-scope unattributed write inside the interval, effect.observed of unknown",
        build_a8,
        "valid",
        tier="authoritative",
    )
    member(
        "A9",
        "a9-permit-beside-none-not-exercised",
        None,
        "A1 with permit beside an empty write set, equal roots, effect.observed of none",
        build_a9,
        "valid",
        tier="authoritative",
    )
    member(
        "A10",
        "a10-deny-not-evaluated-standing-source",
        None,
        "A2 with evaluation of not-evaluated and unavailableInput of standing-source",
        build_a10,
        "valid",
        tier="authoritative",
    )
    member(
        "A11",
        "a11-oversight-check-with-record-digest",
        None,
        "A1 plus oversight with act of check and the overseer's record digest",
        build_a11,
        "valid",
        tier="authoritative",
    )
    member(
        "A12",
        "a12-permit-not-evaluated-policy-source",
        None,
        "A1 with evaluation of not-evaluated, unavailableInput of policy-source and "
        "the allow-all fallback's policyDigest: a decision point failing open, "
        "agreement of agree",
        build_a12,
        "valid",
        tier="authoritative",
    )
    member(
        "A13",
        "a13-leaked-deny-not-evaluated-two-inputs",
        None,
        "A3 with evaluation of not-evaluated and unavailableInput of key-source and "
        "consumption-state: a leak during an outage, agreement of disagree",
        build_a13,
        "valid",
        tier="authoritative",
    )
    member(
        "A14",
        "a14-deny-not-evaluated-policy-not-held",
        None,
        "A2 with evaluation of not-evaluated, unavailableInput of policy-source and "
        "the deny-all fallback's policyDigest: a profile the decision point does not "
        "hold, failing closed, agreement of agree",
        build_a14,
        "valid",
        tier="authoritative",
    )

    rejects: list[tuple[str, str, str, str, Callable[[], Built], str]] = [
        (
            "F1",
            "f1-agent-member-removed",
            "A1",
            "A1 with the whole agent member removed",
            mutate("A1", _drop("agent")),
            "member-missing",
        ),
        (
            "F2",
            "f2-subject-kind-none-beside-named-subject",
            "A1",
            "subjectKind of none beside a named subject",
            mutate("A1", _set("delegation.subjectKind", "none")),
            "delegation-subject-inconsistent",
        ),
        (
            "F3",
            "f3-digest-bound-without-arguments-digest",
            "A1",
            "digest-bound with argumentsDigest removed",
            mutate("A1", _drop("resource.argumentsDigest")),
            "arguments-digest-missing",
        ),
        (
            "F3b",
            "f3b-not-bindable-arguments-digest-null",
            "A6",
            "not-bindable carrying argumentsDigest of null",
            mutate("A6", _set("resource.argumentsDigest", None)),
            "arguments-digest-forbidden",
        ),
        (
            "F3c",
            "f3c-not-bindable-arguments-digest-empty",
            "A6",
            "not-bindable carrying argumentsDigest of the empty string",
            mutate("A6", _set("resource.argumentsDigest", "")),
            "arguments-digest-forbidden",
        ),
        (
            "F4",
            "f4-action-changed-request-digest-kept",
            "A1",
            "action changed, requestDigest left at its original value",
            mutate("A1", _set("decision.action", "delete")),
            "request-digest-mismatch",
        ),
        (
            "F5",
            "f5-beacon-anchored-without-anchor",
            "A1",
            "beacon-anchored with externalAnchor removed",
            mutate("A1", _set("correlation.timeBasis", "beacon-anchored")),
            "external-anchor-inconsistent",
        ),
        (
            "F6",
            "f6-unequal-postures-declared-agree",
            "A1",
            "two unequal postures declared as agree",
            mutate("A1", _f6),
            "posture-agreement-underivable",
        ),
        (
            "F7",
            "f7-enforced-before-signal",
            "A4",
            "enforcedAt one second before signalReceivedAt",
            mutate("A4", lambda p: p["remediation"][0].update(enforcedAt="2026-09-19T11:04:06Z")),
            "remediation-order",
        ),
        (
            "T1",
            "t1-observed-edited-to-none-resigned",
            "A1",
            "effect.observed edited to none, writes intact, signed again with the real key",
            mutate("A1", _set("effect.observed", "none")),
            "effect-observed-underivable",
        ),
        (
            "T2",
            "t2-declaration-order-not-rfc8785",
            "A1",
            "serialized in declaration order, not RFC 8785 order",
            build_t2,
            "signature-invalid",
        ),
        (
            "T3",
            "t3-member-repeated-at-depth-three",
            "A1",
            "a member name repeated at depth three",
            build_t3,
            "duplicate-member",
        ),
        (
            "T4",
            "t4-nesting-129-levels",
            "A1",
            "nesting 129 levels deep",
            build_t4,
            "nesting-too-deep",
        ),
        (
            "T5",
            "t5-integer-two-to-the-53",
            "A1",
            "an integer of magnitude exactly 2^53",
            build_t5,
            "unsafe-integer",
        ),
        (
            "D1",
            "d1-disagree-with-both-sides-agreeing",
            "A1",
            "agreement of disagree with both sides agreeing",
            mutate("A1", _set("agreement", "disagree")),
            "agreement-underivable",
        ),
        (
            "D2",
            "d2-one-sided-with-both-values",
            "A1",
            "agreement of one-sided with both values present",
            mutate("A1", _set("agreement", "one-sided")),
            "agreement-reserved-value",
        ),
        (
            "D3",
            "d3-disagree-beside-permit-and-none",
            "A9",
            "agreement of disagree beside permit and none",
            mutate("A9", _set("agreement", "disagree")),
            "agreement-underivable",
        ),
        (
            "S1",
            "s1-second-subject-removed",
            "A1",
            "second subject entry removed, interval left present",
            build_s1,
            "subject-interval-mismatch",
        ),
        (
            "S2",
            "s2-second-subject-is-before-root",
            "A1",
            "second subject entry's digest set to the before-state root",
            build_s2,
            "subject-after-root-mismatch",
        ),
        (
            "I1r",
            "i1r-interval-removed-subject-kept",
            "A1",
            "interval removed, second subject entry left present",
            build_i1r,
            "subject-interval-mismatch",
        ),
        (
            "TI1",
            "ti1-authoritative-with-self-vantage",
            "A1",
            "authoritative declared with vantage of self",
            mutate("A1", _set("observation.vantage", "self")),
            "tier-overclaim-vantage",
        ),
        (
            "TI2",
            "ti2-authoritative-without-commitment",
            "A1",
            "authoritative declared with no prior commitment",
            mutate("A1", _drop("observation.priorCommitment")),
            "tier-overclaim-commitment",
        ),
        (
            "TI3",
            "ti3-authoritative-with-empty-scope",
            "A1",
            "authoritative declared with an empty pathScope",
            mutate("A1", _set("effect.pathScope", [])),
            "tier-overclaim-scope",
        ),
        (
            "TI4",
            "ti4-authoritative-with-gap-inside-scope",
            "A1",
            "authoritative declared with a coverage gap inside pathScope",
            mutate("A1", _ti4),
            "tier-overclaim-coverage",
        ),
        (
            "TI5",
            "ti5-authoritative-on-not-bindable",
            "A6",
            "authoritative declared on A6",
            mutate("A6", _set("tier", "authoritative")),
            "tier-overclaim-binding",
        ),
        (
            "C1",
            "c1-commitment-key-is-agent-signer",
            "A1",
            "commitment keyid added to agent.signers",
            mutate("A1", _c1),
            "commitment-key-is-agent-signer",
        ),
        (
            "C2",
            "c2-committed-after-interval-opened",
            "A1",
            "committedAt one second after openedAt",
            mutate("A1", _set("observation.priorCommitment.committedAt", "2026-09-19T11:04:02Z")),
            "commitment-order",
        ),
        (
            "C3",
            "c3-nonce-changed-digest-kept",
            "A1",
            "witnessNonce changed, commitmentDigest left at its original value",
            mutate("A1", _set("observation.priorCommitment.witnessNonce", h("nonce/substituted"))),
            "commitment-digest-mismatch",
        ),
        (
            "E1",
            "e1-none-with-a-write-set",
            "A2",
            "observed of none with a non-empty write set",
            mutate("A2", _e1),
            "effect-observed-underivable",
        ),
        (
            "E2",
            "e2-second-write-breaks-chain",
            "A1",
            "a second write whose pre-state is not the first write's post-state",
            mutate("A1", _e2),
            "write-chain-broken",
        ),
        (
            "E3",
            "e3-empty-tree-carries-sha1-constant",
            "A1",
            "empty-tree under sha256 carrying the sha1 constant",
            mutate("A1", _e3),
            "empty-tree-constant-mismatch",
        ),
        (
            "E4",
            "e4-first-write-not-from-before-root",
            "A1",
            "the only write's pre-state is not the before-state root, its post-state is "
            "the after-state root",
            mutate("A1", _e4),
            "write-chain-broken",
        ),
        (
            "E5",
            "e5-last-write-not-to-after-root",
            "A1",
            "the only write starts from the before-state root and its post-state is not "
            "the after-state root",
            mutate("A1", _e5),
            "write-chain-broken",
        ),
        (
            "E6",
            "e6-no-write-and-unequal-roots",
            "A2",
            "an empty write set beside an after-state root unequal to the before-state "
            "root, second subject moved to match",
            mutate("A2", _e6),
            "write-chain-broken",
        ),
        (
            "V1",
            "v1-enforcement-outside-closed-set",
            "A4",
            "enforcement of quarantined, outside the closed set",
            mutate("A4", lambda p: p["remediation"][0].update(enforcement="quarantined")),
            "value-outside-vocabulary",
        ),
        (
            "V2",
            "v2-glob-in-path-scope",
            "A1",
            "a pathScope member carrying a glob metacharacter",
            mutate("A1", _set("effect.pathScope", ["/srv/ledger/*"])),
            "path-scope-glob",
        ),
        (
            "V3",
            "v3-write-outside-scope-marked-in-scope",
            "A1",
            "a write outside pathScope carrying inScope of true",
            mutate("A1", _v3),
            "write-scope-mismatch",
        ),
        (
            "FE1",
            "fe1-six-of-seven-field-evidence-keys",
            "A1",
            "six of the seven fieldEvidence keys present",
            mutate("A1", _fe1),
            "field-evidence-keys",
        ),
        (
            "FE2",
            "fe2-substrate-covered-beside-self",
            "A5",
            "substrate-covered declared beside vantage of self",
            mutate("A5", _set("fieldEvidence.resource", "substrate-covered")),
            "field-evidence-self-substrate",
        ),
        (
            "EV1",
            "ev1-not-evaluated-without-unavailable-input",
            "A10",
            "not-evaluated with unavailableInput removed",
            mutate("A10", _drop("evaluation.unavailableInput")),
            "evaluation-inconsistent",
        ),
        (
            "EV2",
            "ev2-evaluated-naming-unavailable-input",
            "A2",
            "evaluated carrying unavailableInput of standing-source",
            mutate("A2", _set("evaluation.unavailableInput", ["standing-source"])),
            "evaluation-inconsistent",
        ),
        (
            "EV3",
            "ev3-evaluation-member-removed",
            "A1",
            "the evaluation member removed, the shape of a revision 01 record",
            mutate("A1", _drop("evaluation")),
            "member-missing",
        ),
        (
            "EV4",
            "ev4-unavailable-input-outside-closed-set",
            "A10",
            "unavailableInput of network, outside the closed set",
            mutate("A10", _set("evaluation.unavailableInput", ["network"])),
            "value-outside-vocabulary",
        ),
        (
            "EV5",
            "ev5-unavailable-input-named-twice",
            "A10",
            "unavailableInput naming standing-source twice",
            mutate(
                "A10", _set("evaluation.unavailableInput", ["standing-source", "standing-source"])
            ),
            "evaluation-inconsistent",
        ),
        (
            "EV6",
            "ev6-not-evaluated-with-empty-unavailable-input",
            "A10",
            "not-evaluated with unavailableInput of the empty array",
            mutate("A10", _set("evaluation.unavailableInput", [])),
            "evaluation-inconsistent",
        ),
        (
            "EV7",
            "ev7-evaluated-with-empty-unavailable-input",
            "A2",
            "evaluated carrying unavailableInput of the empty array",
            mutate("A2", _set("evaluation.unavailableInput", [])),
            "evaluation-inconsistent",
        ),
        (
            "EV8",
            "ev8-evaluated-with-null-unavailable-input",
            "A2",
            "evaluated carrying unavailableInput of null",
            mutate("A2", _set("evaluation.unavailableInput", None)),
            "evaluation-inconsistent",
        ),
        (
            "EV9",
            "ev9-status-outside-closed-set",
            "A10",
            "evaluation.status of partially-evaluated, outside the closed set, "
            "unavailableInput kept",
            mutate("A10", _set("evaluation.status", "partially-evaluated")),
            "value-outside-vocabulary",
        ),
        (
            "EV10",
            "ev10-evaluation-carrying-an-undefined-member",
            "A10",
            "evaluation carrying a free-text reason member the draft does not define",
            mutate("A10", _set("evaluation.reason", "status list endpoint timed out")),
            "evaluation-malformed",
        ),
        (
            "OV1",
            "ov1-oversight-act-outside-closed-set",
            "A11",
            "oversight act of approval, outside the closed set",
            mutate("A11", _set("oversight.act", "approval")),
            "value-outside-vocabulary",
        ),
        (
            "OV2",
            "ov2-oversight-carrying-an-undefined-member",
            "A11",
            "oversight carrying an overseer member the draft does not define",
            mutate("A11", _set("oversight.overseer", "user:bob@example.org")),
            "oversight-malformed",
        ),
    ]
    for draft_id, slug, parent, row, build, code in rejects:
        member(draft_id, slug, parent, row, build, "malformed", [code])

    member(
        "N1",
        "n1-anchor-token-with-no-offline-rule",
        "A1",
        "an anchor token digest carried with no offline validation rule defined",
        mutate("A1", _n1),
        None,
        readings=TWO_READINGS_N1,
    )
    member(
        "N2",
        "n2-enforced-forty-days-after-signal",
        "A4",
        "enforcement forty days after the signal, ordering intact",
        mutate("A4", lambda p: p["remediation"][0].update(enforcedAt="2026-10-29T11:04:07Z")),
        None,
        readings=TWO_READINGS_N2,
    )


def expected_of(entry: Member) -> dict[str, Any]:
    """The manifest's expected block: a settled row's verdict, never an open row's."""
    expected: dict[str, Any] = {"codes": entry["codes"]}
    if entry["verdict"] is not None:
        expected["verdict"] = entry["verdict"]
    if entry["tier"] is not None:
        expected["derivedTier"] = entry["tier"]
    return expected


def vector_id(body: bytes) -> str:
    return "v" + hashlib.sha256(body).hexdigest()[:ID_HEX]


def emit() -> None:
    define()
    statements_dir = os.path.join(HERE, "statements")
    os.makedirs(statements_dir, exist_ok=True)
    built: list[tuple[Member, bytes, str]] = []
    ids: dict[str, str] = {}
    for entry in MEMBERS:
        body = json.dumps(envelope(entry["build"]()["payload"]), indent=2, sort_keys=True)
        raw = body.encode() + b"\n"
        ident = vector_id(raw)
        if ident in ids.values():
            raise SystemExit(f"identifier collision on {entry['draftId']}")
        ids[entry["draftId"]] = ident
        built.append((entry, raw, ident))

    vectors: list[dict[str, Any]] = []
    keep: set[str] = set()
    for entry, raw, ident in built:
        rel = f"statements/{ident}.json"
        with open(os.path.join(HERE, rel), "wb") as fh:
            fh.write(raw)
        keep.add(f"{ident}.json")
        out: dict[str, Any] = {
            "id": ident,
            "draftId": entry["draftId"],
            "slug": entry["slug"],
            "kind": entry["kind"],
            "file": rel,
            "row": entry["row"],
            "expected": expected_of(entry),
        }
        if entry["parent"] is not None:
            out["parent"] = ids[entry["parent"]]
            out["parentDraftId"] = entry["parent"]
        if entry["readings"] is not None:
            out["readings"] = entry["readings"]
        vectors.append(out)

    for stale in sorted(os.listdir(statements_dir)):
        if stale.endswith(".json") and stale not in keep:
            os.remove(os.path.join(statements_dir, stale))

    counts: dict[str, int] = {}
    for v in vectors:
        counts[v["kind"]] = counts.get(v["kind"], 0) + 1
    manifest: dict[str, Any] = {
        "suite": SUITE,
        "draft": DRAFT,
        "predicateType": PREDICATE_TYPE,
        "predicateDocument": PREDICATE_DOCUMENT,
        "payloadType": PAYLOAD_TYPE,
        "algorithm": {"envelope": "ed25519", "digest": "sha256"},
        "keys": {
            "observer": {"keyid": OBSERVER_KEYID, "publicKey": OBSERVER_PUB},
            "agent": {"keyid": AGENT_KEYID, "publicKey": AGENT_PUB},
        },
        "keyNote": (
            "PUBLISHED TEST KEYS, derived from fixed seeds in gen_vectors.py. The "
            "observer key signs every envelope. The agent key signs nothing: it is "
            "the key agent.signers names, so the commitment-key disjointness rule "
            "has something to be disjoint from."
        ),
        "emptyTree": EMPTY_TREE,
        "counts": counts,
        "note": (
            "One member per row of Appendix B of the draft, in the row's order; "
            "draftId is the row's identifier and parentDraftId its from column. An "
            "accept or reject member is scored on expected.verdict. An indeterminate "
            "member is a row the draft leaves open: it carries no expected.verdict, "
            "and a verifier conforms on it by reaching any verdict its readings list. "
            "expected.codes are the reference reader's names for its first refusal, "
            "published so two implementations can compare where they stopped; the "
            "draft does not define them."
        ),
        "vectors": vectors,
    }
    manifest["corpusDigest"] = corpus_digest(manifest)
    with open(os.path.join(HERE, "MANIFEST.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    write_index(manifest)


def write_index(manifest: dict[str, Any]) -> None:
    counts = manifest["counts"]
    vectors = manifest["vectors"]
    lines = [
        "# Agent audit record conformance vectors",
        "",
        "Generated by `gen_vectors.py`. Do not edit: every regeneration rewrites it.",
        "",
        f"Predicate: `{PREDICATE_TYPE}`, defined by [`{DRAFT}`]({PREDICATE_DOCUMENT}).",
        "",
        f"Corpus digest: `{manifest['corpusDigest']}`",
        "",
        f"{counts.get('indeterminate', 0)} member(s) are indeterminate.",
        "",
        f"This corpus is {len(vectors)} vectors, of which {counts['accept']} a "
        f"conformant verifier must not fail closed on and {counts['reject']} it "
        "must reject.",
        "",
        "| Appendix B | from | verdict | file | row |",
        "| --- | --- | --- | --- | --- |",
    ]
    for v in vectors:
        parent = v.get("parentDraftId", "root")
        if v["kind"] == "indeterminate":
            verdict = " or ".join(r["verdict"] for r in v["readings"])
        else:
            verdict = v["expected"]["verdict"]
        lines.append(
            f"| `{v['draftId']}` | {parent} | {verdict} | "
            f"[`{v['id']}`]({v['file']}) | {v['row']} |"
        )
    with open(os.path.join(HERE, "INDEX.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    emit()
