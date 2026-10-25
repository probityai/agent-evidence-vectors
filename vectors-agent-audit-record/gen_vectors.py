#!/usr/bin/env python3
"""Generate the agent audit record conformance corpus.

Regenerate byte-identically:

    uv run --extra generators python vectors-agent-audit-record/gen_vectors.py

The corpus is Appendix B of the Internet-Draft
draft-gilda-audit-agent-audit-record-00, member for member and in the table's
order, followed by members for rules of Section 5.4 that Appendix B carries no
row for. Each of those names the section it tests in ``draftSection`` and
continues the identifier series of the rows beside it. Every member is a
complete DSSE envelope whose payload is an in-toto Statement v1 carrying an
agent audit record, except R1 to R9: each of those is a retained record, the
envelope beside the retention entry of Section 4.7, and its file carries both.
The vector file carries the bytes and nothing else; the verdict a verifier must
reach, and the identifier the member answers to, live in MANIFEST.json.

Each reject member is built from the accept member the Appendix B `from` column
names, by the one mutation its row describes, so a verifier that refuses every
input scores nothing here. Where a mutation moves a value another member is a
function of (a root, a request digest), the dependent value moves with it, which
is what "roots and chain moved to match" means in the rows that say it.

Ed25519 signatures are deterministic (RFC 8032) and every key below comes from a
fixed seed, so the corpus is byte-identical on every machine. The keys are
PUBLISHED TEST KEYS, and the transparency log the retained records are anchored
in is a test log whose tree heads the manifest publishes.
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
PREDICATE_DOCUMENT = "https://datatracker.ietf.org/doc/draft-gilda-audit-agent-audit-record/00/"
DRAFT = "draft-gilda-audit-agent-audit-record-00"
#: The revision every earlier release of this corpus tested. Its records carry
#: no evaluation.inputs, so each is malformed under DRAFT (EV13).
PREVIOUS_DRAFT = "draft-gilda-wimse-agent-audit-record-02"
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


# ---------------------------------------------------------------------------
# Evaluation inputs (Section 5.4 of draft-gilda-audit-agent-audit-record-00).
# Every entry carries input, lastResult and maxAge, and every age is measured
# from lastResult to decision.reportedAt, 2026-09-19T11:04:02Z in every member
# except FR17a; the skew tolerance is 300 seconds. The accept members carry the
# inputs the draft's own example prints: a policy read at 10:00:00 under a
# day's maximum and a standing value read at 11:00:00 under an hour's.
# ---------------------------------------------------------------------------

NEVER_HELD = "none"
HOUR = 3600
DAY = 86400


def entry(name: str, last_result: str, max_age: int) -> dict[str, Any]:
    return {"input": name, "lastResult": last_result, "maxAge": max_age}


def baseline_inputs() -> list[dict[str, Any]]:
    return [
        entry("policy-source", "2026-09-19T10:00:00Z", DAY),
        entry("standing-source", "2026-09-19T11:00:00Z", HOUR),
    ]


#: A value read at 09:30:00 is 5642 seconds old at reportedAt, past an hour.
STALE = "2026-09-19T09:30:00Z"


def second_hop_inputs(standing_last_result: str) -> list[dict[str, Any]]:
    """The inputs of a decision point that is the second of two hops.

    It reads the policy and the key source itself and receives standing from the
    first hop, so the standing entry carries the SOURCE's lastResult unchanged
    and this hop's own maxAge. Nothing in the bytes says which entry was
    forwarded: what the members fix is that the age runs from the carried
    lastResult to this record's reportedAt, never from when the hop received it,
    and never from issuedAt.
    """
    return [
        entry("policy-source", "2026-09-19T10:00:00Z", DAY),
        entry("key-source", "2026-09-19T11:00:00Z", HOUR),
        entry("standing-source", standing_last_result, HOUR),
    ]


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
        "evaluation": {"status": "evaluated", "inputs": baseline_inputs()},
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
    section: str | None = None,
    dating: dict[str, Any] | None = None,
    revision: str | None = None,
    aggregation: dict[str, Any] | None = None,
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
            "section": section,
            "dating": dating,
            "revision": revision,
            "aggregation": aggregation,
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
    pred["evaluation"] = {
        "status": "not-evaluated",
        "inputs": [
            entry("policy-source", "2026-09-19T10:00:00Z", DAY),
            entry("standing-source", STALE, HOUR),
        ],
        "unavailableInput": ["standing-source"],
    }
    return accept("A10", pred)


def build_a11() -> Built:
    pred = baseline()
    pred["oversight"] = {"act": "check", "recordDigest": h("overseer/signed-record")}
    return accept("A11", pred)


# --- accept members for Sections 5.4 and 5.5 -------------------------------
#
# Appendix B has one accept row per member: A10 names standing-source and A11
# names check. A reader that hard-coded those two values scored every row, so
# these carry every other value of both closed sets. Found by an outside reader
# who wrote the rules from the section text rather than from the rows.


def _unavailable(name: str, inputs: list[str]) -> Callable[[], Built]:
    """A10 with ``inputs`` unavailable: each named input's entry is stale and
    every other entry fresh, so the set a verifier derives is the named one."""

    def build() -> Built:
        pred = from_pred("A10")
        standing = STALE if "standing-source" in inputs else "2026-09-19T11:00:00Z"
        pred["evaluation"]["inputs"] = [
            entry("policy-source", "2026-09-19T10:00:00Z", DAY),
            entry("standing-source", standing, HOUR),
        ] + [entry(n, STALE, HOUR) for n in ("key-source", "consumption-state") if n in inputs]
        pred["evaluation"]["unavailableInput"] = inputs
        return accept(name, pred)

    return build


# --- the fallback a decision point enforced (Section 5.4, rows A18 to A20) ----
#
# Under not-evaluated, decision.reported is the outcome the decision point fell
# back to, and where the policy itself was the input it could not obtain,
# decision.policyDigest names the fallback it enforced: an allow-all document
# for a decision point failing open (A18), a deny-all one for a decision point
# that does not hold the profile a request names (A20).


def build_a18() -> Built:
    pred = baseline()
    pred["decision"]["policyDigest"] = h("policy/fallback-allow-all")
    pred["evaluation"] = {
        "status": "not-evaluated",
        "inputs": [
            entry("policy-source", NEVER_HELD, DAY),
            entry("standing-source", "2026-09-19T11:00:00Z", HOUR),
        ],
        "unavailableInput": ["policy-source"],
    }
    return accept("A18", pred)


def build_a19() -> Built:
    """A3, the deny that leaked, recorded by a decision point whose key source and
    consumption state were both stale: the agreement table is unchanged by
    evaluation, so the record still derives disagree."""
    pred = from_pred("A3")
    pred["evaluation"] = {
        "status": "not-evaluated",
        "inputs": [
            entry("policy-source", "2026-09-19T10:00:00Z", DAY),
            entry("standing-source", "2026-09-19T11:00:00Z", HOUR),
            entry("key-source", STALE, HOUR),
            entry("consumption-state", STALE, HOUR),
        ],
        "unavailableInput": ["key-source", "consumption-state"],
    }
    return accept("A19", pred)


def build_a20() -> Built:
    pred = from_pred("A2")
    pred["decision"]["policyDigest"] = h("policy/fallback-deny-all")
    pred["evaluation"] = {
        "status": "not-evaluated",
        "inputs": [
            entry("policy-source", NEVER_HELD, DAY),
            entry("standing-source", "2026-09-19T11:00:00Z", HOUR),
        ],
        "unavailableInput": ["policy-source"],
    }
    return accept("A20", pred)


# --- freshness members (Section 5.4, rows FR1 to FR18) -----------------------


def _with_inputs(parent: str, name: str, entries: list[dict[str, Any]]) -> Callable[[], Built]:
    def build() -> Built:
        pred = from_pred(parent)
        pred["evaluation"]["inputs"] = entries
        return accept(name, pred)

    return build


def _entry_change(
    index: int, change: Callable[[dict[str, Any]], None]
) -> Callable[[dict[str, Any]], None]:
    def apply(pred: dict[str, Any]) -> None:
        change(pred["evaluation"]["inputs"][index])

    return apply


#: Indices into second_hop_inputs.
KEY_ENTRY, STANDING_ENTRY = 1, 2


def build_fr17a() -> Built:
    """The first hop: it reads standing from its source at 10:00:00 and applies
    a two-hour maximum, so at its reportedAt of 11:04:00 the value is 3840
    seconds old and fresh."""
    pred = baseline()
    pred["decision"]["decisionPointId"] = "pdp://prod.example.org/gateway-1"
    pred["decision"]["reportedAt"] = "2026-09-19T11:04:00Z"
    pred["evaluation"]["inputs"] = [
        entry("policy-source", "2026-09-19T10:00:00Z", DAY),
        entry("standing-source", "2026-09-19T10:00:00Z", 2 * HOUR),
    ]
    return accept("FR17a", pred)


def build_fr17b() -> Built:
    """The second hop: it copies the source's lastResult of 10:00:00 unchanged
    and applies its own one-hour maximum, so at its reportedAt of 11:04:02 the
    same value is 3842 seconds old and stale. It could not evaluate, and it
    denied."""
    pred = from_pred("A10")
    pred["evaluation"]["inputs"] = [
        entry("policy-source", "2026-09-19T10:00:00Z", DAY),
        entry("standing-source", "2026-09-19T10:00:00Z", HOUR),
    ]
    return accept("FR17b", pred)


def _fr13b(pred: dict[str, Any]) -> None:
    pred["evaluation"]["inputs"][KEY_ENTRY]["maxAge"] = -1
    pred["evaluation"]["unavailableInput"] = ["key-source", "standing-source"]


def _ev14(pred: dict[str, Any]) -> None:
    pred["evaluation"]["status"] = "not-evaluated"
    pred["evaluation"]["unavailableInput"] = []


def _fr17c(pred: dict[str, Any]) -> None:
    pred["evaluation"]["status"] = "evaluated"
    del pred["evaluation"]["unavailableInput"]


def _oversight(name: str, act: str, *, record_digest: bool = True) -> Callable[[], Built]:
    def build() -> Built:
        pred = from_pred("A11")
        pred["oversight"]["act"] = act
        if not record_digest:
            del pred["oversight"]["recordDigest"]
        return accept(name, pred)

    return build


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


# Section 5.3 requires the ordered write chain to reproduce the after-state root
# from the before-state root. That replay is four comparisons: the running root
# starts at beforeRoot, each write's preStateDigest must equal it and its
# postStateDigest replaces it, and the root after the last write must be
# afterRoot. E2 breaks a link between two writes with both ends intact, E4
# breaks only the start, E5 only the end, and E6 is the case with no write at
# all. A reader that drops any one of those comparisons accepts exactly one of
# the four, which scripts/write-chain-replay-test.py checks against weakened
# copies of both packaged readers.


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
        "A18",
        "a18-permit-not-evaluated-policy-source-allow-all-fallback",
        None,
        "A1 with evaluation.status of not-evaluated, policy-source never established, "
        "unavailableInput of policy-source and the allow-all fallback's decision.policyDigest",
        build_a18,
        "valid",
        tier="authoritative",
    )
    member(
        "A19",
        "a19-leaked-deny-not-evaluated-two-stale-inputs",
        None,
        "A3 with evaluation.status of not-evaluated, key-source and consumption-state stale, "
        "and unavailableInput naming both",
        build_a19,
        "valid",
        tier="authoritative",
    )
    member(
        "A20",
        "a20-deny-profile-not-held-deny-all-fallback",
        None,
        "A2 with evaluation.status of not-evaluated, a profile the request names not held, "
        "unavailableInput of policy-source and the deny-all fallback's decision.policyDigest",
        build_a20,
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
            "EV11",
            "ev11-status-outside-closed-set",
            "A10",
            "evaluation.status of partially-evaluated, outside the closed set",
            mutate("A10", _set("evaluation.status", "partially-evaluated")),
            "value-outside-vocabulary",
        ),
        (
            "EV12",
            "ev12-evaluation-carrying-a-reason",
            "A10",
            "evaluation carrying a free-text reason member this document does not define",
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
        "n1-anchor-digest-proof-not-held",
        "A1",
        "an anchor token digest carried in correlation.externalAnchor, the proof not held: "
        "the verifier reads beacon-anchored as the producer's statement, accepts the record "
        "and does not date it from the anchor",
        mutate("A1", _n1),
        "valid",
        tier="authoritative",
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

    # Rows revision 02's Appendix B had no row for and draft-gilda-audit-agent-
    # audit-record-00 adds, each first published here as a section member. The
    # tuples keep the section each was written against; the manifest no longer
    # carries it, because each is now a row.
    section_accepts: list[tuple[str, str, str, str, Callable[[], Built]]] = [
        (
            "A12",
            "a12-not-evaluated-key-source",
            "5.4",
            "A10 with unavailableInput of key-source",
            _unavailable("A12", ["key-source"]),
        ),
        (
            "A13",
            "a13-not-evaluated-consumption-state",
            "5.4",
            "A10 with unavailableInput of consumption-state",
            _unavailable("A13", ["consumption-state"]),
        ),
        (
            "A14",
            "a14-not-evaluated-all-three-inputs",
            "5.4",
            "A10 with unavailableInput naming all three inputs, each once, in neither "
            "the draft's order nor sorted order",
            _unavailable("A14", ["key-source", "standing-source", "consumption-state"]),
        ),
        (
            "A15",
            "a15-oversight-observation",
            "5.5",
            "A11 with oversight act of observation",
            _oversight("A15", "observation"),
        ),
        (
            "A16",
            "a16-oversight-decision-without-record-digest",
            "5.5",
            "A11 with oversight act of decision and recordDigest absent, which is optional",
            _oversight("A16", "decision", record_digest=False),
        ),
        (
            "A17",
            "a17-oversight-release",
            "5.5",
            "A11 with oversight act of release",
            _oversight("A17", "release"),
        ),
    ]
    for draft_id, slug, _section, row, build in section_accepts:
        member(draft_id, slug, None, row, build, "valid", tier="authoritative")

    section_rejects: list[tuple[str, str, str, str, str, Callable[[], Built], str]] = [
        (
            "E4",
            "e4-first-write-not-from-before-root",
            "A1",
            "5.3",
            "the only write's pre-state is not the before-state root, its post-state is "
            "the after-state root",
            mutate("A1", _e4),
            "write-chain-broken",
        ),
        (
            "E5",
            "e5-last-write-not-to-after-root",
            "A1",
            "5.3",
            "the only write starts from the before-state root and its post-state is not "
            "the after-state root",
            mutate("A1", _e5),
            "write-chain-broken",
        ),
        (
            "E6",
            "e6-no-write-and-unequal-roots",
            "A2",
            "5.3",
            "an empty write set beside an after-state root unequal to the before-state "
            "root, second subject moved to match",
            mutate("A2", _e6),
            "write-chain-broken",
        ),
        (
            "EV5",
            "ev5-not-evaluated-empty-unavailable-input",
            "A10",
            "5.4",
            "not-evaluated with unavailableInput of the empty array",
            mutate("A10", _set("evaluation.unavailableInput", [])),
            "evaluation-inconsistent",
        ),
        (
            "EV6",
            "ev6-unavailable-input-named-twice",
            "A10",
            "5.4",
            "not-evaluated with standing-source named twice",
            mutate("A10", _set("evaluation.unavailableInput", ["standing-source"] * 2)),
            "evaluation-inconsistent",
        ),
        (
            "EV7",
            "ev7-unavailable-input-not-an-array",
            "A10",
            "5.4",
            "not-evaluated with unavailableInput of the string standing-source, not an array",
            mutate("A10", _set("evaluation.unavailableInput", "standing-source")),
            "evaluation-inconsistent",
        ),
        (
            "EV8",
            "ev8-evaluated-unavailable-input-null",
            "A2",
            "5.4",
            "evaluated carrying unavailableInput of null",
            mutate("A2", _set("evaluation.unavailableInput", None)),
            "evaluation-inconsistent",
        ),
        (
            "EV9",
            "ev9-evaluated-unavailable-input-empty-array",
            "A2",
            "5.4",
            "evaluated carrying unavailableInput of the empty array",
            mutate("A2", _set("evaluation.unavailableInput", [])),
            "evaluation-inconsistent",
        ),
        (
            "EV10",
            "ev10-evaluated-unavailable-input-empty-string",
            "A2",
            "5.4",
            "evaluated carrying unavailableInput of the empty string",
            mutate("A2", _set("evaluation.unavailableInput", "")),
            "evaluation-inconsistent",
        ),
        (
            "OV3",
            "ov3-oversight-without-act",
            "A11",
            "5.5",
            "oversight with act removed, recordDigest kept",
            mutate("A11", _drop("oversight.act")),
            "member-missing",
        ),
    ]
    for draft_id, slug, parent, _section, row, build, code in section_rejects:
        member(draft_id, slug, parent, row, build, "malformed", [code])

    define_freshness()
    define_retained()
    define_revision_01()
    rank = {draft_id: i for i, draft_id in enumerate(ORDER)}
    missing = [m["draftId"] for m in MEMBERS if m["draftId"] not in rank]
    if missing or len(rank) != len(MEMBERS):
        raise SystemExit(f"ORDER and the defined members differ: {missing}")
    MEMBERS.sort(key=lambda m: rank[m["draftId"]])


def define_freshness() -> None:
    """Section 5.4 as draft-gilda-audit-agent-audit-record-00 states it: every
    entry of evaluation.inputs, its age from lastResult to decision.reportedAt,
    and the unavailable inputs a verifier derives from the entries. FR1 to FR13
    and EV13 are rows of that draft's Appendix B. FR16 to FR18 are proposed for
    a later revision, numbered past the FR14 and FR15 rows revision 01 prints:
    FR16 refuses a record with no reportedAt, the time every age is measured
    to, FR17a to FR17c are one forwarded value judged at two hops that each
    apply their own maxAge, and FR18 holds the skew tolerance FR9 refuses past,
    so a verifier allowing no skew at all is caught. FR14 and FR15 are rows of
    revision 01 (define_revision_01)."""
    fresh = second_hop_inputs("2026-09-19T10:30:00Z")
    accepts: list[tuple[str, str, str, Callable[[], Built]]] = [
        (
            "FR1",
            "fr1-second-hop-every-input-fresh",
            "A1 written by the second of two hops: each input fresh at decision.reportedAt, "
            "standing-source carried from the first hop with the source's lastResult unchanged",
            _with_inputs("A1", "FR1", fresh),
        ),
        (
            "FR2",
            "fr2-age-equal-to-max-age-is-fresh",
            "FR1 with standing-source's age at decision.reportedAt exactly equal to its "
            "maxAge, 3600 seconds, so the input is fresh",
            _with_inputs("A1", "FR2", second_hop_inputs("2026-09-19T10:04:02Z")),
        ),
        (
            "FR3",
            "fr3-forwarded-standing-one-second-stale",
            "A10 written by the second of two hops, the forwarded standing-source one second "
            "older than its maxAge",
            _with_inputs("A10", "FR3", second_hop_inputs("2026-09-19T10:04:01Z")),
        ),
        (
            "FR4",
            "fr4-forwarded-standing-never-established",
            "A10 written by the second of two hops, which received standing-source as never "
            "established, lastResult of none",
            _with_inputs("A10", "FR4", second_hop_inputs(NEVER_HELD)),
        ),
    ]
    for draft_id, slug, row, build in accepts:
        member(draft_id, slug, None, row, build, "valid", tier="authoritative")

    rejects: list[tuple[str, str, str, str, Callable[[], Built], str]] = [
        (
            "FR5",
            "fr5-entry-without-last-result",
            "FR1",
            "an entry with lastResult removed",
            mutate("FR1", _entry_change(STANDING_ENTRY, lambda e: e.pop("lastResult"))),
            "member-missing",
        ),
        (
            "FR6",
            "fr6-entry-without-max-age",
            "FR1",
            "an entry with maxAge removed",
            mutate("FR1", _entry_change(STANDING_ENTRY, lambda e: e.pop("maxAge"))),
            "member-missing",
        ),
        (
            "FR7",
            "fr7-unavailable-input-names-a-fresh-entry",
            "FR3",
            "unavailableInput naming key-source, whose entry is fresh, in place of standing-source",
            mutate("FR3", _set("evaluation.unavailableInput", ["key-source"])),
            "evaluation-inconsistent",
        ),
        (
            "FR8",
            "fr8-evaluated-beside-a-stale-entry",
            "FR1",
            "evaluated beside an entry one second older than its maxAge",
            mutate(
                "FR1",
                _entry_change(
                    STANDING_ENTRY, lambda e: e.update(lastResult="2026-09-19T10:04:01Z")
                ),
            ),
            "evaluation-inconsistent",
        ),
        (
            "FR9",
            "fr9-last-result-after-the-decision",
            "FR1",
            "an entry whose lastResult is later than decision.reportedAt by 301 seconds, more "
            "than the skew tolerance",
            mutate(
                "FR1",
                _entry_change(KEY_ENTRY, lambda e: e.update(lastResult="2026-09-19T11:09:03Z")),
            ),
            "evaluation-result-after-decision",
        ),
        (
            "FR10",
            "fr10-one-input-in-two-entries",
            "FR1",
            "one input named in two entries",
            mutate(
                "FR1",
                lambda p: p["evaluation"]["inputs"].append(
                    dict(p["evaluation"]["inputs"][KEY_ENTRY])
                ),
            ),
            "evaluation-input-repeated",
        ),
        (
            "FR11",
            "fr11-entry-with-a-fourth-member",
            "FR1",
            "an entry carrying a fourth member, source, this document does not define",
            mutate(
                "FR1",
                _entry_change(
                    KEY_ENTRY, lambda e: e.update(source="https://keys.example.org/jwks")
                ),
            ),
            "evaluation-entry-malformed",
        ),
        (
            "FR12",
            "fr12-entry-input-outside-closed-set",
            "FR1",
            "an entry whose input is network, outside the closed set",
            mutate("FR1", _entry_change(KEY_ENTRY, lambda e: e.update(input="network"))),
            "value-outside-vocabulary",
        ),
        (
            "FR13",
            "fr13-entry-with-negative-max-age",
            "FR1",
            "an entry with a negative maxAge",
            mutate("FR1", _entry_change(KEY_ENTRY, lambda e: e.update(maxAge=-1))),
            "evaluation-entry-malformed",
        ),
        (
            "FR13b",
            "fr13b-negative-max-age-named-unavailable",
            "FR3",
            "FR3 with key-source's maxAge of -1 and unavailableInput naming key-source and "
            "standing-source: the entry a negative maxAge makes stale is named, so only the "
            "sign of maxAge refuses the record",
            mutate("FR3", _fr13b),
            "evaluation-entry-malformed",
        ),
        (
            "EV13",
            "ev13-evaluation-inputs-removed",
            "A1",
            "evaluation.inputs removed, the shape of a record under "
            "draft-gilda-wimse-agent-audit-record-02",
            mutate("A1", _drop("evaluation.inputs")),
            "member-missing",
        ),
        (
            "EV14",
            "ev14-not-evaluated-all-fresh-empty-unavailable-input",
            "A2",
            "A2 recorded as not-evaluated with every entry fresh and unavailableInput of the "
            "empty array: it matches the empty derived set, so only the rule that "
            "not-evaluated names at least one input refuses it",
            mutate("A2", _ev14),
            "evaluation-inconsistent",
        ),
    ]
    #: Members that test a sentence of Section 5.4 no Appendix B row isolates.
    proposed = {"FR13b", "EV14"}
    for draft_id, slug, parent, row, build, code in rejects:
        section = "5.4" if draft_id in proposed else None
        member(draft_id, slug, parent, row, build, "malformed", [code], section=section)

    member(
        "FR16",
        "fr16-no-decision-reported-at",
        "FR1",
        "FR1 with decision.reportedAt removed: no reference time to measure any input's age to",
        mutate("FR1", _drop("decision.reportedAt")),
        "malformed",
        ["member-missing"],
        section="5.4",
    )
    member(
        "FR18",
        "fr18-last-result-inside-skew-tolerance",
        None,
        "FR1 with key-source's lastResult 300 seconds after decision.reportedAt, exactly the "
        "skew tolerance: not malformed, and an age below zero is at most maxAge, so fresh",
        _with_inputs(
            "A1",
            "FR18",
            [
                entry("policy-source", "2026-09-19T10:00:00Z", DAY),
                entry("key-source", "2026-09-19T11:09:02Z", HOUR),
                entry("standing-source", "2026-09-19T10:30:00Z", HOUR),
            ],
        ),
        "valid",
        tier="authoritative",
        section="5.4",
    )
    member(
        "FR17a",
        "fr17a-first-hop-two-hour-max-age-fresh",
        None,
        "the first of two hops: standing-source read from its source at 10:00:00 under the "
        "hop's own maxAge of 7200, 3840 seconds old at its reportedAt of 11:04:00, fresh, "
        "evaluated",
        build_fr17a,
        "valid",
        tier="authoritative",
        section="5.4",
    )
    member(
        "FR17b",
        "fr17b-second-hop-one-hour-max-age-stale",
        None,
        "the second hop, receiving FR17a's standing-source: the source's lastResult of "
        "10:00:00 copied unchanged under this hop's own maxAge of 3600, 3842 seconds old at "
        "11:04:02, stale, not-evaluated naming standing-source, deny beside none",
        build_fr17b,
        "valid",
        tier="authoritative",
        section="5.4",
    )
    member(
        "FR17c",
        "fr17c-second-hop-carries-first-hops-verdict",
        "FR17b",
        "FR17b recorded as evaluated, the first hop's verdict carried over in place of this "
        "hop's own maxAge",
        mutate("FR17b", _fr17c),
        "malformed",
        ["evaluation-inconsistent"],
        section="5.4",
    )


# ---------------------------------------------------------------------------
# Rows of revision 01 (draft-gilda-audit-agent-audit-record-01, Appendix B).
#
# Each member here carries draftRevision and the row identifier revision 01
# prints. The corpus otherwise tests -00, so a reader conforming only to -00
# fails TI6, V4 and V5, and that is the change revision 01 makes:
#
# * Section 5.4: where a decision depended on several values of one input, the
#   entry takes lastResult and maxAge from ONE value, the one whose lastResult
#   plus maxAge is earliest. -00 took the oldest lastResult and the smallest
#   maxAge from different values. FR14 carries the two source values in the
#   manifest's aggregation block, so a producer's aggregation is tested on its
#   input and not only on a prebuilt record; FR15 is the record the -00 rule
#   writes, refused because it reports two fresh values as one stale input.
#   Mikhail Sergeev, review of -00, 20 October 2026 point 1, and
#   probityai/agent-evidence-vectors#249.
# * Section 5.7: a gap inside pathScope beside scopeComplete of true is
#   malformed at any tier (V4, V5), and the tier's coverage clause is
#   scopeComplete of true (TI6). -00's clause was "scopeComplete is true or
#   every gap is outside pathScope", which passed both. Mikhail Sergeev, the
#   same review, point 4, and probityai/agent-evidence-vectors#250.
# ---------------------------------------------------------------------------

REVISION_01 = "draft-gilda-audit-agent-audit-record-01"

#: The two values of standing-source a deny judging two delegation paths
#: depended on, as the producer held them, and decision.reportedAt of A2.
#: Value A is 30 seconds old under 60 and expires at 11:04:32; value B is 3600
#: seconds old under 7200 and expires at 12:04:02. Both are fresh.
FR14_REPORTED_AT = "2026-09-19T11:04:02Z"
FR14_VALUES = [
    {"lastResult": "2026-09-19T11:03:32Z", "maxAge": 60},
    {"lastResult": "2026-09-19T10:04:02Z", "maxAge": 2 * HOUR},
]
#: Index of standing-source in baseline_inputs().
BASELINE_STANDING = 1


def build_fr14() -> Built:
    """A2 with standing-source carrying value A's pair, the earliest expiry."""
    pred = from_pred("A2")
    first = FR14_VALUES[0]
    pred["evaluation"]["inputs"][BASELINE_STANDING] = entry(
        "standing-source", first["lastResult"], first["maxAge"]
    )
    return accept("FR14", pred)


def _fr15(pred: dict[str, Any]) -> None:
    """The -00 aggregation: the oldest lastResult (B's) beside the smallest
    maxAge (A's), from different values, still recorded as evaluated."""
    held = pred["evaluation"]["inputs"][BASELINE_STANDING]
    held["lastResult"] = min(v["lastResult"] for v in FR14_VALUES)
    held["maxAge"] = min(v["maxAge"] for v in FR14_VALUES)


def _coverage(scope_complete: bool, gaps: list[str]) -> Callable[[dict[str, Any]], None]:
    def change(pred: dict[str, Any]) -> None:
        pred["observation"]["coverage"] = {"scopeComplete": scope_complete, "gaps": gaps}

    return change


#: A path under A1's pathScope of /srv/ledger/, and one outside it.
GAP_INSIDE = "/srv/ledger/archive/"
GAP_OUTSIDE = "/srv/reports/"


def define_revision_01() -> None:
    member(
        "TI6",
        "ti6-authoritative-incomplete-gaps-outside-scope",
        "A1",
        "authoritative declared with scopeComplete of false and gaps naming only paths "
        "outside pathScope, which draft-gilda-audit-agent-audit-record-00 accepted",
        mutate("A1", _coverage(False, [GAP_OUTSIDE])),
        "malformed",
        ["tier-overclaim-coverage"],
        revision=REVISION_01,
    )
    member(
        "V4",
        "v4-scope-complete-beside-gap-inside-scope",
        "A1",
        "scopeComplete of true beside a gap inside pathScope, all other tier clauses met: "
        "TI4 with only scopeComplete changed from false to true",
        mutate("A1", _coverage(True, [GAP_INSIDE])),
        "malformed",
        ["coverage-inconsistent"],
        revision=REVISION_01,
    )
    member(
        "V5",
        "v5-scope-complete-beside-gap-inside-scope-voluntary",
        "A5",
        "scopeComplete of true beside a gap inside pathScope, tier of voluntary",
        mutate("A5", _coverage(True, [GAP_INSIDE])),
        "malformed",
        ["coverage-inconsistent"],
        revision=REVISION_01,
    )
    member(
        "FR14",
        "fr14-two-fresh-values-earliest-expiry-pair",
        None,
        "A2 judging two delegation paths, two values of standing-source each fresh at "
        "decision.reportedAt (ages 30 and 3600 seconds under a maxAge of 60 and of 7200), "
        "the entry carrying the first value's pair, the one that expires first",
        build_fr14,
        "valid",
        tier="authoritative",
        revision=REVISION_01,
        aggregation={
            "input": "standing-source",
            "reportedAt": FR14_REPORTED_AT,
            "values": FR14_VALUES,
        },
    )
    member(
        "FR15",
        "fr15-oldest-last-result-beside-smallest-max-age",
        "FR14",
        "the entry carrying the second value's lastResult beside the first value's maxAge, "
        "under evaluated: the pair the -00 rule writes, age 3600 under 60",
        mutate("FR14", _fr15),
        "malformed",
        ["evaluation-inconsistent"],
        revision=REVISION_01,
    )


# ---------------------------------------------------------------------------
# Retained records (Section 4.7, rows R1 to R9).
#
# A retained record is A1's envelope beside the retention entry a retaining
# party keeps for it. Every anchor in these members is a transparency-log
# inclusion proof, the one anchor kind a verifier can validate offline as a
# hash commitment with nothing but a hash function: the proof is the base64 of
# an RFC 9162 TransItem of type inclusion_proof_v2 (Section 4.12), the logged
# entry is the 32 bytes of envelopeDigest, so the leaf hash is
# SHA-256(0x00 || envelopeDigest), and the path recomputes to a tree head by
# RFC 9162 Section 2.1.3.2. The tree heads are published in the manifest under
# anchorTrust: they are the checkpoints a verifier already holds by a means
# other than a signature, which is what makes a transparency-log anchor a hash
# commitment under Section 4.7.2, and each one's timestamp is the time of every
# anchor that recomputes to it.
# ---------------------------------------------------------------------------

#: RFC 5612 reserves enterprise number 32473 for documentation. The test log's
#: identifier is OID 1.3.6.1.4.1.32473.1.1, carried as RFC 9162 Section 4.4 says:
#: the DER contents octets, without tag or length.
LOG_OID = (1, 3, 6, 1, 4, 1, 32473, 1, 1)
INCLUSION_PROOF_V2 = 0x0106
TREE_HEADS: list[dict[str, Any]] = []


def oid_contents(arcs: tuple[int, ...]) -> bytes:
    out = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out.extend(reversed(chunk))
    return bytes(out)


LOG_ID = oid_contents(LOG_OID)


def leaf_hash(entry_bytes: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry_bytes).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """The largest power of two smaller than n (RFC 9162 Section 2.1.1)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def tree_hash(entries: list[bytes]) -> bytes:
    if len(entries) == 1:
        return leaf_hash(entries[0])
    k = _split(len(entries))
    return node_hash(tree_hash(entries[:k]), tree_hash(entries[k:]))


def audit_path(index: int, entries: list[bytes]) -> list[bytes]:
    """PATH(m, D[n]) of RFC 9162 Section 2.1.3.1."""
    if len(entries) == 1:
        return []
    k = _split(len(entries))
    if index < k:
        return audit_path(index, entries[:k]) + [tree_hash(entries[k:])]
    return audit_path(index - k, entries[k:]) + [tree_hash(entries[:k])]


def inclusion_trans_item(tree_size: int, index: int, path: list[bytes]) -> bytes:
    nodes = b"".join(bytes([len(p)]) + p for p in path)
    return (
        INCLUSION_PROOF_V2.to_bytes(2, "big")
        + bytes([len(LOG_ID)])
        + LOG_ID
        + tree_size.to_bytes(8, "big")
        + index.to_bytes(8, "big")
        + len(nodes).to_bytes(2, "big")
        + nodes
    )


def log_anchor(
    label: str, origin: str, timestamp: str, tree_size: int, index: int, logged: bytes
) -> dict[str, Any]:
    """An anchor whose proof places ``logged`` at ``index`` of a test log of
    ``tree_size`` entries, and the tree head that log published at ``timestamp``.
    Every other entry is a literal filler a reader can recompute."""
    entries = [
        bytes.fromhex(h(f"log/{label}/entry-{i}")) if i != index else logged
        for i in range(tree_size)
    ]
    TREE_HEADS.append(
        {
            "logId": LOG_ID.hex(),
            "treeSize": tree_size,
            "rootHash": tree_hash(entries).hex(),
            "timestamp": timestamp,
        }
    )
    proof = inclusion_trans_item(tree_size, index, audit_path(index, entries))
    return {
        "kind": "transparency-log",
        "origin": origin,
        "proof": base64.b64encode(proof).decode(),
    }


def _jwk_set(public: bytes) -> bytes:
    key = {
        "crv": "Ed25519",
        "kid": OBSERVER_KEYID,
        "kty": "OKP",
        "x": base64.urlsafe_b64encode(public).rstrip(b"=").decode(),
    }
    return canonical_bytes({"keys": [key]})


def a1_envelope() -> dict[str, Any]:
    return envelope(signed(from_pred("A1"))["payload"])


def envelope_digest(env: dict[str, Any]) -> str:
    """Section 4.7: the digest of the RFC 8785 bytes of the DSSE envelope object."""
    return digest(env)


def retention_entry(env: dict[str, Any], *, received: bool) -> dict[str, Any]:
    entry_: dict[str, Any] = {
        "envelopeDigest": envelope_digest(env),
        "received": received,
        "anchorWithin": 300,
        "anchors": [],
        "validationData": [
            {
                "for": "envelope",
                "mediaType": "application/jwk-set+json",
                "value": base64.b64encode(_jwk_set(raw_public(OBSERVER_KEY))).decode(),
            }
        ],
    }
    return entry_


RETENTIONS: dict[str, dict[str, Any]] = {}


def retained(
    name: str, change: Callable[[dict[str, Any], bytes], None], parent: str | None = None
) -> Callable[[], Built]:
    """Build R<n>: A1's envelope beside a retention entry. A root member starts
    from an empty entry; a member with a parent starts from that parent's."""

    def build() -> Built:
        env = a1_envelope()
        logged = bytes.fromhex(envelope_digest(env))
        if parent is None:
            entry_ = retention_entry(env, received=False)
        else:
            entry_ = copy.deepcopy(RETENTIONS[parent])
        change(entry_, logged)
        RETENTIONS[name] = copy.deepcopy(entry_)
        return {"retained": {"envelope": env, "retention": entry_}}

    return build


def _r1(entry_: dict[str, Any], logged: bytes) -> None:
    entry_["anchors"] = [log_anchor("r1", "retainer", "2026-09-19T11:05:00Z", 3, 1, logged)]


def _r2(entry_: dict[str, Any], logged: bytes) -> None:
    entry_["received"] = True
    entry_["receivedAt"] = "2026-09-19T11:04:30Z"
    entry_["anchors"] = [
        log_anchor("r2-sender", "received", "2026-09-19T11:04:20Z", 5, 4, logged),
        log_anchor("r2", "retainer", "2026-09-19T11:04:40Z", 6, 2, logged),
    ]


def _r5(entry_: dict[str, Any], logged: bytes) -> None:
    entry_["received"] = True
    entry_["receivedAt"] = "2026-09-19T11:04:30Z"
    entry_["anchors"] = [
        log_anchor("r5-sender", "received", "2026-09-19T11:04:20Z", 7, 0, logged),
        log_anchor("r5", "retainer", "2026-09-19T11:04:26Z", 8, 7, logged),
    ]


def _r7(entry_: dict[str, Any], logged: bytes) -> None:
    entry_["anchors"] = [log_anchor("r7", "retainer", "2026-09-19T11:14:12Z", 4, 3, logged)]


def _r8(entry_: dict[str, Any], logged: bytes) -> None:
    other = bytes.fromhex(h("envelope/another-record"))
    entry_["anchors"] = [log_anchor("r8", "retainer", "2026-09-19T11:05:00Z", 3, 1, other)]


def _set_entry(name: str, value: Any) -> Callable[[dict[str, Any], bytes], None]:
    def change(entry_: dict[str, Any], _logged: bytes) -> None:
        entry_[name] = value

    return change


def _r4(entry_: dict[str, Any], _logged: bytes) -> None:
    entry_["anchors"][1]["origin"] = "received"


def dating(
    *,
    dated_at: str | None,
    entry_: str = "well-formed",
    code: str | None = None,
    receipt: str | None = None,
) -> dict[str, Any]:
    out: dict[str, Any] = {"entry": entry_, "codes": [code] if code else []}
    if dated_at is not None:
        out["datedAt"] = dated_at
    if receipt is not None:
        out["receipt"] = receipt
    return out


def define_retained() -> None:
    """Rows R1 to R9: an envelope with its retention entry. The record is A1 and
    valid in every one; what each row tests is the dating check, whose result
    the manifest carries beside the verdict in expected.dating."""
    rows: list[tuple[str, str, str | None, str, Callable[[], Built], dict[str, Any]]] = [
        (
            "R1",
            "r1-producer-retains-one-anchor",
            None,
            "A1 retained by its producer: received of false and one anchor of origin retainer "
            "inside anchorWithin of issuedAt",
            retained("R1", _r1),
            dating(dated_at="2026-09-19T11:05:00Z"),
        ),
        (
            "R2",
            "r2-received-inside-the-bracket",
            None,
            "A1 received from another party, receivedAt between issuedAt and the retaining "
            "party's anchor obtained on delivery; the sender's own anchor, earlier, dates it",
            retained("R2", _r2),
            dating(dated_at="2026-09-19T11:04:20Z", receipt="asserted-consistent"),
        ),
        (
            "R3",
            "r3-received-after-the-retainer-anchor",
            "R2",
            "receivedAt later than the retaining party's earliest anchor by 301 seconds, more "
            "than the skew tolerance",
            retained("R3", _set_entry("receivedAt", "2026-09-19T11:09:41Z"), "R2"),
            dating(
                dated_at="2026-09-19T11:04:20Z",
                entry_="malformed",
                code="entry-received-after-anchor",
            ),
        ),
        (
            "R4",
            "r4-received-without-a-retainer-anchor",
            "R2",
            "received of true and no anchor of origin retainer: the retaining party's anchor "
            "relabelled received",
            retained("R4", _r4, "R2"),
            dating(
                dated_at="2026-09-19T11:04:20Z",
                entry_="malformed",
                code="entry-retainer-anchor-missing",
            ),
        ),
        (
            "R5",
            "r5-anchored-before-delivery",
            None,
            "R2 with the retaining party's anchor obtained before delivery and receivedAt "
            "inside the bracket: consistent, asserted, never established",
            retained("R5", _r5),
            dating(dated_at="2026-09-19T11:04:20Z", receipt="asserted-consistent"),
        ),
        (
            "R6",
            "r6-received-before-issued",
            "R2",
            "receivedAt earlier than issuedAt by 301 seconds, more than the skew tolerance",
            retained("R6", _set_entry("receivedAt", "2026-09-19T10:59:10Z"), "R2"),
            dating(
                dated_at="2026-09-19T11:04:20Z",
                entry_="malformed",
                code="entry-received-before-issued",
            ),
        ),
        (
            "R7",
            "r7-retainer-anchor-late",
            "R1",
            "the retaining party's first anchor 601 seconds after issuedAt, later than "
            "anchorWithin plus the skew tolerance",
            retained("R7", _r7, "R1"),
            dating(
                dated_at="2026-09-19T11:14:12Z",
                entry_="malformed",
                code="entry-anchor-late",
            ),
        ),
        (
            "R8",
            "r8-anchor-over-another-envelope",
            "R1",
            "the only anchor's proof is over a different envelope digest: it validates for "
            "nothing here, dates nothing and makes nothing malformed",
            retained("R8", _r8, "R1"),
            dating(dated_at=None),
        ),
        (
            "R9",
            "r9-received-at-beside-received-false",
            "R1",
            "receivedAt carried beside received of false",
            retained("R9", _set_entry("receivedAt", "2026-09-19T11:04:30Z"), "R1"),
            dating(
                dated_at="2026-09-19T11:05:00Z",
                entry_="malformed",
                code="entry-received-at-inconsistent",
            ),
        ),
    ]
    for draft_id, slug, parent, row, build, expected_dating in rows:
        member(
            draft_id,
            slug,
            parent,
            row,
            build,
            "valid",
            tier="authoritative",
            dating=expected_dating,
        )


#: Appendix B's order, then the members for rules it carries no row for. A
#: member is built after every member it is built from, which this order keeps.
ORDER = (
    "A1 A2 A3 A4 A5 A6 A7 A8 A9 A10 A11 A12 A13 A14 A15 A16 A17 A18 A19 A20 "
    "F1 F2 F3 F3b F3c F4 F5 F6 F7 T1 T2 T3 T4 T5 D1 D2 D3 S1 S2 I1r "
    "TI1 TI2 TI3 TI4 TI5 C1 C2 C3 E1 E2 E3 E4 E5 E6 V1 V2 V3 FE1 FE2 "
    "FR1 FR2 FR3 FR4 FR5 FR6 FR7 FR8 FR9 FR10 FR11 FR12 FR13 "
    "EV1 EV2 EV3 EV4 EV5 EV6 EV7 EV8 EV9 EV10 EV11 EV12 EV13 OV1 OV2 OV3 N1 N2 "
    "R1 R2 R3 R4 R5 R6 R7 R8 R9 "
    "FR13b FR16 FR17a FR17b FR17c FR18 EV14 "
    "TI6 V4 V5 FR14 FR15"
).split()


def expected_of(entry: Member) -> dict[str, Any]:
    """The manifest's expected block: a settled row's verdict, never an open row's."""
    expected: dict[str, Any] = {"codes": entry["codes"]}
    if entry["verdict"] is not None:
        expected["verdict"] = entry["verdict"]
    if entry["tier"] is not None:
        expected["derivedTier"] = entry["tier"]
    if entry["dating"] is not None:
        expected["dating"] = entry["dating"]
    return expected


def vector_id(body: bytes) -> str:
    return "v" + hashlib.sha256(body).hexdigest()[:ID_HEX]


def optional_fields(entry: Member, ids: dict[str, str]) -> dict[str, Any]:
    """The manifest fields only some members carry."""
    out: dict[str, Any] = {}
    if entry["parent"] is not None:
        out["parent"] = ids[entry["parent"]]
        out["parentDraftId"] = entry["parent"]
    if entry["readings"] is not None:
        out["readings"] = entry["readings"]
    if entry["section"] is not None:
        out["draftSection"] = entry["section"]
    if entry["revision"] is not None:
        out["draftRevision"] = entry["revision"]
    if entry["aggregation"] is not None:
        out["aggregation"] = entry["aggregation"]
    return out


def emit() -> None:
    define()
    statements_dir = os.path.join(HERE, "statements")
    os.makedirs(statements_dir, exist_ok=True)
    built: list[tuple[Member, bytes, str]] = []
    ids: dict[str, str] = {}
    for entry in MEMBERS:
        made = entry["build"]()
        bundle = made["retained"] if "retained" in made else envelope(made["payload"])
        raw = json.dumps(bundle, indent=2, sort_keys=True).encode() + b"\n"
        ident = vector_id(raw)
        if ident in ids.values():
            raise SystemExit(f"identifier collision on {entry['draftId']}")
        ids[entry["draftId"]] = ident
        built.append((entry, raw, ident))

    retained_dir = os.path.join(HERE, "retained")
    os.makedirs(retained_dir, exist_ok=True)
    vectors: list[dict[str, Any]] = []
    keep: set[str] = set()
    for entry, raw, ident in built:
        folder = "retained" if entry["dating"] is not None else "statements"
        rel = f"{folder}/{ident}.json"
        with open(os.path.join(HERE, rel), "wb") as fh:
            fh.write(raw)
        keep.add(rel)
        out: dict[str, Any] = {
            "id": ident,
            "draftId": entry["draftId"],
            "slug": entry["slug"],
            "kind": entry["kind"],
            "file": rel,
            "row": entry["row"],
            "expected": expected_of(entry),
        }
        out.update(optional_fields(entry, ids))
        vectors.append(out)

    for folder in ("statements", "retained"):
        for stale in sorted(os.listdir(os.path.join(HERE, folder))):
            if stale.endswith(".json") and f"{folder}/{stale}" not in keep:
                os.remove(os.path.join(HERE, folder, stale))

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
        "skewTolerance": 300,
        "anchorTrust": {
            "note": (
                "The tree heads of the test transparency log every R member's anchors are "
                "in, as a verifier holds them by a means other than a signature: a "
                "checkpoint it already witnessed. A transparency-log anchor validates as a "
                "hash commitment when its proof, an RFC 9162 TransItem of type "
                "inclusion_proof_v2 over the leaf SHA-256(0x00 || envelopeDigest), "
                "recomputes to one of these for its logId and treeSize; its time is that "
                "head's timestamp."
            ),
            "treeHeads": TREE_HEADS,
        },
        "counts": counts,
        "note": (
            "One member per row of Appendix B of the draft, in the row's order; "
            "draftId is the row's identifier and parentDraftId its from column. The "
            "members after the last row carry draftSection: each tests a rule of that "
            "section that Appendix B carries no row for, and continues the identifier "
            "series of the rows beside it. A member carrying draftRevision is a row of "
            "that later revision's Appendix B, under the identifier it prints, and tests a "
            "rule that revision changes, so a reader conforming only to the draft named "
            "above may fail it. A member carrying aggregation lists the values of one "
            "input the decision depended on, as the producer held them: a producer's "
            "aggregation over those values must yield the entry the record carries. "
            "R1 to R9 are retained records: the file "
            "carries the envelope beside its retention entry, expected.verdict is the "
            "envelope's verdict, and expected.dating is the result of the dating check "
            "of Section 4.7.1, reported beside it and never folded into it. An "
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


def _dating_label(result: dict[str, Any]) -> str:
    dated = f"dated {result['datedAt']}" if "datedAt" in result else "not dated"
    entry_ = "entry " + result["entry"]
    if result["codes"]:
        entry_ += f" ({result['codes'][0]})"
    parts = [dated, entry_]
    if "receipt" in result:
        parts.append("receipt " + result["receipt"])
    return "; ".join(parts)


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
        "must reject. Releases up to and including v0.25.0 tested "
        f"`{PREVIOUS_DRAFT}`; its records carry no `evaluation.inputs`, and each is "
        "malformed under this draft (`EV13`).",
        "",
        "| id | source | from | verdict | file | row |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for v in vectors:
        parent = v.get("parentDraftId", "root")
        if v["kind"] == "indeterminate":
            verdict = " or ".join(r["verdict"] for r in v["readings"])
        else:
            verdict = v["expected"]["verdict"]
        if "dating" in v["expected"]:
            verdict += ", " + _dating_label(v["expected"]["dating"])
        source = f"Section {v['draftSection']}" if "draftSection" in v else "Appendix B"
        lines.append(
            f"| `{v['draftId']}` | {source} | {parent} | {verdict} | "
            f"[`{v['id']}`]({v['file']}) | {v['row']} |"
        )
    with open(os.path.join(HERE, "INDEX.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    emit()
