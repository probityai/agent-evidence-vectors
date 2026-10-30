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
import datetime
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
ConsumptionRow = tuple[str, str, str | None, str, Callable[[], Built], str, list[str], bool | None]
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
    within: bool | None = None,
    joint: dict[str, Any] | None = None,
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
            "within": within,
            "joint": joint,
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
    define_consumption()
    define_consumption_carryover()
    define_audit_next()
    define_reject_paths()
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
REVISION_03 = "draft-gilda-audit-agent-audit-record-03"

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
# Consumption binding (Section 5.4 of revision 01): rows CS1 to CS25.
#
# A decision under a cumulative limit carries decision.operationKey, the
# agent's identifier for one intended operation, and its consumption-state
# entry carries the consumption member. Retry identity is the operation key,
# never the request digest: a request digest is a content digest, so two
# identical intended payments share one and the second must still be counted.
# The worked numbers are a limit of 50000 pence with 30000 consumed and a
# request of 12000 (probityai/agent-evidence-vectors#213).
#
# CS18 to CS25 cover a limit document that is replaced while a permit is held.
# consumption.supersedes names the limit document a record's limitDigest
# replaced, the set checks group records by the ledger that link draws, and a
# retry is still the operation key, never the limit. CS25 is the control: two
# limit documents no supersedes links stay two ledgers.
# ---------------------------------------------------------------------------

CS_LIMIT_DOCUMENT = h("limit/spend-limit-document")
CS_OTHER_LIMIT_DOCUMENT = h("limit/limit-document-named-by-the-authority")
CS_RAISED_LIMIT_DOCUMENT = h("limit/spend-limit-document-raised")
CS_CUT_LIMIT_DOCUMENT = h("limit/spend-limit-document-cut")
CS_SEPARATE_LIMIT_DOCUMENT = h("limit/spend-limit-document-of-another-ledger")
CS_HELD_REQUEST = h("request/the-first-call-as-the-held-entry-recorded-it")
OP_R1, OP_R2, OP_R3 = "urn:example:op:r1", "urn:example:op:r2", "urn:example:op:r3"
CONSUMPTION_ENTRY = 2


def held_entry(key: str, request_digest: str, amount: int) -> dict[str, Any]:
    return {"operationKey": key, "requestDigest": request_digest, "amount": amount}


def consumption_pred(
    *,
    key: str = OP_R1,
    consumed: int = 30000,
    requested: int = 12000,
    held: list[dict[str, Any]] | None = None,
    revision: int = 41,
    limit_digest: str = CS_LIMIT_DOCUMENT,
    limit: int = 50000,
    supersedes: str | None = None,
) -> dict[str, Any]:
    """The baseline decision under a 50000 GBP pence limit, carrying its operation
    key and the consumption it read."""
    pred = baseline()
    held = held or []
    pred["decision"]["operationKey"] = key
    state = entry("consumption-state", "2026-09-19T11:04:00Z", 60)
    state["consumption"] = {
        "limitDigest": limit_digest,
        "unit": "GBP",
        "limit": limit,
        "consumed": consumed,
        "reserved": sum(item["amount"] for item in held),
        "requested": requested,
        "held": held,
        "stateRevision": revision,
    }
    if supersedes is not None:
        state["consumption"]["supersedes"] = supersedes
    pred["evaluation"]["inputs"] = baseline_inputs() + [state]
    return pred


def _consumption(pred: dict[str, Any]) -> dict[str, Any]:
    found: dict[str, Any] = pred["evaluation"]["inputs"][CONSUMPTION_ENTRY]["consumption"]
    return found


def cs_root(name: str, **knobs: Any) -> Callable[[], Built]:
    def build() -> Built:
        return accept(name, consumption_pred(**knobs))

    return build


def cs_from(
    parent: str, name: str, change: Callable[[dict[str, Any]], None]
) -> Callable[[], Built]:
    def build() -> Built:
        pred = from_pred(parent)
        change(pred)
        return accept(name, pred)

    return build


def _cs4(pred: dict[str, Any]) -> None:
    """The retry: the held entry is this call's own key and request digest."""
    state = _consumption(pred)
    state["held"] = [held_entry(OP_R1, pred["decision"]["requestDigest"], 12000)]
    state["reserved"] = 12000
    state["stateRevision"] = 42


def _cs3(pred: dict[str, Any]) -> None:
    _consumption(pred)["reserved"] = 12000


def _cs10(pred: dict[str, Any]) -> None:
    _consumption(pred)["held"][0]["requestDigest"] = CS_HELD_REQUEST


def _cs11(pred: dict[str, Any]) -> None:
    pred["decision"]["operationKey"] = OP_R2
    _consumption(pred)["consumed"] = 20000


def _cs13(pred: dict[str, Any]) -> None:
    state = _consumption(pred)
    digest_ = state["held"][0]["requestDigest"]
    state["held"] = [held_entry(OP_R1, digest_, 12000), held_entry(OP_R1, digest_, 12000)]
    state["reserved"] = 24000


def _cs6(pred: dict[str, Any]) -> None:
    pred["evaluation"]["inputs"][0]["consumption"] = copy.deepcopy(_consumption(pred))


def _second_operation(
    *,
    key: str,
    revision: int,
    same_request: bool,
    held: list[dict[str, Any]] | None = None,
    consumed: int = 30000,
    requested: int = 12000,
    record: str,
    limit_digest: str = CS_LIMIT_DOCUMENT,
    limit: int = 50000,
    supersedes: str | None = None,
) -> dict[str, Any]:
    pred = consumption_pred(
        key=key,
        revision=revision,
        held=held,
        consumed=consumed,
        requested=requested,
        limit_digest=limit_digest,
        limit=limit,
        supersedes=supersedes,
    )
    pred["recordId"] = f"urn:example:record:{record}"
    if not same_request:
        pred["resource"]["argumentsDigest"] = h("arguments/settlements-append-second")
        rebind_request(pred)
    seal_commitment(pred)
    return pred


def cs_set(
    name: str, build_second: Callable[[dict[str, Any]], dict[str, Any]], first: str = "CS4"
) -> Callable[[], Built]:
    """A set member: two records under one limitDigest, the first a member of the
    corpus in its own right, the second built from the first."""

    def build() -> Built:
        a = from_pred(first)
        b = build_second(a)
        PREDICATES[name] = copy.deepcopy(b)
        return {"set": [signed(a)["payload"], signed(b)["payload"]]}

    return build


def _stale_second(same_request: bool) -> Callable[[dict[str, Any]], dict[str, Any]]:
    def second(_first: dict[str, Any]) -> dict[str, Any]:
        return _second_operation(
            key=OP_R2, revision=41, same_request=same_request, record="cs-second"
        )

    return second


def _release_pair(name: str) -> Callable[[], Built]:
    """CS8: the first record reads revision 42 with the first call held; the
    second reads revision 43 and no longer holds it, and no record of that
    operation is in the set."""

    def build() -> Built:
        held = [held_entry(OP_R1, CS_HELD_REQUEST, 12000)]
        a = _second_operation(
            key=OP_R2,
            revision=42,
            same_request=False,
            held=held,
            requested=5000,
            record="cs8-first",
        )
        b = _second_operation(
            key=OP_R3,
            revision=43,
            same_request=False,
            consumed=35000,
            requested=5000,
            record="cs8-second",
        )
        PREDICATES[name] = copy.deepcopy(b)
        return {"set": [signed(a)["payload"], signed(b)["payload"]]}

    return build


def _ledger_set(name: str, records: Callable[[], list[dict[str, Any]]]) -> Callable[[], Built]:
    """A set member whose records are one ledger across a limit replacement."""

    def build() -> Built:
        built = records()
        PREDICATES[name] = copy.deepcopy(built[-1])
        return {"set": [signed(pred)["payload"] for pred in built]}

    return build


def _held_under_first_limit(record: str) -> dict[str, Any]:
    """The record every replacement set starts from: a new operation, under the
    first limit document, that reads revision 42 with the first call held (CS4's
    call, the entry carrying its own request digest and amount)."""
    held = [held_entry(OP_R1, PREDICATES["CS4"]["decision"]["requestDigest"], 12000)]
    return _second_operation(
        key=OP_R2, revision=42, same_request=False, held=held, requested=5000, record=record
    )


def _retry_after_replacement(limit: int, limit_digest: str) -> dict[str, Any]:
    """CS4's retry of the held call, read at revision 43 under a limit document
    that replaces the first one."""
    pred = from_pred("CS4")
    _consumption(pred).update(
        limitDigest=limit_digest, limit=limit, stateRevision=43, supersedes=CS_LIMIT_DOCUMENT
    )
    return pred


def _raise_pair() -> list[dict[str, Any]]:
    return [
        _held_under_first_limit("cs18-first"),
        _retry_after_replacement(80000, CS_RAISED_LIMIT_DOCUMENT),
    ]


def _cut_pair() -> list[dict[str, Any]]:
    return [
        _held_under_first_limit("cs19-first"),
        _retry_after_replacement(40000, CS_CUT_LIMIT_DOCUMENT),
    ]


def _new_operation_after_cut(record: str, revision: int, consumed: int) -> dict[str, Any]:
    """A new operation, third in the series, under the cut limit document that
    replaces the first and does not carry the held call."""
    return _second_operation(
        key=OP_R3,
        revision=revision,
        same_request=False,
        consumed=consumed,
        requested=5000,
        record=record,
        limit_digest=CS_CUT_LIMIT_DOCUMENT,
        limit=45000,
        supersedes=CS_LIMIT_DOCUMENT,
    )


def _dropped_pair() -> list[dict[str, Any]]:
    return [
        _held_under_first_limit("cs20-first"),
        _new_operation_after_cut("cs20-second", 43, 35000),
    ]


def _stale_pair() -> list[dict[str, Any]]:
    return [
        _held_under_first_limit("cs21-first"),
        _new_operation_after_cut("cs21-second", 41, 30000),
    ]


def _separate_ledger_set() -> list[dict[str, Any]]:
    """CS20's shape with the link removed: the second record is a new operation
    under a different limit document that names no supersedes, and omits the
    held call. Two limit documents nothing links are two ledgers."""
    return [
        _held_under_first_limit("cs25-first"),
        _second_operation(
            key=OP_R3,
            revision=43,
            same_request=False,
            consumed=35000,
            requested=5000,
            record="cs25-second",
            limit_digest=CS_SEPARATE_LIMIT_DOCUMENT,
            limit=45000,
        ),
    ]


def _settled_set() -> list[dict[str, Any]]:
    """CS20's pair and the record of the held call's own operation, a retry
    denied under the cut limit with effect none, which releases it."""
    denied = consumption_pred(
        key=OP_R1,
        revision=44,
        consumed=35000,
        requested=12000,
        limit_digest=CS_CUT_LIMIT_DOCUMENT,
        limit=45000,
    )
    denied["recordId"] = "urn:example:record:cs22-third"
    denied["decision"]["reported"] = "deny"
    denied["effect"]["observed"] = "none"
    denied["effect"]["writes"] = []
    denied["effect"]["interval"]["afterRoot"] = BEFORE
    seal_commitment(denied)
    return [*_dropped_pair(), denied]


def define_consumption() -> None:
    rows: list[ConsumptionRow] = [
        (
            "CS1",
            "cs1-within-limit-nothing-held",
            None,
            "a consumption entry under a limit of 50000: consumed 30000, nothing held, requested "
            "12000, so 42000 of 50000",
            cs_root("CS1"),
            "valid",
            [],
            True,
        ),
        (
            "CS2",
            "cs2-beyond-limit-permit",
            "CS1",
            "CS1 with requested 25000, 55000 of 50000, still a permit: valid and findable, a "
            "decision point exceeding its authority",
            cs_from("CS1", "CS2", lambda p: _consumption(p).update(requested=25000)),
            "valid",
            [],
            False,
        ),
        (
            "CS3",
            "cs3-reserved-not-the-held-sum",
            "CS1",
            "CS1 with reserved 12000 and nothing held",
            mutate("CS1", _cs3),
            "malformed",
            ["consumption-reserved-mismatch"],
            None,
        ),
        (
            "CS4",
            "cs4-retry-not-counted-twice",
            "CS1",
            "the retry of the first call: operationKey and requestDigest equal a held entry of "
            "12000, within the limit (42000) only because it is not counted twice",
            cs_from("CS1", "CS4", _cs4),
            "valid",
            [],
            True,
        ),
        (
            "CS5",
            "cs5-negative-requested",
            "CS1",
            "CS1 with requested of -1",
            mutate("CS1", lambda p: _consumption(p).update(requested=-1)),
            "malformed",
            ["consumption-value-invalid"],
            None,
        ),
        (
            "CS6",
            "cs6-consumption-on-a-policy-source-entry",
            "CS1",
            "CS1 with the consumption member also on the policy-source entry",
            mutate("CS1", _cs6),
            "malformed",
            ["consumption-misplaced"],
            None,
        ),
        (
            "CS9",
            "cs9-no-state-revision",
            "CS1",
            "CS1 with stateRevision removed",
            mutate("CS1", lambda p: _consumption(p).pop("stateRevision")),
            "malformed",
            ["member-missing"],
            None,
        ),
        (
            "CS10",
            "cs10-held-key-with-another-request",
            "CS4",
            "CS4 with the held entry's requestDigest another request's: one operation key "
            "reused for a different request",
            mutate("CS4", _cs10),
            "malformed",
            ["consumption-key-reused"],
            None,
        ),
        (
            "CS11",
            "cs11-new-operation-same-request-within-limit",
            "CS4",
            "CS4 under another operationKey with consumed 20000: the same intended payment "
            "again, a new operation counted (20000 + 12000 + 12000 = 44000 of 50000)",
            cs_from("CS4", "CS11", _cs11),
            "valid",
            [],
            True,
        ),
        (
            "CS12",
            "cs12-new-operation-same-request-beyond-limit",
            "CS4",
            "CS4 under another operationKey: counted it is 54000 of 50000, and read as a retry "
            "of the held call it would be 42000",
            cs_from("CS4", "CS12", lambda p: p["decision"].update(operationKey=OP_R2)),
            "valid",
            [],
            False,
        ),
        (
            "CS13",
            "cs13-two-held-entries-one-key",
            "CS4",
            "CS4 with two held entries under one operationKey, 12000 each, summing to reserved",
            mutate("CS4", _cs13),
            "malformed",
            ["consumption-held-key-repeated"],
            None,
        ),
        (
            "CS14",
            "cs14-no-operation-key",
            "CS1",
            "CS1 with decision.operationKey removed",
            mutate("CS1", lambda p: p["decision"].pop("operationKey")),
            "malformed",
            ["member-missing"],
            None,
        ),
        (
            "CS15",
            "cs15-limit-document-differs-from-authority",
            "CS1",
            "CS1 with limitDigest the digest of a limit document the authority names: not "
            "delegation.authorityDigest, and valid",
            cs_from(
                "CS1", "CS15", lambda p: _consumption(p).update(limitDigest=CS_OTHER_LIMIT_DOCUMENT)
            ),
            "valid",
            [],
            True,
        ),
        (
            "CS16",
            "cs16-limit-document-is-the-authority",
            "CS1",
            "CS1 with limitDigest equal to delegation.authorityDigest, the authority document "
            "stating the limit itself",
            cs_from(
                "CS1",
                "CS16",
                lambda p: _consumption(p).update(limitDigest=p["delegation"]["authorityDigest"]),
            ),
            "valid",
            [],
            True,
        ),
        (
            "CS23",
            "cs23-supersedes-names-its-own-limit-document",
            "CS1",
            "CS1 with supersedes the record's own limitDigest: a limit document cannot replace "
            "itself",
            mutate("CS1", lambda p: _consumption(p).update(supersedes=CS_LIMIT_DOCUMENT)),
            "malformed",
            ["consumption-supersedes-self"],
            None,
        ),
        (
            "CS24",
            "cs24-supersedes-is-not-a-digest",
            "CS1",
            "CS1 with supersedes a string that is not a digest",
            mutate("CS1", lambda p: _consumption(p).update(supersedes="limit-document-v1")),
            "malformed",
            ["consumption-value-invalid"],
            None,
        ),
    ]
    for draft_id, slug, parent, row, build, verdict, codes, within in rows:
        member(
            draft_id,
            slug,
            parent,
            row,
            build,
            verdict,
            codes,
            tier="authoritative" if verdict == "valid" else None,
            revision=REVISION_01,
            within=within,
        )
    sets = [
        (
            "CS7",
            "cs7-set-stale-revision-omits-held",
            _stale_second(False),
            "the retry of the first call, which reads revision 42 and holds it, then a new "
            "operation that reads revision 41, omits the held call and is permitted: each record "
            "valid, the pair spends the limit twice",
            "consumption-set-stale-revision",
        ),
        (
            "CS17",
            "cs17-set-stale-revision-identical-request",
            _stale_second(True),
            "CS7 where the second operation is the same intended payment, an identical "
            "requestDigest under another operationKey: the set still fails, so the check keys on "
            "the operation key and not on the request digest",
            "consumption-set-stale-revision",
        ),
    ]
    for draft_id, slug, second, row, code in sets:
        member(
            draft_id,
            slug,
            "CS4",
            row,
            cs_set(draft_id, second),
            "valid",
            tier="authoritative",
            revision=REVISION_01,
            joint={"verdict": "malformed", "codes": [code], "withinLimit": [True, True]},
        )
    member(
        "CS8",
        "cs8-set-release-without-a-none-record",
        None,
        "a record reading revision 42 holds an earlier call; the next, reading revision 43, "
        "no longer holds it, and no record of that operation shows none or occurred: each "
        "record valid, the release is unexplained",
        _release_pair("CS8"),
        "valid",
        tier="authoritative",
        revision=REVISION_01,
        joint={
            "verdict": "malformed",
            "codes": ["consumption-set-release-unshown"],
            "withinLimit": [True, True],
        },
    )
    replaced = [
        (
            "CS18",
            "cs18-set-limit-raised-while-held",
            "a call is held under the first limit document; the limit is raised, and the retry "
            "of the held call is read under the new document, which names the first as "
            "supersedes and carries the held entry unchanged: each record valid, the set valid",
            _raise_pair,
            "valid",
            None,
            [True, True],
        ),
        (
            "CS19",
            "cs19-set-limit-cut-while-held",
            "CS18 where the new document cuts the limit below what is consumed and held: the "
            "retry is not counted twice and is beyond the cut limit, so its withinLimit is "
            "false. Each record valid, the set valid, and the over-limit permit is findable",
            _cut_pair,
            "valid",
            None,
            [True, False],
        ),
        (
            "CS20",
            "cs20-set-held-permit-dropped-on-replacement",
            "a call is held under the first limit document; the limit is cut, and the next "
            "record, under the new document that names the first as supersedes, is a new "
            "operation that omits the held call, with no record of that call showing none or "
            "occurred: each record valid, the held permit left unseen, the set is malformed",
            _dropped_pair,
            "malformed",
            "consumption-set-release-unshown",
            [True, True],
        ),
        (
            "CS21",
            "cs21-set-stale-revision-across-replacement",
            "CS20 where the record under the new document read a stateRevision older than the "
            "record holding the permit and omits it: each record valid, the set malformed "
            "across the replacement",
            _stale_pair,
            "malformed",
            "consumption-set-stale-revision",
            [True, True],
        ),
        (
            "CS22",
            "cs22-set-held-permit-settled-across-replacement",
            "CS20 where the set also holds the record of the held call's own operation, "
            "denied under the cut limit with effect none: the release is shown, the set valid",
            _settled_set,
            "valid",
            None,
            [True, True, False],
        ),
        (
            "CS25",
            "cs25-set-separate-ledger-no-supersedes",
            "CS20 without the link: a call is held under the first limit document, and the next "
            "record is a new operation under a different limit document that names no "
            "supersedes and omits the held call: each record valid, the two limit documents are "
            "two ledgers, the set valid",
            _separate_ledger_set,
            "valid",
            None,
            [True, True],
        ),
    ]
    for draft_id, slug, row, records, verdict, joint_code, limits in replaced:
        member(
            draft_id,
            slug,
            None,
            row,
            _ledger_set(draft_id, records),
            "valid",
            tier="authoritative",
            revision=REVISION_01,
            joint={
                "verdict": verdict,
                "codes": [joint_code] if joint_code else [],
                "withinLimit": limits,
            },
        )


# ---------------------------------------------------------------------------
# CS26 to CS33: what a limit replacement does to a claim, from the enforcement
# answer on modelcontextprotocol/financial-services-interest-group#17. A call
# refused before the tool ran, or whose tool reported nothing sent, leaves no
# claim, so its retry is new under the limit then in force: a raise admits it
# (CS26), a cut refuses it (CS27), and a record of the operation showing none
# ends a claim that was held (CS28). Any other call keeps its claim, keyed by
# the principal, the agent key and the operation key, never by the limit
# document: an unknown outcome is carried over (CS29) and cannot be dropped
# (CS30), and a permit that presents the held key as a new operation under a
# new limit document is caught whether or not that document names the old one
# (CS31, CS32). CS33 is the control: the same operation key under another
# principal and agent key is another claim.
#
# CS34 to CS40: the exact asset. consumption may carry asset, a CAIP-19 asset
# id with the decimals of its smallest subunit, in place of the ISO 4217 unit
# (vendrell46 on the same thread). One ledger counts one denomination.
# ---------------------------------------------------------------------------

USDC_BASE = "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
USDC_SOLANA = (
    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp/token:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
)
OTHER_PRINCIPAL = "user:bob@example.org"
OTHER_AGENT_KEYID = hashlib.sha256(b"another agent key").hexdigest()[:32]


def _named(pred: dict[str, Any], record: str) -> dict[str, Any]:
    pred["recordId"] = f"urn:example:record:{record}"
    seal_commitment(pred)
    return pred


def _refused_before_run(pred: dict[str, Any]) -> None:
    """A deny: the tool never ran, so the effect is none and nothing is claimed."""
    pred["decision"]["reported"] = "deny"
    _effect_none(pred)
    pred["agreement"] = "agree"


def _effect_none(pred: dict[str, Any]) -> None:
    pred["effect"]["observed"] = "none"
    pred["effect"]["writes"] = []
    pred["effect"]["interval"]["afterRoot"] = BEFORE
    pred["agreement"] = "not-exercised"


def _effect_unknown(pred: dict[str, Any]) -> None:
    after = h("root/after-unattributed-write-of-the-held-call")
    pred["effect"]["writes"] = [write(LEDGER_PATH, BEFORE, after, "unattributed")]
    pred["effect"]["interval"]["afterRoot"] = after
    pred["effect"]["observed"] = "unknown"
    pred["agreement"] = "indeterminate"


def _refused_then_retried(cut: bool) -> list[dict[str, Any]]:
    """CS26 and CS27: the first call is refused before its tool ran, under the
    first limit document; its retry, the same operation key and request, is read
    under the replacement with nothing held. Under the raise (80000) a request of
    25000 the first limit could not admit is within; under the cut (40000) a
    request of 12000 the first limit could admit is not, and is refused."""
    requested = 12000 if cut else 25000
    first = consumption_pred(key=OP_R1, revision=41, requested=requested)
    _refused_before_run(first)
    retry = consumption_pred(
        key=OP_R1,
        revision=42,
        requested=requested,
        limit_digest=CS_CUT_LIMIT_DOCUMENT if cut else CS_RAISED_LIMIT_DOCUMENT,
        limit=40000 if cut else 80000,
        supersedes=CS_LIMIT_DOCUMENT,
    )
    if cut:
        _refused_before_run(retry)
    return [
        _named(first, f"cs{27 if cut else 26}-first"),
        _named(retry, f"cs{27 if cut else 26}-retry"),
    ]


def _held_retry_record(
    record: str, revision: int, effect: Callable[[dict[str, Any]], None]
) -> dict[str, Any]:
    """The held call's own retry record under the first limit document, holding
    its own key (CS4's shape), with the effect its tool reported."""
    pred = from_pred("CS4")
    _consumption(pred)["stateRevision"] = revision
    effect(pred)
    return _named(pred, record)


def _nothing_sent_then_new() -> list[dict[str, Any]]:
    """CS28: a call is held; its tool reports nothing sent (effect none), which
    ends the claim; under the raised limit the same key is a new operation."""
    new = consumption_pred(
        key=OP_R1,
        revision=44,
        limit_digest=CS_RAISED_LIMIT_DOCUMENT,
        limit=80000,
        supersedes=CS_LIMIT_DOCUMENT,
    )
    return [
        _held_under_first_limit("cs28-first"),
        _held_retry_record("cs28-nothing-sent", 43, _effect_none),
        _named(new, "cs28-new"),
    ]


def _unknown_carried(dropped: bool) -> list[dict[str, Any]]:
    """CS29 and CS30: a call is held and its retry's outcome is unknown; the limit
    is raised, and a new operation under the new document carries the held
    entry (CS29) or omits it (CS30)."""
    held = (
        []
        if dropped
        else [held_entry(OP_R1, PREDICATES["CS4"]["decision"]["requestDigest"], 12000)]
    )
    name = "cs30" if dropped else "cs29"
    later = _second_operation(
        key=OP_R3,
        revision=44,
        same_request=False,
        held=held,
        consumed=30000,
        requested=5000,
        record=f"{name}-new",
        limit_digest=CS_RAISED_LIMIT_DOCUMENT,
        limit=80000,
        supersedes=CS_LIMIT_DOCUMENT,
    )
    return [
        _held_under_first_limit(f"{name}-first"),
        _held_retry_record(f"{name}-unknown", 43, _effect_unknown),
        later,
    ]


def _forged_new(linked: bool, other_scope: bool = False) -> list[dict[str, Any]]:
    """CS31 to CS33: a call is held under the first limit document; a permit for
    the same operation key, under a raised limit document, holds nothing and
    counts the request again as a new operation."""
    forged = consumption_pred(
        key=OP_R1,
        revision=43,
        limit_digest=CS_RAISED_LIMIT_DOCUMENT,
        limit=80000,
        supersedes=CS_LIMIT_DOCUMENT if linked else None,
    )
    if other_scope:
        forged["delegation"]["subject"] = OTHER_PRINCIPAL
        forged["agent"]["signers"] = [OTHER_AGENT_KEYID]
    name = "cs33" if other_scope else ("cs31" if linked else "cs32")
    return [_held_under_first_limit(f"{name}-first"), _named(forged, f"{name}-forged")]


def _in_asset(pred: dict[str, Any], asset_id: str, decimals: int = 6) -> None:
    """Count the consumption in a token: no ISO 4217 unit, the CAIP-19 asset and
    its decimals, amounts in micro-USDC (50 USDC, 30 consumed, 12 requested)."""
    state = _consumption(pred)
    del state["unit"]
    state["asset"] = {"id": asset_id, "decimals": decimals}
    state["limit"], state["consumed"], state["requested"] = 50_000_000, 30_000_000, 12_000_000


def _asset_pair(second_asset: str, decimals: int, unlinked: bool = False) -> list[dict[str, Any]]:
    """CS38 to CS40: two new operations under one limit document, the first
    counted in USDC on Base, the second in second_asset at decimals."""
    first = consumption_pred(key=OP_R2, revision=41)
    _in_asset(first, USDC_BASE)
    second = consumption_pred(
        key=OP_R3,
        revision=42,
        limit_digest=CS_SEPARATE_LIMIT_DOCUMENT if unlinked else CS_LIMIT_DOCUMENT,
    )
    _in_asset(second, second_asset, decimals)
    second["resource"]["argumentsDigest"] = h("arguments/settlements-append-second")
    rebind_request(second)
    return [_named(first, "asset-first"), _named(second, "asset-second")]


def define_consumption_carryover() -> None:
    sets: list[
        tuple[str, str, str, Callable[[], list[dict[str, Any]]], str, str | None, list[bool]]
    ] = [
        (
            "CS26",
            "cs26-set-refused-before-run-retried-under-raise",
            "a call refused before its tool ran under the first limit document (25000 on 30000 "
            "consumed of 50000) leaves no claim; its retry, the same operation key and request, "
            "is read under a raised limit document that names the first as supersedes, holds "
            "nothing and is counted as new: within the raise, permitted, the set valid",
            lambda: _refused_then_retried(False),
            "valid",
            None,
            [False, True],
        ),
        (
            "CS27",
            "cs27-set-refused-before-run-retried-under-cut",
            "CS26 under a cut: a call of 12000 refused before its tool ran leaves no claim, "
            "and its retry is checked as new under the cut limit of 40000, where it is over "
            "the limit and refused: the set valid",
            lambda: _refused_then_retried(True),
            "valid",
            None,
            [True, False],
        ),
        (
            "CS28",
            "cs28-set-nothing-sent-ends-claim-across-replacement",
            "a call is held; the record of its retry shows the tool sent nothing (effect none), "
            "which ends the claim; under a raised limit document the same operation key is then "
            "a new operation, holds nothing and is counted: the set valid",
            _nothing_sent_then_new,
            "valid",
            None,
            [True, True, True],
        ),
        (
            "CS29",
            "cs29-set-unknown-outcome-carried-over-replacement",
            "a call is held and the record of its retry shows an unknown outcome; the limit is "
            "raised, and a new operation under the new document carries the held entry "
            "unchanged: the claim survives the replacement, the set valid",
            lambda: _unknown_carried(False),
            "valid",
            None,
            [True, True, True],
        ),
        (
            "CS30",
            "cs30-set-unknown-outcome-dropped-on-replacement",
            "CS29 where the new operation under the new document omits the held entry: an "
            "unknown outcome does not release a claim, so the release is unexplained",
            lambda: _unknown_carried(True),
            "malformed",
            "consumption-set-release-unshown",
            [True, True, True],
        ),
        (
            "CS31",
            "cs31-set-held-retry-forged-as-new-under-replacement",
            "a call is held under the first limit document; a permit for the same operation key, "
            "under a raised document that names the first as supersedes, holds nothing and counts "
            "the request again as a new operation: each record valid, the retry presented as new",
            lambda: _forged_new(True),
            "malformed",
            "consumption-set-retry-as-new",
            [True, True],
        ),
        (
            "CS32",
            "cs32-set-held-retry-forged-as-new-under-unlinked-limit",
            "CS31 where the new limit document names no supersedes: the claim is keyed by the "
            "principal, the agent key and the operation key, never by the limit document, so "
            "leaving out the link does not make the retry new",
            lambda: _forged_new(False),
            "malformed",
            "consumption-set-retry-as-new",
            [True, True],
        ),
        (
            "CS33",
            "cs33-set-same-key-other-principal-and-agent-key",
            "CS32 where the second permit is under another principal and another agent key: the "
            "same operation key in another scope is another claim, the set valid",
            lambda: _forged_new(False, other_scope=True),
            "valid",
            None,
            [True, True],
        ),
        (
            "CS38",
            "cs38-set-usdc-base-and-usdc-solana-one-limit",
            "two operations under one limit document, the first counted in USDC on Base "
            f"({USDC_BASE}), the second in USDC on Solana ({USDC_SOLANA}): two assets in one "
            "ledger, the set malformed",
            lambda: _asset_pair(USDC_SOLANA, 6),
            "malformed",
            "consumption-set-asset-mismatch",
            [True, True],
        ),
        (
            "CS39",
            "cs39-set-asset-decimals-mismatch",
            "CS38 where both operations name USDC on Base and the second declares decimals 18: "
            "one amount read at two scales, the set malformed",
            lambda: _asset_pair(USDC_BASE, 18),
            "malformed",
            "consumption-set-asset-mismatch",
            [True, True],
        ),
        (
            "CS40",
            "cs40-set-two-assets-two-ledgers",
            "CS38 where the second operation is under another limit document that names no "
            "supersedes: two ledgers, each counting one asset, the set valid",
            lambda: _asset_pair(USDC_SOLANA, 6, unlinked=True),
            "valid",
            None,
            [True, True],
        ),
    ]
    singles: list[ConsumptionRow] = [
        (
            "CS34",
            "cs34-asset-usdc-on-base",
            "CS1",
            "CS1 counted in USDC on Base: no unit, asset carrying the CAIP-19 id "
            f"{USDC_BASE} and decimals 6, amounts in its smallest subunit",
            cs_from("CS1", "CS34", lambda p: _in_asset(p, USDC_BASE)),
            "valid",
            [],
            True,
        ),
        (
            "CS35",
            "cs35-asset-id-not-caip19",
            "CS34",
            "CS34 with asset.id USDC, a ticker that names no chain or contract",
            mutate("CS34", lambda p: _consumption(p)["asset"].update(id="USDC")),
            "malformed",
            ["consumption-value-invalid"],
            None,
        ),
        (
            "CS36",
            "cs36-asset-decimals-out-of-range",
            "CS34",
            "CS34 with asset.decimals 256, beyond any token's decimals",
            mutate("CS34", lambda p: _consumption(p)["asset"].update(decimals=256)),
            "malformed",
            ["consumption-value-invalid"],
            None,
        ),
        (
            "CS37",
            "cs37-asset-and-unit-both",
            "CS34",
            "CS34 that also carries unit USD: the amounts would be read in two subunits",
            mutate("CS34", lambda p: _consumption(p).update(unit="USD")),
            "malformed",
            ["consumption-unit-ambiguous"],
            None,
        ),
    ]

    def add_sets(chosen: list[Any]) -> None:
        for draft_id, slug, row, records, verdict, joint_code, limits in chosen:
            member(
                draft_id,
                slug,
                None,
                row,
                _ledger_set(draft_id, records),
                "valid",
                tier="authoritative",
                revision=REVISION_01,
                joint={
                    "verdict": verdict,
                    "codes": [joint_code] if joint_code else [],
                    "withinLimit": limits,
                },
            )

    add_sets(sets[:8])
    for draft_id, slug, parent, row, build, verdict, codes, within in singles:
        member(
            draft_id,
            slug,
            parent,
            row,
            build,
            verdict,
            codes,
            tier="authoritative" if verdict == "valid" else None,
            revision=REVISION_01,
            within=within,
        )
    add_sets(sets[8:])


# ---------------------------------------------------------------------------
# Rows of revision 01 that follow the consumption rows: A21 (Section 5.2,
# agent.authentication of api-key) and SQ1 to SQ5 (the sequence member).
# ---------------------------------------------------------------------------


SERIES = "urn:example:series:observer-1"


def derived(
    name: str, parent: str, change: Callable[[dict[str, Any]], None]
) -> Callable[[], Built]:
    """A member built from its parent's predicate and kept as a parent itself."""

    def build() -> Built:
        pred = from_pred(parent)
        change(pred)
        return accept(name, pred)

    return build


def _sequence(seq: int, **extra: Any) -> Callable[[dict[str, Any]], None]:
    return _set("sequence", {"boundary": SERIES, "seq": seq, **extra})


def sequence_set(seqs: list[int]) -> Callable[[], Built]:
    """A set member: SQ1, then one further record of its series per seq, each
    its own record (recordId differs, so its commitment is sealed again)."""

    def build() -> Built:
        records = [from_pred("SQ1")]
        for index, seq in enumerate(seqs):
            pred = from_pred("SQ1")
            pred["recordId"] = f"{RECORD_ID}:series-{index + 2}"
            pred["sequence"]["seq"] = seq
            seal_commitment(pred)
            records.append(pred)
        return {"set": [signed(pred)["payload"] for pred in records]}

    return build


def define_audit_next() -> None:
    member(
        "A21",
        "a21-authentication-api-key",
        "A1",
        "A1 with agent.authentication of api-key, a bearer secret presented with the request "
        "that is not an OAuth access token; authentication is outside the request digest",
        mutate("A1", _set("agent.authentication", "api-key")),
        "valid",
        tier="authoritative",
        revision=REVISION_01,
    )
    member(
        "SQ1",
        "sq1-sequence-first-of-series",
        "A1",
        "A1 with sequence carrying a boundary and a seq of 1, the first record of its series",
        derived("SQ1", "A1", _sequence(1)),
        "valid",
        tier="authoritative",
        revision=REVISION_01,
    )
    member(
        "SQ2",
        "sq2-sequence-undefined-member",
        "SQ1",
        "sequence carrying a count member this document does not define",
        mutate("SQ1", _sequence(1, count=3)),
        "malformed",
        ["sequence-malformed"],
        revision=REVISION_01,
    )
    member(
        "SQ3",
        "sq3-sequence-seq-zero",
        "SQ1",
        "sequence with a seq of 0",
        mutate("SQ1", _sequence(0)),
        "malformed",
        ["sequence-malformed"],
        revision=REVISION_01,
    )
    member(
        "SQ4",
        "sq4-set-sequence-gap",
        "SQ1",
        "records of one series with seq 1 and 3 held, seq 2 not held: each record valid, "
        "the set names seq 2 as issued and not received",
        sequence_set([3]),
        "valid",
        tier="authoritative",
        revision=REVISION_01,
        joint={"verdict": "valid", "codes": [], "missing": [{"boundary": SERIES, "seq": 2}]},
    )
    member(
        "SQ5",
        "sq5-set-sequence-duplicate",
        "SQ1",
        "two records of one series with seq 1 and different envelope digests: each record "
        "valid, the set fails the check",
        sequence_set([1]),
        "valid",
        tier="authoritative",
        revision=REVISION_01,
        joint={"verdict": "malformed", "codes": ["sequence-duplicate"]},
    )
    member(
        "IS1",
        "is1-issued-one-second-before-sealed",
        "A1",
        "issuedAt one second earlier than effect.interval.sealedAt",
        mutate("A1", _set("issuedAt", "2026-09-19T11:04:05Z")),
        "malformed",
        ["issued-before-sealed"],
        revision=REVISION_03,
    )
    member(
        "IS2",
        "is2-issued-one-day-before-sealed",
        "A1",
        "issuedAt one day earlier than effect.interval.sealedAt, on a day before the "
        "interval opened",
        mutate("A1", _set("issuedAt", "2026-09-18T11:04:06Z")),
        "malformed",
        ["issued-before-sealed"],
        revision=REVISION_03,
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


def _jwk_set(public: bytes, kid: str = OBSERVER_KEYID) -> bytes:
    key = {
        "crv": "Ed25519",
        "kid": kid,
        "kty": "OKP",
        "x": base64.urlsafe_b64encode(public).rstrip(b"=").decode(),
    }
    return canonical_bytes({"keys": [key]})


def a1_envelope() -> dict[str, Any]:
    return envelope(signed(from_pred("A1"))["payload"])


# --- OpenTimestamps anchors (Section 4.7.2, rows R10 to R12 and R16) ---------
#
# An opentimestamps anchor's proof is the base64 of a DetachedTimestampFile over
# envelopeDigest: the magic, version 1, the sha256 file-hash op, the digest
# bytes, then a timestamp tree of commitment operations ending in attestations.
# A Bitcoin attestation names a block height, and the proof validates when the
# message it attests is the Merkle root of the header at that height that the
# manifest's anchorTrust.blockHeaders holds. Those are 80-byte headers of a test
# chain, pinned bytes in this corpus so nothing is fetched at verify time; the
# anchor's time is the header's time field.

OTS_MAGIC = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294")
OTS_BITCOIN = bytes.fromhex("0588960d73d71901")
OTS_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
SHA256_OP: tuple[str, bytes] = ("sha256", b"")
BLOCK_HEADERS: list[dict[str, Any]] = []
ROOT_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("00" * 31 + "55"))
OTHER_ROOT_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("00" * 31 + "66"))


def varuint(n: int) -> bytes:
    out = bytearray()
    while True:
        low, n = n & 0x7F, n >> 7
        out.append(low | 0x80 if n else low)
        if not n:
            return bytes(out)


def varbytes(data: bytes) -> bytes:
    return varuint(len(data)) + data


def ots_apply(message: bytes, ops: list[tuple[str, bytes]]) -> bytes:
    for op, arg in ops:
        if op == "sha256":
            message = hashlib.sha256(message).digest()
        elif op == "append":
            message = message + arg
        else:
            message = arg + message
    return message


def _ots_chain(ops: list[tuple[str, bytes]], tag: bytes, payload: bytes) -> bytes:
    codes = {"sha256": b"\x08", "append": b"\xf0", "prepend": b"\xf1"}
    out = b""
    for op, arg in ops:
        out += codes[op] + (varbytes(arg) if op != "sha256" else b"")
    return out + b"\x00" + tag + varbytes(payload)


def ots_proof(
    digest_bytes: bytes, branches: list[tuple[list[tuple[str, bytes]], bytes, bytes]]
) -> str:
    """A DetachedTimestampFile whose timestamp holds each branch as one chain of
    operations from the digest to its attestation."""
    body = b"".join(
        (b"\xff" if i < len(branches) - 1 else b"") + _ots_chain(*branch)
        for i, branch in enumerate(branches)
    )
    raw = OTS_MAGIC + varuint(1) + b"\x08" + digest_bytes + body
    return base64.b64encode(raw).decode()


def _unix(moment: str) -> int:
    return int(
        datetime.datetime.strptime(moment, "%Y-%m-%dT%H:%M:%SZ")
        .replace(tzinfo=datetime.UTC)
        .timestamp()
    )


def hold_block(height: int, merkle_root: bytes, timestamp: str) -> None:
    """Pin the 80 bytes of a test block header carrying ``merkle_root``."""
    header = (
        (0x20000000).to_bytes(4, "little")
        + bytes.fromhex(h(f"block/{height - 1}"))
        + merkle_root
        + _unix(timestamp).to_bytes(4, "little")
        + bytes.fromhex("ffff001d")
        + (height).to_bytes(4, "little")
    )
    BLOCK_HEADERS.append({"height": height, "header": header.hex()})


def calendar_ops(label: str) -> list[tuple[str, bytes]]:
    """A calendar's commitment: a nonce appended and hashed, then one sibling."""
    return [
        ("append", bytes.fromhex(h(f"ots/{label}/nonce"))[:16]),
        SHA256_OP,
        ("prepend", bytes.fromhex(h(f"ots/{label}/calendar-sibling"))),
        SHA256_OP,
    ]


def block_ops(label: str, levels: int = 2) -> list[tuple[str, bytes]]:
    """A transaction carrying the message, then its path up the block's Merkle tree."""
    ops: list[tuple[str, bytes]] = [
        ("prepend", bytes.fromhex(h(f"ots/{label}/tx-prefix"))[:24]),
        ("append", bytes.fromhex(h(f"ots/{label}/tx-suffix"))[:12]),
        SHA256_OP,
        SHA256_OP,
    ]
    for level in range(levels):
        side = "append" if level % 2 == 0 else "prepend"
        ops += [(side, bytes.fromhex(h(f"ots/{label}/block-level-{level}"))), SHA256_OP, SHA256_OP]
    return ops


def ots_anchor(
    label: str,
    logged: bytes,
    height: int,
    timestamp: str,
    *,
    prefix: list[tuple[str, bytes]] | None = None,
) -> dict[str, Any]:
    """A complete opentimestamps anchor of origin retainer, and its held block."""
    ops = (prefix if prefix is not None else calendar_ops(label)) + block_ops(label)
    hold_block(height, ots_apply(logged, ops), timestamp)
    return {
        "kind": "opentimestamps",
        "origin": "retainer",
        "proof": ots_proof(logged, [(ops, OTS_BITCOIN, varuint(height))]),
    }


def ots_pending(label: str, logged: bytes) -> dict[str, Any]:
    """A pending proof: the calendar's commitment and its promise, no block."""
    uri = varbytes(b"https://calendar.example/" + label.encode())
    return {
        "kind": "opentimestamps",
        "origin": "retainer",
        "proof": ots_proof(logged, [(calendar_ops(label), OTS_PENDING, uri)]),
    }


ROOT_JWKS = _jwk_set(raw_public(ROOT_KEY), hashlib.sha256(raw_public(ROOT_KEY)).hexdigest()[:32])
OTHER_ROOT_JWKS = _jwk_set(
    raw_public(OTHER_ROOT_KEY), hashlib.sha256(raw_public(OTHER_ROOT_KEY)).hexdigest()[:32]
)


def rooted_envelope() -> dict[str, Any]:
    """A1 for a decision that rested on a delegation chain: delegation.rootDigest
    is the digest of the root key set the chain verifier held."""
    pred = from_pred("A1")
    pred["delegation"]["rootDigest"] = hashlib.sha256(ROOT_JWKS).hexdigest()
    return envelope(signed(pred)["payload"])


def root_element(material: bytes) -> dict[str, Any]:
    return {
        "for": "delegation-root",
        "mediaType": "application/jwk-set+json",
        "value": base64.b64encode(material).decode(),
    }


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
    name: str,
    change: Callable[[dict[str, Any], bytes], None],
    parent: str | None = None,
    make_envelope: Callable[[], dict[str, Any]] = a1_envelope,
) -> Callable[[], Built]:
    """Build R<n>: an envelope, A1's unless ``make_envelope`` names another,
    beside a retention entry. A root member starts from an empty entry; a member
    with a parent starts from that parent's."""

    def build() -> Built:
        env = make_envelope()
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
    delegation_root: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """expected.dating. Every member reports the delegation root, and a record
    with no delegation.rootDigest reports it not established."""
    out: dict[str, Any] = {"entry": entry_, "codes": [code] if code else []}
    if dated_at is not None:
        out["datedAt"] = dated_at
    if receipt is not None:
        out["receipt"] = receipt
    out["delegationRoot"] = delegation_root or {"result": "not-established"}
    return out


def _r10(entry_: dict[str, Any], logged: bytes) -> None:
    entry_["anchors"][1] = ots_anchor("r10", logged, 880011, "2026-09-19T10:54:30Z")


def _r11(entry_: dict[str, Any], logged: bytes) -> None:
    entry_["anchors"][1] = ots_anchor("r11", logged, 880000, "2026-09-19T09:04:29Z")


def _r12(entry_: dict[str, Any], logged: bytes) -> None:
    entry_["anchorWithin"] = 3600
    entry_["anchors"] = [
        ots_pending("r12", logged),
        ots_anchor("r12", logged, 880016, "2026-09-19T11:40:00Z"),
    ]


def _r16(entry_: dict[str, Any], logged: bytes) -> None:
    """The retaining party's own Merkle tree over four envelope digests, its root
    carried in a Bitcoin transaction, the transaction in a block."""
    leaves = [logged] + [bytes.fromhex(h(f"r16/batch-{i}")) for i in range(1, 4)]
    pair = hashlib.sha256(leaves[2] + leaves[3]).digest()
    tree = [("append", leaves[1]), SHA256_OP, ("append", pair), SHA256_OP]
    entry_["anchorWithin"] = 3600
    entry_["anchors"] = [ots_anchor("r16", logged, 880015, "2026-09-19T11:30:00Z", prefix=tree)]


def _r13(entry_: dict[str, Any], logged: bytes) -> None:
    entry_["anchors"] = [log_anchor("r13", "retainer", "2026-09-19T11:05:00Z", 3, 1, logged)]
    entry_["validationData"].append(root_element(ROOT_JWKS))


def _r14(entry_: dict[str, Any], _logged: bytes) -> None:
    entry_["validationData"] = [
        v for v in entry_["validationData"] if v["for"] != "delegation-root"
    ]


def _r15(entry_: dict[str, Any], _logged: bytes) -> None:
    for element in entry_["validationData"]:
        if element["for"] == "delegation-root":
            element["value"] = root_element(OTHER_ROOT_JWKS)["value"]


def _statement_edit(parent: str, edit: Callable[[dict[str, Any]], None]) -> Callable[[], Built]:
    """A member whose Statement, not its predicate, differs from the parent's."""

    def build() -> Built:
        stmt = statement(from_pred(parent))
        edit(stmt)
        return {"payload": canonical_bytes(stmt)}

    return build


def _raw_payload(parent: str, tail: bytes) -> Callable[[], Built]:
    """The parent's Statement bytes with ``tail`` appended or substituted wholesale."""

    def build() -> Built:
        payload = canonical_bytes(statement(from_pred(parent)))
        return {"payload": payload[:-1] + tail}

    return build


def _unreadable_envelope() -> Built:
    env = envelope(canonical_bytes(statement(from_pred("A1"))))
    env["payloadType"] = "application/json"
    return {"bundle": env}


def _held_extra(pred: dict[str, Any]) -> None:
    _consumption(pred)["held"][0]["note"] = "extra"


def _blank_key(pred: dict[str, Any]) -> None:
    pred["decision"]["operationKey"] = ""


def _entry_edit(
    change: Callable[[dict[str, Any]], None],
) -> Callable[[dict[str, Any], bytes], None]:
    def apply(entry_: dict[str, Any], _logged: bytes) -> None:
        change(entry_)

    return apply


def _extra_root(entry_: dict[str, Any]) -> None:
    entry_["validationData"].append(root_element(ROOT_JWKS))


def _garbled_root(entry_: dict[str, Any]) -> None:
    for element in entry_["validationData"]:
        if element["for"] == "delegation-root":
            element["value"] = "***not base64***"


def _unparseable_retained() -> Built:
    env = envelope(b"{not json")
    return {"retained": {"envelope": env, "retention": retention_entry(env, received=False)}}


def _retained_without_entry() -> Built:
    return {"bundle": {"envelope": a1_envelope()}}


def _set_wrong_key() -> Built:
    records = [envelope(p) for p in sequence_set([3])()["set"]]
    return {"bundle": {"members": records}}


def _set_all_malformed() -> Built:
    payloads = []
    for stamp in ("2026-09-19T11:04:05Z", "2026-09-18T11:04:06Z"):
        pred = from_pred("A1")
        pred["issuedAt"] = stamp
        payloads.append(signed(pred)["payload"])
    return {"set": payloads}


# The section of draft-gilda-audit-agent-audit-record-03 whose text makes each
# member malformed. X1, X17 and X18 carry none: the draft states no rule for a
# fractional number, and does not define the bundle a set member is.
REJECT_SECTIONS: dict[str, str] = {
    "X2": "4.6", "X3": "4.3", "X4": "4", "X5": "4", "X6": "5.9", "X7": "5.9",
    "X8": "4.2", "X9": "4.4", "X10": "4.6", "X11": "4.7", "X12": "4.7",
    "X13": "4.7", "X14": "4.7", "X15": "4.6", "X16": "4.7",
}


def define_reject_paths() -> None:
    """Members X1 to X18: one reject member for each path of the reference reader
    that no earlier member reached and that fires on a one-field change of an
    existing member. Each is its parent with that one field changed."""
    rows: list[tuple[str, str, str, str, Callable[[], Built], list[str]]] = [
        (
            "X1", "x1-float-in-statement", "A1", "a number with a fraction in the Statement",
            _raw_payload("A1", b',"ratio":0.5}'), ["value-not-representable"],
        ),
        (
            "X2", "x2-payload-not-json", "A1", "a payload that is not JSON",
            lambda: {"payload": b"{not json"}, ["not-parseable"],
        ),
        (
            "X3", "x3-issued-at-no-offset", "A1", "issuedAt carrying no UTC offset",
            mutate("A1", _set("issuedAt", "2026-09-19T11:04:06")), ["timestamp-malformed"],
        ),
        (
            "X4", "x4-statement-type-unexpected", "A1", "_type naming another Statement type",
            _statement_edit("A1", lambda st: st.__setitem__("_type", "https://example.com/Stmt")),
            ["statement-type-unexpected"],
        ),
        (
            "X5", "x5-predicate-type-mismatch", "A1", "predicateType naming another predicate",
            _statement_edit(
                "A1", lambda st: st.__setitem__("predicateType", "https://example.com/other/v1")
            ),
            ["predicate-type-mismatch"],
        ),
        (
            "X6", "x6-held-entry-extra-member", "CS4",
            "a held entry with a member beyond the three",
            mutate("CS4", _held_extra), ["consumption-malformed"],
        ),
        (
            "X7", "x7-operation-key-empty", "CS4", "decision.operationKey the empty string",
            mutate("CS4", _blank_key), ["operation-key-invalid"],
        ),
        (
            "X8", "x8-subject-digest-not-request", "A1", "the first subject's digest another value",
            _statement_edit(
                "A1", lambda st: st["subject"][0]["digest"].__setitem__("sha256", AFTER)
            ),
            ["subject-request-mismatch"],
        ),
        (
            "X9", "x9-envelope-payload-type", "A1", "payloadType another media type",
            _unreadable_envelope, ["envelope-unreadable"],
        ),
        (
            "X10", "x10-predicate-not-an-object", "A1", "predicate a string, correctly signed",
            _statement_edit("A1", lambda st: st.__setitem__("predicate", "none")),
            ["statement-shape"],
        ),
    ]
    for draft_id, slug, parent, row, build, codes in rows:
        member(
            draft_id, slug, parent, row, build, "malformed", codes,
            section=REJECT_SECTIONS.get(draft_id),
        )

    dated: list[tuple[str, str, str, str, Callable[[], Built], str]] = [
        (
            "X11", "x11-received-not-boolean", "R1", "received a string, not a boolean",
            retained("X11", _entry_edit(lambda e: e.__setitem__("received", "no")), "R1"),
            "entry-shape-malformed",
        ),
        (
            "X12", "x12-entry-names-another-envelope", "R1", "envelopeDigest another envelope's",
            retained(
                "X12",
                _entry_edit(lambda e: e.__setitem__("envelopeDigest", h("other"))),
                "R1",
            ),
            "entry-envelope-digest-mismatch",
        ),
        (
            "X13", "x13-root-element-without-root-digest", "R1",
            "a delegation-root element beside a record carrying no delegation.rootDigest",
            retained("X13", _entry_edit(_extra_root), "R1"),
            "entry-delegation-root-unexpected",
        ),
        (
            "X14", "x14-root-element-not-base64", "R13",
            "the delegation-root element's value not base64",
            retained("X14", _entry_edit(_garbled_root), "R13", make_envelope=rooted_envelope),
            "entry-delegation-root-unreadable",
        ),
    ]
    for draft_id, slug, parent, row, build, code in dated:
        member(
            draft_id, slug, parent, row, build, "valid", tier="authoritative",
            section=REJECT_SECTIONS.get(draft_id),
            dating=dating(
                dated_at=None if draft_id == "X11" else "2026-09-19T11:05:00Z",
                entry_="malformed",
                code=code,
            ),
        )
    member(
        "X15", "x15-retained-record-unparseable", "R1",
        "the retained record's payload not JSON: the record malformed and the dating unreadable",
        _unparseable_retained, "malformed", ["not-parseable"],
        section=REJECT_SECTIONS.get("X15"),
        dating=dating(dated_at=None, entry_="malformed", code="entry-record-unreadable"),
    )
    member(
        "X16", "x16-retained-without-retention", "R1",
        "a retained member with no retention entry",
        _retained_without_entry, "malformed", ["retained-unreadable"],
        section=REJECT_SECTIONS.get("X16"),
        dating=dating(dated_at=None, entry_="malformed", code="retained-unreadable"),
    )
    member(
        "X17", "x17-set-without-records", "SQ4",
        "a set member whose records member is named otherwise",
        _set_wrong_key, "malformed", [],
        joint={"verdict": "malformed", "codes": ["set-unreadable"]},
    )
    member(
        "X18", "x18-set-of-malformed-records", "A1",
        "a set whose two records are each malformed under IS1 and IS2",
        _set_all_malformed, "malformed", ["issued-before-sealed"],
        joint={"verdict": "malformed", "codes": ["set-record-malformed"]},
    )


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
    established = {"result": "established", "algorithm": "Ed25519"}
    later: list[tuple[str, str, str | None, str, Callable[[], Built], dict[str, Any]]] = [
        (
            "R10",
            "r10-opentimestamps-retainer-anchor",
            "R2",
            "the retaining party's anchor is opentimestamps, its block header time 600 seconds "
            "earlier than receivedAt: inside the 7200 seconds an opentimestamps time allows",
            retained("R10", _r10, "R2"),
            dating(dated_at="2026-09-19T10:54:30Z", receipt="asserted-consistent"),
        ),
        (
            "R11",
            "r11-opentimestamps-header-too-early",
            "R10",
            "the block header time earlier than receivedAt by 7201 seconds, more than the "
            "7200 seconds an opentimestamps time allows",
            retained("R11", _r11, "R10"),
            dating(
                dated_at="2026-09-19T09:04:29Z",
                entry_="malformed",
                code="entry-received-after-anchor",
            ),
        ),
        (
            "R12",
            "r12-pending-then-upgraded-proof",
            "R1",
            "anchors holding a pending OpenTimestamps proof followed by its upgraded, complete "
            "proof: dated at the upgraded proof's block time, the pending element dating nothing",
            retained("R12", _r12, "R1"),
            dating(dated_at="2026-09-19T11:40:00Z"),
        ),
        (
            "R13",
            "r13-delegation-root-established",
            None,
            "R1 for a record carrying delegation.rootDigest, with a delegation-root element "
            "whose digest equals it: the root established, its algorithm read off the element",
            retained("R13", _r13, make_envelope=rooted_envelope),
            dating(dated_at="2026-09-19T11:05:00Z", delegation_root=established),
        ),
        (
            "R14",
            "r14-delegation-root-element-omitted",
            "R13",
            "the delegation-root element omitted: the root not established, never a pass",
            retained("R14", _r14, "R13", make_envelope=rooted_envelope),
            dating(dated_at="2026-09-19T11:05:00Z"),
        ),
        (
            "R15",
            "r15-delegation-root-digest-unequal",
            "R13",
            "the delegation-root element carries another key set, whose digest is unequal to "
            "delegation.rootDigest",
            retained("R15", _r15, "R13", make_envelope=rooted_envelope),
            dating(
                dated_at="2026-09-19T11:05:00Z",
                entry_="malformed",
                code="entry-delegation-root-mismatch",
            ),
        ),
        (
            "R16",
            "r16-opentimestamps-through-own-tree",
            "R1",
            "the only anchor an opentimestamps proof whose path runs from envelopeDigest through "
            "a Merkle tree the retaining party built and a Bitcoin transaction carrying its root "
            "to the block header",
            retained("R16", _r16, "R1"),
            dating(dated_at="2026-09-19T11:30:00Z"),
        ),
    ]
    for draft_id, slug, parent, row, build, expected_dating in later:
        member(
            draft_id,
            slug,
            parent,
            row,
            build,
            "valid",
            tier="authoritative",
            dating=expected_dating,
            revision=REVISION_01,
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
    "TI6 V4 V5 FR14 FR15 "
    "CS1 CS2 CS3 CS4 CS5 CS6 CS7 CS8 CS9 CS10 CS11 CS12 CS13 CS14 CS15 CS16 CS17 "
    "CS18 CS19 CS20 CS21 CS22 CS23 CS24 CS25 "
    "CS26 CS27 CS28 CS29 CS30 CS31 CS32 CS33 CS34 CS35 CS36 CS37 CS38 CS39 CS40 "
    "A21 SQ1 SQ2 SQ3 SQ4 SQ5 "
    "R10 R11 R12 R13 R14 R15 R16 "
    "IS1 IS2 "
    "X1 X2 X3 X4 X5 X6 X7 X8 X9 X10 X11 X12 X13 X14 X15 X16 X17 X18"
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
    if entry["within"] is not None:
        expected["withinLimit"] = entry["within"]
    if entry["joint"] is not None:
        expected["set"] = entry["joint"]
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


def member_folder(entry: Member) -> str:
    if entry["dating"] is not None:
        return "retained"
    return "sets" if entry["joint"] is not None else "statements"


def member_bundle(made: Built) -> dict[str, Any]:
    """The JSON a member's file carries: a set's records, a retained record's
    envelope beside its entry, or the one envelope."""
    if "bundle" in made:
        bundle: dict[str, Any] = made["bundle"]
        return bundle
    if "set" in made:
        return {"records": [envelope(payload) for payload in made["set"]]}
    if "retained" in made:
        retained_bundle: dict[str, Any] = made["retained"]
        return retained_bundle
    return envelope(made["payload"])


def emit() -> None:
    define()
    statements_dir = os.path.join(HERE, "statements")
    os.makedirs(statements_dir, exist_ok=True)
    built: list[tuple[Member, bytes, str]] = []
    ids: dict[str, str] = {}
    for entry in MEMBERS:
        made = entry["build"]()
        bundle = member_bundle(made)
        raw = json.dumps(bundle, indent=2, sort_keys=True).encode() + b"\n"
        ident = vector_id(raw)
        if ident in ids.values():
            raise SystemExit(f"identifier collision on {entry['draftId']}")
        ids[entry["draftId"]] = ident
        built.append((entry, raw, ident))

    retained_dir = os.path.join(HERE, "retained")
    os.makedirs(retained_dir, exist_ok=True)
    os.makedirs(os.path.join(HERE, "sets"), exist_ok=True)
    vectors: list[dict[str, Any]] = []
    keep: set[str] = set()
    for entry, raw, ident in built:
        folder = member_folder(entry)
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

    for folder in ("statements", "retained", "sets"):
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
            "blockHeaders": BLOCK_HEADERS,
            "blockHeaderNote": (
                "The 80-byte headers of a test chain, pinned here so an opentimestamps anchor "
                "validates with nothing fetched: a verifier holds them independently, as "
                "blocks of the chain with the most work. An opentimestamps anchor validates "
                "when its proof recomputes from envelopeDigest to the Merkle root field of the "
                "header at the height its Bitcoin attestation names; its time is the "
                "header's time field, little-endian Unix seconds."
            ),
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
        if "withinLimit" in v["expected"]:
            verdict += ", withinLimit " + str(v["expected"]["withinLimit"]).lower()
        if "set" in v["expected"]:
            joint = v["expected"]["set"]
            if joint["codes"]:
                verdict += f", the set {joint['verdict']} ({joint['codes'][0]})"
            else:
                verdict += f", the set {joint['verdict']}"
            for point in joint.get("missing", []):
                verdict += f", seq {point['seq']} issued and not received"
        source = f"Section {v['draftSection']}" if "draftSection" in v else "Appendix B"
        lines.append(
            f"| `{v['draftId']}` | {source} | {parent} | {verdict} | "
            f"[`{v['id']}`]({v['file']}) | {v['row']} |"
        )
    with open(os.path.join(HERE, "INDEX.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    emit()
