"""The agent audit record, and the corpus that holds its conformance set.

The record format is defined by the Internet-Draft
``draft-gilda-audit-agent-audit-record-00``, which replaces
``draft-gilda-wimse-agent-audit-record-02``: one in-toto Statement in a DSSE
envelope, seventeen required predicate members and one optional one carrying the
seven minimum audit fields of Section 11 of ``draft-ietf-wimse-aims``, and the
recomputes that make those fields checkable. Appendix B of the draft lists the
conformance corpus, and ``vectors-agent-audit-record/`` publishes it member for
member: each manifest entry carries the Appendix B identifier in ``draftId``.
The members after the last row test sentences of Section 5.4 that Appendix B
has no row for, and name the section in ``draftSection``. Members carrying
``draftRevision`` are rows of revision 01, whose rules this reader applies where
they differ: an entry for an input with several values takes its pair from one
value (``aggregate_values``), and the coverage clause of Section 5.7 is
``scopeComplete`` of true, a gap inside ``pathScope`` beside it being malformed
at any tier. Members CS1 to CS17 are rows of the same revision: a
``consumption-state`` entry may carry the ``consumption`` member, and
``decision.operationKey`` is the agent's identifier for one intended operation
and the identity of a retry (``consumption_findings``, ``within_limit``,
``verify_set``). A set member (CS7, CS8, CS17) is a file of several records
judged one by one and then as a set under one ``limitDigest``.

``evaluation.inputs`` is required under both statuses, each entry's age runs
from its ``lastResult`` to ``decision.reportedAt``, and the unavailable inputs
are derived from the entries, so a record shaped for revision 02 is malformed.
Rows R1 to R9 are retained records: the envelope beside the retention entry of
Section 4.7, judged twice, once for the record's verdict and once by the dating
check of Section 4.7.1, whose result is reported beside the verdict.

Two things live here, both stdlib-only for the reason the whole rail is: a
relying party runs it with nothing installed.

1. A VERIFIER: ``verify(raw, policy)`` judges one DSSE envelope and returns the
   verdict, the single first refusal code, and the tier it RECOMPUTED. Every rule
   is one function, registered in ``RULES`` in the order it runs. The order
   follows the draft's "Verifying a record" section: the signature, then the JSON
   profile, then membership, then the recomputes. Rule ORDER is load-bearing,
   because the manifest pins one code per reject member and that code is the
   FIRST refusal.
2. A JUDGE for the corpus: ``judge(directory)`` reads the corpus's MANIFEST.json
   and says of every member whether this rail reaches the verdict and the code
   the manifest declares, plus the claims that belong to no single member.

The draft states verdicts, not codes. A conforming verifier is scored on the
verdict; the codes are this reader's names for its first refusal, published so
two implementations can compare where they stopped.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import datetime
import functools
import hashlib
import importlib
import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SUITE = "agent-audit-record-conformance"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
IJSON_LIMIT = 2**53
MAX_DEPTH = 128
GLOB_METACHARACTERS = frozenset("*?[]{}")
UNATTRIBUTED = "unattributed"

#: The empty tree object name under each algorithm: the digest of ``tree 0\0``.
#: sha1 is computed through ``usedforsecurity=False`` so this module imports where
#: a FIPS build refuses sha1 for security use; it is a name here, not a MAC.
EMPTY_TREE = {
    "sha1": hashlib.sha1(b"tree 0\x00", usedforsecurity=False).hexdigest(),
    "sha256": hashlib.sha256(b"tree 0\x00").hexdigest(),
}

#: The closed vocabularies of Section 5, keyed by the dotted member path a value
#: sits at. ``[]`` marks every element of an array.
VOCABULARIES: dict[str, frozenset[str]] = {
    "tier": frozenset({"voluntary", "authoritative"}),
    "hashAlgorithm": frozenset({"sha256"}),
    "agent.authentication": frozenset(
        {"wimse-wpt", "http-message-signature", "mtls", "oauth-access-token", "api-key", "none"}
    ),
    "delegation.subjectKind": frozenset({"user", "system", "none"}),
    "resource.kind": frozenset({"path", "uri", "tool"}),
    "resource.binding": frozenset({"digest-bound", "not-bindable"}),
    "decision.reported": frozenset({"permit", "deny", "permit-with-conditions"}),
    "effect.observed": frozenset({"occurred", "none", "unknown"}),
    "effect.interval.baseResolution": frozenset({"supplied", "empty-tree"}),
    "agreement": frozenset({"agree", "disagree", "not-exercised", "indeterminate", "one-sided"}),
    "correlation.scope": frozenset({"producer", "cross-party"}),
    "correlation.timeBasis": frozenset({"beacon-anchored", "asserted"}),
    "correlation.externalAnchor.kind": frozenset({"rfc3161", "transparency-log", "opentimestamps"}),
    "posture.reported": frozenset({"no_network", "allowlist", "sinkhole", "unsafe_bypass_egress"}),
    "posture.observed": frozenset({"no_network", "allowlist", "sinkhole", "unsafe_bypass_egress"}),
    "posture.agreement": frozenset({"agree", "disagree"}),
    "remediation[].cause": frozenset(
        {
            "session-revoked",
            "risk-elevated",
            "subject-disabled",
            "token-replay-suspected",
            "policy-changed",
            "operator-action",
        }
    ),
    "remediation[].enforcement": frozenset(
        {
            "access-attenuated",
            "session-terminated",
            "tokens-discarded",
            "privileges-reduced",
            "reevaluated",
            "not-enforced",
        }
    ),
    "remediation[].postEnforcementEffect": frozenset({"occurred", "none", "unknown"}),
    "observation.vantage": frozenset({"below-observed", "peer", "self"}),
    "evaluation.status": frozenset({"evaluated", "not-evaluated"}),
    "oversight.act": frozenset({"observation", "check", "decision", "release"}),
}

#: The inputs an evaluation entry names (Table 3 of the successor draft): the
#: standing source, the key source, the consumption state and the policy source.
EVALUATION_INPUTS = frozenset(
    {"standing-source", "key-source", "consumption-state", "policy-source"}
)
#: What a decision that could not be evaluated names as missing, drawn from the
#: same table. A separate name so a sweep can narrow one without the other.
UNAVAILABLE_INPUTS = EVALUATION_INPUTS
#: The three members an evaluation entry carries, each required, and no other.
ENTRY_MEMBERS = frozenset({"input", "lastResult", "maxAge"})
#: The one member an entry may carry beside them, and only on a consumption-state
#: entry (Section 5.4 of revision 01): the cumulative-limit state the decision
#: point read.
ENTRY_OPTIONAL = frozenset({"consumption"})
CONSUMPTION_INPUT = "consumption-state"
#: The members of ``consumption``, each required, and no other.
CONSUMPTION_MEMBERS = (
    "limitDigest",
    "unit",
    "limit",
    "consumed",
    "reserved",
    "requested",
    "held",
    "stateRevision",
)
#: The non-negative integers among them (smallest subunit of ``unit``).
CONSUMPTION_COUNTS = ("limit", "consumed", "reserved", "requested", "stateRevision")
#: The members of one ``held`` entry, an earlier permit that has not settled.
HELD_MEMBERS = ("operationKey", "requestDigest", "amount")
PERMITS = frozenset({"permit", "permit-with-conditions"})
#: The sentences of the consumption rule, by name, so a sweep can weaken one at a
#: time (check_vectors.py): where the member sits, that ``reserved`` is the held
#: sum, that held keys are distinct, that the call carries its operation key,
#: that counts are non-negative integers, that stateRevision is required, and
#: that one key is one request.
CONSUMPTION_CHECKS = frozenset(
    {
        "misplaced",
        "reserved",
        "distinct-keys",
        "operation-key",
        "counts",
        "state-revision",
        "key-reuse",
    }
)
#: The lastResult of an input the decision point never held a value of.
NEVER_HELD = "none"
#: The tolerance for every comparison between times two parties wrote.
SKEW_TOLERANCE = datetime.timedelta(seconds=300)
#: The only members an evaluation object may carry (EV12).
EVALUATION_MEMBERS = frozenset({"status", "inputs", "unavailableInput"})
#: The only members an oversight object may carry.
OVERSIGHT_MEMBERS = frozenset({"act", "recordDigest"})

#: The seventeen required predicate members, and the members each object member
#: requires.
#: ``resource.argumentsDigest``, ``correlation.externalAnchor`` and
#: ``observation.priorCommitment`` are conditional and checked where their rule
#: is stated, never here.
TOP_MEMBERS = (
    "recordId",
    "tier",
    "hashAlgorithm",
    "agent",
    "delegation",
    "resource",
    "decision",
    "effect",
    "agreement",
    "correlation",
    "posture",
    "remediation",
    "observation",
    "fieldEvidence",
    "doesNotAssert",
    "issuedAt",
    "evaluation",
)
NESTED_MEMBERS: dict[str, tuple[str, ...]] = {
    "agent": ("id", "credentialDigest", "authentication", "signers"),
    "delegation": ("subject", "subjectKind", "authorityDigest"),
    "resource": ("kind", "id", "binding"),
    "decision": (
        "action",
        "requestDigest",
        "reported",
        "decisionPointId",
        "policyDigest",
        "reportedAt",
    ),
    "effect": ("observed", "interval", "pathScope", "writes"),
    "effect.interval": ("beforeRoot", "afterRoot", "baseResolution", "openedAt", "sealedAt"),
    "correlation": ("id", "scope", "timeBasis"),
    "posture": (
        "reported",
        "reportedDigest",
        "observed",
        "observedDigest",
        "assessedAt",
        "agreement",
    ),
    "observation": ("vantage", "coverage"),
    "observation.coverage": ("scopeComplete", "gaps"),
    "evaluation": ("status", "inputs"),
}
WRITE_MEMBERS = ("path", "preStateDigest", "postStateDigest", "requestDigest", "inScope")
REMEDIATION_MEMBERS = (
    "cause",
    "signalReceivedAt",
    "enforcedAt",
    "enforcement",
    "postEnforcementEffect",
    "postEnforcementRoot",
)
COMMITMENT_MEMBERS = ("committedAt", "witnessNonce", "commitmentDigest", "keyid", "sig")
FIELD_EVIDENCE_KEYS = frozenset(
    {"agent", "correlation", "decision", "delegation", "posture", "remediation", "resource"}
)
FIELD_EVIDENCE_VALUES = frozenset({"substrate-covered", "producer-asserted"})

#: The rail's module names, resolved at call time: the rail imports this module
#: to dispatch to it, so importing it back at module load would depend on which
#: side was imported first.
_RAIL_NAMES = ("agent_evidence_vectors.run_vectors", "run_vectors", "__main__")


def _rail() -> Any:
    for name in _RAIL_NAMES:
        module = sys.modules.get(name)
        if module is not None and hasattr(module, "ed25519_verify"):
            return module
    for name in _RAIL_NAMES[:2]:
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        if hasattr(module, "ed25519_verify"):
            return module
    raise RuntimeError("the reference rail is importable as neither of its names")


def _ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    return bool(_rail().ed25519_verify(public_key, message, signature))


def pae(payload_type: str, payload: bytes) -> bytes:
    """The DSSE pre-authentication encoding."""
    kind = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(kind), kind, len(payload), payload)


class Malformed(Exception):
    """A record the draft calls malformed. Every refusal it states is this one."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Policy:
    """What a consumer brings: the predicate type it expects and the observer's key.

    Neither is read from the record, because a record carrying its own expected
    type or its own key would be grading its own homework.
    """

    predicate_type: str
    observer_public_key: str


@dataclass
class Report:
    """One verification: the verdict, the first refusal, the RECOMPUTED tier."""

    verdict: str
    codes: list[str]
    derived_tier: str = ""


# --------------------------------------------------------------------------
# RFC 8785 and the JSON profile.
# --------------------------------------------------------------------------


def _encode(node: Any) -> str:
    """RFC 8785 for the value space this format uses: no floats are admitted."""
    if node is None:
        return "null"
    if node is True:
        return "true"
    if node is False:
        return "false"
    if isinstance(node, str):
        return json.dumps(node, ensure_ascii=False, separators=(",", ":"))
    if isinstance(node, int):
        if abs(node) >= IJSON_LIMIT:
            raise Malformed("unsafe-integer")
        return str(node)
    if isinstance(node, list):
        return "[" + ",".join(_encode(item) for item in node) + "]"
    if isinstance(node, dict):
        members = sorted(node.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(f"{_encode(k)}:{_encode(v)}" for k, v in members) + "}"
    raise Malformed("value-not-representable")


def canonical_bytes(node: Any) -> bytes:
    return _encode(node).encode("utf-8")


def jcs_digest(node: Any) -> str:
    return hashlib.sha256(canonical_bytes(node)).hexdigest()


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise Malformed("duplicate-member")
        out[key] = value
    return out


def _safe_int(text: str) -> int:
    value = int(text)
    if abs(value) >= IJSON_LIMIT:
        raise Malformed("unsafe-integer")
    return value


def _refuse_float(text: str) -> float:
    raise Malformed("value-not-representable")


def _depth(node: Any) -> int:
    """Container nesting, counting the top-level value as one."""
    if isinstance(node, dict):
        return 1 + max((_depth(v) for v in node.values()), default=0)
    if isinstance(node, list):
        return 1 + max((_depth(v) for v in node), default=0)
    return 0


def parse_statement(payload: bytes) -> Any:
    """Parse under the JSON profile: no repeated name, no unsafe integer, no float,
    no nesting past 128 levels."""
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Malformed("not-parseable") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_no_duplicates,
            parse_int=_safe_int,
            parse_float=_refuse_float,
        )
    except Malformed:
        raise
    except (ValueError, RecursionError) as exc:
        raise Malformed("not-parseable") from exc
    if _depth(value) > MAX_DEPTH:
        raise Malformed("nesting-too-deep")
    return value


# --------------------------------------------------------------------------
# Shared readings.
# --------------------------------------------------------------------------


def _at(pred: dict[str, Any], dotted: str) -> Any:
    node: Any = pred
    for part in dotted.split("."):
        node = node[part]
    return node


def _instant(value: Any) -> datetime.datetime:
    if not isinstance(value, str):
        raise Malformed("timestamp-malformed")
    try:
        parsed = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Malformed("timestamp-malformed") from exc
    if parsed.tzinfo is None:
        raise Malformed("timestamp-malformed")
    return parsed


def _under(path: str, scope: str) -> bool:
    """Segment-boundary containment: ``/`` holds everything, ``/a/`` holds ``/a/x``."""
    if scope == "/":
        return path.startswith("/")
    base = scope if scope.endswith("/") else scope + "/"
    return path == scope.rstrip("/") or path.startswith(base)


def request_digest(pred: dict[str, Any]) -> str:
    """The RFC 8785 digest over action, argumentsDigest, resourceId, resourceKind.

    Under ``not-bindable`` the hashed object holds the other three members and no
    ``argumentsDigest`` member at all.
    """
    resource = pred["resource"]
    body: dict[str, Any] = {
        "action": pred["decision"]["action"],
        "resourceId": resource["id"],
        "resourceKind": resource["kind"],
    }
    if resource["binding"] == "digest-bound":
        body["argumentsDigest"] = resource["argumentsDigest"]
    return jcs_digest(body)


def commitment_digest(pred: dict[str, Any], commitment: dict[str, Any]) -> str:
    return jcs_digest(
        {
            "authorityDigest": pred["delegation"]["authorityDigest"],
            "beforeRoot": pred["effect"]["interval"]["beforeRoot"],
            "recordId": pred["recordId"],
            "witnessNonce": commitment["witnessNonce"],
        }
    )


def derive_observed(pred: dict[str, Any]) -> str:
    """``occurred`` for a write attributed to this request; ``none`` for no such
    write and no unattributed write inside pathScope; ``unknown`` otherwise."""
    own = pred["decision"]["requestDigest"]
    writes = pred["effect"]["writes"]
    if any(w["requestDigest"] == own for w in writes):
        return "occurred"
    scope = pred["effect"]["pathScope"]
    if any(
        w["requestDigest"] == UNATTRIBUTED and any(_under(w["path"], s) for s in scope)
        for w in writes
    ):
        return "unknown"
    return "none"


def derive_agreement(reported: str, observed: str) -> str:
    if observed == "unknown":
        return "indeterminate"
    if reported == "deny":
        return "agree" if observed == "none" else "disagree"
    return "agree" if observed == "occurred" else "not-exercised"


def _commitment(pred: dict[str, Any]) -> dict[str, Any] | None:
    commitment = pred["observation"].get("priorCommitment")
    return commitment if isinstance(commitment, dict) else None


def _commitment_complete(pred: dict[str, Any]) -> bool:
    commitment = _commitment(pred)
    return commitment is not None and all(m in commitment for m in COMMITMENT_MEMBERS)


def gaps_inside_scope(pred: dict[str, Any]) -> bool:
    """A gap is inside pathScope when it lies under a member of it, as inScope is
    derived for a write (Section 5.7)."""
    scope = pred["effect"]["pathScope"]
    gaps = pred["observation"]["coverage"]["gaps"]
    return any(any(_under(g, s) for s in scope) for g in gaps)


def coverage_clause_fails(pred: dict[str, Any]) -> bool:
    """The coverage clause of the tier recompute under revision 01: it holds
    exactly when scopeComplete is true (TI4, TI6). Revision 00's clause, true
    when every gap lay outside pathScope, passed a record declaring incomplete
    coverage while naming no gap inside it (TI6)."""
    return pred["observation"]["coverage"]["scopeComplete"] is not True


def tier_failures(pred: dict[str, Any]) -> list[str]:
    """The tier clauses a record fails, in the draft's order."""
    failed: list[str] = []
    if pred["observation"]["vantage"] != "below-observed":
        failed.append("tier-overclaim-vantage")
    if not _commitment_complete(pred):
        failed.append("tier-overclaim-commitment")
    scope = pred["effect"]["pathScope"]
    if not scope:
        failed.append("tier-overclaim-scope")
    if coverage_clause_fails(pred):
        failed.append("tier-overclaim-coverage")
    if pred["resource"]["binding"] != "digest-bound":
        failed.append("tier-overclaim-binding")
    return failed


# --------------------------------------------------------------------------
# The rules, in the order they run.
# --------------------------------------------------------------------------


@dataclass
class _State:
    statement: dict[str, Any]
    predicate: dict[str, Any]
    policy: Policy
    derived_tier: str = ""


def _rule_statement(state: _State) -> None:
    st = state.statement
    if st.get("_type") != STATEMENT_TYPE:
        raise Malformed("statement-type-unexpected")
    if st.get("predicateType") != state.policy.predicate_type:
        raise Malformed("predicate-type-mismatch")


def _rule_subject_interval(state: _State) -> None:
    """The second subject entry is present if and only if an interval is (S1, I1r)."""
    effect = state.predicate.get("effect")
    has_interval = isinstance(effect, dict) and "interval" in effect
    subjects = state.statement["subject"]
    if len(subjects) != (2 if has_interval else 1):
        raise Malformed("subject-interval-mismatch")


def _rule_required_members(state: _State) -> None:
    """No member has a default and no verifier supplies one (F1)."""
    pred = state.predicate
    for name in TOP_MEMBERS:
        if name not in pred:
            raise Malformed("member-missing")
    for dotted, names in NESTED_MEMBERS.items():
        node = _at(pred, dotted)
        if not isinstance(node, dict) or any(n not in node for n in names):
            raise Malformed("member-missing")
    rows: list[tuple[Any, tuple[str, ...]]] = [(w, WRITE_MEMBERS) for w in pred["effect"]["writes"]]
    rows += [(r, REMEDIATION_MEMBERS) for r in pred["remediation"]]
    for row, names in rows:
        if not isinstance(row, dict) or any(n not in row for n in names):
            raise Malformed("member-missing")


def _vocabulary_values(pred: dict[str, Any], dotted: str) -> list[Any]:
    if dotted.startswith("remediation[]."):
        return [row[dotted.split(".", 1)[1]] for row in pred["remediation"]]
    try:
        return [_at(pred, dotted)]
    except (KeyError, TypeError):
        # correlation.externalAnchor and oversight are conditional; their
        # rules run later.
        return []


def _rule_closed_vocabularies(state: _State) -> None:
    """A value outside a closed set is refused, never ignored (V1)."""
    pred = state.predicate
    for dotted, allowed in VOCABULARIES.items():
        for value in _vocabulary_values(pred, dotted):
            if value not in allowed:
                raise Malformed("value-outside-vocabulary")
    for value in pred["fieldEvidence"].values():
        if value not in FIELD_EVIDENCE_VALUES:
            raise Malformed("value-outside-vocabulary")


def _entry_unavailable(entry: dict[str, Any], reported_at: datetime.datetime) -> bool:
    """Stale or never established at ``reported_at``; an age equal to maxAge is fresh."""
    if entry["lastResult"] == NEVER_HELD:
        return True
    produced = _instant(entry["lastResult"])
    if produced - reported_at > SKEW_TOLERANCE:
        raise Malformed("evaluation-result-after-decision")
    age = (reported_at - produced).total_seconds()
    return bool(age > entry["maxAge"])


def _entry_shape(entry: Any) -> None:
    """Exactly input, lastResult and maxAge; an input from the closed set; a
    maxAge that is a non-negative integer."""
    if not isinstance(entry, dict):
        raise Malformed("evaluation-entry-malformed")
    if not ENTRY_MEMBERS <= set(entry):
        raise Malformed("member-missing")
    if set(entry) - ENTRY_MEMBERS - ENTRY_OPTIONAL:
        raise Malformed("evaluation-entry-malformed")
    if entry["input"] not in EVALUATION_INPUTS:
        raise Malformed("value-outside-vocabulary")
    max_age = entry["maxAge"]
    if isinstance(max_age, bool) or not isinstance(max_age, int) or max_age < 0:
        raise Malformed("evaluation-entry-malformed")


def aggregate_values(values: list[dict[str, Any]]) -> dict[str, Any]:
    """The lastResult and maxAge one evaluation entry carries for an input the
    decision depended on several values of (Section 5.4, revision 01).

    Both come from the same value. If any value was never held, lastResult is
    ``none`` and maxAge the smallest bound among the values never held.
    Otherwise the pair is the one whose lastResult plus maxAge is earliest, and
    of two such pairs the one with the earlier lastResult. At one reference time
    every held value is fresh exactly when that time is at most the earliest
    expiry, so the entry is fresh exactly when every value is. Taking the oldest
    lastResult from one value and the smallest maxAge from another, as revision
    00 did, can report two fresh values as one stale input (FR15).

    This is the producer's side: a verifier holding only the record cannot
    recover the values, so the corpus carries them in FR14's ``aggregation``
    block and the judge checks this function against the entry FR14 carries.
    """
    if not values:
        raise ValueError("an entry summarizes at least one value")
    never = [v for v in values if v["lastResult"] == NEVER_HELD]
    if never:
        return {"lastResult": NEVER_HELD, "maxAge": min(v["maxAge"] for v in never)}

    epoch = datetime.datetime(1970, 1, 1, tzinfo=datetime.UTC)

    def expiry(v: dict[str, Any]) -> tuple[int, int]:
        # A valid maxAge may put expiry beyond datetime's calendar range.
        # Subtract aware instants instead of normalizing to a UTC datetime;
        # an offset at the calendar boundary can put that date out of range too.
        elapsed = _instant(v["lastResult"]) - epoch
        produced = (elapsed.days * 86400 + elapsed.seconds) * 1_000_000 + elapsed.microseconds
        return produced + v["maxAge"] * 1_000_000, produced

    chosen = min(values, key=expiry)
    return {"lastResult": chosen["lastResult"], "maxAge": chosen["maxAge"]}


def derive_unavailable(pred: dict[str, Any]) -> list[str]:
    """The inputs a verifier derives as unavailable from ``evaluation.inputs``,
    in entry order, after holding every entry to its shape (FR5, FR6, FR9 to FR13)."""
    entries = pred["evaluation"]["inputs"]
    if not isinstance(entries, list):
        raise Malformed("evaluation-entry-malformed")
    reported_at = _instant(pred["decision"]["reportedAt"])
    seen: set[str] = set()
    unavailable: list[str] = []
    for entry in entries:
        _entry_shape(entry)
        if entry["input"] in seen:
            raise Malformed("evaluation-input-repeated")
        seen.add(entry["input"])
        if _entry_unavailable(entry, reported_at):
            unavailable.append(entry["input"])
    return unavailable


def _rule_evaluation(state: _State) -> None:
    """No member beside status, inputs and unavailableInput (EV12). The entries
    derive the unavailable inputs. Evaluated derives none and names none;
    not-evaluated names the derived set, once each and no other."""
    evaluation = state.predicate["evaluation"]
    if set(evaluation) - EVALUATION_MEMBERS:
        raise Malformed("evaluation-malformed")
    derived = derive_unavailable(state.predicate)
    if evaluation["status"] == "evaluated":
        if "unavailableInput" in evaluation or derived:
            raise Malformed("evaluation-inconsistent")
        return
    inputs = evaluation.get("unavailableInput")
    if not isinstance(inputs, list) or not inputs:
        raise Malformed("evaluation-inconsistent")
    for value in inputs:
        if value not in UNAVAILABLE_INPUTS:
            raise Malformed("value-outside-vocabulary")
    if len(set(inputs)) != len(inputs) or set(inputs) != set(derived):
        raise Malformed("evaluation-inconsistent")


def _is_digest(value: Any) -> bool:
    hex_digits = "0123456789abcdef"
    return isinstance(value, str) and len(value) == 64 and all(c in hex_digits for c in value)


def _rule_oversight(state: _State) -> None:
    """The optional oversight member: an act, and at most the overseer's record digest."""
    if "oversight" not in state.predicate:
        return
    oversight = state.predicate["oversight"]
    if not isinstance(oversight, dict):
        raise Malformed("oversight-malformed")
    if "act" not in oversight:
        raise Malformed("member-missing")
    if set(oversight) - OVERSIGHT_MEMBERS:
        raise Malformed("oversight-malformed")
    if "recordDigest" in oversight and not _is_digest(oversight["recordDigest"]):
        raise Malformed("oversight-malformed")


# --------------------------------------------------------------------------
# Consumption binding (Section 5.4, revision 01): the operation key.
# --------------------------------------------------------------------------


#: The only members a sequence object carries, both required.
SEQUENCE_MEMBERS = frozenset({"boundary", "seq"})


def _rule_sequence(state: _State) -> None:
    """The optional sequence member: exactly boundary, a string, and seq, a
    positive integer (SQ1). Any other member (SQ2) or a seq below 1 (SQ3) is
    refused."""
    if "sequence" not in state.predicate:
        return
    sequence = state.predicate["sequence"]
    if not isinstance(sequence, dict) or set(sequence) != SEQUENCE_MEMBERS:
        raise Malformed("sequence-malformed")
    seq = sequence["seq"]
    if not isinstance(sequence["boundary"], str) or not sequence["boundary"]:
        raise Malformed("sequence-malformed")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        raise Malformed("sequence-malformed")


def _is_count(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def consumption_of(pred: dict[str, Any]) -> dict[str, Any] | None:
    """The ``consumption`` member of the consumption-state entry, if one carries it."""
    for entry in pred["evaluation"]["inputs"]:
        if isinstance(entry, dict) and entry.get("input") == CONSUMPTION_INPUT:
            found = entry.get("consumption")
            return found if isinstance(found, dict) else None
    return None


def held_for(consumption: dict[str, Any], decision: dict[str, Any]) -> dict[str, Any] | None:
    """The held entry this call is a retry of: the one whose operationKey is the
    call's own. Retry identity is the agent's operation key and nothing else; a
    request digest is a content digest, so two intended payments with the same
    action, arguments and resource share one (CS11, CS12)."""
    for held in consumption["held"]:
        if held["operationKey"] == decision.get("operationKey"):
            return held if isinstance(held, dict) else None
    return None


def within_limit(pred: dict[str, Any]) -> bool | None:
    """The value a verifier derives for a record that carries consumption: the
    amount already consumed, plus the amount held for earlier permits, plus this
    call's amount unless it is a retry of a held permit, is at most the limit.
    None for a record that carries no consumption."""
    consumption = consumption_of(pred)
    if consumption is None:
        return None
    counted = consumption["consumed"] + consumption["reserved"]
    if held_for(consumption, pred["decision"]) is None:
        counted += consumption["requested"]
    return bool(counted <= consumption["limit"])


def _held_shape(item: Any) -> None:
    """One held entry: exactly operationKey, requestDigest and amount."""
    if not isinstance(item, dict):
        raise Malformed("consumption-malformed")
    if any(name not in item for name in HELD_MEMBERS):
        raise Malformed("member-missing")
    if set(item) - set(HELD_MEMBERS):
        raise Malformed("consumption-malformed")
    key = item["operationKey"]
    if not isinstance(key, str) or not key or not _is_digest(item["requestDigest"]):
        raise Malformed("consumption-value-invalid")
    if not _is_count(item["amount"]):
        raise Malformed("consumption-value-invalid")


def _consumption_shape(consumption: Any) -> dict[str, Any]:
    if not isinstance(consumption, dict):
        raise Malformed("consumption-malformed")
    required = [
        name
        for name in CONSUMPTION_MEMBERS
        if name != "stateRevision" or "state-revision" in CONSUMPTION_CHECKS
    ]
    if any(name not in consumption for name in required):
        raise Malformed("member-missing")
    if set(consumption) - set(CONSUMPTION_MEMBERS):
        raise Malformed("consumption-malformed")
    unit = consumption["unit"]
    if not _is_digest(consumption["limitDigest"]) or not isinstance(unit, str) or not unit:
        raise Malformed("consumption-value-invalid")
    counted = [name for name in CONSUMPTION_COUNTS if name in consumption]
    if "counts" in CONSUMPTION_CHECKS and not all(_is_count(consumption[n]) for n in counted):
        raise Malformed("consumption-value-invalid")
    held = consumption["held"]
    if not isinstance(held, list):
        raise Malformed("consumption-malformed")
    for item in held:
        _held_shape(item)
    return consumption


def _rule_consumption(state: _State) -> None:
    """The consumption member and the operation key (CS3 to CS6, CS9 to CS14).

    ``consumption`` sits only on a consumption-state entry. ``reserved`` is the
    sum of the held amounts and the held operation keys are distinct. A record
    that carries consumption carries ``decision.operationKey``. A call whose key
    is held is a retry: its request digest and amount are the held entry's
    (CS10), and it is not counted twice (CS4); a call whose key is not held is a
    new operation even when its request digest is a held entry's (CS11, CS12)."""
    pred = state.predicate
    for entry in pred["evaluation"]["inputs"]:
        if (
            "misplaced" in CONSUMPTION_CHECKS
            and "consumption" in entry
            and entry["input"] != CONSUMPTION_INPUT
        ):
            raise Malformed("consumption-misplaced")
    decision = pred["decision"]
    key = decision.get("operationKey")
    if "operationKey" in decision and (not isinstance(key, str) or not key):
        raise Malformed("operation-key-invalid")
    consumption = consumption_of(pred)
    if consumption is None:
        return
    _consumption_shape(consumption)
    keys = [held["operationKey"] for held in consumption["held"]]
    if "distinct-keys" in CONSUMPTION_CHECKS and len(set(keys)) != len(keys):
        raise Malformed("consumption-held-key-repeated")
    held_sum = sum(held["amount"] for held in consumption["held"])
    if "reserved" in CONSUMPTION_CHECKS and held_sum != consumption["reserved"]:
        raise Malformed("consumption-reserved-mismatch")
    if "operation-key" in CONSUMPTION_CHECKS and "operationKey" not in decision:
        raise Malformed("member-missing")
    retried = held_for(consumption, decision)
    if (
        "key-reuse" in CONSUMPTION_CHECKS
        and retried is not None
        and (
            retried["requestDigest"] != decision["requestDigest"]
            or retried["amount"] != consumption["requested"]
        )
    ):
        raise Malformed("consumption-key-reused")


def _rule_delegation(state: _State) -> None:
    """``subjectKind`` of none beside any other subject value (F2)."""
    delegation = state.predicate["delegation"]
    if delegation["subjectKind"] == "none" and delegation["subject"] != "none":
        raise Malformed("delegation-subject-inconsistent")


def _rule_binding(state: _State) -> None:
    """digest-bound carries argumentsDigest; not-bindable carries it in no
    spelling, null and the empty string included (F3, F3b, F3c)."""
    resource = state.predicate["resource"]
    if resource["binding"] == "digest-bound" and "argumentsDigest" not in resource:
        raise Malformed("arguments-digest-missing")
    if resource["binding"] == "not-bindable" and "argumentsDigest" in resource:
        raise Malformed("arguments-digest-forbidden")


def _rule_request_digest(state: _State) -> None:
    """The request digest recomputes and is the first subject's digest (F4, A6)."""
    pred = state.predicate
    recomputed = request_digest(pred)
    if pred["decision"]["requestDigest"] != recomputed:
        raise Malformed("request-digest-mismatch")
    if state.statement["subject"][0].get("digest", {}).get("sha256") != recomputed:
        raise Malformed("subject-request-mismatch")


def _rule_subject_after_root(state: _State) -> None:
    """The second subject's digest is the interval's after-state root (S2)."""
    after = state.predicate["effect"]["interval"]["afterRoot"]
    if state.statement["subject"][1].get("digest", {}).get("sha256") != after:
        raise Malformed("subject-after-root-mismatch")


def _rule_external_anchor(state: _State) -> None:
    """beacon-anchored carries externalAnchor, asserted does not (F5)."""
    correlation = state.predicate["correlation"]
    anchored = correlation["timeBasis"] == "beacon-anchored"
    if anchored != ("externalAnchor" in correlation):
        raise Malformed("external-anchor-inconsistent")


def _rule_remediation_order(state: _State) -> None:
    """enforcedAt at or after signalReceivedAt in every event (F7)."""
    for row in state.predicate["remediation"]:
        if _instant(row["enforcedAt"]) < _instant(row["signalReceivedAt"]):
            raise Malformed("remediation-order")


def _rule_empty_tree(state: _State) -> None:
    """empty-tree carries the constant for the declared algorithm (E3)."""
    pred = state.predicate
    interval = pred["effect"]["interval"]
    if interval["baseResolution"] != "empty-tree":
        return
    if interval["beforeRoot"] != EMPTY_TREE[pred["hashAlgorithm"]]:
        raise Malformed("empty-tree-constant-mismatch")


def _rule_commitment(state: _State) -> None:
    """Order (C2), digest (C3), and key disjointness (C1) of the prior commitment."""
    pred = state.predicate
    if not _commitment_complete(pred):
        return
    commitment = _commitment(pred)
    assert commitment is not None
    opened = _instant(pred["effect"]["interval"]["openedAt"])
    if not _instant(commitment["committedAt"]) < opened:
        raise Malformed("commitment-order")
    if commitment["commitmentDigest"] != commitment_digest(pred, commitment):
        raise Malformed("commitment-digest-mismatch")
    if commitment["keyid"] in pred["agent"]["signers"]:
        raise Malformed("commitment-key-is-agent-signer")


def _rule_write_chain(state: _State) -> None:
    """The ordered writes reproduce afterRoot from beforeRoot (E2)."""
    interval = state.predicate["effect"]["interval"]
    current = interval["beforeRoot"]
    for write in state.predicate["effect"]["writes"]:
        if write["preStateDigest"] != current:
            raise Malformed("write-chain-broken")
        current = write["postStateDigest"]
    if current != interval["afterRoot"]:
        raise Malformed("write-chain-broken")


def _rule_path_scope_literal(state: _State) -> None:
    """No glob metacharacter in pathScope; the universal scope is ``/`` (V2)."""
    for scope in state.predicate["effect"]["pathScope"]:
        if not isinstance(scope, str) or GLOB_METACHARACTERS & set(scope):
            raise Malformed("path-scope-glob")


def _rule_coverage(state: _State) -> None:
    """A gap inside pathScope contradicts scopeComplete of true, and the record
    is malformed whatever tier it declares (V4, V5)."""
    pred = state.predicate
    if pred["observation"]["coverage"]["scopeComplete"] is True and gaps_inside_scope(pred):
        raise Malformed("coverage-inconsistent")


def _rule_tier(state: _State) -> None:
    """The tier is recomputed; a declared authoritative that fails a clause is
    malformed and is never downgraded (TI1 to TI5)."""
    pred = state.predicate
    failed = tier_failures(pred)
    state.derived_tier = "voluntary" if failed else "authoritative"
    if pred["tier"] == "authoritative" and failed:
        raise Malformed(failed[0])


def _rule_write_scope(state: _State) -> None:
    """inScope is derived from the path, never a producer opinion (V3)."""
    scope = state.predicate["effect"]["pathScope"]
    for write in state.predicate["effect"]["writes"]:
        derived = any(_under(write["path"], s) for s in scope)
        if write["inScope"] is not derived:
            raise Malformed("write-scope-mismatch")


def _rule_observed(state: _State) -> None:
    """effect.observed derives from the writes attributed to this request (T1, E1)."""
    if state.predicate["effect"]["observed"] != derive_observed(state.predicate):
        raise Malformed("effect-observed-underivable")


def _rule_agreement(state: _State) -> None:
    """agreement derives from the decision and the effect (D1, D2, D3)."""
    pred = state.predicate
    if pred["agreement"] == "one-sided":
        raise Malformed("agreement-reserved-value")
    derived = derive_agreement(pred["decision"]["reported"], pred["effect"]["observed"])
    if pred["agreement"] != derived:
        raise Malformed("agreement-underivable")


def _rule_posture_agreement(state: _State) -> None:
    """agree when the two postures are equal byte for byte (F6)."""
    posture = state.predicate["posture"]
    equal = canonical_bytes([posture["reported"], posture["reportedDigest"]]) == canonical_bytes(
        [posture["observed"], posture["observedDigest"]]
    )
    if posture["agreement"] != ("agree" if equal else "disagree"):
        raise Malformed("posture-agreement-underivable")


def _rule_field_evidence(state: _State) -> None:
    """Exactly the seven keys (FE1); no substrate-covered beside self (FE2)."""
    pred = state.predicate
    evidence = pred["fieldEvidence"]
    if set(evidence) != FIELD_EVIDENCE_KEYS:
        raise Malformed("field-evidence-keys")
    if pred["observation"]["vantage"] == "self" and "substrate-covered" in evidence.values():
        raise Malformed("field-evidence-self-substrate")


RULES: list[tuple[str, Callable[[_State], None]]] = [
    ("statement", _rule_statement),
    ("subject-interval", _rule_subject_interval),
    ("required-members", _rule_required_members),
    ("closed-vocabularies", _rule_closed_vocabularies),
    ("evaluation", _rule_evaluation),
    ("oversight", _rule_oversight),
    ("sequence", _rule_sequence),
    ("consumption", _rule_consumption),
    ("delegation", _rule_delegation),
    ("binding", _rule_binding),
    ("request-digest", _rule_request_digest),
    ("subject-after-root", _rule_subject_after_root),
    ("external-anchor", _rule_external_anchor),
    ("remediation-order", _rule_remediation_order),
    ("empty-tree", _rule_empty_tree),
    ("commitment", _rule_commitment),
    ("write-chain", _rule_write_chain),
    ("path-scope-literal", _rule_path_scope_literal),
    ("coverage", _rule_coverage),
    ("tier", _rule_tier),
    ("write-scope", _rule_write_scope),
    ("observed", _rule_observed),
    ("agreement", _rule_agreement),
    ("posture-agreement", _rule_posture_agreement),
    ("field-evidence", _rule_field_evidence),
]


#: Rules no Appendix B row reaches. The draft states them and a reader must keep
#: them, but the corpus carries no member for them, so a mutation sweep that
#: disabled one would report it inert for a reason that is the draft's, not this
#: reader's. Named here so the exemption is visible rather than silent.
UNREACHED_BY_CORPUS = frozenset({"statement"})


def rule_names() -> list[str]:
    return [name for name, _ in RULES]


def _envelope_payload(raw: bytes) -> tuple[dict[str, Any], bytes]:
    try:
        envelope = json.loads(raw, object_pairs_hook=_no_duplicates)
        payload = base64.b64decode(envelope["payload"], validate=True)
    except Malformed:
        raise
    except Exception as exc:
        raise Malformed("envelope-unreadable") from exc
    if not isinstance(envelope, dict) or envelope.get("payloadType") != PAYLOAD_TYPE:
        raise Malformed("envelope-unreadable")
    return envelope, payload


def _signature_holds(envelope: dict[str, Any], canonical: bytes, policy: Policy) -> bool:
    """The signature covers the RFC 8785 bytes of the Statement and no other
    serialization, so the bytes checked are the ones this reader derives."""
    try:
        key = bytes.fromhex(policy.observer_public_key)
        signatures = envelope["signatures"]
    except (KeyError, ValueError):
        return False
    message = pae(PAYLOAD_TYPE, canonical)
    for entry in signatures if isinstance(signatures, list) else []:
        try:
            sig = base64.b64decode(entry["sig"], validate=True)
        except Exception:
            continue
        if len(key) == 32 and _ed25519_verify(key, message, sig):
            return True
    return False


def verify(raw: bytes, policy: Policy, *, disabled: str | None = None) -> Report:
    """Judge one DSSE envelope carrying an agent audit record.

    ``disabled`` names one rule to skip, which is how a mutation sweep asks
    whether that rule is load-bearing. Production verification never passes it.
    """
    try:
        envelope, payload = _envelope_payload(raw)
        statement = parse_statement(payload)
        if not isinstance(statement, dict):
            raise Malformed("statement-shape")
        canonical = canonical_bytes(statement)
    except Malformed as exc:
        return Report("malformed", [exc.code])
    if disabled != "signature" and not _signature_holds(envelope, canonical, policy):
        return Report("malformed", ["signature-invalid"])
    predicate = statement.get("predicate")
    if not isinstance(predicate, dict) or not isinstance(statement.get("subject"), list):
        return Report("malformed", ["statement-shape"])
    state = _State(statement=statement, predicate=predicate, policy=policy)
    try:
        for name, rule in RULES:
            if name != disabled:
                rule(state)
    except Malformed as exc:
        return Report("malformed", [exc.code], state.derived_tier)
    except (KeyError, TypeError, AttributeError, IndexError) as exc:
        return Report("malformed", [f"unhandled-shape:{exc.__class__.__name__}"])
    return Report("valid", [], state.derived_tier)


# --------------------------------------------------------------------------
# Retained records and the dating check (Section 4.7).
# --------------------------------------------------------------------------

ANCHOR_KINDS = frozenset({"rfc3161", "transparency-log", "opentimestamps"})
#: A comparison using the time of an opentimestamps anchor allows this in place
#: of the skew tolerance: the consensus bound on a header time (R10, R11).
OTS_TOLERANCE = datetime.timedelta(seconds=7200)
OTS_MAGIC = bytes.fromhex("004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294")
OTS_BITCOIN = bytes.fromhex("0588960d73d71901")
OTS_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
OTS_SHA256, OTS_APPEND, OTS_PREPEND = 0x08, 0xF0, 0xF1
OTS_MAX_BYTES = 4096
OTS_MAX_DEPTH = 256
#: The algorithm a delegation root's key set names, read off its JWK members.
JWK_ALGORITHMS = {
    ("OKP", "Ed25519"): "Ed25519",
    ("OKP", "Ed448"): "Ed448",
    ("EC", "P-256"): "P-256",
    ("EC", "P-384"): "P-384",
    ("EC", "P-521"): "P-521",
}
ANCHOR_ORIGINS = frozenset({"retainer", "received"})
INCLUSION_PROOF_V2 = 0x0106


@dataclass(frozen=True)
class TreeHead:
    """A transparency-log tree head a verifier holds by a means other than its
    signature, such as a checkpoint it already witnessed (Section 4.7.2)."""

    log_id: bytes
    tree_size: int
    root_hash: bytes
    timestamp: str


@dataclass(frozen=True)
class BlockHeader:
    """A Bitcoin block header a verifier holds independently, as a block of the
    chain with the most work (Section 4.7.2): its height, the Merkle root it
    carries in internal byte order, and its timestamp."""

    height: int
    merkle_root: bytes
    timestamp: str


#: What a verifier holds to validate anchors offline: tree heads and block headers.
AnchorTrust = list[TreeHead | BlockHeader]

NOT_ESTABLISHED: dict[str, Any] = {"result": "not-established"}


@dataclass
class Dating:
    """The dating check's result, reported beside the record's verdict. The
    delegation root's result sits beside both and changes neither (R13 to R15)."""

    entry: str
    codes: list[str]
    dated_at: str | None = None
    receipt: str | None = None
    delegation_root: dict[str, Any] = field(default_factory=lambda: dict(NOT_ESTABLISHED))


class _Reader:
    """A cursor over TLS presentation-language bytes (RFC 8446 Section 3)."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.at = 0

    def take(self, n: int) -> bytes:
        if self.at + n > len(self.data):
            raise ValueError("truncated")
        out = self.data[self.at : self.at + n]
        self.at += n
        return out

    def uint(self, n: int) -> int:
        return int.from_bytes(self.take(n), "big")

    def varuint(self) -> int:
        """An OpenTimestamps unsigned LEB128 integer, at most 9 bytes."""
        value, shift = 0, 0
        while True:
            byte = self.take(1)[0]
            value |= (byte & 0x7F) << shift
            if not byte & 0x80:
                return value
            shift += 7
            if shift > 56:
                raise ValueError("varuint too long")

    def varbytes(self, limit: int = OTS_MAX_BYTES) -> bytes:
        n = self.varuint()
        if n > limit:
            raise ValueError("varbytes too long")
        return self.take(n)


def _inclusion_proof(proof: bytes) -> tuple[bytes, int, int, list[bytes]]:
    """Decode an RFC 9162 TransItem of type inclusion_proof_v2 (Section 4.12)."""
    reader = _Reader(proof)
    if reader.uint(2) != INCLUSION_PROOF_V2:
        raise ValueError("not an inclusion_proof_v2")
    log_id = reader.take(reader.uint(1))
    if not 2 <= len(log_id) <= 127:
        raise ValueError("log_id length")
    tree_size, leaf_index = reader.uint(8), reader.uint(8)
    nodes = _Reader(reader.take(reader.uint(2)))
    path: list[bytes] = []
    while nodes.at < len(nodes.data):
        node = nodes.take(nodes.uint(1))
        if len(node) < 32:
            raise ValueError("node hash length")
        path.append(node)
    if reader.at != len(proof):
        raise ValueError("trailing bytes")
    return log_id, tree_size, leaf_index, path


def inclusion_root(leaf: bytes, leaf_index: int, tree_size: int, path: list[bytes]) -> bytes | None:
    """RFC 9162 Section 2.1.3.2, returning the root the path recomputes to."""
    if leaf_index >= tree_size:
        return None
    fn, sn = leaf_index, tree_size - 1
    r = hashlib.sha256(b"\x00" + leaf).digest()
    for p in path:
        if sn == 0:
            return None
        if fn & 1 or fn == sn:
            r = hashlib.sha256(b"\x01" + p + r).digest()
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = hashlib.sha256(b"\x01" + r + p).digest()
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None


def _ots_timestamp(
    reader: _Reader, message: bytes, out: list[tuple[bytes, bytes, bytes]], depth: int
) -> None:
    """One OpenTimestamps timestamp: items, each but the last preceded by 0xff."""
    if depth > OTS_MAX_DEPTH:
        raise ValueError("timestamp too deep")
    while True:
        tag = reader.take(1)[0]
        more = tag == 0xFF
        if more:
            tag = reader.take(1)[0]
        _ots_item(reader, tag, message, out, depth)
        if not more:
            return


def _ots_item(
    reader: _Reader, tag: int, message: bytes, out: list[tuple[bytes, bytes, bytes]], depth: int
) -> None:
    """An attestation (0x00, an 8-byte tag and its payload), or a commitment
    operation applied to ``message`` followed by the timestamp of its result."""
    if tag == 0x00:
        kind = reader.take(8)
        out.append((message, kind, reader.varbytes()))
        return
    if tag == OTS_SHA256:
        result = hashlib.sha256(message).digest()
    elif tag in (OTS_APPEND, OTS_PREPEND):
        argument = reader.varbytes()
        result = message + argument if tag == OTS_APPEND else argument + message
    else:
        raise ValueError("operation this reader does not define")
    if len(result) > OTS_MAX_BYTES:
        raise ValueError("message too long")
    _ots_timestamp(reader, result, out, depth + 1)


def ots_attestations(proof: bytes, envelope_digest: bytes) -> list[tuple[bytes, bytes, bytes]]:
    """Decode a DetachedTimestampFile over ``envelope_digest``: every attestation
    as (the message it attests, its tag, its payload)."""
    reader = _Reader(proof)
    if reader.take(len(OTS_MAGIC)) != OTS_MAGIC or reader.varuint() != 1:
        raise ValueError("not an OpenTimestamps proof")
    if reader.take(1)[0] != OTS_SHA256 or reader.take(32) != envelope_digest:
        raise ValueError("the proof is over another digest")
    out: list[tuple[bytes, bytes, bytes]] = []
    _ots_timestamp(reader, envelope_digest, out, 0)
    if reader.at != len(proof):
        raise ValueError("trailing bytes")
    return out


def _ots_moment(proof: bytes, envelope_digest: bytes, trust: AnchorTrust) -> tuple[str, int] | None:
    """The lowest held block a Bitcoin attestation's message is the Merkle root
    of. A pending attestation validates nothing (R12)."""
    found: list[tuple[int, str]] = []
    for message, kind, payload in ots_attestations(proof, envelope_digest):
        if kind != OTS_BITCOIN:
            continue
        payload_reader = _Reader(payload)
        height = payload_reader.varuint()
        if payload_reader.at != len(payload):
            raise ValueError("trailing bytes in a Bitcoin attestation")
        for held in trust:
            if isinstance(held, BlockHeader) and held.height == height:
                if held.merkle_root == message:
                    found.append((height, held.timestamp))
    if not found:
        return None
    height, timestamp = min(found)
    return timestamp, height


def anchor_time(
    anchor: dict[str, Any], envelope_digest: bytes, trust: AnchorTrust
) -> tuple[str, int | None] | None:
    """The time an anchor establishes over ``envelope_digest`` and, for an
    opentimestamps anchor, the height of its block; None when it does not
    validate. A transparency-log anchor validates when it recomputes to a held
    tree head, an opentimestamps anchor when it recomputes to the Merkle root of
    a held block header. This reader holds no time-stamping authority path, so
    an rfc3161 anchor dates nothing."""
    kind = anchor.get("kind")
    try:
        proof = base64.b64decode(anchor["proof"], validate=True)
        if kind == "opentimestamps":
            return _ots_moment(proof, envelope_digest, trust)
        if kind != "transparency-log":
            return None
        log_id, tree_size, leaf_index, path = _inclusion_proof(proof)
    except (KeyError, TypeError, ValueError):
        return None
    root = inclusion_root(envelope_digest, leaf_index, tree_size, path)
    for head in trust:
        if isinstance(head, TreeHead) and (head.log_id, head.tree_size, head.root_hash) == (
            log_id,
            tree_size,
            root,
        ):
            return head.timestamp, None
    return None


def _retention_shape(entry: Any) -> None:
    if not isinstance(entry, dict):
        raise Malformed("entry-shape-malformed")
    if not isinstance(entry.get("envelopeDigest"), str) or not isinstance(
        entry.get("received"), bool
    ):
        raise Malformed("entry-shape-malformed")
    within = entry.get("anchorWithin")
    if isinstance(within, bool) or not isinstance(within, int) or within < 0:
        raise Malformed("entry-shape-malformed")
    anchors = entry.get("anchors")
    if not isinstance(anchors, list):
        raise Malformed("entry-shape-malformed")
    for anchor in anchors:
        if (
            not isinstance(anchor, dict)
            or anchor.get("kind") not in ANCHOR_KINDS
            or anchor.get("origin") not in ANCHOR_ORIGINS
            or not isinstance(anchor.get("proof"), str)
        ):
            raise Malformed("entry-shape-malformed")


@dataclass
class _Retained:
    entry: dict[str, Any]
    issued_at: datetime.datetime
    computed_digest: str
    heads: AnchorTrust
    received_at: datetime.datetime | None = None
    retention_time: datetime.datetime | None = None
    retention_ots: bool = False
    root_digest: str | None = None
    delegation_root: dict[str, Any] = field(default_factory=lambda: dict(NOT_ESTABLISHED))

    def tolerance(self) -> datetime.timedelta:
        """The tolerance a comparison with the retention time allows."""
        return OTS_TOLERANCE if self.retention_ots else SKEW_TOLERANCE


def _dating_received_at(r: _Retained) -> None:
    """receivedAt is present if and only if received is true (R9)."""
    if r.entry["received"] != ("receivedAt" in r.entry):
        raise Malformed("entry-received-at-inconsistent")
    if r.entry["received"]:
        r.received_at = _instant(r.entry["receivedAt"])


def _dating_envelope_digest(r: _Retained) -> None:
    """The entry names the envelope it sits beside."""
    if r.entry["envelopeDigest"] != r.computed_digest:
        raise Malformed("entry-envelope-digest-mismatch")


def _dating_retainer_anchor(r: _Retained) -> None:
    """A received record carries an anchor of origin retainer (R4)."""
    if r.entry["received"] and not any(a["origin"] == "retainer" for a in r.entry["anchors"]):
        raise Malformed("entry-retainer-anchor-missing")


def _dating_received_before_issued(r: _Retained) -> None:
    """receivedAt no earlier than issuedAt by more than the skew tolerance (R6)."""
    if r.received_at is not None and r.received_at < r.issued_at - SKEW_TOLERANCE:
        raise Malformed("entry-received-before-issued")


def _dating_received_after_anchor(r: _Retained) -> None:
    """receivedAt no later than the retention time by more than the skew tolerance (R3)."""
    if r.received_at is None or r.retention_time is None:
        return
    if r.received_at > r.retention_time + r.tolerance():
        raise Malformed("entry-received-after-anchor")


def _dating_anchor_late(r: _Retained) -> None:
    """The retention time within anchorWithin plus the skew tolerance of receipt,
    or of issuance for a record the retaining party produced (R7)."""
    if r.retention_time is None:
        return
    start = r.received_at if r.received_at is not None else r.issued_at
    limit = datetime.timedelta(seconds=r.entry["anchorWithin"]) + r.tolerance()
    if r.retention_time > start + limit:
        raise Malformed("entry-anchor-late")


def _jwk_algorithm(material: bytes) -> str:
    keys = json.loads(material, object_pairs_hook=_no_duplicates)["keys"]
    algorithms = {JWK_ALGORITHMS.get((k.get("kty"), k.get("crv"))) for k in keys}
    if len(algorithms) != 1 or None in algorithms:
        raise ValueError("no single algorithm")
    return str(algorithms.pop())


def _dating_delegation_root(r: _Retained) -> None:
    """A delegation-root element whose digest equals delegation.rootDigest
    establishes the root and names its algorithm (R13); none leaves it not
    established, never a pass (R14); an unequal digest is malformed (R15)."""
    elements = [
        v
        for v in r.entry.get("validationData") or []
        if isinstance(v, dict) and v.get("for") == "delegation-root"
    ]
    if len(elements) > 1 or (elements and r.root_digest is None):
        raise Malformed("entry-delegation-root-unexpected")
    if not elements:
        return
    try:
        material = base64.b64decode(elements[0]["value"], validate=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise Malformed("entry-delegation-root-unreadable") from exc
    if hashlib.sha256(material).hexdigest() != r.root_digest:
        raise Malformed("entry-delegation-root-mismatch")
    try:
        algorithm = _jwk_algorithm(material)
    except (Malformed, KeyError, TypeError, ValueError, AttributeError) as exc:
        raise Malformed("entry-delegation-root-unreadable") from exc
    r.delegation_root = {"result": "established", "algorithm": algorithm}


DATING_RULES: list[tuple[str, Callable[[_Retained], None]]] = [
    ("entry-received-at", _dating_received_at),
    ("entry-envelope-digest", _dating_envelope_digest),
    ("entry-retainer-anchor", _dating_retainer_anchor),
    ("entry-received-before-issued", _dating_received_before_issued),
    ("entry-received-after-anchor", _dating_received_after_anchor),
    ("entry-anchor-late", _dating_anchor_late),
    ("entry-delegation-root", _dating_delegation_root),
]
#: Dating rules no Appendix B row reaches: no member carries an entry naming
#: another envelope.
DATING_UNREACHED = frozenset({"entry-envelope-digest"})


@dataclass(frozen=True)
class _Moment:
    origin: str
    time: str
    height: int | None


def _earlier(a: _Moment, b: _Moment) -> int:
    """Two opentimestamps anchors compare by block height, any other pair by time."""
    if a.height is not None and b.height is not None and a.height != b.height:
        return -1 if a.height < b.height else 1
    ta, tb = _instant(a.time), _instant(b.time)
    return (ta > tb) - (ta < tb)


def _anchor_times(
    entry: dict[str, Any], digest_bytes: bytes, heads: AnchorTrust, *, disabled: str | None
) -> list[_Moment]:
    """Every anchor that validates, earliest first."""
    out: list[_Moment] = []
    for anchor in entry["anchors"]:
        moment: tuple[str, int | None] | None
        if disabled == "anchor-validation":
            moment = (heads[0].timestamp, None) if heads else None
        else:
            moment = anchor_time(anchor, digest_bytes, heads)
        if moment is not None:
            out.append(_Moment(anchor["origin"], moment[0], moment[1]))
    return sorted(out, key=functools.cmp_to_key(_earlier))


def date_retained(
    envelope: dict[str, Any],
    entry: Any,
    issued_at: str,
    heads: AnchorTrust,
    *,
    disabled: str | None = None,
    root_digest: str | None = None,
) -> Dating:
    """The dating check of Section 4.7.1 over one envelope and its retention entry.

    The record is dated by the earliest anchor of either origin that validates
    over the envelope digest this reader derives; an anchor that does not
    validate dates nothing and makes nothing malformed (R8). A well-formed entry
    for a received record reports receivedAt as asserted and consistent with the
    anchors, never as established (R5)."""
    try:
        _retention_shape(entry)
        digest = hashlib.sha256(canonical_bytes(envelope)).hexdigest()
        retained = _Retained(entry, _instant(issued_at), digest, heads, root_digest=root_digest)
    except Malformed as exc:
        return Dating("malformed", [exc.code])
    times = _anchor_times(entry, bytes.fromhex(digest), heads, disabled=disabled)
    moments = times
    if disabled == "earliest-anchor":
        moments = [t for t in moments if t.origin == "retainer"] or moments
    dated_at = moments[0].time if moments else None
    retainer = [m for m in times if m.origin == "retainer"]
    if retainer:
        retained.retention_time = _instant(retainer[0].time)
        retained.retention_ots = (
            retainer[0].height is not None and disabled != "opentimestamps-tolerance"
        )
    try:
        for name, rule in DATING_RULES:
            if name != disabled:
                rule(retained)
    except Malformed as exc:
        return Dating("malformed", [exc.code], dated_at)
    receipt = None
    if entry["received"]:
        receipt = "asserted-consistent" if retained.retention_time else "asserted-unchecked"
    return Dating("well-formed", [], dated_at, receipt, retained.delegation_root)


def tree_heads(manifest: dict[str, Any]) -> AnchorTrust:
    """The tree heads, then the block headers, the manifest's anchorTrust holds."""
    trust = manifest.get("anchorTrust") or {}
    held: AnchorTrust = [
        TreeHead(
            bytes.fromhex(h["logId"]),
            int(h["treeSize"]),
            bytes.fromhex(h["rootHash"]),
            h["timestamp"],
        )
        for h in trust.get("treeHeads") or []
    ]
    held += [
        block_header(int(b["height"]), bytes.fromhex(b["header"]))
        for b in trust.get("blockHeaders") or []
    ]
    return held


def block_header(height: int, header: bytes) -> BlockHeader:
    """Read the Merkle root field, in internal byte order, and the time field,
    little-endian Unix seconds, off the bytes of a Bitcoin block header."""
    if len(header) != 80:
        raise ValueError("a block header is 80 bytes")
    seconds = int.from_bytes(header[68:72], "little")
    moment = datetime.datetime.fromtimestamp(seconds, datetime.UTC)
    return BlockHeader(height, header[36:68], moment.strftime("%Y-%m-%dT%H:%M:%SZ"))


def verify_retained(
    raw: bytes, policy: Policy, heads: AnchorTrust, *, disabled: str | None = None
) -> tuple[Report, Dating]:
    """Judge a retained record: the envelope's verdict, and the dating result."""
    try:
        bundle = json.loads(raw, object_pairs_hook=_no_duplicates)
        envelope, entry = bundle["envelope"], bundle["retention"]
    except (Malformed, ValueError, KeyError, TypeError):
        unreadable = ["retained-unreadable"]
        return Report("malformed", unreadable), Dating("malformed", unreadable)
    report = verify(json.dumps(envelope).encode(), policy, disabled=disabled)
    try:
        _, payload = _envelope_payload(json.dumps(envelope).encode())
        pred = parse_statement(payload)["predicate"]
        issued_at = pred["issuedAt"]
        root_digest = (pred.get("delegation") or {}).get("rootDigest")
    except (Malformed, KeyError, TypeError, AttributeError):
        return report, Dating("malformed", ["entry-record-unreadable"])
    return report, date_retained(
        envelope, entry, issued_at, heads, disabled=disabled, root_digest=root_digest
    )


def dating_rule_names() -> list[str]:
    return [
        "anchor-validation",
        "earliest-anchor",
        "opentimestamps-tolerance",
        *(n for n, _ in DATING_RULES),
    ]


# --------------------------------------------------------------------------
# Records retained together (Section 5.4, revision 01): the set checks.
# --------------------------------------------------------------------------


@dataclass
class SetReport:
    """A set of records judged together under one limitDigest."""

    verdict: str
    codes: list[str]
    missing: list[dict[str, Any]] = dataclasses.field(default_factory=list)


def _held_keys(pred: dict[str, Any]) -> set[str]:
    consumption = consumption_of(pred)
    assert consumption is not None
    return {held["operationKey"] for held in consumption["held"]}


def _revision(pred: dict[str, Any]) -> int:
    consumption = consumption_of(pred)
    assert consumption is not None
    return int(consumption["stateRevision"])


def _set_stale_revision(group: list[dict[str, Any]]) -> bool:
    """A permit that read a stateRevision older than a record already holding an
    unsettled permit, and omits that permit's operationKey from held, read a
    state that had not counted it: one limit spent twice (CS7, CS17). The key is
    the operation key; a request digest cannot tell two identical intended
    payments apart (CS17)."""
    for later in group:
        for earlier in group:
            if later is earlier or _revision(later) >= _revision(earlier):
                continue
            if later["decision"]["reported"] not in PERMITS:
                continue
            consumption = consumption_of(earlier)
            assert consumption is not None
            seen = _held_keys(later) | {later["decision"].get("operationKey")}
            if any(held["operationKey"] not in seen for held in consumption["held"]):
                return True
    return False


def _set_release_unshown(group: list[dict[str, Any]]) -> bool:
    """A held permit absent from a record that read a later state must be
    explained by the record of that operation: showing none (released) or
    occurred (moved to consumed). A lost response leaves it held (CS8)."""
    shown = {p["decision"].get("operationKey"): p["effect"]["observed"] for p in group}
    for later in group:
        for earlier in group:
            if later is earlier or _revision(later) <= _revision(earlier):
                continue
            consumption = consumption_of(earlier)
            assert consumption is not None
            gone = _held_keys(earlier) - _held_keys(later)
            if any(shown.get(key) not in ("none", "occurred") for key in gone):
                return True
    return False


SET_RULES: list[tuple[str, str, Callable[[list[dict[str, Any]]], bool]]] = [
    ("stale-revision", "consumption-set-stale-revision", _set_stale_revision),
    ("release-unshown", "consumption-set-release-unshown", _set_release_unshown),
]


def consumption_set_findings(
    predicates: list[dict[str, Any]], *, disabled: str | None = None
) -> SetReport:
    """Judge records that carry consumption, grouped by limitDigest. A set is
    malformed on the first check, in SET_RULES order, that any group fails."""
    groups: dict[str, list[dict[str, Any]]] = {}
    for pred in predicates:
        consumption = consumption_of(pred)
        if consumption is not None:
            groups.setdefault(consumption["limitDigest"], []).append(pred)
    for name, code, check in SET_RULES:
        if name != disabled and any(check(group) for group in groups.values()):
            return SetReport("malformed", [code])
    return SetReport("valid", [])


#: The two checks across the records of one sequence series; a test drops one.
SEQUENCE_SET_CHECKS = {"duplicate": True, "gap": True}


def sequence_set_findings(predicates: list[dict[str, Any]], payloads: list[bytes]) -> SetReport:
    """Judge the records that carry sequence. Every record of a set verified
    under the one observer key, so a series is the records with one boundary.
    Two records at one seq with different payload digests fail the set
    (SQ5); a seq below the highest held, which no record holds, is named as
    issued and not received (SQ4)."""
    series: dict[str, dict[int, set[str]]] = {}
    for pred, payload in zip(predicates, payloads, strict=True):
        sequence = pred.get("sequence")
        if sequence is None:
            continue
        digest = hashlib.sha256(payload).hexdigest()
        series.setdefault(sequence["boundary"], {}).setdefault(sequence["seq"], set()).add(digest)
    if SEQUENCE_SET_CHECKS["duplicate"] and any(
        len(digests) > 1 for held in series.values() for digests in held.values()
    ):
        return SetReport("malformed", ["sequence-duplicate"])
    missing = []
    if SEQUENCE_SET_CHECKS["gap"]:
        for boundary in sorted(series):
            held = series[boundary]
            missing += [
                {"boundary": boundary, "seq": n} for n in range(1, max(held)) if n not in held
            ]
    return SetReport("valid", [], missing)


def set_records(raw: bytes) -> list[bytes]:
    """The envelopes a set member carries, each as bytes a verifier is handed."""
    bundle = json.loads(raw, object_pairs_hook=_no_duplicates)
    return [json.dumps(env).encode() for env in bundle["records"]]


def verify_set(
    raw: bytes, policy: Policy, *, disabled: str | None = None
) -> tuple[list[Report], SetReport]:
    """Judge a set member: every record on its own, then the records together.
    A record that is itself malformed leaves the set unjudged (malformed)."""
    try:
        envelopes = set_records(raw)
    except (Malformed, ValueError, KeyError, TypeError):
        return [], SetReport("malformed", ["set-unreadable"])
    reports = [verify(env, policy, disabled=disabled) for env in envelopes]
    if any(r.verdict != "valid" for r in reports):
        return reports, SetReport("malformed", ["set-record-malformed"])
    payloads = [_envelope_payload(env)[1] for env in envelopes]
    predicates = [parse_statement(payload)["predicate"] for payload in payloads]
    joint = consumption_set_findings(predicates, disabled=disabled)
    if joint.verdict != "valid":
        return reports, joint
    return reports, sequence_set_findings(predicates, payloads)


def set_rule_names() -> list[str]:
    return [name for name, _, _ in SET_RULES]


# --------------------------------------------------------------------------
# The corpus judge.
# --------------------------------------------------------------------------


class Judged:
    """One corpus, judged: members with their findings, and corpus findings."""

    def __init__(self) -> None:
        self.members: list[tuple[str, str, list[str]]] = []
        self.findings: list[str] = []
        self.notes: list[str] = []

    def ok(self) -> bool:
        return not self.findings and all(not findings for _, _, findings in self.members)

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for _, kind, _ in self.members:
            counts[kind] = counts.get(kind, 0) + 1
        return counts


def policy_for(manifest: dict[str, Any]) -> Policy:
    key = str(manifest.get("keys", {}).get("observer", {}).get("publicKey", ""))
    return Policy(str(manifest.get("predicateType", "")), key)


def _declared_findings(entry: dict[str, Any], report: Report) -> list[str]:
    label = f"{entry.get('draftId')} {entry.get('slug')}"
    expected = entry.get("expected") or {}
    if report.verdict != expected.get("verdict"):
        return [f"{label}: expected {expected.get('verdict')}, got {report.verdict} {report.codes}"]
    codes = expected.get("codes") or []
    if report.codes != codes:
        return [f"{label}: expected codes {codes}, got {report.codes}"]
    if report.verdict == "valid" and expected.get("derivedTier") != report.derived_tier:
        declared = expected.get("derivedTier")
        return [f"{label}: expected derivedTier {declared!r}, got {report.derived_tier!r}"]
    return []


def _limit_findings(entry: dict[str, Any], raw: bytes) -> list[str]:
    """A member whose record carries consumption declares the withinLimit a
    verifier derives; a member that carries none declares none."""
    label = f"{entry.get('draftId')} {entry.get('slug')}"
    expected = entry.get("expected") or {}
    try:
        pred = json.loads(_envelope_payload(raw)[1])["predicate"]
        got = within_limit(pred)
    except (Malformed, KeyError, TypeError, ValueError):
        return [] if "withinLimit" not in expected else [f"{label}: withinLimit cannot be derived"]
    if got != expected.get("withinLimit"):
        return [f"{label}: expected withinLimit {expected.get('withinLimit')}, got {got}"]
    return []


def _set_findings(entry: dict[str, Any], raw: bytes, policy: Policy) -> list[str]:
    """A set member: each record reaches the member's verdict, tier and
    withinLimit, and the records together reach expected.set."""
    label = f"{entry.get('draftId')} {entry.get('slug')}"
    expected = entry["expected"]
    declared = expected["set"]
    reports, joint = verify_set(raw, policy)
    findings: list[str] = []
    for index, report in enumerate(reports):
        for found in _declared_findings(entry, report):
            findings.append(f"record {index + 1}: {found}")
    limits = []
    for env in set_records(raw):
        limits.append(within_limit(json.loads(_envelope_payload(env)[1])["predicate"]))
    if limits != declared.get("withinLimit", [None] * len(limits)):
        findings.append(
            f"{label}: expected withinLimit {declared.get('withinLimit')}, got {limits}"
        )
    if joint.missing != declared.get("missing", []):
        findings.append(
            f"{label}: expected missing {declared.get('missing', [])}, got {joint.missing}"
        )
    if (joint.verdict, joint.codes) != (declared["verdict"], declared["codes"]):
        findings.append(
            f"{label}: expected set {declared['verdict']} {declared['codes']}, "
            f"got {joint.verdict} {joint.codes}"
        )
    return findings


def conforming_verdicts(entry: dict[str, Any]) -> set[str]:
    """Every verdict a conforming verifier may reach on one manifest entry.

    An accept or reject member has one: ``expected.verdict``. An indeterminate
    member is a row the draft leaves open, and it has every verdict its
    ``readings`` list; it carries no ``expected.verdict``, because any single
    value there would score a listed reading as wrong. Score a second
    implementation with this, not with ``expected.verdict``.
    """
    if entry.get("kind") == "indeterminate":
        return {str(reading.get("verdict")) for reading in entry.get("readings") or []}
    return {str((entry.get("expected") or {}).get("verdict"))}


def _indeterminate_findings(entry: dict[str, Any], report: Report) -> list[str]:
    allowed = sorted(conforming_verdicts(entry))
    label = f"{entry.get('draftId')} {entry.get('slug')}"
    if "verdict" in (entry.get("expected") or {}):
        return [
            f"{label}: declared indeterminate and pins expected.verdict beside readings, so "
            "a scorer reading that field marks a listed reading wrong"
        ]
    if len(allowed) < 2:
        return [f"{label}: declared indeterminate and names fewer than two readings"]
    if report.verdict not in allowed:
        return [f"{label}: this rail took {report.verdict!r}, outside the declared set {allowed}"]
    return []


def dating_dict(dated: Dating) -> dict[str, Any]:
    """A dating result in the manifest's expected.dating shape."""
    out: dict[str, Any] = {"entry": dated.entry, "codes": dated.codes}
    if dated.dated_at is not None:
        out["datedAt"] = dated.dated_at
    if dated.receipt is not None:
        out["receipt"] = dated.receipt
    out["delegationRoot"] = dated.delegation_root
    return out


def _dating_findings(entry: dict[str, Any], dated: Dating) -> list[str]:
    declared = (entry.get("expected") or {}).get("dating")
    got = dating_dict(dated)
    if got != declared:
        label = f"{entry.get('draftId')} {entry.get('slug')}"
        return [f"{label}: expected dating {declared}, got {got}"]
    return []


def aggregation_findings(entry: dict[str, Any], raw: bytes) -> list[str]:
    """A member carrying ``aggregation`` lists the values of one input as the
    producer held them; aggregate_values over them must yield the entry the
    record carries, measured to the same decision.reportedAt (FR14)."""
    block = entry.get("aggregation")
    if block is None:
        return []
    label = f"{entry.get('draftId')} {entry.get('slug')}"
    try:
        _, payload = _envelope_payload(raw)
        pred = json.loads(payload)["predicate"]
        want = aggregate_values(block["values"])
    except (Malformed, KeyError, TypeError, ValueError) as exc:
        return [f"{label}: the aggregation block cannot be checked: {exc}"]
    if pred["decision"]["reportedAt"] != block["reportedAt"]:
        return [f"{label}: the aggregation is measured to a reportedAt the record does not carry"]
    held = [e for e in pred["evaluation"]["inputs"] if e.get("input") == block["input"]]
    got = [{"lastResult": e.get("lastResult"), "maxAge": e.get("maxAge")} for e in held]
    if got != [want]:
        return [f"{label}: aggregating the listed values gives {want}, the record carries {got}"]
    return []


def _judge_member(
    directory: str, entry: dict[str, Any], policy: Policy, heads: AnchorTrust
) -> tuple[str, str, list[str]]:
    identifier, kind = str(entry.get("id", "")), str(entry.get("kind", ""))
    try:
        with open(os.path.join(directory, str(entry.get("file", ""))), "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        return identifier, kind, [f"the vector body is unreadable: {exc}"]
    findings: list[str] = []
    recomputed = "v" + hashlib.sha256(raw).hexdigest()[:16]
    if recomputed != identifier:
        findings.append(
            f"file bytes hash to {recomputed} and the manifest calls this member {identifier}"
        )
    expected = entry.get("expected") or {}
    if "dating" in expected:
        report, dated = verify_retained(raw, policy, heads)
        findings.extend(_declared_findings(entry, report))
        findings.extend(_dating_findings(entry, dated))
        return identifier, kind, findings
    if "set" in expected:
        findings.extend(_set_findings(entry, raw, policy))
        return identifier, kind, findings
    report = verify(raw, policy)
    findings.extend(aggregation_findings(entry, raw))
    if kind == "accept":
        findings.extend(_limit_findings(entry, raw))
    if kind in ("accept", "reject"):
        findings.extend(_declared_findings(entry, report))
    elif kind == "indeterminate":
        findings.extend(_indeterminate_findings(entry, report))
    else:
        findings.append(f"kind {kind!r} is not one this rail replays")
    return identifier, kind, findings


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """sha256 over every member's bytes, concatenated in identifier order."""
    digest = hashlib.sha256()
    for entry in sorted(manifest.get("vectors", []), key=lambda e: str(e.get("id"))):
        with open(os.path.join(root, str(entry.get("file", ""))), "rb") as handle:
            digest.update(handle.read())
    return digest.hexdigest()


def _corpus_findings(directory: str, manifest: dict[str, Any]) -> list[str]:
    out: list[str] = []
    entries: list[dict[str, Any]] = manifest.get("vectors") or []
    by_id = {str(e.get("id")): e for e in entries}
    measured: dict[str, int] = {}
    for entry in entries:
        measured[str(entry.get("kind"))] = measured.get(str(entry.get("kind")), 0) + 1
        if entry.get("kind") == "reject":
            parent = by_id.get(str(entry.get("parent")))
            if parent is None or parent.get("kind") != "accept":
                out.append(f"{entry.get('draftId')}: a reject member names no accept parent")
    if manifest.get("counts") != measured:
        out.append(f"counts declare {manifest.get('counts')} and the members are {measured}")
    draft_ids = [str(e.get("draftId")) for e in entries]
    if len(set(draft_ids)) != len(draft_ids):
        out.append("two members carry one Appendix B identifier")
    if manifest.get("emptyTree") != EMPTY_TREE:
        out.append("the manifest's empty-tree constants are not the ones this rail computes")
    try:
        recomputed = corpus_digest(manifest, directory)
    except OSError as exc:
        return out + [f"the corpus digest could not be recomputed: {exc}"]
    if manifest.get("corpusDigest") != recomputed:
        out.append(f"corpusDigest does not recompute ({recomputed[:12]})")
    return out


def judge(directory: str) -> Judged:
    with open(os.path.join(directory, "MANIFEST.json"), encoding="utf-8") as handle:
        manifest = json.load(handle)
    judged = Judged()
    entries: list[dict[str, Any]] = manifest.get("vectors") or []
    if not entries:
        judged.findings.append("the manifest carries no vectors, so this run measured nothing")
        return judged
    policy = policy_for(manifest)
    heads = tree_heads(manifest)
    for entry in entries:
        judged.members.append(_judge_member(directory, entry, policy, heads))
    judged.findings.extend(_corpus_findings(directory, manifest))
    return judged


def render(judged: Judged, suite: str) -> str:
    lines = [f"suite: {suite}", f"members: {len(judged.members)}"]
    counts = judged.counts()
    for kind in sorted(counts):
        lines.append(f"  {kind}: {counts[kind]}")
    failed = 0
    for member_id, _, findings in judged.members:
        if findings:
            failed += 1
            lines.extend(f"FAIL {member_id}: {finding}" for finding in findings)
    lines.extend(f"FAIL corpus: {finding}" for finding in judged.findings)
    lines.extend(f"note: {note}" for note in judged.notes)
    if judged.ok():
        lines.append("verdict: every member behaves as MANIFEST.json declares")
    else:
        lines.append(
            f"verdict: {failed} member(s) and {len(judged.findings)} "
            "corpus-level claim(s) do not hold"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="auditrecord",
        description="judge vectors-agent-audit-record/ with the reference reader for "
        "draft-gilda-audit-agent-audit-record-00 and the five rows of revision 01 "
        "(TI6, V4, V5, FR14, FR15)",
    )
    parser.add_argument("directory", help="a corpus directory carrying MANIFEST.json")
    args = parser.parse_args(argv)
    judged = judge(args.directory)
    sys.stdout.write(render(judged, SUITE))
    return 0 if judged.ok() else 1


if __name__ == "__main__":
    raise SystemExit(main())
