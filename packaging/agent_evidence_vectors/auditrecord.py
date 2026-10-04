"""The agent audit record, and the corpus that holds its conformance set.

The record format is defined by the Internet-Draft
``draft-gilda-wimse-agent-audit-record-02``: one in-toto Statement in a DSSE
envelope, sixteen predicate members carrying the seven minimum audit fields of
Section 11 of ``draft-ietf-wimse-aims``, and the recomputes that make those
fields checkable. Appendix B of the draft lists the conformance corpus, and
``vectors-agent-audit-record/`` publishes it member for member: each manifest
entry carries the Appendix B identifier in ``draftId``.

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
import datetime
import hashlib
import importlib
import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
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
        {"wimse-wpt", "http-message-signature", "mtls", "oauth-access-token", "none"}
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

#: What a decision that could not be evaluated names as missing: the standing
#: source, the key source and the consumption state.
UNAVAILABLE_INPUTS = frozenset({"standing-source", "key-source", "consumption-state"})
#: The only members an oversight object may carry.
OVERSIGHT_MEMBERS = frozenset({"act", "recordDigest"})

#: The sixteen predicate members, and the members each object member requires.
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
    "evaluation": ("status",),
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
    coverage = pred["observation"]["coverage"]
    gaps_inside = any(any(_under(g, s) for s in scope) for g in coverage["gaps"])
    if coverage["scopeComplete"] is not True and gaps_inside:
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


def _rule_evaluation(state: _State) -> None:
    """Evaluated names no unavailable input; not-evaluated names one or more, once each."""
    evaluation = state.predicate["evaluation"]
    if evaluation["status"] == "evaluated":
        if "unavailableInput" in evaluation:
            raise Malformed("evaluation-inconsistent")
        return
    inputs = evaluation.get("unavailableInput")
    if not isinstance(inputs, list) or not inputs:
        raise Malformed("evaluation-inconsistent")
    for value in inputs:
        if value not in UNAVAILABLE_INPUTS:
            raise Malformed("value-outside-vocabulary")
    if len(set(inputs)) != len(inputs):
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


def _judge_member(
    directory: str, entry: dict[str, Any], policy: Policy
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
    report = verify(raw, policy)
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
    for entry in entries:
        judged.members.append(_judge_member(directory, entry, policy))
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
        "draft-gilda-wimse-agent-audit-record",
    )
    parser.add_argument("directory", help="a corpus directory carrying MANIFEST.json")
    args = parser.parse_args(argv)
    judged = judge(args.directory)
    sys.stdout.write(render(judged, SUITE))
    return 0 if judged.ok() else 1


if __name__ == "__main__":
    raise SystemExit(main())
