"""Judge whether an execution is bound to a quorum of approvals of exactly its bytes.

A tool call that pauses for approval and then runs is safe only if the run is
bound to the approvals, and the approvals to the people and the bytes. Every
denied record below carries approvals that a verifier matching approvals to a
call by the call's identifier would accept. The arguments can be swapped under
the same call identifier in a resubmitted history. A resume field can replace
them after the approver saw them. A validator can rewrite them between display
and execution. The same approval can be sent twice. The approver can be named
only in the request body, can be the proposer, can be counted twice toward the
quorum, or can enter the policy through a delegation that removed somebody. A
late approval can revive a call whose approval window had closed. The approval
can be spent after the call was already dispatched, by a party that is not the
authority, without the witness seeing it. And an approval spent on an effect
that never landed can be recorded as done.

The record has four parties. The proposer is the principal whose model proposed
the call. The approvers decide on the bytes the proposal showed them. The
authority consumes approvals and dispatches the call; its key is
``policy.authorityKeyId``. The witness log is kept apart from the authority and
records each consumption.

* ``proposal``: ``proposalId``, ``proposer``, ``toolCallId``, ``tool``,
  ``argsShown`` (the arguments the approvers were shown), ``modelResponse``
  (the model response that proposed the call), ``historyDigest`` (a claim:
  the digest of ``modelResponse``) and ``proposedAt``.
* ``policy``: ``quorum``, ``approvers``, ``approverKeys`` (principal to key
  id), ``delegations`` (each ``delegationId``, ``issuer``, ``add``, ``remove``
  and ``quorum``, which is null or an integer), ``timeoutSeconds``,
  ``rejectVetoes``, ``separationOfDuties.conflicts`` (pairs of principals that
  may not both count toward one quorum) and ``authorityKeyId``.
* ``approvals``: every decision received for the proposal. Each carries
  ``approvalId``, ``proposalId``, ``toolCallId``, ``tool``,
  ``approverClaimed`` (the principal the request body names),
  ``authenticatedPrincipal`` (the principal the authentication context
  established; absent or null when there was none), ``keyId``, ``decision``
  (``approve`` or ``reject``), ``argsDigest``, ``historyDigest``, ``issuedAt``
  and ``expiresAt``.
* ``execution``: ``executionId``, ``toolCallId``, ``tool``, ``historyDigest``
  (of the history the call ran from), ``argsExecuted``, ``transforms`` (each
  ``kind`` of ``override_args``, ``editedArgs``, ``after_tool_validate`` or
  ``none``, with ``beforeDigest`` and ``afterDigest``), ``approvalIds`` (the
  approvals the execution relies on), ``consumedBy``, ``consumedAt``,
  ``dispatchedAt``, ``outcome`` (``applied``, ``failed`` or ``uncertain``) and
  ``approvalStatus`` (``spent``, ``returned`` or ``held``).
* ``ledger``: the authority's consumption ledger as it read it before this
  execution, one entry per earlier consumption (``approvalId``,
  ``toolCallId``, ``executionId``, ``consumedAt``). An empty list means the
  ledger was read and held nothing; an absent member means it was never read.
* ``witness``: the witness log, entries ``seq`` (gapless from 1), ``kind``,
  ``digest`` and ``at``. The consumption of an approval is the entry of kind
  ``approval`` whose digest is the digest of ``{approvalId, consumedAt,
  consumedBy, executionId}``.

A digest is ``sha256:`` and the lowercase hex SHA-256 of the object's JCS
bytes. Every digest the reader relies on is recomputed: a digest member is a
claim to check, never a value to trust.

An approval ``counts`` for the seat of its principal: an approver named in
``policy.approvers`` holds a seat, and a principal a valid delegation adds
stands in for the seat of the delegation's issuer. Two approvals for one seat
count once. The checks below that read approvals read the approvals the
execution relies on, except the veto, which reads every decision received.

The reader checks in a fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the approval-binding v2 contract (``contract_id_unknown``);
3. the record has the fields and types the contract names, every time parses,
   every number is an integer, the witness sequence is gapless and every
   approval the execution relies on is presented (``malformed_record``);
4. the consumption ledger was read: an absent ledger is not an empty one
   (``consumption_not_checked``);
5. every delegation only adds approvers: it removes nobody, lowers no quorum,
   and is issued by an approver the policy names (``approver_delegation_widened``);
6. each relied approval names this proposal, call and tool, the execution runs
   this call and tool, and the model response holds the call
   (``approval_not_for_call``);
7. each relied approval has an authenticated principal; a principal named only
   in the request body is not authenticated (``approver_unauthenticated``);
8. the body's claimed approver is the authenticated principal
   (``approver_claim_mismatch``);
9. the approval's key is the key the policy binds to that principal
   (``approver_key_not_bound``);
10. the principal is an approver or was added by a valid delegation
    (``approver_ineligible``);
11. no relied approval's seat is the proposer's, directly or through a
    delegate (``approver_is_proposer``);
12. no seat is counted more than once, whether by two approvals, one approval
    cited twice, or a delegate and its delegator (``approver_counted_twice``);
13. no two counted seats are a conflicting pair (``approvers_conflicted``);
14. every relied approval's decision is ``approve`` (``approval_not_granted``);
15. when the policy says a reject vetoes, no authenticated, eligible reject
    for this proposal was issued at or before consumption
    (``approval_vetoed``);
16. the relied approvals reach the quorum, the larger of the policy's and any
    delegation's (``quorum_not_met``);
17. each relied approval's ``argsDigest`` is the digest of ``argsShown``
    (``approval_not_for_bytes``);
18. the digest of ``argsExecuted`` is the approved digest, whatever changed
    the arguments (``args_changed_after_approval``);
19. the transforms account for the executed bytes: they chain from the digest
    of ``argsShown`` to the digest of ``argsExecuted``, and a ``none`` changes
    nothing (``transforms_unaccounted``);
20. the proposal's ``historyDigest`` is the digest of ``modelResponse``, and
    every relied approval and the execution carry it
    (``history_digest_mismatch``);
21. the call was dispatched before every relied approval's ``expiresAt``
    (``approval_expired``);
22. no relied approval was issued after it was consumed
    (``approval_postdates_consumption``);
23. the quorum was reached before ``proposedAt + timeoutSeconds``; a call
    whose window closed stays refused (``timeout_not_fail_closed``);
24. no relied approval is in the ledger (``approval_replayed``);
25. the call is not in the ledger (``call_already_executed``);
26. the authority consumed the approvals (``consumption_not_by_authority``);
27. the witness holds each relied approval's consumption
    (``consumption_not_witnessed``);
28. the approvals were consumed, and the witness saw it, at or before dispatch
    (``consumed_after_dispatch``);
29. the approval status follows the outcome: ``applied`` spends the approvals,
    ``failed`` returns them, ``uncertain`` holds them (``outcome_misrecorded``).

A record that passes all of them is ``allow`` with reason ``quorum_bound``.

The external-verifier contract: ``<verifier> <case-dir>/record.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``allow`` and 1 for ``deny``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shlex
import subprocess
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

SUITE = "approval-binding/v2"
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/contract/approval-binding/v2"
ALLOW, DENY = "allow", "deny"
ALLOW_REASON = "quorum_bound"
EXIT_FOR = {ALLOW: 0, DENY: 1}
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "malformed_record",
    "consumption_not_checked",
    "approver_delegation_widened",
    "approval_not_for_call",
    "approver_unauthenticated",
    "approver_claim_mismatch",
    "approver_key_not_bound",
    "approver_ineligible",
    "approver_is_proposer",
    "approver_counted_twice",
    "approvers_conflicted",
    "approval_not_granted",
    "approval_vetoed",
    "quorum_not_met",
    "approval_not_for_bytes",
    "args_changed_after_approval",
    "transforms_unaccounted",
    "history_digest_mismatch",
    "approval_expired",
    "approval_postdates_consumption",
    "timeout_not_fail_closed",
    "approval_replayed",
    "call_already_executed",
    "consumption_not_by_authority",
    "consumption_not_witnessed",
    "consumed_after_dispatch",
    "outcome_misrecorded",
)
TRANSFORM_KINDS = ("override_args", "editedArgs", "after_tool_validate", "none")
STATUS_FOR_OUTCOME = {"applied": "spent", "failed": "returned", "uncertain": "held"}
WITNESS_KINDS = ("grant", "permit", "effect", "srl", "approval")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-approval-binding-v2" if
        (_HERE / "corpora").exists()
        else _HERE.parents[1] / "corpora" / "vectors-approval-binding-v2")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def digest(value: object) -> str:
    """``sha256:`` and the hex SHA-256 of the value's JCS bytes (integers and strings)."""
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + _sha(data.encode("utf-8"))


def consumption_statement(approval_id: str, execution: dict[str, Any]) -> dict[str, Any]:
    """The statement whose digest the witness records for one consumption."""
    return {"approvalId": approval_id, "consumedAt": execution["consumedAt"],
            "consumedBy": execution["consumedBy"], "executionId": execution["executionId"]}


def _when(value: Any) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{value!r} is not an RFC 3339 UTC instant")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


# Structural check ----------------------------------------------------------------


def _has_float(value: Any) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, dict):
        return any(_has_float(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_float(v) for v in value)
    return False


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _int(value: Any, floor: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= floor


def _texts(value: Any, nonempty: bool = False) -> bool:
    return (isinstance(value, list) and (bool(value) or not nonempty)
            and all(_text(v) for v in value))


def _fields(obj: Any, texts: tuple[str, ...]) -> bool:
    return isinstance(obj, dict) and all(_text(obj.get(name)) for name in texts)


def _digest_ok(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.match(value) is not None


def _proposal_ok(p: Any) -> bool:
    if not _fields(p, ("proposalId", "proposer", "toolCallId", "tool")):
        return False
    response = p.get("modelResponse")
    calls = response.get("toolCalls") if isinstance(response, dict) else None
    return (isinstance(p.get("argsShown"), dict) and isinstance(calls, list)
            and all(_fields(c, ("toolCallId", "tool")) and isinstance(c.get("args"), dict)
                    for c in calls)
            and _digest_ok(p.get("historyDigest")) and _text(p.get("proposedAt")))


def _delegation_ok(d: Any) -> bool:
    return (_fields(d, ("delegationId", "issuer")) and _texts(d.get("add"))
            and _texts(d.get("remove"))
            and (d.get("quorum") is None or _int(d.get("quorum"), 1)))


def _policy_ok(p: Any) -> bool:
    if not isinstance(p, dict):
        return False
    keys = p.get("approverKeys")
    sod = p.get("separationOfDuties")
    conflicts = sod.get("conflicts") if isinstance(sod, dict) else None
    return (_int(p.get("quorum"), 1) and _texts(p.get("approvers"), nonempty=True)
            and isinstance(keys, dict) and all(_text(v) for v in keys.values())
            and isinstance(p.get("delegations"), list)
            and all(_delegation_ok(d) for d in p["delegations"])
            and _int(p.get("timeoutSeconds"), 1) and isinstance(p.get("rejectVetoes"), bool)
            and isinstance(conflicts, list)
            and all(_texts(pair) and len(pair) == 2 for pair in conflicts)
            and _text(p.get("authorityKeyId")))


def _approval_ok(a: Any) -> bool:
    names = ("approvalId", "proposalId", "toolCallId", "tool", "approverClaimed", "keyId",
             "issuedAt", "expiresAt")
    if not _fields(a, names):
        return False
    principal = a.get("authenticatedPrincipal")
    return ((principal is None or _text(principal))
            and a.get("decision") in ("approve", "reject")
            and _digest_ok(a.get("argsDigest")) and _digest_ok(a.get("historyDigest")))


def _execution_ok(e: Any) -> bool:
    names = ("executionId", "toolCallId", "tool", "consumedBy", "consumedAt", "dispatchedAt")
    if not _fields(e, names):
        return False
    transforms = e.get("transforms")
    return (_digest_ok(e.get("historyDigest")) and isinstance(e.get("argsExecuted"), dict)
            and isinstance(transforms, list)
            and all(isinstance(t, dict) and t.get("kind") in TRANSFORM_KINDS
                    and _digest_ok(t.get("beforeDigest")) and _digest_ok(t.get("afterDigest"))
                    for t in transforms)
            and _texts(e.get("approvalIds"))
            and e.get("outcome") in STATUS_FOR_OUTCOME
            and e.get("approvalStatus") in STATUS_FOR_OUTCOME.values())


def _ledger_ok(ledger: Any) -> bool:
    return isinstance(ledger, list) and all(
        _fields(x, ("approvalId", "toolCallId", "executionId", "consumedAt")) for x in ledger)


def _witness_ok(witness: Any) -> bool:
    if not isinstance(witness, list):
        return False
    for index, entry in enumerate(witness, start=1):
        if not (isinstance(entry, dict) and _int(entry.get("seq"), 1)
                and entry["seq"] == index and entry.get("kind") in WITNESS_KINDS
                and _digest_ok(entry.get("digest")) and _text(entry.get("at"))):
            return False
    return True


def _times(record: dict[str, Any]) -> list[Any]:
    execution = record["execution"]
    out: list[Any] = [record["proposal"]["proposedAt"], execution["consumedAt"],
                      execution["dispatchedAt"]]
    for approval in record["approvals"]:
        out += [approval["issuedAt"], approval["expiresAt"]]
    out += [entry["consumedAt"] for entry in record.get("ledger") or []]
    out += [entry["at"] for entry in record.get("witness") or []]
    return out


def _malformed(record: dict[str, Any]) -> bool:
    shape = (
        not _has_float(record)
        and _proposal_ok(record.get("proposal")) and _policy_ok(record.get("policy"))
        and isinstance(record.get("approvals"), list)
        and all(_approval_ok(a) for a in record["approvals"])
        and _execution_ok(record.get("execution"))
        and ("ledger" not in record or _ledger_ok(record["ledger"]))
        and ("witness" not in record or _witness_ok(record["witness"]))
    )
    if not shape:
        return True
    presented = {a["approvalId"] for a in record["approvals"]}
    if len(presented) != len(record["approvals"]):
        return True
    if not set(record["execution"]["approvalIds"]) <= presented:
        return True
    try:
        for value in _times(record):
            _when(value)
    except ValueError:
        return True
    return False


# The parsed view the later checks read --------------------------------------------


class _View:
    """The record's relations, read once ``malformed_record`` has passed."""

    def __init__(self, record: dict[str, Any], skip: frozenset[str]) -> None:
        self.record = record
        self.skip = skip
        self.proposal: dict[str, Any] = record["proposal"]
        self.policy: dict[str, Any] = record["policy"]
        self.execution: dict[str, Any] = record["execution"]
        by_id = {a["approvalId"]: a for a in record["approvals"]}
        self.relied: list[dict[str, Any]] = [by_id[i] for i in self.execution["approvalIds"]]
        self.history = digest(self.proposal["modelResponse"])
        self.shown = digest(self.proposal["argsShown"])

    def principal(self, approval: dict[str, Any]) -> str:
        """The authenticated principal, or the body's claim when none was established.

        The fallback is read only when ``approver_unauthenticated`` is switched
        off, so a test can prove that check is the only thing refusing the case.
        """
        authenticated = approval.get("authenticatedPrincipal")
        return str(authenticated if authenticated is not None else approval["approverClaimed"])

    def valid_delegations(self) -> list[dict[str, Any]]:
        return [d for d in self.policy["delegations"] if not _widens(self.policy, d)]

    def seat(self, principal: str) -> str | None:
        """The seat a principal's approval counts for, or None when it holds none."""
        if principal in self.policy["approvers"]:
            return principal
        for delegation in self.valid_delegations():
            if principal in delegation["add"]:
                return str(delegation["issuer"])
        return None

    def counted_seat(self, approval: dict[str, Any]) -> str:
        principal = self.principal(approval)
        return self.seat(principal) or principal

    def quorum(self) -> int:
        raised = [d["quorum"] for d in self.valid_delegations() if d["quorum"] is not None]
        return max([int(self.policy["quorum"]), *raised])


def _widens(policy: dict[str, Any], delegation: dict[str, Any]) -> bool:
    lowered = delegation["quorum"] is not None and delegation["quorum"] < policy["quorum"]
    return bool(delegation["remove"]) or lowered or delegation["issuer"] not in policy["approvers"]


def _not_for_call(v: _View) -> bool:
    p, e = v.proposal, v.execution
    call = (p["proposalId"], p["toolCallId"], p["tool"])
    if any((a["proposalId"], a["toolCallId"], a["tool"]) != call for a in v.relied):
        return True
    if (e["toolCallId"], e["tool"]) != (p["toolCallId"], p["tool"]):
        return True
    return not any((c["toolCallId"], c["tool"]) == (p["toolCallId"], p["tool"])
                   for c in p["modelResponse"]["toolCalls"])


def _claim_mismatch(v: _View) -> bool:
    return any(a.get("authenticatedPrincipal") is not None
               and a["approverClaimed"] != a["authenticatedPrincipal"] for a in v.relied)


def _key_not_bound(v: _View) -> bool:
    keys = v.policy["approverKeys"]
    return any(keys.get(v.principal(a)) != a["keyId"] for a in v.relied)


def _counted_twice(v: _View) -> bool:
    seats = [v.counted_seat(a) for a in v.relied]
    return len(set(seats)) != len(seats)


def _conflicted(v: _View) -> bool:
    seats = {v.counted_seat(a) for a in v.relied}
    return any(set(pair) <= seats for pair in v.policy["separationOfDuties"]["conflicts"])


def _vetoed(v: _View) -> bool:
    if not v.policy["rejectVetoes"]:
        return False
    consumed = _when(v.execution["consumedAt"])
    keys = v.policy["approverKeys"]
    for a in v.record["approvals"]:
        principal = a.get("authenticatedPrincipal")
        if (a["decision"] == "reject" and principal is not None
                and a["approverClaimed"] == principal and keys.get(principal) == a["keyId"]
                and v.seat(principal) is not None
                and a["proposalId"] == v.proposal["proposalId"]
                and _when(a["issuedAt"]) <= consumed):
            return True
    return False


def _transforms_unaccounted(v: _View) -> bool:
    current = v.shown
    for transform in v.execution["transforms"]:
        if transform["beforeDigest"] != current:
            return True
        if transform["kind"] == "none" and transform["afterDigest"] != transform["beforeDigest"]:
            return True
        current = transform["afterDigest"]
    return current != digest(v.execution["argsExecuted"])


def _history_mismatch(v: _View) -> bool:
    claims = [v.proposal["historyDigest"], v.execution["historyDigest"],
              *(a["historyDigest"] for a in v.relied)]
    return any(claim != v.history for claim in claims)


def _timed_out(v: _View) -> bool:
    issued = sorted(_when(a["issuedAt"]) for a in v.relied)
    needed = v.quorum()
    if len(issued) < needed:
        return False
    closes = _when(v.proposal["proposedAt"]) + timedelta(seconds=v.policy["timeoutSeconds"])
    return issued[needed - 1] >= closes


def _ledger(v: _View) -> list[dict[str, Any]]:
    return list(v.record.get("ledger") or [])


def _not_witnessed(v: _View) -> bool:
    witness = v.record.get("witness")
    if witness is None:
        return True
    seen = {e["digest"] for e in witness if e["kind"] == "approval"}
    return any(digest(consumption_statement(a["approvalId"], v.execution)) not in seen
               for a in v.relied)


def _after_dispatch(v: _View) -> bool:
    dispatched = _when(v.execution["dispatchedAt"])
    if _when(v.execution["consumedAt"]) > dispatched:
        return True
    wanted = {digest(consumption_statement(a["approvalId"], v.execution)) for a in v.relied}
    return any(e["kind"] == "approval" and e["digest"] in wanted and _when(e["at"]) > dispatched
               for e in v.record.get("witness") or [])


def _checks(record: dict[str, Any], skip: frozenset[str]) -> dict[str, Callable[[], bool]]:
    view: list[_View] = []

    def v() -> _View:
        if not view:
            view.append(_View(record, skip))
        return view[0]

    return {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "malformed_record": lambda: _malformed(record),
        "consumption_not_checked": lambda: "ledger" not in record,
        "approver_delegation_widened": lambda: any(
            _widens(v().policy, d) for d in v().policy["delegations"]),
        "approval_not_for_call": lambda: _not_for_call(v()),
        "approver_unauthenticated": lambda: any(
            a.get("authenticatedPrincipal") is None for a in v().relied),
        "approver_claim_mismatch": lambda: _claim_mismatch(v()),
        "approver_key_not_bound": lambda: _key_not_bound(v()),
        "approver_ineligible": lambda: any(
            v().seat(v().principal(a)) is None for a in v().relied),
        "approver_is_proposer": lambda: any(
            v().counted_seat(a) == v().proposal["proposer"]
            or v().principal(a) == v().proposal["proposer"] for a in v().relied),
        "approver_counted_twice": lambda: _counted_twice(v()),
        "approvers_conflicted": lambda: _conflicted(v()),
        "approval_not_granted": lambda: any(a["decision"] != "approve" for a in v().relied),
        "approval_vetoed": lambda: _vetoed(v()),
        "quorum_not_met": lambda: len(v().relied) < v().quorum(),
        "approval_not_for_bytes": lambda: any(a["argsDigest"] != v().shown for a in v().relied),
        "args_changed_after_approval": lambda: any(
            a["argsDigest"] != digest(v().execution["argsExecuted"]) for a in v().relied),
        "transforms_unaccounted": lambda: _transforms_unaccounted(v()),
        "history_digest_mismatch": lambda: _history_mismatch(v()),
        "approval_expired": lambda: any(
            _when(v().execution["dispatchedAt"]) >= _when(a["expiresAt"]) for a in v().relied),
        "approval_postdates_consumption": lambda: any(
            _when(a["issuedAt"]) > _when(v().execution["consumedAt"]) for a in v().relied),
        "timeout_not_fail_closed": lambda: _timed_out(v()),
        "approval_replayed": lambda: bool(
            {x["approvalId"] for x in _ledger(v())} & {a["approvalId"] for a in v().relied}),
        "call_already_executed": lambda: any(
            x["toolCallId"] == v().execution["toolCallId"] for x in _ledger(v())),
        "consumption_not_by_authority": lambda: (
            v().execution["consumedBy"] != v().policy["authorityKeyId"]),
        "consumption_not_witnessed": lambda: _not_witnessed(v()),
        "consumed_after_dispatch": lambda: _after_dispatch(v()),
        "outcome_misrecorded": lambda: (
            STATUS_FOR_OUTCOME[v().execution["outcome"]] != v().execution["approvalStatus"]),
    }


def _load(record_path: Path) -> dict[str, Any]:
    record: dict[str, Any] = json.loads(record_path.read_text(encoding="utf-8"))
    return record


def _first_failure(record: dict[str, Any], skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it. The checks after
    ``malformed_record`` read a record only once it has passed, so a skipped
    ``malformed_record`` lets a malformed record fail in them.
    """
    if not isinstance(record, dict):
        return "malformed_record"
    failures = _checks(record, skip)
    for name in CHECKS:
        if name in skip:
            continue
        try:
            if failures[name]():
                return name
        except (KeyError, TypeError, ValueError, IndexError, AttributeError):
            return "unreadable_record" if "malformed_record" in skip else "malformed_record"
    return None


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record."""
    failure = _first_failure(_load(record_path), skip)
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    return {"decision": ALLOW, "reason": ALLOW_REASON}


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(_sha((directory / name).read_bytes()) != value for name, value in files.items()):
        return "fixture digest mismatch"
    return None


def _validated_entries(root: Path) -> tuple[list[dict[str, Any]], str | None]:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    if _sha(_json(entries)) != manifest["corpusDigest"]:
        return [], "manifest digest mismatch"
    if manifest.get("suite") != SUITE:
        return [], "unexpected suite"
    if not entries or len({entry["id"] for entry in entries}) != len(entries):
        return [], "empty or duplicate vector identifiers"
    if any(entry.get("path") != f"cases/{entry['id']}" for entry in entries):
        return [], "case path does not match identifier"
    actual_dirs = {p.name for p in (root / "cases").iterdir() if p.is_dir()}
    if actual_dirs != {entry["id"] for entry in entries}:
        return [], "case directories do not match manifest"
    return entries, None


def _external_answer(command: list[str], path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run([*command, str(path), "--json"], capture_output=True,
                                text=True, timeout=90, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = json.loads(result.stdout)
        observed = {key: answer[key] for key in ("decision", "reason")}
    except (ValueError, KeyError, TypeError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every record, through the named verifier or the reference reader.

    Returns the number of records answered and every disagreement.
    """
    try:
        entries, manifest_error = _validated_entries(root)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    if manifest_error:
        return 0, [manifest_error]
    command = shlex.split(verifier) if isinstance(verifier, str) else verifier
    if command is not None and not command:
        return 0, ["verifier command is empty"]
    errors: list[str] = []
    answered = 0
    for entry in entries:
        name, directory = entry["id"], root / entry["path"]
        fixture_error = _fixture_error(directory, entry)
        if fixture_error:
            errors.append(f"{name}: {fixture_error}")
            continue
        record_path = directory / "record.json"
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(record_path, skip)
        else:
            ran, observed = _external_answer(command, record_path)
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    directory = Path(root)
    answered, errors = check(verifier, directory)
    try:
        manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
        total = len(manifest["vectors"])
    except (OSError, ValueError, KeyError, TypeError):
        manifest, total = {}, 0
    for error in errors:
        print(error)
    rail = "reference reader" if verifier is None else shlex.join(verifier)
    print(f"{SUITE}: {rail} answered {answered} of {total} cases, {len(errors)} disagreements")
    if not answered or not total:
        print("no report written: no case was answered")
        return 2
    report = {
        "suite": SUITE, "rail": "own-reader" if verifier is None else "external",
        "verifier": {"command": verifier, "vectorsExecuted": answered, "note": rail_note},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {"vectors": total, "conform": total - len(errors), "fail": len(errors),
                   "suiteRefusals": 0},
        "failures": errors,
    }
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    return 1 if errors or answered != total else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("record", nargs="?",
                        help="judge one record.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every record through this verifier instead")
    args = parser.parse_args(argv)
    if args.record:
        answer = verify(Path(args.record))
        print(json.dumps(answer, sort_keys=True) if args.json else
              f"{answer['decision']} {answer['reason']}")
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
