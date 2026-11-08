"""Build the approval-binding v2 cases byte-identically.

Every case is one record of a proposed tool call, the policy that governs its
approval, every decision received for it, the execution that relied on some of
them, the consumption ledger the authority read, and the witness log. Each
denied case departs from a conformant record in one place, except where the
attack it reproduces changes two things at once; those are named in the tests.
Every digest a case does not deliberately falsify is computed from the record's
own objects. The public wording the cases follow is in README.md.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import approvalbindingv2 as reader  # noqa: E402

SUITE = reader.SUITE
AUTO = "<computed>"
PROPOSED = "2026-11-08T10:00:00Z"
CONSUMED = "2026-11-08T10:05:00Z"
DISPATCHED = "2026-11-08T10:05:01Z"
EXPIRES = "2026-11-08T11:00:00Z"
PROPOSER = "agent:planner"
ALICE, BOB, CAROL, DAVE = "user:alice", "user:bob", "user:carol", "user:dave"
AUTHORITY = "key:authority-1"
CALL, TOOL, PROPOSAL = "call-7f3a", "payments.refund", "proposal-1"
ARGS = {"account": "acct-alice", "amountCents": 2000, "reason": "duplicate charge"}
SWAPPED = {"account": "acct-mallory-offshore", "amountCents": 499900,
           "reason": "duplicate charge"}
VALIDATED = {"account": "acct-alice", "amountCents": 2000, "reason": "duplicate charge",
             "currency": "USD"}
EARLIER = {"approvalId": "approval-0001", "consumedAt": "2026-11-08T09:00:00Z",
           "executionId": "execution-0001", "toolCallId": "call-0001"}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def at(base: str, seconds: int) -> str:
    """An RFC 3339 instant ``seconds`` after ``base``."""
    return (reader._when(base) + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def response(args: dict[str, Any] = ARGS, response_id: str = "response-1") -> dict[str, Any]:
    """The model response that proposed the call."""
    return {"model": "model-a", "responseId": response_id,
            "toolCalls": [{"args": args, "tool": TOOL, "toolCallId": CALL}]}


def approval(approval_id: str, principal: str | None, *, claimed: str | None = None,
             key: str | None = None, decision: str = "approve",
             issued: str = "2026-11-08T10:01:00Z",
             expires: str = EXPIRES, args_digest: str = AUTO,
             history_digest: str = AUTO) -> dict[str, Any]:
    """One decision; ``principal`` None leaves the authentication member absent."""
    name = claimed or principal or ""
    body: dict[str, Any] = {
        "approvalId": approval_id, "approverClaimed": name, "argsDigest": args_digest,
        "decision": decision, "expiresAt": expires, "historyDigest": history_digest,
        "issuedAt": issued, "keyId": key or "key:" + name.split(":", 1)[1],
        "proposalId": PROPOSAL, "tool": TOOL, "toolCallId": CALL,
    }
    if principal is not None:
        body["authenticatedPrincipal"] = principal
    return body


def delegation(issuer: str, add: list[str], remove: list[str] | None = None,
               quorum: int | None = None, name: str = "delegation-1") -> dict[str, Any]:
    return {"add": add, "delegationId": name, "issuer": issuer, "quorum": quorum,
            "remove": remove or []}


def transform(kind: str, before: object, after: object) -> dict[str, Any]:
    return {"afterDigest": reader.digest(after), "beforeDigest": reader.digest(before),
            "kind": kind}


A1 = approval("approval-1", ALICE)
A2 = approval("approval-2", BOB, issued="2026-11-08T10:02:00Z")


def base() -> dict[str, Any]:
    """The conformant record: two of three distinct approvers, consumed, witnessed."""
    return {
        "approvals": [copy.deepcopy(A1), copy.deepcopy(A2)],
        "contractId": reader.CONTRACT_ID,
        "execution": {
            "approvalIds": ["approval-1", "approval-2"], "approvalStatus": "spent",
            "argsExecuted": dict(ARGS), "consumedAt": CONSUMED, "consumedBy": AUTHORITY,
            "dispatchedAt": DISPATCHED, "executionId": "execution-2", "historyDigest": AUTO,
            "outcome": "applied", "tool": TOOL, "toolCallId": CALL, "transforms": [],
        },
        "ledger": [dict(EARLIER)],
        "policy": {
            "approverKeys": {ALICE: "key:alice", BOB: "key:bob", CAROL: "key:carol",
                             DAVE: "key:dave", "user:mallory": "key:mallory",
                             "system:gateway": "key:gateway", PROPOSER: "key:planner"},
            "approvers": [ALICE, BOB, CAROL], "authorityKeyId": AUTHORITY, "delegations": [],
            "quorum": 2, "rejectVetoes": True, "separationOfDuties": {"conflicts": []},
            "timeoutSeconds": 1800,
        },
        "proposal": {
            "argsShown": dict(ARGS), "historyDigest": AUTO, "modelResponse": response(),
            "proposalId": PROPOSAL, "proposedAt": PROPOSED, "proposer": PROPOSER,
            "tool": TOOL, "toolCallId": CALL,
        },
    }


def witness_for(record: dict[str, Any]) -> list[dict[str, Any]]:
    """The witness log: one earlier entry, then each relied approval's consumption."""
    execution = record["execution"]
    entries = [{"at": EARLIER["consumedAt"], "digest": reader.digest(EARLIER),
                "kind": "approval", "seq": 1}]
    for approval_id in dict.fromkeys(execution["approvalIds"]):
        statement = reader.consumption_statement(approval_id, execution)
        entries.append({"at": execution["consumedAt"], "digest": reader.digest(statement),
                        "kind": "approval", "seq": len(entries) + 1})
    return entries


def finalize(record: dict[str, Any]) -> dict[str, Any]:
    """Compute every digest a case left to be computed, and the witness log."""
    proposal = record.get("proposal", {})
    shown = reader.digest(proposal.get("argsShown"))
    history = reader.digest(proposal.get("modelResponse"))
    if proposal.get("historyDigest") == AUTO:
        proposal["historyDigest"] = history
    for item in record.get("approvals", []):
        if item.get("argsDigest") == AUTO:
            item["argsDigest"] = shown
        if item.get("historyDigest") == AUTO:
            item["historyDigest"] = history
    execution = record.get("execution", {})
    if execution.get("historyDigest") == AUTO:
        execution["historyDigest"] = history
    record["witness"] = witness_for(record)
    return record


Mutation = Callable[[dict[str, Any]], object]


def build(mutate: Mutation | None = None, after: Mutation | None = None) -> dict[str, Any]:
    """The conformant record with ``mutate`` applied before the digests are
    computed and ``after`` applied once they are."""
    body = base()
    if mutate is not None:
        mutate(body)
    finalize(body)
    if after is not None:
        after(body)
    return body


def relied(*approvals: dict[str, Any]) -> Mutation:
    """Present exactly these approvals and rely on all of them."""
    def apply(r: dict[str, Any]) -> None:
        r["approvals"] = [copy.deepcopy(a) for a in approvals]
        r["execution"]["approvalIds"] = [a["approvalId"] for a in approvals]
    return apply


def extra(*approvals: dict[str, Any]) -> Mutation:
    """Present these approvals as well, without relying on them."""
    def apply(r: dict[str, Any]) -> None:
        r["approvals"] += [copy.deepcopy(a) for a in approvals]
    return apply


def both(*steps: Mutation) -> Mutation:
    def apply(r: dict[str, Any]) -> None:
        for step in steps:
            step(r)
    return apply


def policy(**fields: Any) -> Mutation:
    return lambda r: r["policy"].update(fields)


def execution(**fields: Any) -> Mutation:
    return lambda r: r["execution"].update(fields)


def second(**fields: Any) -> Mutation:
    """Change the second approval's members."""
    return lambda r: r["approvals"][1].update(fields)


def ledger(*entries: dict[str, Any]) -> Mutation:
    return lambda r: r.update(ledger=[dict(EARLIER), *entries])


def spent(approval_id: str, call: str = CALL, run: str = "execution-1",
          when: str = "2026-11-08T10:04:00Z") -> dict[str, Any]:
    return {"approvalId": approval_id, "consumedAt": when, "executionId": run,
            "toolCallId": call}


CAROL_APPROVES = approval("approval-3", CAROL, issued="2026-11-08T10:03:00Z")
CAROL_REJECTS = approval("approval-3", CAROL, decision="reject", issued="2026-11-08T10:03:00Z")
DAVE_APPROVES = approval("approval-4", DAVE, issued="2026-11-08T10:03:30Z")
CAROL_TO_DAVE = delegation(CAROL, [DAVE])
PROPOSER_APPROVES = policy(approvers=[ALICE, BOB, CAROL, PROPOSER])
OTHER_HISTORY = reader.digest(response(response_id="response-other-run"))

Case = tuple[str, dict[str, Any], str, str, str]


def allow(name: str, body: dict[str, Any], edit: str) -> Case:
    return (name, body, "allow", reader.ALLOW_REASON, edit)


def deny(name: str, body: dict[str, Any], reason: str, edit: str) -> Case:
    return (name, body, "deny", reason, edit)


def controls() -> list[Case]:
    return [
        allow("allow-two-of-three-distinct", build(),
              "control: two of three distinct approvers approved the shown bytes"),
        allow("allow-one-of-one",
              build(both(policy(quorum=1, approvers=[ALICE]), relied(A1))),
              "control: a one-of-one policy and its one approval"),
        allow("allow-quorum-through-delegated-approver",
              build(both(policy(delegations=[CAROL_TO_DAVE]), relied(A1, DAVE_APPROVES))),
              "control: the second approval comes from a principal an approver added"),
        allow("allow-identity-transform-recorded",
              build(execution(transforms=[transform("after_tool_validate", ARGS, ARGS),
                                          transform("none", ARGS, ARGS)])),
              "control: a validator ran and changed nothing, and the record says so"),
        allow("allow-transforms-round-trip",
              build(execution(transforms=[transform("override_args", ARGS, SWAPPED),
                                          transform("after_tool_validate", SWAPPED, ARGS)])),
              "control: the arguments were replaced and restored before dispatch"),
        allow("allow-failed-outcome-approval-returned",
              build(execution(outcome="failed", approvalStatus="returned")),
              "control: the effect failed and the approvals were returned"),
        allow("allow-uncertain-outcome-approval-held",
              build(execution(outcome="uncertain", approvalStatus="held")),
              "control: the effect is uncertain and the approvals are held"),
        allow("allow-reject-after-consumption",
              build(extra(approval("approval-3", CAROL, decision="reject",
                                   issued=at(CONSUMED, 1)))),
              "control: a reject issued one second after consumption came too late to veto"),
        allow("allow-reject-without-veto-policy",
              build(both(policy(rejectVetoes=False), extra(CAROL_REJECTS))),
              "control: a reject under a policy where rejects do not veto"),
        allow("allow-unauthenticated-decisions-not-counted",
              build(extra(approval("approval-3", None, claimed=CAROL, decision="reject"),
                          approval("approval-5", None, claimed="user:mallory"))),
              "control: decisions named only in the body are neither counted nor a veto"),
        allow("allow-more-approvals-than-quorum",
              build(relied(A1, A2, CAROL_APPROVES)),
              "control: three distinct approvals for a quorum of two"),
        allow("allow-delegation-raises-quorum",
              build(both(policy(delegations=[delegation(ALICE, [], quorum=3)]),
                         relied(A1, A2, CAROL_APPROVES))),
              "control: a delegation raised the quorum to three and three approved"),
        allow("allow-dispatch-one-second-before-expiry",
              build(second(expiresAt=at(DISPATCHED, 1))),
              "control: dispatched one second before an approval expires"),
        allow("allow-quorum-one-second-before-timeout",
              build(policy(timeoutSeconds=121)),
              "control: the quorum was reached one second before the window closed"),
        allow("allow-consumed-at-dispatch-instant",
              build(execution(dispatchedAt=CONSUMED)),
              "control: consumed and dispatched in the same second"),
        allow("allow-ledger-read-empty", build(lambda r: r.update(ledger=[])),
              "control: the ledger was read and held nothing"),
        allow("allow-approval-issued-at-consumption",
              build(second(issuedAt=CONSUMED)),
              "control: an approval issued at the instant it was consumed"),
    ]


def contract_and_form() -> list[Case]:
    return [
        deny("contract-id-missing", build(after=lambda r: r.pop("contractId")),
             "contract_id_missing", "the record names no contract"),
        deny("contract-id-v1", build(after=lambda r: r.update(
             contractId=reader.CONTRACT_ID.replace("/v2", "/v1"))), "contract_id_unknown",
             "a single-approval v1 record presented under the quorum contract"),
        deny("malformed-approvals-missing", build(after=lambda r: r.pop("approvals")),
             "malformed_record", "the record omits the decisions it is judged against"),
        deny("malformed-quorum-zero", build(after=policy(quorum=0)), "malformed_record",
             "a quorum of zero approvals"),
        deny("malformed-number-not-integer", build(after=policy(timeoutSeconds=1800.0)),
             "malformed_record", "the timeout is written as a float"),
        deny("malformed-decision-unknown", build(after=second(decision="approved")),
             "malformed_record", "a decision outside approve and reject"),
        deny("malformed-witness-sequence-gap",
             build(after=lambda r: r["witness"][2].update(seq=4)), "malformed_record",
             "the witness sequence skips a number"),
        deny("malformed-relied-approval-not-presented",
             build(after=execution(approvalIds=["approval-1", "approval-9"])),
             "malformed_record", "the execution relies on an approval the record does not hold"),
        deny("malformed-duplicate-approval-id",
             build(after=second(approvalId="approval-1")), "malformed_record",
             "two decisions share one identifier"),
        deny("malformed-authenticated-principal-empty",
             build(after=second(authenticatedPrincipal="")), "malformed_record",
             "the authentication context names an empty principal"),
        deny("malformed-digest-form",
             build(after=second(argsDigest="0" * 64)), "malformed_record",
             "an arguments digest without its algorithm prefix"),
        deny("malformed-time-not-utc",
             build(after=execution(dispatchedAt="2026-11-08T11:05:01+01:00")),
             "malformed_record", "the dispatch time carries an offset instead of Z"),
        deny("consumption-ledger-not-read", build(after=lambda r: r.pop("ledger")),
             "consumption_not_checked",
             "the record carries no ledger: absent is not the same as read and empty"),
    ]


def identity() -> list[Case]:
    return [
        deny("delegation-removes-approver",
             build(policy(delegations=[delegation(ALICE, [], remove=[CAROL])])),
             "approver_delegation_widened", "a delegation removes an approver"),
        deny("delegation-lowers-quorum",
             build(policy(delegations=[delegation(ALICE, [], quorum=1)])),
             "approver_delegation_widened", "a delegation lowers the quorum to one"),
        deny("delegation-issued-by-non-approver",
             build(policy(delegations=[delegation(DAVE, ["user:erin"])])),
             "approver_delegation_widened", "a principal outside the policy issues a delegation"),
        deny("proposer-delegates-its-own-approver",
             build(both(policy(delegations=[delegation(PROPOSER, ["user:mallory"])]),
                        relied(A1, approval("approval-5", "user:mallory")))),
             "approver_delegation_widened",
             "the proposing agent adds an approver of its choosing and that approver counts"),
        deny("approval-for-another-proposal", build(second(proposalId="proposal-2")),
             "approval_not_for_call", "the second approval was given for another proposal"),
        deny("execution-runs-another-tool", build(execution(tool="payments.transfer")),
             "approval_not_for_call", "the execution runs a different tool under the call id"),
        deny("call-not-in-model-response",
             build(lambda r: r["proposal"]["modelResponse"]["toolCalls"][0].update(
                 toolCallId="call-other")),
             "approval_not_for_call", "the model response the proposal cites holds no such call"),
        deny("approver-named-only-in-body",
             build(lambda r: r["approvals"][1].pop("authenticatedPrincipal")),
             "approver_unauthenticated",
             "the second approver is named in the request body and nowhere else"),
        deny("authenticated-principal-null", build(second(authenticatedPrincipal=None)),
             "approver_unauthenticated", "the authentication context established no principal"),
        deny("body-claim-differs-from-authenticated",
             build(second(approverClaimed=CAROL)), "approver_claim_mismatch",
             "the body names carol while the authenticated principal is bob"),
        deny("approval-signed-under-another-key", build(second(keyId="key:alice")),
             "approver_key_not_bound", "bob's approval is signed under alice's key"),
        deny("approver-not-in-policy",
             build(relied(A1, approval("approval-5", "user:mallory"))), "approver_ineligible",
             "an authenticated principal the policy does not name approves"),
        deny("automatic-approval-by-the-gateway",
             build(relied(A1, approval("approval-5", "system:gateway"))), "approver_ineligible",
             "the gateway approved on the approvers' behalf"),
        deny("proposer-approves-own-call",
             build(both(PROPOSER_APPROVES, relied(A1, approval("approval-5", PROPOSER)))),
             "approver_is_proposer", "the proposing agent is an approver and approves itself"),
        deny("proposer-approves-through-delegate",
             build(both(PROPOSER_APPROVES, policy(delegations=[delegation(PROPOSER, [DAVE])]),
                        relied(A1, DAVE_APPROVES))),
             "approver_is_proposer", "the proposer's seat approves through its delegate"),
        deny("same-approver-approves-twice",
             build(relied(A1, approval("approval-2", ALICE, issued="2026-11-08T10:02:00Z"))),
             "approver_counted_twice", "alice's two approvals are counted as two"),
        deny("same-approval-cited-twice",
             build(execution(approvalIds=["approval-1", "approval-1"])),
             "approver_counted_twice", "one approval is cited twice toward the quorum"),
        deny("delegate-and-delegator-both-counted",
             build(both(policy(delegations=[CAROL_TO_DAVE]),
                        relied(CAROL_APPROVES, DAVE_APPROVES))),
             "approver_counted_twice", "carol and the delegate she added fill one seat twice"),
        deny("conflicting-approvers-both-counted",
             build(policy(separationOfDuties={"conflicts": [[ALICE, BOB]]})),
             "approvers_conflicted", "two approvers the policy says may not both count"),
    ]


def decisions() -> list[Case]:
    return [
        deny("reject-counted-as-approval",
             build(both(policy(rejectVetoes=False), second(decision="reject"))),
             "approval_not_granted", "a recorded reject is counted toward the quorum"),
        deny("eligible-reject-vetoes", build(extra(CAROL_REJECTS)), "approval_vetoed",
             "carol rejected before consumption and the policy says a reject vetoes"),
        deny("reject-at-consumption-instant-vetoes",
             build(extra(approval("approval-3", CAROL, decision="reject", issued=CONSUMED))),
             "approval_vetoed", "a reject issued at the instant of consumption"),
        deny("one-approval-of-two", build(relied(A1)), "quorum_not_met",
             "one approval for a quorum of two"),
        deny("no-approvals-and-dispatched",
             build(both(relied(), execution(dispatchedAt=at(PROPOSED, 1800),
                                            consumedAt=at(PROPOSED, 1800)))),
             "quorum_not_met", "the window closed with no approval and the call ran anyway"),
        deny("delegation-raises-quorum-not-met",
             build(policy(delegations=[delegation(ALICE, [], quorum=3)])), "quorum_not_met",
             "a delegation raised the quorum to three and two approved"),
    ]


def bytes_and_history() -> list[Case]:
    mallory = transform("override_args", ARGS, SWAPPED)
    return [
        deny("approval-covers-bytes-never-shown",
             build(both(second(argsDigest=reader.digest(VALIDATED)),
                        lambda r: r["approvals"][0].update(argsDigest=reader.digest(VALIDATED)),
                        execution(argsExecuted=dict(VALIDATED), transforms=[
                            transform("after_tool_validate", ARGS, VALIDATED)]))),
             "approval_not_for_bytes",
             "the approvals cover the validated bytes, which the approvers were never shown"),
        deny("split-quorum-different-bytes",
             build(second(argsDigest=reader.digest(SWAPPED))), "approval_not_for_bytes",
             "the two approvers approved different bytes"),
        deny("swapped-args-same-call-id",
             build(execution(argsExecuted=dict(SWAPPED),
                             historyDigest=reader.digest(response(SWAPPED)))),
             "args_changed_after_approval",
             "the resubmitted history swaps the arguments under the approved call id"),
        deny("resume-field-replaces-args",
             build(execution(argsExecuted=dict(SWAPPED), transforms=[
                 transform("editedArgs", ARGS, SWAPPED)])),
             "args_changed_after_approval",
             "a resume payload's edited arguments replace the approved ones"),
        deny("override-args-replaces-args",
             build(execution(argsExecuted=dict(SWAPPED), transforms=[mallory])),
             "args_changed_after_approval", "an approval carries override arguments"),
        deny("validator-rewrites-after-approval",
             build(execution(argsExecuted=dict(VALIDATED), transforms=[
                 transform("after_tool_validate", ARGS, VALIDATED)])),
             "args_changed_after_approval",
             "a validator rewrote the arguments after the approvers saw them"),
        deny("args-changed-with-no-transform-recorded",
             build(execution(argsExecuted=dict(SWAPPED))), "args_changed_after_approval",
             "the executed arguments differ and the record names no transform"),
        deny("transform-log-claims-unapplied-change",
             build(execution(transforms=[mallory])), "transforms_unaccounted",
             "the record claims an override the executed bytes do not show"),
        deny("transform-none-changes-digest",
             build(execution(transforms=[
                 {**transform("none", ARGS, SWAPPED)},
                 transform("override_args", SWAPPED, ARGS)])),
             "transforms_unaccounted", "a transform recorded as none changes the bytes"),
        deny("approval-from-another-run",
             build(lambda r: [a.update(historyDigest=OTHER_HISTORY) for a in r["approvals"]]),
             "history_digest_mismatch",
             "the approvals were given in another run, for another model response"),
        deny("proposal-history-digest-forged",
             build(lambda r: [r["proposal"].update(historyDigest=OTHER_HISTORY),
                              r["execution"].update(historyDigest=OTHER_HISTORY),
                              *(a.update(historyDigest=OTHER_HISTORY)
                                for a in r["approvals"])]),
             "history_digest_mismatch",
             "every party carries one history digest, and it is not the response's"),
        deny("execution-ran-from-edited-history",
             build(execution(historyDigest=OTHER_HISTORY)), "history_digest_mismatch",
             "the call ran from a history other than the one approved"),
    ]


def time_and_consumption() -> list[Case]:
    resend = execution(executionId="execution-3", consumedAt="2026-11-08T10:06:00Z",
                       dispatchedAt="2026-11-08T10:06:01Z")
    first_run = [spent("approval-1", when=CONSUMED), spent("approval-2", when=CONSUMED)]
    return [
        deny("dispatched-at-expiry", build(second(expiresAt=DISPATCHED)), "approval_expired",
             "dispatched at the instant an approval expires"),
        deny("dispatched-after-expiry",
             build(lambda r: r["approvals"][0].update(expiresAt="2026-11-08T10:04:00Z")),
             "approval_expired", "dispatched a minute after an approval expired"),
        deny("approval-issued-after-consumption", build(second(issuedAt=at(CONSUMED, 1))),
             "approval_postdates_consumption",
             "an approval issued one second after it was consumed"),
        deny("quorum-reached-at-timeout", build(policy(timeoutSeconds=120)),
             "timeout_not_fail_closed", "the quorum was reached at the instant the window closed"),
        deny("late-approval-revives-timed-out-call", build(policy(timeoutSeconds=60)),
             "timeout_not_fail_closed", "an approval after the window closed revives the call"),
        deny("same-approval-resent", build(both(ledger(*first_run), resend)),
             "approval_replayed", "the approved resume body is sent a second time"),
        deny("concurrent-double-click-loser",
             build(ledger(spent("approval-1", when=CONSUMED, run="execution-winner"),
                          spent("approval-2", when=CONSUMED, run="execution-winner"))),
             "approval_replayed",
             "a second click consumed the approvals in the same second as the first"),
        deny("approval-consumed-by-another-call",
             build(ledger(spent("approval-2", call="call-other"))), "approval_replayed",
             "an approval already spent on another call is presented again"),
        deny("double-submit-with-fresh-approval",
             build(ledger(spent("approval-0002"))), "call_already_executed",
             "the call already ran once and is submitted again with a fresh approval"),
        deny("worker-consumed-its-own-approvals", build(execution(consumedBy="key:worker-1")),
             "consumption_not_by_authority", "the worker, not the authority, spent the approvals"),
        deny("consumption-missing-from-witness",
             build(after=lambda r: r.update(witness=r["witness"][:2])),
             "consumption_not_witnessed", "the witness saw one of the two consumptions"),
        deny("witness-absent", build(after=lambda r: r.pop("witness")),
             "consumption_not_witnessed", "the record carries no witness log"),
        deny("witness-records-another-execution",
             build(after=lambda r: r.update(witness=witness_for(
                 {"execution": {**r["execution"], "executionId": "execution-other"}}))),
             "consumption_not_witnessed",
             "the witnessed consumptions belong to another execution"),
        deny("dispatched-before-consumption", build(execution(consumedAt=at(DISPATCHED, 1))),
             "consumed_after_dispatch",
             "the call was dispatched a second before its approvals were consumed"),
        deny("witness-saw-consumption-after-dispatch",
             build(after=lambda r: r["witness"][2].update(at=at(DISPATCHED, 1))),
             "consumed_after_dispatch", "the witness saw a consumption after dispatch"),
        deny("failed-outcome-approval-spent", build(execution(outcome="failed")),
             "outcome_misrecorded", "the effect failed and the approvals are recorded as spent"),
        deny("uncertain-outcome-approval-spent", build(execution(outcome="uncertain")),
             "outcome_misrecorded", "the effect is uncertain and the approvals are spent"),
        deny("applied-outcome-approval-returned",
             build(execution(approvalStatus="returned")), "outcome_misrecorded",
             "the effect landed and the approvals were returned for reuse"),
        deny("applied-outcome-approval-held", build(execution(approvalStatus="held")),
             "outcome_misrecorded", "the effect landed and the approvals are only held"),
    ]


def cases() -> list[Case]:
    """Every case: id, record, expected decision and reason, and what it departs from."""
    return [*controls(), *contract_and_form(), *identity(), *decisions(),
            *bytes_and_history(), *time_and_consumption()]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    directory_root = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = directory_root / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    entries = []
    for name, body, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        data = _json(body)
        (directory / "record.json").write_bytes(data)
        entries.append({
            "edit": edit, "expected": {"decision": decision, "reason": reason},
            "files": {"record.json": _sha(data)}, "id": name, "path": f"cases/{name}",
        })
    manifest = {
        "contractId": reader.CONTRACT_ID, "corpusDigest": _sha(_json(entries)), "suite": SUITE,
        "verifierContract": "verifier record.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    verdict_words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
