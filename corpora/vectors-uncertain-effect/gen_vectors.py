"""Build the uncertain-effect cases byte-identically.

Every case is one runtime's trail for one intended effect whose reply may have
been lost. Each denied case is built so the check it names is the first that
fails and every earlier check passes, and each allowed case is a control that
keeps a verifier from denying everything. Every case also carries the runtime
scenario it pairs with: the counting effect owner's behaviour that produces the
same situation, and the results a conforming runtime may leave in it.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import uncertaineffect as reader  # noqa: E402

SUITE = reader.SUITE
T0 = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)
KEY = "order-7f3a"
ARGS = {"quantity": 1, "sku": "A-1"}
CHANGED_ARGS = {"quantity": 2, "sku": "A-1"}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def digest(args: dict[str, Any]) -> str:
    """``sha256:`` over the RFC 8785 bytes of the arguments (ASCII keys and integers here)."""
    return "sha256:" + _sha(json.dumps(args, sort_keys=True, separators=(",", ":")).encode())


def ts(seconds: float) -> str:
    """An RFC 3339 instant ``seconds`` after the case's start."""
    return (T0 + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def attempt(n: int, at: float, reply: str, *, key: str = KEY, args: dict[str, Any] | None = None,
            worker: str | None = None, token: int | None = None,
            trigger: tuple[str, str] | None = None) -> dict[str, Any]:
    """One dispatch of the operation and the reply the caller got."""
    item: dict[str, Any] = {"argsDigest": digest(args or ARGS), "attempt": n,
                            "dispatchedAt": ts(at), "idempotencyKey": key, "reply": reply}
    if worker is not None:
        item.update({"fencingToken": token, "worker": worker})
    if trigger is not None:
        item["trigger"] = {"id": trigger[1], "kind": trigger[0]}
    return item


def lookup(at: float, result: str, *, final: bool = True, key: str = KEY) -> dict[str, Any]:
    """One answer the effect owner gave about the key."""
    return {"at": ts(at), "final": final, "idempotencyKey": key, "result": result}


def lease(worker: str, token: int, start: float, end: float) -> dict[str, Any]:
    return {"acquiredAt": ts(start), "expiresAt": ts(end), "fencingToken": token,
            "worker": worker}


def scenario(sid: str, summary: str, calls: list[str], accepted: list[tuple[int, str]], *,
             dedupe: bool = False, lookups: list[str] | None = None,
             lease_lost_after: int | None = None, restart: dict[str, str] | None = None,
             forgets_keys_after: int | None = None) -> dict[str, Any]:
    """The counting owner's behaviour and the results a conforming runtime may leave."""
    owner: dict[str, Any] = {"calls": calls, "deduplicatesByKey": dedupe,
                             "lookups": lookups or ["final"]}
    if lease_lost_after is not None:
        owner["lease"] = {"lostAfterCall": lease_lost_after, "token": 1}
    if forgets_keys_after is not None:
        owner["forgetsKeysAfterCalls"] = forgets_keys_after
    body: dict[str, Any] = {
        "accepted": [{"effects": n, "outcome": o} for n, o in accepted], "id": sid,
        "operation": {"action": "create-order", "args": ARGS, "idempotencyKey": KEY},
        "owner": owner, "summary": summary}
    if restart is not None:
        body["restart"] = restart
    return body


SCENARIOS = {
    "confirmed": scenario(
        "confirmed", "the first call commits and its reply arrives",
        ["commit"], [(1, "committed")]),
    "commit-then-lost-reply": scenario(
        "commit-then-lost-reply",
        "the first call commits and its reply is lost; the owner does not deduplicate, and "
        "its lookups are final, so the runtime must ask before it sends again",
        ["commit_drop"], [(1, "committed")]),
    "commit-then-lost-reply-deduplicating": scenario(
        "commit-then-lost-reply-deduplicating",
        "the first call commits and its reply is lost; the owner deduplicates by key, so a "
        "resend under the same key and arguments is safe",
        ["commit_drop"], [(1, "committed")], dedupe=True),
    "owner-unreachable-after-lost-reply": scenario(
        "owner-unreachable-after-lost-reply",
        "the first call commits and its reply is lost, and the owner cannot answer lookups; "
        "the outcome stays unknown and nothing is sent again",
        ["commit_drop"], [(1, "unknown")], lookups=["unavailable"]),
    "lost-before-commit": scenario(
        "lost-before-commit",
        "the first call is lost before it commits; a final lookup says absent, after which a "
        "resend is safe and so is reporting not run",
        ["drop"], [(0, "not_run"), (1, "committed")]),
    "late-commit-after-missed-lookup": scenario(
        "late-commit-after-missed-lookup",
        "the first call's reply is lost and it commits late: the first lookup misses it and "
        "is not final, the next one finds it",
        ["late_commit"], [(1, "committed")], lookups=["non_final"]),
    "definite-no-effect": scenario(
        "definite-no-effect",
        "the first call is refused with a definite no-effect answer; a resend is safe",
        ["no_effect"], [(0, "not_run"), (1, "committed")]),
    "lease-lost-after-lost-reply": scenario(
        "lease-lost-after-lost-reply",
        "the worker's first call commits and its reply is lost, and its lease passes to "
        "another worker; it must not dispatch again under the old fencing token",
        ["commit_drop"], [(1, "committed"), (1, "unknown")], lease_lost_after=1),
    "crash-mid-step-checkpoint-kept": scenario(
        "crash-mid-step-checkpoint-kept",
        "the worker is killed while its call is in flight and the owner commits it anyway; the "
        "step restarts with its checkpoint and the same task, and must not send it again",
        ["commit_hold"], [(1, "committed"), (1, "unknown")],
        restart={"mode": "crash", "state": "kept", "taskId": "same"}),
    "crash-mid-step-checkpoint-lost": scenario(
        "crash-mid-step-checkpoint-lost",
        "the worker is killed while its call is in flight and its checkpoint is lost; the step "
        "restarts under a new task, and the owner deduplicates by key, so the key must not "
        "follow the task",
        ["commit_hold"], [(1, "committed"), (1, "unknown")], dedupe=True,
        restart={"mode": "crash", "state": "wiped", "taskId": "new"}),
    "redelivery-new-task-id": scenario(
        "redelivery-new-task-id",
        "the call commits and its reply is lost; the engine redelivers the step under a new "
        "task identifier, and the owner deduplicates by key",
        ["commit_drop"], [(1, "committed"), (1, "unknown")], dedupe=True,
        restart={"mode": "rerun", "state": "kept", "taskId": "new"}),
    "rewind-replay-after-confirmed": scenario(
        "rewind-replay-after-confirmed",
        "the call commits and is confirmed; the run is rewound, its history is gone, and the "
        "step replays against an owner that does not deduplicate",
        ["commit"], [(1, "committed")], dedupe=False,
        restart={"mode": "rerun", "state": "wiped", "taskId": "same"}),
    "duplicate-human-completion": scenario(
        "duplicate-human-completion",
        "two deliveries of one completion signal run the step at the same time against a slow "
        "owner that does not deduplicate",
        ["commit_slow"], [(1, "committed"), (1, "unknown")], dedupe=False,
        restart={"mode": "concurrent", "state": "kept", "taskId": "new"}),
    "key-forgotten-by-owner-then-replay": scenario(
        "key-forgotten-by-owner-then-replay",
        "the call commits and is confirmed, the owner then forgets the key, and a replay with "
        "no history finds a lookup that is not final: the replay must not send again",
        ["commit"], [(1, "committed"), (1, "unknown")], dedupe=True, forgets_keys_after=1,
        restart={"mode": "rerun", "state": "wiped", "taskId": "same"}),
}


def build(name: str, attempts: list[dict[str, Any]], reported: str, owner_effects: int, *,
          dedupe: bool = False, retention: int | None = None,
          lookups: list[dict[str, Any]] | None = None,
          leases: list[dict[str, Any]] | None = None,
          reservation: dict[str, Any] | None = None, as_of: float = 300,
          **top: Any) -> dict[str, Any]:
    """One runtime trail for the operation, with the owner's answers and ledger count."""
    record: dict[str, Any] = {
        "asOf": ts(as_of), "attempts": copy.deepcopy(attempts),
        "contractId": reader.CONTRACT_ID,
        "effectOwner": {"deduplicatesByKey": dedupe, "id": "orders-service",
                        "keyRetentionSeconds": retention},
        "operation": {"action": "create-order", "argsDigest": digest(ARGS), "id": "op-1",
                      "idempotencyKey": KEY},
        "ownerEffects": owner_effects, "recordId": f"record-{name}",
        "reconciliations": copy.deepcopy(lookups or []),
        "reported": {"outcome": reported},
    }
    if leases is not None:
        record["leases"] = copy.deepcopy(leases)
    if reservation is not None:
        record["reservation"] = reservation
    record.update(top)
    return {key: value for key, value in record.items() if value is not None}


def invoice(at: float, units: int) -> dict[str, Any]:
    """A final invoice from the billing party: a notice, not an answer from the effect owner."""
    return {"at": ts(at), "final": True, "from": "billing", "kind": "invoice", "units": units}


def held(charged: bool = True, expires: float = 120) -> dict[str, Any]:
    """The capacity reserved for the operation, and whether it is still charged."""
    return {"charged": charged, "expiresAt": ts(expires), "units": 5}


Case = tuple[str, dict[str, Any], str, str, str, str]


def _lease_pair(expires_a: float, b_start: float) -> list[dict[str, Any]]:
    return [lease("worker-a", 1, 0, expires_a), lease("worker-b", 2, b_start, b_start + 60)]


def _controls() -> list[Case]:
    ok = reader.ALLOWED_REASON
    lost = attempt(1, 1, "timeout")
    return [
        ("allow-confirmed-first-attempt",
         build("allow-confirmed-first-attempt", [attempt(1, 1, "confirmed")], "committed", 1,
               reservation=held()), "allow", ok, "confirmed",
         "control: the first attempt is confirmed and the owner holds one effect"),
        ("allow-commit-timeout-reconciled-present",
         build("allow-commit-timeout-reconciled-present", [lost], "committed", 1,
               lookups=[lookup(30, "present")], reservation=held()),
         "allow", ok, "commit-then-lost-reply",
         "control: the reply is lost, a lookup finds the effect, the runtime closes the "
         "unknown as committed and sends nothing again"),
        ("allow-commit-timeout-held-unknown",
         build("allow-commit-timeout-held-unknown", [lost], "unknown", 1,
               reservation=held(), as_of=60),
         "allow", ok, "owner-unreachable-after-lost-reply",
         "control: the reply is lost, no lookup answers, and the runtime reports unknown with "
         "the reservation charged"),
        ("allow-unknown-charged-past-expiry",
         build("allow-unknown-charged-past-expiry", [lost], "unknown", 1,
               reservation=held(expires=120), as_of=300),
         "allow", ok, "owner-unreachable-after-lost-reply",
         "control: the reservation expired at 120 seconds and the unknown stays charged at 300"),
        ("allow-timeout-reconciled-absent-not-run",
         build("allow-timeout-reconciled-absent-not-run", [lost], "not_run", 0,
               lookups=[lookup(30, "absent")], reservation=held(charged=False)),
         "allow", ok, "lost-before-commit",
         "control: a final lookup finds the effect absent, the runtime reports not run and "
         "releases the reservation"),
        ("allow-retry-after-final-absent",
         build("allow-retry-after-final-absent", [lost, attempt(2, 40, "confirmed")],
               "committed", 1, lookups=[lookup(30, "absent")], reservation=held()),
         "allow", ok, "lost-before-commit",
         "control: a final lookup finds the effect absent before the resend, which is "
         "confirmed"),
        ("allow-retry-same-key-owner-deduplicates",
         build("allow-retry-same-key-owner-deduplicates", [lost, attempt(2, 40, "confirmed")],
               "committed", 1, dedupe=True, retention=86400, reservation=held()),
         "allow", ok, "commit-then-lost-reply-deduplicating",
         "control: the owner deduplicates by key, the resend carries the same key and "
         "arguments inside the retention window, and the owner holds one effect"),
        ("allow-definite-no-effect-then-retry",
         build("allow-definite-no-effect-then-retry",
               [attempt(1, 1, "no_effect"), attempt(2, 5, "confirmed")], "committed", 1,
               reservation=held()),
         "allow", ok, "definite-no-effect",
         "control: the first attempt got a definite no-effect answer, so the resend is safe"),
        ("allow-lease-taken-over-reconciled",
         build("allow-lease-taken-over-reconciled",
               [attempt(1, 1, "timeout", worker="worker-a", token=1)], "committed", 1,
               lookups=[lookup(50, "present")], leases=_lease_pair(30, 31),
               reservation=held()),
         "allow", ok, "lease-lost-after-lost-reply",
         "control: worker-a's reply is lost, its lease passes to worker-b, and worker-b "
         "finds the effect instead of sending it again"),
        ("allow-retry-after-final-absent-invoice-noted",
         build("allow-retry-after-final-absent-invoice-noted", [lost, attempt(2, 40, "confirmed")],
               "committed", 1, lookups=[lookup(30, "absent")], reservation=held(),
               notices=[invoice(20, 5)]),
         "allow", ok, "lost-before-commit",
         "control: a final invoice arrives after the lost reply, but a final owner lookup "
         "also finds the effect absent before the resend, which is confirmed"),
        ("allow-zero-invoice-reported-unknown",
         build("allow-zero-invoice-reported-unknown", [lost], "unknown", 1,
               reservation=held(), as_of=60, notices=[invoice(20, 0)]),
         "allow", ok, "owner-unreachable-after-lost-reply",
         "control: a zero invoice arrives after the lost reply, no owner lookup answers, and "
         "the runtime reports unknown with the reservation charged"),
        ("allow-late-commit-awaited",
         build("allow-late-commit-awaited", [lost], "committed", 1,
               lookups=[lookup(20, "absent", final=False), lookup(60, "present")],
               reservation=held()),
         "allow", ok, "late-commit-after-missed-lookup",
         "control: a lookup that is not final misses the effect, the runtime waits, and the "
         "next lookup finds it"),
    ]


def _identity_cases() -> list[Case]:
    base = [attempt(1, 1, "confirmed")]
    no_key = build("identity-missing-key", base, "committed", 1)
    del no_key["operation"]["idempotencyKey"]
    no_digest = build("identity-missing-args-digest", base, "committed", 1)
    del no_digest["attempts"][0]["argsDigest"]
    unknown_cid = reader.CONTRACT_ID.replace("/predicate/v1/", "/contract/v0/")
    return [
        ("contract-id-missing", build("contract-id-missing", base, "committed", 1,
                                      contractId=None),
         "deny", "contract_id_missing", "confirmed", "the record names no contract"),
        ("contract-id-unknown", build("contract-id-unknown", base, "committed", 1,
                                      contractId=unknown_cid),
         "deny", "contract_id_unknown", "confirmed",
         "the record names a contract version that does not exist"),
        ("identity-missing-key", no_key, "deny", "operation_identity_missing", "confirmed",
         "the operation carries no idempotency key"),
        ("identity-missing-args-digest", no_digest, "deny", "operation_identity_missing",
         "confirmed", "the attempt carries no arguments digest"),
    ]


def _dispatch_cases() -> list[Case]:
    lost = attempt(1, 1, "timeout")
    resend = attempt(2, 40, "confirmed")
    a_lost = attempt(1, 1, "timeout", worker="worker-a", token=1)
    a_resend = attempt(2, 40, "confirmed", worker="worker-a", token=1)
    return [
        ("key-reused-args-changed",
         build("key-reused-args-changed", [lost, attempt(2, 40, "confirmed", args=CHANGED_ARGS)],
               "committed", 1, dedupe=True, retention=86400),
         "deny", "idempotency_key_args_changed", "commit-then-lost-reply-deduplicating",
         "the resend carries the operation's key with quantity 2 where the operation said 1"),
        ("dispatch-after-lease-expired",
         build("dispatch-after-lease-expired", [a_lost, a_resend], "committed", 1, dedupe=True,
               retention=86400, leases=[lease("worker-a", 1, 0, 30)]),
         "deny", "dispatch_beyond_lease", "lease-lost-after-lost-reply",
         "worker-a resends at 40 seconds under a lease that expired at 30"),
        ("dispatch-with-superseded-token",
         build("dispatch-with-superseded-token", [a_lost, a_resend], "committed", 1, dedupe=True,
               retention=86400, leases=_lease_pair(60, 35)),
         "deny", "dispatch_beyond_lease", "lease-lost-after-lost-reply",
         "worker-a resends at 40 seconds inside its own window, after worker-b was granted "
         "fencing token 2 at 35"),
        ("retry-after-commit-timeout",
         build("retry-after-commit-timeout", [lost, resend], "committed", 2),
         "deny", "retry_after_unknown", "commit-then-lost-reply",
         "the reply is lost after the commit and the runtime resends at once to an owner "
         "that does not deduplicate, which holds two effects"),
        ("retry-after-lookup-not-final",
         build("retry-after-lookup-not-final", [lost, resend], "committed", 2,
               lookups=[lookup(20, "absent", final=False)]),
         "deny", "retry_after_unknown", "late-commit-after-missed-lookup",
         "the runtime resends after a lookup that was not final missed a late commit"),
        ("retry-under-new-key",
         build("retry-under-new-key", [lost, attempt(2, 40, "confirmed", key="order-7f3b")],
               "committed", 2, dedupe=True, retention=86400),
         "deny", "retry_after_unknown", "commit-then-lost-reply-deduplicating",
         "the owner deduplicates by key and the resend carries a new key, so both commit"),
        ("retry-after-key-retention-expired",
         build("retry-after-key-retention-expired", [lost, attempt(2, 90000, "confirmed")],
               "committed", 2, dedupe=True, retention=86400, as_of=90100),
         "deny", "retry_after_unknown", "commit-then-lost-reply-deduplicating",
         "the resend carries the same key 25 hours later, after the owner's 24-hour key "
         "retention, so the owner applied it again"),
        ("duplicate-effect-despite-deduplication",
         build("duplicate-effect-despite-deduplication", [lost, resend], "committed", 2,
               dedupe=True, retention=86400),
         "deny", "duplicate_effect", "commit-then-lost-reply-deduplicating",
         "the owner declares deduplication by key and its own ledger holds two effects"),
    ]


def _outcome_cases() -> list[Case]:
    lost = attempt(1, 1, "timeout")
    return [
        ("retry-after-final-invoice",
         build("retry-after-final-invoice", [lost, attempt(2, 40, "confirmed")], "committed", 2,
               notices=[invoice(20, 5)]),
         "deny", "retry_after_unknown", "commit-then-lost-reply",
         "a final invoice arrives after the lost reply and the runtime resends to an owner "
         "that does not deduplicate; an invoice is billing's word, not the owner's lookup"),
        ("zero-invoice-reported-not-run",
         build("zero-invoice-reported-not-run", [lost], "not_run", 1,
               notices=[invoice(20, 0)]),
         "deny", "outcome_settled_without_authority", "owner-unreachable-after-lost-reply",
         "a zero invoice arrives after the lost reply and the runtime reports not run; no "
         "owner lookup answered and the owner holds the effect"),
        ("unknown-released-at-expiry",
         build("unknown-released-at-expiry", [lost], "unknown", 1,
               reservation=held(charged=False, expires=120), as_of=300),
         "deny", "unknown_released", "owner-unreachable-after-lost-reply",
         "the reservation stopped being charged when it expired while the outcome is unknown"),
        ("timeout-reported-not-run",
         build("timeout-reported-not-run", [lost], "not_run", 1),
         "deny", "outcome_settled_without_authority", "owner-unreachable-after-lost-reply",
         "the reply is lost and no lookup answered, and the runtime reports not run; the "
         "owner holds the effect"),
        ("timeout-reported-committed",
         build("timeout-reported-committed", [lost], "committed", 0),
         "deny", "outcome_settled_without_authority", "owner-unreachable-after-lost-reply",
         "the reply is lost and no lookup answered, and the runtime reports committed; the "
         "owner holds nothing"),
        ("reconciled-absent-reported-committed",
         build("reconciled-absent-reported-committed", [lost], "committed", 0,
               lookups=[lookup(30, "absent")]),
         "deny", "outcome_disagrees_with_authority", "lost-before-commit",
         "a final lookup finds the effect absent and the runtime still reports committed"),
        ("reconciled-present-still-unknown",
         build("reconciled-present-still-unknown", [lost], "unknown", 1,
               lookups=[lookup(30, "present")], reservation=held()),
         "deny", "outcome_disagrees_with_authority", "commit-then-lost-reply",
         "a lookup finds the effect and the runtime never closes the unknown"),
    ]


def stop(ack: float, commit: tuple[float, float] | None, reported: str, *,
         checks: list[tuple[float, str]] | None = None, revoked: float = 12) -> dict[str, Any]:
    """A stop of the run: request, acknowledgement, revocation, later authority checks,
    the owner's own commit interval for the effect, and how the runtime reported the stop."""
    out: dict[str, Any] = {
        "acknowledgedAt": ts(ack), "requestedAt": ts(ack - 1), "revokedAt": ts(revoked),
        "authorityChecks": [{"at": ts(at), "result": result}
                            for at, result in (checks or [(20, "refused")])],
        "reported": reported,
    }
    if commit is not None:
        out["ownerCommit"] = {"notAfter": ts(commit[1]), "notBefore": ts(commit[0])}
    return out


def _cancel_cases() -> list[Case]:
    """A cancel is reported and the effect lands after it (the cancel race)."""
    ok = reader.ALLOWED_REASON
    lost = attempt(1, 1, "connection_lost")
    found = [lookup(40, "present")]
    return [
        ("allow-cancel-clean-stop",
         build("allow-cancel-clean-stop", [attempt(1, 1, "confirmed")], "committed", 1,
               stop=stop(10, (2, 3), "quiescent")),
         "allow", ok, "confirmed",
         "control: the effect commits before the stop is acknowledged, the revoked "
         "credential is refused afterwards, and the stop is reported quiescent"),
        ("allow-cancel-commit-after-ack-reported",
         build("allow-cancel-commit-after-ack-reported", [lost], "committed", 1,
               lookups=found, stop=stop(10, (15, 16), "effect_after_stop")),
         "allow", ok, "late-commit-after-missed-lookup",
         "control: the effect lands five seconds after the acknowledgement and the runtime "
         "reports it as an effect after the stop"),
        ("allow-cancel-straddle-not-established",
         build("allow-cancel-straddle-not-established", [lost], "committed", 1,
               lookups=found, stop=stop(10, (8, 12), "not_established")),
         "allow", ok, "late-commit-after-missed-lookup",
         "control: the owner's commit interval contains the acknowledgement and the runtime "
         "leaves the stop not established"),
        ("cancel-authority-accepted-after-revocation",
         build("cancel-authority-accepted-after-revocation", [attempt(1, 1, "confirmed")],
               "committed", 1,
               stop=stop(10, (2, 3), "quiescent", checks=[(14, "accepted"), (20, "refused")])),
         "deny", "authority_used_after_revocation", "confirmed",
         "a credential check two seconds after the revocation committed is still accepted"),
        ("cancel-commit-after-ack-reported-quiescent",
         build("cancel-commit-after-ack-reported-quiescent", [lost], "committed", 1,
               lookups=found, stop=stop(10, (15, 16), "quiescent")),
         "deny", "effect_after_stop_reported_quiescent", "late-commit-after-missed-lookup",
         "the stop is acknowledged at 10 seconds, the owner commits the effect at 15, and "
         "the runtime reports the stop quiescent"),
        ("cancel-straddle-reported-quiescent",
         build("cancel-straddle-reported-quiescent", [lost], "committed", 1,
               lookups=found, stop=stop(10, (8, 12), "quiescent")),
         "deny", "stop_straddle_reported_settled", "late-commit-after-missed-lookup",
         "the owner's commit interval contains the acknowledgement and the runtime reports "
         "the stop quiescent"),
        ("cancel-straddle-reported-after-stop",
         build("cancel-straddle-reported-after-stop", [lost], "committed", 1,
               lookups=found, stop=stop(10, (8, 12), "effect_after_stop")),
         "deny", "stop_straddle_reported_settled", "late-commit-after-missed-lookup",
         "the owner's commit interval contains the acknowledgement and the runtime settles "
         "it as after the stop"),
        ("cancel-reported-not-run-owner-committed",
         build("cancel-reported-not-run-owner-committed", [lost], "not_run", 1,
               stop=stop(10, (15, 16), "effect_after_stop")),
         "deny", "outcome_settled_without_authority", "owner-unreachable-after-lost-reply",
         "the runtime's record says the cancelled step did not run while the owner "
         "committed it after the stop"),
        ("cancel-resume-replays-same-key",
         build("cancel-resume-replays-same-key", [lost, attempt(2, 120, "confirmed")],
               "committed", 2, stop=stop(10, (15, 16), "effect_after_stop")),
         "deny", "retry_after_unknown", "commit-then-lost-reply",
         "the run resumes at 120 seconds and sends the cancelled step again under the same "
         "key to an owner that does not deduplicate, which holds two effects"),
    ]


def _durable_cases() -> list[Case]:
    """Crash mid-step, checkpoint loss, redelivery under a new task id, rewind, retention
    delete and a duplicate human completion."""
    ok = reader.ALLOWED_REASON
    crash = attempt(1, 1, "worker_crashed")
    new_key = "order-7f3b-task-2"
    redelivery = ("redelivery", "task-2")
    replay = ("replay", "history-reset-1")
    return [
        ("allow-crash-mid-step-held-unknown",
         build("allow-crash-mid-step-held-unknown", [crash], "unknown", 1,
               reservation=held(), as_of=60),
         "allow", ok, "crash-mid-step-checkpoint-kept",
         "control: the worker crashed with its call in flight, nothing was sent again, and the "
         "runtime reports unknown with the reservation charged"),
        ("allow-crash-checkpoint-lost-reconciled-present",
         build("allow-crash-checkpoint-lost-reconciled-present", [crash], "committed", 1,
               lookups=[lookup(30, "present")], reservation=held()),
         "allow", ok, "crash-mid-step-checkpoint-lost",
         "control: the worker crashed and lost its checkpoint, the restart asked the owner "
         "by key, found the effect and closed the unknown as committed"),
        ("allow-redelivery-same-key-owner-deduplicates",
         build("allow-redelivery-same-key-owner-deduplicates",
               [attempt(1, 1, "timeout"), attempt(2, 40, "confirmed", trigger=redelivery)],
               "committed", 1, dedupe=True, retention=86400, reservation=held()),
         "allow", ok, "redelivery-new-task-id",
         "control: the engine redelivers the step under task-2, the resend carries the "
         "operation's key, and the owner deduplicates it"),
        ("allow-replay-after-confirmed-owner-deduplicates",
         build("allow-replay-after-confirmed-owner-deduplicates",
               [attempt(1, 1, "confirmed"), attempt(2, 90, "confirmed", trigger=replay)],
               "committed", 1, dedupe=True, retention=86400, reservation=held()),
         "allow", ok, "rewind-replay-after-confirmed",
         "control: a rewind replays a confirmed step under the same key and the owner "
         "deduplicates it"),
        ("allow-duplicate-completion-owner-deduplicates",
         build("allow-duplicate-completion-owner-deduplicates",
               [attempt(1, 1, "confirmed", trigger=("completion", "approval-9")),
                attempt(2, 2, "confirmed", trigger=("completion", "approval-9"))],
               "committed", 1, dedupe=True, retention=86400, reservation=held()),
         "allow", ok, "duplicate-human-completion",
         "control: one human completion is delivered twice, both runs carry the operation's "
         "key, and the owner deduplicates"),
        ("redelivery-under-task-derived-key",
         build("redelivery-under-task-derived-key",
               [attempt(1, 1, "timeout"),
                attempt(2, 40, "confirmed", key=new_key, trigger=redelivery)],
               "committed", 2, dedupe=True, retention=86400),
         "deny", "idempotency_key_follows_trigger", "redelivery-new-task-id",
         "the engine redelivers the step under task-2 and the resend derives its key from the "
         "task identifier, so the owner's deduplication never sees the first call"),
        ("replay-under-new-key-after-confirmed",
         build("replay-under-new-key-after-confirmed",
               [attempt(1, 1, "confirmed"),
                attempt(2, 90, "confirmed", key=new_key, trigger=replay)],
               "committed", 2, dedupe=True, retention=86400),
         "deny", "idempotency_key_follows_trigger", "rewind-replay-after-confirmed",
         "a rewind replays a confirmed step under a new key, so the owner applies it again"),
        ("duplicate-completion-under-delivery-key",
         build("duplicate-completion-under-delivery-key",
               [attempt(1, 1, "confirmed", trigger=("completion", "approval-9")),
                attempt(2, 2, "confirmed", key=new_key, trigger=("completion", "approval-9"))],
               "committed", 2, dedupe=True, retention=86400),
         "deny", "idempotency_key_follows_trigger", "duplicate-human-completion",
         "one human completion is delivered twice and the second delivery keys the call by its "
         "own delivery identifier"),
        ("crash-redelivery-resends-blind",
         build("crash-redelivery-resends-blind",
               [crash, attempt(2, 40, "confirmed", trigger=redelivery)], "committed", 2),
         "deny", "retry_after_unknown", "crash-mid-step-checkpoint-lost",
         "the worker crashed with its call in flight and the redelivered step resends it to an "
         "owner that does not deduplicate, without asking the owner first"),
        ("checkpoint-lost-attempt-unrecorded",
         build("checkpoint-lost-attempt-unrecorded", [attempt(1, 40, "confirmed",
               trigger=redelivery)], "committed", 2),
         "deny", "owner_effect_unaccounted", "crash-mid-step-checkpoint-lost",
         "the first attempt died with its checkpoint, so the trail lists one attempt where the "
         "owner's ledger holds two effects"),
        ("history-deleted-effect-unaccounted",
         build("history-deleted-effect-unaccounted", [], "not_run", 1),
         "deny", "owner_effect_unaccounted", "rewind-replay-after-confirmed",
         "the run's history was deleted by retention, the trail lists no attempt, and the "
         "owner's ledger holds the effect"),
        ("replay-after-key-forgotten-applies-twice",
         build("replay-after-key-forgotten-applies-twice",
               [attempt(1, 1, "confirmed"), attempt(2, 5000, "confirmed", trigger=replay)],
               "committed", 2, dedupe=True, retention=3600, as_of=5100),
         "deny", "duplicate_effect", "key-forgotten-by-owner-then-replay",
         "the owner forgot the key after 3600 seconds, a replay at 5000 sent it again, and the "
         "owner's ledger holds two effects"),
        ("crash-reported-not-run",
         build("crash-reported-not-run", [crash], "not_run", 1),
         "deny", "outcome_settled_without_authority", "crash-mid-step-checkpoint-kept",
         "the worker crashed with its call in flight and the runtime reports the step did "
         "not run; the owner committed it"),
        ("crash-unknown-released",
         build("crash-unknown-released", [crash], "unknown", 1,
               reservation=held(charged=False, expires=120), as_of=300),
         "deny", "unknown_released", "crash-mid-step-checkpoint-kept",
         "the reservation for a crashed step stopped being charged when it expired while the "
         "outcome is unknown"),
    ]


def cases() -> list[Case]:
    """Every case: id, record, decision, reason, runtime scenario id, and what it shows."""
    return [*_controls(), *_identity_cases(), *_dispatch_cases(), *_outcome_cases(),
            *_cancel_cases(), *_durable_cases()]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base_dir = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base_dir / entry["path"]
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
    for name, body, decision, reason, scenario_id, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        data = _json(body)
        (directory / "record.json").write_bytes(data)
        entries.append({
            "edit": edit, "expected": {"decision": decision, "reason": reason},
            "files": {"record.json": _sha(data)},
            "id": name, "path": f"cases/{name}", "retained": reader.retained(body),
            "runtime": {"recordedEffects": body["ownerEffects"],
                        "scenario": SCENARIOS[scenario_id]},
        })
    manifest = {
        "contractId": reader.CONTRACT_ID,
        "corpusDigest": _sha(_json(entries)), "suite": SUITE,
        "runtimeContract": "runtime scenario.json, AEV_EFFECT_OWNER; see uncertaineffect_runtime",
        "verifierContract": "verifier record.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    verdict_words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
