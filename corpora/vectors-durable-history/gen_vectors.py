"""Build the durable-history cases byte-identically.

Every case is one record read under the contract at ``contractId``: what the
operator exported of a durable workflow run (``exports``) and what was
witnessed at execution time outside the operator's worker (``witnessed``). The
run is a support agent refunding a customer: a model request, a ticket read, a
second model request asking for the refund, an approval Update, and the gated
refund activity. Each denied case departs from a conformant record in one
place: an edit, deletion, reset, move or injection in the history, or a change
in what was witnessed. The public wording the cases follow is in README.md.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import durablehistory as reader  # noqa: E402

SUITE = reader.SUITE
WORKFLOW, RUN, FORK = "refund-T-100", "run-0001", "run-0002"
CALL = "call-refund-T-100"
UPDATE = "approve-call-refund-T-100"
CODEC_KEY = "key:codec-1"
ARGS = {"amountCents": 2000, "customerId": "alice", "payeeAccount": "acct-alice"}
RESULT = {"amountCents": 2000, "ref": "RF-0001", "status": "applied"}
DECLINED = {"amountCents": 2000, "reason": "card-closed", "status": "declined"}
TICKET = {"account": "acct-alice", "amountCents": 2000, "customerId": "alice",
          "text": "My order arrived broken. Please refund the 20.00 to my card on file."}
CODE = reader.digest({"tool": "issue_refund", "build": "worker-image-1"})
OTHER_CODE = reader.digest({"tool": "issue_refund", "build": "worker-image-2"})
GRANT = reader.digest({"grantId": "grant-refunds-1"})
SRL = {"digest": reader.digest([]), "epoch": 1}

Record = dict[str, Any]
Events = list[dict[str, Any]]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def plain(data: Any) -> dict[str, Any]:
    return {"data": data, "encoding": reader.PLAIN}


def sealed(data: Any, label: str) -> dict[str, Any]:
    """A deterministic stand-in for an AEAD codec's output: opaque bytes."""
    body = reader.canonical(data)
    stream = b""
    while len(stream) < len(body):
        stream += hashlib.sha256(f"{label}:{len(stream)}".encode()).digest()
    nonce = hashlib.sha256(f"nonce:{label}".encode()).digest()[:12]
    data_bytes = nonce + bytes(a ^ b for a, b in zip(body, stream, strict=False))
    return {"data": base64.b64encode(data_bytes).decode("ascii"),
            "encoding": reader.ENCRYPTED, "keyId": CODEC_KEY}


def cipher_digest(payload: dict[str, Any]) -> str:
    return reader.bytes_digest(reader.ciphertext(payload))


def ev(kind: str, **attributes: Any) -> dict[str, Any]:
    return {"attributes": attributes, "eventType": kind}


def scheduled(activity: str, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
    return ev(reader.SCHEDULED, activityId=activity, activityType=kind, input=payload)


def model_call(tool: str, call: str, args: dict[str, Any]) -> dict[str, Any]:
    return {"args": args, "callId": call, "tool": tool}


def number(events: Events) -> Events:
    """Give events their ids 1..n, and point each close at its schedule by activity."""
    out = copy.deepcopy(events)
    at: dict[str, int] = {}
    for index, event in enumerate(out, 1):
        event["eventId"] = index
        attrs = event["attributes"]
        if event["eventType"] == reader.SCHEDULED:
            at[attrs["activityId"]] = index
        elif "activity" in attrs:
            attrs["scheduledEventId"] = at[attrs.pop("activity")]
    return out


def closed(kind: str, activity: str, attempt: int = 1, **attributes: Any) -> dict[str, Any]:
    return ev(kind, activity=activity, attempt=attempt, **attributes)


def events(*, args: dict[str, Any] | None = None, model_args: dict[str, Any] | None = None,
           result: Any = None, seal: bool = False, attempt: int = 1,
           tool: str = "issue_refund", run: str = RUN,
           reset_from: dict[str, Any] | None = None, refund_close: str = reader.COMPLETED,
           updates: tuple[str, ...] = (UPDATE,), extra: Events | None = None) -> Events:
    """The run's history, before numbering; every argument is a departure."""
    wrap: Callable[[Any, str], dict[str, Any]] = sealed if seal else (lambda d, _l: plain(d))
    refund_args = ARGS if args is None else args
    asked = refund_args if model_args is None else model_args
    start = {"runId": run, "workflowId": WORKFLOW}
    if reset_from is not None:
        start["resetFrom"] = reset_from
    close_attrs = {"result": wrap(RESULT if result is None else result, "result-4")}
    body = [
        ev(reader.STARTED, **start),
        ev("WorkflowTaskCompleted"),
        scheduled("1", reader.MODEL_ACTIVITY, wrap({"prompt": "Handle ticket T-100."}, "in-1")),
        closed(reader.COMPLETED, "1", result=wrap({"toolCalls": [model_call(
            "read_ticket", "call-read-T-100", {"ticketId": "T-100"})]}, "result-1")),
        ev("WorkflowTaskCompleted"),
        scheduled("2", "tool:read_ticket", wrap({"args": {"ticketId": "T-100"},
                                                 "callId": "call-read-T-100"}, "in-2")),
        closed(reader.COMPLETED, "2", result=wrap(TICKET, "result-2")),
        ev("WorkflowTaskCompleted"),
        scheduled("3", reader.MODEL_ACTIVITY, wrap({"prompt": "Ticket read."}, "in-3")),
        closed(reader.COMPLETED, "3", result=wrap({"toolCalls": [model_call(
            tool, CALL, asked)]}, "result-3")),
        ev("WorkflowTaskCompleted"),
        *(ev(reader.UPDATE_ACCEPTED, updateId=u) for u in updates),
        ev("WorkflowTaskCompleted"),
        scheduled("4", "tool:" + tool, wrap({"args": refund_args, "callId": CALL}, "in-4")),
    ]
    if refund_close == reader.COMPLETED:
        body.append(closed(reader.COMPLETED, "4", attempt, **close_attrs))
    elif refund_close == reader.TIMED_OUT:
        body.append(closed(reader.TIMED_OUT, "4", attempt))
    body += [ev("WorkflowTaskCompleted"), *(extra or []),
             ev("WorkflowExecutionCompleted", result=plain("Refund handled."))]
    return body


def show(history: Events, numbered: bool = True) -> dict[str, Any]:
    return {"events": number(history) if numbered else history, "source": "workflow-show"}


def cloud(*histories: Events) -> dict[str, Any]:
    return {"items": [{"history": {"events": number(h)}} for h in histories],
            "source": "cloud-export"}


def permit(*, attempt: int = 1, args: dict[str, Any] | None = None,
           model_args: dict[str, Any] | None = None, code: str = CODE,
           approvals: tuple[str, ...] = (UPDATE,), **extra: Any) -> dict[str, Any]:
    refund_args = ARGS if args is None else args
    body = {
        "activityId": "4", "approvalIds": list(approvals),
        "argsDigest": reader.digest(refund_args), "attempt": attempt,
        "authorityKeyId": "key:authority-1", "callId": CALL,
        "expiresAt": "2026-11-08T12:05:00Z", "grantDigest": GRANT,
        "issuedAt": "2026-11-08T12:00:00Z", "modelActivityId": "3",
        "modelArgsDigest": reader.digest(refund_args if model_args is None else model_args),
        "permitId": f"permit-{WORKFLOW}-4-{attempt}", "runId": RUN, "srl": SRL,
        "tool": "issue_refund", "toolCodeDigest": code, "workflowId": WORKFLOW,
    }
    body.update(extra)
    return body


def effect(*, attempt: int = 1, outcome: str = "applied", result: Any = RESULT,
           args: dict[str, Any] | None = None, **extra: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "argsDigest": reader.digest(ARGS if args is None else args), "callId": CALL,
        "effectId": f"effect-{WORKFLOW}-4-{attempt}", "grantDigest": GRANT,
        "observedAt": "2026-11-08T12:00:02Z", "observerKeyId": "key:system-of-record-1",
        "outcome": outcome, "permitId": f"permit-{WORKFLOW}-4-{attempt}", "runId": RUN,
        "srl": SRL, "workflowId": WORKFLOW,
    }
    if result is not None:
        body["resultDigest"] = reader.digest(result)
    body.update(extra)
    return body


def record(exports: list[dict[str, Any]] | None = None, *,
           permits: list[dict[str, Any]] | None = None,
           effects: list[dict[str, Any]] | None = None,
           contract: str | None = reader.CONTRACT_ID) -> Record:
    """One record; every argument is a departure from the conformant record."""
    body: Record = {
        "exports": exports if exports is not None else [show(events())],
        "witnessed": {
            "effects": effects if effects is not None else [effect()],
            "expectedToolCodeDigest": CODE, "gatedTools": ["issue_refund"],
            "permits": permits if permits is not None else [permit()],
            "runId": RUN, "workflowId": WORKFLOW,
        },
    }
    if contract is not None:
        body["contractId"] = contract
    return body


def broken(mutate: Callable[[Record], Any], base: Record | None = None) -> Record:
    """A record with one change applied by ``mutate``."""
    body = copy.deepcopy(record() if base is None else base)
    mutate(body)
    return body


def _event(body: Record, event_id: int) -> dict[str, Any]:
    found: dict[str, Any] = body["exports"][0]["events"][event_id - 1]
    return found


def _refund_event(history: Events, kind: str) -> int:
    """The id of the refund activity's schedule or close event in a numbered history."""
    at = next(e["eventId"] for e in history
              if e["eventType"] == reader.SCHEDULED and e["attributes"]["activityId"] == "4")
    if kind == reader.SCHEDULED:
        return at
    return next(e["eventId"] for e in history
                if e["eventType"] == kind and e["attributes"].get("scheduledEventId") == at)


# ---------------------------------------------------------------- shapes


def _codec_record(**overrides: Any) -> Record:
    """The run under an encrypting payload codec, witnessed by ciphertext digest."""
    history = events(seal=True, **overrides)
    numbered = number(history)
    refund_in = numbered[_refund_event(numbered, reader.SCHEDULED) - 1]["attributes"]["input"]
    refund_out = numbered[_refund_event(numbered, reader.COMPLETED) - 1]["attributes"]["result"]
    model_out = next(e for e in numbered if e["eventType"] == reader.COMPLETED
                     and e["attributes"]["scheduledEventId"] == 9)["attributes"]["result"]
    return record(
        [show(history)],
        permits=[permit(inputCiphertextDigest=cipher_digest(refund_in),
                        modelResponseCiphertextDigest=cipher_digest(model_out))],
        effects=[effect(resultCiphertextDigest=cipher_digest(refund_out))])


def _flip_byte(payload: dict[str, Any]) -> None:
    raw = bytearray(reader.ciphertext(payload))
    raw[-1] ^= 0x01
    payload["data"] = base64.b64encode(bytes(raw)).decode("ascii")


def _reset_event(point: int) -> Events:
    return [ev(reader.RESET, newRunId=FORK, resetEventId=point)]


def _last_witnessed() -> int:
    return _refund_event(number(events()), reader.COMPLETED)


def _forked(point: int) -> Events:
    return events(run=FORK, reset_from={"baseRunId": RUN, "resetEventId": point})


def _other_workflow() -> Events:
    history = events()
    history[0] = ev(reader.STARTED, runId="run-0009", workflowId="refund-T-200")
    return history


Case = tuple[str, Record, str, str, str]
LOST = effect(outcome="uncertain", result=None)
SETTLED = effect(outcome="uncertain", result=None, settlement={
    "observerKeyId": "key:system-of-record-1", "outcome": "applied",
    "resultDigest": reader.digest(RESULT), "settledAt": "2026-11-08T12:10:00Z",
    "source": reader.SYSTEM_OF_RECORD})
RETRY_PERMITS = [permit(attempt=1), permit(attempt=2)]
FAILED_FIRST = effect(attempt=1, outcome="not-applied", result=None)
APPLIED_FIRST = effect(attempt=1)
EDITED = {**ARGS, "amountCents": 20}
MALLORY = {**ARGS, "amountCents": 499900, "payeeAccount": "acct-mallory-offshore"}
OVERRIDE = {**ARGS, "amountCents": 1500}


def controls() -> list[Case]:
    last = _last_witnessed()
    return [
        ("allow-clean-run", record(), "allow", reader.ALLOW_REASON,
         "control: the exported history matches every witnessed record"),
        ("allow-witnessed-retry",
         record([show(events(attempt=2))], permits=RETRY_PERMITS,
                effects=[FAILED_FIRST, effect(attempt=2)]),
         "allow", reader.ALLOW_REASON,
         "control: the first attempt failed before any effect and the second, also permitted, "
         "applied; the history records one completion, of attempt 2"),
        ("allow-codec-encrypted-run", _codec_record(), "allow", reader.ALLOW_REASON,
         "control: every payload is encrypted and each witnessed one matches its witnessed "
         "ciphertext"),
        ("allow-cloud-export-run", record([cloud(events())]), "allow", reader.ALLOW_REASON,
         "control: the same run, read from a cloud export file"),
        ("allow-cloud-export-duplicate-delivery",
         record([cloud(_other_workflow(), events(), events())]), "allow", reader.ALLOW_REASON,
         "control: at-least-once delivery put the witnessed run in the file twice, beside "
         "another workflow's run"),
        ("allow-lost-reply-settled-from-system-of-record",
         record(effects=[SETTLED]), "allow", reader.ALLOW_REASON,
         "control: the reply was lost, the system of record settled the call as applied, and "
         "the activity was completed with that settled result"),
        ("allow-lost-reply-left-uncertain",
         record([show(events(refund_close=reader.TIMED_OUT))], effects=[LOST]),
         "allow", reader.ALLOW_REASON,
         "control: the reply was lost and the history honestly records a timeout"),
        ("allow-reset-after-last-witnessed-event",
         record([show(events(extra=_reset_event(last)))]), "allow", reader.ALLOW_REASON,
         "control: the run was reset to the last witnessed event, so every witnessed event "
         "stays in force"),
        ("allow-approved-argument-override",
         record([show(events(args=OVERRIDE, model_args=ARGS))],
                permits=[permit(args=OVERRIDE, model_args=ARGS)],
                effects=[effect(args=OVERRIDE)]),
         "allow", reader.ALLOW_REASON,
         "control: the approver lowered the amount; the model's request and the permitted, "
         "scheduled arguments differ, and both were witnessed"),
        ("allow-declined-refund-recorded-as-declined",
         record([show(events(result=DECLINED))],
                effects=[effect(outcome="not-applied", result=DECLINED)]),
         "allow", reader.ALLOW_REASON,
         "control: the processor declined and the history records the decline"),
        ("allow-distinct-update-ids",
         record([show(events(updates=(UPDATE, "approve-call-refund-T-100-note")))]),
         "allow", reader.ALLOW_REASON, "control: two Updates with distinct ids"),
        ("allow-ungated-tool-without-permit",
         record([show(events(extra=[
             scheduled("5", "tool:read_ticket", plain({"args": {"ticketId": "T-101"},
                                                       "callId": "call-read-T-101"})),
             closed(reader.COMPLETED, "5", result=plain(TICKET))]))]),
         "allow", reader.ALLOW_REASON,
         "control: a second ticket read, a tool nobody gates, ran with no permit"),
    ]


def history_attacks() -> list[Case]:
    last = _last_witnessed()
    return [
        ("reset-before-witnessed-event",
         record([show(events(extra=_reset_event(last - 1)))]), "deny", "history_reset",
         "the run was reset one event before the refund completed, so the reset discards a "
         "witnessed event and a new run supersedes it"),
        ("reset-fork-exported-instead",
         record([show(_forked(4))]), "deny", "history_reset",
         "the operator reset the run and exported the forked run in place of the witnessed one"),
        ("reset-fork-point-before-witnessed",
         record([cloud(events(), _forked(10))]), "deny", "history_reset",
         "the export carries the witnessed run and a fork reset to a point before the refund"),
        ("run-deleted", record([]), "deny", "witnessed_run_missing_from_history",
         "the operator deleted the run; the export holds nothing"),
        ("cloud-export-without-run", record([cloud(_other_workflow())]), "deny",
         "witnessed_run_missing_from_history",
         "the cloud export file carries another workflow's run and not the witnessed one"),
        ("different-run-exported",
         record([show(events(run="run-0003"))]), "deny", "witnessed_run_missing_from_history",
         "the export is a run of the same workflow with another run id and no reset link"),
        ("event-moved",
         broken(lambda r: r["exports"][0]["events"].insert(
             2, r["exports"][0]["events"].pop(5))), "deny", "event_sequence_broken",
         "an event was moved without renumbering, so event ids no longer run in order"),
        ("event-dropped-leaving-gap",
         broken(lambda r: r["exports"][0]["events"].pop(4)), "deny", "event_sequence_broken",
         "an event was removed and the ids after it were left as they were"),
        ("completion-before-schedule",
         broken(lambda r: _event(r, _refund_event(r["exports"][0]["events"],
                                                  reader.COMPLETED))["attributes"].update(
             scheduledEventId=_last_witnessed() + 3)),
         "deny", "event_sequence_broken",
         "the refund's completion points at a schedule event later than itself"),
        ("second-completion-for-one-schedule",
         record([show(events(extra=[closed(reader.COMPLETED, "4", result=plain(RESULT))]))]),
         "deny", "event_sequence_broken", "one scheduled activity is completed twice"),
    ]


def codec_attacks() -> list[Case]:
    def keyless_edit(r: Record) -> None:
        history = r["exports"][0]["events"]
        _flip_byte(history[_refund_event(history, reader.SCHEDULED) - 1]["attributes"]["input"])

    def moved(r: Record) -> None:
        history = r["exports"][0]["events"]
        ticket = copy.deepcopy(history[6]["attributes"]["result"])
        history[_refund_event(history, reader.COMPLETED) - 1]["attributes"]["result"] = ticket

    def stripped(r: Record) -> None:
        history = r["exports"][0]["events"]
        history[_refund_event(history, reader.SCHEDULED) - 1]["attributes"]["input"] = plain(
            {"args": MALLORY, "callId": CALL})

    def reencrypted(r: Record) -> None:
        history = r["exports"][0]["events"]
        history[_refund_event(history, reader.SCHEDULED) - 1]["attributes"]["input"] = sealed(
            {"args": MALLORY, "callId": CALL}, "in-4-edited")

    base = _codec_record()
    return [
        ("codec-keyless-ciphertext-edit", broken(keyless_edit, base), "deny",
         "encrypted_payload_differs_from_witnessed",
         "an editor without the codec key changed the refund input's ciphertext; it no longer "
         "decrypts, and it is not the ciphertext witnessed"),
        ("codec-ciphertext-moved-between-events", broken(moved, base), "deny",
         "encrypted_payload_differs_from_witnessed",
         "a valid ciphertext was copied from the ticket read's result onto the refund's result; "
         "a codec with no associated data decrypts it"),
        ("codec-stripped-and-edited", broken(stripped, base), "deny",
         "encrypted_payload_differs_from_witnessed",
         "the refund input was stored as edited plaintext where a ciphertext was witnessed"),
        ("codec-key-holder-reencrypted-edit", broken(reencrypted, base), "deny",
         "encrypted_payload_differs_from_witnessed",
         "the operator, who holds the codec key, encrypted edited arguments; the codec accepts "
         "them and the witnessed ciphertext does not"),
    ]


def edit_attacks() -> list[Case]:
    def remove_model_call(r: Record) -> None:
        r["exports"][0]["events"][9]["attributes"]["result"]["data"]["toolCalls"] = []

    return [
        ("model-args-edited",
         record([show(events(model_args=MALLORY))]), "deny",
         "model_request_differs_from_witnessed",
         "only the model's recorded request was edited: the history says the model asked to pay "
         "the attacker while it scheduled the permitted refund"),
        ("model-call-removed", broken(remove_model_call), "deny",
         "model_request_differs_from_witnessed",
         "the model's request for the refund was removed from its recorded response"),
        ("store-edit-amount",
         record([show(events(args=EDITED))]), "deny", "history_args_differ_from_permitted",
         "the operator edited the store: the model's request and the scheduled input both say "
         "20 cents, consistently, where 2000 was permitted"),
        ("consistent-rewrite",
         record([show(events(args=EDITED, result={**RESULT, "amountCents": 20}))]), "deny",
         "history_args_differ_from_permitted",
         "every payload was rewritten to tell one coherent story of a 20-cent refund"),
        ("scheduled-tool-changed",
         record([show(events(tool="issue_credit"))]), "deny",
         "history_args_differ_from_permitted",
         "the activity is recorded as another tool than the one permitted"),
        ("result-edited",
         record([show(events(result=RESULT))],
                effects=[effect(outcome="not-applied", result=DECLINED)]),
         "deny", "history_result_differs_from_witnessed",
         "the processor declined, and the recorded result was edited to say applied"),
        ("result-without-witnessed-effect", record(effects=[]), "deny",
         "history_result_differs_from_witnessed",
         "the history records a result for a permitted attempt whose effect nobody witnessed"),
        ("settled-result-differs",
         record([show(events(result={**RESULT, "ref": "RF-0042"}))], effects=[SETTLED]),
         "deny", "history_result_differs_from_witnessed",
         "the lost reply was settled by the system of record, and the history records another "
         "result"),
        ("tool-code-changed",
         record(permits=[permit(code=OTHER_CODE)]), "deny", "tool_code_changed",
         "the permit names tool code other than the measured launch's; the history is "
         "untouched, so replay passes"),
    ]


def effect_attacks() -> list[Case]:
    def remove_refund(r: Record) -> None:
        r["exports"] = [show([e for e in events() if e["attributes"].get("activityId") != "4"
                              and e["attributes"].get("activity") != "4"])]

    return [
        ("hidden-retry",
         record([show(events(attempt=2))], permits=[permit(attempt=1)], effects=[FAILED_FIRST]),
         "deny", "activity_unwitnessed",
         "attempt 1 was permitted and failed; attempt 2 completed with no permit"),
        ("injected-refund-activity",
         record([show(events(extra=[
             scheduled("5", "tool:issue_refund",
                       plain({"args": MALLORY, "callId": "call-refund-T-100-b"})),
             closed(reader.COMPLETED, "5", result=plain({**RESULT, "ref": "RF-0002"}))]))]),
         "deny", "activity_unwitnessed", "a second refund activity ran with no permit"),
        ("witnessed-activity-removed", broken(remove_refund), "deny",
         "witnessed_effect_missing",
         "the permitted refund activity was removed from the history and the ids renumbered"),
        ("applied-effect-recorded-as-timeout",
         record([show(events(refund_close=reader.TIMED_OUT))]), "deny",
         "witnessed_effect_missing",
         "the system of record applied the refund, and the history says the activity timed out"),
        ("retry-both-attempts-applied",
         record([show(events(attempt=2))], permits=RETRY_PERMITS,
                effects=[APPLIED_FIRST, effect(attempt=2)]),
         "deny", "witnessed_effect_missing",
         "both attempts applied a refund and the history records only the second"),
        ("update-accepted-twice",
         record([show(events(updates=(UPDATE, UPDATE)))]), "deny", "update_applied_twice",
         "one approval Update id is accepted twice"),
        ("lost-reply-recorded-as-completed",
         record(effects=[LOST]), "deny", "lost_reply_settled_without_evidence",
         "the reply was lost and the outcome is uncertain, and the history records the "
         "activity as completed with a result"),
        ("lost-reply-settled-by-worker",
         record(effects=[{**SETTLED, "settlement": {**SETTLED["settlement"],
                                                    "source": "worker"}}]),
         "deny", "lost_reply_settled_without_evidence",
         "the lost reply was settled by the operator's own worker, not the system of record"),
        ("lost-reply-settled-not-applied",
         record(effects=[{**SETTLED, "settlement": {
             **{k: v for k, v in SETTLED["settlement"].items() if k != "resultDigest"},
             "outcome": "not-applied"}}]),
         "deny", "lost_reply_settled_without_evidence",
         "the system of record settled the lost reply as not applied, and the history records "
         "a completion"),
    ]


def _replace(body: Record, path: tuple[Any, ...], value: Any) -> None:
    target = body
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value


def malformed() -> list[Case]:
    def bad(path: tuple[Any, ...], value: Any) -> Record:
        return broken(lambda r: _replace(r, path, value))

    return [
        ("malformed-exports-not-list", bad(("exports",), {"events": []}), "deny",
         "malformed_record", "the exports are an object instead of a list"),
        ("malformed-unknown-source", bad(("exports", 0, "source"), "archive"), "deny",
         "malformed_record", "the export names a source the contract does not read"),
        ("malformed-event-id-text", bad(("exports", 0, "events", 0, "eventId"), "1"), "deny",
         "malformed_record", "an event id is text"),
        ("malformed-started-event-missing",
         broken(lambda r: r["exports"][0]["events"].pop(0)), "deny", "malformed_record",
         "the run has no start event, so it names no run"),
        ("malformed-payload-encoding-unknown",
         bad(("exports", 0, "events", 13, "attributes", "input", "encoding"), "binary/zstd"),
         "deny", "malformed_record", "a payload names an encoding the contract does not read"),
        ("malformed-ciphertext-not-base64",
         broken(lambda r: _replace(r, ("exports", 0, "events", 13, "attributes", "input",
                                       "data"), "not!base64"), _codec_record()),
         "deny", "malformed_record", "a ciphertext is not base64"),
        ("malformed-permit-digest",
         bad(("witnessed", "permits", 0, "argsDigest"), "sha256:XYZ"), "deny",
         "malformed_record", "a permit's arguments digest is not a sha256 digest"),
        ("malformed-effect-permit-unknown",
         bad(("witnessed", "effects", 0, "permitId"), "permit-unknown"), "deny",
         "malformed_record", "a witnessed effect names a permit that was never issued"),
        ("malformed-effect-outcome-unknown",
         bad(("witnessed", "effects", 0, "outcome"), "probably"), "deny", "malformed_record",
         "a witnessed effect's outcome is outside applied, not-applied and uncertain"),
        ("malformed-settlement-on-applied-effect",
         bad(("witnessed", "effects", 0, "settlement"), SETTLED["settlement"]), "deny",
         "malformed_record", "an effect that was observed applied also carries a settlement"),
        ("malformed-permit-time",
         bad(("witnessed", "permits", 0, "issuedAt"), "soon"), "deny", "malformed_record",
         "a permit's issue time is not an RFC 3339 instant"),
        ("contract-id-missing", record(contract=None), "deny", "contract_id_missing",
         "the record names no contract"),
        ("contract-id-unknown",
         record(contract=reader.CONTRACT_ID.replace("/v1", "/v0")), "deny",
         "contract_id_unknown", "the record names a contract version that does not exist"),
    ]


def cases() -> list[Case]:
    """Every case: id, record, expected decision and reason, and what it departs from."""
    return [*controls(), *history_attacks(), *codec_attacks(), *edit_attacks(),
            *effect_attacks(), *malformed()]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
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
