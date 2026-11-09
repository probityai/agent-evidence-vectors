"""Judge whether a durable engine's exported history agrees with what was witnessed.

A durable-execution engine keeps a history of every run: the activities it
scheduled, their inputs and their results. That history is the operator's
record. The operator can edit the store, rewrite an exported copy, delete a
run, or reset it into a new run, and replaying the history against the
workflow code still passes, because replay compares activity identifiers and
types and never inputs or results. An encrypting payload codec stops an editor
without the key and does not stop the key holder.

This contract compares one exported history with the records witnessed at
execution time, outside the operator's worker: for each gated tool call a
permit (the exact arguments, the tool, the code that ran, and what the model
asked for) and an effect (what the system of record observed). The history is
read in two export shapes: ``workflow-show`` (one run, ``events``) and
``cloud-export`` (``items[].history.events``, one or more runs per file, and the
same run more than once under at-least-once delivery). Every copy of the
witnessed run is checked.

The reader checks in a fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the durable-history contract (``contract_id_unknown``);
3. the record has the fields and types the contract names, every time parses,
   every digest is well formed, every ciphertext decodes as base64, and each
   witnessed effect belongs to a witnessed permit of the same call
   (``malformed_record``);
4. the witnessed run was not reset at a point before a witnessed event, and the
   export does not offer a run forked from it in its place (``history_reset``);
5. the export holds the witnessed run (``witnessed_run_missing_from_history``);
6. every exported run's event ids run 1, 2, 3 ... in order, the run opens with
   its one start event, and each activity is scheduled once and closed at most
   once, after its schedule (``event_sequence_broken``);
7. every encrypted payload of a witnessed activity is byte for byte the
   ciphertext witnessed at execution, and none was replaced by plaintext
   (``encrypted_payload_differs_from_witnessed``);
8. each permitted activity is scheduled as the permitted tool with the
   permitted call id and arguments (``history_args_differ_from_permitted``);
9. the model's recorded request for each permitted call names the permitted
   tool and the arguments the model was witnessed asking for
   (``model_request_differs_from_witnessed``);
10. each recorded result of a witnessed attempt is the result witnessed for it
    (``history_result_differs_from_witnessed``);
11. every permit names the tool code of the measured launch
    (``tool_code_changed``);
12. every completed attempt of a gated tool has a permit for that attempt
    (``activity_unwitnessed``);
13. every permitted activity is in the history, and every applied effect has a
    completion for its attempt (``witnessed_effect_missing``);
14. no Update id is accepted twice (``update_applied_twice``);
15. no attempt whose witnessed outcome is uncertain is recorded as completed
    unless the system of record settled it as applied
    (``lost_reply_settled_without_evidence``).

A record that passes all fifteen is ``allow`` with reason ``consistent``.

Digests are ``sha256:`` and lowercase hex: of the canonical JSON bytes of an
arguments or result value (sorted keys, no whitespace), and of the decoded
bytes of a ciphertext. The reader recomputes every digest it compares.

The external-verifier contract: ``<verifier> <case-dir>/record.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``allow`` and 1 for ``deny``.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import shlex
import subprocess
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

SUITE = "durable-history/v1"
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/contract/durable-history/v1"
ALLOW, DENY = "allow", "deny"
ALLOW_REASON = "consistent"
EXIT_FOR = {ALLOW: 0, DENY: 1}
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "malformed_record",
    "history_reset",
    "witnessed_run_missing_from_history",
    "event_sequence_broken",
    "encrypted_payload_differs_from_witnessed",
    "history_args_differ_from_permitted",
    "model_request_differs_from_witnessed",
    "history_result_differs_from_witnessed",
    "tool_code_changed",
    "activity_unwitnessed",
    "witnessed_effect_missing",
    "update_applied_twice",
    "lost_reply_settled_without_evidence",
)
PLAIN, ENCRYPTED = "json/plain", "binary/encrypted"
SOURCES = ("workflow-show", "cloud-export")
OUTCOMES = ("applied", "not-applied", "uncertain")
SYSTEM_OF_RECORD = "system-of-record"
MODEL_ACTIVITY = "model_request"
TOOL_PREFIX = "tool:"
STARTED, SCHEDULED = "WorkflowExecutionStarted", "ActivityTaskScheduled"
COMPLETED, TIMED_OUT = "ActivityTaskCompleted", "ActivityTaskTimedOut"
UPDATE_ACCEPTED, RESET = "WorkflowExecutionUpdateAccepted", "WorkflowExecutionReset"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-durable-history" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "corpora" / "vectors-durable-history")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def canonical(value: object) -> bytes:
    """The canonical JSON bytes a value digest is taken over."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def digest(value: object) -> str:
    """The digest of a JSON value: of its canonical bytes."""
    return "sha256:" + _sha(canonical(value))


def bytes_digest(data: bytes) -> str:
    return "sha256:" + _sha(data)


def ciphertext(payload: dict[str, Any]) -> bytes:
    """The decoded bytes of an encrypted payload."""
    return base64.b64decode(payload["data"], validate=True)


# ---------------------------------------------------------------- structure


def _is_int(value: Any, low: int = 0) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= low


def _is_text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _is_time(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _payload_ok(payload: Any) -> bool:
    if not isinstance(payload, dict) or "data" not in payload:
        return False
    if payload.get("encoding") == PLAIN:
        return True
    if payload.get("encoding") != ENCRYPTED or not _is_text(payload.get("keyId")):
        return False
    if not isinstance(payload["data"], str):
        return False
    try:
        ciphertext(payload)
    except (binascii.Error, ValueError):
        return False
    return True


def _tool_call_ok(call: Any) -> bool:
    return (isinstance(call, dict) and _is_text(call.get("callId"))
            and _is_text(call.get("tool")) and isinstance(call.get("args"), dict))


def _scheduled_ok(attrs: dict[str, Any]) -> bool:
    kind, payload = attrs.get("activityType"), attrs.get("input")
    if not isinstance(payload, dict) or not _payload_ok(payload):
        return False
    if not (_is_text(attrs.get("activityId")) and _is_text(kind)):
        return False
    if payload["encoding"] != PLAIN or not str(kind).startswith(TOOL_PREFIX):
        return True
    data = payload["data"]
    return isinstance(data, dict) and _is_text(data.get("callId")) and isinstance(
        data.get("args"), dict)


def _started_ok(attrs: dict[str, Any]) -> bool:
    if not (_is_text(attrs.get("workflowId")) and _is_text(attrs.get("runId"))):
        return False
    reset = attrs.get("resetFrom")
    return reset is None or (isinstance(reset, dict) and _is_text(reset.get("baseRunId"))
                             and _is_int(reset.get("resetEventId"), 1))


_ATTRIBUTE_RULES: dict[str, Callable[[dict[str, Any]], bool]] = {
    STARTED: _started_ok,
    SCHEDULED: _scheduled_ok,
    COMPLETED: lambda a: (_is_int(a.get("scheduledEventId"), 1) and _is_int(a.get("attempt"), 1)
                          and _payload_ok(a.get("result"))),
    TIMED_OUT: lambda a: _is_int(a.get("scheduledEventId"), 1) and _is_int(a.get("attempt"), 1),
    UPDATE_ACCEPTED: lambda a: _is_text(a.get("updateId")),
    RESET: lambda a: _is_text(a.get("newRunId")) and _is_int(a.get("resetEventId"), 1),
}


def _event_ok(event: Any) -> bool:
    if not (isinstance(event, dict) and _is_int(event.get("eventId"))
            and _is_text(event.get("eventType")) and isinstance(event.get("attributes"), dict)):
        return False
    rule = _ATTRIBUTE_RULES.get(event["eventType"])
    return rule is None or rule(event["attributes"])


def _histories(export: dict[str, Any]) -> list[Any]:
    """The event lists one export carries, in file order."""
    if export["source"] == "workflow-show":
        return [export["events"]]
    return [item["history"]["events"] for item in export["items"]]


def _export_ok(export: Any) -> bool:
    if not isinstance(export, dict) or export.get("source") not in SOURCES:
        return False
    if export["source"] == "workflow-show":
        shape = isinstance(export.get("events"), list)
    else:
        items = export.get("items")
        shape = isinstance(items, list) and all(
            isinstance(i, dict) and isinstance(i.get("history"), dict)
            and isinstance(i["history"].get("events"), list) for i in items)
    if not shape:
        return False
    for events in _histories(export):
        if not events or not all(_event_ok(e) for e in events):
            return False
        if not any(e["eventType"] == STARTED for e in events):
            return False
    return _model_results_ok(export)


def _model_results_ok(export: dict[str, Any]) -> bool:
    """A plain model response carries a list of well-formed tool calls."""
    for events in _histories(export):
        kinds = {e["eventId"]: e["attributes"]["activityType"] for e in events
                 if e["eventType"] == SCHEDULED}
        for event in events:
            attrs = event["attributes"]
            if (event["eventType"] != COMPLETED or kinds.get(attrs["scheduledEventId"])
                    != MODEL_ACTIVITY or attrs["result"]["encoding"] != PLAIN):
                continue
            data = attrs["result"]["data"]
            calls = data.get("toolCalls") if isinstance(data, dict) else None
            if not isinstance(calls, list) or not all(_tool_call_ok(c) for c in calls):
                return False
    return True


_PERMIT_TEXT = ("permitId", "workflowId", "runId", "callId", "activityId", "tool",
                "modelActivityId", "authorityKeyId")
_PERMIT_DIGESTS = ("grantDigest", "argsDigest", "modelArgsDigest", "toolCodeDigest")
_OPTIONAL_DIGESTS = ("inputCiphertextDigest", "modelResponseCiphertextDigest")


def _srl_ok(entry: dict[str, Any]) -> bool:
    srl = entry.get("srl")
    return srl is None or (isinstance(srl, dict) and _is_int(srl.get("epoch"))
                           and _is_digest(srl.get("digest")))


def _permit_ok(permit: Any) -> bool:
    if not isinstance(permit, dict):
        return False
    if not all(_is_text(permit.get(n)) for n in _PERMIT_TEXT):
        return False
    if not all(_is_digest(permit.get(n)) for n in _PERMIT_DIGESTS):
        return False
    if not all(n not in permit or _is_digest(permit[n]) for n in _OPTIONAL_DIGESTS):
        return False
    approvals = permit.get("approvalIds")
    if approvals is not None and not (isinstance(approvals, list)
                                      and all(_is_text(a) for a in approvals)):
        return False
    return (_is_int(permit.get("attempt"), 1) and _is_time(permit.get("issuedAt"))
            and _is_time(permit.get("expiresAt")) and _srl_ok(permit))


def _settlement_ok(settlement: Any) -> bool:
    if not isinstance(settlement, dict):
        return False
    result = settlement.get("resultDigest")
    return (_is_text(settlement.get("source")) and settlement.get("outcome") in OUTCOMES[:2]
            and _is_time(settlement.get("settledAt")) and _is_text(settlement.get("observerKeyId"))
            and (result is None or _is_digest(result)))


def _effect_ok(effect: Any) -> bool:
    if not isinstance(effect, dict):
        return False
    names = ("effectId", "permitId", "workflowId", "runId", "callId", "observerKeyId")
    if not all(_is_text(effect.get(n)) for n in names):
        return False
    if not (_is_digest(effect.get("grantDigest")) and _is_digest(effect.get("argsDigest"))):
        return False
    if not all(n not in effect or _is_digest(effect[n])
               for n in ("resultDigest", "resultCiphertextDigest")):
        return False
    if effect.get("outcome") not in OUTCOMES or not _is_time(effect.get("observedAt")):
        return False
    if "settlement" in effect and (effect["outcome"] != "uncertain"
                                   or not _settlement_ok(effect["settlement"])):
        return False
    return _srl_ok(effect)


def _witnessed_ok(witnessed: Any) -> bool:
    if not isinstance(witnessed, dict):
        return False
    tools = witnessed.get("gatedTools")
    shape = (_is_text(witnessed.get("workflowId")) and _is_text(witnessed.get("runId"))
             and _is_digest(witnessed.get("expectedToolCodeDigest"))
             and isinstance(tools, list) and bool(tools) and all(_is_text(t) for t in tools)
             and isinstance(witnessed.get("permits"), list) and bool(witnessed["permits"])
             and isinstance(witnessed.get("effects"), list))
    if not shape:
        return False
    if not all(_permit_ok(p) for p in witnessed["permits"]):
        return False
    return all(_effect_ok(e) for e in witnessed["effects"]) and _witness_holds(witnessed)


def _witness_holds(witnessed: dict[str, Any]) -> bool:
    """Permits and effects belong to the witnessed run and to each other."""
    run = (witnessed["workflowId"], witnessed["runId"])
    permits = {p["permitId"]: p for p in witnessed["permits"]}
    attempts = {(p["activityId"], p["attempt"]) for p in witnessed["permits"]}
    if len(permits) != len(witnessed["permits"]) or len(attempts) != len(permits):
        return False
    if any((p["workflowId"], p["runId"]) != run for p in witnessed["permits"]):
        return False
    if len({e["permitId"] for e in witnessed["effects"]}) != len(witnessed["effects"]):
        return False
    for effect in witnessed["effects"]:
        permit = permits.get(effect["permitId"])
        if permit is None or (effect["workflowId"], effect["runId"]) != run:
            return False
        if (effect["callId"], effect["argsDigest"]) != (permit["callId"], permit["argsDigest"]):
            return False
    return True


def _malformed(record: dict[str, Any]) -> bool:
    exports = record.get("exports")
    if not isinstance(exports, list) or not all(_export_ok(e) for e in exports):
        return True
    return not _witnessed_ok(record.get("witnessed"))


# ---------------------------------------------------------------- the runs


class Run:
    """One exported run, indexed by event id and activity."""

    def __init__(self, events: list[dict[str, Any]]) -> None:
        self.events = events
        start = next(e for e in events if e["eventType"] == STARTED)["attributes"]
        self.workflow_id: str = start["workflowId"]
        self.run_id: str = start["runId"]
        self.reset_from: dict[str, Any] | None = start.get("resetFrom")
        self.scheduled = {e["attributes"]["activityId"]: e for e in events
                          if e["eventType"] == SCHEDULED}
        by_event = {e["eventId"]: e["attributes"]["activityId"] for e in self.scheduled.values()}
        self.closes: dict[str, list[dict[str, Any]]] = {}
        for event in events:
            if event["eventType"] in (COMPLETED, TIMED_OUT):
                activity = by_event.get(event["attributes"]["scheduledEventId"])
                if activity is not None:
                    self.closes.setdefault(activity, []).append(event)

    def completion(self, activity: str, attempt: int | None = None) -> dict[str, Any] | None:
        """The completed event of an activity, for one attempt when it is named."""
        for event in self.closes.get(activity, []):
            if event["eventType"] == COMPLETED and attempt in (None,
                                                               event["attributes"]["attempt"]):
                return event
        return None


def _runs(record: dict[str, Any]) -> list[Run]:
    return [Run(events) for export in record["exports"] for events in _histories(export)]


def _copies(record: dict[str, Any]) -> list[Run]:
    """Every exported copy of the witnessed run."""
    witnessed = record["witnessed"]
    return [r for r in _runs(record)
            if (r.workflow_id, r.run_id) == (witnessed["workflowId"], witnessed["runId"])]


def _permits(record: dict[str, Any]) -> list[dict[str, Any]]:
    permits: list[dict[str, Any]] = record["witnessed"]["permits"]
    return permits


def _effect_of(record: dict[str, Any], permit: dict[str, Any]) -> dict[str, Any] | None:
    for effect in record["witnessed"]["effects"]:
        if effect["permitId"] == permit["permitId"]:
            return dict(effect)
    return None


def _pairs(record: dict[str, Any]) -> Iterator[tuple[Run, dict[str, Any]]]:
    for run in _copies(record):
        for permit in _permits(record):
            yield run, permit


# ---------------------------------------------------------------- the checks


def _witnessed_events(record: dict[str, Any], run: Run) -> list[int]:
    """Event ids in ``run`` that belong to a witnessed activity or model request."""
    activities = {p["activityId"] for p in _permits(record)}
    activities |= {p["modelActivityId"] for p in _permits(record)}
    ids: list[int] = []
    for activity in activities & set(run.scheduled):
        ids.append(run.scheduled[activity]["eventId"])
        ids += [e["eventId"] for e in run.closes.get(activity, [])]
    return ids


def _reset(record: dict[str, Any]) -> bool:
    witnessed = record["witnessed"]
    forks = [r.reset_from["resetEventId"] for r in _runs(record)
             if r.reset_from is not None and r.workflow_id == witnessed["workflowId"]
             and r.reset_from["baseRunId"] == witnessed["runId"]]
    copies = _copies(record)
    if not copies:
        return bool(forks)
    for run in copies:
        points = forks + [e["attributes"]["resetEventId"] for e in run.events
                          if e["eventType"] == RESET]
        last = max(_witnessed_events(record, run), default=0)
        if any(point < last for point in points):
            return True
    return False


def _sequence_broken(run: Run) -> bool:
    events = run.events
    if [e["eventId"] for e in events] != list(range(1, len(events) + 1)):
        return True
    if events[0]["eventType"] != STARTED or sum(e["eventType"] == STARTED for e in events) != 1:
        return True
    if len(run.scheduled) != sum(e["eventType"] == SCHEDULED for e in events):
        return True
    scheduled_at = {e["eventId"] for e in run.scheduled.values()}
    for event in events:
        if event["eventType"] in (COMPLETED, TIMED_OUT):
            at = event["attributes"]["scheduledEventId"]
            if at not in scheduled_at or at >= event["eventId"]:
                return True
    return any(len(closes) > 1 for closes in run.closes.values())


def _cipher_differs(payload: dict[str, Any] | None, witnessed: Any) -> bool:
    """An encrypted payload, or a witnessed ciphertext, that the other does not match."""
    if payload is None:
        return False
    if payload["encoding"] != ENCRYPTED:
        return witnessed is not None
    return bool(witnessed != bytes_digest(ciphertext(payload)))


def _result_of(event: dict[str, Any] | None) -> dict[str, Any] | None:
    return None if event is None else dict(event["attributes"]["result"])


def _encrypted_differs(record: dict[str, Any]) -> bool:
    for run, permit in _pairs(record):
        scheduled = run.scheduled.get(permit["activityId"])
        inputs = None if scheduled is None else scheduled["attributes"]["input"]
        if _cipher_differs(inputs, permit.get("inputCiphertextDigest")):
            return True
        model = _result_of(run.completion(permit["modelActivityId"]))
        if _cipher_differs(model, permit.get("modelResponseCiphertextDigest")):
            return True
        effect = _effect_of(record, permit)
        result = _result_of(run.completion(permit["activityId"], permit["attempt"]))
        if effect is not None and _cipher_differs(result, effect.get("resultCiphertextDigest")):
            return True
    return False


def _model_differs(record: dict[str, Any]) -> bool:
    for run, permit in _pairs(record):
        scheduled = run.scheduled.get(permit["modelActivityId"])
        response = _result_of(run.completion(permit["modelActivityId"]))
        if scheduled is None or scheduled["attributes"]["activityType"] != MODEL_ACTIVITY:
            return True
        if response is None:
            return True
        if response["encoding"] != PLAIN:
            continue
        calls = [c for c in response["data"]["toolCalls"] if c["callId"] == permit["callId"]]
        if len(calls) != 1 or calls[0]["tool"] != permit["tool"]:
            return True
        if digest(calls[0]["args"]) != permit["modelArgsDigest"]:
            return True
    return False


def _args_differ(record: dict[str, Any]) -> bool:
    for run, permit in _pairs(record):
        scheduled = run.scheduled.get(permit["activityId"])
        if scheduled is None:
            continue
        attrs = scheduled["attributes"]
        if attrs["activityType"] != TOOL_PREFIX + permit["tool"]:
            return True
        if attrs["input"]["encoding"] != PLAIN:
            continue
        data = attrs["input"]["data"]
        if data["callId"] != permit["callId"] or digest(data["args"]) != permit["argsDigest"]:
            return True
    return False


def _settled_as_applied(effect: dict[str, Any]) -> bool:
    settlement = effect.get("settlement")
    return (isinstance(settlement, dict) and settlement["source"] == SYSTEM_OF_RECORD
            and settlement["outcome"] == "applied")


def _witnessed_result(effect: dict[str, Any] | None) -> tuple[bool, str | None]:
    """Whether the attempt's result is judged here, and the digest witnessed for it."""
    if effect is None:
        return True, None
    if effect["outcome"] != "uncertain":
        return True, effect.get("resultDigest")
    if _settled_as_applied(effect):
        return True, effect["settlement"].get("resultDigest")
    return False, None


def _result_differs(record: dict[str, Any]) -> bool:
    for run, permit in _pairs(record):
        completed = run.completion(permit["activityId"], permit["attempt"])
        result = _result_of(completed)
        if result is None or result["encoding"] != PLAIN:
            continue
        judged, witnessed = _witnessed_result(_effect_of(record, permit))
        if judged and digest(result["data"]) != witnessed:
            return True
    return False


def _code_changed(record: dict[str, Any]) -> bool:
    expected = record["witnessed"]["expectedToolCodeDigest"]
    return any(p["toolCodeDigest"] != expected for p in _permits(record))


def _unwitnessed(record: dict[str, Any]) -> bool:
    gated = {TOOL_PREFIX + t for t in record["witnessed"]["gatedTools"]}
    permitted = {(p["activityId"], p["attempt"]) for p in _permits(record)}
    for run in _copies(record):
        for activity, scheduled in run.scheduled.items():
            if scheduled["attributes"]["activityType"] not in gated:
                continue
            for event in run.closes.get(activity, []):
                if event["eventType"] == COMPLETED and (
                        activity, event["attributes"]["attempt"]) not in permitted:
                    return True
    return False


def _effect_missing(record: dict[str, Any]) -> bool:
    for run, permit in _pairs(record):
        if permit["activityId"] not in run.scheduled:
            return True
        effect = _effect_of(record, permit)
        if (effect is not None and effect["outcome"] == "applied"
                and run.completion(permit["activityId"], permit["attempt"]) is None):
            return True
    return False


def _update_twice(record: dict[str, Any]) -> bool:
    for run in _copies(record):
        ids = [e["attributes"]["updateId"] for e in run.events
               if e["eventType"] == UPDATE_ACCEPTED]
        if len(ids) != len(set(ids)):
            return True
    return False


def _lost_reply(record: dict[str, Any]) -> bool:
    for run, permit in _pairs(record):
        effect = _effect_of(record, permit)
        if effect is None or effect["outcome"] != "uncertain" or _settled_as_applied(effect):
            continue
        if run.completion(permit["activityId"], permit["attempt"]) is not None:
            return True
    return False


def _load(record_path: Path) -> dict[str, Any]:
    record: dict[str, Any] = json.loads(record_path.read_text(encoding="utf-8"))
    return record


def _first_failure(record: dict[str, Any], skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it. The checks after
    the contract checks read a record only once ``malformed_record`` has passed,
    so a skipped ``malformed_record`` lets a malformed record fail in them.
    """
    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "malformed_record": lambda: _malformed(record),
        "history_reset": lambda: _reset(record),
        "witnessed_run_missing_from_history": lambda: not _copies(record),
        "event_sequence_broken": lambda: any(_sequence_broken(r) for r in _runs(record)),
        "encrypted_payload_differs_from_witnessed": lambda: _encrypted_differs(record),
        "history_args_differ_from_permitted": lambda: _args_differ(record),
        "model_request_differs_from_witnessed": lambda: _model_differs(record),
        "history_result_differs_from_witnessed": lambda: _result_differs(record),
        "tool_code_changed": lambda: _code_changed(record),
        "activity_unwitnessed": lambda: _unwitnessed(record),
        "witnessed_effect_missing": lambda: _effect_missing(record),
        "update_applied_twice": lambda: _update_twice(record),
        "lost_reply_settled_without_evidence": lambda: _lost_reply(record),
    }
    for name in CHECKS:
        if name in skip:
            continue
        try:
            if failures[name]():
                return name
        except (KeyError, TypeError, ValueError, IndexError, AttributeError, StopIteration,
                binascii.Error):
            # A record the structural check would have refused. With that check
            # switched off, the failure is a different one, so the tests see it.
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
