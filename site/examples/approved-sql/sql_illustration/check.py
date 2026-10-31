"""Compare supplied approval, application, audit, and later state records."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROFILE = "oel-approved-sql-illustration/v1"
ORIGIN = "author-created-fixture"


class InvalidInput(ValueError):
    """The document does not follow this illustration's input contract."""


@dataclass(frozen=True)
class Target:
    """The exact database context supplied with a record."""

    instance: str
    database: str
    schema: str


@dataclass(frozen=True)
class Parameter:
    """A position, database type, and exact value bytes; None means SQL NULL."""

    position: int
    database_type: str
    value: bytes | None


@dataclass(frozen=True)
class Call:
    """The supplied request and its execution inputs."""

    request_id: str
    sql: bytes
    parameters: tuple[Parameter, ...]
    target: Target
    executing_principal: str


def _object(value: object, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise InvalidInput(f"{label}: expected exactly {sorted(keys)}")
    return value


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidInput(f"{label}: expected nonempty text")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise InvalidInput(f"{label}: invalid Unicode") from exc
    return value


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        raise InvalidInput(f"{label}: expected a boolean")
    return value


def _bytes(value: object, label: str) -> bytes:
    if not isinstance(value, str):
        raise InvalidInput(f"{label}: expected canonical base64")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidInput(f"{label}: invalid base64") from exc
    if base64.b64encode(decoded).decode("ascii") != value:
        raise InvalidInput(f"{label}: noncanonical base64")
    return decoded


def _target(value: object) -> Target:
    obj = _object(value, {"instance", "database", "schema"}, "target")
    return Target(*(_text(obj[name], name) for name in ("instance", "database", "schema")))


def _parameter(value: object, position: int) -> Parameter:
    obj = _object(value, {"position", "database_type", "value_b64"}, "parameter")
    if type(obj["position"]) is not int or obj["position"] != position:
        raise InvalidInput("parameters: positions must be 1, 2, ... in list order")
    return Parameter(
        position,
        _text(obj["database_type"], "database_type"),
        None if obj["value_b64"] is None else _bytes(obj["value_b64"], "parameter value"),
    )


def _call(value: object) -> Call:
    obj = _object(
        value,
        {"request_id", "sql_utf8_b64", "parameters", "target", "executing_principal"},
        "call",
    )
    sql = _bytes(obj["sql_utf8_b64"], "sql_utf8_b64")
    try:
        sql.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidInput("SQL must be exact UTF-8 bytes in this illustration") from exc
    if not sql or not isinstance(obj["parameters"], list):
        raise InvalidInput("call: SQL must be nonempty and parameters must be a list")
    return Call(
        _text(obj["request_id"], "request_id"),
        sql,
        tuple(_parameter(p, i) for i, p in enumerate(obj["parameters"], 1)),
        _target(obj["target"]),
        _text(obj["executing_principal"], "executing_principal"),
    )


def _outcome(value: object) -> dict[str, str]:
    obj = _object(value, {"statement", "transaction"}, "outcome")
    statement = _text(obj["statement"], "statement")
    transaction = _text(obj["transaction"], "transaction")
    if statement not in {"succeeded", "failed"}:
        raise InvalidInput("statement: expected succeeded or failed")
    if transaction not in {"committed", "rolled_back", "unknown"}:
        raise InvalidInput("transaction: expected committed, rolled_back, or unknown")
    return {"statement": statement, "transaction": transaction}


def _record(value: object, *, audit: bool) -> tuple[Call, dict[str, str], str | None]:
    keys = {"call", "outcome", "event_id"} if audit else {"call", "outcome"}
    obj = _object(value, keys, "audit record" if audit else "application record")
    event_id = _text(obj["event_id"], "event_id") if audit else None
    return _call(obj["call"]), _outcome(obj["outcome"]), event_id


def _differences(left: Call, right: Call) -> list[str]:
    pairs = {
        "request_id": (left.request_id, right.request_id),
        "sql_bytes": (left.sql, right.sql),
        "typed_parameters": (left.parameters, right.parameters),
        "database_instance": (left.target.instance, right.target.instance),
        "database": (left.target.database, right.target.database),
        "schema": (left.target.schema, right.target.schema),
        "executing_principal": (left.executing_principal, right.executing_principal),
    }
    return [name for name, (a, b) in pairs.items() if a != b]


def _later(value: object, target: Target) -> str:
    if value is None:
        return "not_supplied"
    obj = _object(value, {"target", "resource", "at_commit_b64", "later_b64"}, "later_state")
    supplied_target = _target(obj["target"])
    _text(obj["resource"], "resource")
    at_commit = _bytes(obj["at_commit_b64"], "at_commit_b64")
    later = _bytes(obj["later_b64"], "later_b64")
    if supplied_target != target:
        return "target_not_comparable"
    return "supplied_state_unchanged" if at_commit == later else "supplied_state_differs"


def _matched_result(
    granted: bool,
    approval_difference: list[str],
    application_difference: list[str] | None,
    outcome: dict[str, str],
) -> str:
    if not granted:
        return "approval_not_granted"
    if approval_difference:
        return "execution_differs_from_approval"
    if application_difference is None:
        return "application_record_missing"
    if application_difference:
        return "application_audit_disagreement"
    if outcome["statement"] == "failed":
        return "statement_failed"
    if outcome["transaction"] == "rolled_back":
        return "transaction_rolled_back"
    if outcome["transaction"] == "unknown":
        return "commit_not_established"
    return "recorded_commit_matches"


def assess(document: object) -> dict[str, Any]:
    """Assess this author-created projection; do not authenticate native records."""
    obj = _object(
        document,
        {"profile", "origin", "approval", "application", "audit", "later_state"},
        "document",
    )
    if obj["profile"] != PROFILE or obj["origin"] != ORIGIN:
        raise InvalidInput("expected the author-created illustration profile and origin")
    approval = _object(obj["approval"], {"granted", "call"}, "approval")
    granted = _boolean(approval["granted"], "granted")
    approved_call = _call(approval["call"])
    application = None if obj["application"] is None else _record(obj["application"], audit=False)
    audit = _object(obj["audit"], {"scope", "complete", "records"}, "audit")
    complete = _boolean(audit["complete"], "complete")
    scope = _object(audit["scope"], {"request_id", "target", "window_label"}, "audit scope")
    scope_request = _text(scope["request_id"], "scope request_id")
    scope_target = _target(scope["target"])
    scope_window = _text(scope["window_label"], "window_label")
    if not isinstance(audit["records"], list):
        raise InvalidInput("audit records must be a list")
    records = [_record(row, audit=True) for row in audit["records"]]
    if len({row[2] for row in records}) != len(records):
        raise InvalidInput("duplicate audit event_id")
    matching = [row for row in records if row[0].request_id == approved_call.request_id]
    scoped_complete = (
        complete
        and scope_request == approved_call.request_id
        and scope_target == approved_call.target
    )
    result: dict[str, Any] = {
        "profile": PROFILE,
        "origin": ORIGIN,
        "approval_granted": granted,
        "application_present": application is not None,
        "application_outcome": None if application is None else application[1],
        "audit_matches": len(matching),
        "declared_audit_scope": {
            "request_id": scope_request,
            "target": {
                "instance": scope_target.instance,
                "database": scope_target.database,
                "schema": scope_target.schema,
            },
            "window_label": scope_window,
            "complete": complete,
            "matches_approval": scope_request == approved_call.request_id
            and scope_target == approved_call.target,
        },
        "approval_audit_differences": None,
        "application_audit_differences": None,
        "later_state": _later(obj["later_state"], approved_call.target),
        "later_change_attribution": "not_assessed",
    }
    if not matching:
        result["result"] = (
            "no_match_in_declared_complete_scope"
            if scoped_complete
            else "insufficient_audit_evidence"
        )
    elif len(matching) != 1:
        result["result"] = "ambiguous_database_join"
    else:
        actual_call, outcome, event_id = matching[0]
        approval_diff = _differences(approved_call, actual_call)
        application_diff = None
        if application is not None:
            application_diff = _differences(application[0], actual_call)
            if application[1] != outcome:
                application_diff.append("outcome")
        result.update(
            {
                "audit_event_id": event_id,
                "audit_outcome": outcome,
                "approval_audit_differences": approval_diff,
                "application_audit_differences": application_diff,
                "result": _matched_result(granted, approval_diff, application_diff, outcome),
            }
        )
    return result


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    obj: dict[str, object] = {}
    for key, value in pairs:
        if key in obj:
            raise InvalidInput(f"duplicate JSON key: {key}")
        obj[key] = value
    return obj


def _reject_constant(value: str) -> None:
    raise InvalidInput(f"invalid JSON constant: {value}")


def read(path: Path) -> object:
    """Read strict JSON without duplicate keys or nonstandard numeric constants."""
    try:
        return json.loads(
            path.read_bytes(), object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
    except (OSError, UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise InvalidInput(str(exc)) from exc


def main(argv: list[str] | None = None) -> int:
    """Print an assessment; return 0 for a matching recorded commit, 1 otherwise."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("document", type=Path)
    args = parser.parse_args(argv)
    try:
        result = assess(read(args.document))
    except InvalidInput as exc:
        print(json.dumps({"result": "invalid_input", "error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["result"] == "recorded_commit_matches" else 1


if __name__ == "__main__":
    raise SystemExit(main())
