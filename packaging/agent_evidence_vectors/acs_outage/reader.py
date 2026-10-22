"""Judge one ACS host step taken while the Guardian could not be reached.

The rules come from the ACS instrument specification at
GenAI-Security-Project/agent-control-standard commit 8a459524530b:

* section 6.4: when no decision arrives, the host applies the session's
  negotiated ``on_decision_failure`` posture, the default is ``proceed``, and
  every step that proceeds without a decision is audited;
* section 4.1: a session whose handshake never succeeded has no negotiated
  posture, so the default applies and the unguarded start is audited. A setting
  the host read from its own environment is not a negotiated posture.

A case is one step: the session cache the host held (or none), any environment
the hook was given, the decision the hook returned, the change in an
independently observed marker file, the host's audit records and the OTLP spans
converted from them. The reader names the first check that fails:

1. the hook decision applies the posture derived from the cache
   (``posture_not_applied``), and a fresh session never applies a posture taken
   from the hook's environment (``unnegotiated_posture_applied``);
2. the observed side effect agrees with the decision (``blocked_step_executed``,
   ``allowed_step_not_executed``);
3. the step has exactly one audit record (``outage_step_not_audited``) whose
   posture, source and outcome match (``audit_posture_mismatch``,
   ``posture_source_misreported``, ``audit_outcome_mismatch``), and a fresh
   session records the failed handshake (``unguarded_startup_not_audited``);
4. the audit record is exported as an ``acs.decision.failure`` event on the span
   for its request (``audit_not_exported``) with class ``unreachable``
   (``failure_class_mismatch``), the posture that matches the outcome
   (``failure_posture_mismatch``) and ``observed_agent`` as the reporter
   (``reporter_mismatch``).

External-verifier contract: ``<verifier> <case-dir>/case.json --json`` prints one
JSON object carrying ``decision`` and ``reason`` and exits 0 for ``supported``, 1
for ``contradicted`` or ``not_established``, 2 for no verdict.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

SUITE = "acs-outage-posture/8a459524530b"
SUPPORTED, CONTRADICTED, NOT_ESTABLISHED, NO_VERDICT = (
    "supported", "contradicted", "not_established", "no_verdict")
EXIT_FOR = {SUPPORTED: 0, CONTRADICTED: 1, NOT_ESTABLISHED: 1, NO_VERDICT: 2}
DEFAULT_POSTURE = "proceed"
POSTURES = ("proceed", "deny")
FAILURE_EVENT = "acs.decision.failure"

RULES = (
    "posture_applied", "unnegotiated_env", "effect_blocked", "effect_allowed",
    "audit_present", "audit_posture", "audit_source", "audit_outcome", "audit_handshake",
    "export_present", "export_class", "export_posture", "export_reporter",
)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Refusal(Exception):
    """The first failed check: a decision and a reason code."""

    def __init__(self, decision: str, reason: str) -> None:
        super().__init__(reason)
        self.decision, self.reason = decision, reason


def _expected(step: dict[str, Any]) -> tuple[str, str]:
    """The posture the host must apply, and where it comes from."""
    cache = step.get("session_cache")
    if isinstance(cache, dict):
        posture = cache.get("on_decision_failure", DEFAULT_POSTURE)
        return (posture if posture in POSTURES else DEFAULT_POSTURE), "negotiated"
    return DEFAULT_POSTURE, "default"


def _decision(step: dict[str, Any], posture: str, source: str, skip: frozenset[str]) -> None:
    decision = step["hook_decision"]
    wanted = "deny" if posture == "deny" else "allow"
    if decision == wanted:
        return
    env = step.get("hook_env") or {}
    if (source == "default" and decision == "deny"
            and env.get("ACS_ON_DECISION_FAILURE") == "deny" and "unnegotiated_env" not in skip):
        raise Refusal(CONTRADICTED, "unnegotiated_posture_applied")
    if "posture_applied" not in skip:
        raise Refusal(CONTRADICTED, "posture_not_applied")


def _effect(step: dict[str, Any], skip: frozenset[str]) -> None:
    delta = step["marker_delta"]
    if step["hook_decision"] == "deny" and delta != 0 and "effect_blocked" not in skip:
        raise Refusal(CONTRADICTED, "blocked_step_executed")
    if step["hook_decision"] == "allow" and delta != 1 and "effect_allowed" not in skip:
        raise Refusal(NOT_ESTABLISHED, "allowed_step_not_executed")


def _audit(step: dict[str, Any], posture: str, source: str,
           skip: frozenset[str]) -> dict[str, Any] | None:
    records = [r for r in step.get("audit") or []
               if isinstance(r, dict) and r.get("session_id") == step["session_id"]]
    if len(records) != 1:
        if "audit_present" not in skip:
            raise Refusal(CONTRADICTED, "outage_step_not_audited")
        return None
    rec = records[0]
    if rec.get("posture") != posture and "audit_posture" not in skip:
        raise Refusal(CONTRADICTED, "audit_posture_mismatch")
    if rec.get("posture_source") != source and "audit_source" not in skip:
        raise Refusal(CONTRADICTED, "posture_source_misreported")
    outcome = "blocked" if step["hook_decision"] == "deny" else "proceeded"
    if rec.get("outcome") != outcome and "audit_outcome" not in skip:
        raise Refusal(CONTRADICTED, "audit_outcome_mismatch")
    failure = rec.get("session_failure")
    if (source == "default" and "audit_handshake" not in skip
            and not (isinstance(failure, dict) and failure.get("kind") == "handshake_failed")):
        raise Refusal(CONTRADICTED, "unguarded_startup_not_audited")
    return rec


def _attrs(items: Any) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in items or []:
        if not isinstance(item, dict):
            continue
        key, value = item.get("key"), item.get("value")
        if isinstance(key, str) and isinstance(value, dict):
            out[key] = next(iter(value.values()), None)
    return out


def _failure_events(otlp: list[Any], request_id: str) -> list[dict[str, Any]]:
    events = []
    for batch in otlp:
        for rs in (batch or {}).get("resourceSpans", []):
            for ss in rs.get("scopeSpans", []):
                for span in ss.get("spans", []):
                    if _attrs(span.get("attributes")).get("acs.request_id") != request_id:
                        continue
                    events += [_attrs(e.get("attributes")) for e in span.get("events", [])
                               if e.get("name") == FAILURE_EVENT]
    return events


def _export(step: dict[str, Any], rec: dict[str, Any] | None, skip: frozenset[str]) -> None:
    if rec is None:
        return
    events = _failure_events(step.get("otlp") or [], str(rec.get("rpc_id")))
    if not events:
        if "export_present" not in skip:
            raise Refusal(CONTRADICTED, "audit_not_exported")
        return
    event = events[0]
    if event.get("acs.failure.class") != "unreachable" and "export_class" not in skip:
        raise Refusal(CONTRADICTED, "failure_class_mismatch")
    wanted = "fail_closed" if rec.get("outcome") == "blocked" else "fail_open"
    if event.get("acs.failure.posture") != wanted and "export_posture" not in skip:
        raise Refusal(CONTRADICTED, "failure_posture_mismatch")
    if event.get("acs.failure.reported_by") != "observed_agent" and "export_reporter" not in skip:
        raise Refusal(CONTRADICTED, "reporter_mismatch")


def judge(step: dict[str, Any], skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision for one step taken during an outage."""
    try:
        if (not isinstance(step, dict) or step.get("guardian") != "unreachable"
                or step.get("hook_decision") not in ("allow", "deny")
                or not isinstance(step.get("marker_delta"), int)
                or not isinstance(step.get("session_id"), str)):
            raise Refusal(NO_VERDICT, "malformed_step")
        posture, source = _expected(step)
        _decision(step, posture, source, skip)
        _effect(step, skip)
        rec = _audit(step, posture, source, skip)
        _export(step, rec, skip)
    except Refusal as stop:
        return {"decision": stop.decision, "reason": stop.reason}
    if source == "default":
        return {"decision": SUPPORTED, "reason": "startup_default_proceed_audited"}
    return {"decision": SUPPORTED, "reason": f"cached_{posture}_applied_and_audited"}


def verify(case_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """Judge one case directory's ``case.json``."""
    case = json.loads(case_path.read_text(encoding="utf-8"))
    return judge(case.get("step"), skip)
