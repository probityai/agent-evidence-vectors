"""Write the frozen ot-federation corpus, or with --check report whether it is current.

Every case is one trail of the ot-federation-case/v1 shape with one fault seeded
into a clean base trail, or a positive control. The expected answers are written
here by hand from the case contract; the builder then refuses to write a corpus
the reader disagrees with, so a stale reader cannot freeze its own mistakes.

The corpus is written without sorting keys: the positive control
``evidence_keys_unsorted`` keeps its evidence members in reverse order on disk, and
``evidence_non_ascii`` keeps its non-ASCII characters unescaped, so a reader that
hashes the evidence without sort_keys or with ensure_ascii refuses a good trail.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

PACKAGING = Path(__file__).resolve().parents[1] / "packaging"
sys.path.insert(0, str(PACKAGING))

from agent_evidence_vectors.ot_federation.reader import (  # noqa: E402
    CLAIMS,
    CONTRADICTED,
    ESTABLISHED,
    NOT_ESTABLISHED,
    canonical_sha256,
    evaluate,
)

CORPUS = PACKAGING / "agent_evidence_vectors/ot_federation/corpus"
PID = "6f1c2a90-3b5e-4d7a-9c11-0a2b3c4d5e6f"
OTHER = "0d9e8f7a-6b5c-4d3e-8f21-9a8b7c6d5e4f"
E, C, N = ESTABLISHED, CONTRADICTED, NOT_ESTABLISHED


def _evidence(pid: str = PID, tenant: str = "corpus-site") -> dict[str, Any]:
    return {
        "effect_verification": {
            "status": "EFFECT_VERIFIED",
            "vantage": "same_deployment",
            "verifier_identity": "corpus-observer/v1",
        },
        "lifecycle": {"events": ["assessed", "execution_authorized", "execution_result"]},
        "proposal": {"proposal_id": pid, "tenant": tenant},
    }


def base(decision: str = "verify") -> dict[str, Any]:
    """A trail every claim establishes: one approved, reviewed dispatch, applied and observed."""
    evidence = _evidence()
    return {
        "schema": "ot-federation-case/v1",
        "case_id": "",
        "kind": "positive",
        "fault": None,
        "claim": {
            "proposal_id": PID,
            "tool": "set_zone_setpoint",
            "zone_id": "ZONE-03",
            "setpoint_c": 21.5,
            "claimed_effect": "EFFECT_VERIFIED",
        },
        "decision": {
            "decision": decision,
            "approved": True,
            "reasons": [],
            "reviewer": {"approved": True, "model": "corpus-reviewer"},
        },
        "execution": {"executed": True, "executions": 1, "dispatched_at_sim_s": 7200},
        "twin_operation": {
            "operation_id": PID,
            "zone_id": "ZONE-03",
            "status": "APPLIED",
            "requested_setpoint_c": 21.5,
            "new_setpoint_c": 21.5,
            "previous_setpoint_c": 20.0,
            "sim_time_s": 7200,
        },
        "observation": {"observed_setpoint_c": 21.5, "observed_at_sim_s": 7260},
        "remora_envelope": {
            "request": {"request_id": PID, "proposed_action": "set_zone_setpoint"},
            "effect": {"ledger_entry": {"effect_vantage": "same_deployment"}},
        },
        "remora_evidence": evidence,
        "evidence_sha256": canonical_sha256(evidence),
    }


def _redigest(c: dict[str, Any]) -> None:
    c["evidence_sha256"] = canonical_sha256(c["remora_evidence"])


def _reversed(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _reversed(value[k]) for k in sorted(value, reverse=True)}
    if isinstance(value, list):
        return [_reversed(v) for v in value]
    return value


def _set(path: str, value: Any) -> Callable[[dict[str, Any]], None]:
    def edit(c: dict[str, Any]) -> None:
        *parents, last = path.split(".")
        node = c
        for p in parents:
            node = node[p]
        node[last] = value

    return edit


def _drop(path: str) -> Callable[[dict[str, Any]], None]:
    def edit(c: dict[str, Any]) -> None:
        *parents, last = path.split(".")
        node = c
        for p in parents:
            node = node[p]
        del node[last]

    return edit


def _all(*edits: Callable[[dict[str, Any]], None]) -> Callable[[dict[str, Any]], None]:
    def edit(c: dict[str, Any]) -> None:
        for e in edits:
            e(c)

    return edit


def _evidence_other_proposal(c: dict[str, Any]) -> None:
    c["remora_evidence"]["proposal"]["proposal_id"] = OTHER
    _redigest(c)


def _no_binding(c: dict[str, Any]) -> None:
    del c["remora_envelope"]["request"]["request_id"]
    del c["remora_evidence"]["proposal"]
    _redigest(c)


def _non_ascii(c: dict[str, Any]) -> None:
    c["remora_evidence"]["proposal"]["tenant"] = "Zürich Süd, 21,5 °C"
    _redigest(c)


def _keys_unsorted(c: dict[str, Any]) -> None:
    c["remora_evidence"] = _reversed(c["remora_evidence"])


def _ascii_escaped_digest(c: dict[str, Any]) -> None:
    c["remora_evidence"]["proposal"]["tenant"] = "Zürich Süd, 21,5 °C"
    text = json.dumps(
        c["remora_evidence"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    c["evidence_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()


def _unsorted_digest(c: dict[str, Any]) -> None:
    c["remora_evidence"] = _reversed(c["remora_evidence"])
    text = json.dumps(c["remora_evidence"], separators=(",", ":"), ensure_ascii=False)
    c["evidence_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()


def _spaced_digest(c: dict[str, Any]) -> None:
    text = json.dumps(c["remora_evidence"], sort_keys=True, ensure_ascii=False)
    c["evidence_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()


def _not_executed_but_observed(c: dict[str, Any]) -> None:
    c["execution"]["executed"] = False
    c["twin_operation"] = None


MALFORMED = None  # expected claims for a case the reader must refuse as malformed

# id, fault shape, edit, expected verdict, expected claims overrides (others ESTABLISHED), note
CASES: list[tuple[str, str, Any, str, Any, str]] = [
    (
        "clean_verify",
        "none",
        None,
        E,
        {},
        "An approved VERIFY with an approving reviewer, applied once and observed.",
    ),
    (
        "clean_accept",
        "none",
        _all(_set("decision.decision", "accept"), _set("decision.reviewer", None)),
        E,
        {},
        "An approved ACCEPT needs no reviewer.",
    ),
    (
        "clean_escalate",
        "none",
        _set("decision.decision", "escalate"),
        E,
        {},
        "An approved ESCALATE with an approving reviewer.",
    ),
    (
        "clean_observed_at_dispatch",
        "boundary",
        _set("observation.observed_at_sim_s", 7200),
        E,
        {},
        "An observation at the dispatch second is at or after it.",
    ),
    (
        "clean_envelope_only_binding",
        "boundary",
        _all(_drop("remora_evidence.proposal"), _redigest),
        E,
        {},
        "One binding source is enough: the envelope names the proposal and the evidence is silent.",
    ),
    (
        "clean_evidence_only_binding",
        "boundary",
        _set("remora_envelope", None),
        E,
        {},
        "One binding source is enough: the evidence names the proposal and there is no envelope.",
    ),
    (
        "evidence_non_ascii",
        "digest_rule",
        _non_ascii,
        E,
        {},
        "Evidence with non-ASCII text, digested with ensure_ascii=False as the contract says. "
        "A reader that escapes refuses it.",
    ),
    (
        "evidence_keys_unsorted",
        "digest_rule",
        _keys_unsorted,
        E,
        {},
        "Evidence whose members are in reverse order on disk. "
        "A reader that hashes without sort_keys refuses it.",
    ),
    (
        "decision_not_approved",
        "executed_without_approval",
        _set("decision.approved", False),
        C,
        {"decision_correspondence": C},
        "Executed while decision.approved is false.",
    ),
    (
        "accept_not_approved",
        "executed_without_approval",
        _all(
            _set("decision.decision", "accept"),
            _set("decision.reviewer", None),
            _set("decision.approved", False),
        ),
        C,
        {"decision_correspondence": C},
        "An ACCEPT is not an approval by its name alone: approved is false.",
    ),
    (
        "reviewer_rejected",
        "reviewer_overridden",
        _set("decision.reviewer.approved", False),
        C,
        {"decision_correspondence": C},
        "decision.approved is true, but the VERIFY's reviewer did not approve.",
    ),
    (
        "reviewer_absent",
        "reviewer_missing",
        _set("decision.reviewer", None),
        N,
        {"decision_correspondence": N},
        "A VERIFY with no reviewer record: the review is not shown.",
    ),
    (
        "decision_unknown",
        "executed_on_other_decision",
        _set("decision.decision", "deny"),
        C,
        {"decision_correspondence": C},
        "Executed on a DENY whose approved flag is true.",
    ),
    (
        "envelope_other_proposal",
        "decision_bound_elsewhere",
        _set("remora_envelope.request.request_id", OTHER),
        C,
        {"decision_correspondence": C},
        "The envelope's request_id names another proposal.",
    ),
    (
        "evidence_other_proposal",
        "decision_bound_elsewhere",
        _evidence_other_proposal,
        C,
        {"decision_correspondence": C},
        "The evidence's proposal_id names another proposal; "
        "the digest matches the altered evidence.",
    ),
    (
        "decision_unbound",
        "decision_binding_missing",
        _no_binding,
        N,
        {"decision_correspondence": N},
        "Neither the envelope nor the evidence names the proposal.",
    ),
    (
        "denied_but_applied",
        "denied_but_applied",
        _set("execution.executed", False),
        C,
        {"decision_correspondence": C, "single_dispatch": N},
        "Nothing executed, yet the twin recorded APPLIED.",
    ),
    (
        "not_executed_but_observed",
        "denied_but_observed",
        _not_executed_but_observed,
        C,
        {
            "decision_correspondence": C,
            "single_dispatch": N,
            "call_binding": N,
            "declared_effect_observed": N,
        },
        "Nothing executed and no twin record, yet an effect was observed.",
    ),
    (
        "replayed_execution",
        "replayed_execution",
        _set("execution.executions", 2),
        C,
        {"single_dispatch": C},
        "Executed twice.",
    ),
    (
        "execution_count_missing",
        "execution_count_missing",
        _drop("execution.executions"),
        N,
        {"single_dispatch": N},
        "No execution count: never assumed to be one.",
    ),
    (
        "twin_record_missing",
        "twin_record_missing",
        _set("twin_operation", None),
        N,
        {"call_binding": N, "declared_effect_observed": N},
        "No twin operation record.",
    ),
    (
        "twin_other_operation",
        "proposal_swapped",
        _set("twin_operation.operation_id", OTHER),
        C,
        {"call_binding": C},
        "The twin's record is for another proposal.",
    ),
    (
        "twin_requested_other_value",
        "request_swapped",
        _set("twin_operation.requested_setpoint_c", 23.0),
        C,
        {"call_binding": C},
        "The twin was asked for another value than the claim.",
    ),
    (
        "twin_not_applied",
        "twin_status",
        _set("twin_operation.status", "REJECTED"),
        C,
        {"declared_effect_observed": C},
        "The twin did not apply the change; the observation still shows the value.",
    ),
    (
        "twin_other_zone",
        "twin_zone",
        _set("twin_operation.zone_id", "ZONE-07"),
        C,
        {"declared_effect_observed": C},
        "The twin applied the change to another zone.",
    ),
    (
        "twin_value_differs_observation_matches",
        "effect_value_split",
        _set("twin_operation.new_setpoint_c", 23.0),
        C,
        {"declared_effect_observed": C},
        "The twin applied another value while the observation shows the claimed one.",
    ),
    (
        "observation_differs_twin_matches",
        "effect_value_split",
        _set("observation.observed_setpoint_c", 23.0),
        C,
        {"declared_effect_observed": C},
        "The twin applied the claimed value while the observation shows another.",
    ),
    (
        "twin_value_missing",
        "effect_value_missing",
        _drop("twin_operation.new_setpoint_c"),
        N,
        {"declared_effect_observed": N},
        "The twin record has no applied value.",
    ),
    (
        "observation_null",
        "effect_not_observed",
        _set("observation", None),
        N,
        {"declared_effect_observed": N, "observation_after_dispatch": N},
        "No observation at all.",
    ),
    (
        "observed_value_missing",
        "effect_value_missing",
        _drop("observation.observed_setpoint_c"),
        N,
        {"declared_effect_observed": N},
        "The observation carries no value.",
    ),
    (
        "dispatch_time_missing",
        "dispatch_time_missing",
        _drop("execution.dispatched_at_sim_s"),
        N,
        {"observation_after_dispatch": N},
        "No dispatch time.",
    ),
    (
        "observation_time_missing",
        "observation_time_missing",
        _drop("observation.observed_at_sim_s"),
        N,
        {"observation_after_dispatch": N},
        "No observation time: never assumed equal to the dispatch time.",
    ),
    (
        "observed_before_dispatch",
        "observed_before_dispatch",
        _set("observation.observed_at_sim_s", 7199),
        C,
        {"observation_after_dispatch": C},
        "Observed one second before the dispatch.",
    ),
    (
        "evidence_digest_mismatch",
        "evidence_digest_mismatch",
        _set("remora_evidence.proposal.tenant", "corpus-site-2"),
        C,
        {"evidence_digest_integrity": C},
        "The evidence changed after it was digested.",
    ),
    (
        "evidence_digest_escaped",
        "digest_rule",
        _ascii_escaped_digest,
        C,
        {"evidence_digest_integrity": C},
        "The digest was taken with ensure_ascii=True, which the contract does not allow.",
    ),
    (
        "evidence_digest_unsorted",
        "digest_rule",
        _unsorted_digest,
        C,
        {"evidence_digest_integrity": C},
        "The digest was taken without sorting keys.",
    ),
    (
        "evidence_digest_spaced",
        "digest_rule",
        _spaced_digest,
        C,
        {"evidence_digest_integrity": C},
        "The digest was taken with the default separators.",
    ),
    (
        "evidence_digest_not_hex",
        "digest_form",
        _set("evidence_sha256", "sha256:" + "0" * 64),
        N,
        {"evidence_digest_integrity": N},
        "The digest is not 64 lowercase hex.",
    ),
    (
        "malformed_setpoint_string",
        "malformed",
        _set("claim.setpoint_c", "21.5"),
        N,
        MALFORMED,
        "The claimed setpoint is a string.",
    ),
    (
        "malformed_execution_missing",
        "malformed",
        _drop("execution"),
        N,
        MALFORMED,
        "The execution member is missing.",
    ),
    (
        "malformed_schema",
        "malformed",
        _set("schema", "ot-federation-case/v0"),
        N,
        MALFORMED,
        "Another schema.",
    ),
    (
        "malformed_executions_bool",
        "malformed",
        _set("execution.executions", True),
        N,
        MALFORMED,
        "A boolean execution count.",
    ),
]


def build() -> dict[str, Any]:
    out = []
    for cid, shape, edit, verdict, overrides, note in CASES:
        c = base()
        if edit is not None:
            edit(c)
        if isinstance(c, dict):
            c["case_id"] = cid
            c["kind"] = "positive" if verdict == E else "negative"
            c["fault"] = None if verdict == E else shape
        claims = None if overrides is MALFORMED else {k: overrides.get(k, E) for k in CLAIMS}
        expected = {"verdict": verdict, "claims": claims}
        got = evaluate(copy.deepcopy(c))
        if {"verdict": got["verdict"], "claims": got["claims"]} != expected:
            raise SystemExit(f"{cid}: the reader answers {got}, the case expects {expected}")
        out.append({"id": cid, "fault_shape": shape, "note": note, "expected": expected, "case": c})
    return {"schema": "aev-ot-federation-cases/v1", "cases": out}


def serialise(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    """Write the corpus, or with --check report whether it is current."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    cases = serialise(build())
    manifest = serialise(
        {
            "schema": "aev-ot-federation-corpus/v1",
            "members": {"cases.json": "sha256:" + hashlib.sha256(cases).hexdigest()},
        }
    )
    files = {CORPUS / "cases.json": cases, CORPUS / "manifest.json": manifest}
    if args.check:
        stale = [str(p) for p, b in files.items() if not p.exists() or p.read_bytes() != b]
        if stale:
            print("stale: " + ", ".join(stale))
            return 1
        print("ot-federation corpus is current")
        return 0
    CORPUS.mkdir(parents=True, exist_ok=True)
    for p, b in files.items():
        p.write_bytes(b)
    print(f"wrote {len(CASES)} cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
