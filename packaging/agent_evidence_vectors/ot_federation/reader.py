"""Judge one building-control decision trail of the ot-federation-case/v1 shape.

A trail records one proposed setpoint change for a zone of a simulated
building: the proposal, the decision on it, the dispatch, the twin's own
operation record, an observation, and an evidence bundle with its digest. The
reader answers six claims separately, each ``ESTABLISHED``, ``CONTRADICTED`` or
``NOT_ESTABLISHED``:

* ``decision_correspondence``: a dispatch happened only under an approved
  ACCEPT, or an approved VERIFY or ESCALATE whose reviewer approved, and the
  decision is bound to this proposal by the envelope's ``request_id`` or the
  evidence's ``proposal_id``. A trail that says nothing executed while the twin
  recorded APPLIED, or an effect was observed, contradicts itself.
* ``single_dispatch``: the recorded execution count is exactly one. An absent
  count is never assumed.
* ``call_binding``: the twin's operation record is for this proposal and the
  value it was asked to apply.
* ``declared_effect_observed``: the twin recorded APPLIED for the claimed zone
  and value, and the observation shows that value. Each of the twin record and
  the observation is checked on its own, so one cannot stand in for the other.
* ``observation_after_dispatch``: the observation was made at or after the
  dispatch, both times recorded.
* ``evidence_digest_integrity``: ``evidence_sha256`` is the SHA-256 of the
  UTF-8 bytes of ``json.dumps(remora_evidence, sort_keys=True,
  separators=(",", ":"), ensure_ascii=False)``.

The case verdict is ``CONTRADICTED`` if any claim is, else ``NOT_ESTABLISHED``
if any claim is, else ``ESTABLISHED``. A trail that is not of the schema's
shape is answered ``NOT_ESTABLISHED`` as malformed; the reader never raises on
a case. Missing evidence is never filled in with an assumed value.

This file uses only the standard library and imports nothing else from the
package, so a network-less sandbox can carry it alone, checked by its SHA-256.
The reader computes results without reading a case's expected answer.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

__all__ = [
    "CLAIMS",
    "CONTRADICTED",
    "ESTABLISHED",
    "NOT_ESTABLISHED",
    "MalformedCase",
    "canonical_sha256",
    "evaluate",
    "load_case",
]

ESTABLISHED = "ESTABLISHED"
CONTRADICTED = "CONTRADICTED"
NOT_ESTABLISHED = "NOT_ESTABLISHED"
CLAIMS = (
    "decision_correspondence",
    "single_dispatch",
    "call_binding",
    "declared_effect_observed",
    "observation_after_dispatch",
    "evidence_digest_integrity",
)
SCHEMA = "ot-federation-case/v1"
APPROVING = frozenset({"accept", "verify", "escalate"})
NEEDS_REVIEWER = frozenset({"verify", "escalate"})
HEX64 = re.compile(r"[0-9a-f]{64}")


class MalformedCase(ValueError):
    """The input is not a trail of the ot-federation-case/v1 shape."""


def _refuse_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise MalformedCase(f"duplicate member {key!r}")
        out[key] = value
    return out


def _refuse_constant(name: str) -> Any:
    raise MalformedCase(f"non-finite number {name}")


def load_case(data: bytes) -> Any:
    """Parse one case file as UTF-8 JSON, refusing duplicate members and NaN or Infinity."""
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_refuse_duplicates,
            parse_constant=_refuse_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MalformedCase(f"not UTF-8 JSON: {exc}") from exc


def canonical_sha256(value: Any) -> str:
    """The digest rule of the case contract, as hex."""
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_num(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _obj_or_null(value: Any) -> bool:
    return value is None or isinstance(value, dict)


def _check_shape(case: Any) -> None:  # noqa: C901
    if not isinstance(case, dict) or case.get("schema") != SCHEMA:
        raise MalformedCase(f"not an {SCHEMA} object")
    for key in (
        "case_id",
        "kind",
        "claim",
        "decision",
        "execution",
        "twin_operation",
        "observation",
        "remora_evidence",
        "evidence_sha256",
    ):
        if key not in case:
            raise MalformedCase(f"case lacks {key!r}")
    claim, decision, execution = case["claim"], case["decision"], case["execution"]
    if not (isinstance(claim, dict) and isinstance(decision, dict) and isinstance(execution, dict)):
        raise MalformedCase("claim, decision and execution must be objects")
    if not (
        isinstance(claim.get("proposal_id"), str)
        and isinstance(claim.get("zone_id"), str)
        and isinstance(claim.get("tool"), str)
        and _is_num(claim.get("setpoint_c"))
    ):
        raise MalformedCase(
            "claim needs string proposal_id, tool and zone_id and a numeric setpoint_c"
        )
    if not (
        isinstance(decision.get("decision"), str) and isinstance(decision.get("approved"), bool)
    ):
        raise MalformedCase("decision needs a string decision and a boolean approved")
    if not _obj_or_null(decision.get("reviewer")):
        raise MalformedCase("decision.reviewer must be an object or null")
    if not isinstance(execution.get("executed"), bool):
        raise MalformedCase("execution.executed must be a boolean")
    if execution.get("dispatched_at_sim_s") is not None and not _is_int(
        execution["dispatched_at_sim_s"]
    ):
        raise MalformedCase("execution.dispatched_at_sim_s must be an integer or null")
    if "executions" in execution and not _is_int(execution["executions"]):
        raise MalformedCase("execution.executions must be an integer")
    if not (_obj_or_null(case["twin_operation"]) and _obj_or_null(case["observation"])):
        raise MalformedCase("twin_operation and observation must be objects or null")
    obs = case["observation"]
    if obs is not None:
        if "observed_setpoint_c" in obs and not _is_num(obs["observed_setpoint_c"]):
            raise MalformedCase("observation.observed_setpoint_c must be a number")
        if "observed_at_sim_s" in obs and not _is_int(obs["observed_at_sim_s"]):
            raise MalformedCase("observation.observed_at_sim_s must be an integer")
    if not isinstance(case["evidence_sha256"], str):
        raise MalformedCase("evidence_sha256 must be a string")
    if "remora_envelope" in case and not _obj_or_null(case["remora_envelope"]):
        raise MalformedCase("remora_envelope must be an object or null")


def _bound_ids(case: dict[str, Any]) -> tuple[Any, Any]:
    env = case.get("remora_envelope")
    request = env.get("request") if isinstance(env, dict) else None
    env_id = request.get("request_id") if isinstance(request, dict) else None
    evidence = case["remora_evidence"]
    proposal = evidence.get("proposal") if isinstance(evidence, dict) else None
    ev_id = proposal.get("proposal_id") if isinstance(proposal, dict) else None
    return env_id, ev_id


def _decision(case: dict[str, Any]) -> tuple[str, str]:  # noqa: C901
    decision, execution = case["decision"], case["execution"]
    twin, obs = case["twin_operation"], case["observation"]
    if not execution["executed"]:
        if (isinstance(twin, dict) and twin.get("status") == "APPLIED") or obs is not None:
            return (
                CONTRADICTED,
                "nothing executed, yet the twin recorded APPLIED or an effect was observed",
            )
        return NOT_ESTABLISHED, "nothing executed, so no dispatch to attest"
    kind = decision["decision"]
    if decision["approved"] is not True:
        return CONTRADICTED, "executed while decision.approved is false"
    if kind not in APPROVING:
        return CONTRADICTED, f"executed on decision {kind!r}, not an ACCEPT, VERIFY or ESCALATE"
    if kind in NEEDS_REVIEWER:
        reviewer = decision.get("reviewer")
        if not isinstance(reviewer, dict) or "approved" not in reviewer:
            return NOT_ESTABLISHED, f"executed on {kind} with no reviewer record"
        if reviewer["approved"] is not True:
            return CONTRADICTED, f"executed on {kind} although the reviewer did not approve"
    pid = case["claim"]["proposal_id"]
    env_id, ev_id = _bound_ids(case)
    if env_id is not None and env_id != pid:
        return CONTRADICTED, "the envelope's request_id names another proposal"
    if ev_id is not None and ev_id != pid:
        return CONTRADICTED, "the evidence's proposal_id names another proposal"
    if env_id is None and ev_id is None:
        return NOT_ESTABLISHED, "neither the envelope nor the evidence names the proposal"
    return ESTABLISHED, "an approved decision bound to the proposal"


def _single(case: dict[str, Any]) -> tuple[str, str]:
    execution = case["execution"]
    if "executions" not in execution:
        return NOT_ESTABLISHED, "execution.executions absent"
    if execution["executions"] != 1:
        return CONTRADICTED, f"executed {execution['executions']} times"
    if execution["executed"] is not True:
        return NOT_ESTABLISHED, "no dispatch recorded"
    return ESTABLISHED, "executed once"


def _binding(case: dict[str, Any]) -> tuple[str, str]:
    twin, claim = case["twin_operation"], case["claim"]
    if twin is None or "operation_id" not in twin:
        return NOT_ESTABLISHED, "no twin operation record for the proposal"
    if twin["operation_id"] != claim["proposal_id"]:
        return CONTRADICTED, "the twin's operation record is for another proposal"
    if "requested_setpoint_c" in twin and twin["requested_setpoint_c"] != claim["setpoint_c"]:
        return CONTRADICTED, "the twin was asked for another value"
    return ESTABLISHED, "the twin's operation record is for the proposal"


def _effect(case: dict[str, Any], strict_vantage: bool) -> tuple[str, str]:
    twin, obs, claim = case["twin_operation"], case["observation"], case["claim"]
    if twin is None or "status" not in twin:
        return NOT_ESTABLISHED, "no twin status"
    if twin["status"] != "APPLIED":
        return CONTRADICTED, f"twin status {twin['status']!r}, not APPLIED"
    if "zone_id" not in twin:
        return NOT_ESTABLISHED, "the twin record names no zone"
    if twin["zone_id"] != claim["zone_id"]:
        return CONTRADICTED, "the twin applied the change to another zone"
    if not _is_num(twin.get("new_setpoint_c")):
        return NOT_ESTABLISHED, "the twin record has no applied value"
    if twin["new_setpoint_c"] != claim["setpoint_c"]:
        return CONTRADICTED, "the twin applied another value"
    if obs is None or "observed_setpoint_c" not in obs:
        return NOT_ESTABLISHED, "no observed value"
    if obs["observed_setpoint_c"] != claim["setpoint_c"]:
        return CONTRADICTED, "the observation shows another value"
    if strict_vantage and _vantage(case) != "separate_deployment":
        return (
            NOT_ESTABLISHED,
            f"observation vantage is {_vantage(case)}, not a separate deployment",
        )
    return ESTABLISHED, "the twin applied and the observation shows the claimed value"


def _after(case: dict[str, Any]) -> tuple[str, str]:
    dispatched = case["execution"].get("dispatched_at_sim_s")
    obs = case["observation"]
    if dispatched is None:
        return NOT_ESTABLISHED, "dispatch time absent"
    if obs is None or "observed_at_sim_s" not in obs:
        return NOT_ESTABLISHED, "observation time absent"
    if obs["observed_at_sim_s"] < dispatched:
        return CONTRADICTED, "observed before the dispatch"
    return ESTABLISHED, "observed at or after the dispatch"


def _digest(case: dict[str, Any]) -> tuple[str, str]:
    want = case["evidence_sha256"]
    if not HEX64.fullmatch(want):
        return NOT_ESTABLISHED, "evidence_sha256 is not 64 lowercase hex"
    if canonical_sha256(case["remora_evidence"]) != want:
        return CONTRADICTED, "evidence_sha256 is not the canonical digest of remora_evidence"
    return ESTABLISHED, "evidence digest matches"


def _vantage(case: dict[str, Any]) -> str:
    env = case.get("remora_envelope")
    effect = env.get("effect") if isinstance(env, dict) else None
    entry = effect.get("ledger_entry") if isinstance(effect, dict) else None
    vantage = entry.get("effect_vantage") if isinstance(entry, dict) else None
    return vantage if isinstance(vantage, str) else "unrecorded"


def evaluate(case: Any, *, strict_vantage: bool = False) -> dict[str, Any]:
    """Return the verdict, the first claim behind it, and each claim's answer and reason.

    ``strict_vantage`` counts an observation only when the trail records it as
    made from a separate deployment.
    """
    try:
        _check_shape(case)
        judged = {
            "decision_correspondence": _decision(case),
            "single_dispatch": _single(case),
            "call_binding": _binding(case),
            "declared_effect_observed": _effect(case, strict_vantage),
            "observation_after_dispatch": _after(case),
            "evidence_digest_integrity": _digest(case),
        }
    except (MalformedCase, KeyError, TypeError, AttributeError) as exc:
        return {
            "verdict": NOT_ESTABLISHED,
            "claim_id": None,
            "reason": f"malformed: {exc}",
            "claims": None,
        }
    claims = {name: judged[name][0] for name in CLAIMS}
    for word in (CONTRADICTED, NOT_ESTABLISHED):
        for name in CLAIMS:
            if claims[name] == word:
                return {
                    "verdict": word,
                    "claim_id": name,
                    "reason": f"{name}: {judged[name][1]}",
                    "claims": claims,
                }
    return {
        "verdict": ESTABLISHED,
        "claim_id": None,
        "reason": "six claims established",
        "claims": claims,
    }
