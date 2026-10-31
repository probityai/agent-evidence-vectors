"""Assess immutable JSON bytes with a separately selected consumer policy."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Set
from typing import Any

from agent_evidence_vectors import run_vectors as rail

from .errors import InputError

PROFILE = "probity.authority-effect-case/v1"
COMMITMENT_PROFILE = "probity.authority-effect-intent/v1"
SIGNATURE_DOMAIN = b"probity.authority-effect-authorization/v1\x00"
ENVELOPE = {"operation", "chainId", "target", "calldataHash", "value"}
INTENT = ENVELOPE | {"effectSha256", "validFrom", "validUntil"}
HEX = re.compile(r"^[0-9a-f]+$")
MAX_BYTES = 1024 * 1024


def canonical(value: Any) -> bytes:
    """Use the installed Vectors canonical serializer for this integer profile."""
    return rail.jcs_dumps(value)


def commitment(intent: dict) -> str:
    """Commit every intent field and the versioned profile in the preimage."""
    return hashlib.sha256(canonical({"profile": COMMITMENT_PROFILE, "intent": intent})).hexdigest()


def _object(value: Any, required: Set[str], optional: Set[str] = frozenset()) -> dict:
    if (
        type(value) is not dict
        or not required <= value.keys()
        or value.keys() - required - optional
    ):
        raise InputError("object has missing or unsupported fields")
    return value


def _text(value: Any) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > 8192:
        raise InputError("expected nonempty bounded scalar string")
    return value


def _integer(value: Any, minimum: int = 0) -> int:
    if type(value) is not int or not minimum <= value <= 2**53 - 1:
        raise InputError("expected bounded integer")
    return value


def _hex(value: Any, length: int) -> str:
    if type(value) is not str or len(value) != length or HEX.fullmatch(value) is None:
        raise InputError("expected lowercase fixed-length hexadecimal")
    return value


def _units(value: Any) -> list[str]:
    if type(value) is not list or len(value) > 4096:
        raise InputError("expected bounded inventory")
    items = [_text(item) for item in value]
    if len(set(items)) != len(items):
        raise InputError("duplicate inventory unit")
    return items


def _parse(raw: bytes) -> dict:
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        raise InputError("expected bounded immutable JSON bytes")
    try:
        value = rail.parse_json_value(raw)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InputError("malformed JSON input") from exc
    if type(value) is not dict:
        raise InputError("expected JSON object")
    return value


def _envelope(value: Any, extra: set[str]) -> dict:
    value = _object(value, ENVELOPE | extra)
    for name in ("operation", "target", "value"):
        _text(value[name])
    if not value["value"].isascii() or not value["value"].isdecimal():
        raise InputError("value is not a canonical unsigned decimal")
    if value["value"] != "0" and value["value"].startswith("0"):
        raise InputError("value has leading zeros")
    _integer(value["chainId"], 1)
    _hex(value["calldataHash"], 64)
    return value


def _validate(case: dict, policy: dict) -> None:
    _object(
        case, {"profile", "caseId", "authorization", "runtime"}, {"report", "observation", "scan"}
    )
    if case["profile"] != PROFILE:
        raise InputError("unsupported case profile")
    _text(case["caseId"])
    auth = _object(case["authorization"], {"intent", "commitment", "signature"})
    intent = _envelope(auth["intent"], INTENT - ENVELOPE)
    _hex(intent["effectSha256"], 64)
    _integer(intent["validFrom"])
    _integer(intent["validUntil"])
    if intent["validUntil"] < intent["validFrom"]:
        raise InputError("authorization interval is reversed")
    _hex(auth["commitment"], 64)
    _hex(auth["signature"], 128)
    runtime = _envelope(case["runtime"], {"submittedAt"})
    _integer(runtime["submittedAt"])
    _object(
        policy, {"profile", "principalPublicKey", "referenceTime", "maxObservationAge", "scanUnits"}
    )
    if policy["profile"] != "probity.authority-effect-policy/v1":
        raise InputError("unsupported policy profile")
    _hex(policy["principalPublicKey"], 64)
    _integer(policy["referenceTime"])
    _integer(policy["maxObservationAge"])
    _units(policy["scanUnits"])
    if runtime["submittedAt"] > policy["referenceTime"]:
        raise InputError("runtime submission follows policy reference time")


def _optional(case: dict, policy: dict) -> None:
    if case.get("report") is not None:
        report = _envelope(case["report"], {"completed"})
        if type(report["completed"]) is not bool:
            raise InputError("report.completed must be boolean")
    if case.get("observation") is not None:
        observation = _envelope(case["observation"], {"effectSha256", "observedAt", "operator"})
        _hex(observation["effectSha256"], 64)
        _integer(observation["observedAt"])
        _text(observation["operator"])
    if case.get("scan") is not None:
        scan = _object(case["scan"], {"scanned", "skipped", "findings", "exitCode", "stdout"})
        scanned, skipped = set(_units(scan["scanned"])), set(_units(scan["skipped"]))
        _units(scan["findings"])
        _integer(scan["exitCode"])
        _text(scan["stdout"])
        if scanned & skipped or scanned | skipped != set(policy["scanUnits"]):
            raise InputError("scan inventory differs from consumer-selected inventory")


def _claim(value: bool | None, reason: str) -> dict:
    return {"value": value, "reason": reason}


def _comparison(left: dict | None, right: dict, fields: set[str]) -> dict:
    if left is None:
        return _claim(None, "evidence_unavailable")
    same = all(left[key] == right[key] for key in fields)
    return _claim(same, "supplied_fields_match" if same else "supplied_fields_differ")


def _authorization(auth: dict, runtime: dict, policy: dict) -> dict:
    intent = auth["intent"]
    hash_ok = commitment(intent) == auth["commitment"]
    signature_ok = rail.ed25519_verify(
        bytes.fromhex(policy["principalPublicKey"]),
        SIGNATURE_DOMAIN + bytes.fromhex(auth["commitment"]),
        bytes.fromhex(auth["signature"]),
    )
    at_use = intent["validFrom"] <= runtime["submittedAt"] <= intent["validUntil"]
    verified = hash_ok and signature_ok and at_use
    destination = _comparison(intent, runtime, {"operation", "chainId", "target"})
    envelope = _comparison(intent, runtime, ENVELOPE)
    if not verified:
        destination = envelope = _claim(None, "authorization_not_verified_at_use")
    return {
        "commitmentRecomputed": _claim(
            hash_ok, "preimage_matches" if hash_ok else "preimage_differs"
        ),
        "signatureUnderSelectedKey": _claim(
            signature_ok, "signature_valid" if signature_ok else "signature_invalid"
        ),
        "authorizationTimeAtUse": _claim(
            at_use, "inside_interval" if at_use else "outside_interval"
        ),
        "destinationAuthorized": destination,
        "callEnvelopeAuthorized": envelope,
    }


def _observation(observation: dict | None, intent: dict, runtime: dict, policy: dict) -> dict:
    freshness = _claim(None, "observation_unavailable")
    effect = _claim(None, "observation_unavailable")
    if observation is not None:
        fresh = (
            runtime["submittedAt"] <= observation["observedAt"] <= policy["referenceTime"]
            and policy["referenceTime"] - observation["observedAt"] <= policy["maxObservationAge"]
        )
        freshness = _claim(fresh, "inside_selected_window" if fresh else "outside_selected_window")
        bound = all(observation[key] == runtime[key] for key in ENVELOPE)
        if fresh and bound:
            equal = observation["effectSha256"] == intent["effectSha256"]
            effect = _claim(
                equal, "supplied_effect_matches" if equal else "supplied_current_state_differs"
            )
        else:
            effect = _claim(None, "observation_stale_or_wrong_execution")
    return {
        "reportedDispatchMatchesObservation": _comparison(observation, runtime, ENVELOPE),
        "observationFresh": freshness,
        "suppliedCurrentEffectMatches": effect,
        "observationProvenanceAuthenticated": _claim(
            None, "synthetic_input_has_no_observer_authentication"
        ),
    }


def _scan(scan: dict | None, expected_units: list[str]) -> dict:
    if scan is None:
        return {
            name: _claim(None, "scan_unavailable")
            for name in (
                "coverageComplete",
                "noFindingReported",
                "processExitMatchesCoverage",
                "truncationNoticePresent",
            )
        }
    complete = (
        bool(expected_units) and set(scan["scanned"]) == set(expected_units) and not scan["skipped"]
    )
    clean = not scan["findings"]
    expected_exit = 0 if complete and clean else 1
    notice = f"truncated: {len(scan['skipped'])} unit(s)"
    return {
        "coverageComplete": _claim(
            complete, "all_selected_units_scanned" if complete else "incomplete_selected_coverage"
        ),
        "noFindingReported": _claim(
            clean, "no_finding_in_scanned_units" if clean else "finding_reported"
        ),
        "processExitMatchesCoverage": _claim(
            scan["exitCode"] == expected_exit, "supplied_process_exit_compared"
        ),
        "truncationNoticePresent": _claim(notice in scan["stdout"], "notice_compared")
        if scan["skipped"]
        else _claim(None, "no_truncation"),
    }


def assess(case_bytes: bytes, policy_bytes: bytes) -> dict:
    """Return independent truth values; this fixture does not authorize dispatch."""
    case, policy = _parse(case_bytes), _parse(policy_bytes)
    _validate(case, policy)
    _optional(case, policy)
    auth, runtime = case["authorization"], case["runtime"]
    report = case.get("report")
    claims = _authorization(auth, runtime, policy)
    claims["reportedTargetMatchesRuntime"] = _comparison(
        report, runtime, {"operation", "chainId", "target"}
    )
    claims["historicalCompletionReported"] = _claim(
        report["completed"] if report is not None else None,
        "producer_supplied_report" if report is not None else "report_unavailable",
    )
    claims.update(_observation(case.get("observation"), auth["intent"], runtime, policy))
    claims.update(_scan(case.get("scan"), policy["scanUnits"]))
    return {
        "schema": "probity.authority-effect-report/v1",
        "caseId": case["caseId"],
        "claims": claims,
        "policySha256": hashlib.sha256(policy_bytes).hexdigest(),
        "caseSha256": hashlib.sha256(case_bytes).hexdigest(),
        "scope": {
            "inputClass": "synthetic_supplied_records",
            "admission": "not_evaluated",
            "signatureScope": (
                "Selected test key over declared commitment; preimage is checked separately"
            ),
            "doesNotEstablish": [
                "live_dispatch",
                "independent_observation",
                "trusted_time",
                "observer_key_custody",
                "chain_finality",
                "commercial_adoption",
            ],
        },
    }
