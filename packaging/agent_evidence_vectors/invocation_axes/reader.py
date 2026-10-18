"""Judge one pinned MCP invocation on three separate axes.

A decision capture and an execution bundle can both name the same MCP
``tools/call``. This reader keeps three claims about that call apart:

* ``package_integrity``: the capture package is the one that was pinned, and
  every retained member is the byte string its manifest names.
* ``request_decision_correspondence``: the captured request is the pinned
  invocation, and the captured decision is bound to that invocation.
* ``observed_effect``: an execution bundle bound to the same invocation shows a
  dispatch and an independent observation of the declared delta.

Each axis answers ``ESTABLISHED``, ``CONTRADICTED`` or ``NOT_ESTABLISHED``.
Three further properties are always ``NOT_ESTABLISHED`` here, whatever the
inputs say about themselves: capture authenticity, capture coverage, and
kernel-to-tool attribution. Nothing in a self-describing package can raise them.

The reader computes results without reading a case's expected answer.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

ESTABLISHED = "ESTABLISHED"
CONTRADICTED = "CONTRADICTED"
NOT_ESTABLISHED = "NOT_ESTABLISHED"

# Dispatch outcomes of REMORA's effect-evidence-v1 contract. REFUSED means
# dispatch never began; BEGAN_OUTCOME_UNKNOWN still counts as a dispatch.
REFUSED = "REFUSED"
DISPATCH_OUTCOMES = frozenset({"DISPATCHED", "BEGAN_OUTCOME_UNKNOWN", REFUSED})

AXES = (
    "package_integrity",
    "request_decision_correspondence",
    "observed_effect",
)
NON_CLAIMS = (
    "capture_authenticity",
    "capture_coverage",
    "kernel_to_tool_attribution",
)
CAPTURE_SCHEMA = "aev-invocation-capture-package/v1"
EXECUTION_SCHEMA = "aev-invocation-execution-bundle/v1"
REQUEST_MEMBER = "request.json"
DECISION_MEMBER = "decision.json"
INDEPENDENT_SOURCE = "independent_reader"


class MalformedInput(ValueError):
    """Raised for input this reader refuses before it judges any axis."""


def _refuse_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise MalformedInput(f"duplicate member name {key!r}")
        out[key] = value
    return out


def _refuse_float(text: str) -> Any:
    raise MalformedInput(f"non-integer number {text!r} has no exact canonical form here")


def _refuse_constant(text: str) -> Any:
    raise MalformedInput(f"non-JSON number {text!r}")


def parse_strict(data: bytes) -> Any:
    """Parse UTF-8 JSON, refusing duplicate names, floats and NaN/Infinity."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MalformedInput("member is not UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_refuse_duplicates,
            parse_float=_refuse_float,
            parse_constant=_refuse_constant,
        )
    except json.JSONDecodeError as exc:
        raise MalformedInput(f"member is not JSON: {exc.msg}") from exc


def _utf16_key(key: str) -> bytes:
    return key.encode("utf-16-be")


def canonical(value: Any) -> bytes:
    """RFC 8785 bytes for the integer-only JSON this corpus uses."""
    return _canon(value).encode("utf-8")


def _canon(value: Any) -> str:
    if value is None or isinstance(value, (bool, str)):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[" + ",".join(_canon(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: _utf16_key(kv[0]))
        return (
            "{"
            + ",".join(json.dumps(k, ensure_ascii=False) + ":" + _canon(v) for k, v in items)
            + "}"
        )
    raise MalformedInput(f"value of type {type(value).__name__} has no canonical form here")


def sha256_tag(data: bytes) -> str:
    """Return ``sha256:<hex>`` for raw bytes."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def invocation_binding(request: Any) -> str:
    """Bind an MCP request by its method and params, never its JSON-RPC id.

    The id and the ``jsonrpc`` version tag are transport framing: a proxy and an
    executor may see different ids for the same call. Member order inside
    ``params`` is not a change; array order and scalar kind are.
    """
    if not isinstance(request, dict):
        raise MalformedInput("request is not a JSON object")
    if request.get("method") != "tools/call" or not isinstance(request.get("params"), dict):
        raise MalformedInput("request is not an MCP tools/call")
    return sha256_tag(canonical({"method": request["method"], "params": request["params"]}))


def _result(status: str, reason: str, **extra: Any) -> dict[str, Any]:
    out: dict[str, Any] = {"result": status, "reason": reason}
    out.update(extra)
    return out


def judge_package(capture: dict[str, Any]) -> dict[str, Any]:
    """Axis 1: the pinned manifest and every member's bytes."""
    manifest = capture.get("manifest")
    objects = capture.get("objects")
    if not isinstance(manifest, dict) or not isinstance(objects, dict):
        raise MalformedInput("capture needs a manifest object and an objects map")
    if manifest.get("schema") != CAPTURE_SCHEMA:
        raise MalformedInput(f"capture manifest schema is not {CAPTURE_SCHEMA}")
    pinned = capture.get("pinned_package_digest")
    if pinned is None:
        return _result(NOT_ESTABLISHED, "unpinned_package")
    if sha256_tag(canonical(manifest)) != pinned:
        return _result(CONTRADICTED, "manifest_digest_mismatch")
    listed = manifest.get("objects")
    if not isinstance(listed, list):
        raise MalformedInput("manifest objects is not a list")
    return _judge_members(listed, objects)


def _judge_members(listed: list[dict[str, Any]], objects: dict[str, str]) -> dict[str, Any]:
    names = [member.get("name") for member in listed]
    if len(set(names)) != len(names):
        return _result(CONTRADICTED, "duplicate_member")
    for member in listed:
        name = member["name"]
        if name not in objects:
            return _result(CONTRADICTED, "missing_member", member=name)
        if sha256_tag(objects[name].encode("utf-8")) != member.get("sha256"):
            return _result(CONTRADICTED, "member_digest_mismatch", member=name)
    unlisted = sorted(set(objects) - set(names))
    if unlisted:
        return _result(CONTRADICTED, "unlisted_member", member=unlisted[0])
    return _result(ESTABLISHED, "pinned_manifest_and_members_match")


def judge_correspondence(
    capture: dict[str, Any], binding: str, integrity: dict[str, Any]
) -> dict[str, Any]:
    """Axis 2: the captured request and decision against the pinned invocation."""
    if integrity["result"] != ESTABLISHED:
        return _result(NOT_ESTABLISHED, "package_not_established")
    objects = capture["objects"]
    if REQUEST_MEMBER not in objects or DECISION_MEMBER not in objects:
        return _result(NOT_ESTABLISHED, "request_or_decision_absent")
    request = parse_strict(objects[REQUEST_MEMBER].encode("utf-8"))
    if invocation_binding(request) != binding:
        return _result(CONTRADICTED, "request_differs_from_pinned_invocation")
    decision = parse_strict(objects[DECISION_MEMBER].encode("utf-8"))
    if not isinstance(decision, dict):
        raise MalformedInput("decision is not a JSON object")
    if decision.get("request_binding") != binding:
        return _result(CONTRADICTED, "decision_bound_to_other_request")
    verdict = decision.get("decision")
    if verdict not in ("allow", "deny"):
        return _result(NOT_ESTABLISHED, "decision_value_unknown")
    return _result(ESTABLISHED, "request_and_decision_bound_to_invocation", decision=verdict)


def _same(expected: Any, observed: Any) -> bool:
    """Exact equality with strict scalar kinds, so ``false`` is not ``0``."""
    if type(expected) is not type(observed):
        return False
    if isinstance(expected, dict):
        return expected.keys() == observed.keys() and all(
            _same(expected[k], observed[k]) for k in expected
        )
    if isinstance(expected, list):
        return len(expected) == len(observed) and all(
            _same(a, b) for a, b in zip(expected, observed, strict=True)
        )
    return bool(expected == observed)


def _dispatch_gate(
    bundle: dict[str, Any], binding: str, correspondence: dict[str, Any]
) -> dict[str, Any] | None:
    if bundle.get("schema") != EXECUTION_SCHEMA:
        raise MalformedInput(f"execution bundle schema is not {EXECUTION_SCHEMA}")
    if bundle.get("call_binding") != binding:
        return _result(CONTRADICTED, "bundle_bound_to_other_call")
    outcome = (bundle.get("dispatch") or {}).get("outcome")
    if outcome not in DISPATCH_OUTCOMES:
        return _result(NOT_ESTABLISHED, "dispatch_outcome_unrecognised", outcome=outcome)
    dispatched = outcome != REFUSED
    if dispatched and correspondence.get("decision") == "deny":
        return _result(CONTRADICTED, "dispatched_after_deny")
    report = bundle.get("execution_report") or {}
    if not dispatched:
        if report.get("status") == "success":
            return _result(CONTRADICTED, "success_reported_without_dispatch")
        return _result(NOT_ESTABLISHED, "not_dispatched")
    return None


def judge_effect(
    bundle: dict[str, Any] | None, binding: str, correspondence: dict[str, Any]
) -> dict[str, Any]:
    """Axis 3: dispatch plus an independent observation of the declared delta."""
    if bundle is None:
        return _result(NOT_ESTABLISHED, "no_execution_bundle")
    gate = _dispatch_gate(bundle, binding, correspondence)
    if gate is not None:
        return gate
    declared = (bundle.get("postcondition") or {}).get("expected_fields") or {}
    if not declared:
        return _result(NOT_ESTABLISHED, "vacuous_postcondition")
    observation = bundle.get("observation")
    if observation is None:
        return _result(NOT_ESTABLISHED, "effect_unobservable")
    if observation.get("source") != INDEPENDENT_SOURCE:
        return _result(NOT_ESTABLISHED, "observation_not_independent")
    fields = observation.get("fields") or {}
    for name, value in declared.items():
        if name not in fields or not _same(value, fields[name]):
            return _result(CONTRADICTED, "observed_contradicts_declared_delta", field=name)
    return _result(ESTABLISHED, "independent_observation_matches_declared_delta")


def evaluate(invocation: Any, case: dict[str, Any]) -> dict[str, Any]:
    """Judge one case. ``case['expected']`` is never read here."""
    binding = invocation_binding(invocation)
    capture = case["capture"]
    integrity = judge_package(capture)
    correspondence = judge_correspondence(capture, binding, integrity)
    effect = judge_effect(case.get("execution"), binding, correspondence)
    out: dict[str, Any] = {
        "invocation_binding": binding,
        "package_integrity": integrity,
        "request_decision_correspondence": correspondence,
        "observed_effect": effect,
    }
    for prop in NON_CLAIMS:
        out[prop] = _result(NOT_ESTABLISHED, "outside_this_corpus")
    return out


def summary(actual: dict[str, Any]) -> dict[str, str]:
    """The per-axis and non-claim result words, in a fixed order."""
    return {key: actual[key]["result"] for key in (*AXES, *NON_CLAIMS)}
