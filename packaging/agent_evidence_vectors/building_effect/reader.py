"""Judge one building-automation write on six separate axes.

A trail records one commanded change to a plant point (a setpoint, a valve
position, a start command) and what was seen afterwards. A verifier that reads
only the final line can accept a trail that is wrong in one of four ways, and
this reader keeps each way apart:

* ``dispatch_count``: exactly one dispatch began. A retry means the observed
  state cannot be attributed to one command.
* ``authority_at_dispatch``: an approval was in force at the moment of the
  latest dispatch. A pause revokes an approval until it is granted again.
* ``observation_after_dispatch``: an observation was sampled at or after the
  latest dispatch. A read that predates a retry confirms the earlier command.
* ``observation_freshness``: the confirming read is a live read taken close to
  the moment it was recorded. A cached or aged value is not a confirmation.
* ``observed_effect``: a live read after the latest dispatch shows the declared
  value. No observation is never read as a clean result.
* ``observation_vantage``: the read came from a reader other than the
  dispatcher. Under ``strict_vantage`` a reader that shares the dispatcher's
  deployment does not establish independence.

Each axis answers ``ESTABLISHED``, ``CONTRADICTED`` or ``NOT_ESTABLISHED``. The
derived ``effect_confirmed`` is ``ESTABLISHED`` only when every axis is, and
``CONTRADICTED`` when any axis is. A trail's own ``claimed_clean`` field is
never read. Times are integer seconds.

The reader computes results without reading a case's expected answer.
"""

from __future__ import annotations

from typing import Any

from ..invocation_axes.reader import (  # noqa: F401  (re-exported for the runner)
    CONTRADICTED,
    ESTABLISHED,
    NOT_ESTABLISHED,
    MalformedInput,
    canonical,
    parse_strict,
    sha256_tag,
)

__all__ = [
    "AXES",
    "CONTRADICTED",
    "DERIVED",
    "ESTABLISHED",
    "NON_CLAIMS",
    "NOT_ESTABLISHED",
    "MalformedInput",
    "canonical",
    "evaluate",
    "parse_strict",
    "sha256_tag",
]

AXES = (
    "dispatch_count",
    "authority_at_dispatch",
    "observation_after_dispatch",
    "observation_freshness",
    "observed_effect",
    "observation_vantage",
)
DERIVED = ("effect_confirmed",)
NON_CLAIMS = (
    "sensor_calibration",
    "physical_state_beyond_the_point",
    "reader_independence_from_the_building",
)
REFUSED = "REFUSED"
DISPATCH_OUTCOMES = frozenset({"DISPATCHED", "BEGAN_OUTCOME_UNKNOWN", REFUSED})
SOURCES = frozenset({"independent_reader", "dispatcher_echo"})
VANTAGES = frozenset({"same_deployment", "separate_deployment"})


def _int(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MalformedInput(f"{where} must be an integer")
    return value


def _validate_dispatch(dispatch: Any) -> None:
    _int(dispatch.get("at"), "dispatch.at")
    if dispatch.get("outcome") not in DISPATCH_OUTCOMES:
        raise MalformedInput(f"dispatch outcome {dispatch.get('outcome')!r} is not known")


def _validate_observation(obs: Any) -> None:
    for key in ("at", "read_at", "value"):
        _int(obs.get(key), f"observation.{key}")
    if obs.get("source") not in SOURCES:
        raise MalformedInput(f"observation source {obs.get('source')!r} is not known")
    if obs.get("vantage") not in VANTAGES:
        raise MalformedInput(f"observation vantage {obs.get('vantage')!r} is not known")
    if not isinstance(obs.get("cached"), bool):
        raise MalformedInput("observation.cached must be a boolean")


def _validate_approval(approval: Any) -> None:
    _int(approval.get("granted_at"), "approval.granted_at")
    for key in ("paused_at", "regranted_at"):
        for t in approval.get(key, []):
            _int(t, f"approval.{key}")


def _validate(trail: Any) -> None:
    if not isinstance(trail, dict):
        raise MalformedInput("trail must be an object")
    for key in ("target", "dispatches", "observations", "freshness_window"):
        if key not in trail:
            raise MalformedInput(f"trail lacks {key!r}")
    _int(trail["freshness_window"], "freshness_window")
    target = trail["target"]
    _int(target.get("value") if isinstance(target, dict) else None, "target.value")
    for dispatch in trail["dispatches"]:
        _validate_dispatch(dispatch)
    for obs in trail["observations"]:
        _validate_observation(obs)
    if trail.get("approval") is not None:
        _validate_approval(trail["approval"])


def _latest_dispatch(trail: dict[str, Any]) -> int | None:
    times = [d["at"] for d in trail["dispatches"] if d["outcome"] != REFUSED]
    return max(times) if times else None


def _post(trail: dict[str, Any], dispatch: int) -> list[dict[str, Any]]:
    return [o for o in trail["observations"] if o["read_at"] >= dispatch]


def _fresh(trail: dict[str, Any], dispatch: int) -> list[dict[str, Any]]:
    window = trail["freshness_window"]
    return [
        o
        for o in _post(trail, dispatch)
        if not o["cached"] and 0 <= o["at"] - o["read_at"] <= window
    ]


def _dispatch_count(trail: dict[str, Any], _dispatch: int | None) -> str:
    began = [d for d in trail["dispatches"] if d["outcome"] != REFUSED]
    if not began:
        return NOT_ESTABLISHED
    return ESTABLISHED if len(began) == 1 else CONTRADICTED


def _authority(trail: dict[str, Any], dispatch: int | None) -> str:
    approval = trail.get("approval")
    if approval is None or dispatch is None or approval["granted_at"] > dispatch:
        return NOT_ESTABLISHED
    in_force = approval["granted_at"]
    for paused in sorted(t for t in approval.get("paused_at", []) if t <= dispatch):
        if paused < in_force:
            continue
        regrants = [t for t in approval.get("regranted_at", []) if paused < t <= dispatch]
        if not regrants:
            return CONTRADICTED
        in_force = max(regrants)
    return ESTABLISHED


def _after(trail: dict[str, Any], dispatch: int | None) -> str:
    if dispatch is None or not trail["observations"]:
        return NOT_ESTABLISHED
    return ESTABLISHED if _post(trail, dispatch) else CONTRADICTED


def _freshness(trail: dict[str, Any], dispatch: int | None) -> str:
    if dispatch is None or not _post(trail, dispatch):
        return NOT_ESTABLISHED
    return ESTABLISHED if _fresh(trail, dispatch) else CONTRADICTED


def _effect(trail: dict[str, Any], dispatch: int | None) -> str:
    fresh = [] if dispatch is None else _fresh(trail, dispatch)
    if not fresh:
        return NOT_ESTABLISHED
    want = trail["target"]["value"]
    return ESTABLISHED if any(o["value"] == want for o in fresh) else CONTRADICTED


def _confirming(trail: dict[str, Any], dispatch: int | None) -> list[dict[str, Any]]:
    want = trail["target"]["value"]
    pool = [] if dispatch is None else _fresh(trail, dispatch)
    return [o for o in pool if o["value"] == want]


def _vantage(trail: dict[str, Any], dispatch: int | None) -> str:
    confirming = _confirming(trail, dispatch)
    if not confirming:
        return NOT_ESTABLISHED
    independent = [o for o in confirming if o["source"] == "independent_reader"]
    if not independent:
        return CONTRADICTED
    if any(o["vantage"] == "separate_deployment" for o in independent):
        return ESTABLISHED
    return NOT_ESTABLISHED if trail.get("strict_vantage") else ESTABLISHED


_JUDGES = {
    "dispatch_count": _dispatch_count,
    "authority_at_dispatch": _authority,
    "observation_after_dispatch": _after,
    "observation_freshness": _freshness,
    "observed_effect": _effect,
    "observation_vantage": _vantage,
}


def evaluate(trail: Any) -> dict[str, str]:
    """Return one answer per axis plus the derived ``effect_confirmed``."""
    _validate(trail)
    dispatch = _latest_dispatch(trail)
    out = {axis: _JUDGES[axis](trail, dispatch) for axis in AXES}
    words = set(out.values())
    if CONTRADICTED in words:
        out["effect_confirmed"] = CONTRADICTED
    elif words == {ESTABLISHED}:
        out["effect_confirmed"] = ESTABLISHED
    else:
        out["effect_confirmed"] = NOT_ESTABLISHED
    return out
