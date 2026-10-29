"""Write the frozen building-effect corpus, or with --check report whether it is current."""

from __future__ import annotations

import argparse
import copy
import sys
from pathlib import Path
from typing import Any

PACKAGING = Path(__file__).resolve().parents[1] / "packaging"
sys.path.insert(0, str(PACKAGING))

from agent_evidence_vectors.building_effect.reader import (  # noqa: E402
    canonical,
    evaluate,
    sha256_tag,
)

CORPUS = PACKAGING / "agent_evidence_vectors/building_effect/corpus"

PLANTS = {
    "bms_setpoint": {"point": "ahu-2/supply-air-temp-setpoint", "value": 19},
    "valve_position": {"point": "chw-valve-4/position-percent", "value": 60},
    "heat_pump_start": {"point": "hp-1/run-command", "value": 1},
}


def base(plant: str) -> dict[str, Any]:
    """A trail that every axis establishes: one approved dispatch, one live separate read."""
    return {
        "plant": plant,
        "target": dict(PLANTS[plant]),
        "freshness_window": 30,
        "strict_vantage": False,
        "approval": {"granted_at": 100, "paused_at": [], "regranted_at": []},
        "dispatches": [{"at": 200, "outcome": "DISPATCHED"}],
        "observations": [
            {
                "at": 215,
                "read_at": 212,
                "value": PLANTS[plant]["value"],
                "cached": False,
                "source": "independent_reader",
                "vantage": "separate_deployment",
            }
        ],
    }


def make(plant: str, **changes: Any) -> dict[str, Any]:
    trail = base(plant)
    for key, value in changes.items():
        trail[key] = value
    return trail


def obs(plant: str, **changes: Any) -> dict[str, Any]:
    out = copy.deepcopy(base(plant)["observations"][0])
    out.update(changes)
    return out


def _spec() -> list[tuple[str, str, str, dict[str, Any]]]:
    rows: list[tuple[str, str, str, dict[str, Any]]] = []
    for plant in PLANTS:
        value = PLANTS[plant]["value"]
        rows += [
            (
                f"{plant}_clean",
                "none",
                "A single approved dispatch, a live separate read.",
                make(plant),
            ),
            (
                f"{plant}_read_predates_retry",
                "observation_predates_retried_dispatch",
                "The read confirms the first command; a second dispatch followed it.",
                make(
                    plant,
                    dispatches=[
                        {"at": 200, "outcome": "DISPATCHED"},
                        {"at": 260, "outcome": "BEGAN_OUTCOME_UNKNOWN"},
                    ],
                    observations=[obs(plant, at=250, read_at=247)],
                ),
            ),
            (
                f"{plant}_cached_read",
                "stale_read_counted_as_confirmation",
                "The only matching value is a cached read.",
                make(plant, observations=[obs(plant, cached=True)]),
            ),
            (
                f"{plant}_aged_read",
                "stale_read_counted_as_confirmation",
                "The matching value was sampled long before it was recorded.",
                make(plant, observations=[obs(plant, at=290, read_at=212)]),
            ),
            (
                f"{plant}_approval_survives_pause",
                "approval_survives_pause",
                "The plant was paused after approval and never approved again.",
                make(
                    plant,
                    approval={"granted_at": 100, "paused_at": [150], "regranted_at": []},
                ),
            ),
            (
                f"{plant}_approval_regranted",
                "none",
                "A pause was followed by a fresh approval before dispatch.",
                make(
                    plant,
                    approval={"granted_at": 100, "paused_at": [150], "regranted_at": [180]},
                ),
            ),
            (
                f"{plant}_missing_observation",
                "missing_observation_read_as_clean",
                "No read exists; the trail calls itself clean.",
                make(plant, observations=[], claimed_clean=True),
            ),
            (
                f"{plant}_wrong_value",
                "none",
                "A live separate read shows a different value.",
                make(plant, observations=[obs(plant, value=value + 7)]),
            ),
        ]
    rows += [
        (
            "vantage_same_deployment_strict",
            "same_deployment_reader",
            "Every read shares the dispatcher's deployment; strict vantage will not count it.",
            make(
                "bms_setpoint",
                strict_vantage=True,
                observations=[obs("bms_setpoint", vantage="same_deployment")],
            ),
        ),
        (
            "vantage_same_deployment_lenient",
            "none",
            "The same trail without strict vantage: the other axes hold.",
            make("bms_setpoint", observations=[obs("bms_setpoint", vantage="same_deployment")]),
        ),
        (
            "vantage_dispatcher_echo",
            "dispatcher_marks_its_own_work",
            "The only confirming read is the dispatcher reading its own write back.",
            make("valve_position", observations=[obs("valve_position", source="dispatcher_echo")]),
        ),
        (
            "refused_dispatch_only",
            "none",
            "The dispatch was refused, so nothing began and nothing is established.",
            make(
                "heat_pump_start", dispatches=[{"at": 200, "outcome": "REFUSED"}], observations=[]
            ),
        ),
        (
            "retry_with_post_retry_read",
            "none",
            "A retry happened and a live read followed it; the retry still breaks attribution.",
            make(
                "valve_position",
                dispatches=[
                    {"at": 200, "outcome": "DISPATCHED"},
                    {"at": 240, "outcome": "DISPATCHED"},
                ],
                observations=[obs("valve_position", at=255, read_at=252)],
            ),
        ),
    ]
    return rows


def _cases() -> list[dict[str, Any]]:
    cases = []
    for case_id, shape, note, trail in _spec():
        cases.append(
            {
                "id": case_id,
                "fault_shape": shape,
                "note": note,
                "trail": trail,
                "expected": evaluate(trail),
            }
        )
    return cases


def _dump(value: Any) -> str:
    return canonical(value).decode("utf-8") + "\n"


def render() -> dict[str, str]:
    """Every corpus file, by name, as the exact text it must hold."""
    cases = _dump(
        {
            "schema": "aev-building-effect-cases/v1",
            "result_vocabulary": ["ESTABLISHED", "CONTRADICTED", "NOT_ESTABLISHED"],
            "time_unit": "integer seconds",
            "non_claims": [
                "sensor_calibration",
                "physical_state_beyond_the_point",
                "reader_independence_from_the_building",
            ],
            "cases": _cases(),
        }
    )
    manifest = _dump(
        {
            "schema": "aev-building-effect-corpus/v1",
            "members": {"cases.json": sha256_tag(cases.encode("utf-8"))},
        }
    )
    return {"cases.json": cases, "manifest.json": manifest}


def main(argv: list[str] | None = None) -> int:
    """Write the corpus, or with --check report whether it is current."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    stale = []
    for name, text in render().items():
        path = CORPUS / name
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                stale.append(name)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
    if stale:
        print("stale corpus files: " + ", ".join(stale), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
