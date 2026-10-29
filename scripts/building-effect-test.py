"""Challenge the building-effect reader: hand-written answers, refusals and rule kills."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

PACKAGING = Path(__file__).resolve().parents[1] / "packaging"
sys.path.insert(0, str(PACKAGING))

from agent_evidence_vectors.building_effect.reader import (  # noqa: E402
    AXES,
    CONTRADICTED,
    ESTABLISHED,
    NOT_ESTABLISHED,
    MalformedInput,
    evaluate,
    parse_strict,
)
from agent_evidence_vectors.building_effect.run import main as run_main  # noqa: E402
from agent_evidence_vectors.building_effect.run import run_corpus  # noqa: E402

CORPUS = PACKAGING / "agent_evidence_vectors/building_effect/corpus"
CASES = json.loads((CORPUS / "cases.json").read_text())["cases"]
BY_ID = {case["id"]: case for case in CASES}
E, C, N = ESTABLISHED, CONTRADICTED, NOT_ESTABLISHED

# Written by hand, not read back from the corpus, so a reader change that also
# regenerates the corpus still fails here.
HAND = {
    "bms_setpoint_clean": dict.fromkeys(AXES, E) | {"effect_confirmed": E},
    "bms_setpoint_read_predates_retry": {
        "dispatch_count": C,
        "authority_at_dispatch": E,
        "observation_after_dispatch": C,
        "observation_freshness": N,
        "observed_effect": N,
        "observation_vantage": N,
        "effect_confirmed": C,
    },
    "valve_position_cached_read": {
        "dispatch_count": E,
        "authority_at_dispatch": E,
        "observation_after_dispatch": E,
        "observation_freshness": C,
        "observed_effect": N,
        "observation_vantage": N,
        "effect_confirmed": C,
    },
    "heat_pump_start_approval_survives_pause": {
        "dispatch_count": E,
        "authority_at_dispatch": C,
        "observation_after_dispatch": E,
        "observation_freshness": E,
        "observed_effect": E,
        "observation_vantage": E,
        "effect_confirmed": C,
    },
    "bms_setpoint_missing_observation": {
        "dispatch_count": E,
        "authority_at_dispatch": E,
        "observation_after_dispatch": N,
        "observation_freshness": N,
        "observed_effect": N,
        "observation_vantage": N,
        "effect_confirmed": N,
    },
    "vantage_same_deployment_strict": dict.fromkeys(AXES, E)
    | {"observation_vantage": N, "effect_confirmed": N},
}


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_every_case_matches_its_expected_answer(case: dict[str, Any]) -> None:
    assert evaluate(case["trail"]) == case["expected"]


@pytest.mark.parametrize("case_id", sorted(HAND))
def test_hand_written_answers(case_id: str) -> None:
    assert evaluate(BY_ID[case_id]["trail"]) == HAND[case_id]


def test_each_fault_shape_is_present_on_every_plant() -> None:
    shapes = {
        "observation_predates_retried_dispatch",
        "stale_read_counted_as_confirmation",
        "approval_survives_pause",
        "missing_observation_read_as_clean",
    }
    for plant in ("bms_setpoint", "valve_position", "heat_pump_start"):
        found = {c["fault_shape"] for c in CASES if c["id"].startswith(plant)}
        assert shapes <= found, plant


def test_a_fault_shape_never_yields_a_confirmed_effect() -> None:
    for case in CASES:
        if case["fault_shape"] != "none":
            assert evaluate(case["trail"])["effect_confirmed"] != E, case["id"]


def test_claimed_clean_is_never_read() -> None:
    trail = copy.deepcopy(BY_ID["bms_setpoint_missing_observation"]["trail"])
    answers = {evaluate({**trail, "claimed_clean": v})["effect_confirmed"] for v in (True, False)}
    assert answers == {N}


def test_each_axis_has_a_non_established_vector() -> None:
    for axis in AXES:
        words = {case["expected"][axis] for case in CASES}
        assert {E, N} <= words, axis


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t: t["dispatches"].append({"at": 205, "outcome": "DISPATCHED"}),
        lambda t: t["approval"].update(paused_at=[150]),
        lambda t: t["observations"][0].update(cached=True),
        lambda t: t["observations"][0].update(read_at=199, at=210),
        lambda t: t["observations"][0].update(value=0),
        lambda t: t["observations"][0].update(source="dispatcher_echo"),
        lambda t: t.update(observations=[]),
    ],
)
def test_one_change_breaks_a_clean_trail(mutate: Any) -> None:
    trail = copy.deepcopy(BY_ID["bms_setpoint_clean"]["trail"])
    mutate(trail)
    assert evaluate(trail)["effect_confirmed"] != E


def test_strict_vantage_flips_same_deployment_only() -> None:
    trail = copy.deepcopy(BY_ID["vantage_same_deployment_lenient"]["trail"])
    assert evaluate(trail)["observation_vantage"] == E
    trail["strict_vantage"] = True
    assert evaluate(trail)["observation_vantage"] == N
    trail["observations"][0]["vantage"] = "separate_deployment"
    assert evaluate(trail)["observation_vantage"] == E


@pytest.mark.parametrize(
    "mutate",
    [
        lambda t: t["observations"][0].update(value=1.5),
        lambda t: t["observations"][0].update(cached="no"),
        lambda t: t["dispatches"][0].update(outcome="SENT"),
        lambda t: t["observations"][0].update(source="someone"),
        lambda t: t.pop("freshness_window"),
    ],
)
def test_malformed_trail_is_refused(mutate: Any) -> None:
    trail = copy.deepcopy(BY_ID["bms_setpoint_clean"]["trail"])
    mutate(trail)
    with pytest.raises(MalformedInput):
        evaluate(json.loads(json.dumps(trail)))


def test_strict_parse_refuses_float_and_duplicate_names() -> None:
    with pytest.raises(MalformedInput):
        parse_strict(b'{"a": 1.5}')
    with pytest.raises(MalformedInput):
        parse_strict(b'{"a": 1, "a": 2}')


def test_runner_reports_no_failures_and_refuses_a_tampered_member(tmp_path: Path) -> None:
    assert run_corpus(CORPUS)["failures"] == []
    copy_dir = tmp_path / "corpus"
    copy_dir.mkdir()
    for name in ("cases.json", "manifest.json"):
        (copy_dir / name).write_bytes((CORPUS / name).read_bytes())
    (copy_dir / "cases.json").write_bytes((CORPUS / "cases.json").read_bytes() + b" ")
    with pytest.raises(MalformedInput):
        run_corpus(copy_dir)


def test_runner_writes_one_report(tmp_path: Path) -> None:
    out = tmp_path / "run"
    assert run_main(["--output", str(out), "--implementation-revision", "0" * 40]) == 0
    report = json.loads((out / "report.json").read_text())
    assert report["failures"] == []


def test_corpus_is_what_the_builder_writes() -> None:
    script = Path(__file__).with_name("building-effect-build.py")
    done = subprocess.run([sys.executable, str(script), "--check"], capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
