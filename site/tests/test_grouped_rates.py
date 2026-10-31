"""Discriminating checks for task weighting, paired uncertainty, and label gaps."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import logging
import math
import re
from collections import Counter
from fractions import Fraction
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings, strategies as st

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("atlas_grouped_rates", ROOT / "tools/check_grouped_rates.py")
assert SPEC is not None and SPEC.loader is not None
READER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(READER)
INPUT = ROOT / "examples/task-grouped-rates/input.json"
REPORT = ROOT / "examples/task-grouped-rates/report.json"


@pytest.fixture
def toy() -> dict[str, Any]:
    """Give each check its own complete declared toy population."""
    return json.loads(INPUT.read_bytes())


def set_arm_labels(task: dict[str, Any], arm: str, labels: list[str]) -> None:
    """Construct new declared inputs, keeping explicit labels and counts aligned."""
    task[arm] = {"episodes": [{"episodeId": f"episode-{index}", "outcome": label}
                              for index, label in enumerate(labels)],
                 "counts": {"total": len(labels), **{name: labels.count(name) for name in READER.OUTCOMES}}}


def refuse(call: Any, reason: str, caplog: pytest.LogCaptureFixture) -> None:
    """Require the exact domain error and its one bounded log message."""
    with caplog.at_level(logging.ERROR, logger="atlas.grouped_rates"):
        with pytest.raises(ValueError, match=f"^{re.escape(reason)}$"):
            call()
    assert caplog.messages == [f"grouped rates refused: {reason}"]


class TestReadJson:
    class TestPassingCases:
        def test_retained_input_is_exactly_bound(self) -> None:
            report = READER.build_report(INPUT.read_bytes())
            assert report["inputSha256"] == hashlib.sha256(INPUT.read_bytes()).hexdigest()
            assert report["inputBytes"] == INPUT.stat().st_size
            assert report["readerSha256"] == hashlib.sha256((ROOT / "tools/check_grouped_rates.py").read_bytes()).hexdigest()

        def test_json_representation_change_changes_digest_only(self, toy: dict[str, Any]) -> None:
            compact = json.dumps(toy, separators=(",", ":")).encode()
            assert READER.build_report(compact)["inputSha256"] != READER.build_report(INPUT.read_bytes())["inputSha256"]
            assert READER.build_report(compact)["result"] == READER.build_report(INPUT.read_bytes())["result"]

    class TestFailingCases:
        @pytest.mark.parametrize("raw,reason", [
            (b'{"x":1,"x":2}', "JSON object repeats a field"),
            (b'{"x":NaN}', "JSON contains a non-finite number"),
            (b'{"x":Infinity}', "JSON contains a non-finite number"),
            (b'{"x":-Infinity}', "JSON contains a non-finite number"),
            (b'{"x":1e999}', "JSON contains a non-finite number"),
            (b'{"x":', "input must be valid bounded-depth UTF-8 JSON"),
            (b'\xff', "input must be valid bounded-depth UTF-8 JSON"),
            (b'[]', "input root must be an object"),
            (b'{"x":' * 64 + b'0' + b'}' * 64, "input must be valid bounded-depth UTF-8 JSON"),
        ], ids=["duplicate", "nan", "infinity", "negative-infinity", "overflow", "malformed", "utf8", "root", "depth"])
        def test_ambiguous_or_invalid_json_is_refused(self, raw: bytes, reason: str,
                                                     caplog: pytest.LogCaptureFixture) -> None:
            refuse(lambda: READER.read_json(raw), reason, caplog)

        def test_oversized_input_is_refused(self, caplog: pytest.LogCaptureFixture) -> None:
            refuse(lambda: READER.read_json(b' ' * (READER.MAX_INPUT_BYTES + 1)),
                   "input exceeds the declared byte cap", caplog)


class TestValidateInput:
    class TestPassingCases:
        @given(failures=st.integers(0, 20), successes=st.integers(0, 20), unresolved=st.integers(0, 10))
        def test_every_label_is_accounted_for(self, failures: int, successes: int, unresolved: int) -> None:
            document = json.loads(INPUT.read_bytes())
            labels = ["failure"] * failures + ["success"] * successes + ["unresolved"] * unresolved
            set_arm_labels(document["tasks"][0], "attack", labels)
            READER.validate_input(document)
            assert sum(document["tasks"][0]["attack"]["counts"][name] for name in READER.OUTCOMES) == len(labels)

        def test_unknown_independence_remains_visible(self, toy: dict[str, Any]) -> None:
            toy["population"]["taskIndependence"] = "unknown"
            result = READER.analyze(toy)
            assert result["population"]["taskIndependence"] == "unknown"
            assert result["independentUnitsVerified"] is None
            assert result["intervalCoverageEstablished"] is False

    class TestFailingCases:
        @pytest.mark.parametrize("bad", [-1, 65_537, 1.5, True, "3", None, float("nan"), float("inf")])
        def test_impossible_count_types_are_refused(self, toy: dict[str, Any], bad: Any,
                                                   caplog: pytest.LogCaptureFixture) -> None:
            toy["tasks"][0]["attack"]["counts"]["failure"] = bad
            refuse(lambda: READER.validate_input(toy), "episode count must be a bounded nonnegative integer", caplog)

        @pytest.mark.parametrize("field", ["total", "failure", "success", "unresolved"])
        def test_count_label_disagreement_is_refused(self, toy: dict[str, Any], field: str,
                                                    caplog: pytest.LogCaptureFixture) -> None:
            toy["tasks"][0]["attack"]["counts"][field] += 1
            refuse(lambda: READER.validate_input(toy), "declared counts differ from retained episode labels", caplog)

        @pytest.mark.parametrize("label", ["unknown", "timeout", "", None, [], 0])
        def test_unrecognized_outcomes_are_not_scored(self, toy: dict[str, Any], label: Any,
                                                    caplog: pytest.LogCaptureFixture) -> None:
            toy["tasks"][0]["attack"]["episodes"][0]["outcome"] = label
            refuse(lambda: READER.validate_input(toy), "episode outcome label is unsupported", caplog)

        def test_empty_task_population_is_refused(self, toy: dict[str, Any], caplog: pytest.LogCaptureFixture) -> None:
            toy["tasks"] = []
            refuse(lambda: READER.validate_input(toy), "task population must contain between 1 and 64 tasks", caplog)

        def test_unmatched_task_is_refused(self, toy: dict[str, Any], caplog: pytest.LogCaptureFixture) -> None:
            del toy["tasks"][0]["benign"]
            refuse(lambda: READER.validate_input(toy), "contract object lacks a required field", caplog)

        def test_repeated_task_id_is_refused(self, toy: dict[str, Any], caplog: pytest.LogCaptureFixture) -> None:
            toy["tasks"][1]["taskId"] = toy["tasks"][0]["taskId"]
            refuse(lambda: READER.validate_input(toy), "task population repeats a task id", caplog)

        def test_repeated_episode_id_is_refused(self, toy: dict[str, Any], caplog: pytest.LogCaptureFixture) -> None:
            episodes = toy["tasks"][0]["attack"]["episodes"]
            episodes[1]["episodeId"] = episodes[0]["episodeId"]
            refuse(lambda: READER.validate_input(toy), "task arm repeats an episode id", caplog)

        def test_changed_control_conditions_are_refused(self, toy: dict[str, Any], caplog: pytest.LogCaptureFixture) -> None:
            toy["matching"]["benign"]["conditions"] = {"agent": "different agent"}
            refuse(lambda: READER.validate_input(toy), "attack and benign conditions do not match", caplog)

        def test_identical_intervention_is_refused(self, toy: dict[str, Any], caplog: pytest.LogCaptureFixture) -> None:
            toy["matching"]["benign"]["intervention"] = toy["matching"]["attack"]["intervention"]
            refuse(lambda: READER.validate_input(toy), "attack and benign interventions must differ", caplog)

        @pytest.mark.parametrize("character", ["\x00", "\x1f", "\x7f", "\x85", "\u200b"])
        def test_nonprintable_task_id_is_refused(self, toy: dict[str, Any], character: str,
                                               caplog: pytest.LogCaptureFixture) -> None:
            toy["tasks"][0]["taskId"] = "task" + character
            refuse(lambda: READER.validate_input(toy), "contract text has a control character", caplog)

        @pytest.mark.parametrize("level,reason", [("NaN", "confidence level must be a finite decimal string"),
                                                 ("inf", "confidence level must be a finite decimal string"),
                                                 (0.95, "confidence level must be a finite decimal string"),
                                                 ("0.0", "confidence level must be strictly between zero and one"),
                                                 ("1.0", "confidence level must be a finite decimal string")])
        def test_unsupported_interval_levels_are_refused(self, toy: dict[str, Any], level: Any, reason: str,
                                                       caplog: pytest.LogCaptureFixture) -> None:
            toy["resampling"]["confidenceLevel"] = level
            refuse(lambda: READER.validate_input(toy), reason, caplog)

        def test_unknown_rate_field_is_not_silently_ignored(self, toy: dict[str, Any],
                                                          caplog: pytest.LogCaptureFixture) -> None:
            toy["failureRate"] = float("nan")
            refuse(lambda: READER.validate_input(toy), "contract object has an unknown field", caplog)

        def test_submitted_measurement_cannot_use_toy_independence(self, toy: dict[str, Any],
                                                                caplog: pytest.LogCaptureFixture) -> None:
            toy["evidenceKind"] = "submitted-measurement"
            refuse(lambda: READER.validate_input(toy), "illustration independence cannot label a submitted measurement", caplog)

        def test_exact_draw_cap_cannot_truncate_population(self, toy: dict[str, Any], caplog: pytest.LogCaptureFixture) -> None:
            tasks = [copy.deepcopy(task) for task in (toy["tasks"] * 2)[:7]]
            for index, task in enumerate(tasks):
                task["taskId"] = f"T{index}"
            toy["tasks"] = tasks
            refuse(lambda: READER.validate_input(toy), "exhaustive resampling exceeds the draw cap", caplog)


class TestAnalyze:
    class TestPassingCases:
        def test_both_estimands_match_hand_calculation(self, toy: dict[str, Any]) -> None:
            result = READER.analyze(toy)
            assert result["declaredTaskCount"] == 4
            assert result["episodeCounts"] == {"attack": 19, "benign": 19}
            assert result["aggregateArms"]["attack"]["resolvedDenominator"] == 18
            assert result["estimands"]["episode_weighted_resolved"]["attack_minus_benign"]["exact"] == "4/9"
            assert result["estimands"]["task_weighted_resolved"]["attack_minus_benign"]["exact"] == "11/40"
            assert result["aggregateArms"]["attack"]["allAttemptFailureBounds"]["lower"]["exact"] == "12/19"
            assert result["aggregateArms"]["attack"]["allAttemptFailureBounds"]["upper"]["exact"] == "13/19"

        def test_all_ordered_draws_and_nearest_rank_endpoints(self, toy: dict[str, Any]) -> None:
            result = READER.analyze(toy)["bootstrap"]
            indices = {tuple(draw["taskIndices"]) for draw in result["draws"]}
            assert len(indices) == result["drawCount"] == 4 ** 4 == 256
            assert all(len(draw) == 4 and set(draw) <= {0, 1, 2, 3} for draw in indices)
            multiplicities = Counter(tuple(sorted(draw)) for draw in indices)
            for group, observed in multiplicities.items():
                assert observed == math.factorial(4) // math.prod(math.factorial(n) for n in Counter(group).values())
            expected = {"episode_weighted_resolved": ("-1/10", "10/17"), "task_weighted_resolved": ("-1/4", "23/40")}
            for name, endpoints in expected.items():
                interval = result["intervals"][name]["attack_minus_benign"]
                assert (interval["lower"]["exact"], interval["upper"]["exact"]) == endpoints
                assert interval["missingDraws"] == 0

        def test_paired_control_is_retained_in_every_draw(self, toy: dict[str, Any]) -> None:
            for task in toy["tasks"]:
                task["benign"] = copy.deepcopy(task["attack"])
            result = READER.analyze(toy)["bootstrap"]
            for draw in result["draws"]:
                for row in draw["statistics"].values():
                    assert row["attack"] == row["benign"]
                    assert row["attack_minus_benign"]["exact"] == "0"
            assert result["intervals"]["episode_weighted_resolved"]["attack"]["distinctValues"] > 1

        @given(factor=st.integers(2, 8))
        @settings(max_examples=7)
        def test_cloned_repeats_add_no_independent_tasks(self, factor: int) -> None:
            original = json.loads(INPUT.read_bytes())
            cloned = copy.deepcopy(original)
            for task in cloned["tasks"]:
                for arm in READER.ARMS:
                    labels = [episode["outcome"] for episode in task[arm]["episodes"]] * factor
                    set_arm_labels(task, arm, labels)
            first, second = READER.analyze(original), READER.analyze(cloned)
            assert first["declaredTaskCount"] == second["declaredTaskCount"] == 4
            assert first["estimands"] == second["estimands"]
            assert first["bootstrap"] == second["bootstrap"]
            # An episode-iid calculation incorrectly claims an SE gain of sqrt(factor).
            variance = Fraction(2, 3) * Fraction(1, 3) / 18 + Fraction(2, 9) * Fraction(7, 9) / 18
            clone_variance = Fraction(2, 3) * Fraction(1, 3) / (18 * factor) + Fraction(2, 9) * Fraction(7, 9) / (18 * factor)
            assert variance / clone_variance == factor
            assert second["episodeCounts"] == {"attack": 19 * factor, "benign": 19 * factor}

        @pytest.mark.parametrize("labels", [[], ["unresolved"]])
        def test_missing_task_arm_is_retained_and_blocks_intervals(self, toy: dict[str, Any], labels: list[str]) -> None:
            set_arm_labels(toy["tasks"][3], "attack", labels)
            result = READER.analyze(toy)
            assert result["declaredTaskCount"] == 4
            assert result["missingTaskArmRates"] == [{"taskId": "T04", "arm": "attack"}]
            assert result["estimands"]["task_weighted_resolved"]["attack"] is None
            intervals = result["bootstrap"]["intervals"]
            assert intervals["episode_weighted_resolved"]["attack"]["missingDraws"] == 1
            assert intervals["task_weighted_resolved"]["attack"]["missingDraws"] == 256 - 3 ** 4
            assert intervals["episode_weighted_resolved"]["attack"]["lower"] is None
            assert intervals["episode_weighted_resolved"]["benign"]["status"] == "computed-conditional"
            assert len(result["bootstrap"]["draws"]) == 256

        @pytest.mark.parametrize("label", ["failure", "success"])
        def test_all_success_or_failure_is_disclosed_as_degenerate(self, toy: dict[str, Any], label: str) -> None:
            for task in toy["tasks"]:
                for arm in READER.ARMS:
                    set_arm_labels(task, arm, [label, label])
            result = READER.analyze(toy)
            for row in result["bootstrap"]["intervals"].values():
                assert all(interval["status"] == "degenerate" for interval in row.values())
            assert result["intervalCoverageEstablished"] is False

        def test_all_unresolved_remains_unscored(self, toy: dict[str, Any]) -> None:
            for task in toy["tasks"]:
                for arm in READER.ARMS:
                    set_arm_labels(task, arm, ["unresolved"])
            result = READER.analyze(toy)
            assert all(value is None for row in result["estimands"].values() for value in row.values())
            assert all(interval["missingDraws"] == 256 for row in result["bootstrap"]["intervals"].values()
                       for interval in row.values())

        def test_reordered_tasks_have_identical_analysis(self, toy: dict[str, Any]) -> None:
            first = READER.analyze(toy)
            toy["tasks"].reverse()
            assert READER.analyze(toy) == first

        def test_single_task_has_no_established_coverage(self, toy: dict[str, Any]) -> None:
            toy["tasks"] = toy["tasks"][:1]
            result = READER.analyze(toy)
            assert result["bootstrap"]["drawCount"] == 1
            assert result["bootstrap"]["intervals"]["task_weighted_resolved"]["attack_minus_benign"]["status"] == "degenerate"
            assert result["intervalCoverageEstablished"] is False

    class TestFailingCases:
        def test_bad_control_cannot_emit_an_analysis(self, toy: dict[str, Any], caplog: pytest.LogCaptureFixture) -> None:
            toy["matching"]["benign"]["conditions"]["budget"] = "new unmatched budget"
            refuse(lambda: READER.analyze(toy), "attack and benign conditions do not match", caplog)


class TestTaskDraws:
    class TestPassingCases:
        def test_sampled_generator_is_reproducible_and_seed_bound(self, toy: dict[str, Any]) -> None:
            config = {"mode": "monte-carlo", "confidenceLevel": "0.95", "seed": 20261003, "replicates": 32}
            toy["resampling"] = config
            first = READER.analyze(toy)["bootstrap"]
            assert first == READER.analyze(toy)["bootstrap"]
            assert first["generator"] == "sha256-counter-rejection-v1"
            assert first["configuration"]["seed"] == 20261003
            assert len(first["draws"]) == 32
            toy["resampling"]["seed"] += 1
            assert first["draws"] != READER.analyze(toy)["bootstrap"]["draws"]

        @given(task_count=st.integers(1, 64), seed=st.integers(0, 2 ** 64 - 1))
        def test_every_sample_index_belongs_to_declared_population(self, task_count: int, seed: int) -> None:
            config = {"mode": "monte-carlo", "confidenceLevel": "0.95", "seed": seed, "replicates": 32}
            draws = list(READER.task_draws(task_count, config))
            assert len(draws) == 32
            assert all(len(draw) == task_count and all(0 <= index < task_count for index in draw) for draw in draws)

    class TestFailingCases:
        @pytest.mark.parametrize("seed", [-1, 2 ** 64, True, 1.5, None])
        def test_invalid_seed_is_refused(self, toy: dict[str, Any], seed: Any, caplog: pytest.LogCaptureFixture) -> None:
            toy["resampling"] = {"mode": "monte-carlo", "confidenceLevel": "0.95", "seed": seed, "replicates": 32}
            refuse(lambda: READER.validate_input(toy), "random seed must be an unsigned 64-bit integer", caplog)

        @pytest.mark.parametrize("replicates", [0, 31, 4097, True, 32.0])
        def test_replicate_bounds_are_refused(self, toy: dict[str, Any], replicates: Any,
                                             caplog: pytest.LogCaptureFixture) -> None:
            toy["resampling"] = {"mode": "monte-carlo", "confidenceLevel": "0.95", "seed": 0, "replicates": replicates}
            refuse(lambda: READER.validate_input(toy), "sampled replicate count must be between 32 and 4096", caplog)


class TestMain:
    class TestPassingCases:
        def test_frozen_source_bound_report_reconstructs(self, capsys: pytest.CaptureFixture[str]) -> None:
            READER.main(["--input", str(INPUT), "--expect", str(REPORT)])
            actual = capsys.readouterr().out.encode()
            assert actual == REPORT.read_bytes()

        def test_output_file_reconstructs_identically(self, tmp_path: Path) -> None:
            output = tmp_path / "report.json"
            READER.main(["--input", str(INPUT), "--expect", str(REPORT), "--output", str(output)])
            assert output.read_bytes() == REPORT.read_bytes()

        def test_large_supported_report_roundtrip_uses_report_cap(self, toy: dict[str, Any], tmp_path: Path) -> None:
            extra = copy.deepcopy(toy["tasks"][0])
            extra["taskId"] = "T05"
            toy["tasks"].append(extra)
            source, expected, output = (tmp_path / name for name in ("input.json", "expected.json", "output.json"))
            source.write_text(json.dumps(toy))
            READER.main(["--input", str(source), "--output", str(expected)])
            assert expected.stat().st_size > READER.MAX_INPUT_BYTES
            READER.main(["--input", str(source), "--expect", str(expected), "--output", str(output)])
            assert output.read_bytes() == expected.read_bytes()

        def test_all_existing_registered_records_remain_byte_identical(self) -> None:
            # The paired-rate artifact is deliberately outside the measured register.
            register = json.loads((ROOT / "data/lab-register.json").read_bytes())
            original = json.dumps(register["records"][:19], sort_keys=True, separators=(",", ":")).encode()
            assert hashlib.sha256(original).hexdigest() == "8e7627f67aceefb7bd6d4b3311c6e4975f894d0ff4a5176274c963fa273008e7"

    class TestFailingCases:
        def test_report_cap_refuses_before_any_truncated_output(self, monkeypatch: pytest.MonkeyPatch,
                                                              caplog: pytest.LogCaptureFixture) -> None:
            monkeypatch.setattr(READER, "MAX_REPORT_BYTES", 16)
            refuse(lambda: READER.serialize({"retained": "all complete report bytes"}),
                   "report exceeds the declared byte cap", caplog)

        @pytest.mark.parametrize("field", ["inputSha256", "readerSha256"])
        def test_stale_source_or_input_report_refuses_before_output(self, tmp_path: Path, field: str,
                                                                 capsys: pytest.CaptureFixture[str],
                                                                 caplog: pytest.LogCaptureFixture) -> None:
            expected = json.loads(REPORT.read_bytes())
            expected[field] = "0" * 64
            changed = tmp_path / "changed.json"
            changed.write_text(json.dumps(expected))
            output = tmp_path / "must-not-exist.json"
            refuse(lambda: READER.main(["--input", str(INPUT), "--expect", str(changed), "--output", str(output)]),
                   "reconstructed report differs from retained report", caplog)
            assert not output.exists()
            assert capsys.readouterr().out == ""
