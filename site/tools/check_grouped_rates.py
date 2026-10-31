#!/usr/bin/env python3
"""Reconstruct matched-control rates without treating task repeats as new tasks.

This standard-library reader keeps every attempted episode, validates declared
counts, and computes two distinct descriptive estimands. The paired task
bootstrap retains both arms and all episodes of each selected task. It does
not authenticate a producer, verify independence, or certify interval coverage.
See ``examples/task-grouped-rates/README.md`` for the computational contract.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import logging
import math
import re
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from fractions import Fraction
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LOGGER = logging.getLogger("atlas.grouped_rates")
DEFAULT_INPUT = ROOT / "examples/task-grouped-rates/input.json"
OUTCOMES = ("failure", "success", "unresolved")
ARMS = ("attack", "benign")
ESTIMANDS = ("episode_weighted_resolved", "task_weighted_resolved")
METRICS = ("attack", "benign", "attack_minus_benign")
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_REPORT_BYTES = 128 * 1024 * 1024
MAX_TASKS = 64
MAX_EPISODES = 65_536
MAX_EXACT_DRAWS = 65_536
MAX_SAMPLED_DRAWS = 4096


def require(condition: bool, message: str) -> None:
    """Reject one invalid contract condition with a bounded, exact reason."""
    if not condition:
        raise ValueError(message)


def fields(value: Any, required: Sequence[str], optional: Sequence[str] = ()) -> None:
    """Require an object with explicit fields rather than ignoring extensions."""
    require(isinstance(value, dict), "contract field must be an object")
    require(set(required) <= value.keys(), "contract object lacks a required field")
    require(value.keys() <= set(required) | set(optional), "contract object has an unknown field")


def nonempty_text(value: Any) -> None:
    """Validate printable nonempty text without interpreting its truthfulness."""
    require(isinstance(value, str) and bool(value.strip()), "contract text must be nonempty")
    require(value.isprintable(), "contract text has a control character")


def count(value: Any) -> None:
    """Reject booleans, fractional, negative, or unbounded episode counts."""
    require(type(value) is int and 0 <= value <= MAX_EPISODES,
            "episode count must be a bounded nonnegative integer")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Preserve an unambiguous JSON object; duplicate keys cannot override data."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "JSON object repeats a field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    """Refuse JSON NaN/infinity tokens before any numerical calculation."""
    raise ValueError("JSON contains a non-finite number")


def _finite_float(value: str) -> float:
    """Reject exponent overflow as well as nonstandard NaN/infinity tokens."""
    parsed = float(value)
    require(math.isfinite(parsed), "JSON contains a non-finite number")
    return parsed


def read_json(raw: bytes, max_bytes: int = MAX_INPUT_BYTES) -> dict[str, Any]:
    """Parse bounded UTF-8 JSON without duplicate fields or non-finite numbers.

    Parameters
    ----------
    raw : bytes
        Exact retained input representation. :func:`build_report` binds its
        length and SHA-256, independently of the parsed document.
    max_bytes : int, optional
        Explicit byte cap. Reports use a separately declared larger cap when
        read by :func:`main`; this never increases the episode-input cap.

    Returns
    -------
    dict of str to Any
        Parsed object; domain validation is performed by :func:`validate_input`.

    Raises
    ------
    ValueError
        If the input exceeds the byte cap, is malformed, contains duplicate
        keys/non-finite constants, or does not have an object root.
    """
    try:
        require(len(raw) <= max_bytes, "input exceeds the declared byte cap")
        return _parse_json(raw)
    except ValueError as error:
        LOGGER.error("grouped rates refused: %s", error)
        raise


def _parse_json(raw: bytes) -> dict[str, Any]:
    """Keep parser errors separate from logged reader contract refusals."""
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                              parse_constant=_reject_constant, parse_float=_finite_float)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("input must be valid bounded-depth UTF-8 JSON") from error
    require(isinstance(document, dict), "input root must be an object")
    _bounded_depth(document)
    return document


def _bounded_depth(document: dict[str, Any]) -> None:
    """Enforce a fixed nesting cap even when a host raises Python's recursion limit."""
    pending: list[tuple[Any, int]] = [(document, 0)]
    while pending:
        value, depth = pending.pop()
        require(depth <= 32, "input must be valid bounded-depth UTF-8 JSON")
        children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
        pending.extend((child, depth + 1) for child in children)


def validate_population(population: Any, evidence_kind: str) -> None:
    """Require the population, independence declaration, and residual dependence."""
    names = ("tasks", "episodes", "selection", "taskIndependence", "independenceBasis",
             "residualDependence")
    fields(population, names)
    for name in names:
        nonempty_text(population[name])
    require(population["taskIndependence"] in
            {"assumed-for-illustration", "declared-independent", "unknown", "dependence-remains"},
            "task independence status is unsupported")
    require(population["taskIndependence"] != "assumed-for-illustration" or
            evidence_kind == "synthetic-illustration",
            "illustration independence cannot label a submitted measurement")


def validate_matching(matching: Any) -> None:
    """Require identical declared conditions and one shared outcome criterion.

    Equality checks the retained declarations only. It does not establish that
    the producer actually held conditions fixed, that the intervention was
    randomized, or that the shared rubric is scientifically appropriate.
    """
    fields(matching, ("attack", "benign", "outcomeCriteria"))
    nonempty_text(matching["outcomeCriteria"])
    for arm in ARMS:
        fields(matching[arm], ("conditions", "intervention"))
        nonempty_text(matching[arm]["intervention"])
        conditions = matching[arm]["conditions"]
        require(isinstance(conditions, dict) and bool(conditions), "matched conditions must be nonempty")
        for key, value in conditions.items():
            nonempty_text(key)
            nonempty_text(value)
    require(matching["attack"]["conditions"] == matching["benign"]["conditions"],
            "attack and benign conditions do not match")
    require(matching["attack"]["intervention"] != matching["benign"]["intervention"],
            "attack and benign interventions must differ")


def validate_arm(arm: Any) -> None:
    """Bind all per-task counts to explicit retained episode IDs and labels."""
    fields(arm, ("episodes", "counts"))
    require(isinstance(arm["episodes"], list), "episodes must be a list")
    fields(arm["counts"], ("total", *OUTCOMES))
    for value in arm["counts"].values():
        count(value)
    identities: set[str] = set()
    observed: Counter[str] = Counter()
    for episode in arm["episodes"]:
        fields(episode, ("episodeId", "outcome"))
        nonempty_text(episode["episodeId"])
        require(episode["episodeId"] not in identities, "task arm repeats an episode id")
        require(episode["outcome"] in OUTCOMES, "episode outcome label is unsupported")
        identities.add(episode["episodeId"])
        observed[episode["outcome"]] += 1
    expected = {name: observed[name] for name in OUTCOMES}
    expected["total"] = len(arm["episodes"])
    require(arm["counts"] == expected, "declared counts differ from retained episode labels")


def validate_tasks(tasks: Any) -> None:
    """Preserve task membership and require both arms for every declared task."""
    require(isinstance(tasks, list) and 1 <= len(tasks) <= MAX_TASKS,
            "task population must contain between 1 and 64 tasks")
    identities: set[str] = set()
    total = 0
    for task in tasks:
        fields(task, ("taskId", "attack", "benign"))
        nonempty_text(task["taskId"])
        require(task["taskId"] not in identities, "task population repeats a task id")
        identities.add(task["taskId"])
        for arm in ARMS:
            validate_arm(task[arm])
            total += task[arm]["counts"]["total"]
    require(total <= MAX_EPISODES, "population exceeds the declared episode cap")


def confidence_level(value: Any) -> Fraction:
    """Parse an exact decimal nominal level strictly inside the unit interval."""
    require(isinstance(value, str) and re.fullmatch(r"0\.\d{1,6}", value) is not None,
            "confidence level must be a finite decimal string")
    level = Fraction(value)
    require(0 < level < 1, "confidence level must be strictly between zero and one")
    return level


def validate_resampling(config: Any, task_count: int) -> None:
    """Validate explicit exhaustive or deterministic Monte Carlo resource bounds."""
    fields(config, ("mode", "confidenceLevel"), ("seed", "replicates"))
    confidence_level(config["confidenceLevel"])
    require(isinstance(config["mode"], str) and config["mode"] in {"exhaustive", "monte-carlo"},
            "resampling mode is unsupported")
    if config["mode"] == "exhaustive":
        require(set(config) == {"mode", "confidenceLevel"}, "exhaustive resampling has no random seed")
        require(task_count ** task_count <= MAX_EXACT_DRAWS, "exhaustive resampling exceeds the draw cap")
        return
    require("seed" in config and "replicates" in config, "sampled resampling requires seed and replicates")
    require(type(config["seed"]) is int and 0 <= config["seed"] < 2 ** 64,
            "random seed must be an unsigned 64-bit integer")
    require(type(config["replicates"]) is int and 32 <= config["replicates"] <= MAX_SAMPLED_DRAWS,
            "sampled replicate count must be between 32 and 4096")


def validate_input(document: dict[str, Any]) -> None:
    """Validate every retained declaration before emitting a successful report.

    Parameters
    ----------
    document : dict of str to Any
        Input from :func:`read_json`. Unknown fields are refused to prevent a
        caller's additional claimed rates or weighting rules being ignored.

    Raises
    ------
    ValueError
        A bounded reason describing the first malformed contract condition.
        The same reason is logged once under ``atlas.grouped_rates``.

    Notes
    -----
    A zero-attempt or unresolved-only arm remains a retained observation gap.
    Its rate is undefined, not zero; :func:`analyze` preserves that distinction.
    """
    try:
        fields(document, ("schemaVersion", "evidenceKind", "population", "matching", "tasks", "resampling"))
        require(type(document["schemaVersion"]) is int and document["schemaVersion"] == 1,
                "schema version is unsupported")
        require(isinstance(document["evidenceKind"], str) and
                document["evidenceKind"] in {"synthetic-illustration", "submitted-measurement"},
                "evidence kind is unsupported")
        validate_population(document["population"], document["evidenceKind"])
        validate_matching(document["matching"])
        validate_tasks(document["tasks"])
        validate_resampling(document["resampling"], len(document["tasks"]))
    except ValueError as error:
        LOGGER.error("grouped rates refused: %s", error)
        raise


def resolved_rate(counts: Mapping[str, int]) -> Fraction | None:
    """Return failures per resolved episode, leaving missing denominators undefined."""
    denominator = counts["failure"] + counts["success"]
    return Fraction(counts["failure"], denominator) if denominator else None


def exact_value(value: Fraction | None) -> dict[str, Any] | None:
    """Serialize an exact rational alongside a convenience finite decimal value."""
    if value is None:
        return None
    return {"exact": str(value), "decimal": float(value)}


def aggregate(tasks: Sequence[dict[str, Any]], arm: str) -> dict[str, int]:
    """Sum retained counts, including unresolved episodes, in one selected arm."""
    return {name: sum(task[arm]["counts"][name] for task in tasks) for name in ("total", *OUTCOMES)}


def mean_defined(values: Sequence[Fraction | None]) -> Fraction | None:
    """Compute an equal-task mean only when every declared task rate is defined."""
    if any(value is None for value in values):
        return None
    return sum((value for value in values if value is not None), Fraction()) / len(values)


def statistics(tasks: Sequence[dict[str, Any]]) -> dict[str, dict[str, Fraction | None]]:
    """Compute both weighting targets and their attack-minus-benign contrasts.

    Parameters
    ----------
    tasks : sequence of dict
        Original tasks or one task-resampling draw. Repeated selections retain
        a whole task in both arms; no episode is independently selected.

    Returns
    -------
    dict
        ``episode_weighted_resolved`` uses a ratio of summed counts in each
        arm. ``task_weighted_resolved`` averages task proportions, giving every
        declared task equal weight. A missing arm rate makes its contrast
        undefined. These targets differ when cluster sizes or rates differ.
    """
    result = {name: {} for name in ESTIMANDS}
    for arm in ARMS:
        result[ESTIMANDS[0]][arm] = resolved_rate(aggregate(tasks, arm))
        result[ESTIMANDS[1]][arm] = mean_defined([resolved_rate(task[arm]["counts"]) for task in tasks])
    for row in result.values():
        attack, benign = row["attack"], row["benign"]
        row["attack_minus_benign"] = attack - benign if attack is not None and benign is not None else None
    return result


def _sample_index(seed: int, counter: int, task_count: int) -> int:
    """Draw one reproducible uniform index using SHA-256 rejection sampling.

    The byte encoding and rejection boundary are part of this reader's
    source-bound ``sha256-counter-rejection-v1`` convention. Modulo reduction
    is applied only below a multiple of ``task_count``, avoiding modulo bias.
    """
    limit = 2 ** 256 - (2 ** 256 % task_count)
    for attempt in itertools.count():
        material = f"probity-task-bootstrap-v1:{seed}:{counter}:{attempt}".encode("ascii")
        candidate = int.from_bytes(hashlib.sha256(material).digest(), "big")
        if candidate < limit:
            return candidate % task_count
    raise AssertionError("unreachable rejection sampler exit")


def task_draws(task_count: int, config: Mapping[str, Any]) -> Iterator[tuple[int, ...]]:
    """Yield ordered paired draws with replacement, preserving task multiplicity."""
    if config["mode"] == "exhaustive":
        yield from itertools.product(range(task_count), repeat=task_count)
        return
    for replicate in range(config["replicates"]):
        yield tuple(_sample_index(config["seed"], replicate * task_count + position, task_count)
                    for position in range(task_count))


def empirical_quantile(values: Sequence[Fraction], probability: Fraction) -> Fraction:
    """Use the left inverse empirical CDF, with an exact nearest-rank index.

    At probability ``p`` the rank is ``max(1, ceil(p * B))`` in the sorted
    ``B`` values. This explicit step-function convention performs no linear
    interpolation; it is not SciPy's default quantile implementation.
    """
    ordered = sorted(values)
    rank = max(1, math.ceil(probability * len(ordered)))
    return ordered[rank - 1]


def percentile_interval(values: Sequence[Fraction | None], level: Fraction) -> dict[str, Any]:
    """Describe the complete empirical distribution; never discard missing draws.

    A missing statistic blocks the interval, even when other draws are valid.
    A constant distribution is disclosed as degenerate. Neither a computed
    interval nor its nominal level establishes repeated-sampling coverage.
    """
    missing = sum(value is None for value in values)
    if missing:
        return {"status": "not-computed-missing-draw-statistic", "missingDraws": missing,
                "totalDraws": len(values), "lower": None, "upper": None}
    defined = [value for value in values if value is not None]
    tail = (1 - level) / 2
    return {"status": "degenerate" if len(set(defined)) == 1 else "computed-conditional",
            "missingDraws": 0, "totalDraws": len(defined),
            "distinctValues": len(set(defined)), "minimum": exact_value(min(defined)),
            "maximum": exact_value(max(defined)),
            "lower": exact_value(empirical_quantile(defined, tail)),
            "upper": exact_value(empirical_quantile(defined, 1 - tail))}


def arm_summary(counts: dict[str, int]) -> dict[str, Any]:
    """Report resolved denominator and worst-case bounds over unresolved labels."""
    total = counts["total"]
    bounds = None
    if total:
        bounds = {"lower": exact_value(Fraction(counts["failure"], total)),
                  "upper": exact_value(Fraction(counts["failure"] + counts["unresolved"], total))}
    return {"counts": counts, "resolvedDenominator": counts["failure"] + counts["success"],
            "resolvedFailureRate": exact_value(resolved_rate(counts)),
            "allAttemptFailureBounds": bounds}


def bootstrap(tasks: Sequence[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    """Retain every paired draw and all six statistics before computing intervals."""
    draws = []
    distributions = {estimand: {metric: [] for metric in METRICS} for estimand in ESTIMANDS}
    for indices in task_draws(len(tasks), config):
        values = statistics([tasks[index] for index in indices])
        draws.append({"taskIndices": list(indices), "statistics":
                      {name: {metric: exact_value(value) for metric, value in row.items()}
                       for name, row in values.items()}})
        append_statistics(distributions, values)
    level = confidence_level(config["confidenceLevel"])
    return {"method": "paired-task-bootstrap-percentile-v1", "nominalLevel": config["confidenceLevel"],
            "quantileRule": "left-inverse-empirical-cdf-nearest-rank",
            "configuration": config, "generator": "none-exhaustive" if config["mode"] == "exhaustive"
            else "sha256-counter-rejection-v1", "drawCount": len(draws),
            "taskIndexOrder": [task["taskId"] for task in tasks], "draws": draws,
            "intervals": {name: {metric: percentile_interval(values, level) for metric, values in row.items()}
                          for name, row in distributions.items()}}


def append_statistics(distributions: dict[str, dict[str, list[Any]]],
                      values: dict[str, dict[str, Fraction | None]]) -> None:
    """Preserve all six statistics, including undefined ones, in draw order."""
    for name, row in values.items():
        for metric, value in row.items():
            distributions[name][metric].append(value)


def analyze(document: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct descriptive rates and conditional paired task intervals.

    Parameters
    ----------
    document : dict
        Complete contract; validated by :func:`validate_input` before any
        arithmetic. Task IDs are sorted for deterministic resampling order.

    Returns
    -------
    dict
        Retained populations, per-task counts, unresolved labels, two weighting
        targets, missing task-arm rates, every paired draw, and interval limits.
        ``intervalCoverageEstablished`` and ``independentUnitsVerified`` never
        become true solely from producer declarations or a successful replay.
    """
    validate_input(document)
    tasks = sorted(document["tasks"], key=lambda task: task["taskId"])
    points = statistics(tasks)
    return {"evidenceKind": document["evidenceKind"], "population": document["population"],
            "matching": document["matching"], "samplingUnit": "paired-task-cluster",
            "declaredTaskCount": len(tasks), "independentUnitsVerified": None,
            "episodeCounts": {arm: aggregate(tasks, arm)["total"] for arm in ARMS},
            "unresolvedPolicy": "exclude-from-resolved-rate; retain-counts-and-all-attempt-bounds",
            "missingTaskPolicy": "retain-every-task; undefined-task-rates-block-equal-task-estimand",
            "missingTaskArmRates": [{"taskId": task["taskId"], "arm": arm} for task in tasks for arm in ARMS
                                    if resolved_rate(task[arm]["counts"]) is None],
            "perTask": [{"taskId": task["taskId"], **{arm: arm_summary(task[arm]["counts"])
                                                     for arm in ARMS}} for task in tasks],
            "aggregateArms": {arm: arm_summary(aggregate(tasks, arm)) for arm in ARMS},
            "estimands": {name: {metric: exact_value(value) for metric, value in row.items()}
                          for name, row in points.items()},
            "estimandDefinitions": {
                ESTIMANDS[0]: "failures / resolved episodes in each arm; difference of arm ratios",
                ESTIMANDS[1]: "mean of all declared task failure proportions in each arm; paired mean difference"},
            "bootstrap": bootstrap(tasks, document["resampling"]), "intervalCoverageEstablished": False,
            "limits": [
                "A synthetic illustration is not an empirical robot or agent measurement.",
                "Input declarations do not verify matching, rubric validity, task independence or custody.",
                "Task resampling assumes independent exchangeable task clusters; residual task dependence remains explicit.",
                "Exhaustive draws are exact for the empirical bootstrap distribution, not exact population confidence coverage.",
                "Small task populations and degenerate distributions can make nominal intervals unreliable.",
                "Unresolved outcomes are excluded only from the disclosed resolved estimands; selection can bias them.",
                "A matched observational contrast alone does not establish a causal attack effect.",
                "Duplicating episodes within existing tasks adds no independent task sampling units."]}


def build_report(raw: bytes) -> dict[str, Any]:
    """Bind complete reconstructed output to exact input and reader source bytes."""
    return {"format": "probity-task-grouped-rates-v1",
            "inputSha256": hashlib.sha256(raw).hexdigest(), "inputBytes": len(raw),
            "readerSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "result": analyze(read_json(raw))}


def serialize(report: dict[str, Any]) -> bytes:
    """Emit bounded deterministic ASCII JSON without truncation or non-finite values.

    The separate report cap permits the complete exhaustive distribution to
    exceed the input cap. :func:`main` uses this same cap for retained-report
    readback, so any successfully emitted report can be compared again.
    """
    encoded = (json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    if len(encoded) > MAX_REPORT_BYTES:
        LOGGER.error("grouped rates refused: report exceeds the declared byte cap")
        raise ValueError("report exceeds the declared byte cap")
    return encoded


def main(argv: Sequence[str] | None = None) -> None:
    """Read one local contract, optionally require an exact retained report, emit JSON.

    ``--expect`` compares before any successful output or file creation. It is
    an integrity/reproduction check of the complete source-bound report, not a
    promotion to empirical or independently operated evidence.
    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--expect", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    with args.input.open("rb") as source:
        raw = source.read(MAX_INPUT_BYTES + 1)
    report = build_report(raw)
    if args.expect is not None:
        with args.expect.open("rb") as expected:
            original = read_json(expected.read(MAX_REPORT_BYTES + 1), max_bytes=MAX_REPORT_BYTES)
        if report != original:
            LOGGER.error("grouped rates refused: reconstructed report differs from retained report")
            raise ValueError("reconstructed report differs from retained report")
    encoded = serialize(report)
    if args.output is None:
        print(encoded.decode("ascii"), end="")
    else:
        args.output.write_bytes(encoded)


if __name__ == "__main__":
    main()
