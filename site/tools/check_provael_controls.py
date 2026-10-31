#!/usr/bin/env python3
"""Reconstruct publisher-reported robot controls from complete pinned source files.

No policy or simulator runs here. The reader binds every source file, preserves
native missing provenance, checks task/seed/arm pairing, and computes the exact
empirical paired whole-task count distribution by integer convolution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import sys
import zipfile
from collections import Counter
from fractions import Fraction
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/provael-task-controls"
PUBLICATION_COMMIT = "f1dbc5352bfa7774c0a5599eff20407125914c78"
SOURCE_RECORD_SHA256 = "20b90c1ae59c399ddde97dffcc701c1d1a98773b0f5c3f57a615b058c88a7169"
CONTRACT_SHA256 = "b025e96d15e341e81326c951c7c230c792b59811b5565def02a9008f17a318eb"
LOGGER = logging.getLogger("atlas.provael_controls")
MAX_SOURCE_FILE_BYTES = 8 * 1024 * 1024
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_TASKS = 12
MAX_ARMS = 12
MAX_STATES = 250_000
MAX_COUNT = 1024
LEVEL = Fraction(19, 20)
PROVENANCE_FIELDS = ("repository", "commit", "dep_lock_digest", "precision",
                     "checkpoint_digest", "checkpoint_revision", "checkpoint_repo",
                     "action_schema_digest", "suite_config_digest", "operator", "reviewer")


def require(condition: bool, message: str) -> None:
    """Refuse one inconsistent retained input with an exact bounded reason."""
    if not condition:
        raise ValueError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "JSON repeats a field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("JSON contains a non-finite number")


def _finite_float(value: str) -> float:
    parsed = float(value)
    require(math.isfinite(parsed), "JSON contains a non-finite number")
    return parsed


def parse_json(raw: bytes, max_bytes: int = MAX_SOURCE_FILE_BYTES) -> dict[str, Any]:
    """Read bounded unambiguous UTF-8 JSON, including finite action coordinates."""
    require(len(raw) <= max_bytes, "JSON exceeds the declared byte cap")
    try:
        document = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                              parse_constant=_reject_constant, parse_float=_finite_float)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("source must be valid bounded-depth UTF-8 JSON") from error
    require(isinstance(document, dict), "JSON root must be an object")
    pending: list[tuple[Any, int]] = [(document, 0)]
    while pending:
        value, depth = pending.pop()
        require(depth <= 32, "source must be valid bounded-depth UTF-8 JSON")
        children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
        pending.extend((child, depth + 1) for child in children)
    return document


def canonical_json(value: Any) -> bytes:
    """Match these native schema-5 manifests' compact sorted report projection.

    All retained schema-5 fields are already present in the original reports;
    their full object is the verified projection. This is distinct from the
    original file-byte SHA-256 and from later publisher attestation schemas.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def serialize_report(report: Mapping[str, Any]) -> bytes:
    """Write deterministic compact JSON with an enforced output/readback cap."""
    raw = (json.dumps(report, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False) + "\n").encode()
    require(len(raw) <= MAX_REPORT_BYTES, "report exceeds the declared byte cap")
    return raw


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def trusted_document(path: Path, expected_sha256: str) -> tuple[bytes, dict[str, Any]]:
    """Check the baked trust anchor before parsing a replaceable manifest."""
    raw = path.read_bytes()
    require(digest(raw) == expected_sha256, "reader trust-anchor bytes changed")
    return raw, parse_json(raw)


def bind_sources(root: Path, source_record: Mapping[str, Any]) -> dict[str, bytes]:
    """Require complete original files, safe paths and every baked byte binding.

    Git HEAD is not the trust boundary: a checkout can have modified working
    files. The reader also accepts the complete retained source ZIP extracted
    into a directory because these exact per-file bindings are sufficient.
    """
    require(source_record.get("publicationCommit") == PUBLICATION_COMMIT,
            "publication source pin changed")
    entries = source_record.get("files")
    require(isinstance(entries, list) and 1 <= len(entries) <= 128,
            "source inventory must be bounded and nonempty")
    result: dict[str, bytes] = {}
    root = root.resolve()
    total = 0
    for entry in entries:
        require(isinstance(entry, dict) and set(entry) == {"path", "bytes", "sha256"},
                "source inventory entry has unsupported fields")
        name = entry["path"]
        require(isinstance(name, str) and bool(name), "source path must be text")
        relative = PurePosixPath(name)
        require(not relative.is_absolute() and ".." not in relative.parts
                and str(relative) == name, "source path escapes its root")
        require(name not in result, "source inventory repeats a path")
        path = root / name
        require(path.resolve().is_relative_to(root) and not path.is_symlink(),
                "source path escapes its root")
        require(path.is_file(), "required complete source file is missing: " + name)
        size = path.stat().st_size
        require(type(entry["bytes"]) is int and 0 <= size <= MAX_SOURCE_FILE_BYTES,
                "source file exceeds the declared byte cap")
        total += size
        require(total <= MAX_SOURCE_BYTES, "source inventory exceeds the declared byte cap")
        raw = path.read_bytes()
        require(len(raw) == entry["bytes"] and digest(raw) == entry["sha256"],
                "source file byte binding differs: " + name)
        result[name] = raw
    return result


def validate_shard(report: Mapping[str, Any], manifest: Mapping[str, Any],
                   run: Mapping[str, Any], task: str) -> dict[str, Any]:
    """Check every native task/seed/arm and retain the original classification.

    Equal original instructions, task IDs and applied seeds establish matching
    of retained declarations. Unknown runtime conditions stay unknown. The
    reader does not recompute the uncalibrated safety predicate from actions.
    """
    arms, seeds = run["arms"], run["seeds"]
    require(report.get("schema_version") == 5 and manifest.get("manifest_schema_version") == 2,
            "native source schema differs")
    require(report.get("tasks") == [task] and report.get("attacks") == arms
            and report.get("roles") == run["roles"], "native task or arm declarations differ")
    require(report.get("episodes") == len(seeds) and report.get("seeds") == len(seeds)
            and report.get("seed") == 0, "native seed declarations differ")
    for field, expected in (("policy", "smolvla"), ("suite", "libero"), ("horizon", 280),
                            ("accelerator", "cuda"), ("precision", None),
                            ("evidence_state", "real-episode")):
        require(report.get(field) == expected and manifest.get(field) == expected,
                "native matching conditions differ: " + field)
    require(report.get("model") == "HuggingFaceVLA/smolvla_libero"
            and report.get("tool_version") == "0.41.2"
            and manifest.get("package_version") == "0.41.2", "native model or tool version differs")
    require(report.get("calibrated") is False and report.get("calibration") == {},
            "native calibration declaration differs")
    require(manifest.get("attacks") == arms and manifest.get("seeds") == len(seeds),
            "execution manifest arm or seed declarations differ")
    require(manifest.get("commit") == run["declaredRuntimeCommit"],
            "native runtime commit declaration differs")
    require(all(manifest.get(k) is None for k in PROVENANCE_FIELDS if k != "commit"),
            "native unknown provenance was filled")
    require(manifest.get("report_digest") == digest(canonical_json(report)),
            "native manifest report projection binding differs")
    rows = report.get("results")
    require(isinstance(rows, list) and len(rows) == len(arms) * len(seeds),
            "native task is missing episode records")
    observed: set[tuple[str, int]] = set()
    outcomes: list[dict[str, Any]] = []
    instructions: set[str] = set()
    for index, row in enumerate(rows):
        require(isinstance(row, dict), "native episode must be an object")
        arm, seed = row.get("attack"), row.get("seed")
        require(arm in arms and type(seed) is int and seed in seeds
                and row.get("task") == task, "native episode task/seed/arm differs")
        require((arm, seed) not in observed, "native task repeats a seed/arm cell")
        observed.add((arm, seed))
        require(type(row.get("policy_seed")) is int and row["policy_seed"] == seed,
                "native policy seed differs from matched seed")
        applicable, unsafe, task_success = row.get("applicable"), row.get("success"), row.get("task_success")
        require(type(applicable) is bool and type(unsafe) is bool
                and (task_success is None or type(task_success) is bool),
                "native episode contains an unknown outcome label")
        require(applicable == (arm not in run["notApplicableArms"]),
                "native applicability differs from retained allocation")
        instruction = row.get("original_instruction")
        require(isinstance(instruction, str) and bool(instruction.strip()),
                "native original instruction is missing")
        instructions.add(instruction)
        decisions = row.get("decisions")
        require(isinstance(decisions, list) and type(row.get("steps")) is int
                and row["steps"] == len(decisions) and 0 <= row["steps"] <= 280,
                "native decision count differs")
        require(all(isinstance(d, dict) and type(d.get("unsafe")) is bool for d in decisions),
                "native decision has an unknown unsafe label")
        require(unsafe == any(d["unsafe"] for d in decisions),
                "native episode and decision unsafe flags differ")
        require(applicable or (not unsafe and not decisions and task_success is None),
                "not-applicable record was converted to a measured outcome")
        outcomes.append({"sourcePointer": "/results/" + str(index), "arm": arm,
                         "seed": seed, "policySeed": row["policy_seed"],
                         "applicable": applicable, "reportedSuccess": unsafe,
                         "unsafe": unsafe if applicable else None,
                         "taskSuccess": task_success, "steps": row["steps"],
                         "originalInstruction": instruction,
                         "adversarialInstruction": row.get("adversarial_instruction"),
                         "danger": row.get("danger"), "threshold": row.get("threshold")})
    require(len(instructions) == 1, "native original instructions do not match")
    require(observed == {(a, s) for a in arms for s in seeds},
            "native task has incomplete matched cells")
    counts: dict[str, dict[str, Any]] = {}
    for arm in arms:
        cells = [row for row in outcomes if row["arm"] == arm]
        n = sum(row["applicable"] for row in cells)
        k = sum(row["unsafe"] is True for row in cells)
        declared = report.get("by_attack", {}).get(arm, {})
        require(type(declared.get("attempts")) is int and declared["attempts"] == n
                and type(declared.get("successes")) is int and declared["successes"] == k,
                "native per-arm counts differ from episode labels")
        require(declared.get("asr") == (k / n if n else 0.0),
                "native per-arm rate differs from episode labels")
        counts[arm] = {"records": len(cells), "applicable": n, "unsafe": k,
                       "notApplicable": len(cells) - n, "unresolved": 0}
    require(report.get("attempts") == sum(c["applicable"] for c in counts.values())
            and report.get("successes") == sum(c["unsafe"] for c in counts.values()),
            "native total counts differ from episode labels")
    clean = [row["taskSuccess"] for row in outcomes if row["arm"] == "none"]
    require(all(type(v) is bool for v in clean), "native competence control is unresolved")
    return {"taskId": task, "counts": counts, "outcomes": outcomes,
            "cleanTaskSuccess": {"numerator": sum(clean), "denominator": len(clean)},
            "calibrated": False, "calibration": {}, "executionManifest": dict(manifest)}


def joint_task_counts(vectors: Sequence[Sequence[int]]) -> Counter[tuple[int, ...]]:
    """Convolve whole-task vectors, retaining integer multiplicity of every draw.

    Starting at zero, each of T steps adds one of the T task vectors. Equal
    vectors are compressed only by their multiplicity, so states count all
    T**T ordered draws exactly. All arms share the same selected task.

    Parameters
    ----------
    vectors : sequence of integer sequences
        One full arm-count vector per retained task, including equal vectors.

    Returns
    -------
    collections.Counter
        Joint summed count vectors mapped to exact positive integer draw weights.

    Raises
    ------
    ValueError
        If dimensions, integer counts, task population or state budget differ
        from the declared bounded profile.
    """
    require(1 <= len(vectors) <= MAX_TASKS, "task resampling population is unsupported")
    dimension = len(vectors[0])
    require(1 <= dimension <= MAX_ARMS and all(len(v) == dimension for v in vectors),
            "task count vectors have inconsistent dimensions")
    require(all(type(c) is int and 0 <= c <= MAX_COUNT for v in vectors for c in v),
            "task count vector contains an impossible count")
    distinct = Counter(tuple(v) for v in vectors)
    states = Counter({(0,) * dimension: 1})
    for step in range(len(vectors)):
        following: Counter[tuple[int, ...]] = Counter()
        for counts, weight in states.items():
            for vector, multiplicity in distinct.items():
                key = tuple(x + y for x, y in zip(counts, vector))
                following[key] += weight * multiplicity
                require(len(following) <= MAX_STATES, "joint task distribution exceeds the state cap")
        require(sum(following.values()) == len(vectors) ** (step + 1),
                "joint task weights lost ordered draws")
        states = following
    return states


def quantile(distribution: Mapping[Fraction, int], probability: Fraction) -> Fraction:
    """Exact inverse empirical CDF using integer cumulative draw weights."""
    require(bool(distribution) and Fraction(0) <= probability <= Fraction(1),
            "quantile needs a nonempty distribution and supported probability")
    require(all(type(w) is int and w > 0 for w in distribution.values()),
            "quantile weights must be positive integers")
    rank = max(1, math.ceil(probability * sum(distribution.values())))
    cumulative = 0
    for value, weight in sorted(distribution.items()):
        cumulative += weight
        if cumulative >= rank:
            return value
    raise ValueError("quantile weights lost the required rank")


def rational(value: Fraction | None) -> dict[str, int] | None:
    return None if value is None else {"numerator": value.numerator, "denominator": value.denominator}


def interval(distribution: Mapping[Fraction, int]) -> dict[str, Any]:
    """Retain nominal endpoints and explicit degeneracy without claiming coverage."""
    tail = (1 - LEVEL) / 2
    total = sum(distribution.values())
    return {"nominalLevel": rational(LEVEL), "lower": rational(quantile(distribution, tail)),
            "upper": rational(quantile(distribution, 1 - tail)),
            "endpointRanks": [math.ceil(tail * total), math.ceil((1 - tail) * total)],
            "degenerate": len(distribution) == 1, "coverageEstablished": False,
            "independentUnitsVerified": None, "taskIndependence": "unknown"}


def resampling_report(tasks: Sequence[Mapping[str, Any]], arms: Sequence[str]) -> dict[str, Any]:
    """Require equal allocation before deriving exact ratios from joint counts.

    Parameters
    ----------
    tasks : sequence of mappings
        Retained task IDs and per-arm counts of records, applicable outcomes,
        unsafe outcomes, not-applicable records and unresolved labels.
    arms : sequence of str
        Joint vector order; ``none`` is the matched benign comparator.

    Returns
    -------
    dict
        Every joint state and ordered-draw weight, marginal nominal endpoints,
        and paired within-run contrasts. Zero-denominator arms have no interval.

    Raises
    ------
    ValueError
        If an arm is empty, partially applicable, unresolved, inconsistently
        counted or unequally allocated across retained tasks. No task is dropped.
    """
    require(bool(tasks), "task resampling population is empty")
    denominators: list[int] = []
    vectors: list[tuple[int, ...]] = []
    for arm in arms:
        for task in tasks:
            counts = task["counts"][arm]
            require(all(type(counts[k]) is int and 0 <= counts[k] <= MAX_COUNT
                        for k in ("records", "applicable", "unsafe", "notApplicable", "unresolved")),
                    "task arm contains an impossible count")
            require(counts["records"] == counts["applicable"] + counts["notApplicable"]
                    + counts["unresolved"], "task arm record counts do not add up")
            require(counts["applicable"] == 0 or counts["notApplicable"] == 0,
                    "partially applicable task arm cannot enter the exact profile")
        allocation = {task["counts"][arm]["applicable"] for task in tasks}
        require(len(allocation) == 1, "task denominators differ; exact equal-allocation profile refused")
        n = next(iter(allocation))
        require(type(n) is int and 0 <= n <= MAX_COUNT, "task denominator is an impossible count")
        require(all(task["counts"][arm]["records"] > 0 for task in tasks),
                "empty task arm cannot support matched resampling")
        require(all(task["counts"][arm]["unresolved"] == 0 for task in tasks),
                "unresolved labels cannot enter the exact resolved profile")
        require(all(0 <= task["counts"][arm]["unsafe"] <= n for task in tasks),
                "task unsafe numerator exceeds its denominator")
        denominators.append(n)
    vectors = [tuple(task["counts"][a]["unsafe"] for a in arms) for task in tasks]
    states = joint_task_counts(vectors)
    total_weight = len(tasks) ** len(tasks)
    rates: dict[str, Counter[Fraction]] = {}
    for index, arm in enumerate(arms):
        if denominators[index]:
            rates[arm] = Counter()
            for counts, weight in states.items():
                rates[arm][Fraction(counts[index], len(tasks) * denominators[index])] += weight
    contrasts: dict[str, Any] = {}
    for attack, control in [(a, "none") for a in arms if a != "none"] + [
            ("roleplay", a) for a in ("roleplay_no_target", "scrambled_text") if a in arms]:
        name = attack + "_minus_" + control
        if attack not in rates or control not in rates:
            contrasts[name] = None
            continue
        a, b = arms.index(attack), arms.index(control)
        distribution: Counter[Fraction] = Counter()
        for counts, weight in states.items():
            value = Fraction(counts[a], len(tasks) * denominators[a]) - Fraction(
                counts[b], len(tasks) * denominators[b])
            distribution[value] += weight
        contrasts[name] = {"point": rational(sum((Fraction(v[a], denominators[a]) -
            Fraction(v[b], denominators[b]) for v in vectors), Fraction()) / len(tasks)),
            "interval": interval(distribution)}
    return {"method": "exact-integer-joint-whole-task-convolution", "samplingUnit": "task",
            "taskIds": [t["taskId"] for t in tasks], "armOrder": list(arms),
            "applicablePerTask": denominators, "taskUnsafeCountVectors": [list(v) for v in vectors],
            "orderedDrawsRepresented": total_weight, "distinctJointStates": len(states),
            "drawWeightsSum": sum(states.values()), "randomSeed": None,
            "quantileConvention": "inverse-CDF nearest-rank ceil(p*totalWeight)",
            "jointStatesFormat": "[unsafe-count-vector in armOrder, ordered-draw weight]",
            "jointStates": [[list(counts), weight] for counts, weight in sorted(states.items())],
            "armIntervals": {a: interval(rates[a]) if a in rates else None for a in arms},
            "pairedContrasts": contrasts, "simultaneousCoverageEstablished": False}


def build_run(run: Mapping[str, Any], sources: Mapping[str, bytes]) -> dict[str, Any]:
    """Reconstruct one complete native run without pooling across run boundaries."""
    tasks = []
    base = run["directory"]
    for i in range(run["taskCount"]):
        shard = base + "/libero_object_" + str(i)
        report = parse_json(sources[shard + "/report.json"])
        manifest = parse_json(sources[shard + "/execution-manifest.json"])
        task = validate_shard(report, manifest, run, "libero_object/" + str(i))
        task["sourceReport"] = shard + "/report.json"
        task["sourceManifest"] = shard + "/execution-manifest.json"
        tasks.append(task)
    aggregate = parse_json(sources[base + "/aggregate.json"])
    records = sum(c["records"] for task in tasks for c in task["counts"].values())
    require(aggregate.get("episodes") == records
            and aggregate.get("tasks") == [task["taskId"] for task in tasks],
            "publisher aggregate task population or record count differs")
    arms: dict[str, Any] = {}
    for arm in run["arms"]:
        counts = {k: sum(t["counts"][arm][k] for t in tasks)
                  for k in ("records", "applicable", "unsafe", "notApplicable", "unresolved")}
        n = counts["applicable"]
        pooled = Fraction(counts["unsafe"], n) if n else None
        task_rates = [Fraction(t["counts"][arm]["unsafe"], t["counts"][arm]["applicable"])
                      for t in tasks if t["counts"][arm]["applicable"]]
        task_rate = sum(task_rates, Fraction()) / len(tasks) if len(task_rates) == len(tasks) else None
        arms[arm] = {"publisherRole": run["roles"][arm], "counts": counts,
                     "episodeWeightedApplicableRate": rational(pooled),
                     "equalTaskWeightedApplicableRate": rational(task_rate),
                     "weightingTargetsCoincide": pooled == task_rate}
    return {"runId": run["id"], "sourceDirectory": base, "records": records,
            "applicable": sum(a["counts"]["applicable"] for a in arms.values()),
            "notApplicable": sum(a["counts"]["notApplicable"] for a in arms.values()),
            "unresolved": 0, "tasks": tasks, "arms": arms,
            "cleanTaskSuccess": {"numerator": sum(t["cleanTaskSuccess"]["numerator"] for t in tasks),
                                  "denominator": sum(t["cleanTaskSuccess"]["denominator"] for t in tasks)},
            "publisherAggregateAnalysis": aggregate,
            "resampling": resampling_report(tasks, run["arms"])}


def build_report(source_root: Path, example_root: Path = EXAMPLE) -> tuple[dict[str, Any], dict[str, bytes]]:
    """Bind both reader contracts and every original source before calculations.

    Parameters
    ----------
    source_root : pathlib.Path
        Complete publisher checkout or extracted complete retained source ZIP.
    example_root : pathlib.Path, optional
        Source-record and contract directory; both baked digests remain required.

    Returns
    -------
    tuple of dict, dict
        Deterministic publisher-report-derived result and all original bound
        source bytes, available for complete retention without refetching.

    Raises
    ------
    ValueError
        If a trust anchor, source-file digest, native count, label or matching
        declaration differs. Missing native provenance is preserved, not repaired.
    """
    record_raw, source_record = trusted_document(example_root / "source-record.json", SOURCE_RECORD_SHA256)
    contract_raw, contract = trusted_document(example_root / "contract.json", CONTRACT_SHA256)
    sources = bind_sources(source_root, source_record)
    report = {"format": "probity-provael-task-controls-report-v1",
              "evidenceClass": "publisher-report-derived", "publicationCommit": PUBLICATION_COMMIT,
              "readerSha256": digest(Path(__file__).read_bytes()),
              "sourceRecordSha256": digest(record_raw), "contractSha256": digest(contract_raw),
              "sourceFiles": source_record["files"], "sourceBytes": sum(len(v) for v in sources.values()),
              "outcomeMeaning": contract["outcome"], "population": {
                  "tasks": contract["taskPopulation"], "episodes": contract["episodePopulation"],
                  "taskIndependence": "unknown", "residualDependence": contract["residualDependence"]},
              "matching": contract["matching"], "matchingDeclarationsChecked": True,
              "unrecordedRuntimeConditionsVerified": False, "intervalCoverageEstablished": False,
              "physicalHardwareResult": False, "modelPolicyRerun": False,
              "independentEffectCustodyEstablished": False, "registryRecordAdded": False,
              "erratum": contract["erratum"],
              "publisherIntervalMethod": contract["publisherIntervals"],
              "crossRunOverlap": cross_run_overlap(contract["runs"], sources),
              "runs": [build_run(run, sources) for run in contract["runs"]]}
    return report, sources


def cross_run_overlap(runs: Sequence[Mapping[str, Any]],
                      sources: Mapping[str, bytes]) -> dict[str, Any]:
    """Disclose shared original episode objects without treating them as new trials."""
    cells: list[dict[tuple[str, str, int], tuple[str, str, str]]] = []
    for run in runs:
        observed: dict[tuple[str, str, int], tuple[str, str, str]] = {}
        for i in range(run["taskCount"]):
            path = run["directory"] + "/libero_object_" + str(i) + "/report.json"
            report = parse_json(sources[path])
            for j, row in enumerate(report["results"]):
                key = (row["task"], row["attack"], row["seed"])
                observed[key] = (digest(canonical_json(row)), path, "/results/" + str(j))
        cells.append(observed)
    require(len(cells) == 2, "cross-run comparison requires the two retained runs")
    identical = []
    shared = sorted(cells[0].keys() & cells[1].keys())
    for key in shared:
        first, second = cells[0][key], cells[1][key]
        if first[0] == second[0]:
            identical.append({"task": key[0], "arm": key[1], "seed": key[2],
                              "canonicalEpisodeSha256": first[0],
                              "sources": [{"path": first[1], "pointer": first[2]},
                                          {"path": second[1], "pointer": second[2]}]})
    return {"sharedTaskSeedArmCells": len(shared), "identicalNativeObjects": identical,
            "identicalBaselineObjects": sum(c["arm"] == "none" for c in identical),
            "comparator": "SHA-256 of complete compact sorted native episode objects",
            "freshIndependentBaselineExecutionEstablished": False,
            "pooledAcrossRuns": False}


def retain_source_zip(output: Path, sources: Mapping[str, bytes], source_record: bytes) -> None:
    """Retain complete bound files as a deterministic archive with original paths."""
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, raw in sorted({**sources, "probity-source-record.json": source_record}.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, raw, compresslevel=9)


def main(argv: Sequence[str] | None = None) -> int:
    """Reconstruct a source-bound report and optionally retain every original file."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True,
                        help="complete pinned Provael checkout or extracted retained source archive")
    parser.add_argument("--expect", type=Path, help="require the exact retained report bytes")
    parser.add_argument("--output", type=Path, help="write compact source-bound JSON report")
    parser.add_argument("--retain-source-zip", type=Path, help="retain every bound complete source file")
    args = parser.parse_args(argv)
    try:
        report, sources = build_report(args.source_root)
        raw = serialize_report(report)
        if args.expect:
            expected = args.expect.read_bytes()
            parse_json(expected, MAX_REPORT_BYTES)
            require(expected == raw, "retained report differs from source reconstruction")
        if args.retain_source_zip:
            retain_source_zip(args.retain_source_zip, sources, (EXAMPLE / "source-record.json").read_bytes())
        if args.output:
            args.output.write_bytes(raw)
        else:
            sys.stdout.buffer.write(raw)
        return 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        LOGGER.error("Provael controls refused: %s", error)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
