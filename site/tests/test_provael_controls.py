"""Independent finite oracles and source-refusal checks for published robot controls."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import itertools
import json
import logging
import os
import re
import zipfile
from collections import Counter
from fractions import Fraction
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings, strategies as st

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("atlas_provael_controls", ROOT / "tools/check_provael_controls.py")
assert SPEC is not None and SPEC.loader is not None
READER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(READER)
EXAMPLE = ROOT / "examples/provael-task-controls"
ORIGINAL_REGISTER_SHA256 = "993dd8de2a21e4e1a7f3a978e2be956726ac0f20b2d632a21c85e873ef5e65bf"


def original_register_digest(register: dict[str, Any]) -> str:
    """Authenticate the original wrapper and ordered records as runs are appended."""
    if len(register["records"]) < 19:
        raise ValueError("original register is truncated")
    original = {**register, "records": register["records"][:19]}
    raw = (json.dumps(original, indent=2) + "\n").encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def exhaustive(vectors: list[tuple[int, ...]]) -> Counter[tuple[int, ...]]:
    """Independent ordered-product oracle, deliberately avoiding DP compression."""
    return Counter(tuple(sum(vectors[i][j] for i in draw) for j in range(len(vectors[0])))
                   for draw in itertools.product(range(len(vectors)), repeat=len(vectors)))


def count_tasks(vectors: list[tuple[int, ...]], n: int = 3) -> list[dict[str, Any]]:
    """Build a small authored count fixture with every arm kept in each task."""
    return [{"taskId": "task-" + str(i), "counts": {
        a: {"records": n, "applicable": n, "unsafe": v[j], "notApplicable": 0, "unresolved": 0}
        for j, a in enumerate(("none", "roleplay"))}} for i, v in enumerate(vectors)]


@pytest.fixture
def shard() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Small source-shaped illustration, with explicit native matching declarations."""
    run = {"arms": ["none", "roleplay", "mcp_tool_desc"], "seeds": [0, 1],
           "roles": {"none": "benign-control", "roleplay": "adversarial-treatment",
                     "mcp_tool_desc": "adversarial-treatment"},
           "notApplicableArms": ["mcp_tool_desc"], "declaredRuntimeCommit": None}
    conditions = {"policy": "smolvla", "suite": "libero", "horizon": 280,
                  "accelerator": "cuda", "precision": None, "evidence_state": "real-episode"}
    rows = [{"attack": a, "seed": s, "policy_seed": s, "task": "libero_object/0",
             "applicable": a != "mcp_tool_desc", "success": a == "roleplay",
             "task_success": None if a == "mcp_tool_desc" else a == "none",
             "original_instruction": "pick up the object", "adversarial_instruction": a,
             "steps": 0 if a == "mcp_tool_desc" else 1,
             "decisions": [] if a == "mcp_tool_desc" else [{"unsafe": a == "roleplay"}],
             "danger": 0.0, "threshold": 0.0} for a in run["arms"] for s in run["seeds"]]
    report = {**conditions, "schema_version": 5, "tasks": ["libero_object/0"],
              "attacks": run["arms"], "roles": run["roles"], "seed": 0, "seeds": 2,
              "episodes": 2, "model": "HuggingFaceVLA/smolvla_libero", "tool_version": "0.41.2",
              "calibrated": False, "calibration": {}, "results": rows, "attempts": 4, "successes": 2,
              "by_attack": {a: {"attempts": 0 if a == "mcp_tool_desc" else 2,
                                 "successes": 2 if a == "roleplay" else 0,
                                 "asr": 1.0 if a == "roleplay" else 0.0} for a in run["arms"]}}
    manifest = {**conditions, "manifest_schema_version": 2, "package_version": "0.41.2",
                "attacks": run["arms"], "seeds": 2,
                **{k: None for k in READER.PROVENANCE_FIELDS},
                "report_digest": READER.digest(READER.canonical_json(report))}
    return report, manifest, run


def rebind(report: dict[str, Any], manifest: dict[str, Any]) -> None:
    """Let domain tests reach their target condition after changing illustrative bytes."""
    manifest["report_digest"] = READER.digest(READER.canonical_json(report))


@pytest.fixture
def native_root() -> Path:
    """Native CI always sets this to the exact required full publisher checkout."""
    path = os.environ.get("PROVAEL_SOURCE_ROOT")
    if path is None:
        pytest.skip("complete publisher source checkout not selected in this test runtime")
    return Path(path)


class TestJointTaskCounts:
    class TestPassingCases:
        @settings(max_examples=60, deadline=None)
        @given(st.lists(st.tuples(st.integers(0, 3), st.integers(0, 3)), min_size=1, max_size=4))
        def test_independent_exhaustive_oracle(self, vectors: list[tuple[int, int]]) -> None:
            actual = READER.joint_task_counts(vectors)
            assert actual == exhaustive(vectors)
            assert sum(actual.values()) == len(vectors) ** len(vectors)

        def test_arms_share_task_draw_and_repeats_stay_together(self) -> None:
            vectors = [(3, 0), (0, 3)]
            assert READER.joint_task_counts(vectors) == {(6, 0): 1, (3, 3): 2, (0, 6): 1}
            assert (3, 0) not in READER.joint_task_counts(vectors)

        def test_duplicate_task_vectors_retain_multiplicity(self) -> None:
            vectors = [(0, 3), (0, 3), (3, 0)]
            assert READER.joint_task_counts(vectors) == exhaustive(vectors)
            assert READER.joint_task_counts(vectors)[(0, 9)] == 8

        def test_every_finite_weighted_quantile_matches_expansion(self) -> None:
            states = READER.joint_task_counts([(0, 3), (2, 1), (3, 0)])
            distribution: Counter[Fraction] = Counter()
            for counts, weight in states.items():
                distribution[Fraction(counts[1] - counts[0], 9)] += weight
            expanded = sorted(v for v, w in distribution.items() for _ in range(w))
            for p in [Fraction(0), Fraction(1, 40), Fraction(1, 2), Fraction(39, 40), Fraction(1)]:
                rank = max(1, -((-p.numerator * len(expanded)) // p.denominator))
                assert READER.quantile(distribution, p) == expanded[rank - 1]

    class TestFailingCases:
        @pytest.mark.parametrize("vectors,reason", [
            ([], "task resampling population is unsupported"),
            ([()] , "task count vectors have inconsistent dimensions"),
            ([(1, 2), (1,)] , "task count vectors have inconsistent dimensions"),
            ([(-1, 0)], "task count vector contains an impossible count"),
            ([(True, 0)], "task count vector contains an impossible count"),
            ([(1.2, 0)], "task count vector contains an impossible count"),
            ([(1025, 0)], "task count vector contains an impossible count"),
            ([(0,)] * 13, "task resampling population is unsupported"),
        ])
        def test_impossible_population_refused(self, vectors: Any, reason: str) -> None:
            with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"):
                READER.joint_task_counts(vectors)

        def test_state_cap_is_checked_before_unbounded_growth(self, monkeypatch: pytest.MonkeyPatch) -> None:
            monkeypatch.setattr(READER, "MAX_STATES", 2)
            with pytest.raises(ValueError, match="^joint task distribution exceeds the state cap$"):
                READER.joint_task_counts([(0, 0), (1, 2)])


class TestResamplingReport:
    class TestPassingCases:
        def test_clone_repeats_does_not_add_task_draws_or_change_bounds(self) -> None:
            tasks = count_tasks([(0, 3), (1, 3), (0, 1)])
            original = READER.resampling_report(tasks, ["none", "roleplay"])
            clones = copy.deepcopy(tasks)
            for task in clones:
                for c in task["counts"].values():
                    for field in ("records", "applicable", "unsafe"):
                        c[field] *= 2
            doubled = READER.resampling_report(clones, ["none", "roleplay"])
            assert original["orderedDrawsRepresented"] == doubled["orderedDrawsRepresented"] == 27
            assert original["armIntervals"] == doubled["armIntervals"]
            assert original["pairedContrasts"] == doubled["pairedContrasts"]
            assert original["taskIds"] == doubled["taskIds"]

        @pytest.mark.parametrize("vectors", [[(0, 0)] * 3, [(3, 3)] * 3, [(0, 3)] * 3])
        def test_degenerate_distribution_does_not_certify_population(self, vectors: Any) -> None:
            result = READER.resampling_report(count_tasks(vectors), ["none", "roleplay"])
            assert result["distinctJointStates"] == 1
            assert result["pairedContrasts"]["roleplay_minus_none"]["interval"]["degenerate"] is True
            for interval in result["armIntervals"].values():
                assert interval["coverageEstablished"] is False
                assert interval["independentUnitsVerified"] is None
                assert interval["taskIndependence"] == "unknown"

        def test_not_applicable_population_keeps_no_rate_or_interval(self) -> None:
            tasks = count_tasks([(0, 0), (0, 0)])
            for task in tasks:
                task["counts"]["roleplay"].update(applicable=0, notApplicable=3)
            result = READER.resampling_report(tasks, ["none", "roleplay"])
            assert result["armIntervals"]["roleplay"] is None
            assert result["pairedContrasts"]["roleplay_minus_none"] is None
            assert len(result["taskIds"]) == 2

    class TestFailingCases:
        @pytest.mark.parametrize("field,value,reason", [
            ("applicable", 2, "task arm record counts do not add up"),
            ("unresolved", 1, "task arm record counts do not add up"),
            ("unsafe", 4, "task unsafe numerator exceeds its denominator"),
            ("records", 0, "task arm record counts do not add up"),
        ])
        def test_groups_are_not_silently_dropped(self, field: str, value: int, reason: str) -> None:
            tasks = count_tasks([(0, 3), (0, 1)])
            tasks[0]["counts"]["roleplay"][field] = value
            with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"):
                READER.resampling_report(tasks, ["none", "roleplay"])

        def test_partial_applicability_is_not_hidden_in_constant_denominators(self) -> None:
            tasks = count_tasks([(0, 1), (0, 1)], n=2)
            for task in tasks:
                task["counts"]["roleplay"].update(applicable=1, notApplicable=1)
            with pytest.raises(ValueError, match="^partially applicable task arm cannot enter the exact profile$"):
                READER.resampling_report(tasks, ["none", "roleplay"])

        def test_consistent_unequal_allocation_is_refused(self) -> None:
            tasks = count_tasks([(0, 3), (0, 1)])
            tasks[0]["counts"]["roleplay"].update(records=4, applicable=4)
            with pytest.raises(ValueError, match="^task denominators differ; exact equal-allocation profile refused$"):
                READER.resampling_report(tasks, ["none", "roleplay"])

        def test_consistent_unresolved_population_is_refused(self) -> None:
            tasks = count_tasks([(0, 3), (0, 1)])
            tasks[0]["counts"]["roleplay"].update(records=4, unresolved=1)
            with pytest.raises(ValueError, match="^unresolved labels cannot enter the exact resolved profile$"):
                READER.resampling_report(tasks, ["none", "roleplay"])

        def test_genuinely_empty_task_arm_is_refused(self) -> None:
            tasks = count_tasks([(0, 0), (0, 0)])
            for task in tasks:
                task["counts"]["roleplay"].update(records=0, applicable=0)
            with pytest.raises(ValueError, match="^empty task arm cannot support matched resampling$"):
                READER.resampling_report(tasks, ["none", "roleplay"])


class TestNativeShard:
    class TestPassingCases:
        def test_applied_seed_pairing_unknown_provenance_and_na_retained(self, shard: Any) -> None:
            report, manifest, run = shard
            result = READER.validate_shard(report, manifest, run, "libero_object/0")
            assert result["executionManifest"] == manifest
            assert result["executionManifest"]["commit"] is None
            assert result["counts"]["mcp_tool_desc"] == {
                "records": 2, "applicable": 0, "unsafe": 0, "notApplicable": 2, "unresolved": 0}
            assert all(row["unsafe"] is None for row in result["outcomes"] if not row["applicable"])
            assert result["cleanTaskSuccess"] == {"numerator": 2, "denominator": 2}

    class TestFailingCases:
        @pytest.mark.parametrize("field,value,reason", [
            ("success", None, "native episode contains an unknown outcome label"),
            ("success", "success", "native episode contains an unknown outcome label"),
            ("applicable", 1, "native episode contains an unknown outcome label"),
            ("task_success", "unresolved", "native episode contains an unknown outcome label"),
            ("seed", True, "native episode task/seed/arm differs"),
            ("seed", 3, "native episode task/seed/arm differs"),
            ("policy_seed", 1, "native policy seed differs from matched seed"),
            ("task", "libero_object/1", "native episode task/seed/arm differs"),
            ("attack", "unknown", "native episode task/seed/arm differs"),
            ("original_instruction", "different task", "native original instructions do not match"),
            ("success", True, "native episode and decision unsafe flags differ"),
            ("steps", 2, "native decision count differs"),
        ])
        def test_outcomes_and_matching_refused(self, shard: Any, field: str, value: Any, reason: str) -> None:
            report, manifest, run = shard
            report["results"][0][field] = value
            rebind(report, manifest)
            with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"):
                READER.validate_shard(report, manifest, run, "libero_object/0")

        def test_repeated_cell_is_not_an_independent_new_seed(self, shard: Any) -> None:
            report, manifest, run = shard
            report["results"][1] = copy.deepcopy(report["results"][0])
            rebind(report, manifest)
            with pytest.raises(ValueError, match="^native task repeats a seed/arm cell$"):
                READER.validate_shard(report, manifest, run, "libero_object/0")

        def test_declared_success_count_cannot_override_labels(self, shard: Any) -> None:
            report, manifest, run = shard
            report["by_attack"]["none"]["successes"] = 1
            rebind(report, manifest)
            with pytest.raises(ValueError, match="^native per-arm counts differ from episode labels$"):
                READER.validate_shard(report, manifest, run, "libero_object/0")

        def test_unknown_runtime_commit_cannot_be_backfilled(self, shard: Any) -> None:
            report, manifest, run = shard
            manifest["commit"] = READER.PUBLICATION_COMMIT
            with pytest.raises(ValueError, match="^native runtime commit declaration differs$"):
                READER.validate_shard(report, manifest, run, "libero_object/0")


class TestSourcesAndCli:
    class TestPassingCases:
        def test_native_reconstruction_matches_complete_retained_report(self, native_root: Path) -> None:
            report, sources = READER.build_report(native_root)
            assert READER.serialize_report(report) == (EXAMPLE / "report.json").read_bytes()
            assert len(sources) == 57
            assert [run["records"] for run in report["runs"]] == [400, 180]
            assert [run["applicable"] for run in report["runs"]] == [350, 180]
            assert [run["notApplicable"] for run in report["runs"]] == [50, 0]
            assert report["crossRunOverlap"]["identicalBaselineObjects"] == 30
            assert report["crossRunOverlap"]["pooledAcrossRuns"] is False
            for run in report["runs"]:
                assert run["resampling"]["drawWeightsSum"] == 10**10
                assert len(run["tasks"]) == 10
                assert all(arm["weightingTargetsCoincide"] for arm in run["arms"].values())
            assert [run["resampling"]["distinctJointStates"] for run in report["runs"]] == [9581, 1716]

        def test_source_archive_preserves_complete_original_members(self, tmp_path: Path) -> None:
            sources = {"a/report.json": b'{"success":true}\n', "LICENSE": b"original license\n"}
            archive = tmp_path / "source.zip"
            READER.retain_source_zip(archive, sources, b'{"files":[]}\n')
            first = archive.read_bytes()
            with zipfile.ZipFile(archive) as z:
                assert set(z.namelist()) == {*sources, "probity-source-record.json"}
                assert all(z.read(p) == raw for p, raw in sources.items())
            READER.retain_source_zip(archive, sources, b'{"files":[]}\n')
            assert archive.read_bytes() == first

        def test_original_register_and_first_worked_input_are_immutable(self) -> None:
            register = READER.parse_json((ROOT / "data/lab-register.json").read_bytes())
            assert original_register_digest(register) == ORIGINAL_REGISTER_SHA256
            assert hashlib.sha256((ROOT / "examples/task-grouped-rates/input.json").read_bytes()).hexdigest() == (
                "92940ce8ee827ad09e895ea18903d7f49d7ce94d1bcb1d8fce5d5eba0180bfea")
            assert hashlib.sha256((ROOT / "examples/task-grouped-rates/report.json").read_bytes()).hexdigest() == (
                "f1ed9b4c8b8c4c5f8961926ed2a7ef3553c9c21c24a8191a4648d82717a30650")

    class TestFailingCases:
        @pytest.mark.parametrize("change", ["record", "order", "wrapper", "truncate"])
        def test_original_register_changes_are_refused(self, change: str) -> None:
            register = READER.parse_json((ROOT / "data/lab-register.json").read_bytes())
            register["records"] = register["records"][:19]
            if change == "record":
                register["records"][0]["reviewState"] = "changed"
            elif change == "order":
                register["records"][0], register["records"][1] = register["records"][1], register["records"][0]
            elif change == "wrapper":
                register["protocolVersion"] = "changed"
            else:
                register["records"].pop()
            if change == "truncate":
                with pytest.raises(ValueError, match="^original register is truncated$"):
                    original_register_digest(register)
            else:
                assert original_register_digest(register) != ORIGINAL_REGISTER_SHA256

        @pytest.mark.parametrize("raw,reason", [
            (b'{"x":1,"x":2}', "JSON repeats a field"),
            (b'{"x":NaN}', "JSON contains a non-finite number"),
            (b'{"x":Infinity}', "JSON contains a non-finite number"),
            (b'{"x":1e999}', "JSON contains a non-finite number"),
            (b'[]', "JSON root must be an object"),
            (b'{', "source must be valid bounded-depth UTF-8 JSON"),
        ])
        def test_ambiguous_or_nonfinite_json(self, raw: bytes, reason: str) -> None:
            with pytest.raises(ValueError, match="^" + re.escape(reason) + "$"):
                READER.parse_json(raw)

        def test_source_file_change_is_detected_without_trusting_head(self, tmp_path: Path) -> None:
            p = tmp_path / "report.json"
            raw = b'{"success":true}'
            p.write_bytes(raw)
            record = {"publicationCommit": READER.PUBLICATION_COMMIT,
                      "files": [{"path": p.name, "bytes": len(raw), "sha256": READER.digest(raw)}]}
            assert READER.bind_sources(tmp_path, record) == {p.name: raw}
            p.write_bytes(b'{"success":null}')
            with pytest.raises(ValueError, match="^source file byte binding differs: report.json$"):
                READER.bind_sources(tmp_path, record)

        def test_substituted_source_record_cannot_reselect_raw_inputs(self, tmp_path: Path) -> None:
            p = tmp_path / "source-record.json"
            p.write_bytes(b'{"files":[]}')
            with pytest.raises(ValueError, match="^reader trust-anchor bytes changed$"):
                READER.trusted_document(p, READER.SOURCE_RECORD_SHA256)

        def test_refusal_is_logged_and_leaves_no_report(self, tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
            output = tmp_path / "out.json"
            with caplog.at_level(logging.ERROR, logger="atlas.provael_controls"):
                code = READER.main(["--source-root", str(tmp_path), "--output", str(output)])
            assert code == 1 and not output.exists()
            assert len(caplog.messages) == 1
            assert caplog.messages[0].startswith("Provael controls refused: required complete source file is missing: ")

        def test_oversized_serialization_fails_before_output(self, monkeypatch: pytest.MonkeyPatch) -> None:
            monkeypatch.setattr(READER, "MAX_REPORT_BYTES", 20)
            with pytest.raises(ValueError, match="^report exceeds the declared byte cap$"):
                READER.serialize_report({"x": "x" * 100})
