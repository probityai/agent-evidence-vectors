"""The generated tables agree with matrix.json, and every mutant changes what it says it changes."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import mutants as M  # noqa: E402
import render  # noqa: E402

SAMPLE: dict[str, Any] = {
    "format": "public-agent-conformance/report/v0.1",
    "domain": {"id": "d"},
    "checks": [
        {"check": "a", "state": "pass"},
        {"check": "b", "state": "fail"},
        {"check": "c", "state": "inconclusive", "cause": {"code": "unavailable"}},
        {"check": "d", "state": "not-exercised", "cause": {"code": "withheld"}},
        {"check": "e", "state": "pass", "other-verdict": {"value": "demonstrated", "ref": "e1"},
         "discrimination": {"value": "demonstrated", "ref": "e1"}},
    ],
    "evidence": [{"id": "e1", "changed": "input artifact", "fixed": {"checker": "k", "constraint-set": "s",
                  "domain": "d"}, "compared": ["verdict", "fired-rule list"], "moved": ["verdict"],
                  "delta": {"changes": [{"field": "x"}]},
                  "observations": [{"carried": {"verdict": "pass", "rules": []}},
                                   {"carried": {"verdict": "fail", "rules": []}}]}],
    "roll-up": {"declared": 5, "exercised": 4, "pass": 2, "fail": 1, "inconclusive": 1,
                "not-exercised": 1, "void": 0, "carried": 2, "referenced": 0,
                "negative-capable": {"kind": "shown-by-run"},
                "completeness": {"accounting": {"population": 5, "claim": "satisfied"}}},
    "check-set": {"sha256": "ab" * 32, "leaf-count": 5, "tree-shape": "flat"},
}


def leaves(value: Any, prefix: tuple[Any, ...] = ()) -> dict[tuple[Any, ...], Any]:
    """Every member path of a JSON value, objects and arrays included, with its value."""
    out: dict[tuple[Any, ...], Any] = {prefix: value if not isinstance(value, (dict, list)) else type(value).__name__}
    items = value.items() if isinstance(value, dict) else enumerate(value) if isinstance(value, list) else []
    for key, child in items:
        out.update(leaves(child, prefix + (key,)))
    return out


def changed_members(a: Any, b: Any) -> set[tuple[Any, ...]]:
    """The topmost paths at which two values differ."""
    la, lb = leaves(a), leaves(b)
    diff = {p for p in set(la) | set(lb) if la.get(p) != lb.get(p)}
    return {p for p in diff if not any(p[: n] in diff for n in range(len(p)))}


def jcs(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def test_every_single_field_mutant_changes_one_member() -> None:
    made, _ = M.mutants(SAMPLE, jcs)
    singles = [m for m in made if m["fields_changed"] == 1]
    assert {m["mutant"] for m in singles} == {name for name, _, _ in M.SINGLE}
    for m in singles:
        assert len(changed_members(SAMPLE, m["report"])) == 1, m["mutant"]


def test_the_sample_admits_a_mutant_for_every_target() -> None:
    _, skipped = M.mutants(SAMPLE, jcs)
    assert skipped == []


def test_the_non_ascii_pair_differs_only_in_the_root() -> None:
    made, _ = M.mutants(SAMPLE, jcs, ("non-ascii-root-utf8", "non-ascii-root-escaped"))
    utf8, escaped = (m["report"] for m in made)
    assert changed_members(utf8, escaped) == {("check-set", "sha256")}
    assert changed_members(SAMPLE, utf8) == {("checks", 0, "check"), ("check-set", "sha256")}


def test_a_report_with_nothing_to_aim_at_says_why() -> None:
    bare = {"format": "public-agent-conformance/report/v0.1", "checks": [{"check": "a", "state": "pass"}]}
    _, skipped = M.mutants(bare, jcs)
    reasons = {s["mutant"]: s["why"] for s in skipped}
    assert "row12-checker-changed" in reasons and reasons["row12-checker-changed"]


def test_numbered_rows_map_to_the_table() -> None:
    assert M.table_row("W3C-R-025") == 13 and M.table_row("W3C-R-026") == 14
    assert M.table_row("W3C-R-020") is None


@pytest.mark.skipif(not render.MATRIX.is_file(), reason="matrix.json is written from a run")
def test_generated_files_agree_with_matrix_json() -> None:
    assert render.stale() == []


@pytest.mark.skipif(not render.MATRIX.is_file(), reason="matrix.json is written from a run")
def test_controls_are_recounted_from_the_cells() -> None:
    sys.path.insert(0, str(HERE))
    import matrix  # noqa: PLC0415
    doc = json.loads(render.MATRIX.read_text(encoding="utf-8"))
    assert matrix.controls(doc["readers"], doc["inputs"], doc["cells"]) == doc["controls"]
