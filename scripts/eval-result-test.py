"""Challenge the evaluation-result reader: every case, every repair, every rule kill.

Properties proved here, not assumed:

* every case reads as its expected answer, and every negative reads with exactly the reason
  it names;
* the input a negative's repair produces is its positive twin, and reads as the twin does,
  so no negative refuses for some other reason;
* every reason code has a negative case that carries it alone, and every group has both a
  positive and a negative case;
* every rule is load-bearing: disabling it makes at least one negative stop reporting its
  reason;
* a naive reader (one that infers a direction from the metric name, lets a verifier raise an
  origin, collapses a mixed origin and reads an absent held-out status as false) disagrees
  with the reference on at least one negative per group, so the corpus separates a reader
  that re-derives from one that repeats.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest

PACKAGING = Path(__file__).resolve().parents[1] / "packaging"
sys.path.insert(0, str(PACKAGING))

from agent_evidence_vectors.claim_record.ops import apply_ops  # noqa: E402
from agent_evidence_vectors.eval_result import reader  # noqa: E402
from agent_evidence_vectors.eval_result.reader import CODES, MalformedInput, read  # noqa: E402
from agent_evidence_vectors.eval_result.run import load_corpus, run_corpus  # noqa: E402
from agent_evidence_vectors.eval_result.run import main as evalresult_main  # noqa: E402

CORPUS = PACKAGING / "agent_evidence_vectors/eval_result/corpus"
CASES = load_corpus(CORPUS)["cases"]["cases"]
NEGATIVES = [c for c in CASES if c["kind"] == "negative"]
POSITIVES = [c for c in CASES if c["kind"] == "positive"]
BY_ID = {c["id"]: c for c in CASES}
GROUPS = sorted({c["group"] for c in CASES})


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_every_case_reads_as_expected(case: dict[str, Any]) -> None:
    assert read(case["input"]) == case["expected"]


@pytest.mark.parametrize("case", POSITIVES, ids=lambda c: c["id"])
def test_every_positive_is_clean(case: dict[str, Any]) -> None:
    assert case["expected"]["reasons"] == []


@pytest.mark.parametrize("case", NEGATIVES, ids=lambda c: c["id"])
def test_every_negative_repairs_to_its_twin(case: dict[str, Any]) -> None:
    twin = BY_ID[case["twin"]]
    repaired = apply_ops(case["input"], case["repair"])
    assert repaired == twin["input"]
    assert read(repaired) == twin["expected"]
    assert len(case["expected"]["reasons"]) == 1


def test_every_reason_code_has_a_negative_that_carries_it_alone() -> None:
    carried = {c["expected"]["reasons"][0] for c in NEGATIVES}
    assert carried == set(CODES)


@pytest.mark.parametrize("group", GROUPS)
def test_every_group_has_both_controls(group: str) -> None:
    assert any(c["group"] == group for c in POSITIVES)
    assert any(c["group"] == group for c in NEGATIVES)


@pytest.mark.parametrize("code", CODES)
def test_every_rule_is_load_bearing(code: str) -> None:
    killed = [
        c["id"]
        for c in NEGATIVES
        if code in c["expected"]["reasons"]
        and read(c["input"], disabled=frozenset({code}))["reasons"] != c["expected"]["reasons"]
    ]
    assert killed, f"disabling {code} changes no negative case"


def _naive(case: dict[str, Any]) -> dict[str, Any]:
    """A reader that repeats what is easy to repeat. It exists to be wrong."""
    out = read(case)
    results = case["results"]
    for reading, result in zip(out["readings"], results, strict=True):
        attrs = result["attributes"]
        name = str(attrs.get("gen_ai.evaluation.name", ""))
        if "gen_ai.evaluation.score.direction" not in attrs:
            reading["better"] = "lower" if name == "toxicity" else "higher"
        if "gen_ai.evaluation.items.held_out" not in attrs:
            reading["held_out"] = "not_held_out"
        for index, item in enumerate(result.get("evidence", [])):
            if item.get("verified_by"):
                reading["origins"] = ["external"]
                reading["any_self_reported"] = False
                reading["verification"][index] = "independent_party"
    out["reasons"] = []
    out["ordering"] = (
        None if out["ordering"] is None else {**out["ordering"], "verdict": "first_better"}
    )
    return out


@pytest.mark.parametrize("group", GROUPS)
def test_a_naive_reader_fails_a_negative_in_every_group(group: str) -> None:
    wrong = [
        c["id"] for c in NEGATIVES if c["group"] == group and _naive(c["input"]) != c["expected"]
    ]
    assert wrong


def test_the_naive_reader_passes_no_negative() -> None:
    assert [c["id"] for c in NEGATIVES if _naive(c["input"]) == c["expected"]] == []


def test_the_runner_replays_the_whole_corpus() -> None:
    report = run_corpus(CORPUS)
    assert report["failures"] == []
    assert len(report["results"]) == len(CASES)


@pytest.mark.parametrize(
    "bad",
    [
        [],
        {"results": "x"},
        {"results": [{}]},
        {"results": [{"attributes": {}, "evidence": ["x"]}]},
        {"results": [{"attributes": {}}], "compare": [0, 1]},
        {
            "results": [{"attributes": {"gen_ai.evaluation.score.direction": "maximize"}}] * 2,
            "compare": [0, 1],
        },
    ],
)
def test_unusable_input_is_refused_not_read(bad: Any) -> None:
    with pytest.raises(MalformedInput):
        read(bad)


def test_a_duplicate_member_is_refused() -> None:
    with pytest.raises(MalformedInput):
        reader.parse_strict(b'{"a": 1, "a": 2}')


def test_cli_exit_codes(tmp_path: Path) -> None:
    clean, dirty = BY_ID["held-out-true-required"], BY_ID["held-out-absent-is-unknown-not-false"]
    for case, code in ((clean, 0), (dirty, 1)):
        path = tmp_path / f"{case['id']}.json"
        path.write_text(json.dumps(case["input"]))
        assert evalresult_main(["read", "--input", str(path)]) == code
    junk = tmp_path / "junk.json"
    junk.write_text("[]")
    assert evalresult_main(["read", "--input", str(junk)]) == 2


def test_a_corpus_member_that_differs_from_the_manifest_is_refused(tmp_path: Path) -> None:
    copy = tmp_path / "corpus"
    copy.mkdir()
    for name in ("cases.json", "manifest.json"):
        (copy / name).write_bytes((CORPUS / name).read_bytes())
    (copy / "cases.json").write_bytes((CORPUS / "cases.json").read_bytes() + b" ")
    with pytest.raises(MalformedInput):
        load_corpus(copy)
