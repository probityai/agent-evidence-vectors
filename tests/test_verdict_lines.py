"""Corpus verdict lines: the schema, the validator, and the reference rail's corpus mode.

The rail's corpus mode runs over the AEE corpus and the two record-family
corpora; every line must satisfy the schema (checked by the stdlib validator and
by jsonschema against the schema file, which must agree), every manifest member
must be answered once, and every answer must match the manifest. Each guarantee
is then broken on purpose and the validator must notice.
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packaging"))
import run_vectors
from agent_evidence_vectors import verdictlines

CORPORA = [ROOT / "vectors", ROOT / "corpora/vectors-approval-binding",
           ROOT / "corpora/vectors-uncertain-effect"]
SCHEMA = json.loads((ROOT / "vectors/verdict-line.schema.json").read_text(encoding="utf-8"))
VERIFIER = ("agent-evidence-vectors", "test")


@pytest.fixture(scope="module")
def corpora() -> list[verdictlines.Corpus]:
    return [verdictlines.load_corpus(str(p)) for p in CORPORA]


@pytest.fixture(scope="module")
def rail_lines() -> list[dict]:
    return [line for p in CORPORA for line in run_vectors.corpus_verdict_lines(str(p), VERIFIER)]


def _bare(line: dict, **changes: str) -> dict:
    """``line`` with ``changes`` applied and no result token, as a non-accept line carries none."""
    out = {k: v for k, v in line.items() if k != "result"}
    out.update(changes)
    return out


def _text(lines: list[dict]) -> str:
    return "\n".join(verdictlines.dumps(line) for line in lines) + "\n"


def test_schema_id_matches_module() -> None:
    assert SCHEMA["$id"] == verdictlines.SCHEMA_ID
    assert set(SCHEMA["properties"]) == verdictlines.LINE_KEYS
    assert set(SCHEMA["required"]) == verdictlines.REQUIRED_KEYS
    assert tuple(SCHEMA["properties"]["verdict"]["enum"]) == verdictlines.VERDICTS


def test_rail_answers_every_member_as_the_manifest_expects(corpora, rail_lines) -> None:
    total = sum(len(c.members) for c in corpora)
    assert len(rail_lines) == total == 288 + 37 + 40
    for line in rail_lines:
        jsonschema.validate(line, SCHEMA)
        assert verdictlines.validate_line(line) == []
    report = verdictlines.check(_text(rail_lines), corpora)
    assert report.failures == []
    assert report.answered == total and report.not_applicable == 0 and report.errors == 0


def test_check_counts_against_the_manifest_not_the_lines(corpora, rail_lines) -> None:
    # The validator's verdict on each line comes from the manifest: flipping
    # every line's verdict must fail every line, not just some.
    swap = {"accept": "reject", "reject": "accept"}
    flipped = [dict(ln, verdict=swap[ln["verdict"]]) for ln in rail_lines]
    for ln in flipped:
        ln.pop("result", None)
        if ln["verdict"] == "reject" and ln["reason"] is None:
            ln["reason"] = "flipped"
    report = verdictlines.check(_text(flipped), corpora)
    wrong = [f for f in report.failures if "the manifest expects" in f]
    # The two indeterminate members declare only refusing readings, so they too admit only reject.
    assert len(wrong) == len(rail_lines)


@pytest.mark.parametrize(
    "mutate, needle",
    [
        (lambda ls: ls[1:], "unanswered"),
        (lambda ls: ls + ls[:1], "answered twice"),
        (lambda ls: [dict(ls[0], vector="v-not-in-any-manifest")] + ls[1:], "no such member"),
        (lambda ls: [dict(ls[0], corpusDigest="0" * 64)] + ls[1:], "corpusDigest"),
        (lambda ls: [dict(ls[0], suite="unknown/v1")] + ls[1:], "no corpus handed in"),
        (lambda ls: [_bare(ls[0], verdict="error", reason="crash")] + ls[1:], "could not answer"),
        (
            lambda ls: [_bare(ls[0], verdict="not-applicable", reason="x")] + ls[1:],
            "not-applicable",
        ),
        (lambda ls: [dict(ls[0], verifier={"name": "other", "version": "1"})] + ls[1:], "differs"),
    ],
)
def test_each_guarantee_is_enforced(corpora, rail_lines, mutate, needle) -> None:
    report = verdictlines.check(_text(mutate(copy.deepcopy(rail_lines))), corpora)
    assert any(needle in f for f in report.failures), report.failures


def test_wrong_result_and_normative_reason_fail(corpora, rail_lines) -> None:
    aee_accept = next(i for i, ln in enumerate(rail_lines) if ln.get("result"))
    decision = next(i for i, ln in enumerate(rail_lines) if ln["suite"] == "approval-binding/v1")
    lines = copy.deepcopy(rail_lines)
    lines[aee_accept]["result"] = "not-a-result"
    lines[decision]["reason"] = "not-the-reason"
    failures = verdictlines.check(_text(lines), corpora).failures
    assert any("result 'not-a-result'" in f for f in failures)
    assert any("reason 'not-the-reason'" in f for f in failures)


def test_aee_reason_codes_are_parity_not_conformance(corpora, rail_lines) -> None:
    lines = copy.deepcopy(rail_lines)
    reject = next(
        ln for ln in lines if ln["suite"].startswith("adversarial") and ln["verdict"] == "reject"
    )
    reject["reason"] = "a-code-of-another-vocabulary"
    report = verdictlines.check(_text(lines), corpora)
    assert report.failures == [] and report.reason_parity["differ"] == 1


@pytest.mark.parametrize(
    "line",
    [
        {},
        {"schema": "x"},
        dict.fromkeys(verdictlines.REQUIRED_KEYS, "x"),
    ],
)
def test_validator_and_jsonschema_agree_on_bad_lines(line) -> None:
    assert verdictlines.validate_line(line)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(line, SCHEMA)


def test_validator_and_jsonschema_agree_on_each_field(rail_lines) -> None:
    base = rail_lines[0]
    cases = [
        dict(base, verdict="valid"),
        dict(base, reason=""),
        dict(base, verdict="reject", reason=None),
        dict(base, verdict="reject", reason="x", result="pass"),
        dict(base, verifier={"name": "a"}),
        dict(base, corpusDigest="ABC"),
        dict(base, extra=1),
    ]
    for case in cases:
        stdlib = bool(verdictlines.validate_line(case))
        try:
            jsonschema.validate(case, SCHEMA)
            schema_bad = False
        except jsonschema.ValidationError:
            schema_bad = True
        assert stdlib and schema_bad, case


def test_agree_finds_a_disagreement_and_an_unanswered_member(corpora, rail_lines) -> None:
    second = copy.deepcopy(rail_lines)
    for ln in second:
        ln["verifier"] = {"name": "second", "version": "1"}
    same = verdictlines.agree([verdictlines.check(_text(rail_lines), corpora),
                               verdictlines.check(_text(second), corpora)])
    assert same["ok"] and same["answeredBy"] == {"2": len(rail_lines)}

    second[0]["verdict"] = "reject" if second[0]["verdict"] == "accept" else "accept"
    second[0]["reason"] = second[0]["reason"] or "flipped"
    second[0].pop("result", None)
    split = verdictlines.agree([verdictlines.check(_text(rail_lines), corpora),
                                verdictlines.check(_text(second), corpora)])
    assert not split["ok"] and len(split["disagreements"]) == 1

    # A not-applicable member leaves one answer: under-answered, not agreement.
    na = copy.deepcopy(rail_lines)
    for ln in na:
        ln["verifier"] = {"name": "second", "version": "1"}
    na[0].update(verdict="not-applicable", reason="suite-not-implemented")
    na[0].pop("result", None)
    out = verdictlines.agree([verdictlines.check(_text(rail_lines), corpora),
                              verdictlines.check(_text(na), corpora, allow_not_applicable=True)])
    assert not out["ok"] and len(out["underAnswered"]) == 1
