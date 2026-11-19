"""The corpus regenerates byte for byte, the reference reader agrees with every case, the governance
fields hold,
and a reader that drops the grouping, revocation, identity or tag-registry rule is refused."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("lifecycle_binding_corpus", ROOT / "check_vectors.py")
generator = _load("lifecycle_binding_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import lifecyclebinding as reader  # noqa: E402

MANIFEST = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {
        p.relative_to(ROOT): p.read_bytes()
        for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")]
        if p.is_file()
    }
    regenerated = {
        p.relative_to(tmp_path): p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()
    }
    assert regenerated == committed


def test_reference_reader_agrees_with_every_case() -> None:
    answered, errors = corpus.check()
    assert errors == []
    assert answered == len(MANIFEST["vectors"])


def test_families_and_governance() -> None:
    families = {}
    for vector in MANIFEST["vectors"]:
        families[vector["family"]] = families.get(vector["family"], 0) + 1
        assert vector["expectedClass"] in ("positive", "negative", "absent")
    assert families["lifecycle-shape"] == 11
    assert {"binding-scope", "tag-confusion", "admissibility"} <= set(families)
    assert MANIFEST["keySeedLabel"] == "aev-lifecycle-binding-vectors/"
    assert (ROOT / "REVISIONS.md").is_file()
    for path in (ROOT / "cases").glob("*/record.json"):
        assert json.loads(path.read_text(encoding="utf-8"))["does_not_establish"].startswith(
            "that the executed"
        )


def test_absent_evidence_is_never_satisfied() -> None:
    for vector in MANIFEST["vectors"]:
        if vector["expectedClass"] == "absent":
            assert vector["expected"]["decision"] != "satisfied"


def _first_pair(case: dict) -> str:
    """The old rule: compare the first authorization with the first execution and stop."""
    records = json.loads(case["records_text"])
    controls = [r for r in records if r.get("artifact_type") == "control"]
    executions = [r for r in records if r.get("artifact_type") == "execution"]
    if not controls or not executions:
        return "missing"
    return (
        "satisfied"
        if controls[0]["authorized_action_digest"] == executions[0]["executed_action_digest"]
        else "failure"
    )


def test_the_first_pair_rule_fails_the_corpus() -> None:
    """A regression test with no case identifiers: the old rule must disagree with the corpus
    somewhere."""
    wrong = 0
    for vector in MANIFEST["vectors"]:
        case = json.loads((ROOT / vector["path"] / "record.json").read_text(encoding="utf-8"))
        try:
            got = _first_pair(case)
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
        wrong += got != vector["expected"]["decision"]
    assert wrong >= 5


RULES = {
    "grouping": (
        '(record["decision_ref"]["record_id"], record["instruction_id"]), []',
        '(record["decision_ref"]["record_id"], "all"), []',
        "scope-v1-cross-instruction",
    ),
    "revocation": (
        '            revocation.get(r["producer"], {}).get("state") != "active"\n',
        "            False\n",
        "scope-v4-revoked-executor",
    ),
    "identity": (
        "    shared = {i for i in ids if ids.count(i) > 1}",
        "    shared = set()",
        "scope-v3-duplicate-execution-identity",
    ),
    "tag-registry": (
        '    if record.get("lifecycle_version") != "v1" or '
        'record.get("artifact_type") not in TYPES:',
        '    if record.get("artifact_type") not in TYPES:',
        "tag-a9-other-version",
    ),
}


@pytest.mark.parametrize("rule", sorted(RULES))
def test_a_reader_without_the_rule_fails_its_vectors(rule: str, tmp_path: Path) -> None:
    old, new, case_id = RULES[rule]
    source = Path(reader.__file__).read_text(encoding="utf-8")
    assert old in source
    mutant = tmp_path / "mutant_reader.py"
    mutant.write_text(source.replace(old, new, 1), encoding="utf-8")
    module = _load(f"mutant_{rule.replace('-', '_')}", mutant)
    case = json.loads((ROOT / "cases" / case_id / "record.json").read_text(encoding="utf-8"))
    want = next(v["expected"] for v in MANIFEST["vectors"] if v["id"] == case_id)
    try:
        answer = module.judge(case)
    except (KeyError, ValueError, TypeError):
        answer = None
    assert answer != want
