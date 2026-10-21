"""The five done corpora regenerate, are judged clean, and force every rule they name.

A reader that looked at nothing would judge an intact corpus clean, so each corpus is
also judged after a member's records change and the verdict must move with them.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packaging"))
sys.path.insert(0, str(ROOT / "vectors-done-receipt"))

import bundle_lib as lib  # noqa: E402
from agent_evidence_vectors import donechecks, donerun  # noqa: E402

CORPORA = {
    donerun.CONTRACT_SUITE: "vectors-done-contract",
    donerun.RECEIPT_SUITE: "vectors-done-receipt",
    donerun.SPOOFED_SUITE: "vectors-spoofed-tool-output",
    donerun.TAMPERING_SUITE: "vectors-test-tampering",
    donerun.GRADER_SUITE: "vectors-grader-isolation",
}

# Words that look like codes in the sources and are not: member names of records, role
# names and witness names. A real code is never listed here.
NOT_CODES = {
    "capability_witness", "claims_witness", "contract_sha256", "contract_witness",
    "grade_witness", "observation_witness", "tree_sha256", "tree_witness", "receipt_witness",
    "contract_acceptance", "contract_adequacy", "contract_protected_path", "case_artifact",
    "case_artifact_path", "claims_entry", "claims_completion", "grade_result", "grade_hunk",
    "grade_detectors", "observation_event", "observation_external", "observation_gap",
    "policy_assessment", "policy_witness", "receipt_predicate", "receipt_subject",
    "receipt_verifier", "receipt_records", "receipt_axis", "contract_native_loaded",
}
# Conditions a corpus of regular files cannot carry: an unreadable path, a link.
FILESYSTEM = {"case_unreadable", "policy_unreadable", "member_unreadable", "case_artifact_unsafe",
              "member_incomplete"}


def load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def manifest(corpus: str) -> dict:  # type: ignore[type-arg]
    return json.loads((ROOT / corpus / "MANIFEST.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("suite", list(CORPORA))
def test_corpus_regenerates_byte_identically(suite: str, tmp_path: Path) -> None:
    corpus = CORPORA[suite]
    generator = load(f"gen_{corpus}", ROOT / corpus / "gen_vectors.py")
    generator.generate(tmp_path)
    committed = sorted(p.relative_to(ROOT / corpus) for p in (ROOT / corpus / "cases").rglob("*")
                       if p.is_file())
    fresh = sorted(p.relative_to(tmp_path) for p in (tmp_path / "cases").rglob("*") if p.is_file())
    assert fresh == committed
    for relative in [*fresh, Path("MANIFEST.json")]:
        assert (tmp_path / relative).read_bytes() == (ROOT / corpus / relative).read_bytes()


@pytest.mark.parametrize("suite", list(CORPORA))
def test_reader_judges_the_committed_corpus_clean(suite: str) -> None:
    answered, errors = donerun.check(suite, ROOT / CORPORA[suite])
    assert errors == []
    assert answered == len(manifest(CORPORA[suite])["vectors"]) > 0


@pytest.mark.parametrize("suite", list(CORPORA))
def test_each_corpus_check_script_judges_its_corpus_clean(
        suite: str, capsys: pytest.CaptureFixture[str]) -> None:
    # The README tells a reader to run this script, so it must name the suite the corpus is.
    path = ROOT / CORPORA[suite] / "check_vectors.py"
    with pytest.raises(SystemExit) as stopped:
        exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"),  # noqa: S102
             {"__name__": "__main__", "__file__": str(path)})
    assert stopped.value.code == 0
    assert "0 disagreements" in capsys.readouterr().out


@pytest.mark.parametrize("suite", list(CORPORA))
def test_corpus_holds_more_than_one_verdict(suite: str) -> None:
    kinds = {entry["kind"] for entry in manifest(CORPORA[suite])["vectors"]}
    assert len(kinds) >= 2, kinds


def copy_member(corpus: str, member: str, tmp_path: Path) -> Path:
    target = tmp_path / member
    shutil.copytree(ROOT / corpus / "cases" / member, target)
    return target


def test_changed_records_move_the_verdict(tmp_path: Path) -> None:
    corpus = "vectors-done-receipt"
    honest = copy_member(corpus, "honest", tmp_path)
    adversary = ROOT / corpus / "cases" / "planted-adversary"
    declared = donerun.judge_member(donerun.RECEIPT_SUITE, honest, list(donerun.DECLARABLE))
    assert declared["accepted"] is True
    for name in ("observation.json", "grade.json", "tree.json"):
        (honest / name).write_bytes((adversary / name).read_bytes())
    moved = donerun.judge_member(donerun.RECEIPT_SUITE, honest, list(donerun.DECLARABLE))
    assert moved != declared


def test_a_forged_receipt_is_caught_by_the_receipt_check_alone() -> None:
    """The forged receipt's records are the adversary's; only rederiving shows the lie."""
    member = ROOT / "vectors-done-receipt" / "cases" / "forged-receipt"
    statement = json.loads((member / "receipt.json").read_text(encoding="utf-8"))
    assert statement["predicate"]["accepted"] is True
    verdict = donechecks.run_check(donechecks.RECEIPT, member)
    assert (verdict["decision"], verdict["reason"], verdict["receipt_valid"]) == (
        "contradicted", "receipt_outcome_mismatch", False)


def test_a_contract_that_loses_a_rule_is_judged_valid_by_nothing(tmp_path: Path) -> None:
    member = copy_member("vectors-done-contract", "acceptance-empty", tmp_path)
    assert donerun.judge_member(donerun.CONTRACT_SUITE, member, [])["contract"] == {
        "verdict": "invalid", "code": "contract_acceptance_empty"}
    record = json.loads((member / "contract.json").read_text(encoding="utf-8"))
    record["acceptance"] = [{"id": "unit", "argv": ["pytest"]}]
    raw = lib.enc(record)
    (member / "contract.json").write_bytes(raw)
    statement = json.loads((member / "statement.json").read_text(encoding="utf-8"))
    statement["predicate"] = record
    statement["subject"][0]["digest"]["sha256"] = lib.sha(raw)
    (member / "statement.json").write_bytes(lib.enc(statement))
    assert donerun.judge_member(donerun.CONTRACT_SUITE, member, [])["contract"] == {
        "verdict": "valid"}


def test_every_code_the_reader_can_name_is_forced_by_a_member() -> None:
    sources = "".join((ROOT / "packaging" / "agent_evidence_vectors" / f"{name}.py").read_text(
        encoding="utf-8") for name in ("donerecords", "donechecks", "donerun"))
    kinds = r"(?:contract|tree|observation|capability|grade|claims|case|policy|receipt|" \
            r"statement)"
    codes = set(re.findall(rf'"({kinds}_[a-z_0-9]+)"', sources))
    for record in ("contract", "tree", "observation", "capability", "grade", "claims", "case",
                   "policy", "statement", "receipt"):
        codes |= {f"{record}_{rule}" for rule in
                  ("json_duplicate_key", "json_number", "json_invalid", "fields")}
    declared: set[str] = set()
    for corpus in CORPORA.values():
        for entry in manifest(corpus)["vectors"]:
            declared |= set(re.findall(r'"([a-z_0-9]+)"', json.dumps(entry["expected"])))
    unforced = sorted(codes - declared - NOT_CODES - FILESYSTEM)
    assert unforced == [], unforced


def refusals(value: object) -> list[str]:
    """Every code a declared expectation names: a refusal, or an invalid contract's code."""
    if isinstance(value, dict):
        found = [value[key] for key in ("refused", "code") if isinstance(value.get(key), str)]
        return found + [code for item in value.values() for code in refusals(item)]
    return []


def test_the_reader_names_only_codes_the_specification_lists() -> None:
    text = "".join((ROOT / "spec" / "predicates" / name).read_text(encoding="utf-8")
                   for name in ("done-records.md", "done-receipt.md", "done-contract.md"))
    declared: set[str] = set()
    for corpus in CORPORA.values():
        for entry in manifest(corpus)["vectors"]:
            declared |= set(refusals(entry["expected"]))
    generic = re.compile(r"_(json_invalid|json_duplicate_key|json_number|fields)$")
    unlisted = sorted(code for code in declared if code not in text and not generic.search(code))
    assert unlisted == [], unlisted
