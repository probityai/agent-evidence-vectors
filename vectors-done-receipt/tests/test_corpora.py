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
from agent_evidence_vectors import donechecks, donerecords, donerun  # noqa: E402

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
    "capability_sha256", "capability_witness", "claims_witness", "contract_sha256",
    "contract_witness", "grade_witness", "launch_sha256", "observation_sha256",
    "observation_witness", "tree_sha256", "tree_witness", "launch_receipt",
    "contract_acceptance", "contract_adequacy",
    "contract_protected_path", "case_artifact", "case_artifact_path", "claims_entry",
    "grade_result", "observation_event", "observation_gap", "policy_assessment",
    "policy_witness", "receipt_predicate",
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
    declared = donerun.judge_member(donerun.RECEIPT_SUITE, honest, list(lib_checks()))
    assert declared["done"]["decision"] == "supported"
    for name in ("observation.json", "grade.json", "tree.json"):
        (honest / name).write_bytes((adversary / name).read_bytes())
    moved = donerun.judge_member(donerun.RECEIPT_SUITE, honest, list(lib_checks()))
    assert moved != declared


def lib_checks() -> tuple[str, ...]:
    return donechecks.CLAIM_TYPES


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
    kinds = r"(?:contract|tree|observation|capability|grade|claims|case|policy|launch|" \
            r"launch_receipt|receipt|statement)"
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


def test_the_reader_names_only_codes_the_specification_lists() -> None:
    text = "".join((ROOT / "spec" / "predicates" / name).read_text(encoding="utf-8")
                   for name in ("done-records.md", "done-receipt.md", "done-contract.md"))
    declared: set[str] = set()
    for corpus in CORPORA.values():
        for entry in manifest(corpus)["vectors"]:
            expected = entry["expected"]
            for found in (expected.get("refused"), expected.get("receipt", {}).get("code"),
                          expected.get("contract", {}).get("code")):
                if found:
                    declared.add(found)
    generic = re.compile(r"_(json_invalid|json_duplicate_key|json_number|fields)$")
    unlisted = sorted(code for code in declared if code not in text and not generic.search(code))
    assert unlisted == [], unlisted


def test_recorded_runs_are_the_files_their_manifest_lists() -> None:
    listing = json.loads((ROOT / "vectors-done-receipt" / "recorded" / "MANIFEST.json").read_text(
        encoding="utf-8"))
    for row in listing["files"]:
        data = (ROOT / "vectors-done-receipt" / "recorded" / row["path"]).read_bytes()
        assert len(data) == row["bytes"] and donerecords.sha256(data) == row["sha256"], row["path"]
