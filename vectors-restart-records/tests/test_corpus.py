"""The corpus regenerates byte for byte, forces every rule it can, each reject is
one revertible change of its control, and every accepting record matches the
JSON Schema of its predicate."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent


def _load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)
    return module


generator = _load("restart_records_generator", ROOT / "gen_vectors.py")
checker = generator.checker
MANIFEST: dict[str, Any] = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
ENTRIES: list[dict[str, Any]] = MANIFEST["vectors"]
BY_ID = {e["id"]: e for e in ENTRIES}
REJECTS = [e for e in ENTRIES if e["kind"] == "reject"]


def _files(entry: dict[str, Any]) -> dict[str, bytes]:
    directory = ROOT / entry["path"]
    return {name: (directory / name).read_bytes() for name in entry["files"]}


def _verdict(entry: dict[str, Any], files: dict[str, bytes]) -> tuple[str, str]:
    if entry["shape"] == "bundle":
        return checker.check_bundle_files(files)  # type: ignore[no-any-return]
    return checker.check_record_bytes(files["statement.json"])  # type: ignore[no-any-return]


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {p.relative_to(ROOT): p.read_bytes()
                 for p in [ROOT / "MANIFEST.json", ROOT / "INDEX.md", *(ROOT / "cases").rglob("*")]
                 if p.is_file()}
    regenerated = {p.relative_to(tmp_path): p.read_bytes()
                   for p in tmp_path.rglob("*") if p.is_file()}
    assert regenerated == committed


def test_corpus_digest_recomputes_from_files() -> None:
    assert generator.corpus_digest(MANIFEST, str(ROOT)) == MANIFEST["corpusDigest"]


def test_replay_agrees_with_the_manifest() -> None:
    assert checker.replay(ROOT) == []


def test_counts_match_the_entries() -> None:
    kinds = [e["kind"] for e in ENTRIES]
    assert MANIFEST["counts"] == {"accept": kinds.count("accept"),
                                  "reject": kinds.count("reject")}


def _document_rules(path: str) -> list[tuple[str, str]]:
    """The Rules table of a document, read from the document itself."""
    text = (REPO / path).read_text(encoding="utf-8")
    return [(m.group(1), m.group(2)) for m in
            re.finditer(r"^\| (B?\d+) \| .* \| `?([a-z' -]+?)`? \|$", text, re.MULTILINE)]


@pytest.mark.parametrize("name", checker.NAMES)
def test_checker_rules_are_the_documents_rules(name: str) -> None:
    assert tuple(_document_rules(checker.DOCUMENT[name])) == checker.RULES[name]


def test_checker_bundle_rules_are_the_profiles_rules() -> None:
    assert tuple(_document_rules(checker.PROFILE)) == checker.BUNDLE_RULES


def test_every_rule_is_forced_or_declared_unforceable() -> None:
    every = {(checker.DOCUMENT[n], rule) for n in checker.NAMES for rule, _ in checker.RULES[n]}
    every |= {(checker.PROFILE, rule) for rule, _ in checker.BUNDLE_RULES}
    forced = {(e["document"], e["rule"]) for e in REJECTS}
    unforced = {(u["document"], u["rule"]) for u in MANIFEST["unforcedRules"]}
    assert not forced & unforced
    assert forced | unforced == every


def test_each_reject_names_the_code_of_its_rule() -> None:
    for e in REJECTS:
        if e["shape"] == "record":
            assert e["expected"]["reason"] == dict(checker.RULES[e["predicate"]])[e["rule"]]
        elif e["rule"] != "B1":
            assert e["expected"]["reason"] == dict(checker.BUNDLE_RULES)[e["rule"]]
        else:
            record_codes = {code for n in checker.NAMES for _, code in checker.RULES[n]}
            assert e["expected"]["reason"] in record_codes


@pytest.mark.parametrize("entry", REJECTS, ids=[e["id"] for e in REJECTS])
def test_reverting_the_one_change_gives_back_the_accepting_control(entry: dict[str, Any]) -> None:
    base = BY_ID[entry["base"]]
    assert base["kind"] == "accept"
    files = _files(entry)
    if entry["shape"] == "record":
        reverted = generator.apply(json.loads(files["statement.json"]), entry["mutation"],
                                   revert=True)
        restored = {"statement.json": generator.statement_bytes(reverted)}
    else:
        records = {name: json.loads(data) for name, data in files.items()}
        restored = generator.mutate_bundle(records, entry["mutation"], revert=True)
    assert restored == _files(base)
    assert _verdict(base, restored) == ("accept", base["expected"]["reason"])
    assert _verdict(entry, files) == ("reject", entry["expected"]["reason"])


def _schema(name: str) -> Draft202012Validator:
    path = REPO / "spec" / "schemas" / f"{name}-v1.schema.json"
    return Draft202012Validator(json.loads(path.read_text(encoding="utf-8")))


ACCEPTED_RECORDS = [(e["id"], name) for e in ENTRIES if e["kind"] == "accept"
                    for name in e["files"]]


@pytest.mark.parametrize(("member", "file"), ACCEPTED_RECORDS)
def test_every_accepting_record_validates_against_its_schema(member: str, file: str) -> None:
    statement = json.loads((ROOT / BY_ID[member]["path"] / file).read_bytes())
    name = checker.NAME_OF_TYPE[statement["predicateType"]]
    errors = sorted(_schema(name).iter_errors(statement), key=str)
    assert not errors, [e.message for e in errors]


def test_every_member_is_labelled_synthetic() -> None:
    assert MANIFEST["synthetic"] is True
    assert "synthetic" in MANIFEST["syntheticNote"]
    hosts = re.compile(r"https://([^/\s\"]+)")
    allowed = re.compile(r"(^|\.)example\.(com|org)$")
    permitted = {"in-toto.io", "probityai.github.io"}
    for e in ENTRIES:
        for data in _files(e).values():
            for host in hosts.findall(data.decode()):
                assert allowed.search(host) or host in permitted, (e["id"], host)


def test_a_cycle_is_found_when_one_exists() -> None:
    assert checker.find_cycle({"a": ["b"], "b": ["a"]})
    assert checker.find_cycle({"a": ["a"]})
    assert not checker.find_cycle({"r3": ["r1", "r2"], "r2": ["r1"], "r1": []})


def test_duplicate_member_is_statement_malformed() -> None:
    data = _files(BY_ID["revocation-sweep-control"])["statement.json"]
    doubled = data.replace(b'{\n  "_type"', b'{\n  "_type": "x",\n  "_type"', 1)
    assert doubled != data
    assert checker.check_record_bytes(doubled) == ("reject", "statement-malformed")


def test_cli_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    control = ROOT / BY_ID["re-enable-decision-control"]["path"] / "statement.json"
    reject = ROOT / BY_ID["bundle-b6-predecessor-issued-later"]["path"]
    assert checker.main(["--record", str(control)]) == 0
    assert checker.main(["--bundle", str(reject)]) == 1
    assert checker.main(["--bundle", str(tmp_path)]) == 2
    assert checker.main([]) == 0
    assert "PASS" in capsys.readouterr().out
