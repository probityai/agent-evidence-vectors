"""Both recognised hosts name one identifier, and no other spelling does.

spec/identifiers/HOSTS.md states the rule. These tests hold the package to it:

* the three functions in ``agent_evidence_vectors.identifiers`` reproduce every pair in
  spec/identifiers/host-equivalence.json;
* every reader that compares an identifier taken from a record returns the same verdict
  and reason for each corpus member when the member's identifiers are respelled under
  ``https://probityai.org/`` (an unsigned member is rewritten in a copy), and when the
  reader's own identifier is respelled there instead (which is what a signed member
  needs, and what the release that flips ``IDENTIFIER_HOST`` does);
* the ``http://probityai.org/`` spelling keeps the verdict any unknown identifier gets.
"""

from __future__ import annotations

import dataclasses
import importlib
import json
import shutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "packaging"))
from agent_evidence_vectors import identifiers

OLD = "https://probityai.github.io/"
NEW = "https://probityai.org/"
HTTP_NEW = "http://probityai.org/"
UNKNOWN = "https://example.invalid/"
VECTORS = json.loads((REPO / "spec" / "identifiers" / "host-equivalence.json").read_text())


def _respell(value: Any, to: str) -> Any:
    """``value`` with every identifier under the old host moved to the host ``to``."""
    return value.replace(OLD, to, 1) if isinstance(value, str) and value.startswith(OLD) else value


# --- the rule ---------------------------------------------------------------------------


def test_the_host_written_is_still_the_old_one() -> None:
    assert identifiers.IDENTIFIER_HOST == "probityai.github.io"
    assert identifiers.RECOGNISED_HOSTS == ("probityai.github.io", "probityai.org")
    assert identifiers.identifier("a/b") == "https://probityai.github.io/a/b"


@pytest.mark.parametrize("pair", VECTORS["pairs"], ids=lambda p: f"{p['same']}:{p['b']}")
def test_every_equivalence_pair_holds(pair: dict[str, Any]) -> None:
    assert VECTORS["version"] == 1
    assert identifiers.same_identifier(pair["a"], pair["b"]) is pair["same"], pair["why"]
    assert identifiers.same_identifier(pair["b"], pair["a"]) is pair["same"], pair["why"]


def test_the_vectors_cover_every_family_and_every_refused_spelling() -> None:
    same = [p for p in VECTORS["pairs"] if p["same"] and p["a"] != p["b"]]
    assert len(same) >= 9, "one pair per published identifier family"
    refused = {p["b"].split("agent-evidence")[0] for p in VECTORS["pairs"] if not p["same"]}
    for spelling in ("http://probityai.org/", "https://www.probityai.org/",
                     "https://probityai.org:443/", "https://probityai.org./",
                     "https://PROBITYAI.ORG/", "https://user@probityai.org/",
                     "https://probityai.org.example/", "https://probityai.organisation/"):
        assert spelling in refused, spelling


def test_canonical_form_maps_the_host_and_keeps_the_path() -> None:
    path = "agent-evidence-vectors/predicate/v1/observed-effect"
    assert identifiers.canonical_identifier(NEW + path) == OLD + path
    assert identifiers.canonical_identifier(OLD + path) == OLD + path
    for other in (HTTP_NEW + path, "https://www.probityai.org/" + path, "", "probityai.org"):
        assert identifiers.canonical_identifier(other) == other


@pytest.mark.parametrize("value", [None, 7, 1.5, True, ["https://probityai.org/x"],
                                   {"id": "https://probityai.org/x"}])
def test_a_value_that_is_not_a_string_is_returned_as_it_was(value: Any) -> None:
    assert identifiers.canonical_identifier(value) is value
    assert not identifiers.same_identifier(value, OLD + "x")


def test_the_rule_follows_the_written_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """After the flip both spellings still name one identifier, now spelled the new way."""
    monkeypatch.setattr(identifiers, "IDENTIFIER_HOST", "probityai.org")
    assert identifiers.identifier("a") == NEW + "a"
    assert identifiers.canonical_identifier(OLD + "a") == NEW + "a"
    assert identifiers.same_identifier(OLD + "a", NEW + "a")
    assert not identifiers.same_identifier(OLD + "a", HTTP_NEW + "a")


# --- readers that judge one unsigned case file ------------------------------------------

# Each reader, and the module constants it compares a record's identifier with.
CASE_READERS = {
    "aggregateaccounting": ("CONTRACT_ID",),
    "approvalbinding": ("CONTRACT_ID",),
    "authoritydispatch": ("CONTRACT_ID",),
    "badgevc": ("CONTRACT_ID",),
    "budgetlineage": ("CONTRACT_ID",),
    "capabilityrequirement": ("CONTRACT_ID",),
    "chunkedexport": ("CONTRACT_ID",),
    "completionconfirmation": ("CONTRACT_ID",),
    "containmentjournal": ("CONTRACT_ID", "RECEIPT_CONTRACT_ID"),
    "convertedargs": ("CONTRACT_ID",),
    "decisionclient": ("CONTRACT_ID",),
    "delegatorright": ("CONTRACT_ID",),
    "dispatchfence": ("CONTRACT_ID",),
    "evidencecell": ("PREDICATE_TYPE",),
    "evidencestate": ("CONTRACT_ID",),
    "executionbilling": ("CONTRACT_ID",),
    "monitorcoverage": ("CONTRACT_ID",),
    "propagationstep": ("CONTRACT_ID",),
    "refusalreason": ("CONTRACT_ID",),
    "responsibilityescalation": ("CONTRACT_ID",),
    "signaturecoverage": ("CONTRACT_ID",),
    "uncertaineffect": ("CONTRACT_ID",),
}


def _answer(module: ModuleType, path: Path) -> dict[str, Any] | None:
    try:
        answer = module.verify(path)
    except Exception:  # noqa: BLE001 -- not the file this reader is handed
        return None
    return answer if isinstance(answer, dict) else None


def _members(module: ModuleType) -> list[tuple[str, Path, str, dict[str, Any]]]:
    """Every member: its id, directory, the file the reader is handed, and what it expects.

    The handed file is the one whose answer matches the manifest, so a member is never
    compared through a file the reader does not read.
    """
    root = Path(module.ROOT)
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    found = []
    for entry in manifest["vectors"]:
        directory = root / entry["path"]
        expected = entry["expected"]
        for name in sorted(entry.get("files") or {}):
            answer = _answer(module, directory / name) if name.endswith(".json") else None
            if answer is not None and {k: answer.get(k) for k in expected} == expected:
                found.append((entry["id"], directory, name, expected))
                break
        else:
            raise AssertionError(f"{module.__name__} {entry['id']}: no file gives its answer")
    return found


def _rewritten(directory: Path, tmp: Path, to: str) -> tuple[Path, int]:
    copy = tmp / to.split("/")[2].replace(".", "-")
    shutil.copytree(directory, copy)
    count = 0
    for member in copy.rglob("*.json"):
        text = member.read_text(encoding="utf-8")
        count += text.count(OLD)
        member.write_text(text.replace(OLD, to), encoding="utf-8")
    return copy, count


@pytest.mark.parametrize("name", sorted(CASE_READERS))
def test_a_case_reader_reads_a_member_respelled_under_the_new_host_alike(
        name: str, tmp_path: Path) -> None:
    module = importlib.import_module(f"agent_evidence_vectors.{name}")
    members = _members(module)
    rewritten = 0
    for member_id, directory, handed, expected in members:
        before = module.verify(directory / handed)
        copy, count = _rewritten(directory, tmp_path / member_id, NEW)
        rewritten += count > 0
        after = module.verify(copy / handed)
        # Equal in every field once the echoed bytes are spelled back: a reader reports the
        # record's own bytes, so only the comparison is canonical.
        assert json.loads(json.dumps(after).replace(NEW, OLD)) == before, member_id
        assert {k: after.get(k) for k in expected} == expected, member_id
    assert rewritten >= len(members) - 2, f"{name}: the rewrite reached {rewritten} members"


@pytest.mark.parametrize("name", sorted(CASE_READERS))
def test_a_case_reader_keeps_refusing_the_http_spelling(name: str, tmp_path: Path) -> None:
    module = importlib.import_module(f"agent_evidence_vectors.{name}")
    accepting = {d for d, code in getattr(module, "EXIT_FOR", {}).items() if code == 0}
    checked = 0
    for member_id, directory, handed, expected in _members(module):
        if expected.get("decision") not in accepting:
            continue
        http, count = _rewritten(directory, tmp_path / member_id / "a", HTTP_NEW)
        unknown, _ = _rewritten(directory, tmp_path / member_id / "b", UNKNOWN)
        if not count:
            continue
        refused = module.verify(http / handed)
        assert refused.get("decision") not in accepting, member_id
        assert {k: refused.get(k) for k in expected} == {
            k: module.verify(unknown / handed).get(k) for k in expected}, member_id
        checked += 1
    assert checked, f"{name}: no accepted member carries an identifier"


@pytest.mark.parametrize("name", sorted(CASE_READERS))
def test_a_case_reader_whose_own_identifier_moves_to_the_new_host_reads_alike(
        name: str, monkeypatch: pytest.MonkeyPatch) -> None:
    module = importlib.import_module(f"agent_evidence_vectors.{name}")
    members = _members(module)
    before = {m: module.verify(d / h) for m, d, h, _ in members}
    for constant in CASE_READERS[name]:
        monkeypatch.setattr(module, constant, _respell(getattr(module, constant), NEW))
    for member_id, directory, handed, expected in members:
        after = module.verify(directory / handed)
        assert {k: after.get(k) for k in expected} == {
            k: before[member_id].get(k) for k in expected}, member_id


# --- readers whose members are signed: the reader's identifier moves instead ------------


def _judged(judged: Any) -> tuple[Any, Any]:
    return [(m, k, list(f)) for m, k, f in judged.members], list(judged.findings)


@pytest.mark.parametrize("to,same", [(NEW, True), (HTTP_NEW, False)])
def test_the_observed_effect_reader_routes_both_spellings(
        to: str, same: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    module = importlib.import_module("agent_evidence_vectors.observedeffect")
    root = str(REPO / "corpora" / "vectors-observed-effect")
    before = module.judge(root)
    assert before.ok()
    spec = module.predicate_type_from_spec
    monkeypatch.setattr(module, "predicate_type_from_spec", lambda path: _respell(spec(path), to))
    after = module.judge(root)
    assert (_judged(after) == _judged(before)) is same
    assert after.ok() is same


@pytest.mark.parametrize("to,same", [(NEW, True), (HTTP_NEW, False)])
def test_the_audit_record_reader_routes_both_spellings(
        to: str, same: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    module = importlib.import_module("agent_evidence_vectors.auditrecord")
    root = str(REPO / "corpora" / "vectors-agent-audit-record")
    before = module.judge(root)
    assert before.ok()
    policy_for = module.policy_for

    def respelled(*args: Any, **kwargs: Any) -> Any:
        policy = policy_for(*args, **kwargs)
        return dataclasses.replace(policy, predicate_type=_respell(policy.predicate_type, to))

    monkeypatch.setattr(module, "policy_for", respelled)
    after = module.judge(root)
    assert (_judged(after) == _judged(before)) is same
    assert after.ok() is same


@pytest.mark.parametrize("to,same", [(NEW, True), (HTTP_NEW, False)])
def test_the_self_reported_record_reader_routes_both_spellings(
        to: str, same: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    module = importlib.import_module("agent_evidence_vectors.selfreportedrecord")
    before = module.judge(module.ROOT)
    assert before.ok()
    monkeypatch.setattr(module, "PREDICATE_TYPE", _respell(module.PREDICATE_TYPE, to))
    after = module.judge(module.ROOT)
    assert (_judged(after) == _judged(before)) is same
    assert after.ok() is same


@pytest.mark.parametrize("to,same", [(NEW, True), (HTTP_NEW, False)])
def test_the_verdict_evidence_reader_routes_both_spellings(
        to: str, same: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    module = importlib.import_module("agent_evidence_vectors.verdict_evidence.reader")
    cases = sorted((Path(module.__file__).parent / "corpus" / "cases").glob("*/case.json"))
    before = {case: module.verify(case) for case in cases}
    assert cases
    monkeypatch.setattr(module, "PEER_PREDICATE", _respell(module.PEER_PREDICATE, to))
    after = {case: module.verify(case) for case in cases}
    assert (after == before) is same


def test_the_verdict_evidence_peer_statement_compares_canonically() -> None:
    module = importlib.import_module("agent_evidence_vectors.verdict_evidence.reader")
    for to, accepted in ((OLD, True), (NEW, True), (HTTP_NEW, False), (UNKNOWN, False)):
        body = json.dumps({"_type": module.STATEMENT_V1,
                           "predicateType": module.PEER_PREDICATE.replace(OLD, to),
                           "predicate": {}}).encode()
        try:
            module._statement(body, module.PEER_PREDICATE, frozenset(), "peer:")
        except module.Refusal as stop:
            assert not accepted and stop.reason == "unsupported_predicate", to
        else:
            assert accepted, to


@pytest.mark.parametrize("to,same", [(NEW, True), (HTTP_NEW, False)])
def test_the_claim_record_reader_routes_both_spellings(
        to: str, same: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    run = importlib.import_module("agent_evidence_vectors.claim_record.run")
    reader = importlib.import_module("agent_evidence_vectors.claim_record.reader")
    root = Path(reader.__file__).parent / "corpus"
    before = run.run_corpus(root)
    copy, count = _rewritten(root, tmp_path, to)
    assert count
    # The manifest pins each member by digest, so the respelled copy is pinned afresh.
    manifest = json.loads((copy / "manifest.json").read_text(encoding="utf-8"))
    manifest["members"] = {name: reader.sha256_tag((copy / name).read_bytes())
                           for name in manifest["members"]}
    (copy / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    rewritten = run.run_corpus(copy)
    monkeypatch.setattr(reader, "CLAIM_TYPE", _respell(reader.CLAIM_TYPE, to))
    moved = run.run_corpus(root)

    def verdicts(result: dict[str, Any]) -> Any:
        return [(r["case_id"], json.dumps(r["actual"]).replace(to, OLD))
                for r in result["results"]]

    assert (verdicts(rewritten) == verdicts(before)) is same
    assert (verdicts(moved) == verdicts(before)) is same


# --- local copies of the rule: each must equal agent_evidence_vectors.identifiers -------------


def _load(name: str, relative: str) -> ModuleType:
    """A module from this repository by path, for code that runs on its own and keeps no dependency."""
    import importlib.util

    path = REPO / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(path.parent))
    return module


def _every_spelling() -> list[Any]:
    values: list[Any] = []
    for pair in VECTORS["pairs"]:
        values.extend((pair["a"], pair["b"]))
    values.extend([None, 7, "", "https://probityai.org", HTTP_NEW + "x", "HTTPS://probityai.org/x"])
    return values


LOCAL_COPIES = [
    ("govops_verifier", "interop/govops-trace-profile/verifier.py"),
    ("vocabulary_registry", "packages/vocabulary/registry.py"),
]


@pytest.mark.parametrize("name,relative", LOCAL_COPIES)
def test_a_local_copy_of_the_rule_matches_the_package(name: str, relative: str) -> None:
    module = _load(name, relative)
    assert module.IDENTIFIER_HOST == identifiers.IDENTIFIER_HOST
    assert tuple(module.RECOGNISED_HOSTS) == identifiers.RECOGNISED_HOSTS
    for value in _every_spelling():
        assert module.canonical_identifier(value) == identifiers.canonical_identifier(value), value


def test_the_govops_verifier_predicate_type_is_built_on_the_written_host() -> None:
    module = _load("govops_verifier", "interop/govops-trace-profile/verifier.py")
    assert module.PREDICATE_TYPE == identifiers.identifier(
        "agent-evidence-vectors/predicate/v1/govops-trace-record")


@pytest.mark.parametrize("to,same", [(OLD, True), (NEW, True), (HTTP_NEW, False), (UNKNOWN, False)])
def test_the_vocabulary_evaluator_lookup_reads_both_spellings_alike(to: str, same: bool) -> None:
    module = _load("vocabulary_registry", "packages/vocabulary/registry.py")
    held = next(iter(module.EVALUATORS))
    assert held == identifiers.identifier("agent-evidence-vectors/evaluator/payment-scope/v1")
    evaluators = {held: (lambda inputs: "within", ("within", "outside"))}
    record = {"evaluator": held.replace(OLD, to, 1), "asserted": "within", "inputs": {}}
    derived = module.asserted_verdict(record, evaluators)
    assert (derived.value == "rederived_agrees") is same


def test_the_admission_generator_writes_under_the_written_host() -> None:
    module = _load("admission_gen", "packages/admission/rego/gen_verifier_isolation_vectors.py")
    assert module.IDENTIFIER_HOST == identifiers.IDENTIFIER_HOST
    assert module.PREDICATE_URI == identifiers.identifier("probity/predicate/v1/done-receipt")


@pytest.mark.parametrize("name,relative", [
    ("host_allowlist_gate", "packages/admission/scripts/host-allowlist-gate.py"),
    ("check_predicate_pages", "scripts/check_predicate_pages.py"),
])
def test_both_host_allowlists_hold_every_recognised_host(name: str, relative: str) -> None:
    module = _load(name, relative)
    assert set(identifiers.RECOGNISED_HOSTS) <= set(module.ALLOWED_HOSTS)


def test_the_reference_stage_routes_an_audit_record_under_either_host() -> None:
    module = _load("action_reference_stage", "scripts/action-reference-stage.py")
    path = "agent-evidence-vectors/predicate/v1/agent-audit-record"
    assert set(module.AUDIT_RECORD_PREDICATES) == {f"https://{h}/{path}" for h in identifiers.RECOGNISED_HOSTS}
