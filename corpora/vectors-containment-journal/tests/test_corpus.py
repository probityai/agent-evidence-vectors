"""The corpus regenerates, each denied case fails exactly the rule it names, every
rule is forced by a case, and a journal or receipt edited after the fact is refused."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("containment_journal_corpus", ROOT / "check_vectors.py")
generator = _load("containment_journal_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import containmentjournal as reader  # noqa: E402

CHECKS = reader.CHECKS
RECEIPT_CHECKS = reader.RECEIPT_CHECKS
DENIED = {case[0]: case[4] for case in generator.cases() if case[3] == "deny"}
ALLOWED = [case[0] for case in generator.cases() if case[3] == "allow"]
RECEIPT_CONTROL = "allow-blast-radius-receipt-recomputes"


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


def _case_for(rule: str) -> str:
    return "reject-" + rule.replace("_", "-")


def _verdict(name: str, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    return reader.verify(ROOT / "cases" / name / "record.json", skip)


def _staged(tmp_path: Path, name: str) -> Path:
    staged = tmp_path / name
    shutil.copytree(ROOT / "cases" / name, staged)
    return staged


def _record(name: str) -> dict[str, Any]:
    value: dict[str, Any] = json.loads(
        (ROOT / "cases" / name / "record.json").read_text(encoding="utf-8"))
    return value


def _write(path: Path, value: object) -> None:
    path.write_bytes(generator._json(value))


def test_regeneration_is_byte_identical(tmp_path: Path) -> None:
    generator.generate(tmp_path)
    committed = {p.relative_to(ROOT): p.read_bytes()
                 for p in [ROOT / "MANIFEST.json", *(ROOT / "cases").rglob("*")] if p.is_file()}
    regenerated = {p.relative_to(tmp_path): p.read_bytes()
                   for p in tmp_path.rglob("*") if p.is_file()}
    assert regenerated == committed


def test_reference_reader_agrees_with_every_case() -> None:
    answered, errors = corpus.check()
    assert errors == []
    assert answered == len(generator.cases())


def test_counts_come_from_the_manifest() -> None:
    manifest = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["counts"] == {"allow": len(ALLOWED), "deny": len(DENIED)}


def test_every_rule_has_its_denied_case() -> None:
    assert set(DENIED.values()) == set(CHECKS) | set(RECEIPT_CHECKS)
    assert all(name == _case_for(reason) for name, reason in DENIED.items())


@pytest.mark.parametrize("name", sorted(DENIED))
def test_each_denied_case_fails_exactly_its_named_rule(name: str) -> None:
    reason = DENIED[name]
    rules = RECEIPT_CHECKS if reason in RECEIPT_CHECKS else CHECKS
    allowed = reader.RECEIPT_REASON if rules is RECEIPT_CHECKS else reader.ALLOWED_REASON
    assert _verdict(name) == {"decision": "deny", "reason": reason}
    later = frozenset(rules[rules.index(reason):])
    assert _verdict(name, later) == {"decision": "allow", "reason": allowed}
    assert _verdict(name, frozenset({reason})) != {"decision": "deny", "reason": reason}


@pytest.mark.parametrize("rule", CHECKS + RECEIPT_CHECKS)
def test_every_rule_is_forced_by_exactly_its_case(rule: str) -> None:
    _, errors = corpus.check(skip=frozenset({rule}))
    assert _failed(errors) == {_case_for(rule)}, f"switching off {rule}: {errors}"


def test_verifier_that_denies_everything_fails_the_controls(tmp_path: Path) -> None:
    script = tmp_path / "deny.py"
    script.write_text('import json, sys\nprint(json.dumps({"decision": "deny", '
                      '"reason": "contract_id_missing"}))\nsys.exit(1)\n', encoding="ascii")
    _, errors = corpus.check(f"{sys.executable} {script}")
    assert set(ALLOWED) <= _failed(errors)


def test_verifier_that_allows_everything_fails_every_denied_case(tmp_path: Path) -> None:
    script = tmp_path / "allow.py"
    script.write_text('import json, sys\nprint(json.dumps({"decision": "allow", '
                      '"reason": "containment_consistent"}))\nsys.exit(0)\n', encoding="ascii")
    _, errors = corpus.check(f"{sys.executable} {script}")
    assert set(DENIED) <= _failed(errors)


def test_missing_verifier_does_not_count_as_answered(tmp_path: Path) -> None:
    answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
    assert answered == 0 and errors


def test_an_impossible_date_is_malformed_not_an_exception(tmp_path: Path) -> None:
    staged = _staged(tmp_path, "allow-continue-with-authority")
    record = _record("allow-continue-with-authority")
    record["entries"][1]["alertAt"] = "2026-02-30T09:00:00Z"
    _write(staged / "record.json", record)
    assert reader.verify(staged / "record.json") == {"decision": "deny",
                                                    "reason": "record_malformed"}


@pytest.mark.parametrize("name", ALLOWED)
def test_dropping_an_entry_moves_the_verdict(tmp_path: Path, name: str) -> None:
    record = _record(name)
    staged = _staged(tmp_path, name)
    # The journal alone cannot see its own tail cut off; the receipt's head can.
    last = len(record["entries"]) if name == RECEIPT_CONTROL else len(record["entries"]) - 1
    for index in range(last):
        dropped = json.loads(json.dumps(record))
        del dropped["entries"][index]
        _write(staged / "record.json", dropped)
        assert reader.verify(staged / "record.json")["decision"] == "deny", index


@pytest.mark.parametrize("name", ALLOWED)
def test_flipping_a_byte_in_an_entry_moves_the_verdict(tmp_path: Path, name: str) -> None:
    body = (ROOT / "cases" / name / "record.json").read_bytes()
    staged = _staged(tmp_path, name)
    marker = b'"at": "'
    starts = [i for i in range(len(body)) if body.startswith(marker, i)]
    entries = len(_record(name)["entries"])
    assert len(starts) == entries
    flipped_any = 0
    for index, start in enumerate(starts):
        if index == entries - 1 and name != RECEIPT_CONTROL:
            continue
        # The last digit of the entry's seconds, one bit flipped: still a digit, still in order.
        position = body.index(b"Z", start) - 1
        mutated = bytearray(body)
        mutated[position] ^= 0x01
        (staged / "record.json").write_bytes(bytes(mutated))
        assert reader.verify(staged / "record.json")["decision"] == "deny", index
        flipped_any += 1
    assert flipped_any


def test_flipping_a_byte_in_the_receipt_moves_the_verdict(tmp_path: Path) -> None:
    staged = _staged(tmp_path, RECEIPT_CONTROL)
    body = (staged / "receipt.json").read_bytes()
    # A count one off, or a reached agent renamed to one the journal does not list.
    for member in (b'"deliveries": ', b'"toolCalls": ', b'"agent-'):
        position = body.index(member) + len(member)
        mutated = bytearray(body)
        mutated[position] ^= 0x01
        (staged / "receipt.json").write_bytes(bytes(mutated))
        assert reader.verify(staged / "record.json")["decision"] == "deny", member


REFUSED = "allow-isolated-agents-tool-call-refused"
ATTESTED = "allow-retrieval-inside-snapshot"


def _edited_verdict(tmp_path: Path, name: str, change: Any) -> dict[str, str]:
    """Apply a change to a control's journal, re-chain it, and judge it."""
    record = _record(name)
    change(record)
    generator.rechain(record["entries"])
    staged = _staged(tmp_path, name)
    _write(staged / "record.json", record)
    return reader.verify(staged / "record.json")


def _unrefuse(record: dict[str, Any]) -> None:
    call = record["entries"][-1]
    del call["refused"], call["refusalReason"]


def _refused_false(record: dict[str, Any]) -> None:
    call = record["entries"][-1]
    call["refused"] = False
    del call["refusalReason"]


def _reason_only(record: dict[str, Any]) -> None:
    del record["entries"][-1]["refused"]


def _no_root(record: dict[str, Any]) -> None:
    del record["snapshotRoot"]


def _no_root_no_claim(record: dict[str, Any]) -> None:
    del record["snapshotRoot"]
    record["claims"] = {}


def _outside(record: dict[str, Any]) -> None:
    record["entries"][1]["documentDigest"] = generator.OUTSIDE


def _sibling_swapped(record: dict[str, Any]) -> None:
    record["entries"][1]["proof"][0][0] = "left"


def _too_deep(record: dict[str, Any]) -> None:
    record["entries"][1]["proof"] = record["entries"][1]["proof"] * 33


def _unbound(record: dict[str, Any]) -> None:
    del record["entries"][3]["grantChainDigest"]


def _bad_profile(record: dict[str, Any]) -> None:
    record["componentProfileDigest"] = "sha256:00"


# Each attempt to get an isolated agent's call, an unattested document or an unbound
# call past the 1.1 rules, and the reason the reader must give.
BYPASSES = [
    (REFUSED, _unrefuse, "tool_call_by_isolated_agent"),
    (REFUSED, _refused_false, "tool_call_by_isolated_agent"),
    (REFUSED, _reason_only, "record_malformed"),
    (REFUSED, _unbound, "tool_call_authority_unbound"),
    (REFUSED, _bad_profile, "record_malformed"),
    (ATTESTED, _no_root, "retrieval_admitted_outside_snapshot"),
    (ATTESTED, _outside, "retrieval_admitted_outside_snapshot"),
    (ATTESTED, _sibling_swapped, "retrieval_admitted_outside_snapshot"),
    (ATTESTED, _too_deep, "record_malformed"),
]


@pytest.mark.parametrize(("name", "change", "reason"), BYPASSES,
                         ids=[change.__name__ for _, change, _ in BYPASSES])
def test_each_bypass_attempt_is_refused(tmp_path: Path, name: str, change: Any,
                                        reason: str) -> None:
    assert _edited_verdict(tmp_path, name, change) == {"decision": "deny", "reason": reason}


def test_a_run_that_names_no_snapshot_and_claims_none_is_judged_on_the_rest(
        tmp_path: Path) -> None:
    # No root and no claim: the journal says nothing about attestation, so a consumer
    # that relies on attested retrieval requires the retrievalAttested claim.
    assert _edited_verdict(tmp_path, ATTESTED, _no_root_no_claim) == {
        "decision": "allow", "reason": reader.ALLOWED_REASON}


def test_the_reach_rule_counts_every_tool_call_by_a_tainted_agent() -> None:
    # The subject is tainted from the start; from fromSeq on, a delivery the router did
    # not drop counts when its sender is tainted and taints the receiver, even one already
    # tainted; a tool call counts when its agent is tainted, refused or not.
    assert reader.reach(_record(REFUSED), "agent-c", 0) == {
        "agents": [], "deliveries": 0, "toolCalls": 1}
    again = _record("allow-blast-radius-counts-delivery-to-tainted-receiver")
    assert reader.reach(again, "agent-c", 0) == {
        "agents": ["agent-a"], "deliveries": 2, "toolCalls": 0}


def _drop_after_refusal(record: dict[str, Any]) -> None:
    refusal = record["entries"][1]
    record["entries"].insert(2, {"event": "delivery", "sender": refusal["sender"],
                                 "receiver": refusal["receiver"],
                                 "bodyDigest": refusal["bodyDigest"], "edgeInForce": True,
                                 "dropped": True, "prev": "", "at": refusal["at"]})
    for index, entry in enumerate(record["entries"]):
        entry["seq"] = index


def _unknown_refusal_code(record: dict[str, Any]) -> None:
    record["entries"][1]["reasonCode"] = "private_policy_rule_7"


def test_a_drop_over_a_present_edge_is_still_denied_beside_a_refusal(tmp_path: Path) -> None:
    name = "allow-refusal-over-present-edge"
    assert _edited_verdict(tmp_path / "drop", name, _drop_after_refusal) == {
        "decision": "deny", "reason": "drop_over_present_edge"}
    assert _edited_verdict(tmp_path / "code", name, _unknown_refusal_code) == {
        "decision": "deny", "reason": "closed_vocabulary_violation"}


def test_the_inclusion_path_reaches_the_root_for_every_snapshot_document() -> None:
    for document in generator.DOCUMENTS:
        assert reader.merkle_root(document, generator.inclusion(document)) == \
            generator.SNAPSHOT_ROOT
    assert reader.merkle_root(generator.OUTSIDE, generator.inclusion(generator.OUTSIDE)) != \
        generator.SNAPSHOT_ROOT


def test_the_manifest_revision_is_the_changelogs_newest() -> None:
    manifest = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
    heading = next(line for line in (ROOT / "CHANGES.md").read_text(encoding="utf-8").splitlines()
                   if line.startswith("## suiteRevision "))
    assert manifest["suiteRevision"] == int(heading.split()[2])
