"""The corpus regenerates, forces every check in order, and separates a verifier that
trusts a signature, or one verdict for a hosted endpoint, from one that holds the rule."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str, path: Path):  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


corpus = _load("capability_requirement_corpus", ROOT / "check_vectors.py")
generator = _load("capability_requirement_generator", ROOT / "gen_vectors.py")
from agent_evidence_vectors import capabilityrequirement as reader  # noqa: E402

CHECKS = reader.CHECKS
DENIED = {case[0]: case[3] for case in generator.cases() if case[2] == "deny"}
ALLOWED = [case[0] for case in generator.cases() if case[2] == "allow"]


def _records() -> dict[str, dict[str, Any]]:
    return {p.parent.name: json.loads(p.read_text(encoding="utf-8"))
            for p in (ROOT / "cases").glob("*/record.json")}


def _manifest() -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
    return loaded


def _failed(errors: list[str]) -> set[str]:
    return {error.split(":", 1)[0] for error in errors}


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
    manifest = _manifest()
    assert manifest["counts"] == {"allow": len(ALLOWED), "deny": len(DENIED)}
    kinds = [row["retained"]["kind"] for row in manifest["vectors"]]
    assert manifest["kinds"] == {kind: kinds.count(kind) for kind in sorted(set(kinds))}


@pytest.mark.parametrize("name", sorted(DENIED))
def test_each_denied_case_fails_exactly_its_named_check(name: str) -> None:
    record, reason = _records()[name], DENIED[name]
    assert reader._first_failure(record, frozenset()) == reason
    assert reader._first_failure(record, frozenset(CHECKS[CHECKS.index(reason):])) is None


@pytest.mark.parametrize("name", CHECKS)
def test_every_check_is_forced_by_some_case(name: str) -> None:
    _, errors = corpus.check(skip=frozenset({name}))
    assert errors, f"switching off {name} changed no verdict"


def test_every_kind_has_allowed_and_denied_cases() -> None:
    rows = _manifest()["vectors"]
    for kind in reader.KINDS:
        decisions = {row["expected"]["decision"] for row in rows
                     if row["retained"]["kind"] == kind}
        assert decisions == {"allow", "deny"}, kind


def test_every_case_signature_is_real_or_named_as_forged() -> None:
    """The requirement, the attestation and each run signature verify unless the case
    exists to show one that does not. A re-signed reject case carries a real signature over
    a requirement the reader refuses, so only an allow case must also pass the reader."""
    rail = generator.rail
    forged_prefixes = ("reject-requirement-", "reject-threshold-", "reject-capability-changed",
                       "reject-evaluation-digest-edited", "reject-held-out-assessor-changed",
                       "reject-report-", "reject-drift-")
    for name, record in _records().items():
        if name.startswith(forged_prefixes) or "kind" not in record or "requirement" not in record:
            continue
        key = base64.b64decode(record["requirerSignature"]["publicKey"])
        sig = base64.b64decode(record["requirerSignature"]["signature"])
        assert rail.ed25519_verify(key, reader.canonical(record["requirement"]), sig), name
        if name.startswith("allow-"):
            assert reader.requirement_failure(record) is None, name


def test_threshold_change_after_signing_breaks_the_signature() -> None:
    rail = generator.rail
    original = _records()["allow-requirement-pinned"]
    edited = _records()["reject-threshold-changed-after-signing"]
    assert original["requirement"]["thresholds"][0]["value"] == 900
    assert edited["requirement"]["thresholds"][0]["value"] == 700
    key = base64.b64decode(original["requirerSignature"]["publicKey"])
    sig = base64.b64decode(original["requirerSignature"]["signature"])
    assert rail.ed25519_verify(key, reader.canonical(original["requirement"]), sig)
    assert not rail.ed25519_verify(key, reader.canonical(edited["requirement"]), sig)
    assert original["requirerSignature"] == edited["requirerSignature"]


def test_identity_and_behaviour_are_two_findings_in_every_allowed_report() -> None:
    """Hosted endpoints report identity unproven beside each of the three behaviours."""
    proven = "allow-report-identity-proven-with-weights-held"
    rows = [row for row in _manifest()["vectors"]
            if row["retained"]["kind"] == "endpoint-report"
            and row["expected"]["decision"] == "allow" and row["id"] != proven]
    hosted = [row["retained"] for row in rows]
    assert {kept["modelIdentity"] for kept in hosted} == {"unproven"}
    assert {kept["behaviour"] for kept in hosted} == set(reader.BEHAVIOURS)


def test_every_drift_outcome_is_covered_by_an_allowed_comparison() -> None:
    outcomes = {row["retained"]["outcome"] for row in _manifest()["vectors"]
                if row["retained"]["kind"] == "drift" and row["expected"]["decision"] == "allow"}
    assert outcomes == {"stable", "drifted", "not_established"}


def _plain_behaviour(record: dict[str, Any]) -> str:
    """Behaviour from the thresholds and the run, without the reader's code."""
    held = record["requirementRecord"]["requirement"]["evaluationSet"]["heldOut"]["assessorKey"]
    run, rail = record["run"], generator.rail
    body = run["body"]
    held_ok = body["heldOut"] is not None and run.get("assessorSignature", {}).get(
        "publicKey") == held and rail.ed25519_verify(
        base64.b64decode(run["assessorSignature"]["publicKey"]),
        json.dumps({"requirementDigest": body["requirementDigest"],
                    "results": body["heldOut"]["results"], "runId": body["runId"]},
                   sort_keys=True, separators=(",", ":")).encode(),
        base64.b64decode(run["assessorSignature"]["signature"]))
    missed, unknown = False, False
    for threshold in record["requirementRecord"]["requirement"]["thresholds"]:
        source = body["public"] if threshold["set"] == "public" else (
            body["heldOut"]["results"] if held_ok else {})
        value = source.get(threshold["metric"])
        if value is None:
            unknown = True
        elif (value < threshold["value"]) if threshold["comparator"] == "gte" else (
                value > threshold["value"]):
            missed = True
    return "contradicted" if missed else ("not_established" if unknown else "supported")


def test_behaviour_in_allowed_reports_matches_an_independent_computation() -> None:
    reports = {name: record for name, record in _records().items()
               if record.get("kind") == "endpoint-report" and name in ALLOWED}
    assert reports
    for name, record in reports.items():
        assert record["behaviour"] == _plain_behaviour(record), name


# The naive arms. Each stands for a verifier someone would plausibly ship, and each
# must pass every control before what it misses counts.
Arm = Callable[[dict[str, Any]], str | None]


def _only(names: tuple[str, ...]) -> Arm:
    def arm(record: dict[str, Any]) -> str | None:
        for name in names:
            failure = reader._first_failure(record, frozenset(set(CHECKS) - {name}))
            if failure:
                return failure
        return None
    return arm


def _escaped(arm: Arm) -> set[str]:
    """The cases the arm allowed and the corpus denies; the controls must all pass."""
    records = _records()
    missed = set()
    for name, record in records.items():
        failure = arm(record)
        if name in ALLOWED:
            assert failure is None, f"a naive arm must pass the controls to count: {name}"
        elif failure is None:
            missed.add(name)
    return missed


SIGNATURES = ("contract_id_missing", "contract_id_unknown", "kind_unknown",
              "requirement_signature_invalid", "run_signature_invalid")


def test_signature_only_verifier_misses_every_denial_past_the_signatures() -> None:
    """A signature proves the signer's bytes. It says nothing about what the bytes pin."""
    past = {name for name, reason in DENIED.items() if reason not in SIGNATURES}
    assert past <= _escaped(_only(SIGNATURES))
    named = {"reject-capability-names-a-model",
             "reject-report-identity-proven-for-a-hosted-endpoint",
             "reject-drift-runs-against-different-requirement-digests"}
    assert named <= _escaped(_only(SIGNATURES))


def test_verifier_that_trusts_held_out_values_without_the_assessor(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Reading held-out values as usable whoever signed them lets a report say supported."""
    monkeypatch.setattr(reader, "_held_out_valid", lambda rr, run: True)
    without = tuple(name for name in CHECKS if name != "held_out_not_assessor_signed")
    escaped = _escaped(_only(without))
    held_out = {name for name, reason in DENIED.items()
                if reason == "held_out_not_assessor_signed" and name.startswith("reject-report-")}
    assert len(held_out) == 5 and held_out <= escaped


def test_one_pass_fail_verdict_cannot_say_which_finding_failed() -> None:
    """A single verdict reads identity and behaviour as one; the corpus separates them."""
    rows = {row["id"]: row for row in _manifest()["vectors"]}
    supported = rows["allow-report-identity-unproven-behaviour-supported"]["retained"]
    miss = rows["allow-report-behaviour-contradicted-public-miss"]["retained"]
    assert supported["modelIdentity"] == miss["modelIdentity"] == "unproven"
    assert supported["behaviour"] != miss["behaviour"]


def test_verifier_that_denies_everything_fails_the_controls(tmp_path: Path) -> None:
    script = tmp_path / "deny.py"
    script.write_text('import json, sys\nprint(json.dumps({"decision": "deny", '
                      '"reason": "contract_id_missing"}))\nsys.exit(1)\n', encoding="ascii")
    _, errors = corpus.check(f"{sys.executable} {script}")
    assert set(ALLOWED) <= _failed(errors)


def test_missing_verifier_does_not_count_as_answered(tmp_path: Path) -> None:
    answered, errors = corpus.check(str(tmp_path / "no-such-verifier"))
    assert answered == 0 and errors


def test_malformed_record_is_denied_not_raised(tmp_path: Path) -> None:
    cid = reader.CONTRACT_ID
    for text in (f'{{"contractId": "{cid}", "kind": "drift"}}',
                 f'{{"contractId": "{cid}", "kind": "endpoint-report", "run": 3}}'):
        path = tmp_path / "record.json"
        path.write_text(text, encoding="utf-8")
        answer = reader.verify(path)
        assert answer["decision"] == "deny" and answer["reason"] in CHECKS


def test_keys_are_the_published_test_keys() -> None:
    expected = {generator.public_key(seed) for seed in
                (generator.REQUIRER, generator.ASSESSOR, generator.VERIFIER)}
    seen = set()
    for record in _records().values():
        if "requirerSignature" in record:
            seen.add(record["requirerSignature"]["publicKey"])
    assert seen <= expected
    assert hashlib.sha256(b"capability-requirement/v1 assessor test key").digest() == (
        generator.ASSESSOR)
