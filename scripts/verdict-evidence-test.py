"""Challenge the ACS verdict evidence controls: every answer, every kill, every contract."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGING = ROOT / "packaging"
sys.path.insert(0, str(PACKAGING))

from agent_evidence_vectors.verdict_evidence import reader  # noqa: E402
from agent_evidence_vectors.verdict_evidence.run import (  # noqa: E402
    CorpusError,
    load_manifest,
    run_corpus,
)

CORPUS = PACKAGING / "agent_evidence_vectors/verdict_evidence/corpus"
MANIFEST = json.loads((CORPUS / "MANIFEST.json").read_text())
CASES = MANIFEST["cases"]
BY_ID = {c["id"]: c for c in CASES}
RUN = [sys.executable, "-m", "agent_evidence_vectors.verdict_evidence.run"]


def _case_json(case_id: str) -> Path:
    return CORPUS / "cases" / case_id / "case.json"


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_every_case_matches_its_expected_answer(case: dict[str, Any]) -> None:
    assert reader.verify(_case_json(case["id"])) == case["expected"]


def test_the_committed_corpus_is_what_the_builder_writes() -> None:
    done = subprocess.run([sys.executable, str(ROOT / "scripts/verdict-evidence-build.py"),
                           "--check"], capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stdout + done.stderr


@pytest.mark.parametrize("control", ["peer", "scope", "integrity", "fields", "quarantine"])
def test_each_control_has_accept_and_reject_cases(control: str) -> None:
    decisions = {c["expected"]["decision"] for c in CASES if c["control"] == control}
    assert "supported" in decisions or control in ("integrity", "fields")
    assert decisions - {"supported"}, control


def test_the_six_named_controls_are_present() -> None:
    reasons = {c["expected"]["reason"] for c in CASES}
    assert {
        "peer_artifact_unverified:untrusted_key",      # wrong peer key
        "peer_artifact_unverified:wrong_vector",       # wrong vector
        "peer_artifact_unverified:wrong_requirement",  # wrong requirement
        "peer_artifact_unverified:not_supplied",       # absent peer artifact
        "quarantine_digest_mismatch",                  # altered quarantine fields
        "quarantine_overdue",                          # overdue review date
    } <= reasons


def test_every_refused_case_names_a_supported_twin() -> None:
    for case in CASES:
        if case["expected"]["decision"] != "supported":
            assert BY_ID[case["twin"]]["expected"]["decision"] == "supported"


def test_no_scope_lift_without_a_peer_signed_statement() -> None:
    # Every case that reads PEER or EXTERNAL carries a peer statement signed by a pinned
    # peer key, and the runner's key never counts as one.
    for case in CASES:
        if case["expected"]["reason"] in ("verdict_verified_peer", "verdict_verified_external"):
            spec = json.loads(_case_json(case["id"]).read_text())
            assert "peer_statement" in spec["supplied"]
            assert not set(spec["policy"]["peer_keys"]) & set(spec["policy"]["trusted_keys"])


@pytest.mark.parametrize("rule", reader.RULES)
def test_every_rule_changes_some_answer(rule: str) -> None:
    skip = frozenset({rule})
    changed = [c["id"] for c in CASES if reader.verify(_case_json(c["id"]), skip) != c["expected"]]
    assert changed, f"switching off {rule} changes no answer: the rule is untested"


def test_the_reader_never_reads_the_expected_answer(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    shutil.copytree(CORPUS, corpus)
    case = corpus / "cases" / "reject-peer-wrong-key" / "case.json"
    assert reader.verify(case)["reason"] == "peer_artifact_unverified:untrusted_key"


def test_a_tampered_case_file_is_refused_before_judging(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    shutil.copytree(CORPUS, corpus)
    target = corpus / "cases" / "accept-quarantine-in-force" / "record.json"
    target.write_bytes(target.read_bytes() + b" ")
    with pytest.raises(CorpusError):
        load_manifest(corpus)


def test_the_reference_reader_passes_through_the_external_contract(
        monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PYTHONPATH", str(PACKAGING))
    report = run_corpus(CORPUS, [*RUN])
    assert report["answered"] == report["total"] == len(CASES)
    assert report["failures"] == []


def _verifier(tmp_path: Path, body: str) -> list[str]:
    script = tmp_path / "verifier.py"
    script.write_text(body)
    return [sys.executable, str(script)]


def test_an_accept_everything_verifier_fails_every_refused_case(tmp_path: Path) -> None:
    cmd = _verifier(tmp_path, 'import json\nprint(json.dumps({"decision": "supported", '
                              '"reason": "verdict_verified_self"}))\n')
    report = run_corpus(CORPUS, cmd)
    refused = {c["id"] for c in CASES if c["expected"]["decision"] != "supported"}
    assert refused <= set(report["failures"])


def test_a_verifier_whose_exit_code_disagrees_fails(tmp_path: Path) -> None:
    cmd = _verifier(tmp_path, 'import json,sys\nprint(json.dumps({"decision": "contradicted", '
                              '"reason": "x"}))\nsys.exit(0)\n')
    report = run_corpus(CORPUS, cmd)
    assert set(report["failures"]) == set(BY_ID)


def test_a_verifier_that_cannot_run_answers_nothing(tmp_path: Path) -> None:
    out = tmp_path / "out"
    done = subprocess.run([*RUN, "--output", str(out), "--verifier", str(tmp_path / "absent")],
                          cwd=PACKAGING, capture_output=True, text=True, check=False)
    assert done.returncode == 2, done.stdout + done.stderr


def test_the_cli_writes_a_report_and_exits_zero(tmp_path: Path) -> None:
    out = tmp_path / "out"
    done = subprocess.run([*RUN, "--output", str(out)], cwd=PACKAGING, capture_output=True,
                          text=True, check=False)
    assert done.returncode == 0, done.stdout + done.stderr
    report = json.loads((out / "report.json").read_text())
    assert report["answered"] == report["total"] == len(CASES)
