"""Challenge the ACS outage posture reader: every expected answer, every refusal, every kill."""

from __future__ import annotations

import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

PACKAGING = Path(__file__).resolve().parents[1] / "packaging"
sys.path.insert(0, str(PACKAGING))

from agent_evidence_vectors.acs_outage import reader  # noqa: E402
from agent_evidence_vectors.acs_outage.run import (  # noqa: E402
    PACKAGED_CORPUS,
    CorpusError,
    load_manifest,
    run_corpus,
)
from agent_evidence_vectors.acs_outage.run import main as run_main  # noqa: E402

MANIFEST = json.loads((PACKAGED_CORPUS / "MANIFEST.json").read_text())
CASES = MANIFEST["cases"]
BY_ID = {case["id"]: case for case in CASES}


def _step(case_id: str) -> dict[str, Any]:
    case = json.loads((PACKAGED_CORPUS / "cases" / case_id / "case.json").read_text())
    return case["step"]


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["id"])
def test_every_case_matches_its_expected_answer(case: dict[str, Any]) -> None:
    assert reader.judge(_step(case["id"])) == case["expected"]


def test_corpus_is_what_the_builder_writes() -> None:
    script = Path(__file__).with_name("acs-outage-build.py")
    assert subprocess.run([sys.executable, str(script), "--check"], check=False).returncode == 0


def test_supported_cases_are_the_four_recorded_steps() -> None:
    supported = [c for c in CASES if c["expected"]["decision"] == reader.SUPPORTED]
    assert sorted(c["source"] for c in supported) == [
        "replay:deny-cached", "replay:deny-fresh", "replay:proceed-cached", "replay:proceed-fresh"]


def test_every_refused_case_is_one_change_from_a_supported_twin() -> None:
    for case in CASES:
        if case["expected"]["decision"] == reader.SUPPORTED:
            continue
        twin = BY_ID[case["twin"]]
        assert twin["expected"]["decision"] == reader.SUPPORTED
        assert _step(case["id"]) != _step(twin["id"])


def test_every_reason_code_is_reached() -> None:
    reasons = {case["expected"]["reason"] for case in CASES}
    for code in ("posture_not_applied", "unnegotiated_posture_applied", "blocked_step_executed",
                 "allowed_step_not_executed", "outage_step_not_audited", "audit_posture_mismatch",
                 "posture_source_misreported", "audit_outcome_mismatch",
                 "unguarded_startup_not_audited", "audit_not_exported", "failure_class_mismatch",
                 "failure_posture_mismatch", "reporter_mismatch", "malformed_step"):
        assert code in reasons, code


def test_reader_never_reads_the_expected_answer() -> None:
    step = _step("accept-cached-deny")
    step["expected"] = {"decision": "contradicted"}
    assert reader.judge(step)["decision"] == reader.SUPPORTED


@pytest.mark.parametrize("rule", reader.RULES)
def test_disabling_each_rule_turns_a_named_case(rule: str) -> None:
    """A rule that no case depends on is a rule nobody tested."""
    turned = [c["id"] for c in CASES
              if reader.judge(_step(c["id"]), frozenset({rule})) != c["expected"]]
    assert turned, f"disabling {rule} changes no answer"


@pytest.mark.parametrize("step", [None, [], {"guardian": "unreachable"},
                                  {"guardian": "unreachable", "hook_decision": "ask",
                                   "marker_delta": 0, "session_id": "s"}])
def test_malformed_steps_get_no_verdict(step: Any) -> None:
    assert reader.judge(step) == {"decision": reader.NO_VERDICT, "reason": "malformed_step"}


def test_run_corpus_with_the_reference_reader() -> None:
    report = run_corpus(PACKAGED_CORPUS)
    assert report["answered"] == report["total"] == len(CASES)
    assert report["failures"] == []


def _copy(tmp_path: Path) -> Path:
    root = tmp_path / "corpus"
    shutil.copytree(PACKAGED_CORPUS, root)
    return root


def test_an_edited_case_is_refused_before_judgement(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    path = root / "cases" / "accept-cached-deny" / "case.json"
    path.write_text(path.read_text().replace('"deny"', '"allow"', 1))
    with pytest.raises(CorpusError):
        load_manifest(root)


def test_an_edited_source_record_is_refused(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    path = root / "source" / "deny" / "audit.jsonl"
    path.write_text(path.read_text().replace("blocked", "proceeded", 1))
    with pytest.raises(CorpusError):
        load_manifest(root)


def test_a_refused_case_without_a_supported_twin_is_refused(tmp_path: Path) -> None:
    root = _copy(tmp_path)
    manifest = json.loads((root / "MANIFEST.json").read_text())
    manifest["cases"][-1]["twin"] = "reject-step-not-audited"
    manifest["corpusDigest"] = reader.sha256_hex(
        json.dumps(manifest["cases"], sort_keys=True).encode())
    (root / "MANIFEST.json").write_text(json.dumps(manifest))
    with pytest.raises(CorpusError):
        load_manifest(root)


def _verifier(tmp_path: Path, body: str) -> str:
    script = tmp_path / "verifier.py"
    script.write_text(body)
    return f"{sys.executable} {script}"


def test_external_verifier_that_agrees_passes(tmp_path: Path) -> None:
    command = _verifier(tmp_path, (
        "import sys\n"
        f"sys.path.insert(0, {str(PACKAGING)!r})\n"
        "from agent_evidence_vectors.acs_outage.run import main\n"
        "raise SystemExit(main(sys.argv[1:]))\n"))
    out = tmp_path / "out"
    assert run_main(["--output", str(out), "--verifier", command,
                     "--implementation-revision", "0" * 40]) == 0


def test_external_verifier_that_always_supports_fails(tmp_path: Path) -> None:
    command = _verifier(tmp_path, (
        "import json\n"
        "print(json.dumps({'decision': 'supported', 'reason': 'x'}))\n"))
    out = tmp_path / "out"
    assert run_main(["--output", str(out), "--verifier", command,
                     "--implementation-revision", "0" * 40]) == 1


def test_external_verifier_whose_exit_disagrees_fails(tmp_path: Path) -> None:
    base = (
        "import sys, json\n"
        f"sys.path.insert(0, {str(PACKAGING)!r})\n"
        "from agent_evidence_vectors.acs_outage.reader import verify\n"
        "from pathlib import Path\n"
        "print(json.dumps(verify(Path(sys.argv[1]))))\n"
        "raise SystemExit(0)\n")
    out = tmp_path / "out"
    assert run_main(["--output", str(out), "--verifier", _verifier(tmp_path, base),
                     "--implementation-revision", "0" * 40]) == 1


def test_a_verifier_that_cannot_run_answers_nothing(tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert run_main(["--output", str(out), "--verifier", str(tmp_path / "missing"),
                     "--implementation-revision", "0" * 40]) == 2


def test_checkout_run_requires_a_revision(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from importlib import metadata

    def missing(name: str) -> str:
        raise metadata.PackageNotFoundError(name)

    monkeypatch.setattr(metadata, "version", missing)
    with pytest.raises(SystemExit):
        run_main(["--output", str(tmp_path / "out")])


def test_single_case_cli_exit_codes(capsys: pytest.CaptureFixture[str]) -> None:
    for case in CASES:
        path = PACKAGED_CORPUS / "cases" / case["id"] / "case.json"
        code = run_main([str(path), "--json"])
        answer = json.loads(capsys.readouterr().out)
        assert answer == case["expected"]
        assert code == reader.EXIT_FOR[answer["decision"]]


def test_copy_is_not_aliasing() -> None:
    step = _step("accept-cached-proceed")
    before = copy.deepcopy(step)
    reader.judge(step)
    assert step == before
