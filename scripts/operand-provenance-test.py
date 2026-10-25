"""Challenge the declared-constant operand provenance cases: every answer, kill and contract."""

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

from agent_evidence_vectors.operand_provenance import reader  # noqa: E402
from agent_evidence_vectors.operand_provenance.run import (  # noqa: E402
    CorpusError,
    load_manifest,
    run_corpus,
)

CORPUS = PACKAGING / "agent_evidence_vectors/operand_provenance/corpus"
MANIFEST = json.loads((CORPUS / "MANIFEST.json").read_text())
CASES = MANIFEST["cases"]
BY_ID = {c["id"]: c for c in CASES}
RUN = [sys.executable, "-m", "agent_evidence_vectors.operand_provenance.run"]


def _case_json(case_id: str) -> Path:
    return CORPUS / "cases" / case_id / "case.json"


def _load(case_id: str) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(_case_json(case_id).read_text())
    return loaded


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["id"])
def test_every_case_matches_its_expected_answer(case: dict[str, Any]) -> None:
    assert reader.verify(_case_json(case["id"])) == case["expected"]


def test_the_committed_corpus_is_what_the_builder_writes() -> None:
    done = subprocess.run([sys.executable, str(ROOT / "scripts/operand-provenance-build.py"),
                           "--check"], capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stdout + done.stderr


def test_the_declared_but_unconsumed_constant_is_refused() -> None:
    # The erratum itself: the declaration is present, the read is absent, and the
    # declaration alone must not ground the operand.
    case = _load("reject-constant-declared-not-consumed")
    derivation = case["derivations"][0]
    name = case["operand"]["grounding"]["constant"]
    assert name in {c["id"] for c in derivation["declared_constants"]}
    assert name not in {c["id"] for c in derivation["executed_reads"]}
    assert reader.judge(case)["reason"] == "constant_declared_not_consumed"


def test_every_refused_case_names_a_supported_twin_one_change_away() -> None:
    for case in CASES:
        if case["expected"]["decision"] == "supported":
            continue
        twin = BY_ID[case["twin"]]
        assert twin["expected"]["decision"] == "supported"
        assert _load(case["id"]) != _load(twin["id"])


def _diff(a: Any, b: Any) -> int:
    if isinstance(a, dict) and isinstance(b, dict):
        keys = set(a) | set(b)
        # A grounding claim is one respect: a constant claim and "originated" differ once.
        return sum(int(a.get(k, ...) != b.get(k, ...)) if k == "grounding"
                   else _diff(a.get(k, ...), b.get(k, ...)) for k in keys if k != "note")
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        return sum(_diff(x, y) for x, y in zip(a, b, strict=True))
    return int(a != b)


def test_each_refused_case_differs_from_its_twin_in_one_respect() -> None:
    for case in CASES:
        if case["expected"]["decision"] != "supported":
            assert _diff(_load(case["id"]), _load(case["twin"])) == 1, case["id"]


@pytest.mark.parametrize("control", ["consumed", "declared", "precision", "route"])
def test_each_paired_control_has_accept_and_reject_cases(control: str) -> None:
    decisions = {c["expected"]["decision"] for c in CASES if c["control"] == control}
    assert "supported" in decisions and decisions - {"supported"}, control


@pytest.mark.parametrize("rule", reader.RULES)
def test_every_rule_changes_some_answer(rule: str) -> None:
    skip = frozenset({rule})
    changed = [c["id"] for c in CASES if reader.verify(_case_json(c["id"]), skip) != c["expected"]]
    assert changed, f"switching off {rule} changes no answer: the rule is untested"


@pytest.mark.parametrize(("mutate", "reason"), [
    (lambda c: c.update(suite="other"), "malformed_case:suite"),
    (lambda c: c.update(derivations=[]), "malformed_case:derivations"),
    (lambda c: c["derivations"].append(dict(c["derivations"][0])),
     "malformed_case:derivations.duplicate"),
    (lambda c: c["operand"].update(value=4), "malformed_case:operand.value"),
    (lambda c: c["operand"].update(value="NaN"), "malformed_case:operand.value"),
    (lambda c: c["operand"].update(value="four"), "malformed_case:operand.value"),
    (lambda c: c["operand"]["grounding"].update(kind="guessed"),
     "malformed_case:operand.grounding"),
    (lambda c: c["operand"]["grounding"].pop("constant"),
     "malformed_case:operand.grounding.constant"),
    (lambda c: c["derivations"][0]["declared_constants"].append(
        dict(c["derivations"][0]["declared_constants"][0])),
     "malformed_case:derivations.declared_constants.duplicate"),
    (lambda c: c["derivations"][0]["executed_reads"].append({"value": "1"}),
     "malformed_case:derivations.executed_reads.id"),
    (lambda c: c["derivations"][0].update(declared_constants="100"),
     "malformed_case:derivations.declared_constants"),
    (lambda c: c.pop("operand"), "malformed_case:operand"),
    (lambda c: c["derivations"].__setitem__(0, "x"), "malformed_case:derivations.id"),
])
def test_a_malformed_case_reaches_no_verdict(mutate: Any, reason: str) -> None:
    case = _load("accept-constant-declared-and-consumed")
    mutate(case)
    assert reader.judge(case) == {"decision": "no_verdict", "reason": reason}


def test_a_claim_naming_an_unknown_derivation_is_not_declared() -> None:
    case = _load("accept-constant-declared-and-consumed")
    case["operand"]["grounding"]["derivation"] = "absent"
    assert reader.judge(case)["reason"] == "constant_not_declared"


def test_an_unreadable_or_non_object_case_reaches_no_verdict(tmp_path: Path) -> None:
    missing = reader.verify(tmp_path / "absent.json")
    listed = tmp_path / "list.json"
    listed.write_text("[]")
    assert missing["reason"] == "malformed_case:unreadable"
    assert reader.verify(listed)["reason"] == "malformed_case:not_an_object"


def test_the_reader_never_reads_the_expected_answer(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    shutil.copytree(CORPUS, corpus)
    (corpus / "MANIFEST.json").unlink()
    case = corpus / "cases" / "reject-constant-declared-not-consumed" / "case.json"
    assert reader.verify(case)["reason"] == "constant_declared_not_consumed"


def test_a_tampered_case_file_is_refused_before_judging(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus"
    shutil.copytree(CORPUS, corpus)
    target = corpus / "cases" / "accept-operand-originated" / "case.json"
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


def test_a_declaration_trusting_verifier_fails_the_erratum_case(tmp_path: Path) -> None:
    # A verifier that grounds an operand on any declared constant, as the instrument
    # did before the erratum, passes the declared cases and fails the unconsumed one.
    body = (
        "import json, sys\n"
        "c = json.load(open(sys.argv[1]))\n"
        "g = c['operand']['grounding']\n"
        "if g['kind'] == 'originated':\n"
        "    print(json.dumps({'decision': 'supported', 'reason': 'operand_originated'}))\n"
        "    sys.exit(0)\n"
        "d = {x['id']: x for x in c['derivations']}.get(g['derivation'], {})\n"
        "ok = any(k['id'] == g['constant'] for k in d.get('declared_constants', []))\n"
        "r = 'constant_declared_and_consumed' if ok else 'constant_not_declared'\n"
        "print(json.dumps({'decision': 'supported' if ok else 'contradicted', 'reason': r}))\n"
        "sys.exit(0 if ok else 1)\n"
    )
    report = run_corpus(CORPUS, _verifier(tmp_path, body))
    assert "reject-constant-declared-not-consumed" in report["failures"]
    assert "reject-claim-names-route-that-did-not-read" in report["failures"]


def test_an_accept_everything_verifier_fails_every_refused_case(tmp_path: Path) -> None:
    cmd = _verifier(tmp_path, 'import json\nprint(json.dumps({"decision": "supported", '
                              '"reason": "constant_declared_and_consumed"}))\n')
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


def test_the_cli_judges_one_case_with_its_exit_code() -> None:
    for case_id, code in (("accept-operand-originated", 0),
                          ("reject-constant-declared-not-consumed", 1),
                          ("reject-executed-reads-absent", 2)):
        done = subprocess.run([*RUN, str(_case_json(case_id)), "--json"], cwd=PACKAGING,
                              capture_output=True, text=True, check=False)
        assert done.returncode == code, done.stdout + done.stderr
        assert json.loads(done.stdout) == BY_ID[case_id]["expected"]


def test_the_cli_writes_a_report_and_exits_zero(tmp_path: Path) -> None:
    out = tmp_path / "out"
    done = subprocess.run([*RUN, "--output", str(out)], cwd=PACKAGING, capture_output=True,
                          text=True, check=False)
    assert done.returncode == 0, done.stdout + done.stderr
    report = json.loads((out / "report.json").read_text())
    assert report["answered"] == report["total"] == len(CASES)
    assert report["schema"] == "aev-operand-provenance-report/v1"
