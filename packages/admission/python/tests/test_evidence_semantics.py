"""Exact evidence semantics: no report reads as a clearance when nothing was checked.

This is the lint over the verifier's output path. It drives every path that prints a denominator or a
link failure with an empty or unchecked input, and scans the package source for the idioms that would
bypass the helpers.
"""

import ast
import json
import re
import urllib.error
from pathlib import Path

import pytest
from agent_evidence_admission import conformance_registry as registry
from agent_evidence_admission import conformance_result as cr
from agent_evidence_admission import coverage_check as cc
from agent_evidence_admission import digest_check, dsse, ed25519
from agent_evidence_admission import evidence_semantics as sem
from agent_evidence_admission.cli import main

SRC = Path(sem.__file__).parent
SEED = bytes(range(32))
PUBLIC = ed25519.public_key(SEED)


def test_an_empty_denominator_prints_no_records():
    assert sem.Tally().headline("records") == sem.NO_RECORDS
    assert sem.Tally().word() == "UNCHECKED"
    assert not sem.Tally().ok


def test_unchecked_is_counted_apart_from_a_pass():
    counts = sem.Tally(passed=2, unchecked=1)
    assert not counts.ok and counts.word() == "UNCHECKED"
    assert "2 of 3" in counts.headline("classes") and "1 not checked" in counts.headline("classes")
    assert sem.Tally(passed=3).word() == "PASS"
    assert sem.Tally(passed=2, failed=1).word() == "FAIL"


def test_a_redaction_names_what_was_left_out():
    assert sem.redacted("api key") == "[redacted: api key]"
    assert "api key" in sem.Tally(passed=1, redactions=["api key"]).headline("records")


def test_an_empty_coverage_report_says_no_records_and_never_pass():
    report = cc.Report("cyclonedx", [], [])
    text = cc.format_report(report)
    assert text.endswith(f"UNCHECKED cyclonedx: {sem.NO_RECORDS}")
    assert "PASS" not in text and not report.ok


def test_a_coverage_report_of_only_unchecked_classes_is_not_a_pass():
    report = cc.Report("cyclonedx", [cc.ClassResult("service", cc.NOT_ASSESSED, "unknown", "stated"), cc.ClassResult("library", cc.COVERED_ELSEWHERE, None, "linked")], [])
    text = cc.format_report(report)
    assert "PASS" not in text and "0 of 2 required classes passed" in text and "2 not checked" in text
    assert report.ok  # accounted for, as before: the exit code is unchanged, the words are not a clearance


def test_a_coverage_report_with_everything_assessed_is_a_pass():
    report = cc.Report("spdx", [cc.ClassResult("library", cc.ASSESSED, None, "stated")], [])
    assert cc.format_report(report).endswith("PASS spdx: 1 of 1 required classes passed, 0 failed, 0 not checked")


def _signed(statement):
    return dsse.make_envelope(cr.canonical(statement), SEED)


def test_an_empty_registry_says_no_records_and_exits_1(tmp_path, capsys):
    (tmp_path / "registry").mkdir()
    code = main(["conformance", "verify", str(tmp_path / "registry"), "--trusted-key", PUBLIC.hex()])
    assert code == 1
    out = capsys.readouterr().out
    assert sem.NO_RECORDS in out and "PASS" not in out and "100" not in out
    code = main(["conformance", "verify", str(tmp_path / "registry"), "--trusted-key", PUBLIC.hex(), "--json"])
    report = json.loads(capsys.readouterr().out)
    assert code == 1 and report["ok"] is False and report["summary"] == sem.NO_RECORDS


def test_a_zero_case_manifest_is_refused_not_scored(tmp_path, capsys):
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"suite": {"revision": 1, "commit": None}, "cases": []}))
    seed = tmp_path / "seed.hex"
    seed.write_text(SEED.hex())
    code = main(["conformance", "run", str(manifest), "--implementation", "x", "--run-label", "author-produced", "--evidence", "measured", "--seed-file", str(seed), "--", "true"])
    assert code == 2 and sem.NO_RECORDS in capsys.readouterr().err


def test_a_score_out_of_zero_is_not_a_conformance_result():
    predicate = {
        "implementation": "x", "suite": {"revision": 1, "commit": None}, "runLabel": "author-produced", "evidence": "measured",
        "scores": [{"role": "score", "passed": 0, "total": 0}], "posting": None, "date": None, "runner": {"kind": "local-run"},
    }
    assert "field-invalid:scores" in cr.validate_predicate(predicate)


def test_errored_cases_are_never_passes(tmp_path):
    manifest = {"suite": {"revision": 1}, "cases": [{"id": "a", "input": "a", "expect": "accept"}]}
    results = cr.run_corpus(manifest, ["/nonexistent-command-for-this-test"], tmp_path)
    assert results[0]["verdict"] == "errored"
    assert cr.statement_from_results("x", manifest, results, "author-produced", "measured")["predicate"]["scores"][0]["passed"] == 0


@pytest.mark.parametrize(
    "failure",
    [
        urllib.error.HTTPError("https://x.example/doc", 404, "Not Found", {}, None),
        urllib.error.HTTPError("https://x.example/doc", 410, "Gone", {}, None),
        urllib.error.HTTPError("https://x.example/doc", 403, "Forbidden", {}, None),
        urllib.error.URLError("certificate verify failed"),
        TimeoutError("timed out"),
        ConnectionResetError("reset"),
    ],
)
def test_every_failed_fetch_is_one_error(monkeypatch, failure):
    def refuse(*_args, **_kwargs):
        raise failure

    monkeypatch.setattr(digest_check.urllib.request, "urlopen", refuse)
    with pytest.raises(sem.LinkError) as caught:
        digest_check.read_source("https://x.example/doc")
    assert str(caught.value) == f"{sem.LINK_ERROR}: https://x.example/doc"
    assert "404" not in str(caught.value) and "certificate" not in str(caught.value)


def test_the_package_prints_no_percentage_and_redacts_only_through_the_helper():
    for path in sorted(SRC.glob("*.py")):
        text = path.read_text()
        assert not re.search(r"100\s*%|\bpercent\b|:\.\d*%|\{[^}]*\}\s*%", text), f"{path.name} writes a percentage"
        if path.name == "evidence_semantics.py":
            continue
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert "redact" not in node.value.lower(), f"{path.name} words a redaction itself; use evidence_semantics.redacted"


def test_a_registry_index_with_a_missing_record_counts_it_failed(tmp_path):
    root = tmp_path / "registry"
    row = {
        "suiteRevision": 1, "suiteCommit": None, "runLabel": "author-produced", "evidence": "measured",
        "figures": [{"role": "score", "figure": "1/1"}], "posting": None, "date": None,
    }
    registry.add_record(root, _signed(cr.statement_from_row("x", row)), {dsse.keyid(PUBLIC): PUBLIC})
    for record in (root / "records").glob("*.dsse.json"):
        record.unlink()
    findings = registry.verify_registry(root, {dsse.keyid(PUBLIC): PUBLIC})
    assert findings and findings[0]["reasons"] == ["listed-but-missing"]
