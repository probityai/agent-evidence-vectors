"""Keep supplied decisions literal and every requested-effect combination explicit."""

import json
import shutil
import subprocess
import sys

import pytest

from authority_effect import cli, frequency_claims
from authority_effect.reader import InputError

ROOT = frequency_claims.ROOT
MANIFEST = json.loads((ROOT / "manifest.json").read_bytes())


@pytest.mark.parametrize("entry", MANIFEST["cases"], ids=lambda entry: entry["id"])
def test_explicit_claim_cells_and_invalid_boolean_inputs(entry):
    raw = (ROOT / entry["path"]).read_bytes()
    if entry["expected"] == "REFUSED":
        with pytest.raises(InputError, match="literal Boolean"):
            frequency_claims.assess_supplied_claims(raw)
    else:
        report = frequency_claims.assess_supplied_claims(raw)
        assert report["claims"] == entry["expected"]
        assert report["requiredPostDecisionState"] == "NOT_SUPPLIED"


def test_complete_table_includes_the_three_previously_absent_cells():
    cells = {
        (
            entry["expected"]["suppliedDecision"],
            entry["expected"]["completionReport"],
            entry["expected"]["requestedEffectComparison"],
        )
        for entry in MANIFEST["cases"]
        if isinstance(entry["expected"], dict)
    }
    assert len(cells) == 12
    assert ("DENIED", "NOT_REPORTED", "DIFFERS_FROM_REQUEST") in cells
    assert ("AUTHORIZED", "NOT_REPORTED", "NOT_ESTABLISHED") in cells
    assert ("DENIED", "REPORTED", "NOT_ESTABLISHED") in cells


@pytest.mark.parametrize(
    "change",
    [
        {"profile": "unsupported"},
        {"requestedEffect": ""},
        {"observation": False},
        {"requiredState": "v0"},
    ],
)
def test_invalid_or_unselected_effect_contract_is_refused(change):
    value = json.loads((ROOT / MANIFEST["cases"][0]["path"]).read_bytes())
    value.update(change)
    with pytest.raises(InputError):
        frequency_claims.assess_supplied_claims(json.dumps(value).encode())


def test_cli_retains_all_comparison_and_refusal_results(tmp_path, monkeypatch, capsys):
    out = tmp_path / "controls"
    monkeypatch.setattr(sys, "argv", ["claims", "frequency-controls", "--output", str(out)])
    assert cli.main() == 0
    report = json.loads(capsys.readouterr().out)
    assert report["passed"] == report["total"] == 28
    rejected = [row for row in report["rows"] if row["actual"] is None]
    assert len(rejected) == 16
    assert all(row["exit"] == 2 for row in rejected)
    with pytest.raises(InputError, match="absent or empty"):
        frequency_claims.run_supplied_controls(out)


def test_unknown_fixture_file_changes_the_selected_population(tmp_path, monkeypatch):
    root = tmp_path / "fixtures"
    shutil.copytree(ROOT, root)
    (root / "unselected.json").write_text("{}")
    monkeypatch.setattr(frequency_claims, "ROOT", root)
    with pytest.raises(InputError, match="population changed"):
        frequency_claims.run_supplied_controls(tmp_path / "out")


def test_tampered_fixture_digest_cannot_start_a_consumer(tmp_path, monkeypatch):
    root = tmp_path / "fixtures"
    shutil.copytree(ROOT, root)
    (root / MANIFEST["cases"][0]["path"]).write_text("{}")
    monkeypatch.setattr(frequency_claims, "ROOT", root)
    with pytest.raises(InputError, match="digest differs"):
        frequency_claims.run_supplied_controls(tmp_path / "out")


def test_unexpected_child_result_is_retained_as_a_failed_comparison(tmp_path, monkeypatch):
    entry = MANIFEST["cases"][0]
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args, 42, b"unparsed output", b"diagnostic"
        ),
    )
    result = frequency_claims._control(entry, tmp_path, str(tmp_path))
    assert not result["matched"] and result["exit"] == 42
    assert (tmp_path / (entry["id"] + ".stdout")).read_bytes() == b"unparsed output"
    assert (tmp_path / (entry["id"] + ".stderr")).read_bytes() == b"diagnostic"


def test_malformed_successful_child_output_cannot_pass():
    process = subprocess.CompletedProcess([], 0, b"not JSON", b"")
    result = {"claims": {"suppliedDecision": "DENIED"}}
    assert not frequency_claims._matched(result, result["claims"], process)
