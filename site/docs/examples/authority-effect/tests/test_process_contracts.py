"""Population, process-retention and CLI controls distinct from reader semantics."""

import hashlib
import json
import runpy
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from authority_effect import cli, runner, scanner
from authority_effect.reader import InputError


def test_cli_refuses_missing_bytes_without_a_verdict(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["reader", "read", "missing", "--policy", "missing"])
    assert cli.main() == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.startswith("refused:")


def test_cli_reads_each_axis(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "reader",
            "read",
            str(runner.ROOT / "cases" / "matching-supplied-records.json"),
            "--policy",
            str(runner.ROOT / "policy.json"),
        ],
    )
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out)["claims"]["destinationAuthorized"]["value"] is True


@pytest.mark.parametrize(
    "command,report,expected",
    [
        ("controls", {"passed": 2, "total": 3}, 1),
        ("controls", {"passed": 3, "total": 3}, 0),
        (
            "coverage-bridge",
            {"passed": 3, "total": 3, "vectorsExecuted": 3, "vectorsFailures": ["changed"]},
            1,
        ),
        (
            "coverage-bridge",
            {"passed": 3, "total": 3, "vectorsExecuted": 2, "vectorsFailures": []},
            1,
        ),
    ],
)
def test_cli_process_gates_propagate_failures(command, report, expected, monkeypatch, capsys):
    from authority_effect import coverage_bridge

    module = runner if command == "controls" else coverage_bridge
    name = "run_controls" if command == "controls" else "run_bridge"
    monkeypatch.setattr(module, name, lambda output: report)
    monkeypatch.setattr(sys, "argv", ["reader", command, "--output", "unused"])
    assert cli.main() == expected
    assert json.loads(capsys.readouterr().out) == report


@pytest.mark.parametrize(
    "mode,exit_code,notice,complete",
    [
        ("complete", 0, False, True),
        ("truncation-zero", 0, True, False),
        ("truncation-one", 1, True, False),
        ("silent-truncation", 0, False, False),
    ],
)
def test_reduced_scanner_preserves_printed_notice_and_status(
    mode, exit_code, notice, complete, monkeypatch, capsys
):
    monkeypatch.setattr(sys, "argv", ["scanner", mode])
    assert scanner.main() == exit_code
    output = capsys.readouterr().out
    assert ("truncated:" in output) is notice
    assert ("selected unit: unit-c" in output) is complete


@pytest.fixture
def copied_root(tmp_path, monkeypatch):
    root = tmp_path / "fixtures"
    shutil.copytree(runner.ROOT, root)
    monkeypatch.setattr(runner, "ROOT", root)
    return root


def rewrite(root, change):
    manifest = json.loads((root / "manifest.json").read_bytes())
    change(manifest)
    (root / "manifest.json").write_text(json.dumps(manifest))


@pytest.mark.parametrize(
    "change",
    [
        lambda m: m.update(cases=[]),
        lambda m: m.update(total=0),
        lambda m: m.update(profile="other"),
        lambda m: m["cases"].append(m["cases"][0]),
        lambda m: m["cases"][0].update(path="../policy.json"),
        lambda m: m["cases"][0].update(id="../escape"),
        lambda m: m.pop("total"),
    ],
)
def test_manifest_refuses_omissions_duplicates_and_escape(change, copied_root):
    rewrite(copied_root, change)
    with pytest.raises(InputError):
        runner._manifest()


def test_baseline_policy_is_bound(copied_root):
    with (copied_root / "policy.json").open("ab") as stream:
        stream.write(b" ")
    with pytest.raises(InputError, match="digest"):
        runner._manifest()


def test_one_changed_case_is_refused_before_child(copied_root, tmp_path):
    entry = runner._manifest()[0]
    (copied_root / entry["path"]).write_text("{}")
    with pytest.raises(InputError, match="digest"):
        runner._control(entry, tmp_path, str(tmp_path))


def test_changed_selected_policy_is_refused_before_child(copied_root, tmp_path):
    entry = runner._manifest()[0]
    (copied_root / entry["policy"]).write_text("{}")
    with pytest.raises(InputError, match="digest"):
        runner._control(entry, tmp_path, str(tmp_path))


@pytest.mark.parametrize(
    "stdout,stderr,exit_code", [(b"{}", b"", 0), (b"not json", b"", 2), (b"{}", b"warning", 0)]
)
def test_child_disagreement_retains_all_output(
    stdout, stderr, exit_code, copied_root, tmp_path, monkeypatch
):
    entry = runner._manifest()[0]
    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a[0], exit_code, stdout, stderr),
    )
    row = runner._control(entry, tmp_path, str(tmp_path))
    assert row["matched"] is False
    assert (tmp_path / (entry["id"] + ".stdout")).read_bytes() == stdout
    assert (tmp_path / (entry["id"] + ".stderr")).read_bytes() == stderr
    assert (tmp_path / (entry["id"] + ".exit")).read_text() == f"{exit_code}\n"


def test_controls_refuses_overwriting_existing_receipt(tmp_path):
    (tmp_path / "kept").write_text("retained")
    with pytest.raises(InputError, match="absent or empty"):
        runner.run_controls(tmp_path)


@pytest.mark.parametrize(
    "change",
    [
        "none",
        "wrong-source",
        "same-byte-alias",
        "same-byte-parent-alias",
        "same-byte-root-alias",
        "changed-bytes",
        "missing-module",
    ],
)
def test_coverage_requires_the_exact_qualified_installed_source(tmp_path, change):
    checker = runpy.run_path(str(Path(__file__).parents[1] / "scripts/check_coverage.py"))
    required = checker["REQUIRED"]
    root = tmp_path / "installed"
    package = root / "authority_effect"
    package.mkdir(parents=True)
    selected = []
    measured = {}
    for name in required:
        path = package / name
        content = b"# selected wheel source\n"
        path.write_bytes(content)
        selected.append(
            {
                "path": "authority_effect/" + name,
                "bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
        measured[str(path)] = {"summary": {"percent_covered": 80}}
    if change == "wrong-source":
        measured[str(tmp_path / "another/reader.py")] = measured.pop(str(package / "reader.py"))
    elif change == "same-byte-alias":
        outside = tmp_path / "another"
        outside.mkdir()
        alias = outside / "reader.py"
        alias.symlink_to(package / "reader.py")
        measured[str(alias)] = measured.pop(str(package / "reader.py"))
    elif change == "same-byte-parent-alias":
        outside = tmp_path / "outside-package"
        package.rename(outside)
        package.symlink_to(outside, target_is_directory=True)
    elif change == "same-byte-root-alias":
        outside = tmp_path / "outside-root"
        root.rename(outside)
        root.symlink_to(outside, target_is_directory=True)
        measured = {
            str(outside / "authority_effect" / Path(name).name): row
            for name, row in measured.items()
        }
    elif change == "changed-bytes":
        (package / "reader.py").write_bytes(b"# later unqualified source\n")
    elif change == "missing-module":
        measured.pop(str(package / "errors.py"))
    qualification = {
        "installedPayload": {
            "installedRoot": str(root),
            "files": selected,
            "wheelSha256": "selected-wheel-digest",
        }
    }
    report = checker["evaluate"]({"files": measured}, qualification)
    assert report["passing"] is (change == "none")
    assert report["selectedWheelSha256"] == "selected-wheel-digest"
