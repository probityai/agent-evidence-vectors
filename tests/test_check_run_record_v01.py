"""check_run_record.py reads a v0.1 report directly.

The fixtures are a published records directory, byte for byte (see
fixtures/agentavow-r4-fbbbd4ac/SOURCE.md). Each negative control changes one
thing in a copy and expects that one thing to be reported.
"""

import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "corpora" / "vectors-mcp-record-contract" / "check_run_record.py"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "agentavow-r4-fbbbd4ac"
NAMES = {"native-verify-mjs": 76, "probity-map-reader": 67, "heldfast-profiles": 16}

_SPEC = importlib.util.spec_from_file_location("check_run_record_v01", CHECKER)
checker = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(checker)


def run(*args):
    return subprocess.run(
        [sys.executable, "-I", str(CHECKER), *map(str, args)],
        capture_output=True, text=True, check=False,
    )


@pytest.fixture()
def copy(tmp_path):
    target = tmp_path / "r4"
    shutil.copytree(FIXTURE, target)
    return target


def verdicts(path, **kw):
    return {p.stem: checker.check_v01_report(p, **kw) for p in checker.v01_reports(str(path))}


def edit(path, change):
    data = json.loads(path.read_text())
    change(data)
    path.write_text(json.dumps(data, indent=2) + "\n")


def test_real_rows_are_recheckable_self_reports():
    found = verdicts(FIXTURE / "records")
    assert set(found) == set(NAMES)
    for name, verdict in found.items():
        assert verdict["recheckable"], (name, verdict["missing"])
        assert verdict["figureMeansWhatItSays"], (name, verdict["notes"])
        assert verdict["independence"] == "self-report"


def test_record_is_built_only_from_the_published_files():
    for name, total in NAMES.items():
        record, problems, misleading = checker.read_v01_report(
            FIXTURE / "records" / "reports" / f"{name}.json")
        assert problems == [] and misleading == []
        side = record["sides"][0]
        assert side["inputs"]["ref"] == "sha256:48cf831840fc81db4e242ce5d2230a99fd41c890e5aa8b00dd6edef24098e9d3"
        assert side["invocation"].startswith(".venv/bin/python emit.py --runner")
        assert side["output"]["published"] is True
        assert record["figure"]["headline"] == f"{total} of {total}"
        assert record["figure"]["scored"] == record["figure"]["total"] == total


def test_runner_refs_come_from_the_checker_field():
    refs = {
        n: checker.read_v01_report(FIXTURE / "records" / "reports" / f"{n}.json")[0]["sides"][0]["runner"]["ref"]
        for n in NAMES
    }
    assert refs["probity-map-reader"] == "d759fb4db68a7fefcc91c2d3ad2a585471d6a53a"
    assert refs["heldfast-profiles"] == "ca5a872264b486907ed5479247e5150c5122d33d"
    assert refs["native-verify-mjs"].startswith("sha256:")


def test_cli_directory_exit_zero_and_json():
    done = run("--v01", FIXTURE / "records")
    assert done.returncode == 0, done.stderr
    assert done.stdout.count("re-checkable, figure honest, self-report") == 3
    as_json = run("--v01", "--json", FIXTURE / "records")
    assert len(json.loads(as_json.stdout)) == 3


def test_v01_report_without_flag_is_unreadable_not_a_finding():
    done = run(FIXTURE / "records" / "reports" / "heldfast-profiles.json")
    assert done.returncode == 2
    assert "--v01" in done.stderr and "NOT re-checkable" not in done.stdout


def test_other_shape_is_unreadable():
    done = run(FIXTURE / "records" / "run.json")
    assert done.returncode == 2 and "not a run record" in done.stderr


def test_wrong_format_is_unreadable(copy):
    path = copy / "records" / "reports" / "heldfast-profiles.json"
    edit(path, lambda d: d.update(format="something/else"))
    assert run("--v01", path).returncode == 2


def test_tampered_report_is_not_published(copy):
    path = copy / "records" / "reports" / "heldfast-profiles.json"
    edit(path, lambda d: d.update(note="x"))
    verdict = verdicts(copy / "records")["heldfast-profiles"]
    assert not verdict["recheckable"]
    assert any("SHA256SUMS lists" in m for m in verdict["missing"])


def test_rollup_that_disagrees_with_checks_misleads(copy):
    path = copy / "records" / "reports" / "heldfast-profiles.json"
    edit(path, lambda d: d["checks"][0].update(state="fail"))
    # keep the digest honest so only the figure is at issue
    sums = copy / "records" / "SHA256SUMS"
    import hashlib
    new = hashlib.sha256(path.read_bytes()).hexdigest()
    lines = [
        f"{new}  reports/heldfast-profiles.json"
        if line.endswith("reports/heldfast-profiles.json")
        else line
        for line in sums.read_text().splitlines()
    ]
    sums.write_text("\n".join(lines) + "\n")
    verdict = verdicts(copy / "records")["heldfast-profiles"]
    assert verdict["recheckable"]
    assert not verdict["figureMeansWhatItSays"]


def test_tag_runner_is_flagged(copy):
    path = copy / "records" / "configs" / "probity-map-reader.json"
    edit(path, lambda d: d.update(checker="probityai/agent-evidence-vectors@v0.1.0/x.py"))
    verdict = verdicts(copy / "records")["probity-map-reader"]
    assert not verdict["recheckable"]
    assert any("runner" in m for m in verdict["missing"])


def test_no_readme_command_means_no_invocation_unless_given(copy):
    (copy / "README.md").write_text("nothing here\n")
    assert not verdicts(copy / "records")["heldfast-profiles"]["recheckable"]
    given = verdicts(copy / "records", invocation="python3 emit.py --out records")
    assert given["heldfast-profiles"]["recheckable"]


def test_two_inputs_have_no_single_reference(copy):
    path = copy / "records" / "configs" / "heldfast-profiles.json"
    edit(path, lambda d: d["inputs"].update(extra={"path": "p", "sha256": "0" * 64}))
    assert not verdicts(copy / "records")["heldfast-profiles"]["recheckable"]


def test_independence_follows_runner_wrote(copy):
    run_json = copy / "records" / "run.json"
    edit(run_json, lambda d: d.update({"runner-wrote": ["native"]}))
    assert verdicts(copy / "records")["heldfast-profiles"]["independence"] == "independent"
    edit(run_json, lambda d: d.pop("runner-wrote"))
    assert verdicts(copy / "records")["heldfast-profiles"]["independence"] == "undeclared"
