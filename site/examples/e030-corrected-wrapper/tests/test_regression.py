"""Real pinned wrapper subprocesses, source isolation and separate operator credit."""

import json
import os
import signal
from pathlib import Path

import pytest

from e030_case import faults, regression


@pytest.mark.parametrize(
    "command,timeout,termination,signum,complete",
    [
        (["bash", "-c", "kill -TERM $$"], 5, "signal", signal.SIGTERM, True),
        (["bash", "-c", "exec sleep 5"], 0.03, "timeout", signal.SIGKILL, False),
        (["/this/e030-test/executable-does-not-exist"], 5, "spawn_failure", None, False),
    ],
)
def test_process_failures_keep_signals_distinct_from_exits(
    tmp_path, command, timeout, termination, signum, complete
):
    stdout, stderr, result = regression._capture_process(
        command, cwd=tmp_path, env=regression.clean_environment(), timeout=timeout
    )
    assert isinstance(stdout, bytes) and isinstance(stderr, bytes)
    assert result["termination"] == termination
    assert result["signal"] == signum
    assert result["actual_exit"] is None
    assert result["capture_complete"] is complete
    if signum:
        assert result["returncode"] == -signum
    if not complete:
        assert result["error"]


def input_roots():
    base = Path(os.environ["E030_INPUT_ROOT"])
    return {name: base / name for name in regression.SOURCES}


def test_actual_pinned_corrected_wrapper_and_all_injected_cases(tmp_path):
    output = tmp_path / "result"
    args = [
        "--operator",
        "Probity Codex / shared BoxPool author-run",
        *(str(path) for path in input_roots().values()),
        str(output),
    ]
    assert regression.main(args) == 0
    receipt = json.loads((output / "receipt.json").read_text())
    assert receipt["operator"]["identity"] == "Probity Codex / shared BoxPool author-run"
    assert receipt["operator"]["source"] == "caller-declared"
    assert receipt["vector"]["maintainer"] == "Probity"
    assert receipt["vector"]["finding_credit"] == "imokokok"
    assert receipt["all_expected_controls_matched"]
    assert len(receipt["cases"]) == 14
    cases = {case["name"]: case for case in receipt["cases"]}
    assert cases["failed-install"]["actual_exit"] == 23
    assert not cases["failed-install"]["pass_printed"]
    assert cases["failed-node"]["recorded_exit"] == 17
    assert not cases["failed-node"]["pass_printed"]
    for name in ["absent-report", "malformed-report", "wrong-input", "stale-generation"]:
        assert cases[name]["actual_exit"] == 0
        assert cases[name]["pass_printed"]
        assert not cases[name]["comparison"]["accepted_projection"]
    assert cases["matching-projection"]["comparison"]["accepted_projection"]
    assert not receipt["scope"]["producer_verifier_executed"]
    for case in receipt["cases"]:
        assert (output / case["name"] / "wrapper.stdout").exists()
        assert (output / case["name"] / "wrapper.stderr").exists()
        assert json.loads((output / case["name"] / "process.json").read_text())["capture_complete"]


def test_inherited_git_and_shell_settings_are_removed(monkeypatch):
    monkeypatch.setenv("GIT_DIR", "/another/repository")
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "core.worktree")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "/another/worktree")
    monkeypatch.setenv("BASH_ENV", "/another/startup")
    monkeypatch.setenv("PYTHONPATH", "/another/python")
    env = regression.clean_environment()
    assert "GIT_DIR" not in env and "GIT_CONFIG_COUNT" not in env
    assert "GIT_CONFIG_KEY_0" not in env and "GIT_CONFIG_VALUE_0" not in env
    assert "BASH_ENV" not in env and "PYTHONPATH" not in env
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull


def test_output_cannot_select_or_modify_a_producer_tree(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    roots = {"review": source}
    with pytest.raises(ValueError, match="outside producer"):
        regression.validate_output(source / "result", roots)
    alias = tmp_path / "alias"
    alias.symlink_to(source, target_is_directory=True)
    with pytest.raises(ValueError, match="outside producer"):
        regression.validate_output(alias / "result", roots)
    with pytest.raises(ValueError, match="must not exist"):
        regression.validate_output(source, roots)
    with pytest.raises(ValueError, match="parent must exist"):
        regression.validate_output(tmp_path / "absent" / "result", roots)
    regression.validate_output(tmp_path / "new-result", roots)


def test_wrong_or_missing_source_cannot_start_a_run(tmp_path):
    roots = input_roots()
    roots["review"] = roots["aps"]
    with pytest.raises(ValueError, match="wrong source revision"):
        regression.validate_sources({key: path.resolve() for key, path in roots.items()})
    with pytest.raises(ValueError, match="Git read failed"):
        regression._git(tmp_path, "rev-parse", "HEAD")
    output = tmp_path / "never-created"
    with pytest.raises(ValueError, match="operator identity"):
        regression.run("", input_roots(), output)
    assert not output.exists()


def test_operator_option_is_required_without_legacy_aliases():
    with pytest.raises(SystemExit) as failure:
        regression.main(["--runner", "legacy", "r", "a", "p", "out"])
    assert failure.value.code == 2


def test_injected_node_uses_actual_exit_and_explicit_destination(tmp_path, monkeypatch):
    log = tmp_path / "trace"
    monkeypatch.setenv("VECTOR_LOG", str(log))
    monkeypatch.setenv("NODE_EXIT", "17")
    assert faults.main(["verify.mjs"]) == 17
    monkeypatch.setenv("NODE_EXIT", "0")
    with pytest.raises(ValueError, match="one explicit"):
        faults.main(["verify.mjs"])
    monkeypatch.setenv("E030_FAULT", "matching")
    output = tmp_path / "injected.json"
    assert faults.main(["verify.mjs", "--out", str(output)]) == 0
    assert (
        json.loads(output.read_text())["profile"] == "frequency.external-assurance.aps-priorseal.v1"
    )
    with pytest.raises(ValueError, match="unknown fixture fault"):
        faults.emit("invented", output)
