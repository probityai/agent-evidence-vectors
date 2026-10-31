"""Check real fresh-prefix imports and failures before any target module starts."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from authority_effect import InputError as public_error
from authority_effect import isolated
from authority_effect.errors import InputError
from authority_effect.reader import InputError as reader_error


def test_public_and_reader_refusal_keep_one_class():
    assert public_error is reader_error is InputError
    assert isinstance(InputError("refused"), ValueError)


def test_command_executes_source_before_target_and_retains_profile(tmp_path):
    profile = tmp_path / "profile.json"
    command = isolated.command("authority_effect.cli", record=profile)
    result = subprocess.run([*command, "--help"], capture_output=True, timeout=30, check=False)
    assert result.returncode == 0 and not result.stderr
    assert b"frequency-controls" in result.stdout
    recorded = json.loads(profile.read_bytes())
    assert recorded["beforeTargetImport"] and recorded["privateEmptyPrefix"]
    assert recorded["preloadedTargets"] == []
    assert recorded["isolated"] and recorded["dontWriteBytecode"]
    assert recorded["prefixStillEmpty"]
    assert not Path(recorded["actualPycachePrefix"]).exists()
    assert recorded["imports"]["authority_effect.reader"]["cached"].startswith(
        recorded["actualPycachePrefix"] + "/"
    )


def test_prefix_profile_refuses_nonempty_and_nonprivate(tmp_path):
    directory = tmp_path / "prefix"
    directory.mkdir(mode=0o700)
    isolated._prefix_profile(directory)
    (directory / "kept").write_text("kept")
    with pytest.raises(RuntimeError, match="new, empty and private"):
        isolated._prefix_profile(directory)
    (directory / "kept").unlink()
    directory.chmod(0o755)
    with pytest.raises(RuntimeError, match="new, empty and private"):
        isolated._prefix_profile(directory)
    assert directory.exists()


def test_relative_profile_stays_with_parent_when_child_uses_outside_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    command = isolated.command("authority_effect.cli", record=Path("retained-profile.json"))
    result = subprocess.run(
        [*command, "--help"], cwd=outside, capture_output=True, timeout=30, check=False
    )
    assert result.returncode == 0 and not result.stderr
    assert (tmp_path / "retained-profile.json").is_file()
    assert not (outside / "retained-profile.json").exists()
    assert json.loads((tmp_path / "retained-profile.json").read_bytes())["privateEmptyPrefix"]


@pytest.mark.parametrize(
    "target_flag,target", [("--module", "authority_effect.cli"), ("--script", "probe.py")]
)
def test_main_uses_actual_interpreter_flags_before_target(
    tmp_path, monkeypatch, target_flag, target
):
    script = tmp_path / "probe.py"
    script.write_text("raise SystemExit(0)\n")
    if target_flag == "--script":
        target = str(script)
    recorded = {}

    def child(argv, **kwargs):
        prefix = Path(argv[4].removeprefix("pycache_prefix="))
        assert prefix.is_dir() and not any(prefix.iterdir())
        assert prefix.stat().st_uid == os.geteuid()
        assert argv[1:4] == ["-I", "-B", "-X"]
        recorded["prefix"] = prefix
        recorded["argv"] = argv
        return subprocess.CompletedProcess(argv, 7)

    monkeypatch.setattr(isolated.subprocess, "run", child)
    monkeypatch.setattr(sys, "argv", ["isolated", target_flag, target, "--", "--help"])
    assert isolated.main() == 7
    assert not recorded["prefix"].exists()
    assert recorded["argv"][-1] == "--help"


def test_bootstrap_records_script_profile_before_execution(tmp_path):
    script = tmp_path / "probe.py"
    script.write_text("import sys\nassert sys.pycache_prefix and sys.flags.isolated\n")
    profile = tmp_path / "script-profile.json"
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(Path(isolated.__file__).resolve()),
            "--script",
            str(script),
            "--cache-record",
            str(profile),
        ],
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0 and not result.stdout and not result.stderr
    recorded = json.loads(profile.read_bytes())
    assert recorded["targetKind"] == "script"
    assert recorded["selectedTarget"] == str(script)


def test_preexisting_profile_refuses_before_target(tmp_path):
    script = tmp_path / "probe.py"
    marker = tmp_path / "executed"
    script.write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
    profile = tmp_path / "kept.json"
    profile.write_text("kept")
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(Path(isolated.__file__).resolve()),
            "--script",
            str(script),
            "--cache-record",
            str(profile),
        ],
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode != 0 and b"FileExistsError" in result.stderr
    assert not marker.exists() and profile.read_text() == "kept"
