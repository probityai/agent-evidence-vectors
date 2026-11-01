"""Refuse absolute local paths in retained run records, at the writer and in the corpus.

Literal roots are built from parts so this file holds none for the repository scans.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "packaging"))

from agent_evidence_vectors import record_paths  # noqa: E402
from agent_evidence_vectors.record_paths import (  # noqa: E402
    LocalPathError,
    find_local_path,
    portable_argv,
    portable_command,
    refuse_local_paths,
    relativize,
    write_records,
)

S = "/"
REFUSED = [
    S + "home" + S + "someone" + S + "work",
    S + "Users" + S + "someone" + S + "x",
    "C:" + "\\" + "Users" + "\\" + "someone",
    "~" + S + "Documents",
    S + "mnt" + S + "data",
    S + "blue" + S + "group" + S + "u",
    S + "root" + S + ".cache",
]
SCRATCH = S + "tmp" + S + "run-1"


@pytest.mark.parametrize("path", REFUSED)
def test_every_local_root_is_refused(path: str) -> None:
    assert find_local_path(f"run at {path} done") is not None
    with pytest.raises(LocalPathError, match="absolute local path"):
        refuse_local_paths("report.json", {"note": path})


def test_a_path_inside_a_nested_value_is_refused() -> None:
    with pytest.raises(LocalPathError):
        refuse_local_paths("r.json", {"a": [{"b": REFUSED[0]}]})


@pytest.mark.parametrize(
    "text",
    [
        "packaging/agent_evidence_vectors/run.py",
        "../.build/result",
        "https://example.invalid/home/page",
        "see the foo/tmp/bar file",
        "a~/b",
        "version 1.0 on Linux",
    ],
)
def test_repo_relative_paths_and_urls_are_allowed(text: str) -> None:
    assert find_local_path(text) is None
    refuse_local_paths("r.json", {"note": text})


def test_a_hosted_runner_home_is_allowed_and_a_person_home_is_not() -> None:
    assert find_local_path(S + "home" + S + "runner" + S + "work") is None
    gate = S + "home" + S + "gate" + S + "work"
    assert find_local_path(gate) is not None
    assert find_local_path(gate, ci_homes=("runner", "gate")) is None


def test_scratch_is_allowed_only_in_a_declared_reproduction_field() -> None:
    refuse_local_paths("r.json", {"command": f"python run.py --output {SCRATCH}"})
    with pytest.raises(LocalPathError):
        refuse_local_paths("r.json", {"note": SCRATCH})
    refuse_local_paths("r.json", {"verifier": ["python", SCRATCH + "/verify.py"]})
    with pytest.raises(LocalPathError):
        refuse_local_paths("r.json", {"command": REFUSED[0]})
    with pytest.raises(LocalPathError):
        refuse_local_paths("r.json", {"verifier": [REFUSED[0]]})


def test_relativize_rewrites_under_the_root_and_refuses_outside(tmp_path: Path) -> None:
    assert relativize(tmp_path / "a" / "b.json", tmp_path) == "a/b.json"
    with pytest.raises(LocalPathError, match="no repo-relative form"):
        relativize(tmp_path.parent / "elsewhere", tmp_path)


def test_portable_command_names_the_environment_and_drops_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "prefix", "/opt/env")
    monkeypatch.setattr(sys, "executable", "/opt/env/bin/python")
    monkeypatch.setattr(sys, "argv", [str(tmp_path / "pkg" / "run.py"), "--output", "result"])
    assert portable_command() == "<env>/bin/python pkg/run.py --output result"
    assert find_local_path(portable_command(), allow_scratch=True) is None


def test_a_refused_record_writes_nothing(tmp_path: Path) -> None:
    out = tmp_path / "result"
    with pytest.raises(LocalPathError):
        write_records(out, {"ok.json": {"a": 1}, "bad.json": {"p": REFUSED[0]}})
    assert not out.exists()


def test_a_clean_record_is_written_and_an_existing_output_is_refused(tmp_path: Path) -> None:
    out = tmp_path / "result"
    write_records(out, {"report.json": {"b": 2, "a": 1}})
    assert json.loads((out / "report.json").read_text()) == {"a": 1, "b": 2}
    with pytest.raises(FileExistsError):
        write_records(out, {"report.json": {}})


# The corpus scan: a record already committed, or a new writer that bypasses
# write_records, goes red here. Adversarial inputs under cases/ name roots on purpose.
RECORD_SUFFIXES = (".json", ".jsonl", ".log", ".txt", ".stderr", ".stdout", ".xml")


def _tracked_records() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    ).stdout.decode()
    return [
        ROOT / name
        for name in out.split("\0")
        if name.endswith(RECORD_SUFFIXES)
        and "/cases/" not in name
    ]


def test_the_scan_sees_the_published_records() -> None:
    names = {p.relative_to(ROOT).as_posix() for p in _tracked_records()}
    assert "packaging/conformance-report.json" in names
    assert len(names) > 100


def test_no_committed_record_carries_an_absolute_local_path() -> None:
    leaks = []
    for path in _tracked_records():
        text = path.read_text(encoding="utf-8", errors="replace")
        found = find_local_path(text, allow_scratch=True)
        if found is not None:
            leaks.append(f"{path.relative_to(ROOT)}: {found!r}")
    assert not leaks, "\n".join(leaks)


def test_every_run_record_writer_goes_through_the_shared_function() -> None:
    writers = sorted((ROOT / "packaging" / "agent_evidence_vectors").glob("*/run.py"))
    assert writers
    bypass = [
        w.relative_to(ROOT).as_posix()
        for w in writers
        if "write_records" not in w.read_text(encoding="utf-8")
    ]
    assert not bypass, f"run writers that skip record_paths.write_records: {bypass}"
    assert record_paths.write_records is write_records


def test_portable_argv_names_the_environment_and_drops_the_working_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "prefix", "/opt/env")
    monkeypatch.setattr(sys, "executable", "/opt/env/bin/python")
    got = portable_argv(["/opt/env/bin/python3", str(tmp_path / "v" / "check.py")])
    assert got == ["<env>/bin/python3", "v/check.py"]


def test_a_temp_dir_under_a_home_is_scratch_not_a_person(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A box keeps each job's temporary directory under the account's home, so pytest's
    # tmp_path looks like a home path. It is scratch exactly as the shared temp dir is.
    scratch_root = S + "home" + S + "gate" + S + "work" + S + ".t" + S + "job"
    monkeypatch.setenv("TMPDIR", scratch_root)
    monkeypatch.setattr(record_paths.tempfile, "gettempdir", lambda: scratch_root)
    inside = scratch_root + S + "pytest-of-gate" + S + "pytest-0" + S + "absent"
    refuse_local_paths("r.json", {"verifier": inside})
    refuse_local_paths("r.json", {"command": f"run --verifier {inside}"})
    assert find_local_path(inside, allow_scratch=True) is None


def test_a_temp_dir_path_outside_a_reproduction_field_is_still_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch_root = S + "home" + S + "gate" + S + "work" + S + ".t" + S + "job"
    monkeypatch.setenv("TMPDIR", scratch_root)
    monkeypatch.setattr(record_paths.tempfile, "gettempdir", lambda: scratch_root)
    with pytest.raises(LocalPathError):
        refuse_local_paths("r.json", {"note": scratch_root + S + "x"})


def test_only_the_temp_dir_is_scratch_not_the_rest_of_the_home(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scratch_root = S + "home" + S + "gate" + S + "work" + S + ".t" + S + "job"
    monkeypatch.setenv("TMPDIR", scratch_root)
    monkeypatch.setattr(record_paths.tempfile, "gettempdir", lambda: scratch_root)
    other = S + "home" + S + "gate" + S + "work" + S + "repo" + S + "file"
    assert find_local_path(other, allow_scratch=True) is not None
    with pytest.raises(LocalPathError):
        refuse_local_paths("r.json", {"command": other})
    # A sibling whose name only starts like the temp dir is not inside it.
    assert find_local_path(scratch_root + "-more" + S + "x", allow_scratch=True) is not None


@pytest.mark.parametrize("home", [S + "home" + S + "someone", S + "Users" + S + "someone"])
def test_a_temp_dir_that_is_a_home_directory_makes_nothing_scratch(
    home: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TMPDIR", home)
    monkeypatch.setattr(record_paths.tempfile, "gettempdir", lambda: home)
    assert find_local_path(home + S + "Documents" + S + "x", allow_scratch=True) is not None
