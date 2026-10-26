"""The secret-scan job reads the history of the commit under test, not of every branch.

The checkout fetches every branch and gitleaks scans all of them by default, so one
open branch holding a finding failed the job on main and on every other branch. These
tests run the scan command the workflow declares against a scratch repository in
which only a side branch holds a credential shape.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "secret-scan.yml"
GITLEAKS = os.environ.get("GITLEAKS") or shutil.which("gitleaks") or ""
GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=GIT_ENV)


def _scan_argv() -> list[str]:
    lines = [
        ln.strip()
        for ln in WORKFLOW.read_text().splitlines()
        if ln.strip().startswith("run: ./gitleaks git")
    ]
    assert len(lines) == 1, "the workflow must declare exactly one gitleaks scan"
    argv = shlex.split(lines[0].removeprefix("run: "))
    argv[0] = GITLEAKS
    return argv


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    assert GITLEAKS, "gitleaks is required: set GITLEAKS or put it on PATH"
    work = tmp_path / "repo"
    work.mkdir()
    _git(work, "init", "-q", "-b", "main")
    shutil.copy(ROOT / ".gitleaks.toml", work / ".gitleaks.toml")
    (work / "README.md").write_text("clean\n")
    _git(work, "add", ".")
    _git(work, "commit", "-q", "-m", "clean main")
    _git(work, "switch", "-q", "-c", "side")
    (work / "leak.txt").write_text("token = " + "ghp_" + "a1B2c3D4e5F6g7H8i9J0" * 2 + "\n")
    _git(work, "add", ".")
    _git(work, "commit", "-q", "-m", "side branch holds a credential shape")
    _git(work, "switch", "-q", "main")
    return work


def _run(argv: list[str], cwd: Path) -> int:
    return subprocess.run(argv, cwd=cwd, capture_output=True, check=False).returncode


def test_the_default_scan_would_read_the_side_branch(repo: Path) -> None:
    # The premise: without the flag the finding on the side branch fails a scan of main.
    argv = [a for a in _scan_argv() if not a.startswith("--log-opts")]
    assert _run(argv, repo) == 1


def test_the_declared_scan_ignores_a_finding_on_another_branch(repo: Path) -> None:
    assert _run(_scan_argv(), repo) == 0


def test_the_declared_scan_still_fails_on_a_finding_in_its_own_history(repo: Path) -> None:
    _git(repo, "merge", "-q", "--no-ff", "-m", "merge side", "side")
    assert _run(_scan_argv(), repo) == 1
