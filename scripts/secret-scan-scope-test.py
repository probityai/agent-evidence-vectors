"""The secret-scan job reads the history of the commit under test, not of every branch.

The checkout fetches every branch and gitleaks scans all of them by default, so one
open branch holding a finding failed the job on main and on every other branch. These
tests run scripts/secret-scan.sh, the command the workflow and the pre-push hook share,
against a scratch repository in which only a side branch holds a credential shape.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GIT_ENV = {
    **os.environ,
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
}


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=GIT_ENV)


SCAN = ROOT / "scripts" / "secret-scan.sh"


def _scan_argv(repo: Path, *extra: str) -> list[str]:
    config = str(repo / ".gitleaks.toml")
    return ["bash", str(SCAN), "--repo", str(repo), "--config", config, *extra]


@pytest.fixture
def repo(tmp_path: Path) -> Path:
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
    # The premise: scanning every ref, gitleaks' own default, fails on the side branch.
    assert _run(_scan_argv(repo, "--range", "--all"), repo) == 1


def test_the_declared_scan_ignores_a_finding_on_another_branch(repo: Path) -> None:
    assert _run(_scan_argv(repo), repo) == 0


def test_the_declared_scan_still_fails_on_a_finding_in_its_own_history(repo: Path) -> None:
    _git(repo, "merge", "-q", "--no-ff", "-m", "merge side", "side")
    assert _run(_scan_argv(repo), repo) == 1
