#!/usr/bin/env python3
"""Tests for scripts/archived-repo-gate.py.

Each case writes one line into a scratch git repository and asserts whether the gate
refuses it, so the gate is seen to go red on a live reference and to stay green on a
record that exists only in the archived repository.

Usage: python3 scripts/archived-repo-gate-test.py
Exit 0 when every case holds; 1 naming each case that does not.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location("archived_repo_gate", HERE / "archived-repo-gate.py")
if _SPEC is None or _SPEC.loader is None:
    raise ImportError("cannot load scripts/archived-repo-gate.py")
gate = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(gate)

OLD = "https://github.com/probityai/agent-evidence"
CASES = [
    # (description, file, line, refused)
    ("a blob link", "README.md", f"[guide]({OLD}/blob/main/README.md)", True),
    ("the bare repository URL", "README.md", f"See {OLD} for more.", True),
    ("an Action ref", "ci.yml", "- uses: probityai/agent-evidence@action-v0.1.0", True),
    ("a clone line", "README.md", f"git clone {OLD}", True),
    ("a transferred issue", "README.md", f"[thread]({OLD}/issues/24)", True),
    ("a transferred issue in short form", "README.md", "see probityai/agent-evidence#24", True),
    (
        "an issue number that only starts like an untransferred one",
        "README.md",
        f"{OLD}/issues/300",
        True,
    ),
    ("a CI run", "README.md", f"[run]({OLD}/actions/runs/40802484844)", False),
    ("a pull request", "README.md", f"[PR]({OLD}/pull/53)", False),
    ("an untransferred issue", "README.md", f"[run]({OLD}/issues/35)", False),
    (
        "an untransferred issue in short form",
        "vocab.yaml",
        "read on probityai/agent-evidence#32 at",
        False,
    ),
    (
        "a workflow that was not imported",
        "gen.py",
        f"{OLD}/blob/main/.github/workflows/site-board.yml",
        False,
    ),
    (
        "the vectors repository",
        "README.md",
        "https://github.com/probityai/agent-evidence-vectors",
        False,
    ),
    ("another agent-evidence name", "README.md", "probityai/agent-evidence-atlas", False),
    ("an allowlisted file", "CHANGELOG.md", f"now points at {OLD}, where", False),
    (
        "a live link beside a CI run",
        "README.md",
        f"{OLD}/actions/runs/1 and {OLD}/blob/main/x",
        True,
    ),
]


def run_case(line: str, name: str) -> list[str]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        (root / name).write_text(line + "\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", name], check=True)
        return list(gate.findings(root, {"CHANGELOG.md"}))


def main() -> int:
    failures = []
    for description, name, line, refused in CASES:
        hits = run_case(line, name)
        if bool(hits) != refused:
            failures.append(
                f"{description}: expected {'a refusal' if refused else 'a pass'}, got {hits}"
            )
    try:
        gate.allowed_paths("some/file.md\n")
        failures.append("an allowlist line with no reason was accepted")
    except ValueError:
        pass
    if not gate.is_allowed("pages/vocab/v1/x/index.html", {"pages/vocab/**"}):
        failures.append("a dir/** pattern did not match a file under it")
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1
    print(f"archived-repo-gate: {len(CASES) + 2} cases hold")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
