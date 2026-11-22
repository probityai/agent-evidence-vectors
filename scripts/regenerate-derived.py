#!/usr/bin/env python3
"""Regenerate every file this repository derives, and resolve a merge over them.

Four generators write files that pull requests never edit by hand: the
jcsvectors package copies of the RFC 8785 corpora (scripts/gen-jcsvectors-data.py),
the signed digest list (scripts/release-digests.py), the intake records under
release/intake/ (scripts/gen-intake-records.py) and the shared-source lock
(interop/agentavow-signed-map-v1/lock_sources.py). Each pins bytes of code or
corpora that many pull requests change, so two open pull requests that each
changed anything shared disagreed on every one of those files, and each merge
meant a hand resolution of dozens of generated records.

The files are marked with the `derived` attribute in .gitattributes. Their
content is a function of the rest of the tree, so a merge conflict in one is
never a real disagreement. This script is the one place that knows that:

  uv run --locked --extra generators python scripts/regenerate-derived.py
      rewrite every derived file from the tree
  uv run --locked --extra generators python scripts/regenerate-derived.py --check
      refuse when any derived file differs from what a run writes now
  uv run --locked --extra generators python scripts/regenerate-derived.py --resolve-merge
      after `git merge origin/main` stops on conflicts: when every conflicted
      path carries the `derived` attribute, take one side of each, regenerate,
      and stage the result. A conflict in any other path is refused untouched.

Exit 0 when done (or current under --check); 1 on a refusal or a stale file.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: (name, script). Order matters: the intake records name the signed digest
#: list, so the list is written first. The jcsvectors copies come before both,
#: so any generator that reads a package file reads the refreshed one.
STEPS: list[tuple[str, str]] = [
    ("jcsvectors copies", "scripts/gen-jcsvectors-data.py"),
    ("digest list", "scripts/release-digests.py"),
    ("intake records", "scripts/gen-intake-records.py"),
    ("shared-source lock", "interop/agentavow-signed-map-v1/lock_sources.py"),
]


def run_steps(repo: Path, check: bool, steps: list[tuple[str, str]] = STEPS) -> int:
    """Run every generator, or every generator's check.

    A write stops at the first failure, because a later generator reads what an
    earlier one wrote. A check runs every step and names each stale one: a stale
    intake record used to stop the check before the shared-source lock was read,
    so one CI run reported one stale family and the next run found another.
    """
    failed = []
    for name, script in steps:
        command = [sys.executable, str(repo / script)] + (["--check"] if check else [])
        print(f"== {name}: {script}{' --check' if check else ''}", flush=True)
        if subprocess.run(command, cwd=repo).returncode != 0:
            print(f"FAIL: {name}", file=sys.stderr)
            if not check:
                return 1
            failed.append(name)
    if failed:
        print(f"FAIL: {len(failed)} of {len(steps)} derived families are stale: "
              f"{', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


def git(repo: Path, *args: str) -> str:
    done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)
    if done.returncode != 0:
        raise SystemExit(f"FAIL: git {' '.join(args)}: {done.stderr.strip()}")
    return done.stdout


def unmerged(repo: Path) -> list[str]:
    return [p for p in git(repo, "diff", "--name-only", "--diff-filter=U").split("\n") if p]


def is_derived(repo: Path, path: str) -> bool:
    return git(repo, "check-attr", "derived", "--", path).strip().endswith(": derived: set")


def resolve_merge(repo: Path, regenerate: Callable[[], int]) -> int:
    """Settle a conflicted merge whose conflicts are all in derived files."""
    conflicted = unmerged(repo)
    if not conflicted:
        print("no conflicted paths; nothing to resolve")
        return 0
    foreign = [p for p in conflicted if not is_derived(repo, p)]
    if foreign:
        print("FAIL: these conflicts are not in derived files and need a hand merge; "
              "nothing was changed:\n  " + "\n  ".join(foreign), file=sys.stderr)
        return 1
    for path in conflicted:
        git(repo, "checkout", "--theirs", "--", path)
        git(repo, "add", "--", path)
    if regenerate() != 0:
        return 1
    touched = git(repo, "diff", "--name-only").split("\n")
    touched += git(repo, "ls-files", "--others", "--exclude-standard").split("\n")
    for path in sorted({p for p in touched if p and is_derived(repo, p)}):
        git(repo, "add", "--", path)
    print(f"resolved {len(conflicted)} derived paths by regenerating them; "
          "review `git status`, then commit the merge")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--resolve-merge", action="store_true")
    args = parser.parse_args()
    if args.resolve_merge:
        return resolve_merge(REPO, lambda: run_steps(REPO, False))
    return run_steps(REPO, args.check)


if __name__ == "__main__":
    raise SystemExit(main())
