#!/usr/bin/env python3
"""Tests for scripts/suite-commit-gate.py.

Every case runs against a throwaway pair of repositories built here: an origin
with a default branch, a side branch and a tag on a commit the default branch
does not reach, and a full clone of it. Reachability is a property of refs, so
a fixture that was not a real clone would prove nothing about the one question
the gate asks.

The case that matters most is the dangling commit. It is written into the
clone's object store with ``git commit-tree`` and no ref points at it, which is
exactly the state an old pinned commit is in after a history rewrite: the object
answers ``git cat-file``, the GitHub API still serves it, and ``git clone`` does
not carry it. A gate that asked "does the object exist" would pass it.

That is also why the suite ends by running MUTANTS of the gate: copies with one
guard removed. Each mutant must fail at least one case here. A mutant that
passes every case means the guard it removed is tested by nothing, and the
suite says so rather than reporting green.

Usage: python3 scripts/suite-commit-gate-test.py
Exit 0 when every case holds and every mutant is killed; 1 otherwise.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "suite-commit-gate.py"

ENV = dict(
    os.environ,
    GIT_CONFIG_GLOBAL=os.devnull,
    GIT_CONFIG_NOSYSTEM="1",
    GIT_AUTHOR_NAME="t",
    GIT_AUTHOR_EMAIL="t@example.invalid",
    GIT_COMMITTER_NAME="t",
    GIT_COMMITTER_EMAIL="t@example.invalid",
)


def git(repo: Path, *args: str) -> str:
    done = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, env=ENV, check=True
    )
    return done.stdout.strip()


def commit(repo: Path, name: str) -> str:
    (repo / name).write_text(name, encoding="utf-8")
    git(repo, "add", name)
    git(repo, "commit", "-q", "-m", f"add {name}")
    return git(repo, "rev-parse", "HEAD")


class World:
    """An origin and a full clone of it, with every kind of commit a case needs."""

    def __init__(self, tmp: Path) -> None:
        origin = tmp / "origin"
        origin.mkdir()
        git(origin, "init", "-q", "-b", "main")
        self.first = commit(origin, "a")
        self.head = commit(origin, "b")
        git(origin, "checkout", "-q", "-b", "side")
        self.side = commit(origin, "s")
        git(origin, "checkout", "-q", "-b", "gone", "main")
        self.tagged = commit(origin, "t")
        git(origin, "tag", "-a", "cited/tagged", "-m", "held", self.tagged)
        git(origin, "checkout", "-q", "main")
        git(origin, "branch", "-q", "-D", "gone")
        self.origin = origin
        self.clone = tmp / "clone"
        subprocess.run(
            ["git", "clone", "-q", str(origin), str(self.clone)], env=ENV, check=True
        )
        tree = git(self.clone, "rev-parse", "HEAD^{tree}")
        self.dangling = git(self.clone, "commit-tree", tree, "-p", self.head, "-m", "orphan")

    def write(self, repo: Path, ledger: list[str], rows: list[dict[str, object]]) -> None:
        (repo / "docs").mkdir(exist_ok=True)
        runs = [{"suiteCommit": c} for c in ledger]
        (repo / "docs" / "INDEPENDENT-RUNS.json").write_text(
            json.dumps({"runs": runs, "attempts": [{"suiteCommit": None}]}), encoding="utf-8"
        )
        (repo / "docs" / "REWRITE-MAP-2026-09-18.json").write_text(
            json.dumps({"commits": rows}), encoding="utf-8"
        )


Setup = Callable[[World, Path], Path]
# name, how to build the repository under test, expected exit, words the output must carry
Case = tuple[str, Setup, int, str]


Rows = Callable[[World], list[dict[str, object]]]


def ledger(commits: Callable[[World], list[str]], rows: Rows) -> Setup:
    def setup(world: World, _tmp: Path) -> Path:
        world.write(world.clone, commits(world), rows(world))
        return world.clone

    return setup


def shallow(world: World, tmp: Path) -> Path:
    repo = tmp / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", f"file://{world.origin}", str(repo)],
        env=ENV, check=True,
    )
    world.write(repo, [world.first], [])
    return repo


def no_default_ref(world: World, _tmp: Path) -> Path:
    world.write(world.clone, [world.head], [])
    git(world.clone, "update-ref", "-d", "refs/remotes/origin/main")
    return world.clone


def no_ledger(world: World, _tmp: Path) -> Path:
    world.write(world.clone, [world.head], [])
    (world.clone / "docs" / "INDEPENDENT-RUNS.json").unlink()
    return world.clone


def tag_row(tag: str, target: Callable[[World], str]) -> Rows:
    return lambda w: [{"rewritten": target(w), "tag": tag}]


def NO_ROWS(_world: World) -> list[dict[str, object]]:
    return []


CASES: list[Case] = [
    ("the default branch, a short ID and a cited tag",
     ledger(lambda w: [w.head, w.first[:7]], tag_row("cited/tagged", lambda w: w.tagged)),
     0, "each reachable"),
    ("a commit that exists as an object and that no ref reaches",
     ledger(lambda w: [w.dangling], NO_ROWS), 1, "a fresh clone does not carry it"),
    ("a commit only a side branch reaches",
     ledger(lambda w: [w.side], NO_ROWS), 1, "neither the default branch nor any tag"),
    ("a commit that is not in the clone at all",
     ledger(lambda w: ["59faf842098183ae7b5387ad13e6351c44687279"], NO_ROWS),
     1, "translates it"),
    ("a value that is not a commit ID",
     ledger(lambda w: ["59faf84Z"], NO_ROWS), 1, "is not a commit ID"),
    ("a map row whose tag points at another commit",
     ledger(lambda w: [], tag_row("cited/tagged", lambda w: w.head)), 1, "points at"),
    ("a map row whose tag does not exist",
     ledger(lambda w: [], tag_row("cited/absent", lambda w: w.head)), 1, "does not exist"),
    ("a shallow clone", shallow, 2, "shallow"),
    ("a clone without the default branch's ref", no_default_ref, 2, "does not resolve"),
    ("a clone without the run ledger", no_ledger, 2, "is missing"),
]

# Each mutant removes one guard. The replaced text must occur exactly once in
# the gate, or the mutant is not the mutant it says it is.
MUTANTS = [
    ("reachability is not checked, only existence",
     "    if not reachable(repo, full):\n", "    if False:\n"),
    ("a shallow clone is walked anyway",
     '    if shallow.stdout.strip() != "false":\n', "    if False:\n"),
    ("any branch counts as holding the commit",
     '"--format=%(refname)", DEFAULT_REF, "refs/tags",', '"--format=%(refname)", "refs/",'),
]


def run_case(gate: Path, case: Case) -> str | None:
    name, setup, want, words = case
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        repo = setup(World(tmp), tmp)
        done = subprocess.run(
            [sys.executable, str(gate), "--repo", str(repo)],
            capture_output=True, text=True, env=ENV,
        )
    output = done.stdout + done.stderr
    if done.returncode != want:
        return f"{name}: exit {done.returncode}, wanted {want}\n{output}"
    if words not in output:
        return f"{name}: exit {want} as wanted, but the output does not say {words!r}\n{output}"
    return None


def surviving_mutants() -> list[str]:
    source = GATE.read_text(encoding="utf-8")
    survivors = []
    for label, old, new in MUTANTS:
        if source.count(old) != 1:
            survivors.append(f"{label}: the text it replaces occurs {source.count(old)} times")
            continue
        with tempfile.TemporaryDirectory() as raw:
            mutant = Path(raw) / "suite-commit-gate.py"
            mutant.write_text(source.replace(old, new), encoding="utf-8")
            if all(run_case(mutant, case) is None for case in CASES):
                survivors.append(f"{label}: every case still passes")
    return survivors


def main() -> int:
    failures = [f for case in CASES for f in [run_case(GATE, case)] if f]
    if failures:
        print("\n\n".join(failures), file=sys.stderr)
        return 1
    survivors = surviving_mutants()
    if survivors:
        print("mutants the cases do not kill:\n" + "\n".join(survivors), file=sys.stderr)
        return 1
    print(f"OK: {len(CASES)} cases hold and all {len(MUTANTS)} mutants of the gate are killed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
