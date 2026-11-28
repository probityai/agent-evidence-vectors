#!/usr/bin/env python3
"""Regenerate every file this repository derives, and resolve a merge over them.

Five generators write files that pull requests never edit by hand: the
jcsvectors package copies of the RFC 8785 corpora (scripts/gen-jcsvectors-data.py),
the signed digest list (scripts/release-digests.py), the intake records under
release/intake/ (scripts/gen-intake-records.py), the shared-source lock
(interop/agentavow-signed-map-v1/lock_sources.py) and the reference coverage
(scripts/reference-coverage.py: N of M per corpus, which every corpus a pull request
adds changes). Each pins bytes of code or corpora that many pull requests change, so
two open pull requests that each changed anything shared disagreed on every one of
those files, and each merge meant a hand resolution of dozens of generated records.

One environment runs every step. The reference coverage step imports the reference
verifier, which the `crosscheck` dependency group holds, so every command runs as
UV = `uv run --locked --extra generators --group crosscheck python`.

The files are marked with the `derived` attribute in .gitattributes. Their
content is a function of the rest of the tree, so a merge conflict in one is
never a real disagreement. This script is the one place that knows that:

  UV scripts/regenerate-derived.py
      rewrite every derived file from the tree
  UV scripts/regenerate-derived.py --check
      refuse when any derived file differs from what a run writes now
  UV scripts/regenerate-derived.py --resolve-merge
      after `git merge origin/main` stops on conflicts: when every conflicted
      path carries the `derived` attribute, take one side of each, regenerate,
      and stage the result. A conflict in any other path is refused untouched.
  UV scripts/regenerate-derived.py --stale-ok origin/main
      the plain pull request's form of --check (scripts/pre-queue.py): pass a
      derived file that is only stale and refuse one no generator run wrote.

STALE OR HAND-MADE. The derived files are committed, and the batch run (the
merge group, after merge-train has regenerated the pull request's head on main)
refuses any that is not what a run writes now, so main is always exact. A plain
pull request goes stale the moment it touches a corpus or a checker, or merges
main, and regenerating there only makes two open pull requests conflict. So
--stale-ok regenerates the committed HEAD in a throwaway worktree and asks, for
each file the run would change, where the committed bytes came from. Walking
back from HEAD through every commit that left the file as it was, the bytes
come from main (exact when they landed there), from a clean git merge of two
parents (each parent's copy is then asked the same question), or from one
commit that wrote them. A generator run on that commit's own tree must leave
the file unchanged; when it does not, nothing in the history explains the bytes
and the file is refused as hand-made. A stale file is printed as a notice.

Exit 0 when done (or current under --check, or stale only under --stale-ok);
1 on a refusal, a stale file under --check, or a hand-made file under --stale-ok.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

#: (name, script). Order matters: the intake records name the signed digest
#: list, so the list is written first. The jcsvectors copies come before both,
#: so any generator that reads a package file reads the refreshed one. The
#: reference coverage is last: it reads the corpora and the reference verifier,
#: and nothing reads it.
STEPS: list[tuple[str, str]] = [
    ("jcsvectors copies", "scripts/gen-jcsvectors-data.py"),
    ("digest list", "scripts/release-digests.py"),
    ("intake records", "scripts/gen-intake-records.py"),
    ("shared-source lock", "interop/agentavow-signed-map-v1/lock_sources.py"),
    ("reference coverage", "scripts/reference-coverage.py"),
]

#: What a failed check tells the person who has to make it pass.
REGENERATE_HINT = (
    "regenerate: uv run --locked --python 3.13 --extra generators --group crosscheck python "
    "scripts/regenerate-derived.py, commit the derived files it changes "
    "(after a conflicted `git merge origin/main`: add --resolve-merge)"
)

#: This script, as a path in any tree of the repository: --stale-ok runs the
#: copy committed in the tree it judges, so each tree is judged by its own steps.
SELF = "scripts/regenerate-derived.py"

#: At most this many commits are regenerated to explain stale files; each run
#: costs a full regeneration (about one minute on a hosted runner).
MAX_WITNESSES = 4

#: A stale-file notice names at most this many paths.
NOTICE_PATHS = 30


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
        print(REGENERATE_HINT, file=sys.stderr)
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


class History:
    """Reads of one repository's history, cached: --stale-ok asks the same few many times."""

    def __init__(self, repo: Path, main: str) -> None:
        self.repo = repo
        self.main = git(repo, "rev-parse", "--verify", main + "^{commit}").strip()
        self._parents: dict[str, list[str]] = {}
        self._changed: dict[tuple[str, str], set[str]] = {}
        self._on_main: dict[str, bool] = {}

    def parents(self, commit: str) -> list[str]:
        if commit not in self._parents:
            self._parents[commit] = git(self.repo, "rev-list", "--parents", "-n", "1",
                                        commit).split()[1:]
        return self._parents[commit]

    def changed(self, parent: str, commit: str) -> set[str]:
        """Every path whose bytes differ between ``parent`` and ``commit``."""
        key = (parent, commit)
        if key not in self._changed:
            out = git(self.repo, "diff-tree", "-r", "--no-renames", "--name-only", "-z",
                      parent, commit)
            self._changed[key] = {p for p in out.split("\0") if p}
        return self._changed[key]

    def on_main(self, commit: str) -> bool:
        if commit not in self._on_main:
            done = subprocess.run(["git", "-C", str(self.repo), "merge-base", "--is-ancestor",
                                   commit, self.main], capture_output=True, text=True)
            if done.returncode not in (0, 1):
                raise SystemExit(f"FAIL: git merge-base --is-ancestor {commit}: "
                                 f"{done.stderr.strip()}")
            self._on_main[commit] = done.returncode == 0
        return self._on_main[commit]

    def blob(self, rev: str, path: str) -> str | None:
        """The blob id of ``path`` at ``rev``; None when the tree does not hold it."""
        out = git(self.repo, "ls-tree", "-z", rev, "--", path)
        entries = [e for e in out.split("\0") if e]
        return entries[0].split("\t", 1)[0].split()[2] if entries else None

    def auto_merged(self, commit: str, path: str) -> bool:
        """True when git's own merge of the commit's two parents writes ``path`` as committed."""
        first, second = self.parents(commit)
        done = subprocess.run(["git", "-C", str(self.repo), "merge-tree", "--write-tree",
                               "--name-only", "--no-messages", first, second],
                              capture_output=True, text=True)
        if done.returncode not in (0, 1):
            raise SystemExit(f"FAIL: git merge-tree {first} {second}: {done.stderr.strip()}")
        lines = done.stdout.split("\n")
        if path in lines[1:]:
            return False
        return self.blob(lines[0], path) == self.blob(commit, path)

    def writers(self, path: str, start: str) -> set[str]:
        """The commits whose own tree must regenerate ``path`` as it stands at ``start``.

        Empty when the bytes are main's, or git's clean merge of copies that are.
        """
        need: set[str] = set()
        todo, seen = [start], set()
        while todo:
            commit = todo.pop()
            while commit not in seen:
                seen.add(commit)
                if self.on_main(commit):
                    break
                parents = self.parents(commit)
                same = [p for p in parents if path not in self.changed(p, commit)]
                if same:
                    commit = same[0]
                    continue
                if len(parents) == 2 and self.auto_merged(commit, path):
                    todo.extend(parents)
                else:
                    need.add(commit)
                break
        return need


def regenerated(repo: Path, rev: str) -> tuple[list[str], list[str]]:
    """Run ``rev``'s own regeneration on a throwaway checkout of ``rev``.

    Returns (derived paths the run changed, other paths it changed). The
    checkout is full even when ``repo`` is sparse, and is removed afterwards.
    Raises SystemExit when the run itself fails: a failed run explains nothing.
    """
    tmp = Path(tempfile.mkdtemp(prefix="regen-"))
    tree = tmp / "tree"
    try:
        git(repo, "worktree", "add", "--detach", "--no-checkout", str(tree), rev)
        git(tree, "-c", "core.sparseCheckout=false", "reset", "-q", "--hard", rev)
        script = tree / SELF
        if not script.is_file():
            raise SystemExit(f"FAIL: {rev[:12]} has no {SELF} to regenerate with")
        print(f"== regenerating {rev[:12]} in a throwaway checkout", flush=True)
        if subprocess.run([sys.executable, str(script)], cwd=tree).returncode != 0:
            raise SystemExit(f"FAIL: regenerating {rev[:12]} failed")
        out = git(tree, "-c", "core.sparseCheckout=false", "status", "--porcelain=v1", "-z",
                  "--untracked-files=all")
        paths = sorted({e[3:] for e in out.split("\0") if len(e) > 3})
        derived = [p for p in paths if is_derived(tree, p)]
        return derived, [p for p in paths if p not in derived]
    finally:
        subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(tree)],
                       capture_output=True)
        shutil.rmtree(tmp, ignore_errors=True)


def stale_ok(repo: Path, main: str) -> int:
    """Pass a derived file that is only stale; refuse one no generator run wrote."""
    history = History(repo, main)
    head = git(repo, "rev-parse", "--verify", "HEAD^{commit}").strip()
    stale, foreign = regenerated(repo, head)
    if foreign:
        print("FAIL: regenerating HEAD changed files without the `derived` attribute; "
              "mark them in .gitattributes or stop the generator writing them:\n  "
              + "\n  ".join(foreign), file=sys.stderr)
        return 1
    if not stale:
        print("derived files: every one is what a run writes now")
        return 0
    witnesses: dict[str, list[str]] = {}
    for path in stale:
        for commit in history.writers(path, head):
            witnesses.setdefault(commit, []).append(path)
    if len(witnesses) > MAX_WITNESSES:
        print(f"FAIL: {len(witnesses)} commits wrote stale derived files by themselves, more "
              f"than the {MAX_WITNESSES} this check regenerates; {REGENERATE_HINT}",
              file=sys.stderr)
        return 1
    handmade: list[tuple[str, str]] = []
    for commit, paths in sorted(witnesses.items()):
        rewritten, _ = regenerated(repo, commit)
        handmade += [(path, commit) for path in paths if path in rewritten]
    for path, commit in handmade:
        print(f"::error file={path}::{path} was written by {commit[:12]}, and a generator run on "
              f"that commit's own tree writes it differently: a hand edit or a hand-resolved "
              f"merge, not a stale copy")
    if handmade:
        print(f"FAIL: {len(handmade)} derived files are hand-made; {REGENERATE_HINT}",
              file=sys.stderr)
        return 1
    shown = ", ".join(stale[:NOTICE_PATHS]) + (
        f" and {len(stale) - NOTICE_PATHS} more" if len(stale) > NOTICE_PATHS else "")
    print(f"::notice title=derived files are stale, not hand-made::{len(stale)} derived files "
          f"are not what a run writes now, and each came from main, a clean merge, or a "
          f"generator run. The batch run regenerates them before the merge queue, and the "
          f"merge group refuses any still stale: {shown}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--resolve-merge", action="store_true")
    mode.add_argument("--stale-ok", metavar="MAIN", default=None)
    args = parser.parse_args()
    if args.resolve_merge:
        return resolve_merge(REPO, lambda: run_steps(REPO, False))
    if args.stale_ok is not None:
        return stale_ok(REPO, args.stale_ok)
    return run_steps(REPO, args.check)


if __name__ == "__main__":
    raise SystemExit(main())
