#!/usr/bin/env python3
"""Suite-commit gate: a commit an outside record cites must still be in a clone.

An outside implementation's run record binds itself to this corpus by commit
ID, and the record is only worth its ID if a reader can fetch that commit. On
2026-09-18 this repository's history was rewritten, every commit received a new
ID, and every record pinned to an old one named a commit that no clone of this
repository carries. Nothing here noticed. ``docs/INDEPENDENT-RUNS.json`` itself
went on recording the old corpus ID for three hosted dispatches, copied from
the packets that named it, the day after the rewrite.

What a clone carries is decided by refs, not by objects. The GitHub API goes on
serving an unreachable commit until the server collects it, and so does
``actions/checkout``, which asks the server for a SHA directly. Both answer yes
about a commit that ``git clone`` followed by ``git checkout <sha>`` cannot
reach, which is the reproducer's path and the only one that matters here. So
this gate does not ask whether an object exists. It asks whether the default
branch or a tag reaches it. Other branches do not count: a branch can be
deleted or rewritten under a record at any time, and a tag under ``cited/`` is
the durable way to hold a cited commit that is not on the default branch.

It reads two files:

- ``docs/INDEPENDENT-RUNS.json``: every non-null ``suiteCommit``, in runs and
  attempts alike, must name exactly one commit that the default branch or a tag
  reaches.
- ``docs/REWRITE-MAP-2026-09-18.json``: every ``rewritten`` ID must do the same,
  and every ``tag`` a row names must exist and point at that row's rewritten
  commit, so the map cannot promise a tag that is missing or has moved.

Where it cannot answer, it says so and exits 2 rather than 0. A shallow clone
carries no history to walk, and a clone without the default branch's
remote-tracking ref has nothing to measure reachability against; in either
case "every commit resolves" would be a statement about a clone that could see
nothing. The workflow that runs this checks out with full history, which
fetches every branch and every tag.

An outside implementation that records the suite commit of each of its runs can
be checked the same way. ``--index PATH_OR_URL`` (repeatable) reads such a file,
the shape of ``reports/INDEX.json`` in an implementation's repository: a
``records`` list whose rows carry ``suiteCommit`` and, for a record made before
the rewrite, ``suiteCommitBeforeRewrite``. Every non-null ``suiteCommit`` must
pass the same reachability test, and when a row also names its pre-rewrite ID,
the tag ``cited/<first seven characters of that ID>``, if it exists, must point
at the row's ``suiteCommit``, so a cited tag that was moved is refused. An index
that cannot be read or has no ``records`` list is a gate that did not run (exit
2), never an empty pass.

What it does not catch: a commit ID cited somewhere this repository does not
record. The map lists the IDs found in public records when it was written, and
a record found later has to be added to it by hand.

Usage: python3 scripts/suite-commit-gate.py [--repo DIR] [--index PATH_OR_URL]...
Exit 0 when every cited commit is reachable, 1 when one is not, 2 when the
clone cannot answer.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER = Path("docs") / "INDEPENDENT-RUNS.json"
REWRITE_MAP = Path("docs") / "REWRITE-MAP-2026-09-18.json"
DEFAULT_REF = "refs/remotes/origin/main"
HEX = re.compile(r"^[0-9a-f]{7,40}$")


class CannotAnswer(Exception):
    """The clone cannot say what a fresh clone would carry."""


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    # GIT_NO_LAZY_FETCH: a partial clone would otherwise fetch a missing object
    # from the server on demand, and the server still holds the old commits.
    env = dict(os.environ, GIT_NO_LAZY_FETCH="1")
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, env=env
    )


def check_clone(repo: Path) -> None:
    shallow = git(repo, "rev-parse", "--is-shallow-repository")
    if shallow.returncode != 0:
        raise CannotAnswer(f"{repo} is not a git repository: {shallow.stderr.strip()}")
    if shallow.stdout.strip() != "false":
        raise CannotAnswer("the clone is shallow, so reachability cannot be walked")
    if git(repo, "rev-parse", "-q", "--verify", f"{DEFAULT_REF}^{{commit}}").returncode != 0:
        raise CannotAnswer(f"{DEFAULT_REF} does not resolve; fetch the default branch")


def resolve(repo: Path, cited: str) -> str | None:
    if not HEX.match(cited):
        return None
    done = git(repo, "rev-parse", "-q", "--verify", f"{cited}^{{commit}}")
    return done.stdout.strip() if done.returncode == 0 else None


def reachable(repo: Path, commit: str) -> bool:
    done = git(
        repo, "for-each-ref", "--count=1", "--contains", commit,
        "--format=%(refname)", DEFAULT_REF, "refs/tags",
    )
    if done.returncode != 0:
        raise CannotAnswer(f"git for-each-ref failed: {done.stderr.strip()}")
    return bool(done.stdout.strip())


def commit_failure(repo: Path, where: str, cited: Any) -> tuple[str | None, str | None]:
    """Return (full ID, failure). Exactly one of the two is None."""
    if not isinstance(cited, str) or not HEX.match(cited):
        return None, f"{where}: {cited!r} is not a commit ID"
    full = resolve(repo, cited)
    if full is None:
        return None, (
            f"{where}: {cited} does not name exactly one commit in this clone; "
            f"if it is an ID from before the 2026-09-18 rewrite, "
            f"{REWRITE_MAP.as_posix()} translates it"
        )
    if not reachable(repo, full):
        return None, (
            f"{where}: {cited} exists here but neither the default branch nor any "
            f"tag reaches it, so a fresh clone does not carry it; tag it cited/{full[:7]}"
        )
    return full, None


def ledger_commits(ledger: dict[str, Any]) -> list[tuple[str, Any]]:
    out = []
    for group in ("runs", "attempts"):
        for index, row in enumerate(ledger.get(group, [])):
            if row.get("suiteCommit") is not None:
                out.append((f"{LEDGER.as_posix()} {group}[{index}]", row["suiteCommit"]))
    return out


def tag_failure(repo: Path, where: str, tag: str, full: str) -> str | None:
    done = git(repo, "rev-parse", "-q", "--verify", f"refs/tags/{tag}^{{commit}}")
    if done.returncode != 0:
        return f"{where}: tag {tag} does not exist in this clone"
    if done.stdout.strip() != full:
        return f"{where}: tag {tag} points at {done.stdout.strip()}, not {full}"
    return None


def map_failures(repo: Path, rewrite_map: dict[str, Any]) -> tuple[int, list[str]]:
    failures = []
    rows = rewrite_map.get("commits", [])
    for index, row in enumerate(rows):
        where = f"{REWRITE_MAP.as_posix()} commits[{index}]"
        full, failure = commit_failure(repo, where, row.get("rewritten"))
        if failure:
            failures.append(failure)
        elif row.get("tag") is not None and full is not None:
            failures.extend(f for f in [tag_failure(repo, where, row["tag"], full)] if f)
    return len(rows), failures


def load(repo: Path, rel: Path) -> dict[str, Any]:
    path = repo / rel
    if not path.is_file():
        raise CannotAnswer(f"{rel.as_posix()} is missing")
    loaded: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return loaded


def read_index(source: str) -> list[dict[str, Any]]:
    """The rows of an outside implementation's INDEX.json, from a path or a URL."""
    try:
        if "://" in source:
            with urllib.request.urlopen(source, timeout=30) as response:  # noqa: S310
                raw = response.read().decode("utf-8")
        else:
            raw = Path(source).read_text(encoding="utf-8")
        loaded = json.loads(raw)
    except (OSError, ValueError) as why:
        raise CannotAnswer(f"index {source} cannot be read: {why}") from why
    rows = loaded.get("records") if isinstance(loaded, dict) else None
    if not isinstance(rows, list) or not rows:
        raise CannotAnswer(f"index {source} has no records list")
    return [row for row in rows if isinstance(row, dict)]


def index_failures(repo: Path, source: str) -> tuple[int, list[str]]:
    """Failures of every suiteCommit in one index, and how many were checked."""
    failures: list[str] = []
    checked = 0
    for position, row in enumerate(read_index(source)):
        if row.get("suiteCommit") is None:
            continue
        checked += 1
        where = f"{source} records[{position}] ({row.get('file', 'no file name')})"
        full, failure = commit_failure(repo, where, row["suiteCommit"])
        if failure:
            failures.append(failure)
            continue
        old = row.get("suiteCommitBeforeRewrite")
        if full is not None and isinstance(old, str) and HEX.match(old):
            tag = f"cited/{old[:7]}"
            exists = git(repo, "rev-parse", "-q", "--verify", f"refs/tags/{tag}^{{commit}}")
            if exists.returncode == 0 and exists.stdout.strip() != full:
                failures.append(
                    f"{where}: tag {tag} points at {exists.stdout.strip()}, not {full}"
                )
    return checked, failures


def check(repo: Path, indexes: list[str] | None = None) -> int:
    try:
        check_clone(repo)
        ledger = load(repo, LEDGER)
        rewrite_map = load(repo, REWRITE_MAP)
        cited = ledger_commits(ledger)
        failures = [f for where, c in cited for f in [commit_failure(repo, where, c)[1]] if f]
        mapped, more = map_failures(repo, rewrite_map)
        indexed = 0
        index_more: list[str] = []
        for source in indexes or []:
            count, found = index_failures(repo, source)
            indexed += count
            index_more += found
    except CannotAnswer as why:
        print(f"suite-commit gate did not run: {why}", file=sys.stderr)
        return 2
    failures += more + index_more
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(
        f"OK: {len(cited)} suite commit(s) in the run ledger and {mapped} rewritten "
        f"commit(s) in the rewrite map are each reachable from the default branch or a tag."
    )
    if indexes:
        print(f"OK: {indexed} suite commit(s) in {len(indexes)} index file(s) are each reachable.")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Refuse a cited commit that a fresh clone does not carry."
    )
    parser.add_argument("--repo", type=Path, default=REPO_ROOT)
    parser.add_argument(
        "--index", action="append", default=[], metavar="PATH_OR_URL",
        help="an implementation's INDEX.json whose suiteCommit values must be reachable too",
    )
    args = parser.parse_args(argv)
    return check(args.repo, args.index)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
