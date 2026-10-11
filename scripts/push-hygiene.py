#!/usr/bin/env python3
"""Refuse a push GitHub would refuse, or one that carries unresolved merge conflicts.

Two checks, both cheap enough for the local push gate:

1. **Blob size.** GitHub rejects any push containing a blob of 100 MiB or more,
   and it does so at transport, after the whole gate has run. Every blob reachable
   from HEAD's tree is checked, and so is every blob introduced by the commits not
   yet on ``origin/main`` -- a large file added and deleted inside the push range is
   still in the pack and is still refused. When ``origin/main`` is not present the
   range half cannot run, and the output says so rather than reading as clean.

2. **Conflict markers.** A line starting ``<<<<<<< `` or ``>>>>>>> `` in a tracked
   file is an unresolved merge.

Usage: push-hygiene.py [--rev SHA] [--base REF]. The pre-push hook passes the
pushed revision and the remote's previous value for that ref; by hand the
defaults are HEAD and origin/main.

Exit 0 clean, 1 a finding, 2 the check could not run.
"""

from __future__ import annotations

import argparse
import subprocess
import sys

LIMIT = 100 * 1024 * 1024
MARKER = r"^(<<<<<<< |>>>>>>> )"
EXCLUDE: tuple[str, ...] = ()


def git(*args: str, stdin: str | None = None) -> str:
    """Run git and return stdout; a failure raises, never reads as empty."""
    return subprocess.run(
        ["git", *args], input=stdin, capture_output=True, text=True, check=True
    ).stdout


def big_blobs(revs: list[str], limit: int) -> list[tuple[str, int, str]]:
    """Blobs of LIMIT bytes or more among the objects these rev-list args reach."""
    listing = git("rev-list", "--objects", *revs)
    paths: dict[str, str] = {}
    for line in listing.splitlines():
        oid, _, path = line.partition(" ")
        paths[oid] = path
    if not paths:
        return []
    out = git(
        "cat-file",
        "--batch-check=%(objectname) %(objecttype) %(objectsize)",
        stdin="\n".join(paths) + "\n",
    )
    found = []
    for line in out.splitlines():
        oid, kind, size = line.split()
        if kind == "blob" and int(size) >= limit:
            found.append((oid, int(size), paths[oid]))
    return found


def has_ref(ref: str) -> bool:
    return (
        subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", ref], capture_output=True
        ).returncode
        == 0
    )


def conflict_markers(rev: str) -> list[str]:
    proc = subprocess.run(
        ["git", "grep", "-nI", "-E", MARKER, rev, "--", ".", *EXCLUDE],
        capture_output=True,
        text=True,
    )
    if proc.returncode == 1:
        return []
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, "git grep", proc.stderr)
    return proc.stdout.splitlines()


def main(argv: list[str] | None = None, limit: int = LIMIT) -> int:
    ap = argparse.ArgumentParser(
        description="Refuse a push GitHub would refuse, or one with merge conflicts."
    )
    ap.add_argument("--rev", default="HEAD")
    ap.add_argument("--base", default="origin/main")
    args = ap.parse_args(argv)
    try:
        tree = big_blobs(["--no-walk", args.rev], limit)
        ranged = has_ref(args.base)
        rng = big_blobs([args.rev, "--not", args.base], limit) if ranged else []
        markers = conflict_markers(args.rev)
    except (subprocess.CalledProcessError, OSError) as exc:
        print(f"push-hygiene: REFUSED, the check could not run: {exc}", file=sys.stderr)
        return 2
    findings = {(oid, size, path) for oid, size, path in tree + rng}
    for oid, size, path in sorted(findings, key=lambda f: f[2]):
        print(
            f"  {path}: blob {oid[:12]} is {size / 1048576:.1f} MiB; GitHub refuses 100 MiB or more"
        )
    for line in markers:
        print(f"  unresolved merge conflict marker: {line}")
    scope = (
        f"{args.rev}'s tree and the commits not on {args.base}"
        if ranged
        else (
            f"{args.rev}'s tree only ({args.base} is absent here, "
            "so the push range was NOT checked)"
        )
    )
    if findings or markers:
        print(
            f"push-hygiene: {len(findings)} oversized blob(s), "
            f"{len(markers)} conflict marker(s) in {scope}."
        )
        return 1
    print(f"push-hygiene: no blob of 100 MiB or more and no conflict marker in {scope}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
