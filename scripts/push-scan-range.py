#!/usr/bin/env python3
"""Resolve the revision range a push-range identity scan must cover.

The scan beside this one reads every commit a push carries. Which commits those
are is not a question the scanner can answer: it depends on what the remote held
before the push, and only the event knows that. So this decides the range, and it
exists as its own file because the decision had a defect that a shell fragment
inside a workflow could not be tested for.

The defect: a branch creation reports the all-zero before-sha, and the fallback
for that case scanned the last fifty commits reachable from HEAD. Fifty commits of
HEAD is not what the push added -- on a new branch cut from the default branch it
is almost entirely the default branch's own history. Every new branch was
therefore scanned against history it did not introduce, and refused for a defect
already present on the default branch, which only a rewrite of published history
can clear. A sibling repository hit it on 2026-09-20: two hits eleven commits
behind the branch point, in commits the push did not contain.

What the push adds, on a branch creation, is the commits the default branch does
not already have. That is a range, and this resolves it.

The other half of the defect is quieter and is the reason for `count` below. A
range that resolves to no commits makes the scanner print "0 commit(s) scanned,
clean" and exit 0, so a mis-resolved range does not fail -- it passes, having read
nothing. An empty range is therefore never accepted here: it falls back to the
bounded scan, which is a bound and never a pass.

    scripts/push-scan-range.py             # print the scanner's arguments
    scripts/push-scan-range.py --selftest  # prove every arm of the decision

Read from the environment, because that is the shape the event arrives in:

    PR_BASE         base sha of a pull request, when the event is one
    PUSH_BEFORE     sha the remote held before the push; all-zero on creation
    DEFAULT_BRANCH  the repository's default branch name

Exit codes:
    0  the arguments were printed on stdout
    2  could not decide, which is never a pass
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# How many commits the bounded fallback reads when no range can be established.
# It is a bound on the work, never a statement that the range was covered.
BOUNDED_FALLBACK = 50

ZERO_SHA = re.compile(r"^0+$")


def _resolve(rev: str) -> str | None:
    """The commit `rev` names, or None when it names nothing here."""
    done = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}"],
        capture_output=True,
        check=False,
    )
    if done.returncode != 0:
        return None
    return done.stdout.decode().strip() or None


def _count(rev_range: str) -> int:
    """How many commits `rev_range` reaches; -1 when the range cannot be read."""
    done = subprocess.run(
        ["git", "rev-list", "--count", rev_range],
        capture_output=True,
        check=False,
    )
    if done.returncode != 0:
        return -1
    try:
        return int(done.stdout.decode().strip())
    except ValueError:
        return -1


def _default_branch_tip(default_branch: str, resolve) -> str | None:
    """The default branch's tip, tried in the order a CI checkout makes available.

    A checkout action is not obliged to create a remote-tracking ref for a branch
    it did not check out, so the remote-tracking spelling is tried first and the
    others are not assumed away.
    """
    if not default_branch:
        return None
    for spelling in (
        f"refs/remotes/origin/{default_branch}",
        f"origin/{default_branch}",
        f"refs/heads/{default_branch}",
        default_branch,
    ):
        found = resolve(spelling)
        if found:
            return found
    return None


def choose(
    pr_base: str,
    push_before: str,
    default_branch: str,
    resolve=_resolve,
    count=_count,
) -> tuple[list[str], str]:
    """The scanner's arguments, and one line saying why they were chosen.

    `resolve` and `count` are injected so every arm below is provable without a
    repository shaped to order.
    """
    if pr_base and resolve(pr_base):
        return ["--range", f"{pr_base}..HEAD"], "pull request, from its base"

    if push_before and not ZERO_SHA.match(push_before) and resolve(push_before):
        return ["--range", f"{push_before}..HEAD"], "push, from the tip the remote held"

    # A branch creation. What it adds is what the default branch does not have.
    tip = _default_branch_tip(default_branch, resolve)
    if tip:
        rev_range = f"{tip}..HEAD"
        reached = count(rev_range)
        if reached > 0:
            return (
                ["--range", rev_range],
                f"branch creation, the {reached} commit(s) it adds to {default_branch}",
            )
        # Zero means the pushed tip is already contained in the default branch,
        # which is what a push OF the default branch looks like. Scanning nothing
        # would pass, so this falls through to the bound instead.
        if reached == 0:
            return (
                ["--recent", str(BOUNDED_FALLBACK)],
                f"pushed tip adds nothing to {default_branch}; bounded scan, not a pass",
            )

    return (
        ["--recent", str(BOUNDED_FALLBACK)],
        "no range could be established; bounded scan, not a pass",
    )


# --------------------------------------------------------------------------- #
# selftest


def _table_cases() -> int:
    """Every arm of `choose`, driven through injected resolution."""
    real = {"aaa": "aaa", "bbb": "bbb", "refs/remotes/origin/main": "mmm"}

    def resolve(rev):
        return real.get(rev)

    def count_of(n):
        return lambda _range: n

    checks = [
        (
            "a pull request scans from its base",
            choose("aaa", "", "main", resolve, count_of(3))[0],
            ["--range", "aaa..HEAD"],
        ),
        (
            "an ordinary push scans from the previous tip",
            choose("", "bbb", "main", resolve, count_of(3))[0],
            ["--range", "bbb..HEAD"],
        ),
        (
            "a branch creation scans what it adds to the default branch",
            choose("", "0" * 40, "main", resolve, count_of(2))[0],
            ["--range", "mmm..HEAD"],
        ),
        (
            "a branch creation adding nothing falls back to the bound",
            choose("", "0" * 40, "main", resolve, count_of(0))[0],
            ["--recent", str(BOUNDED_FALLBACK)],
        ),
        (
            "an unresolvable default branch falls back to the bound",
            choose("", "0" * 40, "nope", resolve, count_of(2))[0],
            ["--recent", str(BOUNDED_FALLBACK)],
        ),
        (
            "an unreadable range falls back to the bound",
            choose("", "0" * 40, "main", resolve, count_of(-1))[0],
            ["--recent", str(BOUNDED_FALLBACK)],
        ),
        (
            "a before-sha the repository does not hold falls back",
            choose("", "ccc", "nope", resolve, count_of(2))[0],
            ["--recent", str(BOUNDED_FALLBACK)],
        ),
    ]
    bad = 0
    for label, got, want in checks:
        if got != want:
            print(f"selftest: {label}: got {got}, want {want}", file=sys.stderr)
            bad += 1
    return bad


def _git(cwd: Path, *args: str) -> None:
    done = subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=False)
    if done.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {done.stderr.decode().strip()}")


def _end_to_end() -> int:
    """A clean branch passes and a dirty one refuses, over real commits.

    The decision table above proves which range is chosen. This proves the choice
    is the one that matters: with the range scoped to what a branch adds, a clean
    branch cut from a default branch carrying a hit still passes, and a branch
    adding a hit of its own still refuses. Both halves are needed -- the first is
    the defect being fixed, and the second is the control that the fix did not
    stop it looking.

    The offending strings are assembled here rather than written down, for the
    reason every guard in this repository gives: a fixture spelling out what the
    scanner refuses puts that spelling in the repository.
    """
    scanner = Path(__file__).resolve().parent / "pre-push-identity-scan.py"
    sidecar_src = Path(__file__).resolve().parent.parent / ".githooks"
    dossier = "".join(chr(c) for c in (114, 101, 115, 101, 97, 114, 99, 104)) + "/169-x"

    bad = 0
    with tempfile.TemporaryDirectory() as raw:
        root = Path(raw) / "repo"
        (root / ".githooks").mkdir(parents=True)
        # The scanner reads its word sidecar relative to its own location, so the
        # temporary repository gets a copy of the real one.
        for name in ("commit-msg.forbidden-words",):
            src = sidecar_src / name
            if src.is_file():
                (root / ".githooks" / name).write_bytes(src.read_bytes())

        _git(root, "init", "--quiet", "-b", "main")
        _git(root, "config", "user.email", "t@example.invalid")
        _git(root, "config", "user.name", "t")

        # The default branch carries a hit, exactly as the real one does.
        (root / "legacy.txt").write_text(f"# see {dossier}/NOTES.md\n", encoding="utf-8")
        _git(root, "add", "legacy.txt")
        _git(root, "commit", "--quiet", "-m", "seed a default branch with a hit")

        _git(root, "checkout", "--quiet", "-b", "clean-branch")
        (root / "clean.txt").write_text("nothing of note here\n", encoding="utf-8")
        _git(root, "add", "clean.txt")
        _git(root, "commit", "--quiet", "-m", "add a clean file")

        _git(root, "checkout", "--quiet", "-b", "dirty-branch", "main")
        (root / "dirty.txt").write_text(f"# see {dossier}/OTHER.md\n", encoding="utf-8")
        _git(root, "add", "dirty.txt")
        _git(root, "commit", "--quiet", "-m", "add a file with a hit")

        def scan(branch: str, rev_args: list[str]) -> int:
            _git(root, "checkout", "--quiet", branch)
            done = subprocess.run(
                [sys.executable, str(scanner), *rev_args],
                cwd=root,
                capture_output=True,
                check=False,
            )
            return done.returncode

        # The fix: scoped to what the branch adds.
        rc = scan("clean-branch", ["--range", "main..HEAD"])
        if rc != 0:
            print(
                "selftest: a clean branch cut from a dirty default branch must pass "
                f"when scoped to what it adds (got exit {rc})",
                file=sys.stderr,
            )
            bad += 1

        # The control: the scope did not stop it looking.
        rc = scan("dirty-branch", ["--range", "main..HEAD"])
        if rc != 1:
            print(
                "selftest: a branch adding a hit of its own must refuse "
                f"(got exit {rc}, wanted 1)",
                file=sys.stderr,
            )
            bad += 1

        # The defect this file removes, asserted so it cannot come back quietly:
        # the unscoped bound reaches the default branch's hit and refuses a branch
        # that added nothing wrong.
        rc = scan("clean-branch", ["--recent", "50"])
        if rc != 1:
            print(
                "selftest: the unscoped bound was expected to refuse the clean "
                f"branch, which is the defect being fixed (got exit {rc})",
                file=sys.stderr,
            )
            bad += 1

    return bad


def selftest() -> int:
    bad = _table_cases() + _end_to_end()
    if bad:
        print(f"push-scan-range: {bad} selftest failure(s)", file=sys.stderr)
        return 1
    print(
        "push-scan-range: the decision table and the clean/dirty branch pair both hold"
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument(
        "--why",
        action="store_true",
        help="print the reason on stderr alongside the arguments",
    )
    args = parser.parse_args(argv[1:])

    if args.selftest:
        return selftest()

    rev_args, why = choose(
        os.environ.get("PR_BASE", ""),
        os.environ.get("PUSH_BEFORE", ""),
        os.environ.get("DEFAULT_BRANCH", ""),
    )
    if not rev_args:
        print("push-scan-range: could not decide a range", file=sys.stderr)
        return 2
    if args.why:
        print(f"push-scan-range: {why}", file=sys.stderr)
    # One per line. The caller reads these into an array rather than splitting a
    # single line on spaces, so nothing here depends on the shell's field
    # splitting -- which differs between the shell a runner uses and the one a
    # person checking this locally is likely to have.
    for item in rev_args:
        print(item)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
