#!/usr/bin/env python3
"""Refuse a live reference to the archived probityai/agent-evidence repository.

    python3 scripts/archived-repo-gate.py

probityai/agent-evidence was merged into this repository with its history and then
archived. A reader who follows a link, an install line, an Action ref or a clone
command to it lands on a frozen copy, so every live reference points here instead.
This gate reads every tracked text file and fails on a reference to the archived
repository (the name not followed by a hyphen, so agent-evidence-vectors and the
other agent-evidence-* names never match) unless one of two things holds:

- the reference names something that exists only in the archived repository: a CI
  run, a pull request, a commit, or an issue that was not transferred here
  (ARCHIVED_ONLY below). Those are records of what happened there, and repointing
  them would name something this repository does not hold;
- the file is listed in scripts/archived-repo-allowlist.txt with its reason: history
  sentences, records whose bytes are pinned by a digest, and checks that watch the
  archived repository on purpose.

Exit 0 when every reference is accounted for; 1 naming each one that is not.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWLIST = ROOT / "scripts" / "archived-repo-allowlist.txt"
REFERENCE = re.compile(r"probityai/agent-evidence(?![-A-Za-z0-9_])")
# Issues of the archived repository that were closed before the merge and stayed
# there; the open ones moved here under new numbers.
UNTRANSFERRED_ISSUES = (30, 31, 32, 35)
_ISSUES = "|".join(str(n) for n in UNTRANSFERRED_ISSUES)
ARCHIVED_ONLY = re.compile(
    r"github\.com/probityai/agent-evidence/(?:actions/runs/[0-9]+|pull/[0-9]+|commit/[0-9a-f]{7,40}"
    rf"|issues/(?:{_ISSUES})(?![0-9]))"
    rf"|probityai/agent-evidence#(?:{_ISSUES})(?![0-9])"
)


def allowed_paths(text: str) -> set[str]:
    """Return the path patterns of the allowlist; each line is `<glob>  # <reason>`."""
    paths = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        path, sep, reason = line.partition("#")
        if not sep or not reason.strip():
            raise ValueError(f"allowlist line has no reason: {raw!r}")
        paths.add(path.strip())
    return paths


def is_allowed(path: str, patterns: set[str]) -> bool:
    """True when `path` matches an allowlist pattern (an exact path or a `dir/**` prefix)."""
    return any(path == p or (p.endswith("/**") and path.startswith(p[:-2])) for p in patterns)


def findings(root: Path, patterns: set[str]) -> list[str]:
    """Every unaccounted reference under `root`, as `path:line: text`."""
    out = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "grep",
            "-n",
            "-I",
            "-E",
            "probityai/agent-evidence([^-A-Za-z0-9_]|$)",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if out.returncode not in (0, 1):
        raise RuntimeError(f"git grep failed: {out.stderr.strip()}")
    hits = []
    for line in out.stdout.splitlines():
        path, _, rest = line.partition(":")
        number, _, text = rest.partition(":")
        if is_allowed(path, patterns):
            continue
        left = ARCHIVED_ONLY.sub("", text)
        if REFERENCE.search(left):
            hits.append(f"{path}:{number}: {text.strip()[:160]}")
    return hits


def main() -> int:
    try:
        patterns = allowed_paths(ALLOWLIST.read_text(encoding="utf-8"))
        hits = findings(ROOT, patterns)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"archived-repo-gate did not run: {exc}", file=sys.stderr)
        return 2
    for hit in hits:
        print(hit, file=sys.stderr)
    if hits:
        print(
            f"{len(hits)} reference(s) to the archived probityai/agent-evidence; point them at "
            "probityai/agent-evidence-vectors, or list the file in "
            "scripts/archived-repo-allowlist.txt with its reason",
            file=sys.stderr,
        )
        return 1
    print("no live reference to the archived probityai/agent-evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
