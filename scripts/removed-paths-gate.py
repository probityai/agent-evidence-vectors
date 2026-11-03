#!/usr/bin/env python3
"""Refuse a tracked file at a path that left this repository.

``release/removed-paths.txt`` lists the paths, one per line (``#`` starts a comment). An entry
ending in ``/`` names a directory and matches every file under it; any other entry names one
file. The tracked files come from ``git ls-files``, so an ignored or untracked file is not read.

Usage: python3 scripts/removed-paths-gate.py [--root DIR]
Exit 0 when no tracked file matches, 1 and name each match otherwise, 2 when the list or the
file list cannot be read.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

LIST = "release/removed-paths.txt"


def entries(text: str) -> list[str]:
    return [line.split("#", 1)[0].strip() for line in text.splitlines() if line.split("#", 1)[0].strip()]


def matches(tracked: list[str], removed: list[str]) -> list[tuple[str, str]]:
    found = []
    for path in tracked:
        for entry in removed:
            if (entry.endswith("/") and path.startswith(entry)) or path == entry:
                found.append((path, entry))
    return found


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    args = ap.parse_args(argv)
    try:
        removed = entries((args.root / LIST).read_text(encoding="utf-8"))
        tracked = subprocess.run(
            ["git", "ls-files", "-z"], cwd=args.root, capture_output=True, check=True
        ).stdout.decode().split("\0")
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"removed-paths gate could not run: {exc}", file=sys.stderr)
        return 2
    if not removed:
        print(f"removed-paths gate could not run: {LIST} lists nothing", file=sys.stderr)
        return 2
    found = matches([p for p in tracked if p], removed)
    for path, entry in found:
        print(f"{path}: a removed path ({entry}) is tracked again")
    print(f"removed-paths gate: {len(removed)} entries, {len(found)} match(es)")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
