#!/usr/bin/env python3
"""Fail when the archive an Action user downloads grows past its budget.

A job that runs `uses: probityai/agent-evidence-vectors@<ref>` makes the runner fetch the
whole repository archive at that ref (codeload's tar.gz) before the first step, on every
run. `git archive --format=tar.gz <ref>` produces that archive from the same tree: measured
on 2026-10-31 it gave 10,983,746 bytes at v0.31.0 against 11.0 MB from codeload, and
135,806,433 bytes at main 18fc2c06 against 135.7 MB, when main carried the 171.7 MB site/
tree. A change that pushes the archive over BUDGET_BYTES moves that cost onto every adopter,
so it has to be argued and the budget raised here in the same change.

    python3 scripts/action-download-budget.py [--ref HEAD]
"""

from __future__ import annotations

import argparse
import subprocess
import sys

DESCRIPTION = "Fail when the archive an Action user downloads grows past its budget."
# 15 MB: v0.31.0 is 11.0 MB; the margin covers ordinary corpus growth between releases.
BUDGET_BYTES = 15_000_000


def archive_size(ref: str) -> int:
    proc = subprocess.run(
        ["git", "archive", "--format=tar.gz", ref], capture_output=True, check=False
    )
    if proc.returncode != 0:
        err = proc.stderr.decode(errors="replace")
        raise SystemExit(f"action-download-budget: git archive {ref} failed: {err}")
    return len(proc.stdout)


def verdict(size: int, budget: int) -> tuple[bool, str]:
    line = f"Action download at this ref: {size:,} bytes (budget {budget:,})"
    if size > budget:
        return False, f"{line}: over by {size - budget:,} bytes"
    return True, line


def main() -> int:
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("--ref", default="HEAD")
    parser.add_argument("--budget", type=int, default=BUDGET_BYTES)
    args = parser.parse_args()
    ok, line = verdict(archive_size(args.ref), args.budget)
    print(line if ok else f"::error::{line}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
