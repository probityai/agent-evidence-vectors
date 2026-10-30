#!/usr/bin/env python3
"""Audit the whole published history for a private path, a dossier name or a product name.

The pre-push scan beside this one gates what is ABOUT to be pushed. This one
reads what already HAS been: every commit `origin/main` reaches, first commit to
tip, with the same rules and the same rule sidecar, so a leak that walked past
an older guard is found by the schedule, not by a reader. It is the
instrument that would have named the four 2026-09 commits the day they landed.

    scripts/history-identity-audit.py              # origin/main, end to end
    scripts/history-identity-audit.py --ref HEAD   # another ref

Exit codes, three-valued for the same reason as the pre-push scan:

    0  every commit scanned, nothing found (the count is printed)
    1  at least one commit carries a hit (commit, file and line are printed)
    2  did not scan -- the ref is absent, the sidecar failed to load, or git failed

The rules live in `pre-push-identity-scan.py` and are loaded from that file
by path, so there is exactly one rule set and the two scanners cannot disagree.
"""

from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

SCANNER = Path(__file__).resolve().with_name("pre-push-identity-scan.py")


def _scanner() -> ModuleType:
    spec = importlib.util.spec_from_file_location("pre_push_identity_scan", SCANNER)
    if spec is None or spec.loader is None:
        print(f"history-identity-audit: cannot load {SCANNER}", file=sys.stderr)
        raise SystemExit(2)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--ref", default="origin/main", help="the ref to audit end to end")
    args = parser.parse_args(argv[1:])

    resolved = subprocess.run(
        ["git", "rev-parse", "-q", "--verify", f"{args.ref}^{{commit}}"],
        capture_output=True, check=False,
    )
    if resolved.returncode != 0:
        print(f"history-identity-audit: {args.ref} does not resolve in this clone", file=sys.stderr)
        return 2

    scanner = _scanner()
    sidecar = scanner.Sidecar()
    count, hits = scanner.scan_range([args.ref], sidecar)
    for hit in hits:
        print(hit)
    if hits:
        named = sorted({h.split()[0] for h in hits})
        print(
            f"history-identity-audit: {len(hits)} hit(s) in {len(named)} of {count} commit(s) "
            f"reachable from {args.ref}: {' '.join(named)}",
            file=sys.stderr,
        )
        return 1
    print(f"history-identity-audit: {count} commit(s) reachable from {args.ref} scanned, clean")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
