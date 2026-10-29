#!/usr/bin/env python3
"""Refuse a release procedure that asks for a full local mirror of the CI jobs.

Ruling of 2026-10-07: the local gate is a fast subset (identity and leak scan,
size, secrets, runner labels), and remote CI is the proof. On 2026-10-29 the
release procedure still told the releaser to run scripts/workflow-steps-gate.py,
a serial mirror of every CI job. On one shared box it ran about 15 hours (job 41
of about 220 after three and a half hours) and held v0.30.0 back, while the same
jobs ran in parallel on GitHub in under 40 minutes.

Three statements are checked:

1. RELEASING.md, outside this test's own mention, never tells the releaser to run
   scripts/workflow-steps-gate.py or to set AEV_PRE_PUSH_VENUE to local or pool.
2. The pre-push hook defaults to the leak tier.
3. The Go race test in ci.yml carries an explicit -timeout, so Go's 10 minute
   default is never the limit on a slow machine (the corpora package took 281 s
   on a GitHub runner and exceeded 600 s on a shared box).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN = (
    re.compile(r"workflow-steps-gate\.py"),
    re.compile(r"AEV_PRE_PUSH_VENUE\s*=\s*(local|pool)"),
)


def releasing_violations(text: str) -> list[str]:
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        for pattern in FORBIDDEN:
            if pattern.search(line):
                found.append(f"RELEASING.md:{number}: {line.strip()}")
    return found


def hook_default_violations(text: str) -> list[str]:
    if 'venue="${AEV_PRE_PUSH_VENUE-leak}"' not in text:
        return [".githooks/pre-push: the default venue is not leak"]
    return []


def go_timeout_violations(text: str) -> list[str]:
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        if "go test" in line and "-race" in line and "-timeout" not in line:
            found.append(f".github/workflows/ci.yml:{number}: {line.strip()}")
    return found


def main() -> int:
    problems = (
        releasing_violations((ROOT / "RELEASING.md").read_text(encoding="utf-8"))
        + hook_default_violations((ROOT / ".githooks/pre-push").read_text(encoding="utf-8"))
        + go_timeout_violations((ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))
    )
    # Controls: each rule must fire on a known-bad input, or the test checks nothing.
    controls = (
        releasing_violations("uv run python -B scripts/workflow-steps-gate.py"),
        releasing_violations("AEV_PRE_PUSH_VENUE=pool git push"),
        hook_default_violations('venue="${AEV_PRE_PUSH_VENUE-local}"'),
        go_timeout_violations("go test ./... -race -count=1"),
    )
    if not all(controls):
        print("FAIL: a control did not fire; the checker is blind", file=sys.stderr)
        return 1
    for problem in problems:
        print(f"FAIL {problem}", file=sys.stderr)
    if problems:
        return 1
    print("ok: release procedure runs the leak tier only; Go race test has an explicit timeout")
    return 0


if __name__ == "__main__":
    sys.exit(main())
