#!/usr/bin/env python3
"""Pin the three exit codes of scripts/runner-labels-gate.py.

The pre-push hook reads 1 as "a label nothing serves" and refuses the push, and
reads 2 as "the account could not be read" and lets the push through with a
warning. An unread account used to exit 1, because `SystemExit(message)` with a
string exits 1, so a missing token or a rate limit refused the push by naming a
finding the gate never made. Each case runs the gate against this repository's
workflows with a stand-in `gh` first on PATH.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

GATE = Path(__file__).resolve().parent / "runner-labels-gate.py"


def run_with_gh(script: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="runner-labels-") as scratch:
        gh = Path(scratch) / "gh"
        gh.write_text("#!/bin/sh\n" + script, encoding="utf-8")
        gh.chmod(0o755)
        env = {**os.environ, "PATH": f"{scratch}{os.pathsep}{os.environ.get('PATH', '')}"}
        return subprocess.run(
            [sys.executable, str(GATE), "--owner", "example-org"],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )


CASES = (
    ("an unreadable account is inconclusive", "echo 'rate limit exceeded' >&2\nexit 1\n", 2),
    ("an account with no matching app refuses", "exit 0\n", 1),
    ("an installed app serves its labels", "echo ubicloud-managed-runners\n", 0),
)


def main() -> int:
    failures = []
    for name, script, want in CASES:
        proc = run_with_gh(script)
        if proc.returncode != want:
            failures.append(f"{name}: exit {proc.returncode}, wanted {want}\n{proc.stderr}")
    if failures:
        print("FAIL:\n" + "\n".join(failures))
        return 1
    print(f"OK: {len(CASES)} case(s); each outcome of the runner-label gate has its own exit code.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
