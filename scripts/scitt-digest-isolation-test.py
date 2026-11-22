#!/usr/bin/env python3
"""`release-digests.py --check` must run for somebody who installed nothing.

The property, and why it needs a test rather than a comment
-----------------------------------------------------------
Verifying a published release is the one path in this repository that cannot
have dependencies. A reader clones the tag, runs the four commands the README
lists, and decides whether to trust the corpus. The first of those four is
`python3 scripts/release-digests.py --check`, and it reaches into every corpus
to recompute that corpus's digest from its own files.

v0.10.0 shipped with that property broken. Registering the six newer corpora
made the script load each one's generator by path, and vectors-scitt-cose's
generator imports cbor2 and pycose at module scope -- it registers a COSE
algorithm with a decorator that runs at import time, so the import cannot be
deferred. In a fresh clone the command died with
`ModuleNotFoundError: No module named 'cbor2'`. Nothing caught it, because every
environment that ran the check had the generator extras installed.

So this asserts the property from outside: the check runs in a subprocess whose
interpreter cannot see site-packages at all, and it has to exit 0 there. A
comment saying "keep this stdlib-only" would not have failed when the dependency
arrived; this does.

The isolation is `-S` (no site directories) plus a PYTHONPATH and a PYTHONHOME
left unset, which together remove every installed package from the subprocess's
view while leaving the standard library reachable. A positive control proves the
isolation is real rather than merely asserted: importing a third-party package
under the same flags must FAIL, or the test is measuring nothing and says so.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECK = REPO_ROOT / "scripts" / "release-digests.py"
#: What an interpreter prints when an import failed: the only output that
#: means the check needed a package it could not see.
IMPORT_FAILURE = re.compile(r"\b(ModuleNotFoundError|ImportError)\b")


def isolated(args: list[str]) -> subprocess.CompletedProcess[str]:
    """Run the interpreter with no site directories and no inherited path."""
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"}
    return subprocess.run(
        [sys.executable, "-S", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def main() -> int:
    # The control comes first. If a third-party import SUCCEEDS under these
    # flags then the subprocess can see site-packages, the real assertion below
    # would pass for the wrong reason, and this test would certify a property it
    # never measured.
    control = isolated(["-c", "import cbor2"])
    if control.returncode == 0:
        print(
            "FAIL: the isolation does not isolate. `import cbor2` succeeded in the "
            "subprocess, so this test cannot tell a stdlib-only check from one that "
            "quietly needs a package. Fix the isolation, never the assertion.",
            file=sys.stderr,
        )
        return 1

    done = isolated([str(CHECK), "--check"])
    if done.returncode != 0:
        output = f"{done.stdout}\n{done.stderr}"
        tail = (done.stderr or done.stdout).strip().splitlines()
        if not IMPORT_FAILURE.search(output):
            # The check ran to its verdict under isolation, which is the property
            # this test owns; it refused the digest list itself. Saying "a
            # dependency" here sent authors hunting for a package while the real
            # fix was a regeneration (20 Nov 2026, two merge-queue groups).
            print(
                "FAIL: `release-digests.py --check` ran with no third-party package "
                "reachable and refused the digest list: release/CORPUS-DIGESTS.txt "
                "does not match the corpora on disk. Regenerate it with "
                "`uv run --locked --extra generators python scripts/regenerate-derived.py`.",
                file=sys.stderr,
            )
            for line in tail[-6:]:
                print(f"  {line}", file=sys.stderr)
            return 1
        print(
            "FAIL: `release-digests.py --check` does not run without third-party "
            "packages, so a reader who cloned the tag and installed nothing cannot "
            "verify this release. The corpus whose module pulled in a dependency "
            "owns the fix: give it a digest.py that imports only the standard "
            "library, as vectors-scitt-cose does.",
            file=sys.stderr,
        )
        for line in tail[-6:]:
            print(f"  {line}", file=sys.stderr)
        return 1

    print(
        "OK: the digest check recomputes every corpus with no third-party package "
        "reachable, and the control confirms the subprocess really is isolated."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
