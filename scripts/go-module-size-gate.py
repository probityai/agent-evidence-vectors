"""Refuse a change that makes the root Go module's zip grow past its bound.

The Go module proxy serves the root module as a zip of every tracked file that does not sit
under a nested go.mod (a directory with its own go.mod is a separate module and is left out).
The repository also holds trees that are not Go source (crates/, packages/), so each of
those carries a sentinel go.mod; a new large tree without one would be shipped to every
consumer of the module. This gate measures the uncompressed bytes of the files the module zip
would carry and fails above the bound.

    python3 scripts/go-module-size-gate.py            # check the tracked files of this checkout
    python3 scripts/go-module-size-gate.py --selftest

Standard library only. Exit status: 0 within the bound, 1 over it, 2 the check could not run.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import PurePosixPath

#: Uncompressed bytes the root module may carry. With the imported trees guarded by sentinels it
#: carries 48 MB (a 19.4 MB zip); the bound leaves room for corpora and refuses the unguarded
#: imported trees, which add 179 MB (a 146 MB zip).
BOUND_BYTES = 128 * 1024 * 1024


def tracked_files(root: str) -> list[str]:
    out = subprocess.run(["git", "-C", root, "ls-files", "-z"], check=True,
                         capture_output=True).stdout
    return [p for p in out.decode().split("\0") if p]


def module_files(paths: list[str]) -> list[str]:
    """The paths the root module's zip carries: not under a nested go.mod, not vendor."""
    nested = {str(PurePosixPath(p).parent) for p in paths
              if PurePosixPath(p).name == "go.mod" and PurePosixPath(p).parent != PurePosixPath(".")}

    def inside(path: str) -> bool:
        parent = PurePosixPath(path).parent
        return any(str(a) in nested for a in [parent, *parent.parents]) \
            or "vendor" in PurePosixPath(path).parts[:-1]

    return [p for p in paths if not inside(p)]


def measure(root: str, paths: list[str]) -> int:
    total = 0
    for p in module_files(paths):
        try:
            total += os.lstat(os.path.join(root, p)).st_size
        except FileNotFoundError:
            continue  # tracked and deleted in the working tree: the zip would not carry it
    return total


def selftest() -> int:
    paths = ["go.mod", "aee/a.go", "site/go.mod", "site/docs/x.md", "crates/dsse/vectors/generate/go.mod",
             "crates/dsse/vectors/generate/main.go", "vendor/x/y.go", "pkg/vendor/z.go", "README.md"]
    got = sorted(module_files(paths))
    want = ["README.md", "aee/a.go", "go.mod"]
    if got != want:
        print(f"selftest FAILED: {got} != {want}", file=sys.stderr)
        return 1
    print("selftest ok")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    root = subprocess.run(["git", "rev-parse", "--show-toplevel"], check=True,
                          capture_output=True, text=True).stdout.strip()
    total = measure(root, tracked_files(root))
    print(f"root module carries {total} bytes uncompressed (bound {BOUND_BYTES})")
    if total > BOUND_BYTES:
        print("the root Go module is over its bound: give the new tree a sentinel go.mod "
              "(see packages/go.mod) or move it out of the module root", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except (subprocess.CalledProcessError, OSError) as exc:
        print(f"go-module-size-gate: could not run: {exc}", file=sys.stderr)
        sys.exit(2)
