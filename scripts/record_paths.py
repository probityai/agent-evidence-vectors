"""Find absolute local paths in published run records.

A run record names the machine that wrote it when a path under a home directory, a
mount or a scratch directory reaches its bytes. tests/test_record_paths.py scans every
committed record with :func:`find_local_path`, so a record that leaks, or a copy step
that bypasses the writer-side refusal in agent-evidence-vectors, turns CI red.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

# Home directories of a hosted CI runner, a gate box or a sandbox default user name no person.
CI_HOMES = ("runner", "gate", "default")

_BOUNDARY = r"(?<![A-Za-z0-9_.:~/\\-])"
_ROOTS = (
    rf"{_BOUNDARY}/home/(?P<user>[A-Za-z0-9_.-]+)/",
    rf"{_BOUNDARY}/Users/[A-Za-z0-9_.-]+/",
    r"(?<![A-Za-z0-9_.])[A-Za-z]:[\\/]+Users[\\/]",
    rf"{_BOUNDARY}~/",
    rf"{_BOUNDARY}/(?:mnt|blue|root)/",
)
_LOCAL = re.compile("|".join(f"(?:{r})" for r in _ROOTS))
_HOME = re.compile("|".join(f"(?:{r})" for r in _ROOTS[:3]))
_SCRATCH = re.compile(rf"{_BOUNDARY}/tmp/")


def find_local_path(
    text: str, *, allow_scratch: bool = False, ci_homes: tuple[str, ...] = CI_HOMES
) -> str | None:
    """Return the first absolute local path in ``text`` with a little context, or None."""
    for found in _LOCAL.finditer(text):
        if found.groupdict().get("user") in ci_homes:
            continue
        return _context(text, found)
    if not allow_scratch:
        scratch = _SCRATCH.search(text)
        if scratch is not None:
            return _context(text, scratch)
    return None


def find_home_path(text: str, *, ci_homes: tuple[str, ...] = CI_HOMES) -> str | None:
    """Return the first person's home directory path in ``text``, or None.

    Narrower than :func:`find_local_path`: ``~/``, ``/mnt`` and ``/tmp`` also occur in
    prose and in third-party sources, so the whole-tree scan refuses only home directories.
    """
    for found in _HOME.finditer(text):
        if found.groupdict().get("user") in ci_homes:
            continue
        return _context(text, found)
    return None


def _context(text: str, found: re.Match[str]) -> str:
    return text[max(0, found.start() - 20) : found.end() + 40]


def relativize(path: str | os.PathLike[str], root: str | os.PathLike[str]) -> str:
    """Write ``path`` relative to ``root`` in POSIX form; refuse a path outside ``root``."""
    resolved = Path(os.path.abspath(path))
    base = Path(os.path.abspath(root))
    try:
        return resolved.relative_to(base).as_posix()
    except ValueError:
        raise ValueError(f"{path} is outside {root}, so it has no repo-relative form") from None
