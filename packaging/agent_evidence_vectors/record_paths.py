"""Keep absolute local paths out of every retained run record.

A published run record names the machine that wrote it when a path under a home
directory, a mount or a scratch directory reaches the bytes. Every writer of such a
record calls :func:`write_records`, which refuses before anything is written, and
:func:`relativize` and :func:`portable_command` rewrite a path to a repo-relative or
placeholder form at the point where the writer still has it.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any

# Home directories of a hosted CI runner name no person, so a record may carry them.
CI_HOMES = ("runner",)
# JSON keys that declare how to reproduce the run; a scratch path may appear there.
REPRODUCTION_KEYS = ("command", "reproduction", "verifier")

_BOUNDARY = r"(?<![A-Za-z0-9_.:~/\\-])"
_ROOTS = (
    rf"{_BOUNDARY}/home/(?P<user>[A-Za-z0-9_.-]+)/",
    rf"{_BOUNDARY}/Users/[A-Za-z0-9_.-]+/",
    r"(?<![A-Za-z0-9_.])[A-Za-z]:[\\/]+Users[\\/]",
    rf"{_BOUNDARY}~/",
    rf"{_BOUNDARY}/(?:mnt|blue|root)/",
)
_LOCAL = re.compile("|".join(f"(?:{r})" for r in _ROOTS))
_SCRATCH = re.compile(rf"{_BOUNDARY}/tmp/")


class LocalPathError(ValueError):
    """A record would carry an absolute local path."""


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


def _context(text: str, found: re.Match[str]) -> str:
    return text[max(0, found.start() - 20) : found.end() + 40]


def _strings(value: Any, key: str | None = None) -> Iterator[tuple[str | None, str]]:
    if isinstance(value, str):
        yield key, value
    elif isinstance(value, Mapping):
        for name, item in value.items():
            yield from _strings(item, str(name))
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item, key)


def refuse_local_paths(
    name: str,
    value: Any,
    *,
    reproduction_keys: tuple[str, ...] = REPRODUCTION_KEYS,
    ci_homes: tuple[str, ...] = CI_HOMES,
) -> None:
    """Raise :class:`LocalPathError` when ``value`` (text or a JSON object) holds a local path.

    A scratch path is allowed only inside a field named in ``reproduction_keys``.
    """
    for key, text in _strings(value):
        found = find_local_path(
            text, allow_scratch=key in reproduction_keys, ci_homes=ci_homes
        )
        if found is not None:
            raise LocalPathError(
                f"refusing to write {name}: it contains an absolute local path near "
                f"{found!r}; write repo-relative paths"
            )


def relativize(path: str | os.PathLike[str], root: str | os.PathLike[str]) -> str:
    """Write ``path`` relative to ``root`` in POSIX form; refuse a path outside ``root``."""
    resolved = Path(os.path.abspath(path))
    base = Path(os.path.abspath(root))
    try:
        return resolved.relative_to(base).as_posix()
    except ValueError:
        raise LocalPathError(f"{path} is outside {root}, so it has no repo-relative form") from None


def _portable(text: str) -> str:
    """Name the interpreter environment by a placeholder and drop the working directory."""
    roots = {sys.prefix, os.path.dirname(os.path.dirname(sys.executable))}
    for root in sorted(roots, key=len, reverse=True):
        if root and root != os.sep:
            text = text.replace(root, "<uv-env>" if "/uv/" in root else "<env>")
    return text.replace(os.getcwd().rstrip(os.sep) + os.sep, "")


def portable_argv(argv: list[str]) -> list[str]:
    """Rewrite each argument so it carries no environment or working-directory path."""
    return [_portable(arg) for arg in argv]


def portable_command() -> str:
    """Render the invocation as a shell command without local paths."""
    return _portable(shlex.join([sys.executable, *sys.argv]))


def write_records(output: Path, records: Mapping[str, Any]) -> None:
    """Create ``output`` and write each record as JSON, after refusing any local path.

    Nothing is created when a record is refused, and an existing ``output`` is an error.
    """
    texts = {
        name: json.dumps(value, indent=2, sort_keys=True) + "\n" for name, value in records.items()
    }
    for name, value in records.items():
        refuse_local_paths(name, value)
    if output.exists():
        raise FileExistsError(output)
    output.mkdir(parents=True, exist_ok=False)
    for name, text in texts.items():
        (output / name).write_text(text, encoding="utf-8")
