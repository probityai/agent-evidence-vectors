"""One argv model for an acceptance command, as probity-verify's ``done_argv`` defines it.

A sealed acceptance command and a run of it can be spelled many ways that run the same
tests: ``pytest -q tests`` and ``pytest tests -q``, ``python -m pytest -q tests``. So a
claimed run and an observed exec are compared as an :class:`Invocation`:

- the **program**: a Python entry point run as ``<interpreter> -m <module>`` is that module
  (``python -m pytest`` is ``pytest``); otherwise the program named by ``argv[0]``;
- for **pytest**, the set of targets (``posixpath.normpath`` of every positional argument)
  and the options that choose or change what runs, sorted; options that only change what
  is printed or when a failing run stops are dropped;
- for **any other program**, the arguments in order, a leading ``./`` removed.

An option this module does not know is kept as a selecting option, so an unknown flag never
makes two different runs match.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass

INTERPRETER = re.compile(r"(python|pypy)[0-9.]*$")
_INTERPRETER_VALUES = {"-W", "-X", "--check-hash-based-pycs"}
_REPORTING = {"-q", "--quiet", "-v", "--verbose", "-s", "-x", "--exitfirst", "--no-header",
              "--no-summary", "-l", "--showlocals", "--capture=no", "--disable-warnings",
              "--disable-pytest-warnings", "--strict-markers", "-ra", "-rA", "-rf", "-rs",
              "-rx", "-rX", "-rE", "-rp", "-rP", "-rN"}
_REPORTING_PREFIX = ("--tb=", "--color=", "--durations=", "--maxfail=", "--capture=",
                     "--code-highlight=")
_REPORTING_VALUE = {"--tb", "--color", "--durations", "--maxfail", "--capture"}
_SELECTING_VALUE = {"-k", "-m", "-W", "--deselect", "-c", "-o", "--override-ini", "--rootdir",
                    "--confcutdir", "-p", "--ignore", "--ignore-glob", "--basetemp",
                    "--import-mode"}


@dataclass(frozen=True)
class Invocation:
    """The program and its canonical arguments; see the module docstring."""

    program: str
    args: tuple  # type: ignore[type-arg]


def _plain(word: str) -> str:
    return word[2:] if word.startswith("./") and len(word) > 2 else word


def _module_run(argv: list[str]) -> tuple[str, list[str]] | None:
    """``(module, rest)`` for ``<interpreter> [options] -m <module> rest``."""
    words = argv[1:]
    while words and words[0].startswith("-") and words[0] != "-":
        option = words.pop(0)
        if option == "-m":
            return (words[0], words[1:]) if words else None
        if option.startswith("-m") and len(option) > 2:
            return option[2:], words
        if option in _INTERPRETER_VALUES and words:
            words.pop(0)
    return None


def _pytest_args(args: list[str]) -> tuple:  # type: ignore[type-arg]
    targets: set[str] = set()
    selecting: list[tuple[str, ...]] = []
    words = list(args)
    while words:
        word = words.pop(0)
        if word == "--":
            targets.update(posixpath.normpath(_plain(item)) for item in words)
            break
        if not word.startswith("-") or word == "-":
            targets.add(posixpath.normpath(_plain(word)))
        elif word in _REPORTING or word.startswith(_REPORTING_PREFIX):
            continue
        elif word in _REPORTING_VALUE:
            if words:
                words.pop(0)
        elif word in _SELECTING_VALUE:
            selecting.append((word, words.pop(0) if words else ""))
        else:
            selecting.append((word,))
    return (tuple(sorted(targets)), tuple(sorted(selecting)))


def invocation(argv: list[str], exe: str | None = None) -> Invocation:
    """The invocation an argv runs (``exe``, when given, names the file the kernel ran)."""
    name = posixpath.basename(exe or argv[0])
    program, args = posixpath.basename(argv[0]), list(argv[1:])
    if INTERPRETER.match(name) or INTERPRETER.match(program):
        module = _module_run(argv)
        if module is not None:
            program, args = module
    if program in ("pytest", "py.test"):
        return Invocation("pytest", _pytest_args(args))
    return Invocation(program, tuple(_plain(word) for word in args))
