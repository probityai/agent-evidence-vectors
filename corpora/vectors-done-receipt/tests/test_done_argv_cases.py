"""The argv and path cases the Go done reader is held to, computed by the Python reader.

``corpora/doneargv.go`` restates ``doneargv.py`` and the four ``posixpath`` functions it
uses, because Go's path package normalizes differently. The corpora reach only a few
spellings of a command, so this file lists the spellings that decide each rule, computes
what Python answers for each, and keeps the answers in ``corpora/testdata/done-argv.json``.
The Go test ``TestDoneArgvAgreesWithPython`` reads the same file, so the two readers are
compared on every case and the file cannot drift from Python:

    AEV_WRITE_DONE_ARGV=1 uv run --extra dev pytest \
        vectors-done-receipt/tests/test_done_argv_cases.py
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packaging"))

from agent_evidence_vectors import doneargv  # noqa: E402

FIXTURE = ROOT / "corpora" / "testdata" / "done-argv.json"
PYTEST = ["python", "-m", "pytest"]

INVOCATIONS: list[tuple[list[str], str | None]] = [
    # the program, and an interpreter running a module
    (["pytest", "tests"], None),
    (["py.test", "tests"], None),
    (["./pytest", "tests"], None),
    (["/usr/bin/pytest", "tests"], None),
    ([*PYTEST, "tests"], None),
    (["python", "-mpytest", "tests"], None),
    (["python3.12", "-m", "pytest", "tests"], None),
    (["pypy3", "-m", "pytest", "tests"], None),
    (["/usr/local/bin/python", "-m", "pytest", "tests"], None),
    (["python", "-W", "error", "-m", "pytest", "tests"], None),
    (["python", "-X", "dev", "-m", "pytest", "tests"], None),
    (["python", "--check-hash-based-pycs", "always", "-m", "pytest", "tests"], None),
    (["python", "-W"], None),
    (["python", "-B", "-m", "pytest", "tests"], None),
    (["python", "-m"], None),
    (["python", "-", "-m", "pytest"], None),
    (["python", "test.py"], None),
    (["python", "./test.py", "./"], None),
    (["python", "-c", "print(1)"], None),
    (["pythonx", "-m", "pytest", "tests"], None),
    (["python3.12x", "-m", "pytest", "tests"], None),
    (["python\n", "-m", "pytest", "tests"], None),
    (["py", "-m", "pytest", "tests"], "/usr/bin/python3.12"),
    (["python", "-m", "pytest", "tests"], "/usr/bin/env"),
    (["sh", "-c", "pytest tests"], None),
    (["make", "./check", "test"], None),
    # pytest targets
    ([*PYTEST, "./tests"], None),
    ([*PYTEST, "tests/"], None),
    ([*PYTEST, "a/../b", "b"], None),
    ([*PYTEST, "../tests", "/abs//x/./y"], None),
    ([*PYTEST, "-"], None),
    ([*PYTEST, "--", "-k", "./x"], None),
    ([*PYTEST, "tests", "tests"], None),
    ([*PYTEST, "b", "a"], None),
    # options that only change what is printed, with and without their values
    ([*PYTEST, "-q", "-v", "-s", "-x", "-ra", "-rN", "tests"], None),
    ([*PYTEST, "--tb=short", "--color=yes", "--code-highlight=no", "tests"], None),
    ([*PYTEST, "--durations=5", "--maxfail=1", "--capture=no", "tests"], None),
    ([*PYTEST, "--tb", "short", "tests"], None),
    ([*PYTEST, "--maxfail", "2", "tests"], None),
    ([*PYTEST, "tests", "--tb"], None),
    ([*PYTEST, "--tbx", "tests"], None),
    ([*PYTEST, "--tb-short", "tests"], None),
    ([*PYTEST, "-rZ", "tests"], None),
    # options that choose what runs
    ([*PYTEST, "-k", "edge", "tests"], None),
    ([*PYTEST, "tests", "-k"], None),
    ([*PYTEST, "-m", "slow", "-k", "a", "tests"], None),
    ([*PYTEST, "-k", "b", "-k", "a", "tests"], None),
    ([*PYTEST, "-p", "no:cacheprovider", "--ignore", "x", "tests"], None),
    ([*PYTEST, "--lf", "--ff", "tests"], None),
    ([*PYTEST, "--lf", "-k", "a", "tests"], None),
    ([*PYTEST, "-k=x", "tests"], None),
]

NORMPATHS = ["", ".", "/", "//", "///", "////x", "//x", "a", "a/", "a//b", "a/./b", "a/../b",
             "../a", "../../a", "a/../..", "/..", "/../a", "//../a", "./", "a/b/../../..",
             "../..", "x/..", "./x/../y"]
JOINS = [("a", "b"), ("a/", "b"), ("", "b"), ("a", "/b"), ("a", ""), ("/", "b"), ("a//", "b")]
SPLITS = ["", "a", "/a", "a/b", "a/b/", "//a", "///", "a//b", "/a//b", "a/"]
SPACES = [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x41, 0x85,
          0xA0, 0x1680, 0x2000, 0x200B, 0x2028, 0x3000, 0xFEFF]


def _invocation(argv: list[str], exe: str | None) -> dict[str, Any]:
    found = doneargv.invocation(argv, exe)
    if found.program == "pytest":
        targets, selecting = found.args
        return {"program": "pytest", "targets": list(targets),
                "selecting": [list(item) for item in selecting]}
    return {"program": found.program, "args": list(found.args)}


def cases() -> dict[str, Any]:
    space = re.compile(r"\s")
    return {
        "invocations": [{"argv": argv, "exe": exe or "", "want": _invocation(argv, exe)}
                        for argv, exe in INVOCATIONS],
        "normpath": [{"path": path, "want": posixpath.normpath(path)} for path in NORMPATHS],
        "join": [{"a": a, "b": b, "want": posixpath.join(a, b)} for a, b in JOINS],
        "split": [{"path": path, "want": list(posixpath.split(path))} for path in SPLITS],
        "space": [{"rune": rune, "want": bool(space.match(chr(rune)))} for rune in SPACES],
    }


def encoded() -> bytes:
    return (json.dumps(cases(), indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def test_the_go_argv_cases_are_what_python_answers() -> None:
    if os.environ.get("AEV_WRITE_DONE_ARGV") == "1":
        FIXTURE.write_bytes(encoded())
    assert FIXTURE.read_bytes() == encoded(), (
        "corpora/testdata/done-argv.json is not what the Python reader answers; "
        "regenerate it with AEV_WRITE_DONE_ARGV=1")


def test_every_invocation_case_is_distinct() -> None:
    spelled = [json.dumps([argv, exe]) for argv, exe in INVOCATIONS]
    assert len(set(spelled)) == len(spelled)
