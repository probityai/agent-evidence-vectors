"""The exec and write cases the Go done reader is held to, judged by the Python reader.

The tool-shadow rules of the done checks read how Python was started, which directory it
puts first on the import path, which paths a loader variable names and which writes a run
may make. The corpora reach each of them with a handful of spellings. This file builds the
spellings that decide each rule (interpreter flags in clusters, with values and with the
`--` stop, loader variables with colons and spaces, writes under and beside a cache,
links, exempt and own events) and keeps what the Python reader answers for every one in
``corpora/testdata/done-events.json``. The Go test ``TestDoneEventsAgreeWithPython`` calls
the Go function of each section and requires the same answer. Regenerate with:

    AEV_WRITE_DONE_EVENTS=1 uv run --extra dev pytest \\
        vectors-done-receipt/tests/test_done_event_cases.py
"""

from __future__ import annotations

import itertools
import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packaging"))

from agent_evidence_vectors import donechecks as chk  # noqa: E402

FIXTURE = ROOT / "corpora" / "testdata" / "done-events.json"
CWD = "/work/space"
EXES = ("/usr/bin/python3", "python", "/opt/pypy3.10", "/bin/sh", "/usr/bin/env", "xpython", "")
FIRST = ("python3", "pypy", "sh", "/usr/bin/python3.12", "env", "")
OPTIONS = ("-c", "-m", "-cprint", "-mpkg.mod", "-W", "-Wignore", "-X", "-Xdev", "-I", "-E", "-P",
           "-B", "-S", "-s", "-u", "-Bs", "-BcX", "-Wd", "-WX", "-Xo", "--",
           "--check-hash-based-pycs", "--foo", "-", "-V", "--version", "-Pc", "-Ic", "-sm", "-uW")
KEY = ("-c", "-m", "-cx", "-mp.q", "-W", "-Wd", "-X", "-I", "-E", "-P", "--",
       "--check-hash-based-pycs", "--foo", "-B")
SAFE_OPTIONS = ((), ("-E",), ("-P",), ("-I",), ("-c", "x"), ("-m", "pkg.mod"), ("-EI",),
                ("-B",))
TAILS = ((), ("a.py",), ("sub/a.py",), ("../a.py",), ("/abs/a.py",), ("-",), ("pkg.mod",),
         ("always",), ("x", "y"))
ENVS: tuple[dict[str, str], ...] = (
    {}, {"PYTHONSAFEPATH": "1"}, {"PYTHONSAFEPATH": ""}, {"PYTHONPATH": "p"})
LOADER_KEYS = ("PYTHONHOME", "PYTHONSTARTUP", "PYTHONUSERBASE", "PYTHONPYCACHEPREFIX", "LD_PRELOAD",
               "LD_AUDIT", "PYTHONPATH", "LD_LIBRARY_PATH", "OTHER")
LOADER_VALUES = ("", "a", "a:b", "/x:/y", ":a", "a:", "a b", "a  b", "a:b c", " a", "a\tb",
                 "../up:./here", "/abs", "a\u2003b")
NAMES = ("/work/space/a.py", "/work/space/pkg/mod.py", "/work/space/__pycache__/a.cpython-312.pyc",
         "/work/space/__pycache__/a.pyc", "/work/space/__pycache__/a",
         "/work/space/pkg/__pycache__/m.x.pyc", "/work/space/a.pyc", "/work/space/a.so",
         "/work/space/a.pth", "/work/space/sub/b.txt", "/work/spacex/a.py", "/other/a.py",
         "/work/space", "/work/space/.pytest_cache/v", "/work/space/__pycache__",
         "/work/space/__pycache__/a.cpython-312.pyc/x", "/work/space/pkg", "/work/space/pkg.py")
ALLOWED: tuple[list[str], ...] = (
    [], ["/work/space/a.py"], ["/work/space/pkg"], ["/work/space/a.py", "/work/space/pkg"],
    ["/work/space/__pycache__"], ["/work"])


def event(argv: list[str], exe: str, env: dict[str, str]) -> dict[str, Any]:
    return {"argv": argv, "exe": exe, "cwd": CWD, "env": env}


def started_case(item: dict[str, Any]) -> dict[str, Any]:
    found = chk._started(item)
    started = None if found is None else [sorted(found[0]), found[1], found[2]]
    return {"event": item, "started": started, "zero": chk._python_path_zero(item),
            "replacing": sorted(chk._replacing(item)),
            "safe": None if found is None else chk._safe(found[0], item)}


def bare_events() -> Iterator[dict[str, Any]]:
    for exe in EXES:
        for first in FIRST:
            yield event([first], exe, {})
    for option in OPTIONS:
        for tail in TAILS:
            yield event(["python3", option, *tail], "/usr/bin/python3", {})


def clustered_events() -> Iterator[dict[str, Any]]:
    for pair in itertools.product(KEY, repeat=2):
        for tail in TAILS[:5]:
            yield event(["python3", *pair, *tail], "/usr/bin/python3", {})
    for triple in itertools.product(KEY[:8], repeat=3):
        for tail in TAILS[:2]:
            yield event(["python3", *triple, *tail], "/usr/bin/python3", {})


def spelled_events() -> Iterator[dict[str, Any]]:
    for exe in EXES[3:]:
        for option in KEY:
            yield event(["python3", option, "a.py"], exe, {})
    for first in FIRST[2:]:
        for option in KEY:
            yield event([first, option, "a.py"], "/bin/sh", {})


def environment_events() -> Iterator[dict[str, Any]]:
    for env in ENVS:
        for options in SAFE_OPTIONS:
            for tail in TAILS:
                yield event(["python3", *options, *tail], "/usr/bin/python3", env)


def started_events() -> Iterator[dict[str, Any]]:
    """Every event the started cases judge, in a fixed order, possibly with repeats."""
    yield from bare_events()
    yield from clustered_events()
    yield from spelled_events()
    yield from environment_events()


def started_cases() -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for item in started_events():
        key = json.dumps(item, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(started_case(item))
    return out


def text_cases() -> dict[str, list[dict[str, Any]]]:
    top = [{"name": name, "directory": directory, "want": chk._top_level(name, directory)}
           for directory in ("/work/space", "/work/space/")
           for name in NAMES if name.startswith("/work/space/")]
    entries = [{"key": key, "value": value, "cwd": cwd, "want": chk._entries(key, value, cwd)}
               for key in LOADER_KEYS for value in LOADER_VALUES for cwd in (CWD, "/")]
    excused = [{"name": name, "allowed": allowed, "want": chk._excused(name, allowed)}
               for name in NAMES for allowed in ALLOWED]
    importable = []
    for directory in ("/work/space", "/work/space/pkg", "/other"):
        for allowed in ALLOWED:
            for links in ([], ["/work/space/sub/b.txt"], ["/work/space/pkg"], ["/work/space/a.so"]):
                written = sorted(NAMES)
                want = chk._importable_writes(directory, set(written), set(links), allowed)
                importable.append({"directory": directory, "written": written, "links": links,
                                   "allowed": allowed, "want": want})
    return {"top_level": top, "entries": entries, "excused": excused, "importable": importable}


OWNERS: tuple[tuple[str, str | None, set[str]], ...] = (
    ("write", "agent", {"agent"}), ("write", "tool", {"agent"}), ("exec", "agent", {"agent"}),
    ("rename", "agent", set()), ("write", None, {"agent"}))


def exempt_cases() -> list[dict[str, Any]]:
    writes_pool: tuple[list[str], ...] = (
        [], ["/work/space/out"], ["/work/space/out", "/tmp"], ["/work/space"])
    paths = ("/work/space/out/a", "/work/space/out", "/work/space/x/__pycache__/a", "/tmp/z",
             "/etc/passwd", "/work/space/outx", "a/__pycache__/b")
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for writes in writes_pool:
        for keys in (("path",), ("target",), ("path", "target"), ()):
            for first, second in itertools.product(paths, repeat=2):
                item = {key: (first if key == "path" else second) for key in keys}
                if json.dumps(item, sort_keys=True) in seen and keys != ("path", "target"):
                    continue
                seen.add(json.dumps(item, sort_keys=True))
                for kind, origin, own in OWNERS:
                    full = {**item, "type": kind, "step": 3}
                    if origin is not None:
                        full["origin"] = origin
                    out.append({"event": full, "writes": writes, "own": sorted(own),
                                "exempt": chk._exempt(full, writes),
                                "ownship": chk._own(full, own, writes),
                                "ownship_none": chk._own(full, own, None)})
    return out


def link_cases() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    events = [{"type": "link", "step": 2, "path": "a", "target": "b"},
              {"type": "link", "step": 5, "path": "late"},
              {"type": "link", "step": 1, "target": "only/target"},
              {"type": "write", "step": 1, "path": "w"},
              {"type": "link", "step": 4, "path": "four"}]
    external = [{"type": "link", "step": 2, "paths": ["/x/y", "/x/z"]},
                {"type": "link", "step": 6, "paths": ["/late"]},
                {"type": "write", "step": 1, "paths": ["/w"]},
                {"type": "link", "step": 4, "paths": ["/four"]}]
    for count in range(len(events) + 1):
        for outside in range(len(external) + 1):
            record = {"workspace_root": "/work/space", "events": events[:count],
                      "external_mutations": external[:outside]}
            for before in (0, 1, 2, 3, 4, 5, 6, 7):
                out.append({"record": record, "before": before,
                            "want": sorted(chk._links(record, before))})
    return out


def cases() -> dict[str, Any]:
    return {"started": started_cases(), **text_cases(), "exempt": exempt_cases(),
            "links": link_cases()}


def encoded() -> bytes:
    body = cases()
    lines = [f'"{name}":[\n' + ",\n".join(json.dumps(item, sort_keys=True, separators=(",", ":"),
                                                       ensure_ascii=True) for item in items) + "\n]"
             for name, items in body.items()]
    return ("{" + ",\n".join(lines) + "}\n").encode()


def test_the_go_event_cases_are_what_python_answers() -> None:
    if os.environ.get("AEV_WRITE_DONE_EVENTS") == "1":
        FIXTURE.write_bytes(encoded())
    assert FIXTURE.read_bytes() == encoded(), (
        "corpora/testdata/done-events.json is not what the Python reader answers; "
        "regenerate it with AEV_WRITE_DONE_EVENTS=1")


def test_the_event_cases_reach_every_answer() -> None:
    found = json.loads(FIXTURE.read_bytes())
    assert any(item["started"] is None for item in found["started"])
    assert any(item["started"] and item["started"][1] == "c" for item in found["started"])
    assert any(item["started"] and item["started"][1] == "m" for item in found["started"])
    assert any(item["zero"] is None for item in found["started"])
    assert {item["want"] for item in found["excused"]} == {True, False}
    assert any(item["want"] for item in found["importable"])
    assert any(item["want"] for item in found["links"])
