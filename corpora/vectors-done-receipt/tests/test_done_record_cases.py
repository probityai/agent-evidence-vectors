"""The record cases the Go done reader is held to, judged by the Python reader.

Each corpus member reaches a record rule with one spelling, so most of the Go reader's
record checks were judged by one input each. This file takes, for each record kind, the
valid records of the done corpora that between them carry the most members, breaks
each member of them in the ways that decide a rule (removed, null, of another type,
empty, or a value of the right type that a rule refuses), and keeps what the Python
reader answers for every variant in ``corpora/testdata/done-records.json``: the record
admitted, or the code of the rule it breaks. The Go test ``TestDoneRecordsAgreeWithPython``
parses every variant and requires the same answer. Regenerate with:

    AEV_WRITE_DONE_RECORDS=1 uv run --extra dev pytest \\
        vectors-done-receipt/tests/test_done_record_cases.py
"""

from __future__ import annotations

import copy
import json
import os
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packaging"))

from agent_evidence_vectors import donerecords as rec  # noqa: E402

FIXTURE = ROOT / "corpora" / "testdata" / "done-records.json"
CORPORA = ("vectors-done-contract", "vectors-done-receipt", "vectors-spoofed-tool-output",
           "vectors-test-tampering", "vectors-grader-isolation", "vectors-done-probes")
PARSERS: dict[str, Callable[[bytes], Any]] = {
    "contract": rec.contract, "tree": rec.tree, "observation": rec.observation,
    "capability": rec.capability, "grade": rec.grade, "claims": rec.claims}
BASES_PER_KIND = 8
# Values of the right type that a rule may refuse, tried in place of every string.
STRINGS = ("", "x", "/abs", "../up", "a/./b", "A" * 64, "a" * 64, "2026-10-17T00:00:00Z",
           "2026-10-17T00:00:00", "tests", "-")
NUMBERS = (0, -1, 1, 2, 999, 1.5)


def encode(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def verdict(kind: str, data: bytes) -> str:
    try:
        PARSERS[kind](data)
    except rec.RecordError as exc:
        return exc.code
    except Exception as exc:  # noqa: BLE001 -- a crash is an answer this file must not keep
        return f"crash:{type(exc).__name__}"
    return "ok"


def leaves(value: Any, path: tuple[Any, ...] = ()) -> Iterator[tuple[Any, ...]]:
    yield path
    if isinstance(value, dict):
        for key in sorted(value):
            yield from leaves(value[key], (*path, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from leaves(item, (*path, index))


def get(value: Any, path: tuple[Any, ...]) -> Any:
    for step in path:
        value = value[step]
    return value


def replaced(base: Any, path: tuple[Any, ...], new: Any) -> Any:
    out = copy.deepcopy(base)
    if not path:
        return new
    parent = get(out, path[:-1])
    if new is DELETE:
        del parent[path[-1]]
    else:
        parent[path[-1]] = new
    return out


DELETE = object()


def candidates(value: Any) -> list[Any]:
    """The replacements tried at one place in a record."""
    found: list[Any] = [None, True]
    if isinstance(value, str):
        found += [1, [value], *STRINGS, value + "/", value.upper(), " " + value]
    elif isinstance(value, bool):
        found += [1, "true"]
    elif isinstance(value, (int, float)):
        found += [str(value), *NUMBERS, value + 1, -value - 1]
    elif isinstance(value, list):
        found += [{}, "x", []]
        if value:
            found += [[*value, value[0]], list(reversed(value)), value[:1], [None]]
    elif isinstance(value, dict):
        found += [[], "x", {}, {**value, "unexpected_member": 1}]
    return found


def bases() -> dict[str, list[Any]]:
    """For each kind, the valid records that between them reach the most members."""
    found: dict[str, dict[bytes, Any]] = {kind: {} for kind in PARSERS}
    for corpus in CORPORA:
        for path in sorted((ROOT / corpus / "cases").glob("*/*.json")):
            kind = path.stem
            if kind not in PARSERS or verdict(kind, path.read_bytes()) != "ok":
                continue
            value = json.loads(path.read_bytes())
            found[kind].setdefault(encode(value), value)
    chosen: dict[str, list[Any]] = {}
    for kind, records in found.items():
        covered: set[tuple[Any, ...]] = set()
        picks: list[Any] = []
        pool = [records[key] for key in sorted(records)]
        for _ in range(BASES_PER_KIND):
            best = max(pool, key=lambda r: len(set(leaves(r)) - covered), default=None)
            if best is None or not set(leaves(best)) - covered:
                break
            picks.append(best)
            covered |= set(leaves(best))
            pool.remove(best)
        chosen[kind] = picks
    return chosen


def cases() -> dict[str, Any]:
    """The base records once, and each variant as a path into one, its edit and the answer.

    An edit is ``delete`` or ``set`` with its new value; the record judged is the base with
    the edit applied, in this file's byte form (``encode``)."""
    chosen = bases()
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, bytes]] = set()
    for kind, records in chosen.items():
        for index, base in enumerate(records):
            for path in leaves(base):
                options = candidates(get(base, path))
                if path and isinstance(get(base, path[:-1]), dict):
                    options = [DELETE, *options]
                for new in options:
                    data = encode(replaced(base, path, new))
                    if (kind, data) in seen:
                        continue
                    seen.add((kind, data))
                    edit = {"op": "delete"} if new is DELETE else {"op": "set", "value": new}
                    out.append({"kind": kind, "base": index, "path": list(path), **edit,
                                "want": verdict(kind, data)})
    return {"bases": chosen, "cases": out}


def encoded() -> bytes:
    found = cases()
    lines = [json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
             for item in found["cases"]]
    bases_text = json.dumps(found["bases"], sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True)
    return ('{"bases":' + bases_text + ',\n"cases":[\n' + ",\n".join(lines) + "\n]}\n").encode()


def test_the_go_record_cases_are_what_python_answers() -> None:
    if os.environ.get("AEV_WRITE_DONE_RECORDS") == "1":
        FIXTURE.write_bytes(encoded())
    assert FIXTURE.read_bytes() == encoded(), (
        "corpora/testdata/done-records.json is not what the Python reader answers; "
        "regenerate it with AEV_WRITE_DONE_RECORDS=1")


def test_the_cases_reach_both_answers_for_every_kind() -> None:
    found = json.loads(FIXTURE.read_bytes())["cases"]
    assert not [item for item in found if item["want"].startswith("crash")]
    for kind in PARSERS:
        answers = {item["want"] for item in found if item["kind"] == kind}
        assert "ok" in answers and len(answers) > 2, (kind, answers)
