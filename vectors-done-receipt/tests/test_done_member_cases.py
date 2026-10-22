"""The run cases the Go done reader is held to, judged by the Python reader.

A corpus member is one run, so each verdict rule of the done checks was reached by the few
runs that the corpora hold. This file takes corpus members of every verdict, changes one
member of one record, case or policy (a value removed, a string replaced by another string
the file already uses, a number moved by one, a flag flipped, a list shortened or given a
duplicate), moves the consumer's pins to a changed record's bytes, and
keeps the verdicts the Python reader derives for every variant in
``corpora/testdata/done-members.json.gz`` (one change per member, record and distinct
answer). The Go test ``TestDoneMembersAgreeWithPython``
rebuilds each variant, pins it the same way and requires the same verdicts. Regenerate:

    AEV_WRITE_DONE_MEMBERS=1 uv run --extra dev pytest \\
        vectors-done-receipt/tests/test_done_member_cases.py
"""

from __future__ import annotations

import copy
import gzip
import json
import os
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "packaging"))
sys.path.insert(0, str(ROOT / "vectors-done-receipt"))

import bundle_lib as lib  # noqa: E402
from agent_evidence_vectors import donerecords as rec  # noqa: E402
from agent_evidence_vectors import donerun  # noqa: E402

FIXTURE = ROOT / "corpora" / "testdata" / "done-members.json.gz"
CORPORA = {"vectors-done-contract": donerun.CONTRACT_SUITE,
           "vectors-done-receipt": donerun.RECEIPT_SUITE,
           "vectors-spoofed-tool-output": donerun.SPOOFED_SUITE,
           "vectors-test-tampering": donerun.TAMPERING_SUITE,
           "vectors-grader-isolation": donerun.GRADER_SUITE,
           "vectors-done-probes": donerun.PROBES_SUITE}
ROLES = ("contract", "observation", "tree", "grade", "claims", "capability", "receipt",
         "statement")
# Members of one verdict signature are alike; this many of each are changed.
PER_SIGNATURE = 4
DELETE = object()


def encode(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def leaves(value: Any, path: tuple[Any, ...] = ()) -> Iterator[tuple[Any, ...]]:
    if path:
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


def strings(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, dict):
        return set().union(*(strings(item) for item in value.values()), set())
    if isinstance(value, list):
        return set().union(*(strings(item) for item in value), set())
    return set()


def candidates(value: Any, pool: list[str]) -> list[Any]:
    """Replacements of the same type, so the record stays one a rule reads."""
    if isinstance(value, bool):
        return [not value]
    if isinstance(value, int):
        return [value + 1, value - 1, 0]
    if isinstance(value, str):
        return [item for item in pool if item != value][:4]
    if isinstance(value, list) and value:
        return [value[:-1], [*value, value[0]]]
    return []


def edit(base: Any, path: tuple[Any, ...], new: Any) -> Any:
    if not path:
        return copy.deepcopy(new)
    out = copy.deepcopy(base)
    parent = get(out, path[:-1])
    if new is DELETE:
        del parent[path[-1]]
    else:
        parent[path[-1]] = new
    return out


def loaded(data: bytes) -> Any:
    """The file's JSON, or None for a member whose fault is a file that is not JSON."""
    try:
        return json.loads(data)
    except ValueError:
        return None


def redirected_trees(tree: Any, contract: Any) -> Iterator[Any]:
    """Final trees that put a link, a special file or a file where a protected entry is.

    A single-leaf change cannot add an entry to a tree, and the tree's own digest covers
    every entry, so these are whole records with the digest recomputed: a symlink or a
    special file at each protected path, at each of its ancestors, under it and beside
    it, and a regular file at the path of a protected directory."""
    try:
        rec.tree(encode(tree))
        entries = rec.contract(encode(contract))["protected_paths"]
    except (rec.RecordError, TypeError):
        return  # a member whose fault is its tree or contract: nothing to redirect
    for entry in entries:
        path = entry["path"]
        parts = path.split("/")
        names = [path, f"{path}/x", f"{path}x",
                 *("/".join(parts[:index]) for index in range(1, len(parts)))]
        for name in names:
            for member, value in (("symlinks", "elsewhere"), ("special", "fifo")):
                changed = copy.deepcopy(tree)
                changed[member] = {**changed[member], name: value}
                changed["tree_sha256"] = rec.record_digest(changed)
                yield changed
        if entry["kind"] == "directory":
            changed = copy.deepcopy(tree)
            changed["files"] = {**changed["files"], path: "0" * 64}
            changed["tree_sha256"] = rec.record_digest(changed)
            yield changed


def judged(suite: str, files: dict[str, bytes], declared: list[str]) -> Any:
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        for name, data in files.items():
            (directory / name).write_bytes(data)
        return donerun.judge_member(suite, directory, declared)


def signature(entry: dict[str, Any]) -> str:
    return json.dumps(entry["expected"], sort_keys=True)


def bases() -> list[tuple[str, dict[str, Any]]]:
    chosen: list[tuple[str, dict[str, Any]]] = []
    for corpus in CORPORA:
        manifest = json.loads((ROOT / corpus / "MANIFEST.json").read_bytes())
        taken: dict[str, int] = {}
        for entry in manifest["vectors"]:
            key = signature(entry)
            if taken.get(key, 0) < PER_SIGNATURE:
                taken[key] = taken.get(key, 0) + 1
                chosen.append((corpus, entry))
    return chosen


def variants() -> Iterator[tuple[dict[str, Any], Any]]:
    """Every change this file makes, with its member's files and declared checks."""
    for corpus, entry in bases():
        directory = ROOT / corpus / entry["path"]
        files = {path.name: path.read_bytes() for path in sorted(directory.iterdir())}
        bound = sorted(name[:-5] for name in files
                       if name.endswith((".case.json", ".policy.json")))
        for role in (*ROLES, *bound):
            name = f"{role}.json"
            if name not in files:
                continue
            removed = {"member": f"{corpus}/{entry['path']}", "role": role, "path": [],
                       "op": "remove"}
            yield removed, (files, None, DELETE, entry.get("checks", []), CORPORA[corpus])
            record = loaded(files[name])
            if record is None:
                continue
            pool = sorted(strings(record))
            for path in leaves(record):
                options = candidates(get(record, path), pool)
                if isinstance(get(record, path[:-1]), dict):
                    options = [DELETE, *options]
                for new in options:
                    item: dict[str, Any] = {"member": f"{corpus}/{entry['path']}", "role": role,
                                            "path": list(path)}
                    item.update({"op": "delete"} if new is DELETE else {"op": "set", "value": new})
                    yield item, (files, record, new, entry.get("checks", []), CORPORA[corpus])
            if role == "tree" and "contract.json" in files:
                for new in redirected_trees(record, loaded(files["contract.json"])):
                    item = {"member": f"{corpus}/{entry['path']}", "role": role, "path": [],
                            "op": "set", "value": new}
                    yield item, (files, record, new, entry.get("checks", []), CORPORA[corpus])


def answer(item: dict[str, Any], context: Any) -> Any:
    files, record, new, declared, suite = context
    name = f"{item['role']}.json"
    if item["op"] == "remove":
        return judged(suite, {key: value for key, value in files.items() if key != name},
                      declared)
    changed = {**files, name: encode(edit(record, tuple(item["path"]), new))}
    if item["role"].endswith((".case", ".policy")):
        # Nothing pins a case or a policy; its own edit is the change judged.
        return judged(suite, changed, declared)
    return judged(suite, lib.pinned(changed, item["role"]), declared)


def selected() -> list[dict[str, Any]]:
    """For each member and record, the first change that reaches each distinct verdict set.

    The full sweep is about 47,000 changes; one per distinct answer keeps every verdict
    the sweep reaches on every member and record, and the Go test reads it in seconds.
    Whole-record changes are few and are all kept."""
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item, context in variants():
        want = answer(item, context)
        key = (item["member"], item["role"], json.dumps(want, sort_keys=True))
        # A whole-record change or a removed file reaches its answer by a path no leaf
        # change takes, so it is kept even when a leaf change reached the same answer.
        if key not in seen or not item["path"]:
            seen.add(key)
            out.append({**item, "want": want})
    return out


def pack(found: list[dict[str, Any]]) -> bytes:
    """The cases with each distinct verdict set stored once, gzipped with no timestamp."""
    table: list[str] = []
    index: dict[str, int] = {}
    lines = []
    for item in found:
        text = json.dumps(item["want"], sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if text not in index:
            index[text] = len(table)
            table.append(text)
        lines.append(json.dumps({**item, "want": index[text]}, sort_keys=True,
                                separators=(",", ":"), ensure_ascii=True))
    body = ('{"cases":[\n' + ",\n".join(lines) + '\n],\n"wants":[\n' + ",\n".join(table)
            + "\n]}\n")
    return gzip.compress(body.encode(), compresslevel=9, mtime=0)


def unpack() -> list[dict[str, Any]]:
    stored = json.loads(gzip.decompress(FIXTURE.read_bytes()))
    return [{**item, "want": stored["wants"][item["want"]]} for item in stored["cases"]]


def test_the_go_member_cases_are_what_python_answers() -> None:
    if os.environ.get("AEV_WRITE_DONE_MEMBERS") == "1":
        FIXTURE.write_bytes(pack(selected()))
    stored = unpack()
    contexts = {json.dumps(item, sort_keys=True): context for item, context in variants()}
    assert len(stored) > 1000
    for item in stored:
        key = {name: value for name, value in item.items() if name != "want"}
        context = contexts.get(json.dumps(key, sort_keys=True))
        assert context is not None, f"{key} is no longer a change this file makes"
        assert answer(item, context) == item["want"], (
            f"{key}: the Python reader no longer answers as corpora/testdata/done-members.json.gz "
            "says; regenerate it with AEV_WRITE_DONE_MEMBERS=1")
