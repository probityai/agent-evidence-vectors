"""Hold every published predicate schema to its pinned positive and negative counts.

A schema that is silently loosened, a dropped ``required`` entry or a widened type, still
accepts every honest record, so a suite that only checks positives never notices. This
module pairs each schema in ``spec/schemas`` with the sample records the repository holds for
it and with the mutants of those records, and pins counts per schema in
``spec/schemas/COUNTS.toml``:

* ``samples``: sample records read;
* ``positive``: samples the schema accepts;
* ``negative``: samples the schema rejects;
* ``mutants`` and ``mutants_rejected``: derived single-fault variants of every positive
  sample (each member deleted, each value replaced by one of another type) and how many of
  them the schema rejects.

The mutants are derived from the data, never from the schema, so loosening the schema can
only lower ``mutants_rejected``. Counts are exact: a schema edit that moves one is a change
to the counts file in the same commit, which is the point.
"""

from __future__ import annotations

import copy
import json
import sys
import tomllib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
COUNTS = ROOT / "spec" / "schemas" / "COUNTS.toml"
DEPTH = 6
_SWAP: dict[type, Any] = {bool: 0, int: "x", float: "x", str: 0, list: {}, dict: [], type(None): 0}


def _paths(node: Any, prefix: tuple = (), depth: int = 0) -> Iterator[tuple]:
    """Every addressable position in a document, in a fixed order."""
    yield prefix
    if depth >= DEPTH:
        return
    if isinstance(node, dict):
        for key in sorted(node):
            yield from _paths(node[key], (*prefix, key), depth + 1)
    elif isinstance(node, list):
        for index, item in enumerate(node):
            yield from _paths(item, (*prefix, index), depth + 1)


def _get(doc: Any, path: tuple) -> Any:
    for step in path:
        doc = doc[step]
    return doc


def mutants(doc: Any) -> Iterator[Any]:
    """Single-fault variants of a document: delete one member, or swap one value's type."""
    for path in _paths(doc):
        if not path:
            continue
        parent_path, last = path[:-1], path[-1]
        if isinstance(last, str):
            variant = copy.deepcopy(doc)
            del _get(variant, parent_path)[last]
            yield variant
        variant = copy.deepcopy(doc)
        _get(variant, parent_path)[last] = _SWAP[type(_get(doc, path))]
        yield variant


def _load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def samples(entry: dict) -> list[Any]:
    """The sample documents of one schema entry in path order; a file that is not an object is skipped."""
    paths = sorted(p for pattern in entry["samples"] for p in ROOT.glob(pattern))
    found = []
    for path in paths:
        doc = _load(path)
        if isinstance(doc, dict) and all(doc.get(k) == v for k, v in entry.get("where", {}).items()):
            found.append(doc)
    return found


def measure(entry: dict) -> dict[str, int]:
    schema = json.loads((ROOT / entry["schema"]).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    docs = samples(entry)
    positive = [d for d in docs if validator.is_valid(d)]
    variants = [m for d in positive for m in mutants(d)]
    rejected = sum(1 for m in variants if not validator.is_valid(m))
    return {"samples": len(docs), "positive": len(positive), "negative": len(docs) - len(positive),
            "mutants": len(variants), "mutants_rejected": rejected}


def check() -> list[str]:
    """Every disagreement between the pinned counts and the measured ones, and every unpinned schema."""
    table = tomllib.loads(COUNTS.read_text(encoding="utf-8"))["schema"]
    problems = []
    pinned = {entry["schema"] for entry in table}
    for path in sorted((ROOT / "spec" / "schemas").glob("*.schema.json")):
        rel = path.relative_to(ROOT).as_posix()
        if rel not in pinned:
            problems.append(f"{rel}: no counts are pinned for this schema")
    for entry in table:
        got = measure(entry)
        for key, value in got.items():
            if entry["expect"].get(key) != value:
                problems.append(f"{entry['schema']}: {key} is {value}, pinned {entry['expect'].get(key)}")
        if got["positive"] == 0 or got["negative"] + got["mutants_rejected"] == 0:
            problems.append(f"{entry['schema']}: needs at least one positive and one negative")
    return problems


def main() -> int:
    if "--print" in sys.argv:
        for entry in tomllib.loads(COUNTS.read_text(encoding="utf-8"))["schema"]:
            print(entry["schema"], measure(entry))
        return 0
    problems = check()
    for line in problems:
        print(line)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
