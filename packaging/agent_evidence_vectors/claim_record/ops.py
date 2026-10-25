"""The two JSON edit operations the corpus uses to state a defect and its repair.

``{"op": "set", "path": [...], "value": v}`` sets an object member or replaces a
list element; ``{"op": "del", "path": [...]}`` removes an object member. A path is
a list of object keys and list indices. Removing a list element is not an
operation, so a repair can always name the exact positions it restores.
"""

from __future__ import annotations

import copy
from typing import Any

_MISSING = object()


def _parent(doc: Any, path: list[Any]) -> tuple[Any, Any]:
    if not path:
        raise ValueError("an operation names a non-empty path")
    node = doc
    for step in path[:-1]:
        node = node[step]
    return node, path[-1]


def _get(doc: Any, path: list[Any]) -> Any:
    parent, last = _parent(doc, path)
    if isinstance(parent, dict):
        return parent.get(last, _MISSING)
    return parent[last]


def apply_ops(doc: Any, ops: list[dict[str, Any]]) -> Any:
    """Return a copy of ``doc`` with ``ops`` applied in order."""
    out = copy.deepcopy(doc)
    for op in ops:
        parent, last = _parent(out, op["path"])
        if op["op"] == "set":
            parent[last] = copy.deepcopy(op["value"])
        elif op["op"] == "del":
            if not isinstance(parent, dict) or last not in parent:
                raise ValueError(f"del names no object member at {op['path']}")
            del parent[last]
        else:
            raise ValueError(f"unknown operation {op['op']!r}")
    return out


def mutate(base: Any, ops: list[dict[str, Any]]) -> tuple[Any, list[dict[str, Any]]]:
    """Apply ``ops`` to ``base``; return the result and the operations that undo them."""
    doc = copy.deepcopy(base)
    undo: list[dict[str, Any]] = []
    for op in ops:
        old = _get(doc, op["path"])
        if old is _MISSING:
            undo.append({"op": "del", "path": list(op["path"])})
        else:
            undo.append({"op": "set", "path": list(op["path"]), "value": copy.deepcopy(old)})
        doc = apply_ops(doc, [op])
    return doc, list(reversed(undo))
