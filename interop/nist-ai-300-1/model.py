"""The rule model shared by the generator and the checker.

A rule is one obligation the draft states about one field, at one of two
levels: ``required`` (an artifact that breaks it does not conform) and
``recommended`` (an artifact that breaks it conforms, and the recommendation is
unmet; Clause 6 says a missing recommended field leaves an attestation of
conformity valid). Serialization rules are the three this JSON form adds so that
the draft's own rules can be checked at all: name what you conform to, populate
what you include, and declare every condition the profile names.

Two evaluators live here, and neither reads a JSON Schema. ``violations`` reads
each row as printed, with a subfield's rule in force only where its parent is
present. ``violations_closed`` adds Clause 6's convention that a required (or
recommended) subfield makes its parent required (or recommended) under the same
circumstances. The generator emits an expected verdict only where the two
agree, so no member settles a question the draft leaves open.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

LEVELS = ("required", "recommended")
EMPTY: tuple[Any, ...] = (None, "", [], {})


@dataclass(frozen=True)
class Rule:
    """One obligation. ``field`` is empty for serialization rules."""

    id: str
    table: str
    kind: str  # "field", "conforms-to", "populated" or "declare"
    level: str
    field: str = ""
    when: tuple[str, ...] = ()
    entries_at_least: int = 0
    parent_guard_explicit: bool = False
    value: str = ""
    text: str = ""
    binds: tuple[str, ...] = ()

    @property
    def conditional(self) -> bool:
        """True when the rule only applies under a condition."""
        return bool(self.when) or self.entries_at_least > 0

    @classmethod
    def from_json(cls, table: str, doc: dict[str, Any]) -> Rule:
        """The rule MANIFEST.json records, read back."""
        return cls(
            id=doc["id"],
            table=table,
            kind=doc["kind"],
            level=doc["level"],
            field=doc.get("field", ""),
            when=tuple(doc.get("when", ())),
            entries_at_least=doc.get("entriesAtLeast", 0),
            parent_guard_explicit=doc.get("parentGuardExplicit", False),
            value=doc.get("value", ""),
            text=doc["text"],
            binds=tuple(doc["binds"]),
        )

    def as_json(self) -> dict[str, Any]:
        """The rule as MANIFEST.json records it."""
        out: dict[str, Any] = {"id": self.id, "kind": self.kind, "level": self.level}
        if self.field:
            out["field"] = self.field
        if self.when:
            out["when"] = list(self.when)
        if self.entries_at_least:
            out["entriesAtLeast"] = self.entries_at_least
        if self.parent_guard_explicit:
            out["parentGuardExplicit"] = True
        if self.value:
            out["value"] = self.value
        out["text"] = self.text
        out["binds"] = list(self.binds)
        return out

    def unconditional(self) -> Rule:
        """This rule with its condition removed."""
        return Rule(
            self.id,
            self.table,
            self.kind,
            self.level,
            self.field,
            (),
            0,
            self.parent_guard_explicit,
            self.value,
            self.text,
            self.binds,
        )


def is_starred(field_id: str) -> bool:
    """A field printed with a trailing ``-(*)`` takes one entry per index."""
    return field_id.endswith("-(*)")


def parent_of(field_id: str) -> str | None:
    """The printed ID of a field's parent, or None for a root field."""
    base = field_id[: -len("-(*)")] if is_starred(field_id) else field_id
    if "." not in base:
        return None
    return base.rsplit(".", 1)[0] if is_starred(field_id) else field_id.rsplit(".", 1)[0]


def chain(field_id: str) -> list[str]:
    """The field's ancestors from the root down, followed by the field itself."""
    out = [field_id]
    parent = parent_of(field_id)
    while parent is not None:
        out.append(parent)
        parent = parent_of(parent)
    return list(reversed(out))


def populated(node: Any) -> bool:
    """A field object is populated when it has non-empty content or a subfield."""
    if not isinstance(node, dict):
        return False
    content_ok = "content" in node and node["content"] not in EMPTY
    return content_ok or bool(node.get("subfields"))


def children(container: Any, key: str) -> list[dict[str, Any]]:
    """The field objects stored under ``key``: one, the entries of an array, or none."""
    if not isinstance(container, dict) or key not in container:
        return []
    value = container[key]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return [value] if isinstance(value, dict) else []


def instances(artifact: dict[str, Any], path: list[str]) -> list[dict[str, Any]]:
    """Every field object at ``path`` (root first), branching into array entries."""
    nodes = children({"x": artifact.get("fields")}, "x") if path else []
    current: list[dict[str, Any]] = []
    for depth, key in enumerate(path):
        source = nodes if depth == 0 else [n.get("subfields") or {} for n in current]
        current = [c for s in source for c in children(s, key)]
    return current


def holder(artifact: dict[str, Any], field_id: str) -> list[dict[str, Any]]:
    """The maps a field would live in: ``fields`` for a root, else each parent's subfields."""
    parent = parent_of(field_id)
    if parent is None:
        fields = artifact.get("fields")
        return [fields] if isinstance(fields, dict) else []
    return [p.get("subfields") or {} for p in instances(artifact, chain(parent))]


def condition_holds(rule: Rule, artifact: dict[str, Any], grand: dict[str, Any]) -> bool:
    """Whether a rule's condition holds. ``grand`` is the map holding the starred parent."""
    if rule.entries_at_least:
        parent = parent_of(rule.field) or ""
        return len(children(grand, parent)) >= rule.entries_at_least
    if not rule.when:
        return True
    declared = artifact.get("conditions") or {}
    return any(declared.get(key) is True for key in rule.when)


def field_rule_broken(rule: Rule, artifact: dict[str, Any], closed: bool) -> bool:
    """Whether a field rule is broken, as printed or under the parent-closure reading."""
    if rule.entries_at_least:
        return _entries_rule_broken(rule, artifact)
    if not condition_holds(rule, artifact, {}):
        return False
    missing_here = any(rule.field not in m for m in holder(artifact, rule.field))
    if closed and not rule.parent_guard_explicit:
        ancestors = chain(rule.field)[:-1]
        return missing_here or any(
            not instances(artifact, ancestors[: i + 1]) for i in range(len(ancestors))
        )
    return missing_here


def _entries_rule_broken(rule: Rule, artifact: dict[str, Any]) -> bool:
    starred = parent_of(rule.field) or ""
    grandparent = parent_of(starred)
    maps = holder(artifact, starred) if grandparent is not None else [artifact.get("fields") or {}]
    for grand in maps:
        if not condition_holds(rule, artifact, grand):
            continue
        if any(rule.field not in (e.get("subfields") or {}) for e in children(grand, starred)):
            return True
    return False


def walk(fields: Any) -> Iterator[Any]:
    """Every field object in a fields map, at every depth."""
    if not isinstance(fields, dict):
        return
    for value in fields.values():
        for node in value if isinstance(value, list) else [value]:
            yield node
            if isinstance(node, dict):
                yield from walk(node.get("subfields"))


def broken(rule: Rule, artifact: dict[str, Any], closed: bool = False) -> bool:
    """Whether an artifact breaks a rule."""
    if rule.kind == "conforms-to":
        return artifact.get("conformsTo") != rule.value
    if rule.kind == "populated":
        return not all(populated(n) for n in walk(artifact.get("fields")))
    if rule.kind == "declare":
        return rule.value not in (artifact.get("conditions") or {})
    return field_rule_broken(rule, artifact, closed)


def violations(
    rules: list[Rule], artifact: dict[str, Any], level: str, closed: bool = False
) -> set[str]:
    """Rule ids broken at a level. The recommended level carries the required rules too."""
    wanted = ("required",) if level == "required" else LEVELS
    return {r.id for r in rules if r.level in wanted and broken(r, artifact, closed)}
