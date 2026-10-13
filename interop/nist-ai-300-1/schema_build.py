"""Turn the rule model into JSON Schema (draft 2020-12).

Every rule becomes one entry of the schema's top-level ``allOf``, tagged
``"$comment": "rule:<id>"`` so the checker can find it, delete it, or drop its
condition. A conditional rule is ``{"if": <condition>, "then": <requirement>}``;
an unconditional one is the requirement alone. A requirement on a subfield is
written through ``properties`` all the way down, so it only bites where the
parent is present: the rows-as-printed reading.
"""

from __future__ import annotations

from typing import Any

from model import Rule, chain, is_starred, parent_of

DIALECT = "https://json-schema.org/draft/2020-12/schema"
STARRED_KEY = r"-\(\*\)$"

DEFS: dict[str, Any] = {
    "fieldMap": {
        "type": "object",
        "patternProperties": {
            STARRED_KEY: {"type": "array", "minItems": 1, "items": {"$ref": "#/$defs/field"}}
        },
        "additionalProperties": {"$ref": "#/$defs/field"},
    },
    "field": {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "content": True,
            "subfields": {"$ref": "#/$defs/fieldMap"},
        },
        "additionalProperties": False,
    },
    "populatedMap": {
        "patternProperties": {STARRED_KEY: {"items": {"$ref": "#/$defs/populated"}}},
        "additionalProperties": {"$ref": "#/$defs/populated"},
    },
    "populated": {
        "anyOf": [
            {
                "required": ["content"],
                "properties": {"content": {"not": {"enum": [None, "", [], {}]}}},
            },
            {"required": ["subfields"], "properties": {"subfields": {"minProperties": 1}}},
        ],
        "properties": {"subfields": {"$ref": "#/$defs/populatedMap"}},
    },
}


def wrap(key: str, inner: dict[str, Any], strict: bool) -> dict[str, Any]:
    """Apply ``inner`` to the field object(s) stored under ``key`` in a map."""
    value = {"items": inner} if is_starred(key) else inner
    out: dict[str, Any] = {"properties": {key: value}}
    if strict:
        out["required"] = [key]
    return out


def at_path(path: list[str], inner: dict[str, Any], strict: bool = False) -> dict[str, Any]:
    """A root-level schema applying ``inner`` to every field object at ``path``.

    With ``strict`` every step must exist; without it a missing step makes the
    schema hold vacuously, which is what confines a rule to present parents.
    """
    schema: dict[str, Any] = inner
    for depth in range(len(path) - 1, -1, -1):
        mapped = wrap(path[depth], schema, strict)
        if depth == 0:
            return _fields(mapped, strict)
        schema = {"properties": {"subfields": mapped}}
        if strict:
            schema["required"] = ["subfields"]
    return _fields(inner, strict)


def _fields(mapped: dict[str, Any], strict: bool) -> dict[str, Any]:
    out: dict[str, Any] = {"properties": {"fields": mapped}}
    if strict:
        out["required"] = ["fields"]
    return out


def requirement(rule: Rule) -> dict[str, Any]:
    """The schema that holds when the rule's field is present where it must be."""
    parent = parent_of(rule.field)
    if parent is None:
        return {"properties": {"fields": {"required": [rule.field]}}}
    target = {"required": ["subfields"], "properties": {"subfields": {"required": [rule.field]}}}
    return at_path(chain(parent), target)


def condition(rule: Rule) -> dict[str, Any]:
    """The schema that holds when the rule's condition holds."""
    if rule.entries_at_least:
        starred = parent_of(rule.field) or ""
        grandparent = parent_of(starred)
        inner = {
            "required": [starred],
            "properties": {starred: {"minItems": rule.entries_at_least}},
        }
        if grandparent is None:
            return {"required": ["fields"], "properties": {"fields": inner}}
        target = {"required": ["subfields"], "properties": {"subfields": inner}}
        return at_path(chain(grandparent), target, strict=True)
    tests = [
        {
            "required": ["conditions"],
            "properties": {"conditions": {"required": [k], "properties": {k: {"const": True}}}},
        }
        for k in rule.when
    ]
    return tests[0] if len(tests) == 1 else {"anyOf": tests}


def rule_schema(rule: Rule) -> dict[str, Any]:
    """One ``allOf`` entry."""
    head: dict[str, Any] = {"$comment": f"rule:{rule.id}"}
    if rule.kind == "conforms-to":
        return {**head, "properties": {"conformsTo": {"const": rule.value}}}
    if rule.kind == "populated":
        return {**head, "properties": {"fields": {"$ref": "#/$defs/populatedMap"}}}
    if rule.kind == "declare":
        return {
            **head,
            "required": ["conditions"],
            "properties": {"conditions": {"required": [rule.value]}},
        }
    if rule.conditional:
        return {**head, "if": condition(rule), "then": requirement(rule)}
    return {**head, **requirement(rule)}


def build(title: str, rules: list[Rule], level: str) -> dict[str, Any]:
    """The whole schema for one table at one level."""
    wanted = ("required",) if level == "required" else ("required", "recommended")
    return {
        "$schema": DIALECT,
        "title": title,
        "$comment": "Generated by gen_vectors.py from templates.json and readings.json. "
        "Do not edit by hand.",
        "type": "object",
        "required": ["conformsTo", "fields"],
        "additionalProperties": False,
        "properties": {
            "conformsTo": {"type": "string"},
            "conditions": {"type": "object", "additionalProperties": {"type": "boolean"}},
            "fields": {"$ref": "#/$defs/fieldMap"},
        },
        "allOf": [rule_schema(r) for r in rules if r.level in wanted],
        "$defs": DEFS,
    }
