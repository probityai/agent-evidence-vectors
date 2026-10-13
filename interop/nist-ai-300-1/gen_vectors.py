"""Generate the NIST AI 300-1 serialization, schemas and test set from the PDF.

Reads source/NIST.AI.300-1.ipd.pdf through extract.py and the hand-written
readings.json, and writes templates.json, schemas/, members/, MANIFEST.json and
INDEX.md. Running it twice writes the same bytes. It refuses, rather than
guesses, when the PDF or the readings do not say what it expects.

    uv run --extra dev python interop/nist-ai-300-1/gen_vectors.py
"""

from __future__ import annotations

import copy
import json
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pymupdf  # type: ignore[import-untyped]  # see extract.py

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import extract as X  # noqa: E402
import schema_build  # noqa: E402
from model import Rule, chain, parent_of, violations  # noqa: E402

PDF = HERE / "source" / "NIST.AI.300-1.ipd.pdf"
SOURCE = {
    "path": "source/NIST.AI.300-1.ipd.pdf",
    "title": "NIST AI 300-1 ipd, Guidance and Templates for Public-Facing AI Documentation"
    " (initial public draft)",
    "url": "https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.300-1.ipd.pdf",
    "doi": "10.6028/NIST.AI.300-1.ipd",
    "capturedAt": "2026-10-13T03:31:44Z",
}
# The digest of the PDF this corpus was built from; the generator refuses any other bytes.
SOURCE_SHA256 = "d38f4ce07d398a6c6762fee6472b3d741da45bd446ea5d163a66da73cae9777e"
HEAD_BASE = (
    "ID",
    "Root Field Name",
    "Description",
    "Designation",
    "Additional Guidance and Requirements",
)
HEAD_PROFILE = (
    "ID",
    "Field Name",
    "Description",
    "Designation",
    "Additional Guidance and Requirements",
)
TABLES = (
    X.TableSpec("table-1", "Table 1: Dataset documentation template", (23, 24), HEAD_BASE),
    X.TableSpec("table-2", "Table 2: Model documentation template", (25, 26, 27), HEAD_BASE),
    X.TableSpec(
        "table-a.2.1", "Table A.2.1: Default AI dataset profile", tuple(range(32, 42)), HEAD_PROFILE
    ),
    X.TableSpec(
        "table-a.3.1", "Table A.3.1: Default AI model profile", tuple(range(43, 54)), HEAD_PROFILE
    ),
)
META: dict[str, dict[str, str]] = {
    "table-1": {
        "clause": "5.2",
        "template": "dataset",
        "conformsTo": "NIST.AI.300-1.ipd:5.2",
        "prefix": "T1",
    },
    "table-2": {
        "clause": "5.3",
        "template": "model",
        "conformsTo": "NIST.AI.300-1.ipd:5.3",
        "prefix": "T2",
    },
    "table-a.2.1": {"clause": "A.2", "template": "dataset", "base": "table-1", "prefix": "A21"},
    "table-a.3.1": {"clause": "A.3", "template": "model", "base": "table-2", "prefix": "A31"},
}
CLAUSES = (
    X.ClauseSpec("clause-5.1", (21, "5.1 General"), (23, "5.2 Dataset documentation template")),
    X.ClauseSpec("clause-6", (28, "6 Profiles"), (30, "A Default profiles")),
    X.ClauseSpec("clause-a.1", (30, "A.1 General"), (31, "A.2 Default AI dataset profile")),
    X.ClauseSpec("clause-a.2", (31, "A.2 Default AI dataset profile"), (32, TABLES[2].title)),
    X.ClauseSpec("clause-a.3", (42, "A.3 Default AI Model Profile"), (43, TABLES[3].title)),
)
# Every ruled box in the draft that is not one of TABLES is a note to reviewers
# (page, and how its text starts); the one on page 22 continues the note on page 21.
# None of them carries a field, so none is serialized.
REVIEWER_NOTES = (
    (7, "NOTE TO REVIEWERS"),
    (10, "NOTE FOR REVIEWERS"),
    (10, "NOTE FOR REVIEWERS"),
    (21, "NOTE TO REVIEWERS"),
    (22, "• If yes, whether to provide"),
    (30, "NOTE TO REVIEWERS"),
    (30, "NOTE TO REVIEWERS"),
)
DESIGNATIONS = {
    "Required": "required",
    "Recommended": "recommended",
    "Optional": "optional",
    "Conditionally required": "conditionally-required",
    "Conditionally recommended": "conditionally-recommended",
    "Conditionally required if parent is populated": "conditionally-required",
}
VERDICT = {"required": ("valid", "invalid"), "recommended": ("met", "unmet")}
EXPECT_KEY = {"required": "conformance", "recommended": "recommended"}


class Refusal(Exception):
    """The PDF or the readings do not say what the generator needs them to."""


def refuse(message: str) -> Refusal:
    """Build the exception the generator raises instead of guessing."""
    return Refusal(message)


# ---------------------------------------------------------------- transcript


def transcript(pdf: Path) -> dict[str, Any]:
    """Every table row and every governing clause, as the PDF prints them."""
    doc = X.open_pdf(pdf)
    tables = {spec.key: X.extract_table(doc, spec) for spec in TABLES}
    clauses = {spec.key: X.clause_text(doc, spec) for spec in CLAUSES}
    return {"tables": tables, "clauses": clauses, "census": X.census(doc)}


def census_failures(tr: dict[str, Any]) -> list[str]:
    """Where the census of the whole PDF and the tables this corpus reads disagree."""
    found = tr["census"]
    titles = {spec.title: spec for spec in TABLES}
    out: list[str] = []
    notes = [(b["page"], b["first"]) for b in found["ruled"] if b["first"] not in titles]
    declared = list(REVIEWER_NOTES)
    if len(notes) != len(declared) or any(
        page != want_page or not first.startswith(want)
        for (page, first), (want_page, want) in zip(notes, declared, strict=False)
    ):
        out.append(
            f"census: the ruled boxes that are none of the {len(TABLES)} tables are "
            f"{notes}, not the {len(declared)} notes to reviewers"
        )
    for spec in TABLES:
        boxes = [b for b in found["ruled"] if b["first"] == spec.title]
        if [b["page"] for b in boxes] != list(spec.pages):
            out.append(
                f"census: {spec.key} is ruled on pages {[b['page'] for b in boxes]}, "
                f"not {list(spec.pages)}"
            )
        captioned = [c["page"] for c in found["captions"] if c["title"] == spec.title]
        if captioned != list(spec.pages):
            out.append(f"census: {spec.key} is captioned on pages {captioned}")
        cells = [i for b in boxes for i in b["ids"]]
        printed = [r["id"] for r in tr["tables"][spec.key]]
        if cells != printed:
            out.append(
                f"census: {spec.key} has {len(cells)} rows by its cell grid and "
                f"{len(printed)} by extract.py: {sorted(set(cells) ^ set(printed))}"
            )
    for cap in found["captions"]:
        if cap["title"] not in titles:
            out.append(
                f"census: page {cap['page']} captions a table this corpus does not read: "
                f"{cap['title']!r}"
            )
    return out


def census_summary(tr: dict[str, Any]) -> dict[str, int]:
    """The counts the completeness claim rests on."""
    found = tr["census"]
    titles = {spec.title for spec in TABLES}
    tables = [b for b in found["ruled"] if b["first"] in titles]
    return {
        "pages": found["pages"],
        "ruledBoxes": len(found["ruled"]),
        "captionLines": len(found["captions"]),
        "tables": len({b["first"] for b in tables}),
        "tablePages": len(tables),
        "reviewerNotes": len(found["ruled"]) - len(tables),
        "rows": sum(len(b["ids"]) for b in tables),
    }


def bindings(tr: dict[str, Any]) -> dict[str, Any]:
    """The digest of every table and clause the test set rests on."""
    out: dict[str, Any] = {}
    for spec in TABLES:
        rows = tr["tables"][spec.key]
        pages = sorted({p for r in rows for p in r["pages"]})
        out[spec.key] = {
            "kind": "table",
            "title": spec.title,
            "pages": pages,
            "rows": len(rows),
            "sha256": X.table_digest(rows),
        }
    for cspec in CLAUSES:
        text = tr["clauses"][cspec.key]
        out[cspec.key] = {
            "kind": "clause",
            "heading": cspec.start[1],
            "pages": list(range(cspec.start[0], cspec.end[0] + 1)),
            "sha256": X.sha256_text(text),
        }
    return out


# ---------------------------------------------------------------- readings


@dataclass
class Table:
    """One table: its printed rows, its reading, and the rules they give."""

    key: str
    rows: list[dict[str, Any]]
    reading: dict[str, Any]
    rules: list[Rule] = field(default_factory=list)

    @property
    def prefix(self) -> str:
        return META[self.key]["prefix"]

    def row(self, field_id: str) -> dict[str, Any]:
        for r in self.rows:
            if r["id"] == field_id:
                return r
        raise refuse(f"{self.key}: no row {field_id}")

    @property
    def conditions(self) -> list[str]:
        return sorted(self.reading.get("conditions", {}))


def designation_of(table: Table, row: dict[str, Any]) -> str:
    """The designation class of a row, reading a transposed row from its Description cell."""
    note = table.reading.get("rows", {}).get(row["id"], {})
    printed = row["description"] if "transposed" in note else row["designation"]
    if printed not in DESIGNATIONS:
        raise refuse(
            f"{table.key} {row['id']}: designation {printed!r} is not one the draft defines"
        )
    return DESIGNATIONS[printed]


def quoted(table: Table, field_id: str, text: str) -> str:
    """Refuse unless ``text`` is printed in the row's guidance cell."""
    if text not in table.row(field_id)["guidance"]:
        raise refuse(f"{table.key} {field_id}: {text!r} is not in the printed guidance")
    return text


def resolve_keys(
    table: Table, field_id: str, level: str, seen: tuple[str, ...] = ()
) -> tuple[str, ...]:
    """The declared conditions under which a row is designated at ``level``."""
    if field_id in seen:
        raise refuse(f"{table.key} {field_id}: pointer cycle")
    note = table.reading.get("rows", {}).get(field_id)
    row = table.row(field_id)
    if note is None or designation_of(table, row) != f"conditionally-{level}":
        raise refuse(f"{table.key} {field_id}: pointed at, but not conditionally {level}")
    if "when" in note:
        return (note["when"],)
    if "see" in note:
        keys = [
            k
            for target in note["see"]
            for k in resolve_keys(table, target, level, (*seen, field_id))
        ]
        return tuple(dict.fromkeys(keys))
    raise refuse(f"{table.key} {field_id}: pointed at, but carries no condition that resolves")


def check_condition_quote(table: Table, field_id: str, key: str, text: str) -> None:
    """Refuse unless the row's quoted text contains one of the condition's phrases."""
    phrases = table.reading["conditions"].get(key)
    if not phrases or not any(p in text for p in phrases):
        raise refuse(f"{table.key} {field_id}: condition {key} is not stated by {text!r}")


# ---------------------------------------------------------------- rules


def binds_for(table: Table) -> tuple[str, ...]:
    """What a field rule in this table rests on."""
    if "base" in META[table.key]:
        return (table.key, "clause-6")
    return (table.key, "clause-5.1")


def field_rules(table: Table) -> list[Rule]:
    """Every field rule a table states, in table order."""
    out: list[Rule] = []
    for row in table.rows:
        out.extend(rules_for_row(table, row))
    return out


def rules_for_row(table: Table, row: dict[str, Any]) -> list[Rule]:
    """The rules one row states."""
    fid = row["id"]
    cls = designation_of(table, row)
    note = table.reading.get("rows", {}).get(fid, {})
    base = {"table": table.key, "kind": "field", "field": fid, "binds": binds_for(table)}
    if cls in ("required", "recommended"):
        text = row["description"] if "transposed" in note else row["designation"]
        return [Rule(id=f"{table.key}/field-{fid}/{cls}", level=cls, text=text, **base)]
    if cls == "optional":
        return []
    return conditional_rules(table, row, cls.split("-", 1)[1], note, base)


def conditional_rules(
    table: Table, row: dict[str, Any], level: str, note: dict[str, Any], base: dict[str, Any]
) -> list[Rule]:
    """The rules of a conditionally required or recommended row."""
    fid = row["id"]
    if not note:
        raise refuse(f"{table.key} {fid}: conditional row with no reading")
    if "not_expressible" in note:
        quoted(table, fid, note["text"])
        return []
    text = quoted(table, fid, note["text"])
    explicit = row["designation"].endswith("if parent is populated")
    out = [main_rule(table, fid, level, note, text, explicit, base)]
    other = note.get("otherwise")
    if other:
        lvl = other["level"]
        out.append(
            Rule(
                id=f"{table.key}/field-{fid}/{lvl}",
                level=lvl,
                text=quoted(table, fid, other["text"]),
                **base,
            )
        )
    return out


def main_rule(
    table: Table,
    fid: str,
    level: str,
    note: dict[str, Any],
    text: str,
    explicit: bool,
    base: dict[str, Any],
) -> Rule:
    """The rule a conditional row's own condition states."""
    rid = f"{table.key}/field-{fid}/{level}"
    if "entries_at_least" in note:
        return Rule(
            id=rid,
            level=level,
            entries_at_least=note["entries_at_least"],
            parent_guard_explicit=explicit,
            text=text,
            **base,
        )
    if "when" in note:
        check_condition_quote(table, fid, note["when"], text)
        return Rule(
            id=rid,
            level=level,
            when=(note["when"],),
            parent_guard_explicit=explicit,
            text=text,
            **base,
        )
    if "see" in note:
        keys = tuple(k for t in note["see"] for k in resolve_keys(table, t, level))
        return Rule(id=rid, level=level, when=tuple(dict.fromkeys(keys)), text=text, **base)
    raise refuse(f"{table.key} {fid}: reading names no condition")


def serialization_rules(table: Table) -> list[Rule]:
    """The rules this JSON form adds so the draft's rules can be checked."""
    conforms = META[table.key].get("conformsTo") or table.reading["conformsTo"]
    out = [
        Rule(
            id=f"{table.key}/serialization/conforms-to",
            table=table.key,
            kind="conforms-to",
            level="required",
            value=conforms,
            binds=("clause-6",),
            text="When an attestation is made that a given documentation artifact conforms to this "
            "standard, it shall indicate either conformity to the base templates from Clause 5 or "
            "conformity to a specific profile of the templates.",
        ),
        Rule(
            id=f"{table.key}/serialization/populated",
            table=table.key,
            kind="populated",
            level="required",
            binds=("clause-5.1",),
            text="If a documentation artifact includes a field from this Clause, that field "
            "shall be "
            "populated with information matching the field description and guidance.",
        ),
    ]
    for key in table.conditions:
        out.append(
            Rule(
                id=f"{table.key}/serialization/declare/{key}",
                table=table.key,
                kind="declare",
                level="required",
                value=key,
                binds=(table.key, "clause-6"),
                text="Fields may also be designated as conditionally required or conditionally "
                "recommended, in which case the profile shall clarify the relevant conditions.",
            )
        )
    return out


def check_conditions_used(table: Table) -> None:
    """Every declared condition is named by some rule, and every named one is declared."""
    used = {k for r in table.rules for k in r.when}
    declared = set(table.conditions)
    if used != declared:
        raise refuse(
            f"{table.key}: conditions declared {sorted(declared - used)} unused, "
            f"{sorted(used - declared)} undeclared"
        )


def check_profile_elevates(tables: dict[str, Table]) -> None:
    """Clause 6: a profile may elevate a root field's designation, never lower it."""
    rank = {"required": 2, "recommended": 1}
    for key, meta in META.items():
        if "base" not in meta:
            continue
        mine = {
            (r.field, r.level) for r in tables[key].rules if r.kind == "field" and not r.conditional
        }
        for rule in tables[meta["base"]].rules:
            if rule.kind != "field":
                continue
            if not any(f == rule.field and rank[lvl] >= rank[rule.level] for f, lvl in mine):
                raise refuse(f"{key}: root field {rule.field} is not at least {rule.level}")


def convention_gaps(table: Table) -> list[tuple[str, str]]:
    """Subfield rules whose parent is not designated under at least the same circumstances."""
    by_field: dict[str, list[Rule]] = {}
    for r in table.rules:
        if r.kind == "field":
            by_field.setdefault(r.field, []).append(r)
    gaps = []
    for rule in table.rules:
        parent = parent_of(rule.field) if rule.kind == "field" else None
        if parent is None or rule.parent_guard_explicit:
            continue
        if not covered(rule, by_field.get(parent, [])):
            gaps.append((rule.field, parent))
    return gaps


def covered(rule: Rule, parent_rules: list[Rule]) -> bool:
    """Whether a parent's own rules cover a subfield rule's circumstances."""
    levels = ("required",) if rule.level == "required" else ("required", "recommended")
    mine = [p for p in parent_rules if p.level in levels]
    if any(not p.conditional for p in mine):
        return True
    return bool(rule.when) and set(rule.when) <= {k for p in mine for k in p.when}


def check_gaps_recorded(table: Table, ambiguities: list[dict[str, Any]]) -> None:
    """Every convention gap is named in readings.json by its subfield or its parent."""
    named = {a.get("row") for a in ambiguities if a.get("where") == table.key}
    for child, parent in convention_gaps(table):
        if child not in named and parent not in named:
            raise refuse(
                f"{table.key}: {child} under {parent} breaks the Clause 6 convention "
                "and no ambiguity in readings.json names it"
            )


def build_tables(tr: dict[str, Any], readings: dict[str, Any]) -> dict[str, Table]:
    """Tables with their rules, every reading checked against the printed rows."""
    tables = {}
    for spec in TABLES:
        t = Table(spec.key, tr["tables"][spec.key], readings["tables"].get(spec.key, {}))
        for fid in t.reading.get("rows", {}):
            t.row(fid)
        for row in t.rows:
            parent = parent_of(row["id"])
            if parent is not None:
                t.row(parent)
        t.rules = field_rules(t) + serialization_rules(t)
        check_conditions_used(t)
        check_gaps_recorded(t, readings["ambiguities"])
        tables[spec.key] = t
    check_profile_elevates(tables)
    return tables


# ---------------------------------------------------------------- artifacts


def content_for(row: dict[str, Any]) -> str:
    """Placeholder content: the field's printed name, so a reader can see what each member holds."""
    return f"Example {row['name']}."


def render(table: Table, present: set[str], true_keys: frozenset[str]) -> dict[str, Any]:
    """An artifact holding exactly the fields in ``present``, one entry per starred field."""
    fields: dict[str, Any] = {}
    nodes: dict[str, dict[str, Any]] = {}
    for row in table.rows:
        fid = row["id"]
        if fid not in present:
            continue
        node: dict[str, Any] = {"name": row["name"], "content": content_for(row)}
        parent = parent_of(fid)
        if parent is not None and parent not in present:
            raise refuse(f"{table.key}: {fid} rendered without its parent {parent}")
        home = fields if parent is None else nodes[parent].setdefault("subfields", {})
        home[fid] = [node] if fid.endswith("-(*)") else node
        nodes[fid] = node
    artifact: dict[str, Any] = {"conformsTo": serialization_rules(table)[0].value}
    if table.conditions:
        artifact["conditions"] = {k: k in true_keys for k in table.conditions}
    artifact["fields"] = fields
    return artifact


def every_field(table: Table) -> set[str]:
    return {r["id"] for r in table.rows}


def without(table: Table, present: set[str], fid: str) -> set[str]:
    """``present`` minus a field and everything under it."""
    return {f for f in present if fid not in chain(f)}


def closure(table: Table, level: str, true_keys: frozenset[str], seed: set[str]) -> set[str]:
    """The fewest fields that meet every rule at ``level`` under both readings."""
    wanted = ("required",) if level == "required" else ("required", "recommended")
    present = {a for f in seed for a in chain(f)}
    changed = True
    while changed:
        changed = False
        for rule in table.rules:
            if rule.kind != "field" or rule.level not in wanted or rule.entries_at_least:
                continue
            if rule.when and not set(rule.when) & true_keys:
                continue
            need = set(chain(rule.field)) - present
            if need:
                present |= need
                changed = True
    return present


# ---------------------------------------------------------------- members


@dataclass
class Member:
    """One test document and what it exercises."""

    artifact: dict[str, Any]
    roles: list[dict[str, str]]
    why: str
    name: str


def member_id(table: Table, role: str, rule: Rule, extra: str = "") -> str:
    """A readable, stable identifier: table, role, field or rule, level."""
    tail = rule.id.split("/", 1)[1].removeprefix("field-").replace("(*)", "x").replace("/", "-")
    return f"{table.prefix}-{role}-{tail}{extra}"


def field_members(table: Table, rule: Rule) -> list[Member]:
    """The members one field rule needs."""
    if rule.entries_at_least:
        return entries_members(table, rule)
    full = every_field(table)
    keys = rule.when or ("",)
    out = []
    for key in keys:
        held = frozenset({key}) if key else frozenset()
        art = render(table, without(table, full, rule.field), held)
        cond = (
            f" while {key} holds"
            if key
            else (", and no condition holds" if table.conditions else "")
        )
        out.append(
            Member(
                art,
                [{"rule": rule.id, "role": "violates"}],
                f"Every field but {rule.field}{cond}.",
                member_id(table, "violates", rule, _k(key, rule)),
            )
        )
    if not rule.conditional:
        return out
    art = render(table, without(table, full, rule.field), frozenset())
    out.append(
        Member(
            art,
            [{"rule": rule.id, "role": "inapplicable"}],
            f"Every field but {rule.field}, and no condition holds.",
            member_id(table, "inapplicable", rule),
        )
    )
    for key in rule.when:
        held = frozenset({key})
        present = closure(table, rule.level, held, {rule.field})
        out.append(
            Member(
                render(table, present, held),
                [{"rule": rule.id, "role": "satisfies"}],
                f"Only {key} holds; the fields it makes {rule.level} are present, "
                f"{rule.field} among them.",
                member_id(table, "satisfies", rule, _k(key, rule)),
            )
        )
    return out


def _k(key: str, rule: Rule) -> str:
    return f"-{key}" if key and len(rule.when) > 1 else ""


def entries_members(table: Table, rule: Rule) -> list[Member]:
    """Members for a rule whose condition is the number of entries of a starred field."""
    starred = parent_of(rule.field) or ""
    full = render(table, every_field(table), frozenset())
    entry = entries_of(full, starred)[0]
    two = copy.deepcopy(full)
    second = copy.deepcopy(entry)
    second["subfields"].pop(rule.field)
    entries_of(two, starred).append(second)
    one = copy.deepcopy(full)
    entries_of(one, starred)[0]["subfields"].pop(rule.field)
    present = closure(table, rule.level, frozenset(), {rule.field})
    ok = render(table, present, frozenset())
    entries_of(ok, starred).append(copy.deepcopy(entries_of(ok, starred)[0]))
    n = rule.entries_at_least
    return [
        Member(
            two,
            [{"rule": rule.id, "role": "violates"}],
            f"{starred} has {n} entries and the second lacks {rule.field}.",
            member_id(table, "violates", rule),
        ),
        Member(
            one,
            [{"rule": rule.id, "role": "inapplicable"}],
            f"{starred} has one entry, which lacks {rule.field}.",
            member_id(table, "inapplicable", rule),
        ),
        Member(
            ok,
            [{"rule": rule.id, "role": "satisfies"}],
            f"{starred} has {n} entries, each with {rule.field}.",
            member_id(table, "satisfies", rule),
        ),
    ]


def entries_of(artifact: dict[str, Any], starred: str) -> list[dict[str, Any]]:
    """The entry list of a starred field, in an artifact with one instance of its parent."""
    path = chain(starred)
    node: Any = {"subfields": artifact["fields"]}
    for key in path[:-1]:
        node = node["subfields"][key]
        node = node[0] if isinstance(node, list) else node
    found = node["subfields"][starred]
    assert isinstance(found, list)
    return found


def serialization_members(table: Table, rule: Rule) -> list[Member]:
    """The one member each serialization rule needs."""
    art = render(table, every_field(table), frozenset())
    if rule.kind == "conforms-to":
        other = (
            "NIST.AI.300-1.ipd:5.3"
            if META[table.key]["template"] == "dataset"
            else "NIST.AI.300-1.ipd:5.2"
        )
        art["conformsTo"] = other
        why = f"Every field, but conformsTo names {other}."
    elif rule.kind == "populated":
        leaf = last_leaf(art["fields"])
        leaf["content"] = ""
        why = f"Every field, but {leaf['name']} is present and empty."
    else:
        del art["conditions"][rule.value]
        why = f"Every field, but the condition {rule.value} is not declared."
    return [
        Member(
            art, [{"rule": rule.id, "role": "violates"}], why, member_id(table, "violates", rule)
        )
    ]


def last_leaf(fields: dict[str, Any]) -> dict[str, Any]:
    """The last field object in a map with no subfields."""
    node: Any = list(fields.values())[-1]
    node = node[-1] if isinstance(node, list) else node
    while node.get("subfields"):
        node = list(node["subfields"].values())[-1]
        node = node[-1] if isinstance(node, list) else node
    assert isinstance(node, dict)
    return node


def controls(table: Table) -> list[Member]:
    """Whole-table members with no role: every field, and the fewest fields."""
    keys = frozenset(table.conditions)
    full = every_field(table)
    first = "Every field, and no condition holds." if keys else "Every field."
    out = [
        Member(render(table, full, frozenset()), [], first, f"{table.prefix}-control-every-field")
    ]
    if keys:
        out.append(
            Member(
                render(table, full, keys),
                [],
                "Every field, and every condition holds.",
                f"{table.prefix}-control-every-field-every-condition",
            )
        )
    least = closure(table, "required", frozenset(), set())
    out.append(
        Member(
            render(table, least, frozenset()),
            [],
            "Only the unconditionally required fields.",
            f"{table.prefix}-control-required-only",
        )
    )
    return out


def candidates(table: Table) -> list[Member]:
    out: list[Member] = []
    for rule in table.rules:
        out.extend(
            field_members(table, rule)
            if rule.kind == "field"
            else serialization_members(table, rule)
        )
    return out + controls(table)


def merged(members: list[Member]) -> list[Member]:
    """One member per distinct document, carrying every role that landed on it."""
    by_bytes: dict[str, Member] = {}
    for m in members:
        key = X.canonical(m.artifact)
        if key in by_bytes:
            kept = by_bytes[key]
            kept.roles.extend(r for r in m.roles if r not in kept.roles)
            kept.why = kept.why if m.why in kept.why else f"{kept.why} {m.why}"
        else:
            by_bytes[key] = m
    return list(by_bytes.values())


# ---------------------------------------------------------------- verdicts


def verdicts(table: Table, member: Member) -> tuple[dict[str, Any], dict[str, list[str]]]:
    """Expected verdict per level, and any level the two readings disagree on."""
    expected: dict[str, Any] = {}
    dependent: dict[str, list[str]] = {}
    for level in ("required", "recommended"):
        printed = violations(table.rules, member.artifact, level)
        closed = violations(table.rules, member.artifact, level, closed=True)
        ok, bad = VERDICT[level]
        if bool(printed) == bool(closed):
            expected[EXPECT_KEY[level]] = bad if printed else ok
        else:
            expected[EXPECT_KEY[level]] = None
            dependent[EXPECT_KEY[level]] = sorted(closed ^ printed)
    return expected, dependent


def check_roles(table: Table, member: Member) -> None:
    """Refuse a member whose role its own violations do not bear out."""
    by_id = {r.id: r for r in table.rules}
    for role in member.roles:
        rule = by_id[role["rule"]]
        got = violations(table.rules, member.artifact, rule.level)
        if role["role"] == "violates" and got != {rule.id}:
            raise refuse(f"{member.name}: violates {rule.id} but breaks {sorted(got)}")
        if role["role"] in ("inapplicable", "satisfies") and got:
            raise refuse(f"{member.name}: {role['role']} {rule.id} but breaks {sorted(got)}")
        if role["role"] == "inapplicable":
            swapped = [rule.unconditional() if r.id == rule.id else r for r in table.rules]
            if violations(swapped, member.artifact, rule.level) != {rule.id}:
                raise refuse(
                    f"{member.name}: dropping {rule.id}'s condition does not break it alone"
                )


def check_coverage(table: Table, members: list[Member]) -> None:
    """Every rule has a member that breaks it; every conditional rule all three kinds."""
    have = {(r["rule"], r["role"]) for m in members for r in m.roles}
    for rule in table.rules:
        needed = ["violates"] + (["inapplicable", "satisfies"] if rule.conditional else [])
        for role in needed:
            if (rule.id, role) not in have:
                raise refuse(f"{rule.id}: no member {role} it")


# ---------------------------------------------------------------- output


def write_json(path: Path, value: Any) -> str:
    """Write JSON with a trailing newline; return the SHA-256 of the bytes written."""
    data = (json.dumps(value, ensure_ascii=False, indent=1) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return X.sha256_text(data.decode("utf-8"))


def templates_doc(tables: dict[str, Table], tr: dict[str, Any]) -> dict[str, Any]:
    """templates.json: every printed row, its designation class and reading, and the clauses."""
    out: dict[str, Any] = {
        "about": "Every row of Clause 5 Tables 1 and 2 and Annex A Tables A.2.1 and A.3.1 of "
        "NIST AI 300-1 ipd, cell by cell as the PDF prints them (see extract.py for the "
        "extraction), with the designation class each row's Designation cell names and the "
        "reading of each conditional row from readings.json. "
        "Pages are 1-based PDF page indexes. Generated by gen_vectors.py.",
        "source": source_doc(),
        "designations": DESIGNATIONS,
        "tables": {},
        "clauses": {},
    }
    for spec in TABLES:
        t = tables[spec.key]
        out["tables"][spec.key] = {
            "title": spec.title,
            "clause": META[spec.key]["clause"],
            "template": META[spec.key]["template"],
            "columns": list(spec.header),
            "fields": [field_doc(t, row) for row in t.rows],
        }
    for cspec in CLAUSES:
        out["clauses"][cspec.key] = {"heading": cspec.start[1], "text": tr["clauses"][cspec.key]}
    return out


def field_doc(table: Table, row: dict[str, Any]) -> dict[str, Any]:
    """One row of templates.json."""
    doc: dict[str, Any] = {k: row[k] for k in X.COLUMNS}
    doc["pages"] = row["pages"]
    doc["parent"] = parent_of(row["id"])
    doc["designationClass"] = designation_of(table, row)
    note = table.reading.get("rows", {}).get(row["id"])
    if note:
        doc["reading"] = note
    return doc


def source_doc() -> dict[str, Any]:
    return {**SOURCE, "bytes": PDF.stat().st_size, "sha256": X.sha256_file(PDF)}


def write_index(path: Path, entries: list[dict[str, Any]]) -> None:
    lines = [
        "# Members",
        "",
        "Generated by gen_vectors.py from MANIFEST.json. Do not edit by hand.",
        "",
        "`violates`: the member breaks this rule alone, so deleting the rule from the schema "
        "flips its verdict.",
        "`inapplicable`: the field is absent and the condition does not hold, so dropping the "
        "condition flips it.",
        "`satisfies`: the condition holds and the field is present. A blank verdict depends on "
        "a reading the "
        "draft leaves open (see README.md).",
        "",
        "| id | table | conformance | recommended | roles | case |",
        "|---|---|---|---|---|---|",
    ]
    for e in entries:
        roles = "<br>".join(f"{r['role']} `{r['rule']}`" for r in e["roles"]) or "control"
        exp = e["expected"]
        lines.append(
            f"| [{e['id']}]({e['file']}) | {e['table']} | {exp['conformance'] or ''} | "
            f"{exp['recommended'] or ''} | {roles} | {e['why']} |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def not_expressible(
    tables: dict[str, Table], tr: dict[str, Any], readings: dict[str, Any]
) -> list[dict[str, Any]]:
    """Every rule the draft states that no schema here can check, each quoted."""
    out = []
    for key, t in tables.items():
        for fid, note in t.reading.get("rows", {}).items():
            if "not_expressible" in note:
                out.append(
                    {
                        "where": key,
                        "row": fid,
                        "quote": note["text"],
                        "reason": note["not_expressible"],
                    }
                )
    for item in readings["not_expressible"]:
        check_quote(item, tables, tr)
        out.append(item)
    return out


def check_quote(item: dict[str, Any], tables: dict[str, Table], tr: dict[str, Any]) -> None:
    """Refuse an ambiguity, observation or limit whose quote is not printed where it says."""
    where, quote = item["where"], item["quote"]
    if where in tables:
        rows = [tables[where].row(item["row"])] if "row" in item else tables[where].rows
        hay = " ".join(r[c] for r in rows for c in X.COLUMNS)
    else:
        hay = tr["clauses"][where]
    if quote not in hay:
        raise refuse(f"{item.get('id', where)}: {quote!r} is not printed in {where}")


def main() -> int:
    if X.sha256_file(PDF) != SOURCE_SHA256:
        raise refuse(f"{PDF.name} is not the PDF this corpus binds to ({SOURCE_SHA256})")
    readings = json.loads((HERE / "readings.json").read_text(encoding="utf-8"))
    tr = transcript(PDF)
    missed = census_failures(tr)
    if missed:
        raise refuse("; ".join(missed))
    tables = build_tables(tr, readings)
    for item in readings["ambiguities"] + readings["observations"]:
        check_quote(item, tables, tr)
    limits = not_expressible(tables, tr, readings)
    for sub in ("members", "schemas"):
        shutil.rmtree(HERE / sub, ignore_errors=True)
    write_json(HERE / "templates.json", templates_doc(tables, tr))
    entries: list[dict[str, Any]] = []
    table_docs: dict[str, Any] = {}
    for spec in TABLES:
        t = tables[spec.key]
        table_docs[spec.key] = write_schemas(t, spec.title)
        entries.extend(write_members(t))
    manifest = {
        "corpus": "nist-ai-300-1",
        "about": "A JSON serialization of the Clause 5 templates and Annex A default profiles "
        "of NIST AI 300-1 ipd, a JSON Schema per template and profile at two levels, and test "
        "documents for every rule, bound "
        "by digest to the PDF and to the extracted text of every table and clause they test.",
        "source": source_doc(),
        "extraction": {
            "tool": "PyMuPDF",
            "version": pymupdf.VersionBind,
            "mupdf": pymupdf.VersionFitz,
            "module": "extract.py",
        },
        "bindings": bindings(tr),
        "census": census_summary(tr),
        "tables": table_docs,
        "notExpressible": limits,
        "ambiguities": readings["ambiguities"],
        "observations": readings["observations"],
        "members": entries,
    }
    write_json(HERE / "MANIFEST.json", manifest)
    write_index(HERE / "INDEX.md", entries)
    print(f"wrote {len(entries)} members over {sum(len(t.rules) for t in tables.values())} rules")
    return 0


def write_schemas(table: Table, title: str) -> dict[str, Any]:
    """Write a table's two schemas; return its MANIFEST entry."""
    files = {}
    for level, name in (("required", "conformance"), ("recommended", "recommended")):
        rel = f"schemas/{table.key}.{name}.schema.json"
        write_json(HERE / rel, schema_build.build(f"{title} ({name})", table.rules, level))
        files[name] = rel
    return {
        "conformsTo": serialization_rules(table)[0].value,
        "schemas": files,
        "conditions": table.conditions,
        "rules": [r.as_json() for r in table.rules],
    }


def write_members(table: Table) -> list[dict[str, Any]]:
    """Write a table's members; return their MANIFEST entries."""
    members = merged(candidates(table))
    check_coverage(table, members)
    by_id = {r.id: r for r in table.rules}
    out = []
    for m in sorted(members, key=lambda m: m.name):
        check_roles(table, m)
        expected, dependent = verdicts(table, m)
        rel = f"members/{m.name}.json"
        digest = write_json(HERE / rel, m.artifact)
        binds = sorted({b for r in m.roles for b in by_id[r["rule"]].binds} | {table.key})
        entry: dict[str, Any] = {
            "id": m.name,
            "file": rel,
            "sha256": digest,
            "table": table.key,
            "expected": expected,
            "roles": m.roles,
            "binds": binds,
            "why": m.why,
        }
        if dependent:
            entry["readingDependent"] = dependent
        out.append(entry)
    return out


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Refusal as err:
        print(f"refused: {err}", file=sys.stderr)
        raise SystemExit(1) from err
