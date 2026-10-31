"""Judge the NIST AI 300-1 test set, re-derive every digest, and sweep every rule.

Exits 0 only when all of this holds:

* the PDF is the one MANIFEST.json names, by SHA-256;
* completeness, counted on the PDF itself rather than in characters: every
  ruled box on every page is either a page of one of the four tables or one of
  the seven notes to reviewers, every "Table N:" caption names one of the four,
  each table's cell grid gives the same row IDs extract.py gives, and those
  counts equal MANIFEST.json's census;
* extract.py run on that PDF gives back templates.json cell for cell and clause
  for clause, and the table and clause digests in MANIFEST.json, computed both
  from the PDF and from templates.json;
* every member file matches its recorded digest, and members/ holds nothing else;
* every member gets its expected verdict from the conformance schema and the
  recommended schema of its table (a blank verdict, which the draft leaves open,
  is skipped and must say why);
* each schema carries exactly the rules MANIFEST.json lists for its level;
* the mutation sweep: deleting any rule from its schema flips every member that
  ``violates`` it, dropping the condition of any conditional rule flips every
  member ``inapplicable`` to it, every rule has a member that violates it, and
  every conditional rule has members of all three kinds.

    uv run --extra dev python interop/nist-ai-300-1/check_vectors.py
    uv run --extra dev python interop/nist-ai-300-1/check_vectors.py --counts
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import extract as X  # noqa: E402
import gen_vectors as G  # noqa: E402
import schema_build  # noqa: E402
from model import Rule  # noqa: E402

PASS = {"conformance": "valid", "recommended": "met"}
SCHEMA_OF = {"required": "conformance", "recommended": "recommended"}
LEVEL_OF = {v: k for k, v in SCHEMA_OF.items()}


class Findings:
    """Failures collected across the run; the exit status is whether there were any."""

    def __init__(self) -> None:
        self.items: list[str] = []

    def fail(self, message: str) -> None:
        self.items.append(message)

    def check(self, ok: bool, message: str) -> None:
        if not ok:
            self.fail(message)


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- source


def check_source(
    root: Path, manifest: dict[str, Any], templates: dict[str, Any], out: Findings
) -> None:
    """The PDF's digest agrees with MANIFEST.json, templates.json and the pinned value."""
    pdf = root / manifest["source"]["path"]
    if not pdf.is_file():
        out.fail(f"source PDF missing: {pdf.name}")
        return
    digest = X.sha256_file(pdf)
    for name, want in (
        ("pinned", G.SOURCE_SHA256),
        ("MANIFEST.json", manifest["source"]["sha256"]),
        ("templates.json", templates["source"]["sha256"]),
    ):
        out.check(digest == want, f"source PDF sha256 {digest} differs from {name} {want}")


def check_transcript(
    tr: dict[str, Any], manifest: dict[str, Any], templates: dict[str, Any], out: Findings
) -> None:
    """The PDF re-extracts to templates.json, and both give MANIFEST.json's digests."""
    for key, rows in tr["tables"].items():
        printed = [
            {c: f[c] for c in (*X.COLUMNS, "pages")} for f in templates["tables"][key]["fields"]
        ]
        out.check(printed == rows, f"{key}: templates.json differs from the PDF's text")
        out.check(
            X.table_digest(printed) == manifest["bindings"][key]["sha256"],
            f"{key}: templates.json digest differs from MANIFEST.json",
        )
    for key, text in tr["clauses"].items():
        out.check(
            templates["clauses"][key]["text"] == text,
            f"{key}: templates.json differs from the PDF's text",
        )
    out.check(
        G.bindings(tr) == manifest["bindings"],
        "bindings re-derived from the PDF differ from MANIFEST.json",
    )
    for failure in G.census_failures(tr):
        out.fail(failure)
    recount = G.census_summary(tr)
    out.check(
        recount == manifest["census"],
        f"census re-counted from the PDF {recount} differs from MANIFEST.json {manifest['census']}",
    )


# ---------------------------------------------------------------- members


def check_files(root: Path, manifest: dict[str, Any], out: Findings) -> None:
    """Every member file matches its digest, and no other file sits in members/."""
    listed = {e["file"] for e in manifest["members"]}
    on_disk = {f"members/{p.name}" for p in (root / "members").glob("*")}
    out.check(listed == on_disk, f"members/ and MANIFEST.json disagree: {sorted(listed ^ on_disk)}")
    for e in manifest["members"]:
        path = root / e["file"]
        if path.is_file():
            out.check(
                X.sha256_file(path) == e["sha256"],
                f"{e['id']}: bytes differ from the recorded sha256",
            )


def verdict(validator: Draft202012Validator, instance: Any, level: str) -> str:
    ok, bad = ("valid", "invalid") if level == "conformance" else ("met", "unmet")
    return ok if validator.is_valid(instance) else bad


def check_verdicts(
    root: Path, manifest: dict[str, Any], schemas: dict[str, dict[str, Any]], out: Findings
) -> dict[str, Any]:
    """Every member against both schemas of its table; returns the loaded documents."""
    docs = {}
    validators = {
        t: {lvl: Draft202012Validator(s) for lvl, s in v.items()} for t, v in schemas.items()
    }
    for e in manifest["members"]:
        doc = load(root / e["file"])
        docs[e["id"]] = doc
        for level, want in e["expected"].items():
            if want is None:
                out.check(
                    level in e.get("readingDependent", {}),
                    f"{e['id']}: blank {level} verdict with no reason",
                )
                continue
            got = verdict(validators[e["table"]][level], doc, level)
            out.check(got == want, f"{e['id']}: {level} {got}, expected {want}")
    return docs


# ---------------------------------------------------------------- rules


def tagged(schema: dict[str, Any]) -> list[str]:
    return [entry["$comment"].removeprefix("rule:") for entry in schema["allOf"]]


def check_rule_sets(
    manifest: dict[str, Any], schemas: dict[str, dict[str, Any]], out: Findings
) -> None:
    """Each schema carries exactly the rules of its level, and is the schema they generate."""
    for table, entry in manifest["tables"].items():
        rules = entry["rules"]
        want = {
            "conformance": [r["id"] for r in rules if r["level"] == "required"],
            "recommended": [r["id"] for r in rules],
        }
        model = [Rule.from_json(table, r) for r in rules]
        for level, ids in want.items():
            schema = schemas[table][level]
            have = tagged(schema)
            out.check(
                sorted(have) == sorted(ids) and len(set(have)) == len(have),
                f"{table} {level} schema rules differ from MANIFEST.json",
            )
            rebuilt = schema_build.build(schema.get("title", ""), model, LEVEL_OF[level])
            out.check(
                rebuilt == schema, f"{table} {level} schema is not the one its rules generate"
            )


def mutated(schema: dict[str, Any], rule_id: str, how: str) -> dict[str, Any] | None:
    """The schema with one rule deleted, or with its condition dropped.

    None when the rule is not in the schema, or has no condition to drop.
    """
    out = copy.deepcopy(schema)
    tag = f"rule:{rule_id}"
    found = [e for e in out["allOf"] if e["$comment"] == tag]
    if len(found) != 1 or (how == "drop-condition" and "then" not in found[0]):
        return None
    kept = [e for e in out["allOf"] if e["$comment"] != tag]
    if how == "drop-condition":
        kept.append({"$comment": tag, **found[0]["then"]})
    out["allOf"] = kept
    return out


def sweep(
    manifest: dict[str, Any],
    schemas: dict[str, dict[str, Any]],
    docs: dict[str, Any],
    out: Findings,
) -> Counter[str]:
    """Delete each rule, and drop each condition; every member naming the rule must flip."""
    tally: Counter[str] = Counter()
    by_rule: dict[str, list[tuple[str, str]]] = {}
    for e in manifest["members"]:
        for role in e["roles"]:
            by_rule.setdefault(role["rule"], []).append((role["role"], e["id"]))
    expected = {e["id"]: e["expected"] for e in manifest["members"]}
    for table, entry in manifest["tables"].items():
        for rule in entry["rules"]:
            tally.update(
                sweep_rule(table, rule, schemas, docs, by_rule.get(rule["id"], []), expected, out)
            )
    return tally


def sweep_rule(
    table: str,
    rule: dict[str, Any],
    schemas: dict[str, dict[str, Any]],
    docs: dict[str, Any],
    roles: list[tuple[str, str]],
    expected: dict[str, Any],
    out: Findings,
) -> Counter[str]:
    """One rule's share of the sweep."""
    level = SCHEMA_OF[rule["level"]]
    conditional = "when" in rule or "entriesAtLeast" in rule
    kinds = {k for k, _ in roles}
    needed = {"violates"} | ({"inapplicable", "satisfies"} if conditional else set())
    for kind in sorted(needed - kinds):
        out.fail(f"{rule['id']}: no member {kind} it; a rule no member depends on is not tested")
    tally: Counter[str] = Counter()
    for how, role, flips_to in (
        ("delete", "violates", True),
        ("drop-condition", "inapplicable", False),
    ):
        members = [m for k, m in roles if k == role]
        if not members:
            continue
        schema = mutated(schemas[table][level], rule["id"], how)
        if schema is None:
            out.fail(f"{rule['id']}: the {level} schema carries no entry that can be {how}d")
            continue
        validator = Draft202012Validator(schema)
        for member in members:
            if expected[member][level] is None:
                out.fail(f"{member}: names {rule['id']} at a level its verdict leaves open")
                continue
            before = expected[member][level] == PASS[level]
            after = validator.is_valid(docs[member])
            out.check(
                before != flips_to and after == flips_to,
                f"{member}: does not flip when {rule['id']} is {how}d",
            )
            tally[how] += 1
    return tally


# ---------------------------------------------------------------- counts


def counts(templates: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    """Every figure the README quotes, derived here and nowhere else."""
    out: dict[str, Any] = {"tables": {}}
    for key, table in templates["tables"].items():
        fields = table["fields"]
        rules = manifest["tables"][key]["rules"]
        out["tables"][key] = {
            "fields": len(fields),
            "printed": dict(sorted(Counter(f["designation"] for f in fields).items())),
            "classes": dict(sorted(Counter(f["designationClass"] for f in fields).items())),
            "rules": len(rules),
            "conditions": len(manifest["tables"][key]["conditions"]),
            "members": sum(1 for e in manifest["members"] if e["table"] == key),
        }
    out["fields"] = sum(t["fields"] for t in out["tables"].values())
    out["rules"] = sum(t["rules"] for t in out["tables"].values())
    out["members"] = len(manifest["members"])
    out["conditionalRules"] = sum(
        1
        for t in manifest["tables"].values()
        for r in t["rules"]
        if "when" in r or "entriesAtLeast" in r
    )
    out["readingDependent"] = sum(1 for e in manifest["members"] if "readingDependent" in e)
    out["ambiguities"] = len(manifest["ambiguities"])
    out["observations"] = len(manifest["observations"])
    out["notExpressible"] = len(manifest["notExpressible"])
    return out


def run(root: Path, transcript: Callable[[Path], dict[str, Any]] = G.transcript) -> list[str]:
    """Every check over the tree at ``root``; returns the failures."""
    out = Findings()
    manifest = load(root / "MANIFEST.json")
    templates = load(root / "templates.json")
    check_source(root, manifest, templates, out)
    pdf = root / manifest["source"]["path"]
    if pdf.is_file():
        check_transcript(transcript(pdf), manifest, templates, out)
    schemas = {
        t: {lvl: load(root / rel) for lvl, rel in e["schemas"].items()}
        for t, e in manifest["tables"].items()
    }
    for table in schemas.values():
        for schema in table.values():
            Draft202012Validator.check_schema(schema)
    check_files(root, manifest, out)
    check_rule_sets(manifest, schemas, out)
    docs = check_verdicts(root, manifest, schemas, out)
    tally = sweep(manifest, schemas, docs, out)
    if not out.items:
        c = counts(templates, manifest)
        n = manifest["census"]
        print(
            f"ok: {n['tables']} tables on {n['tablePages']} pages and {n['reviewerNotes']} "
            f"reviewer notes make up all {n['ruledBoxes']} ruled boxes in the "
            f"{n['pages']}-page PDF, {n['rows']} rows by both extractions; "
            f"{c['members']} members over {c['rules']} rules; source and "
            f"{len(manifest['bindings'])} bindings re-derived; {tally['delete']} deletions and "
            f"{tally['drop-condition']} dropped "
            "conditions each flipped the members that name them"
        )
    return out.items


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument(
        "--root", type=Path, default=HERE, help="the corpus directory (default: this one)"
    )
    parser.add_argument(
        "--counts", action="store_true", help="print the derived counts as JSON and exit"
    )
    args = parser.parse_args(argv)
    if args.counts:
        print(
            json.dumps(
                counts(load(args.root / "templates.json"), load(args.root / "MANIFEST.json")),
                indent=1,
            )
        )
        return 0
    failures = run(args.root)
    for failure in failures:
        print(f"FAIL {failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
