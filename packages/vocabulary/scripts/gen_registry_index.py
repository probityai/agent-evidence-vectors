"""Generate registry.json, the machine index of vocabulary.yaml.

    python3 scripts/gen_registry_index.py          # write registry.json
    python3 scripts/gen_registry_index.py --check  # fail when it is stale

registry.json carries, for every term, its section, URI, criticality and
registered values, plus the verdict classes and the SHA-256 of the exact
vocabulary.yaml bytes it was made from (source_sha256). That digest is the
registryDigest a record carries. registry.py reads this file, so a verifier
needs no YAML parser, and the Pages builder reads it to make the term pages.
Never edit registry.json by hand: the check in CI regenerates it and compares.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "vocabulary.yaml"
INDEX = ROOT / "registry.json"
TERM_SECTIONS = (
    "evidence_dimensions",
    "posture_and_coverage",
    "outcome_lattice",
    "record_lifecycle",
    "change_admission",
    "done_verification",
    "incident_response",
)
CRITICALITY = ("critical", "informational")


def build(source: bytes) -> tuple[dict, list[str]]:
    """Return the index for ``source`` and every defect that blocks it."""
    data = yaml.safe_load(source)
    meta = data["meta"]
    base = meta["term_uri_base"]
    failures: list[str] = []
    terms: dict[str, dict] = {}
    for section in TERM_SECTIONS:
        for name, entry in data[section].items():
            if name in terms:
                failures.append(f"{name}: defined in {terms[name]['section']} and {section}")
            criticality = entry.get("criticality")
            if criticality not in CRITICALITY:
                failures.append(f"{name}: criticality {criticality!r} is not one of {CRITICALITY}")
            values = entry.get("values")
            terms[name] = {
                "section": section,
                "uri": base + name,
                "criticality": criticality,
                "values": list(values) if isinstance(values, list) else None,
                "definition": " ".join(str(entry.get("definition", "")).split()),
                "value_definitions": {k: " ".join(str(v).split()) for k, v in (entry.get("value_definitions") or {}).items()},
            }
    classes = data["verdict_classes"]
    parent_term = classes["parent_term"]
    parents = terms.get(parent_term, {}).get("values") or []
    if not parents:
        failures.append(f"verdict_classes: parent term {parent_term!r} has no closed values")
    children = {}
    for code, child in (classes.get("children") or {}).items():
        if child.get("parent") not in parents:
            failures.append(f"verdict_classes.{code}: parent {child.get('parent')!r} is not a value of {parent_term}")
        if code in parents:
            failures.append(f"verdict_classes.{code}: a child code may not repeat a parent")
        children[code] = {"parent": child.get("parent"), "uri": f"{base}{parent_term}#{code}"}
    index = {
        "source": "vocabulary.yaml",
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "version": meta["version"],
        "term_uri_base": base,
        "terms": terms,
        "verdict_classes": {"parent_term": parent_term, "parents": parents, "children": children},
    }
    return index, failures


def render(index: dict) -> str:
    return json.dumps(index, indent=2, sort_keys=True) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="fail when registry.json is stale")
    args = parser.parse_args(argv)
    index, failures = build(SOURCE.read_bytes())
    for failure in failures:
        print(failure, file=sys.stderr)
    if failures:
        return 1
    text = render(index)
    if args.check:
        if not INDEX.is_file() or INDEX.read_text(encoding="utf-8") != text:
            print("registry.json is stale: run python3 scripts/gen_registry_index.py", file=sys.stderr)
            return 1
        print(f"registry.json ok ({len(index['terms'])} terms, sha256 {index['source_sha256']})")
        return 0
    INDEX.write_text(text, encoding="utf-8")
    print(f"wrote registry.json ({len(index['terms'])} terms)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
