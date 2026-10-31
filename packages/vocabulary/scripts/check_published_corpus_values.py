#!/usr/bin/env python3
"""Hold the published conformance corpora to this registry's closed values.

A term that declares `values:` and a `source_path` of the form
`vectors[].<field>` names a field a published corpus manifest carries. This
reads every corpus the installed agent-evidence-vectors package ships, collects
each such field's values from every manifest member, and fails when a corpus
carries a value the term does not define, or when no corpus carries the field
at all (a term whose path matches nothing has checked nothing).

`--self-test` runs the same check on a synthetic corpus holding one undefined
value and requires it to fail, so a check that can never refuse is caught.

Exit 0 every value is defined, 1 at least one is not, 2 the check could not run.
"""

from __future__ import annotations

import json
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parent.parent
_REGISTRY = _ROOT / "vocabulary.yaml"
_PREFIX = "vectors[]."


def closed_terms(registry: dict[str, Any]) -> dict[str, tuple[str, set[str]]]:
    """Map each manifest field a term names to (term, its declared values)."""
    found: dict[str, tuple[str, set[str]]] = {}
    for section in registry.values():
        if not isinstance(section, dict):
            continue
        for name, term in section.items():
            if not isinstance(term, dict):
                continue
            path, values = term.get("source_path"), term.get("values")
            if isinstance(path, str) and path.startswith(_PREFIX) and isinstance(values, list):
                found[path[len(_PREFIX):]] = (name, {str(v) for v in values})
    return found


def check(corpora: Path, terms: dict[str, tuple[str, set[str]]]) -> list[str]:
    seen: dict[str, Counter[str]] = {field: Counter() for field in terms}
    for manifest in sorted(corpora.glob("*/MANIFEST.json")):
        members = json.loads(manifest.read_text(encoding="utf-8")).get("vectors")
        if not isinstance(members, list):
            continue
        for member in members:
            for field in terms:
                if isinstance(member, dict) and field in member:
                    seen[field][f"{manifest.parent.name}:{member[field]}"] += 1
    errors: list[str] = []
    for field, (term, allowed) in sorted(terms.items()):
        if not seen[field]:
            errors.append(f"{term}: no published corpus carries {_PREFIX}{field}")
        for key, count in sorted(seen[field].items()):
            corpus, value = key.split(":", 1)
            status = "defined" if value in allowed else "NOT DEFINED"
            print(f"{term}: {corpus} {_PREFIX}{field} = {value} x{count} ({status})")
            if value not in allowed:
                errors.append(f"{term}: {corpus} carries {value!r}, not one of {sorted(allowed)}")
    return errors


def self_test(terms: dict[str, tuple[str, set[str]]]) -> list[str]:
    if not terms:
        return ["self-test: the registry declares no closed vectors[] term"]
    field, (term, _) = next(iter(sorted(terms.items())))
    with tempfile.TemporaryDirectory() as tmp:
        corpus = Path(tmp) / "synthetic"
        corpus.mkdir()
        member = {field: "NOT-A-DEFINED-VALUE"}
        (corpus / "MANIFEST.json").write_text(json.dumps({"vectors": [member]}), encoding="utf-8")
        if not any("NOT-A-DEFINED-VALUE" in e for e in check(Path(tmp), terms)):
            return [f"self-test: an undefined {term} value was not refused"]
    return []


def main(argv: list[str]) -> int:
    try:
        import agent_evidence_vectors
        import yaml
    except ImportError as exc:
        print(f"check could not run: {exc}", file=sys.stderr)
        return 2
    registry = yaml.safe_load(_REGISTRY.read_text(encoding="utf-8"))
    terms = closed_terms(registry)
    if "--self-test" in argv:
        errors = self_test(terms)
    else:
        corpora = Path(agent_evidence_vectors.__file__).resolve().parent / "corpora"
        if not corpora.is_dir():
            print(f"check could not run: {corpora} is not a directory", file=sys.stderr)
            return 2
        errors = check(corpora, terms)
    for error in errors:
        print(f"FAIL {error}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
