#!/usr/bin/env python3
"""Vendor the obligation registry this bundle's profile maps are written against.

The obligations are not defined here. They are the `aee-c-NN` conditions the
conformance corpus cites, registered in that corpus's own condition table, and
this script copies them into `registry/conditions.json` with the corpus digest
they were read at. A profile map that declared obligations of its own invention
would be a consumer grading itself.

    scripts/gen_condition_registry.py --corpus <vectors checkout>
    scripts/gen_condition_registry.py --check --corpus <vectors checkout>

Exit codes:
    0  written, or under --check the vendored copy matches the corpus
    1  under --check, the vendored copy is stale; what differs is printed
    2  could not read: the corpus checkout is missing, or its registry table
       yielded no rows, which is a broken read and never a clean one
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
OUT = HERE / "registry" / "conditions.json"

CONDITION_RE = re.compile(r"^aee-c-([1-9][0-9]*)$")
ROW_RE = re.compile(r"^\|\s*(aee-c-[0-9]+)\s*\|\s*([^|]+?)\s*\|\s*(.+?)\s*\|\s*$")


def read_registry(index: Path) -> dict[str, dict[str, str]]:
    rows: dict[str, dict[str, str]] = {}
    for line in index.read_text(encoding="utf-8").splitlines():
        m = ROW_RE.match(line.strip())
        if not m:
            continue
        slug, anchor, text = m.group(1), m.group(2), m.group(3)
        if not CONDITION_RE.match(slug):
            continue
        if slug in rows:
            print(f"{index}: {slug} is registered twice", file=sys.stderr)
            raise SystemExit(2)
        rows[slug] = {"anchor": anchor, "text": text}
    return rows


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv[1:])

    manifest_path = args.corpus / "vectors" / "MANIFEST.json"
    index_path = args.corpus / "vectors" / "reject" / "INDEX.md"
    for p in (manifest_path, index_path):
        if not p.is_file():
            print(f"gen_condition_registry: missing {p}", file=sys.stderr)
            return 2

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows = read_registry(index_path)
    if not rows:
        print(
            f"{index_path}: no registry rows were parsed, so nothing was read. "
            f"A registry of zero obligations would make every profile map "
            f"vacuously complete.",
            file=sys.stderr,
        )
        return 2

    cited: dict[str, list[str]] = {}
    for vector in manifest["vectors"]:
        for slug in vector.get("conditions") or []:
            cited.setdefault(slug, []).append(vector["id"])
    if not cited:
        print(f"{manifest_path}: no vector cites any condition", file=sys.stderr)
        return 2

    unregistered = sorted(set(cited) - set(rows))
    if unregistered:
        print(
            f"{manifest_path}: {len(unregistered)} cited condition(s) have no "
            f"registry row: {', '.join(unregistered)}",
            file=sys.stderr,
        )
        return 2

    payload = {
        "source": {
            "suite": manifest["suite"],
            "predicateType": manifest["predicateType"],
            "corpusDigest": manifest["corpusDigest"],
            "specDigest": manifest["specDigest"],
            "tracksUpstream": manifest["tracksUpstream"],
            "derived_by": (
                "scripts/gen_condition_registry.py --corpus <vectors checkout>"
            ),
        },
        "conditions": [
            {
                "id": slug,
                "anchor": rows[slug]["anchor"],
                "text": rows[slug]["text"],
                "vectors": sorted(cited.get(slug, [])),
            }
            for slug in sorted(rows, key=lambda s: int(s.rsplit("-", 1)[1]))
        ],
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"

    if args.check:
        if not OUT.is_file():
            print(f"{OUT} does not exist", file=sys.stderr)
            return 1
        if OUT.read_text(encoding="utf-8") != rendered:
            print(f"{OUT} is stale against {args.corpus}", file=sys.stderr)
            return 1
        print(
            f"check: {len(payload['conditions'])} obligations, corpusDigest "
            f"{payload['source']['corpusDigest'][:12]}, vendored copy is current"
        )
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(rendered, encoding="utf-8")
    print(
        f"wrote {OUT} with {len(payload['conditions'])} obligations at corpusDigest "
        f"{payload['source']['corpusDigest'][:12]}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
