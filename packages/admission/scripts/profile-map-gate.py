#!/usr/bin/env python3
"""Refuse a profile map that claims more than the measurement supports.

Four checks, and the last is the one this file exists for.

1. COMPLETENESS. Every obligation in registry/conditions.json appears exactly
   once in every rail's map, and no map names an obligation the registry does
   not carry. A map missing a row does not read as incomplete; it reads as a
   shorter registry, which is why the count is checked against the registry
   rather than against itself.

2. AN ENFORCED ROW NAMES A RULE THAT EXISTS. `rule` is a locator into that
   rail's own artifact, and the gate opens the artifact and looks for it. A
   declared rule nobody can find is the same defect as a citation pointing
   nowhere.

3. AN UNREACHABLE ROW NAMES AN OBSTRUCTION FROM THE CLOSED VOCABULARY. An open
   vocabulary here would let a shrug pass as a reason.

4. AN ENFORCED ROW WHOSE VECTOR THE RAIL FAILS IS A HARD ERROR. The conformance
   harness already refuses a rail that diverges from the oracle on a VECTOR
   without a declared reason. This lifts that same discipline from the vector to
   the obligation: a rail may not declare that it enforces an obligation while
   the measurement shows it answering differently from the oracle on a vector
   citing it.

Check 4 reads profiles/MEASUREMENTS.json, which is written by
scripts/gen_profile_map.py from a live run of every rail. The measurement is
pinned to a corpus digest, and a measurement taken against a different corpus is
refused rather than used: a stale measurement and a passing rail are
indistinguishable once the corpus has moved.

    scripts/profile-map-gate.py

Exit codes:
    0  every check passed
    1  at least one check failed; each failure names the rail, the obligation
       and what was wrong
    2  could not check: a map, the registry or the measurement file is missing
       or unreadable. Never reported as a pass.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
REGISTRY = HERE / "registry" / "conditions.json"
PROFILES = HERE / "profiles"
MEASUREMENTS = PROFILES / "MEASUREMENTS.json"

DISPOSITIONS = {"enforced", "approximated", "unreachable"}

OBSTRUCTIONS = {
    "no-decode-primitive",
    "no-recompute-primitive",
    "no-set-algebra",
    "no-clock",
    "no-vector-in-projection",
    "oracle-divergence-declared",
}


def cannot(msg: str) -> None:
    print(f"profile-map-gate: COULD NOT CHECK -- {msg}", file=sys.stderr)
    raise SystemExit(2)


def load(path: Path) -> dict:
    if not path.is_file():
        cannot(f"missing {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        cannot(f"{path} is not readable JSON: {exc}")
    return {}


def main(argv: list[str]) -> int:
    argparse.ArgumentParser(description=__doc__).parse_args(argv[1:])

    registry = load(REGISTRY)
    slugs = {c["id"] for c in registry["conditions"]}
    if not slugs:
        cannot(f"{REGISTRY} carries no obligations, so every map would pass vacuously")

    maps = sorted(PROFILES.glob("*/PROFILE-MAP.json"))
    if not maps:
        cannot(f"no PROFILE-MAP.json under {PROFILES}")

    measurements = load(MEASUREMENTS)
    corpus_digest = registry["source"]["corpusDigest"]
    if measurements.get("corpusDigest") != corpus_digest:
        cannot(
            f"{MEASUREMENTS} was taken at corpusDigest "
            f"{measurements.get('corpusDigest')!r} and the registry is at "
            f"{corpus_digest!r}. A measurement from a different corpus cannot "
            f"support a claim about this one; regenerate it."
        )

    problems: list[str] = []
    oracle = measurements["verdicts"]["rego"]

    for path in maps:
        doc = load(path)
        rail = doc["rail"]
        artifact = HERE / doc["artifact"]
        if doc.get("corpusDigest") != corpus_digest:
            problems.append(
                f"{rail}: the map is pinned at corpusDigest "
                f"{doc.get('corpusDigest')!r} and the registry is at "
                f"{corpus_digest!r}"
            )
        if not artifact.is_file():
            cannot(f"{rail}: names artifact {doc['artifact']}, which is not a file")
        source = artifact.read_text(encoding="utf-8", errors="replace")
        verdicts = measurements["verdicts"].get(rail)
        if verdicts is None:
            cannot(f"{rail}: no verdicts for this rail in {MEASUREMENTS}")

        rows = doc["obligations"]

        # 1. completeness, both directions.
        missing = sorted(slugs - set(rows))
        extra = sorted(set(rows) - slugs)
        for slug in missing:
            problems.append(f"{rail}: {slug} is in the registry and has no row")
        for slug in extra:
            problems.append(f"{rail}: {slug} has a row and is in no registry")

        for slug in sorted(set(rows) & slugs):
            row = rows[slug]
            disposition = row.get("disposition")
            if disposition not in DISPOSITIONS:
                problems.append(
                    f"{rail}: {slug} carries disposition {disposition!r}, which is "
                    f"not one of {sorted(DISPOSITIONS)}"
                )
                continue

            # 3. an unreachable row names an obstruction from the closed set.
            if disposition == "unreachable":
                obstruction = row.get("obstruction")
                if obstruction not in OBSTRUCTIONS:
                    problems.append(
                        f"{rail}: {slug} is unreachable and names obstruction "
                        f"{obstruction!r}, which is not in the closed vocabulary "
                        f"{sorted(OBSTRUCTIONS)}"
                    )
                continue

            if disposition == "enforced":
                # 2. the named rule exists in the rail's own artifact.
                rule = row.get("rule")
                if not isinstance(rule, str) or not rule.strip():
                    problems.append(
                        f"{rail}: {slug} is enforced and names no rule. An enforced "
                        f"row without a locator is an assertion."
                    )
                elif rule not in source:
                    problems.append(
                        f"{rail}: {slug} is enforced by rule {rule!r}, which does "
                        f"not appear in {doc['artifact']}"
                    )

                # 4. an enforced obligation whose vector the rail fails.
                for vector in row.get("vectors", []):
                    if vector not in verdicts or vector not in oracle:
                        problems.append(
                            f"{rail}: {slug} cites vector {vector}, which the "
                            f"measurement does not cover, so the enforced claim "
                            f"rests on nothing"
                        )
                        continue
                    if verdicts[vector] != oracle[vector]:
                        problems.append(
                            f"{rail}: {slug} is declared ENFORCED and the rail "
                            f"{'admits' if verdicts[vector] else 'denies'} vector "
                            f"{vector}, which the oracle "
                            f"{'admits' if oracle[vector] else 'denies'}. A rail "
                            f"that answers differently from the oracle on a vector "
                            f"citing an obligation does not enforce it."
                        )

    if problems:
        for p in problems:
            print(f"  {p}")
        print(
            f"\nprofile-map-gate: {len(problems)} problem(s) across {len(maps)} rail(s).",
            file=sys.stderr,
        )
        return 1

    print(
        f"profile-map-gate: {len(maps)} rail(s), {len(slugs)} obligations each, "
        f"every enforced row names a rule that exists and no enforced row has a "
        f"vector its rail answers differently from the oracle."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
