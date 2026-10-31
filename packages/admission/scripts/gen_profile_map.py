#!/usr/bin/env python3
"""Measure what each rail enforces, per obligation, and write the profile maps.

The disposition in a profile map is MEASURED, never typed. Every rail is run
over every vector in this bundle's corpus projection, the per-vector verdicts
are recorded, and each obligation's disposition follows from the vectors that
cite it:

    enforced       the rail matched the oracle on every vector citing the
                   obligation, AND profiles/rule-index.json names a rule in that
                   rail that exists.
    approximated   the rail matched the oracle on every vector citing the
                   obligation, and no rule has been named for it. The rail
                   behaves correctly on everything the corpus forces here, and
                   nobody has yet pointed at the line that does it.
    unreachable    the rail's answer differs from the oracle on at least one
                   vector citing the obligation, or no vector citing it appears
                   in this bundle's corpus projection at all. Either way the
                   rail is not shown to enforce it here, and the map carries an
                   obstruction from the closed vocabulary saying which.

`approximated` is deliberately the default for a rail that agrees with the
oracle, because agreement on the vectors that happen to exist is weaker than a
named rule. Promoting a row to `enforced` costs one line in the rule index and
the gate then checks the rule is really there.

    scripts/gen_profile_map.py [--jobs 2]

Exit codes:
    0  measured and written
    2  could not measure: a rail binary is missing, the corpus is unreadable, or
       the vendored obligation registry is absent. Nothing is written, because a
       map written from a partial measurement reads exactly like a complete one.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE / "conformance"))

REGISTRY = HERE / "registry" / "conditions.json"
RULE_INDEX = HERE / "profiles" / "rule-index.json"
PROFILES = HERE / "profiles"
MEASUREMENTS = PROFILES / "MEASUREMENTS.json"

# The rails this bundle contains. The Go command-line verifier is a fifth rail in
# the wider family and it does not live here, so it gets no map: a map about a
# rail this repository does not carry could never be measured by this repository.
RAILS = {
    "rego": "rego/execution_evidence.rego",
    "kyverno-jmespath": "kyverno/clusterpolicy-adversarial-execution-evidence.yaml",
    "kyverno-cel": "kyverno/imagevalidatingpolicy-adversarial-execution-evidence.yaml",
    "cue": "policy-controller/clusterimagepolicy-adversarial-execution-evidence-cue.yaml",
}

# Closed. A row may only name an obstruction from this set, and the gate refuses
# anything else. An open vocabulary here would let "it is complicated" pass as a
# reason.
OBSTRUCTIONS = {
    "no-decode-primitive": (
        "The rail has no primitive for base64-decoding an embedded payload and "
        "inspecting its fields, so an obligation about the contents of an "
        "observation record is out of its reach."
    ),
    "no-recompute-primitive": (
        "The rail cannot canonicalize a value and recompute its digest, so an "
        "obligation that compares a committed digest against the bytes it "
        "commits to cannot be evaluated."
    ),
    "no-set-algebra": (
        "The rail cannot express the disjointness and union checks the coverage "
        "partition needs."
    ),
    "no-clock": (
        "The rail has no time primitive, so an obligation about the age of an "
        "observation cannot be evaluated."
    ),
    "no-vector-in-projection": (
        "No vector citing this obligation appears in this bundle's corpus "
        "projection, so nothing here forces the rail either way. This is a gap "
        "in what has been measured, not a statement about the rail."
    ),
    "oracle-divergence-declared": (
        "The rail's answer differs from the oracle on at least one vector citing "
        "this obligation, and the conformance harness carries that divergence as "
        "a declared one with a reason."
    ),
}


def fail(msg: str) -> None:
    print(msg, file=sys.stderr)
    raise SystemExit(2)


def measure(jobs: int) -> dict[str, object]:
    try:
        import run_policy_conformance as h
    except ImportError as exc:  # pragma: no cover - environment
        fail(f"could not import the conformance harness: {exc}")

    corpus = h._as_dict(h._load_json(h._CORPUS)["corpus_vectors"], "corpus_vectors")
    vectors = h._corpus_vectors(corpus)
    workdir = Path(tempfile.mkdtemp(prefix="profile-map-"))
    try:
        rig = h._build_rig(workdir)
        results = h._run_all(rig, [(n, s) for _, n, s in vectors], jobs)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    jmespath_rail = rig.policies[0].name
    per_rail = {
        "rego": results["rego"],
        "kyverno-jmespath": results[jmespath_rail],
        "kyverno-cel": results["cel"],
        "cue": results["cue"],
    }
    return {
        "vectors": [n for _, n, _ in vectors],
        "verdicts": {
            rail: {name: bool(ok) for name, (ok, _) in verdicts.items()}
            for rail, verdicts in per_rail.items()
        },
        "jmespath_document": jmespath_rail,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=2)
    args = parser.parse_args(argv[1:])

    if not REGISTRY.is_file():
        fail(f"missing {REGISTRY}; run scripts/gen_condition_registry.py first")
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    obligations = registry["conditions"]
    if not obligations:
        fail(f"{REGISTRY} carries no obligations, so no map could mean anything")

    rules: dict[str, dict[str, str]] = {}
    if RULE_INDEX.is_file():
        rules = json.loads(RULE_INDEX.read_text(encoding="utf-8")).get("rules", {})

    measured = measure(args.jobs)
    present = set(measured["vectors"])

    PROFILES.mkdir(parents=True, exist_ok=True)
    MEASUREMENTS.write_text(
        json.dumps(
            {
                "corpusDigest": registry["source"]["corpusDigest"],
                "predicateType": registry["source"]["predicateType"],
                "jmespathDocument": measured["jmespath_document"],
                "derived_by": "scripts/gen_profile_map.py",
                "verdicts": measured["verdicts"],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    oracle = measured["verdicts"]["rego"]
    for rail, artifact in RAILS.items():
        verdicts = measured["verdicts"][rail]
        rows: dict[str, dict[str, object]] = {}
        for ob in obligations:
            slug = ob["id"]
            covered = sorted(v for v in ob["vectors"] if v in present)
            row: dict[str, object] = {"vectors": covered}
            if not covered:
                row["disposition"] = "unreachable"
                row["obstruction"] = "no-vector-in-projection"
            else:
                diverging = [v for v in covered if verdicts[v] != oracle[v]]
                if diverging:
                    row["disposition"] = "unreachable"
                    row["obstruction"] = "oracle-divergence-declared"
                    row["diverging_vectors"] = diverging
                else:
                    named = rules.get(slug, {}).get(rail)
                    if named:
                        row["disposition"] = "enforced"
                        row["rule"] = named
                    else:
                        row["disposition"] = "approximated"
                        row["basis"] = "corpus-agreement"
            rows[slug] = row

        out = PROFILES / rail / "PROFILE-MAP.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(
                {
                    "rail": rail,
                    "artifact": artifact,
                    "corpusDigest": registry["source"]["corpusDigest"],
                    "derived_by": "scripts/gen_profile_map.py",
                    "obligations": rows,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        counts = {d: 0 for d in ("enforced", "approximated", "unreachable")}
        for row in rows.values():
            counts[row["disposition"]] += 1
        print(
            f"{rail:<18} enforced={counts['enforced']:<3} "
            f"approximated={counts['approximated']:<3} "
            f"unreachable={counts['unreachable']:<3} of {len(rows)}"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
