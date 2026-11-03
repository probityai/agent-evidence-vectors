#!/usr/bin/env python3
"""Is every rule in the reference verifier load-bearing?

    uv run --extra generators python vectors-self-reported-record/mutation_check.py

A green conformance suite cannot answer that about itself. `check_vectors.py`
asks whether each member behaves as declared, and a rule that never fires passes
that check silently: the members it was written for are refused by some earlier,
narrower rule, and the suite reports a pass for a rule nothing ran.

So this harness disables one rule at a time and requires two things of each.

**Liveness.** At least one member the full verifier refuses must be ACCEPTED
with the rule gone. A rule no input reaches is a sentence, not a gate.

**Innocence.** No member the full verifier accepts may become refused with the
rule gone. That direction cannot fail for a rule expressed as a refusal, and it
is checked anyway, because the day it does fail the rule has been written
inverted and every other check in this corpus would read the inversion as
correct.

The sibling observed-effect corpus ran this harness first and it found four
inert rules and one dead clause in the predicate itself on the first run, which
is the argument for having it. This corpus was built with that result in hand:
every rule here has exactly one member written to reach it, and the harness is
what holds that property as the corpus changes.

Exit 0 when every rule is live and innocent; 1 when one is not and is named.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# The verifier is loaded BY PATH rather than by name, and the reason is a real
# failure this file produced. `check_vectors.py` is the name every corpus in this
# repository gives its checker -- CI greps for `<dir>check_vectors.py` and reports
# a corpus "judged by nothing" when it is missing -- so a bare `import
# check_vectors` is ambiguous across the tree. It resolved to a SIBLING corpus's
# checker under the type checker's search path, and every symbol this file reads
# was reported as not existing. Runtime was fine, because the script's own
# directory comes first on sys.path; the checker was not, and a checker error that
# reads as a defect in correct code is worth removing at its root. A path names
# one file.
_spec = importlib.util.spec_from_file_location(
    "self_reported_record_check_vectors", HERE / "check_vectors.py"
)
assert _spec is not None and _spec.loader is not None
cv = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = cv
_spec.loader.exec_module(cv)

RULES: tuple[str, ...] = cv.RULES
firing_rules = cv.firing_rules


def main() -> int:
    manifest = json.loads((HERE / "MANIFEST.json").read_text(encoding="utf-8"))
    members = [
        (entry["id"], entry["kind"], json.loads((HERE / entry["file"]).read_bytes()))
        for entry in manifest["vectors"]
    ]
    refused_by_full = {
        vid for vid, _, statement in members if firing_rules(statement)
    }
    accepted_by_full = {vid for vid, _, _ in members} - refused_by_full

    findings: list[str] = []
    rows: list[tuple[str, int]] = []
    for rule in RULES:
        without = frozenset({rule})
        freed = {
            vid
            for vid, _, statement in members
            if vid in refused_by_full and not firing_rules(statement, without)
        }
        broken = {
            vid
            for vid, _, statement in members
            if vid in accepted_by_full and firing_rules(statement, without)
        }
        rows.append((rule, len(freed)))
        if not freed:
            findings.append(
                f"{rule} is INERT: every member the full verifier refuses is still "
                "refused without it, so no input in this corpus reaches it. Write a "
                "member that trips it and nothing else, or delete the rule."
            )
        if broken:
            findings.append(
                f"{rule} is INVERTED: removing it REFUSES {sorted(broken)}, which the "
                "full verifier accepts. A rule that refuses what the contract permits "
                "is a rule written the wrong way round."
            )

    if findings:
        print(f"FAIL: {len(findings)} rule(s) do not hold:")
        for finding in findings:
            print(f"  {finding}")
        return 1
    for rule, freed in rows:
        print(f"  {rule}: {freed} member(s) accepted without it")
    print(
        f"OK: {len(RULES)} rules, each reached by at least one member and each "
        f"refusing nothing the contract permits."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
