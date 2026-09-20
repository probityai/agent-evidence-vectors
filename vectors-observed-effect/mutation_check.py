#!/usr/bin/env python3
"""Prove every rule in the reference verifier is load-bearing.

    uv run --extra generators python vectors-observed-effect/mutation_check.py

check_vectors.py answers "does the corpus behave as the manifest claims". This
answers the question that has to be asked afterwards, and that a green suite
cannot answer about itself: **would any member still be refused if the rule were
not there?**

For each rule in check_vectors.RULES, this disables that rule alone, re-verifies
every member, and requires that at least one member which the full verifier
refuses is now ACCEPTED. A rule whose removal changes no verdict measures
nothing: either the corpus has no member for it, or another rule refuses the same
input first and the second rule is unreachable. Both are defects and both look
exactly like a passing suite from the inside.

It also runs the check in the other direction: disabling a rule must never turn
an ACCEPT member into a refusal, because that would mean the rule was refusing
something the predicate permits and the corpus was compensating for it.

Exit 0 when every rule is load-bearing on at least one member and no accept
member depends on a rule being absent.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))

# Loaded BY PATH rather than by name, and the reason is a real failure this file
# produced. check_vectors.py is a name every corpus in this repository uses -- CI
# greps for `<dir>check_vectors.py` and reports a corpus "judged by nothing" when it
# is missing -- and pyright's extraPaths puts vectors-artifact-binding/ on the search
# path, so `import check_vectors` resolved to THAT corpus's checker and every
# attribute this file reads was reported as not existing. Runtime was fine, because
# sys.path.insert(0, HERE) wins; the checker was not, and a checker error that reads
# as a defect in correct code is worth removing at the root. A path names one file.
_spec = importlib.util.spec_from_file_location(
    "observed_effect_check_vectors", os.path.join(HERE, "check_vectors.py")
)
assert _spec is not None and _spec.loader is not None
cv = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = cv
_spec.loader.exec_module(cv)


def _sweep_one(
    name: str,
    members: list[tuple[dict[str, Any], bytes]],
    baseline: dict[str, tuple[str, list[str]]],
    observer: str,
) -> tuple[list[str], list[str]]:
    """Disable one rule and report what it frees and what it breaks."""
    freed: list[str] = []
    broke: list[str] = []
    for entry, raw in members:
        was_verdict, _ = baseline[entry["id"]]
        now_verdict, _ = cv.verify(raw, observer, cv.BLOBS, disabled=name)
        if was_verdict != "valid" and now_verdict == "valid":
            freed.append(f"{entry['slug']} ({was_verdict} -> valid)")
        if was_verdict == "valid" and now_verdict != "valid":
            broke.append(f"{entry['slug']} (valid -> {now_verdict})")
    return freed, broke


def main() -> None:
    with open(os.path.join(HERE, "MANIFEST.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    observer = manifest["keys"]["observer"]["publicKey"]

    members = []
    for entry in manifest["vectors"]:
        with open(os.path.join(HERE, entry["file"]), "rb") as fh:
            members.append((entry, fh.read()))

    baseline: dict[str, tuple[str, list[str]]] = {}
    for entry, raw in members:
        baseline[entry["id"]] = cv.verify(raw, observer, cv.BLOBS)

    inert: list[str] = []
    collateral: list[str] = []
    report: list[str] = []

    for name, _fn in cv.RULES:
        freed, broke = _sweep_one(name, members, baseline, observer)
        if not freed:
            inert.append(name)
        if broke:
            collateral.append(f"{name}: {', '.join(broke)}")
        report.append(f"  {name}: frees {len(freed)} -> {freed if freed else 'NOTHING'}")

    print(f"mutation sweep over {len(cv.RULES)} rules and {len(members)} members")
    for line in report:
        print(line)

    failed = False
    for name in inert:
        print(
            f"FAIL rule {name} is INERT: removing it changes no verdict, so nothing "
            "in this corpus measures it"
        )
        failed = True
    for line in collateral:
        print(f"FAIL {line}: disabling a rule turned an accept member into a refusal")
        failed = True

    if failed:
        sys.exit(1)
    print(
        f"OK all {len(cv.RULES)} rules load-bearing, "
        f"{sum(1 for e, _ in members if baseline[e['id']][0] != 'valid')} members refused "
        f"by the full verifier"
    )


if __name__ == "__main__":
    main()
