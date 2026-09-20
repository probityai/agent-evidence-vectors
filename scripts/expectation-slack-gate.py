#!/usr/bin/env python3
"""Expectation-slack gate: a reject vector may pin at most one emitted code.

Why this exists, stated as what actually happened rather than as a principle.

`vd538496f284b4761` is the first vector in this corpus
that separates the two readings of the sealed existential. It does that for one
reason and one reason only: its `codes` cell names `sealed-record-absent` and
nothing else, while the second condition the statement carries on purpose,
`sealed-covers-nothing`, is declared in the `also carries` clause. A reject
vector is graded by intersecting the emitted set with `codes`, so a rail that
reads the existential narrowly emits only the companion, misses the pinned
condition, and goes red. That is the measurement.

Move one word and the measurement is gone. Rewriting the cell as
`` `sealed-record-absent`, `sealed-covers-nothing` `` widens `codes` to both
conditions, and now EITHER reading satisfies the expectation: the narrow rail
emits the companion, the companion is declared, the vector passes, and the only
discriminator the corpus owns has quietly become a vector that measures nothing.
That edit was performed and measured. The replay stayed green at 250 of 250 and
`regenerability-gate`, `vector-distinctness-gate`, `condition-registry-gate`,
`spec-drift-gate`, `code-contract-gate`, `coverage-matrix-gate` and
`dispositions-gate` all exited 0. Nothing in this repository could see it.

The prose already said the rule. `packaging/run_vectors.py` says of a
precedence pin that "its expected-code set stays a single code so the pin still
discriminates", and `vectors/gen_manifest.py` says the also-carries clause
"never widen[s] the expectation, since widening it is exactly what a precedence
pin must not do". Both are docstrings. Neither is a check, and a rule that lives
only in the docstring of the file it constrains is a rule the next edit is free
to break.

So the gate measures the property directly rather than the spelling of the cell,
because the spelling is what an edit changes: it runs the reference rail over
every reject vector and refuses when more than one DECLARED code is actually
EMITTED. Two declared codes that are both emitted mean a rail reporting either
one conforms, which is precisely the state in which the vector cannot force a
condition. Ten vectors were already in that state when the gate was written;
they are frozen below by identifier and by the exact pair that overlaps, so a
frozen entry that changes shape, or that stops overlapping, fails as loudly as a
new one. The freeze is a record of what was inherited, never a place to add to.

Usage: python3 scripts/expectation-slack-gate.py
Exit 0 when every reject expectation pins at most one emitted code; 1 otherwise.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "vectors" / "MANIFEST.json"

sys.path.insert(0, str(REPO_ROOT / "packaging"))

import run_vectors  # noqa: E402

# Vectors whose declared code set already overlapped the emitted set in more
# than one place on the day this gate was written, with the overlap each one
# carried. Every one of them declares genuine alternatives for a statement whose
# fault two rails may reasonably name differently, which is a legitimate shape;
# what it is not is a shape that can pin a reading. Keyed by the exact pair so
# that a vector drifting into a DIFFERENT overlap is a new finding rather than a
# silently covered one.
INHERITED_SLACK: dict[str, tuple[str, ...]] = {
    "vf35474dd75d6b14a": ("result-recompute-mismatch", "result-vocabulary"),
    "v87a339f53f689d9f": ("result-recompute-mismatch", "result-vocabulary"),
    "v131478f1be775746": ("caught-row-uncovered", "refs-empty"),
    "v7622b2c58c2e272d": ("duplicate-record", "record-undecodable"),
    "vb704d6c2420a1c43": ("arming-covers-nothing", "sealed-covers-nothing"),
    "v210a8e2d17bfcc47": ("coverage-incomplete", "row-attack-unknown"),
    "v2d1f9da3e912c63a": (
        "caught-row-uncovered",
        "interception-record-orphaned",
    ),
    "vde0891384c1018ae": ("coverage-incomplete", "observed-attack-uncaught"),
    "v99fb4ac5cb385049": (
        "attribution-pinned-recordless",
        "caught-row-uncovered",
    ),
    "v21e964dddeba0d08": (
        "attribution-pinned-recordless",
        "caught-row-uncovered",
    ),
}


def emitted_codes(verifier: Any, path: Path) -> tuple[str, ...] | None:
    """The conditions the reference rail reports for one vector.

    None where the vector does not parse. That is a real state -- a vector whose
    whole fault is that it is not JSON carries no code set this gate can read --
    and it is reported as its own thing rather than as an empty set, which would
    read as a vector that emits nothing.
    """
    raw = path.read_bytes()
    try:
        stmt = json.loads(raw)
    except ValueError:
        return None
    codes = verifier.verify(stmt, raw).codes
    return tuple(sorted(str(c) for c in codes))


class Findings:
    """What one pass over the reject bucket learned.

    A class rather than four parallel lists threaded through a loop, because
    three of the four are reported together and the fourth -- which frozen
    entries were actually SEEN -- only means anything next to the freeze it is
    compared against.
    """

    def __init__(self) -> None:
        self.slack: list[tuple[str, tuple[str, ...]]] = []
        self.unreadable: list[str] = []
        self.seen_frozen: dict[str, tuple[str, ...]] = {}
        self.examined = 0

    def visit(self, verifier: Any, entry: dict[str, Any]) -> None:
        vid = str(entry.get("id"))
        rel = entry.get("file")
        path = REPO_ROOT / "vectors" / str(rel)
        if not rel or not path.is_file():
            self.unreadable.append(f"{vid} names {rel!r}, which is not on disk")
            return
        expected = entry.get("expected")
        if not isinstance(expected, dict):
            self.unreadable.append(f"{vid} carries no expected object")
            return
        declared = {str(c) for c in (expected.get("codes") or [])}
        also = {str(c) for c in (expected.get("alsoCarries") or [])}
        if declared & also:
            self.slack.append((vid, tuple(sorted(declared & also))))
            return
        observed = emitted_codes(verifier, path)
        if observed is None:
            return
        self.examined += 1
        overlap = tuple(sorted(declared & set(observed)))
        if len(overlap) < 2:
            return
        if INHERITED_SLACK.get(vid) == overlap:
            self.seen_frozen[vid] = overlap
            return
        self.slack.append((vid, overlap))


def main() -> int:
    if not MANIFEST.is_file():
        print(f"FAIL: {MANIFEST} is absent, so no expectation was read and "
              "nothing here is a statement about any vector.", file=sys.stderr)
        return 1
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    entries = manifest.get("vectors")
    if not isinstance(entries, list) or not entries:
        print("FAIL: the manifest lists no vectors, so the check did not run.",
              file=sys.stderr)
        return 1

    verifier = run_vectors.ReferenceVerifier([])
    found = Findings()
    for entry in entries:
        if isinstance(entry, dict) and entry.get("kind") == "reject":
            found.visit(verifier, entry)

    slack = found.slack
    unreadable = found.unreadable
    seen_frozen = found.seen_frozen
    examined = found.examined
    stale = sorted(set(INHERITED_SLACK) - set(seen_frozen))

    if slack or unreadable or stale:
        print("FAIL: a reject expectation is satisfied by more than one "
              "condition the statement actually emits, so it pins none of "
              "them:", file=sys.stderr)
        for vid, overlap in sorted(slack):
            print(f"  - {vid} declares {list(overlap)} and emits all of them. "
                  "A rail reporting either one conforms, so the vector cannot "
                  "force a reading. Keep ONE condition in the expected-code "
                  "cell and move the rest into the `also carries` clause, "
                  "which exempts them from the second-fault check without "
                  "widening what the vector measures.", file=sys.stderr)
        for vid in stale:
            print(f"  - {vid} is frozen here as inherited slack and no longer "
                  f"overlaps in {list(INHERITED_SLACK[vid])}. A freeze that no "
                  "longer describes the vector hides the next change to it; "
                  "delete the entry.", file=sys.stderr)
        for line in unreadable:
            print(f"  - {line}", file=sys.stderr)
        return 1

    print(f"OK: {examined} reject vectors examined, {len(seen_frozen)} carrying "
          "inherited slack and unchanged, none newly widened — every other "
          "expectation pins exactly the one condition it measures.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
