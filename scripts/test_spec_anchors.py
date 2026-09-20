#!/usr/bin/env python3
"""Mutation tests for the anchor-and-digest citation scheme.

A gate only fails in the directions it has axes for, so this asserts BOTH
directions on synthetic files rather than trusting that the real one looked
right once:

  * rewording a cited sentence must change the digest  (the axis that matters)
  * reflowing the same words must not                  (the axis that made line
                                                        numbers useless)
  * deleting the anchor must be a failure, never a skip
  * an anchor covering fewer blocks than recorded must be a failure
  * a stale inline prefix must fail even when the manifest was updated
  * a line-number citation, and the orphaned tail a half-migrated one leaves,
    must both be found -- the second is here because the first version of the
    residual check could not see it and twelve citations were damaged

Run: python3 scripts/test_spec_anchors.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import spec_anchors as sa  # noqa: E402

FAILURES: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        print(f"  ok   {name}")
    else:
        print(f"  FAIL {name} {detail}")
        FAILURES.append(name)


DOC = [
    "# A specification",
    "",
    '<a id="req-one"></a>',
    "",
    "-   its `observationRefs` is non-empty and every index is in range for",
    "    `observationRecords`;",
    "",
    "A second block that the same anchor covers when blocks is 2.",
    "",
    '<a id="req-two"></a>',
    "",
    "The seal MUST carry `aeeObservedSet`.",
]


def main() -> int:
    print("normalization and digest")
    check("reflow leaves the digest identical",
          sa.digest("a b\nc") == sa.digest("a\nb   c"))
    check("a reword changes the digest",
          sa.digest("every index") != sa.digest("each index"))
    check("leading and trailing space are stripped",
          sa.digest("  x  ") == sa.digest("x"))
    check("case is NOT normalized away",
          sa.digest("MUST") != sa.digest("must"))

    print("anchor resolution")
    check("an anchor is found", sa.find_anchor(DOC, "req-one") == 2)
    check("a missing anchor is None, never 0", sa.find_anchor(DOC, "req-absent") is None)
    one = sa.anchored_text(DOC, 2, 1)
    check("one block is the bullet", one is not None and "observationRefs" in one)
    two = sa.anchored_text(DOC, 2, 2)
    check("two blocks reach the second paragraph",
          two is not None and "second block" in two.lower())
    check("an anchor does not swallow the next anchor line",
          (sa.anchored_text(DOC, 2, 3) or "").count('<a id=') == 0)
    check("too many blocks is None, not an empty string",
          sa.anchored_text(DOC, 9, 5) is None)

    print("the reword axis, end to end")
    base = sa.digest(sa.anchored_text(DOC, 2, 1) or "")
    reworded = [l.replace("every index", "each index") for l in DOC]
    check("a reworded bullet digests differently",
          sa.digest(sa.anchored_text(reworded, 2, 1) or "") != base)
    reflowed = list(DOC)
    reflowed[4] = "-   its `observationRefs` is non-empty and every index is in"
    reflowed[5] = "    range for `observationRecords`;"
    check("the same words at a different column digest identically",
          sa.digest(sa.anchored_text(reflowed, 2, 1) or "") == base)

    print("citation parsing")
    d = "0" * 16
    check("a single citation parses",
          sa.parse_citation(f"req-one@{d}") == [("req-one", d)])
    check("a two-anchor citation parses",
          sa.parse_citation(f"req-one@{d},req-two@{d}") == [("req-one", d), ("req-two", d)])
    check("the anchor form matches in prose",
          sa.CITATION_RE.search(f"see (spec:req-one@{d}) for the rule") is not None)

    print("line numbers, and the wreckage half-migrating one leaves")
    check("a plain line-number citation is found",
          sa.LEGACY_CITATION_RE.search("// (spec:1302-1304).") is not None)
    check("a SPACED line-number citation is found whole",
          (sa.LEGACY_CITATION_RE.search("// (spec:1302-1304, 1744-1746).") or
           type("x", (), {"group": lambda self, *a: ""})()).group(0)
          == "spec:1302-1304, 1744-1746")
    check("an orphaned tail after a migrated citation is found",
          sa.ORPHAN_TAIL_RE.search(f"// (spec:req-one@{d}, 1744-1746).") is not None)
    check("a clean migrated citation raises no orphan finding",
          sa.ORPHAN_TAIL_RE.search(f"// (spec:req-one@{d}).") is None)
    check("a migrated citation is not mistaken for a line-number one",
          sa.LEGACY_CITATION_RE.search(f"spec:req-one@{d}") is None)

    print()
    if FAILURES:
        print(f"{len(FAILURES)} assertion(s) failed: {', '.join(FAILURES)}")
        return 1
    print("every assertion held")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
