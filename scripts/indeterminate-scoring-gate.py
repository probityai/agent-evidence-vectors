#!/usr/bin/env python3
"""No corpus pins one expected verdict on a member whose readings allow several.

An indeterminate member records a question the specification leaves open, and
lists under `readings` what a conforming verifier may answer. Two shapes exist
in this repository and the gate reads both:

- a list, `readings: [{"verdict": ...}, ...]`, where each entry names a verdict;
- a map, `expected.readings: {name: value}`, where each value is either the
  verdict `valid` or a condition code. A condition code names a refusal, so it
  reads here as the verdict `invalid`.

Two rules follow, and each has already been broken here:

1. A member whose readings imply more than one verdict carries NO
   `expected.verdict`. Any single value there scores a verifier that takes
   another listed reading as wrong. The agent audit record corpus shipped N1
   and N2 that way, beside a note telling implementers to score on
   `expected.verdict`, and an outside reader found it before a second
   implementation ran. The observed-effect and SCITT carriage corpora carried
   the same shape.
2. A member whose readings imply exactly one verdict (the adversarial execution
   evidence corpus, where the verdict is settled and only the condition is open)
   may carry `expected.verdict`, and it must be the verdict its readings imply.

Every `*/MANIFEST.json` at the root or under `corpora/` is read, so a corpus added
tomorrow is held to the rule without being registered here. A run that finds no
member declaring readings refuses: a gate quantified over nothing cannot be told
apart from a clean one.

Usage: python3 scripts/indeterminate-scoring-gate.py [--root DIR]
Exit 0 clean, 1 with one line per refusal.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

VERDICT_WORDS = frozenset({"valid", "invalid", "malformed", "indeterminate", "not-established"})


def reading_verdicts(entry: dict[str, Any]) -> list[str] | None:
    """The verdict each declared reading implies, or None for a member with none."""
    expected = entry.get("expected")
    listed = entry.get("readings")
    mapped = expected.get("readings") if isinstance(expected, dict) else None
    if isinstance(listed, list):
        return [str(r.get("verdict")) if isinstance(r, dict) else "?" for r in listed]
    if isinstance(mapped, dict):
        return [str(v) if str(v) in VERDICT_WORDS else "invalid" for v in mapped.values()]
    return None


def refusals(root: Path) -> tuple[list[str], int]:
    out: list[str] = []
    read = 0
    manifests = [*root.glob("*/MANIFEST.json"), *root.glob("corpora/*/MANIFEST.json")]
    for manifest_path in sorted(manifests):
        rel = manifest_path.relative_to(root).as_posix()
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        entries = manifest.get("vectors") if isinstance(manifest, dict) else None
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue
            verdicts = reading_verdicts(entry)
            if verdicts is None:
                continue
            read += 1
            expected = entry.get("expected")
            pinned = expected.get("verdict") if isinstance(expected, dict) else None
            implied = sorted(set(verdicts))
            ident = entry.get("id")
            if len(implied) > 1 and pinned is not None:
                out.append(
                    f"{rel} {ident}: its readings allow {implied} and it pins "
                    f"expected.verdict={pinned!r}, so a verifier taking another listed "
                    "reading is scored wrong. Remove expected.verdict; the readings are "
                    "the score."
                )
            elif len(implied) == 1 and pinned is not None and pinned != implied[0]:
                out.append(
                    f"{rel} {ident}: every reading implies {implied[0]!r} and "
                    f"expected.verdict is {pinned!r}"
                )
    return out, read


def main() -> int:
    parser = argparse.ArgumentParser(
        description="refuse a pinned expected.verdict on a member whose readings allow several"
    )
    parser.add_argument("--root", default=str(Path(__file__).resolve().parent.parent))
    args = parser.parse_args()
    found, read = refusals(Path(args.root))
    if read == 0:
        print(
            "indeterminate-scoring-gate: read no member that declares readings under "
            f"{args.root}, so nothing was checked. That is a refusal, not a pass."
        )
        return 1
    for line in found:
        print(f"REFUSE {line}")
    if found:
        return 1
    print(f"indeterminate-scoring-gate: {read} member(s) with readings, none pins a verdict")
    return 0


if __name__ == "__main__":
    sys.exit(main())
