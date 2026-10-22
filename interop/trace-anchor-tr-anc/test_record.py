"""The README's comparison table must say what pins.json and the corpus say.

compare.py holds each pin to its recorded disagreements against the live
TRACE sources; this test, which needs no network, holds the README's table to
that record. Each row's agreement count is the corpus size less the pin's
recorded disagreements, so a pin added, re-measured or removed without the
table following it fails here.

    python3 interop/trace-anchor-tr-anc/test_record.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORPUS = HERE.parents[1] / "vectors-trace-anchor" / "MANIFEST.json"
ROW = re.compile(r"^\| (?P<label>[^|]+?) \| `(?P<commit>[0-9a-f]+)` \| "
                 r"(?P<agree>\d+) of (?P<total>\d+) \| (?P<disagree>\d+) \|$")


def expected_rows() -> dict[str, tuple[str, int, int, int]]:
    pins = json.loads((HERE / "pins.json").read_text(encoding="utf-8"))["pins"]
    total = len(json.loads(CORPUS.read_text(encoding="utf-8"))["vectors"])
    return {pin["label"]: (pin["commit"], total - len(pin["disagreements"]), total,
                           len(pin["disagreements"])) for pin in pins}


def failures(readme: str) -> list[str]:
    expected = expected_rows()
    seen: dict[str, tuple[str, int, int, int]] = {}
    for line in readme.splitlines():
        match = ROW.match(line)
        if match:
            seen[match["label"]] = (match["commit"], int(match["agree"]), int(match["total"]),
                                    int(match["disagree"]))
    found = []
    for label, (commit, agree, total, disagree) in expected.items():
        if label not in seen:
            found.append(f"no README row for pin {label!r}")
            continue
        row_commit, *row_counts = seen[label]
        if not commit.startswith(row_commit):
            found.append(f"{label}: README names {row_commit}, the pin is {commit[:12]}")
        if row_counts != [agree, total, disagree]:
            found.append(f"{label}: README says {row_counts[0]} of {row_counts[1]} with "
                         f"{row_counts[2]} disagreements; the record says {agree} of {total} "
                         f"with {disagree}")
    found.extend(f"README row {label!r} names no pin" for label in sorted(set(seen) - set(expected)))
    return found


def main() -> int:
    readme = (HERE / "README.md").read_text(encoding="utf-8")
    found = failures(readme)
    # The control: a table one count off must be refused, or this test proves nothing.
    tampered = re.sub(r"\| (\d+) of ", lambda m: f"| {int(m[1]) + 1} of ", readme, count=1)
    if not failures(tampered):
        found.append("control: a table with one count changed was accepted")
    for failure in found:
        print(failure)
    if found:
        return 1
    print(f"OK: the README table matches all {len(expected_rows())} pins, and a changed count is refused.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
