#!/usr/bin/env python3
"""Section 4.1: the checks per R4 report that carry a non-ASCII tool name.

    python rows/r4_nonascii.py <work dir> <result.json>

Reads the three reports R4 commits at the pinned AgentAvow commit, and counts
in each the checks whose annotations.name holds a character outside ASCII.
R4 itself reproduces these files byte for byte, so this row needs no R4 run.
Exits 0 only when every report has the posted count of such checks.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rerun  # noqa: E402


def main() -> int:
    work, result = Path(sys.argv[1]), Path(sys.argv[2])
    log = work / "log.txt"
    row = rerun.ROWS["rows"]["R4-nonascii"]
    pin = row["pins"]
    src = rerun.fetch_commit(pin["repository"], pin["commit"], work / "src", log,
                             [f"/{pin['directory']}/records/"])
    reports = src / pin["directory"] / "records" / "reports"
    observed: dict[str, dict] = {}
    for name in sorted(row["expect"]):
        report = json.loads((reports / name).read_text(encoding="utf-8"))
        hits = sorted(c["check"] for c in report["checks"]
                      if any(ord(ch) > 127 for ch in str(c.get("annotations", {}).get("name", ""))))
        observed[name] = {"checks": len(report["checks"]), "non-ascii": len(hits), "ids": hits}
    ok = all(observed[n]["non-ascii"] == row["expect"][n] for n in row["expect"])
    out = {"commit": pin["commit"], "posted": row["expect"], "observed": observed, "ok": ok}
    result.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
