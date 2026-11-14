#!/usr/bin/env python3
"""Print one line per verified record and fail on any verdict code you did not allow.

Reads every ``*.out.json`` that ``agent-evidence-verify --json`` wrote in the given
directories. Each line is: directory, record, decision, verdict, verdict code,
codes, result, tiers. Exit 0 when every record is clean (no verdict code) or carries
a code named with ``--allow``; exit 1 otherwise, naming each refused record.

    python3 summary.py [--allow NOT_RECONSTRUCTIBLE ...] pinned
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--allow", action="append", default=[], metavar="CODE")
    parser.add_argument("directories", type=Path, nargs="+")
    args = parser.parse_args()
    refused: list[str] = []
    seen = 0
    for directory in args.directories:
        for out in sorted(directory.glob("*.out.json")):
            seen += 1
            result = json.loads(out.read_text(encoding="utf-8"))
            check = result["checks"][0]
            record = out.name.removesuffix(".out.json")
            code = check.get("verdict_code")
            print(directory.name, record, result.get("decision"), check.get("verdict"), code,
                  ",".join(check.get("codes", [])) or "-", check.get("result"),
                  ",".join(check.get("tiers") or []) or "-")
            if code is not None and code not in args.allow:
                refused.append(f"{directory.name}/{record}: {code}")
    if seen == 0:
        print("refused: no *.out.json found; nothing was verified")
        return 1
    for line in refused:
        print("refused", line)
    return 1 if refused else 0


if __name__ == "__main__":
    raise SystemExit(main())
