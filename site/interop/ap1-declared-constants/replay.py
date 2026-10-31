#!/usr/bin/env python3
"""Fetch each pinned ap1-run state and hold check.py's answer to expected.json.

Usage: replay.py [WORKDIR]. Clones zorrzai/ap1-run into WORKDIR (a temporary
directory by default), reads the ground-truth module at each pinned commit, runs
check.py on it, and writes results.json beside this file. Exit 0 when every
state matches its expected answer, 1 when one does not, 2 when a fetch fails.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from check import read_derivations, report


def git(repo: str, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", repo, *args], check=True, capture_output=True
    ).stdout


def main(argv: list[str]) -> int:
    with open(os.path.join(HERE, "expected.json"), encoding="utf-8") as fh:
        expected = json.load(fh)
    work = argv[0] if argv else tempfile.mkdtemp(prefix="ap1-run-")
    repo = os.path.join(work, "ap1-run")
    try:
        if not os.path.isdir(os.path.join(repo, ".git")):
            subprocess.run(
                ["git", "clone", "--quiet", expected["repository"], repo], check=True
            )
        rows = []
        for state in expected["states"]:
            raw = git(repo, "show", f"{state['commit']}:{expected['file']}")
            result = report(read_derivations(raw.decode("utf-8-sig")))
            got = [[row["derivation"], row["constant"]] for row in result["unconsumed"]]
            rows.append(
                {
                    "label": state["label"],
                    "commit": state["commit"],
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "result": result["result"],
                    "unconsumed": got,
                    "matches": result["result"] == state["result"]
                    and got == state["unconsumed"],
                }
            )
    except (subprocess.CalledProcessError, OSError) as exc:
        print(f"fetch failed: {exc}", file=sys.stderr)
        return 2
    with open(os.path.join(HERE, "results.json"), "w", encoding="utf-8") as fh:
        json.dump({"states": rows}, fh, indent=2)
        fh.write("\n")
    for row in rows:
        mark = "ok  " if row["matches"] else "DIFF"
        print(
            f"{mark} {row['commit'][:7]} {row['result']:4} {row['unconsumed']} {row['label']}"
        )
    return 0 if all(row["matches"] for row in rows) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
