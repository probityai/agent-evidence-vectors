#!/usr/bin/env python3
"""Section 7.3 item 10: the corpus members that make json.load raise TypeError.

    python rows/item_7_3_10.py <work dir> <result.json>

At agent-evidence-vectors 4cb988e8 every report member of vectors-w3c-report is
parsed as the command of Nov/0000 parses a report, with json.load, then given to
shape_errors and rejections. The members that raise TypeError are listed. Each
of them is then read with the reader's own loader, every number kept as the
token it was written as, which is what --read-w3c-report does with a file, and
its printed verdict is compared with the verdict the corpus expects.

Exits 0 only when eight members raise TypeError, six of them are rejected under
W3C-R-020 and two conform, and each matches its member's expected verdict.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rerun  # noqa: E402

CHILD = r'''
import glob, json, os, sys
sys.path.insert(0, "packaging")
from agent_evidence_vectors import w3creport as w
out = []
for name in sorted(glob.glob("vectors-w3c-report/vectors/*.json")):
    with open(name, "rb") as handle:
        raw = handle.read()
    member = json.loads(raw)
    if member["subjectType"] != "report":
        continue
    try:
        w.shape_errors(member["subject"])
        w.rejections(member["subject"])
        continue
    except TypeError as exc:
        error = str(exc)
    lines = w.verdict_lines(w.load_json(raw)["subject"])
    out.append({"id": member["id"], "plain_json_error": error,
                "expected": member["expected"]["verdict"], "lines": lines})
print(json.dumps(out))
'''


def main() -> int:
    work, result = Path(sys.argv[1]), Path(sys.argv[2])
    log = work / "log.txt"
    expect = rerun.ROWS["rows"]["Item-7.3-10"]["expect"]
    tree = rerun.fetch_commit(rerun.ROWS["aev_repository"], expect["commit"], work / "aev", log,
                              ["/packaging/", "/vectors-w3c-report/"])
    printed = work / "members.json"
    code = rerun.run(["uv", "run", "-q", "--no-project", "--python", "3.13", "python", "-I", "-c",
                      CHILD], tree, log, stdout=printed)
    members = json.loads(printed.read_text(encoding="utf-8")) if code == 0 else []
    for m in members:
        m["verdict"] = "accept" if m["lines"] == ["conforms"] else "reject"
        m["rejected_under"] = sorted({line.split(":", 1)[0] for line in m["lines"]
                                      if line.startswith("W3C-R-")})
    rejected = [m for m in members if m["verdict"] == "reject"]
    accepted = [m for m in members if m["verdict"] == "accept"]
    observed = {"raise TypeError": len(members), "rejected": len(rejected),
                "accepted": len(accepted),
                "rejected under": sorted({c for m in rejected for c in m["rejected_under"]})}
    posted = {k: expect[k] for k in observed}
    ok = (code == 0 and observed == posted
          and all(m["verdict"] == m["expected"] for m in members))
    out = {"commit": expect["commit"], "child_exit": code, "posted": posted, "observed": observed,
           "members": members, "ok": ok}
    result.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
