#!/usr/bin/env python3
"""Recount the three populations the corpus section cites, from the published bytes.

  python3 -I recount.py report REPORT.json CONFORMANCE-REPORT.json
      the 272-record report emitted by agent-evidence-vectors 0.12.0 and the
      conformance report written beside it (both published at tag v0.13.0)
  python3 -I recount.py selection MANIFEST.json
      vectors-w3c-report/MANIFEST.json at tag v0.17.4: its 235 members and the
      165-member selection of section 10 (subjectType report, every
      requirement agreed)

Prints the sha256 of each input and the counts. Reads nothing else.
"""

from __future__ import annotations

import collections
import hashlib
import json
import sys
from typing import Any


def load(path: str) -> tuple[str, Any]:
    with open(path, "rb") as fh:
        raw = fh.read()
    return hashlib.sha256(raw).hexdigest(), json.loads(raw)


def report(report_path: str, conformance_path: str) -> None:
    digest, doc = load(report_path)
    checks = doc["checks"]
    print(f"report.json sha256 {digest}")
    print(f"  records {len(checks)}, distinct check ids {len({c['check'] for c in checks})}")
    print(f"  state {dict(sorted(collections.Counter(c['state'] for c in checks).items()))}")
    harness = collections.Counter(c["annotations"].get("harness-status") for c in checks)
    print(f"  annotation harness-status {dict(harness)}")
    by_kind = collections.Counter((c["annotations"].get("kind"), c["state"]) for c in checks)
    for (kind, state), n in sorted(by_kind.items()):
        print(f"  fixture kind {kind} -> state {state}: {n}")
    print(f"  roll-up negative-capable {doc['roll-up']['negative-capable']}")
    digest, conf = load(conformance_path)
    print(f"conformance-report.json sha256 {digest}")
    print(f"  totals {conf['totals']}")
    print(f"  externalVerifierProbe {conf['externalVerifierProbe']!r}")


def selection(manifest_path: str) -> None:
    digest, manifest = load(manifest_path)
    print(f"MANIFEST.json sha256 {digest}")
    print(f"  corpusDigest {manifest['corpusDigest']}")
    members = manifest["vectors"]
    print(
        f"  members {len(members)}, by subjectType "
        f"{dict(sorted(collections.Counter(m['subjectType'] for m in members).items()))}"
    )
    status = {r["id"]: r.get("status") for r in manifest["requirements"]}
    chosen = [
        m
        for m in members
        if m["subjectType"] == "report"
        and all(status.get(r) == "agreed" for r in m["requirements"])
    ]
    print(
        f"  section 10 selection {len(chosen)}, by kind "
        f"{dict(sorted(collections.Counter(m['kind'] for m in chosen).items()))}"
    )


def main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[1] == "report":
        report(argv[2], argv[3])
        return 0
    if len(argv) == 3 and argv[1] == "selection":
        selection(argv[2])
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
