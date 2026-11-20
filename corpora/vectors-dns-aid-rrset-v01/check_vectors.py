"""The DNS-AID RRset rule, as an oracle: one SVCB record per published agent protocol.

    python3 corpora/vectors-dns-aid-rrset-v01/check_vectors.py <case.json>
        judge one member; the last stdout line is the rail report; exit 0 valid, 1 invalid
    python3 corpora/vectors-dns-aid-rrset-v01/check_vectors.py
        judge every member against MANIFEST.json; exit 0 when all agree

A record's agent protocol is its `proto` value when present (the newer draft's
shape: alpn carries the transports) and otherwise every alpn token that is not a
transport (the earlier draft's example records: alpn=mcp,h2,h3). A conforming
RRset has exactly one record per published protocol and no record that names
none or two. Reading the raw alpn string as the protocol set, which an earlier
oracle did, fails both drafts' own example RRsets; the controls here hold them.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
TRANSPORTS = {"h2", "h3", "http/1.1", "h2c"}


def agent_protocols(record: dict[str, Any]) -> list[str]:
    params = record.get("params") or {}
    if params.get("proto"):
        return [p for p in str(params["proto"]).split(",") if p]
    return [p for p in str(params.get("alpn", "")).split(",") if p and p not in TRANSPORTS]


def findings(case: dict[str, Any]) -> list[str]:
    codes: set[str] = set()
    per = [agent_protocols(r) for r in case.get("rrset") or []]
    if any(len(p) == 0 for p in per):
        codes.add("record-names-no-protocol")
    if any(len(p) > 1 for p in per):
        codes.add("record-names-two-protocols")
    counts = Counter(p[0] for p in per if len(p) == 1)
    published = set(case.get("published") or [])
    if any(n > 1 for n in counts.values()):
        codes.add("protocol-record-duplicated")
    if published - set(counts) - {q for p in per if len(p) > 1 for q in p}:
        codes.add("protocol-record-missing")
    if set(counts) - published:
        codes.add("protocol-record-unexpected")
    return sorted(codes)


def report(case: Any) -> dict[str, Any]:
    if not isinstance(case, dict) or not isinstance(case.get("rrset"), list):
        return {"codes": ["rrset-malformed"], "verdict": "invalid"}
    codes = findings(case)
    return {"codes": codes, "verdict": "invalid" if codes else "valid"}


def main(argv: list[str]) -> int:
    if argv:
        rep = report(json.loads(Path(argv[0]).read_text(encoding="utf-8")))
        print(json.dumps(rep, sort_keys=True))
        return 0 if rep["verdict"] == "valid" else 1
    manifest = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
    bad = 0
    for entry in manifest["vectors"]:
        got = report(json.loads((ROOT / entry["file"]).read_text(encoding="utf-8")))
        want = {k: entry["expected"][k] for k in ("codes", "verdict")}
        if got != want:
            bad += 1
            print(f"FAIL {entry['id']}: {got}, manifest {want}")
    print(f"{len(manifest['vectors']) - bad} of {len(manifest['vectors'])} members behave as MANIFEST.json declares")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
