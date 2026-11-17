"""The DNS-AID RRset rule, as an oracle: one SVCB record per published agent protocol.

    python3 corpora/vectors-dns-aid-rrset-v01/check_vectors.py <case.json>
        judge one member; the last stdout line is the rail report; exit 0 valid, 1 invalid
    python3 corpora/vectors-dns-aid-rrset-v01/check_vectors.py
        judge every member against MANIFEST.json; exit 0 when all agree

A record's agent protocol is its `proto` value when that member is present (the
newer draft's shape: alpn carries the transports), even when it is empty, and
otherwise every alpn token that is not a transport (the earlier draft's example
records: alpn=mcp,h2,h3). Each of the two is a comma-separated string or a list
of strings (RFC 9460 7.1.1 defines alpn as a list of ids). Any other shape, a
member file that names a key twice, or a published list that is not strings is
rrset-malformed: a verdict, never an exception. A conforming
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


class Malformed(Exception):
    pass


def tokens(value: Any) -> list[str]:
    if isinstance(value, str):
        return [p for p in value.split(",") if p]
    if isinstance(value, list) and all(isinstance(p, str) for p in value):
        return [p for p in value if p]
    raise Malformed(f"{value!r} is neither a comma-separated string nor a list of strings")


def agent_protocols(record: Any) -> list[str]:
    if not isinstance(record, dict) or not isinstance(record.get("params", {}), dict):
        raise Malformed("a record is not an object with a params object")
    params = record.get("params", {})
    if "proto" in params:
        return tokens(params["proto"])
    return [p for p in tokens(params.get("alpn", "")) if p not in TRANSPORTS]


def load_case(raw: bytes) -> Any:
    """Strict JSON: a duplicate name, NaN, Infinity or deep nesting is malformed."""

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for k, v in items:
            if k in out:
                raise Malformed(f"the member names {k!r} twice")
            out[k] = v
        return out

    def constant(name: str) -> Any:
        raise Malformed(f"{name} is not a JSON value")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
    except (Malformed, UnicodeDecodeError, ValueError, RecursionError) as exc:
        return Malformed(str(exc))


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
    malformed = {"codes": ["rrset-malformed"], "verdict": "invalid"}
    if not isinstance(case, dict) or not isinstance(case.get("rrset"), list):
        return malformed
    published = case.get("published", [])
    if not isinstance(published, list) or not all(isinstance(p, str) for p in published):
        return malformed
    try:
        codes = findings(case)
    except Malformed:
        return malformed
    return {"codes": codes, "verdict": "invalid" if codes else "valid"}


def main(argv: list[str]) -> int:
    if argv:
        rep = report(load_case(Path(argv[0]).read_bytes()))
        print(json.dumps(rep, sort_keys=True))
        return 0 if rep["verdict"] == "valid" else 1
    manifest = json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))
    bad = 0
    for entry in manifest["vectors"]:
        got = report(load_case((ROOT / entry["file"]).read_bytes()))
        want = {k: entry["expected"][k] for k in ("codes", "verdict")}
        if got != want:
            bad += 1
            print(f"FAIL {entry['id']}: {got}, manifest {want}")
    print(
        f"{len(manifest['vectors']) - bad} of {len(manifest['vectors'])} members "
        "behave as MANIFEST.json declares"
    )
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
