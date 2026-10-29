#!/usr/bin/env python3
"""The MCP server profile criterion as a standalone checker.

    python3 check_server_record.py records/<id>.json [...]

A server run record says what a recorder saw when it launched one version of
one MCP server: the digests of the tool definitions it served, the approved
pins, the previous version's digests, the hosts it contacted, and a verdict.
This checker recomputes every derived field from the observed ones and names
each condition the record breaks. It reads no file but the records.

The corpus Go reader (corpora/mcpserverprofile.go) states the same rules; the
two are held together by the corpus, which both must judge identically.
"""

from __future__ import annotations

import json
import re
import sys

IMMUTABLE = re.compile(r"^sha256:[0-9a-f]{64}$")


def pin_mismatches(tools: dict) -> list[str]:
    """Served tools whose digest differs from the approved pin, or has none."""
    pinned, served = tools.get("pinned", {}), tools.get("served", {})
    return sorted(name for name, digest in served.items() if pinned.get(name) != digest)


def version_diff(diff: dict, served: dict) -> dict[str, list[str]]:
    """Tools changed, added or removed between the previous version and this one."""
    before = diff.get("previousTools", {})
    return {
        "changed": sorted(n for n in served if n in before and before[n] != served[n]),
        "added": sorted(n for n in served if n not in before),
        "removed": sorted(n for n in before if n not in served),
    }


def undeclared_hosts(record: dict) -> list[str]:
    declared = set(record.get("declaredEgress", []))
    return sorted(set(record.get("egress", {}).get("observed", [])) - declared)


def check_server_run(record: dict) -> list[str]:
    violated: list[str] = []
    tools = record.get("tools", {})
    mismatches = pin_mismatches(tools)
    if sorted(tools.get("mismatchReported", [])) != mismatches:
        violated.append("msp-c-1")
    expected = version_diff(record.get("diff", {}), tools.get("served", {}))
    reported = record.get("diff", {}).get("reported", {})
    if any(sorted(reported.get(k, [])) != expected[k] for k in expected):
        violated.append("msp-c-2")
    egress = record.get("egress", {})
    undeclared = undeclared_hosts(record)
    if sorted(egress.get("undeclaredReported", [])) != undeclared:
        violated.append("msp-c-3")
    outcome = record.get("outcome")
    if egress.get("observation") != "recorded" and outcome != "couldnt-run":
        violated.append("msp-c-4")
    if outcome == "clean" and (mismatches or undeclared):
        violated.append("msp-c-5")
    if not IMMUTABLE.match(str(record.get("server", {}).get("artifactDigest", ""))):
        violated.append("msp-c-6")
    return violated


def check_run_set(record: dict) -> list[str]:
    results = record.get("results", {})
    attempted = record.get("attempted")
    violated = []
    if sum(results.values()) != attempted or record.get("headlineDenominator") != attempted:
        violated.append("msp-c-7")
    return violated


def check(record: dict) -> list[str]:
    if record.get("recordType") == "run-set":
        return check_run_set(record)
    return check_server_run(record)


def main(paths: list[str]) -> int:
    worst = 0
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            violated = check(json.load(handle))
        print(path, "violates", violated if violated else "nothing")
        worst = max(worst, 1 if violated else 0)
    return worst


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
