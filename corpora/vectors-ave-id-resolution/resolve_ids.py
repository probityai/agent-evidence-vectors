#!/usr/bin/env python3
"""Check that every AVE id a tool's output carries resolves to an active record.

The output is a tool's SARIF or JSON findings file. The snapshot is a released
AVE records file, read from disk and pinned by its SHA-256, so the verdict
depends on the bytes given and on nothing fetched.

    python3 resolve_ids.py <output> --snapshot <ave-records.json> --sha256 <hex>

Standard library only. One JSON object is printed on stdout:
``{"verdict", "codes", "findings", "snapshot"}``. Exit status:

    0  resolves   every AVE id is well formed and names an active record
    1  fails      at least one finding below
    2  cannot judge: the output or snapshot is unreadable, or the snapshot's
       bytes are not the ones the --sha256 pin names
    3  no-ids     the output carries no AVE id, so there is nothing to judge

Finding codes, one per offending id or run:

    id-malformed          a value claimed as an AVE id that is not AVE-YYYY-NNNNN
    id-unknown            a well-formed id the snapshot has no record for
    id-not-active         a record whose status is anything other than "active";
                          the list of statuses is not assumed to be complete
    run-snapshot-differs  the output declares ave_records_sha256 for a snapshot
                          other than the pinned one

Where an id is read from:

    SARIF  each run's tool.driver.rules[].id and each result's ruleId (or
           rule.id) when the value begins with "AVE-" in any case; and
           properties.ave_id on a rule or a result, whatever its value. A rule
           id that does not begin with "AVE-" is the tool's own and is skipped.
           runs[].properties.ave_records_sha256 is the run's declared snapshot.
    JSON   any object key matching ave_id, ave-id, aveid or ave_ids (any case),
           at any depth, holding a string or a list; a top-level
           ave_records_sha256 is the declared snapshot.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ID = re.compile(r"AVE-[0-9]{4}-[0-9]{5}")
JSON_ID_KEY = re.compile(r"ave[_-]?ids?", re.IGNORECASE)
ACTIVE = "active"
RULES = ("id-malformed", "id-unknown", "id-not-active", "run-snapshot-differs")
EXIT = {"resolves": 0, "fails": 1, "unreadable": 2, "no-ids": 3}


class Unjudgeable(Exception):
    """The output or the snapshot cannot be read as the pin requires."""


def load_snapshot(path: Path, sha256: str) -> dict[str, Any]:
    """Map each record's ave_id to its status, after checking the pin."""
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise Unjudgeable(f"snapshot unreadable: {error}") from error
    digest = hashlib.sha256(raw).hexdigest()
    if digest != sha256.lower():
        raise Unjudgeable(f"snapshot sha256 is {digest}, the pin names {sha256}")
    try:
        records = json.loads(raw)
    except ValueError as error:
        raise Unjudgeable(f"snapshot is not JSON: {error}") from error
    if not isinstance(records, list) or not all(
        isinstance(r, dict) and isinstance(r.get("ave_id"), str) for r in records
    ):
        raise Unjudgeable("snapshot is not a list of records carrying ave_id")
    return {r["ave_id"]: r.get("status") for r in records}


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _claims_ave(value: Any) -> bool:
    return isinstance(value, str) and value.upper().startswith("AVE-")


def _sarif(doc: dict[str, Any]) -> tuple[list[tuple[Any, str]], list[str]]:
    claims: list[tuple[Any, str]] = []
    declared: list[str] = []
    for i, run in enumerate(_list(doc.get("runs"))):
        run = _dict(run)
        sha = _dict(run.get("properties")).get("ave_records_sha256")
        if sha is not None:
            declared.append(str(sha))
        rules = _list(_dict(_dict(run.get("tool")).get("driver")).get("rules"))
        for j, rule in enumerate(rules):
            rule, where = _dict(rule), f"runs[{i}].tool.driver.rules[{j}]"
            if _claims_ave(rule.get("id")):
                claims.append((rule["id"], f"{where}.id"))
            if "ave_id" in _dict(rule.get("properties")):
                claims.append((rule["properties"]["ave_id"], f"{where}.properties.ave_id"))
        for k, result in enumerate(_list(run.get("results"))):
            result, where = _dict(result), f"runs[{i}].results[{k}]"
            rid = result.get("ruleId", _dict(result.get("rule")).get("id"))
            if _claims_ave(rid):
                claims.append((rid, f"{where}.ruleId"))
            if "ave_id" in _dict(result.get("properties")):
                claims.append((result["properties"]["ave_id"], f"{where}.properties.ave_id"))
    return claims, declared


def _walk(node: Any, path: str, claims: list[tuple[Any, str]]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(key, str) and JSON_ID_KEY.fullmatch(key):
                values = value if isinstance(value, list) else [value]
                claims.extend((v, f"{path}.{key}") for v in values)
            else:
                _walk(value, f"{path}.{key}", claims)
    elif isinstance(node, list):
        for n, item in enumerate(node):
            _walk(item, f"{path}[{n}]", claims)


def extract(doc: Any) -> tuple[list[tuple[Any, str]], list[str]]:
    """Return the claimed ids with where each was read, and the declared snapshot digests."""
    if isinstance(doc, dict) and isinstance(doc.get("runs"), list):
        return _sarif(doc)
    claims: list[tuple[Any, str]] = []
    _walk(doc, "$", claims)
    sha = _dict(doc).get("ave_records_sha256")
    return claims, [] if sha is None else [str(sha)]


def judge(
    doc: Any, statuses: dict[str, Any], pinned: str, rules: tuple[str, ...] = RULES
) -> dict[str, Any]:
    """Judge one parsed output against one snapshot; `rules` switches checks off for tests."""
    claims, declared = extract(doc)
    findings = []
    for value, where in claims:
        code = None
        known = isinstance(value, str) and value in statuses
        if "id-malformed" in rules and not (isinstance(value, str) and ID.fullmatch(value)):
            code = "id-malformed"
        elif "id-unknown" in rules and not known:
            code = "id-unknown"
        elif "id-not-active" in rules and known and statuses[value] != ACTIVE:
            code = "id-not-active"
        if code:
            findings.append({"id": value, "where": where, "code": code})
    if "run-snapshot-differs" in rules:
        for sha in declared:
            if sha.lower() != pinned.lower():
                findings.append(
                    {"id": None, "where": "ave_records_sha256", "code": "run-snapshot-differs"}
                )
    codes = sorted({f["code"] for f in findings})
    verdict = "fails" if findings else ("resolves" if claims else "no-ids")
    return {"verdict": verdict, "codes": codes, "findings": findings}


def run(output: Path, snapshot: Path, sha256: str) -> dict[str, Any]:
    """Read both files and judge; an unreadable input is reported, never raised."""
    try:
        statuses = load_snapshot(snapshot, sha256)
        try:
            doc = json.loads(output.read_bytes())
        except (OSError, ValueError) as error:
            raise Unjudgeable(f"output unreadable: {error}") from error
    except Unjudgeable as error:
        return {"verdict": "unreadable", "codes": [], "findings": [], "error": str(error)}
    report = judge(doc, statuses, sha256)
    report["snapshot"] = {"sha256": sha256.lower(), "records": len(statuses)}
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    parser.add_argument("output", type=Path)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args(argv)
    report = run(args.output, args.snapshot, args.sha256)
    print(json.dumps(report, sort_keys=True))
    return EXIT[report["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
