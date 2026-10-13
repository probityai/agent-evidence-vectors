"""Recompute AgentID action_ref v1 and v2 from pinned vectors without the producer's tool.

Usage (from the repository root):

    python interop/agentid-action-ref-v2/reader.py --output-dir NEW_DIR

The reader checks the pinned bytes of every input first, then reproduces the 30 checks
the producer's tools/action_ref_v2.py states for the four published vectors, then runs the
domain cases in DOMAIN-CASES.json. It writes NEW_DIR/report.json and prints one line.

Exit 0: every upstream check holds and every domain case has its declared outcome.
Exit 1: a report was written and at least one check or case differs.
Exit 2: a pin failed, an input is malformed, or the output directory exists; no report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

import rfc8785

HERE = Path(__file__).resolve().parent
FIELDS = ("agent_id", "action_type", "scope", "timestamp_ms")
INT64_MIN, INT64_MAX = -(2**63), 2**63 - 1
SAFE_MAX = 2**53 - 1
MAX_INPUT_BYTES = 64 * 1024


class Refused(Exception):
    """The tuple has no value under the construction being computed."""


class InputError(Exception):
    """A pinned input is missing, changed or malformed."""


class _FloatToken(float):
    """A JSON number written with a fraction or exponent, kept distinct from an integer."""


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate member {key!r}")
        out[key] = value
    return out


def strict_loads(text: str) -> Any:
    """Parse JSON keeping number token types and refusing duplicate members."""

    def bad_constant(name: str) -> Any:
        raise ValueError(f"non-finite number {name}")

    return json.loads(
        text,
        object_pairs_hook=_no_duplicates,
        parse_float=_FloatToken,
        parse_constant=bad_constant,
    )


def _scalar_value(value: Any) -> bool:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def tuple_fields(obj: Any) -> tuple[str, str, str, int]:
    """Exactly four members: three Unicode strings and one integer token."""
    if not isinstance(obj, dict) or set(obj) != set(FIELDS):
        raise Refused("the tuple must have exactly agent_id, action_type, scope, timestamp_ms")
    for name in FIELDS[:3]:
        if not isinstance(obj[name], str) or not _scalar_value(obj[name]):
            raise Refused(f"{name} must be a string of Unicode scalar values")
    ts = obj["timestamp_ms"]
    if type(ts) is not int:
        raise Refused("timestamp_ms must be an integer token")
    return obj["agent_id"], obj["action_type"], obj["scope"], ts


def v1_preimage(obj: Any) -> bytes:
    agent_id, action_type, scope, ts = tuple_fields(obj)
    if not INT64_MIN <= ts <= INT64_MAX:
        raise Refused("timestamp_ms is outside int64")
    tail = struct.pack(">q", ts)
    return agent_id.encode("utf-8") + action_type.encode("utf-8") + scope.encode("utf-8") + tail


def v2_bytes(obj: Any) -> bytes:
    agent_id, action_type, scope, ts = tuple_fields(obj)
    if not -SAFE_MAX <= ts <= SAFE_MAX:
        raise Refused(
            "timestamp_ms is outside the I-JSON integer domain RFC 8785 serializes exactly"
        )
    value = {"agent_id": agent_id, "action_type": action_type, "scope": scope, "timestamp_ms": ts}
    return rfc8785.dumps(value)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tuple_only(t: dict[str, Any]) -> dict[str, Any]:
    return {k: t[k] for k in FIELDS if k in t}


def upstream_checks(name: str, vector: dict[str, Any]) -> list[dict[str, Any]]:
    """The checks the producer's tool states for one vector, recomputed here."""
    rows: list[dict[str, Any]] = []

    def row(label: str, ok: bool) -> None:
        rows.append({"vector": name, "check": label, "result": "PASS" if ok else "FAIL"})

    tuples = vector["tuples"]
    computed: dict[str, tuple[str, str, bytes]] = {}
    for tname, t in tuples.items():
        pre = v1_preimage(_tuple_only(t))
        v1, v2 = sha256_hex(pre), sha256_hex(v2_bytes(_tuple_only(t)))
        computed[tname] = (v1, v2, pre)
        row(f"{tname}: action_ref_v1 recomputes", v1 == t["action_ref_v1"])
        row(f"{tname}: action_ref_v2 recomputes", v2 == t["action_ref_v2"])
        row(
            f"{tname}: versions labelled 1 and 2",
            t.get("action_ref_v1_version") == 1 and t.get("action_ref_v2_version") == 2,
        )
    expected = vector.get("expected", {})
    for key, want in expected.items():
        head, _, which = key.rpartition(".")
        if head in computed and which in ("action_ref_v1", "action_ref_v2"):
            got = computed[head][0 if which == "action_ref_v1" else 1]
            row(f"expected.{key}", got == want)
    names = list(tuples)
    if len(names) == 2 and "v1_collides" in expected:
        a, b = computed[names[0]], computed[names[1]]
        row("expected.v1_collides", (a[0] == b[0]) is expected["v1_collides"])
        row("expected.v2_collides", (a[1] == b[1]) is expected["v2_collides"])
        if "v1_preimage_identical" in expected:
            row(
                "expected.v1_preimage_identical",
                (a[2] == b[2]) is expected["v1_preimage_identical"],
            )
    return rows


def _outcome(fn: Any, obj: Any) -> tuple[str, bytes | None, str | None]:
    try:
        return "defined", fn(obj), None
    except Refused as exc:
        return "refused", None, str(exc)


def domain_case(case: dict[str, Any]) -> dict[str, Any]:
    expect = case["expect"]
    try:
        obj = strict_loads(case["tuple_json"])
    except ValueError as exc:
        obj, parse_error = None, str(exc)
    else:
        parse_error = None
    if parse_error is not None:
        v1 = ("refused", None, f"parse: {parse_error}")
        v2 = ("refused", None, f"parse: {parse_error}")
    else:
        v1, v2 = _outcome(v1_preimage, obj), _outcome(v2_bytes, obj)
    problems: list[str] = []
    if v1[0] != expect["v1"]:
        problems.append(f"v1 {v1[0]}, declared {expect['v1']}")
    if v2[0] != expect["v2"]:
        problems.append(f"v2 {v2[0]}, declared {expect['v2']}")
    if v1[1] is not None and "v1_timestamp_octets_hex" in expect:
        if v1[1][-8:].hex() != expect["v1_timestamp_octets_hex"]:
            problems.append("v1 timestamp octets differ from the hand-written value")
    if v2[1] is not None and "v2_jcs" in expect:
        if v2[1] != expect["v2_jcs"].encode("utf-8"):
            problems.append("v2 canonical bytes differ from the hand-written value")
    return {
        "id": case["id"],
        "v1": v1[0],
        "v1_value": sha256_hex(v1[1]) if v1[1] is not None else None,
        "v1_refusal": v1[2],
        "v2": v2[0],
        "v2_value": sha256_hex(v2[1]) if v2[1] is not None else None,
        "v2_refusal": v2[2],
        "differs_from": expect.get("differs_from"),
        "result": "PASS" if not problems else "FAIL",
        "problems": problems,
    }


def _check_pairs(results: list[dict[str, Any]]) -> None:
    by_id = {r["id"]: r for r in results}
    for r in results:
        other = r["differs_from"]
        if other is None:
            continue
        o = by_id.get(other)
        if o is None:
            r["problems"].append(f"differs_from names unknown case {other}")
        elif (
            r["v2_value"] is None
            or r["v2_value"] == o["v2_value"]
            or r["v1_value"] == o["v1_value"]
        ):
            r["problems"].append(f"not distinct from {other} under both constructions")
        r["result"] = "PASS" if not r["problems"] else "FAIL"


def _read_pinned(base: Path, entry: dict[str, Any]) -> bytes:
    path = base / entry["path"]
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise InputError(f"{entry['path']}: {exc}") from exc
    if len(data) != entry["bytes"] or sha256_hex(data) != entry["sha256"]:
        raise InputError(f"{entry['path']}: bytes differ from the pin")
    return data


def _load_json_file(path: Path) -> Any:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise InputError(f"{path.name}: {exc}") from exc
    if len(data) > MAX_INPUT_BYTES:
        raise InputError(f"{path.name}: larger than {MAX_INPUT_BYTES} bytes")
    try:
        return strict_loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise InputError(f"{path.name}: {exc}") from exc


def run(base: Path, domain_path: Path) -> dict[str, Any]:
    inputs = _load_json_file(base / "INPUTS.json")
    checks: list[dict[str, Any]] = []
    for entry in inputs["files"]:
        raw = _read_pinned(base, entry)
        try:
            vector = strict_loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise InputError(f"{entry['path']}: {exc}") from exc
        try:
            checks.extend(upstream_checks(Path(entry["path"]).name, vector))
        except (KeyError, TypeError, Refused) as exc:
            raise InputError(f"{entry['path']}: {exc}") from exc
    domain = _load_json_file(domain_path)
    cases = [domain_case(c) for c in domain["cases"]]
    _check_pairs(cases)
    passed = sum(r["result"] == "PASS" for r in checks)
    cases_ok = sum(r["result"] == "PASS" for r in cases)
    return {
        "source": {k: inputs[k] for k in ("source_repository", "source_tag", "source_commit")},
        "inputs": [{k: e[k] for k in ("path", "sha256", "bytes")} for e in inputs["files"]],
        "reader_sha256": sha256_hex(Path(__file__).read_bytes()),
        "domain_cases_sha256": sha256_hex(domain_path.read_bytes()),
        "rfc8785_version": metadata.version("rfc8785"),
        "python": sys.version.split()[0],
        "upstream_checks": {"passed": passed, "total": len(checks), "rows": checks},
        "domain_cases": {"passed": cases_ok, "total": len(cases), "rows": cases},
        "not_established": [
            "AgentID adoption of v2 or any emitter producing it",
            "that any signature covers these values",
            "authorization, execution or completeness of any action",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Recompute AgentID action_ref v1 and v2 from pinned vectors."
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--base", type=Path, default=HERE)
    parser.add_argument("--domain-cases", type=Path, default=None)
    args = parser.parse_args(argv)
    if args.output_dir.exists():
        print(f"refused: {args.output_dir} exists; choose a new directory", file=sys.stderr)
        return 2
    domain_path = args.domain_cases or args.base / "DOMAIN-CASES.json"
    try:
        report = run(args.base, domain_path)
    except InputError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    try:
        args.output_dir.mkdir(parents=True)
        out = args.output_dir / "report.json"
        out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"refused: cannot write report: {exc}", file=sys.stderr)
        return 2
    up, dc = report["upstream_checks"], report["domain_cases"]
    print(
        f"upstream checks {up['passed']}/{up['total']}, domain cases {dc['passed']}/{dc['total']}, "
        f"report {out}"
    )
    return 0 if up["passed"] == up["total"] and dc["passed"] == dc["total"] else 1


if __name__ == "__main__":
    sys.exit(main())
