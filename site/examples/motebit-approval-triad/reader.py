"""Read retained approval triads without importing the producer's implementation."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parent
SUITE = "motebit-jcs-ed25519-b64-v1"
KEYS = {
    "approver": "e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f0",
    "agent": "79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664",
}
SIGNATURES = ("signature_approval", "signature_invocation", "signature_receipt")
RELATIONS = ("call_id", "tool_name", "args_hash", "verdict", "ordering", "run")
CASES = (
    "control", "n1-args-hash", "n2-verdict", "n3-ordering", "n4-run",
    "n5-tampered-approval", "n6-tool-name",
)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Refuse repeated JSON keys instead of choosing one signed interpretation."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def refuse_constant(value: str) -> Any:
    """Refuse JSON extensions that cannot have an RFC 8785 preimage."""
    raise ValueError(f"non-finite JSON value: {value}")


def read_object(path: Path) -> dict[str, Any]:
    """Read one strict JSON object; malformed inputs are setup errors."""
    value = json.loads(path.read_bytes(), object_pairs_hook=unique_object,
                       parse_constant=refuse_constant)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path.name}")
    return value


def signature(record: dict[str, Any], role: str) -> str:
    """Check signed bytes against the selected demo key, never an embedded key."""
    encoded = record.get("signature")
    if record.get("suite") != SUITE or not isinstance(encoded, str):
        return "fail"
    try:
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4),
                               altchars=b"-_", validate=True)
        if base64.urlsafe_b64encode(raw).decode().rstrip("=") != encoded:
            return "fail"
        body = {key: value for key, value in record.items() if key != "signature"}
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(KEYS[role])).verify(
            raw, rfc8785.dumps(body))
    except (InvalidSignature, ValueError, binascii.Error, rfc8785.CanonicalizationError):
        return "fail"
    return "pass"


def relations(approval: dict[str, Any], invocation: dict[str, Any],
              receipt: dict[str, Any]) -> dict[str, str]:
    """Compare native fields while keeping identity and effects unevaluated."""
    required = (
        (approval, ("approval_id", "tool_name", "args_hash", "verdict", "run_id")),
        (invocation, ("invocation_id", "tool_name", "args_hash", "status", "task_id")),
        (receipt, ("task_id",)),
    )
    for record, names in required:
        for name in names:
            if not isinstance(record.get(name), str):
                raise ValueError(f"missing or invalid native field: {name}")
    for record, name in ((approval, "resolved_at"), (invocation, "started_at")):
        if type(record.get(name)) is not int:
            raise ValueError(f"expected integer milliseconds: {name}")
    values = (
        approval["approval_id"] == invocation["invocation_id"],
        approval["tool_name"] == invocation["tool_name"],
        approval["args_hash"] == invocation["args_hash"],
        invocation["status"] != "completed" or approval["verdict"] == "approved",
        approval["resolved_at"] <= invocation["started_at"],
        approval["run_id"] == invocation["task_id"] == receipt["task_id"],
    )
    return {name: "pass" if value else "fail"
            for name, value in zip(RELATIONS, values, strict=True)}


def evaluate(case: Path) -> dict[str, Any]:
    """Return native verdict, decisive field and individual signature states."""
    approval, invocation, receipt = (
        read_object(case / name) for name in ("approval.json", "invocation.json", "receipt.json")
    )
    claims = dict(zip(SIGNATURES, (signature(approval, "approver"),
                                 signature(invocation, "agent"),
                                 signature(receipt, "agent")), strict=True))
    failed_signatures = [name for name in SIGNATURES if claims[name] == "fail"]
    if failed_signatures:
        claims.update({name: "not_evaluated" for name in RELATIONS})
        verdict, codes, decisive = "INVALID", ["signature"], failed_signatures[0]
    else:
        claims.update(relations(approval, invocation, receipt))
        codes = [name for name in RELATIONS if claims[name] == "fail"]
        verdict = "MISMATCH" if codes else "MATCH"
        decisive = codes[0] if codes else None
    claims["binding"] = "not_evaluated"
    result = {"verdict": verdict, "claims": claims, "codes": codes, "decisive": decisive}
    deny = case / "deny-receipt.json"
    if deny.exists():
        result["unjoined"] = {"deny-receipt.json": {
            "signature_receipt": signature(read_object(deny), "agent")}}
    return result


def check_source(root: Path) -> None:
    """Check the complete retained population and bytes before evaluating it."""
    source = read_object(root / "SOURCE.json")
    paths = [item["path"] for item in source["files"]]
    expected = set(paths)
    if len(paths) != len(expected):
        raise ValueError("duplicate retained source declaration")
    actual = {p.relative_to(root).as_posix() for p in (root / "retained").rglob("*")
              if p.is_file()}
    if actual != expected:
        raise ValueError("retained source population differs")
    for item in source["files"]:
        path = root / item["path"]
        if path.is_symlink() or not path.resolve().is_relative_to((root / "retained").resolve()):
            raise ValueError("retained source path escapes its root")
        raw = path.read_bytes()
        if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError(f"retained source bytes differ: {item['path']}")


def compare(root: Path, expected: dict[str, Any]) -> dict[str, Any]:
    """Compare every native output field without replacing disagreements."""
    check_source(root)
    rows, differences = [], []
    if expected.get("pinned_keys") != KEYS:
        differences.append({"field": "pinned_keys", "reader": KEYS,
                            "producer": expected.get("pinned_keys")})
    claim_order = [*SIGNATURES, *RELATIONS, "binding"]
    if expected.get("claims") != claim_order:
        differences.append({"field": "claims", "reader": claim_order,
                            "producer": expected.get("claims")})
    declared = expected.get("cases", {})
    if not isinstance(declared, dict):
        raise ValueError("expected cases object")
    if set(declared) != set(CASES):
        differences.append({"field": "case_population", "reader": list(CASES),
                            "producer": sorted(declared)})
    for name in CASES:
        case = root / "retained" / "cases" / name
        actual = evaluate(case)
        wanted = declared.get(name, {})
        if not isinstance(wanted, dict):
            raise ValueError(f"expected case object: {name}")
        checked = {**actual, "dir": f"cases/{name}", "files": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in case.glob("*.json")}}
        # JSON representation keeps Boolean values distinct from numeric values.
        for key in sorted(set(checked) | set(wanted)):
            if (key not in checked or key not in wanted or
                    json.dumps(checked.get(key), sort_keys=True) != json.dumps(wanted.get(key), sort_keys=True)):
                differences.append({"case": name, "field": key,
                                    "reader": checked.get(key), "producer": wanted.get(key)})
        rows.append({"case": name, **actual})
    return {"rows": rows, "differences": differences}


def main(argv: list[str] | None = None) -> int:
    """Write a JSON report; return one for disagreement and two for setup errors."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--expected", type=Path)
    args = parser.parse_args(argv)
    try:
        expected_path = args.expected or args.root / "retained" / "expected.json"
        report = compare(args.root, read_object(expected_path))
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(json.dumps({"setup_error": str(error)}))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 1 if report["differences"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
