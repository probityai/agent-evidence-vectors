#!/usr/bin/env python3
"""Receipt verdict-code registry gate.

``docs/reference/receipt-verdict-codes.json`` maps this suite's failure codes onto a
closed vocabulary of seven receipt verdict codes. This gate holds the registry to the
two things it is built from, in both directions:

* ``aee/codes.go``: every validity code is mapped by exactly one verdict code, every
  consumer-policy code is mapped or listed as outside the receipt axis, and no name in
  the registry is a code the Go core does not define.
* ``vectors/MANIFEST.json``: every verdict code names one vector that produces it. A
  failure code's vector is a reject whose declared codes all map to that verdict code.
  A limit code's vector is an accept whose tier columns carry the code's tier.

An unknown code fails closed: ``verdict_for`` raises for a code no list names, and a
verdict code outside the seven is refused by name. Run with no arguments from anywhere.
Exit 0 when the registry holds; 1 on any disagreement.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY = REPO_ROOT / "docs" / "reference" / "receipt-verdict-codes.json"
CODES_GO = REPO_ROOT / "aee" / "codes.go"
MANIFEST = REPO_ROOT / "vectors" / "MANIFEST.json"

VERDICT_CODES = (
    "NOT_PUBLICLY_VERIFIABLE",
    "LEAF_HASH_MISMATCH",
    "PROOF_BROKEN",
    "CLAIM_NOT_BOUND",
    "SUMMARY_MISMATCH",
    "MALFORMED",
    "NOT_RECONSTRUCTIBLE",
)
KINDS = {"failure": "reject", "limit": "accept"}
CONST_RE = re.compile(r'^Code[A-Za-z0-9]+\s+Code\s*=\s*"([a-z0-9-]+)"')
POLICY_HEADING = "Consumer-policy stage codes"


class UnknownCode(ValueError):
    """A code the registry does not classify. Callers treat it as a refusal."""


def parse_codes(codes_go: Path) -> tuple[set[str], set[str]]:
    """Split ``aee/codes.go`` into (validity codes, consumer-policy codes)."""
    validity: set[str] = set()
    policy: set[str] = set()
    target = validity
    comment: list[str] = []
    in_block = False
    for raw in codes_go.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("//"):
            comment.append(line)
        elif line.startswith("const ("):
            target = policy if POLICY_HEADING in " ".join(comment) else validity
            in_block, comment = True, []
        elif in_block and line == ")":
            in_block, comment = False, []
        else:
            match = CONST_RE.match(line)
            if in_block and match:
                target.add(match.group(1))
            if not line:
                comment = []
    if not validity or not policy:
        raise SystemExit(f"FAIL: {codes_go} yielded no validity or no policy codes")
    return validity, policy


def verdict_for(code: str, registry: dict[str, Any]) -> str | None:
    """The verdict code a failure code maps to, or None for a policy code outside the axis.

    Raises UnknownCode for a code no list names, so a caller that reads a code from a
    newer verifier refuses it instead of passing it.
    """
    for entry in registry["codes"]:
        if code in entry["validity_codes"] or code in entry["consumer_policy_codes"]:
            return str(entry["code"])
    if code in registry["outside_receipt_axis"]:
        return None
    raise UnknownCode(f"no verdict code classifies {code!r}")


def _shape_errors(registry: dict[str, Any]) -> list[str]:
    names = [entry.get("code") for entry in registry.get("codes", [])]
    errors = []
    if sorted(names) != sorted(VERDICT_CODES):
        errors.append(
            f"verdict codes are {sorted(map(str, names))}, expected exactly {sorted(VERDICT_CODES)}"
        )
    for entry in registry.get("codes", []):
        if entry.get("kind") not in KINDS:
            errors.append(
                f"{entry.get('code')}: kind {entry.get('kind')!r} is neither failure nor limit"
            )
        if (entry.get("kind") == "limit") != bool(entry.get("tier")):
            errors.append(f"{entry.get('code')}: a limit carries a tier and a failure carries none")
    vectors = [entry.get("vector") for entry in registry.get("codes", [])]
    if len(set(vectors)) != len(vectors):
        errors.append("two verdict codes share one vector")
    return errors


def _closure_errors(registry: dict[str, Any], validity: set[str], policy: set[str]) -> list[str]:
    errors = []
    seen: dict[str, str] = {}
    for entry in registry["codes"]:
        for field, universe in (("validity_codes", validity), ("consumer_policy_codes", policy)):
            for code in entry[field]:
                if code not in universe:
                    errors.append(
                        f"{entry['code']}.{field} names {code!r}, "
                        "which aee/codes.go does not define there"
                    )
                if code in seen:
                    errors.append(f"{code!r} is mapped by both {seen[code]} and {entry['code']}")
                seen[code] = entry["code"]
    outside = set(registry["outside_receipt_axis"])
    for code in sorted(outside & set(seen)):
        errors.append(f"{code!r} is both mapped and outside the receipt axis")
    for code in sorted(outside - policy):
        errors.append(f"outside_receipt_axis names {code!r}, which is not a consumer-policy code")
    for code in sorted((validity | policy) - set(seen) - outside):
        errors.append(
            f"{code!r} is classified by no verdict code and is not outside the receipt axis"
        )
    return errors


def _vector_errors(registry: dict[str, Any], manifest: dict[str, Any]) -> list[str]:
    by_id = {entry["id"]: entry for entry in manifest["vectors"]}
    errors = []
    for entry in registry["codes"]:
        vector = by_id.get(entry["vector"])
        if vector is None:
            errors.append(f"{entry['code']}: vector {entry['vector']} is not in the manifest")
            continue
        expected = vector.get("expected") or {}
        if vector["kind"] != KINDS[entry["kind"]]:
            errors.append(
                f"{entry['code']}: vector {entry['vector']} is a {vector['kind']}, "
                f"expected {KINDS[entry['kind']]}"
            )
        elif entry["kind"] == "failure":
            stray = [c for c in expected.get("codes", []) if c not in entry["validity_codes"]]
            if stray or not expected.get("codes"):
                errors.append(
                    f"{entry['code']}: vector {entry['vector']} declares codes "
                    f"{stray or 'none'} outside this verdict code"
                )
        else:
            for column in ("tierWithoutKey", "tierWithPinnedKey"):
                if entry["tier"] not in expected.get(column, []):
                    errors.append(
                        f"{entry['code']}: vector {entry['vector']} {column} "
                        f"lacks tier {entry['tier']}"
                    )
    return errors


def check(
    registry: dict[str, Any], validity: set[str], policy: set[str], manifest: dict[str, Any]
) -> list[str]:
    """Every disagreement between the registry and its two sources."""
    errors = _shape_errors(registry)
    if errors:
        return errors
    return _closure_errors(registry, validity, policy) + _vector_errors(registry, manifest)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--registry", type=Path, default=REGISTRY)
    parser.add_argument("--codes", type=Path, default=CODES_GO)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    args = parser.parse_args(argv)
    registry = json.loads(args.registry.read_text(encoding="utf-8"))
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    validity, policy = parse_codes(args.codes)
    errors = check(registry, validity, policy, manifest)
    for error in errors:
        print(f"FAIL: {error}", file=sys.stderr)
    if not errors:
        print("receipt verdict codes: registry agrees with aee/codes.go and the manifest")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
