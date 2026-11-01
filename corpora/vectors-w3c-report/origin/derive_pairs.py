#!/usr/bin/env python3
"""Derive the 42 delta-related pairs of the disensor corpus at one commit.

    python3 derive_pairs.py <checkout of NicolasRocchia/disensor at 1e36257>

Writes ``disensor-1e36257-pairs.json`` beside this file. The pairing rule is
the one the list message of 2026-09-15 counted: a MUST-PASS and a MUST-FAIL
vector of the same schema version whose ``artifact`` objects differ in exactly
one leaf path. The count at that commit is 42 (v0.2 4, v0.3 16, v0.4 22), and
this script refuses any other total, because the corpus these pairs feed
claims to re-cut those 42 and no others.

Each record of a pair is then observed by running the pinned checker,
``disensor.rules.validate_artifact`` at the same commit, so the observation
is what the checker produced and not the vector's declared expectation. The
two are compared and a disagreement stops the derivation.

This is a DERIVATION tool and not part of the corpus's verification path: it
needs the checkout and the ``jsonschema`` package the checker imports. The
generator reads the JSON it writes and needs neither.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import sys
from pathlib import Path
from typing import Any

COMMIT = "1e36257779b4933814445423188ec099a78017ee"
EXPECTED_PAIRS = {"v0.2": 4, "v0.3": 16, "v0.4": 22}


def leaves(value: Any, path: tuple[Any, ...] = ()) -> Any:
    if isinstance(value, dict):
        for key, item in value.items():
            yield from leaves(item, (*path, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from leaves(item, (*path, index))
    else:
        yield path, json.dumps(value, sort_keys=True)


def one_field_pairs(vectors: dict[str, dict[str, Any]], version: str) -> list[dict[str, Any]]:
    """Every (pass, fail) pair of one version whose artifacts differ in one leaf."""
    passes = [k for k, v in vectors.items() if v["expected"]["valid"]]
    fails = [k for k, v in vectors.items() if not v["expected"]["valid"]]
    pairs: list[dict[str, Any]] = []
    for accepted in passes:
        left = dict(leaves(vectors[accepted]["artifact"]))
        for rejected in fails:
            right = dict(leaves(vectors[rejected]["artifact"]))
            keys = set(left) | set(right)
            differing = [k for k in keys if left.get(k) != right.get(k)]
            if len(differing) != 1:
                continue
            key = differing[0]
            pairs.append(
                {
                    "version": version,
                    "pass": accepted,
                    "fail": rejected,
                    "field": "/".join(str(part) for part in key),
                    "before": json.loads(left[key]) if key in left else None,
                    "after": json.loads(right[key]) if key in right else None,
                }
            )
    return pairs


def observe(
    version_dir: Path, name: str, validate: Any, labels: Any
) -> dict[str, Any] | None:
    """Run the pinned checker over one record; None when it disagrees with the vector."""
    raw = (version_dir / f"{name}.json").read_bytes()
    document = json.loads(raw)
    errors = validate(document["artifact"])
    observed = {"valid": not errors, "rules": labels(errors)}
    declared = {"valid": document["expected"]["valid"], "rules": document["expected"]["rules"]}
    if observed != declared:
        print(f"FAIL: {version_dir.name}/{name}: checker {observed} disagrees with {declared}")
        return None
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "verdict": "pass" if not errors else "fail",
        "rules": labels(errors),
        "errorCount": len(errors),
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    checkout = Path(sys.argv[1])
    sys.path.insert(0, str(checkout / "src"))
    # The checker is the checkout's, imported by name at run time: it is not a
    # dependency of this repository and no static checker should resolve it.
    validate_artifact = importlib.import_module("disensor.rules").validate_artifact
    labels = importlib.import_module("disensor.vectors")._labels

    root = checkout / "spec" / "vectors"
    pairs: list[dict[str, Any]] = []
    records: dict[str, dict[str, Any]] = {}
    for version_dir in sorted(root.iterdir()):
        version = version_dir.name
        vectors: dict[str, dict[str, Any]] = {}
        for file in sorted(version_dir.glob("*.json")):
            if file.name != "index.json":
                vectors[file.stem] = json.loads(file.read_text(encoding="utf-8"))
        found = one_field_pairs(vectors, version)
        if len(found) != EXPECTED_PAIRS.get(version):
            print(
                f"FAIL: {version} has {len(found)} one-field pairs, "
                f"expected {EXPECTED_PAIRS.get(version)}"
            )
            return 1
        pairs.extend(found)
        for pair in found:
            for name in (pair["pass"], pair["fail"]):
                ident = f"{version}/{name}"
                if ident in records:
                    continue
                observed = observe(version_dir, name, validate_artifact, labels)
                if observed is None:
                    return 1
                records[ident] = observed
    pairs.sort(key=lambda p: (p["version"], p["pass"], p["fail"]))
    out = {
        "repository": "NicolasRocchia/disensor",
        "commit": COMMIT,
        "checker": "disensor.rules.validate_artifact",
        "pairingRule": (
            "a MUST-PASS and a MUST-FAIL vector of the same schema version whose "
            "artifact objects differ in exactly one leaf path"
        ),
        "pairs": pairs,
        "records": dict(sorted(records.items())),
    }
    target = Path(__file__).resolve().parent / "disensor-1e36257-pairs.json"
    target.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {target.name}: {len(pairs)} pairs over {len(records)} records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
