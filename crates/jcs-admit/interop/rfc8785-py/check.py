#!/usr/bin/env python3
"""Compare pinned Python JCS bytes and raw-input boundaries with native admission."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
NATIVE_COMMAND = [
    "cargo", "test", "--locked",
    "--test", "rfc8785_reference",
    "--test", "cross_rail_differential",
    "--test", "rfc8785_python_boundary",
]


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def verify_files(root: Path, entries: list[dict[str, Any]]) -> None:
    """Refuse source or corpus bytes that differ from the committed manifest."""
    for entry in entries:
        raw = (root / entry["path"]).read_bytes()
        if len(raw) != entry["bytes"] or digest(raw) != entry["sha256"]:
            raise ValueError(f"pinned bytes differ: {entry['path']}")


def load_implementation(source: Path, manifest: dict[str, Any]) -> Any:
    """Check both source modules before importing the pinned implementation."""
    verify_files(source, manifest["python_source"]["files"])
    sys.path.insert(0, str(source / "src"))
    implementation = importlib.import_module("rfc8785")
    if Path(implementation.__file__).resolve() != (source / "src/rfc8785/__init__.py").resolve():
        raise ValueError("rfc8785 was imported from a different source")
    if implementation.__version__ != manifest["python_source"]["version"]:
        raise ValueError("Python implementation version differs")
    return implementation


def python_outcome(implementation: Any, raw: bytes) -> dict[str, Any]:
    """Retain the actual parsed-object outcome separately from raw admission."""
    try:
        canonical = implementation.dumps(json.loads(raw))
    except (ValueError, UnicodeError) as error:
        return {"status": "refused", "error_class": type(error).__name__}
    return {
        "status": "accepted",
        "canonical_hex": canonical.hex(),
        "canonical_sha256": digest(canonical),
        "canonical_bytes": len(canonical),
    }


def require_outcome(actual: dict[str, Any], expected: dict[str, Any], name: str) -> None:
    """Require every declared outcome field, including exact expected bytes."""
    if any(actual.get(key) != value for key, value in expected.items()):
        raise ValueError(f"Python boundary outcome differs: {name}")


def require_bytes(actual: bytes, expected: bytes, name: str) -> None:
    """Compare byte identity before using a digest in a report."""
    if actual != expected:
        raise ValueError(f"canonical bytes differ: {name}")


def qualify_python(source: Path) -> dict[str, Any]:
    """Check every pinned corpus member and every declared Python outcome."""
    manifest = json.loads((HERE / "MANIFEST.json").read_text())
    implementation = load_implementation(source, manifest)
    verify_files(ROOT, manifest["corpus_source"]["files"])
    verify_files(ROOT, [manifest["raw_controls"]])
    positives = []
    for family, output in [("rfc8785", "output"), ("cross-rail", "canonical")]:
        base = ROOT / "tests/vectors" / family
        for expected_path in sorted((base / output).glob("*.json")):
            raw = (base / "input" / expected_path.name).read_bytes()
            expected = expected_path.read_bytes()
            actual = implementation.dumps(json.loads(raw))
            require_bytes(actual, expected, f"{family}/{expected_path.name}")
            positives.append({
                "name": f"{family}/{expected_path.stem}",
                "input_sha256": digest(raw),
                "canonical_sha256": digest(actual),
                "canonical_bytes": len(actual),
                "byte_match": True,
            })
    if len(positives) != 36:
        raise ValueError("expected all 6 reference and 30 Go byte cases")
    boundaries = []
    controls = json.loads((HERE / "controls.json").read_text())["cases"]
    if len(controls) != 11:
        raise ValueError("expected all 11 shared raw controls")
    for case in controls:
        raw = case["raw"].encode("utf-8")
        actual = python_outcome(implementation, raw)
        require_outcome(actual, case["python"], case["name"])
        boundaries.append({
            "name": case["name"],
            "profile": case["profile"],
            "input_sha256": digest(raw),
            "rust_expected": case.get("rust_error", "accepted"),
            "python": {key: value for key, value in actual.items() if key != "canonical_hex"},
        })
    go_rows = manifest["go_refusal_observations"]
    if len(go_rows) != 9:
        raise ValueError("expected all 9 Go raw refusals")
    for case in go_rows:
        raw = (ROOT / "tests/vectors/cross-rail/input" / (case["name"] + ".json")).read_bytes()
        actual = python_outcome(implementation, raw)
        require_outcome(actual, case["python"], case["name"])
        boundaries.append({
            "name": "cross-rail/" + case["name"],
            "profile": "ijson-integers",
            "input_sha256": digest(raw),
            "rust_expected": case["rust_error"],
            "python": {key: value for key, value in actual.items() if key != "canonical_hex"},
        })
    return {
        "schema": "jcs-admit.rfc8785-py.result.v1",
        "python_source": manifest["python_source"],
        "python_runtime": platform.python_version(),
        "manifest_sha256": digest((HERE / "MANIFEST.json").read_bytes()),
        "corpus_source": {key: value for key, value in manifest["corpus_source"].items() if key != "files"},
        "summary": {
            "independent_byte_matches": len(positives),
            "shared_positive_controls": 2,
            "shared_raw_refusals": 9,
            "go_raw_refusals": len(go_rows),
            "python_boundary_observations": len(boundaries),
        },
        "positive_cases": positives,
        "boundary_cases": boundaries,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python-source", type=Path, default=HERE / "source")
    parser.add_argument("--output", type=Path, default=HERE / "report.json")
    parser.add_argument("--verify-source", action="store_true")
    args = parser.parse_args()
    source = args.python_source.resolve()
    if args.verify_source:
        manifest = json.loads((HERE / "MANIFEST.json").read_text())
        load_implementation(source, manifest)
        print("Pinned rfc8785.py source modules and version match")
        return
    report = qualify_python(source)
    subprocess.run(NATIVE_COMMAND, cwd=ROOT, check=True)
    report["native"] = {"command": NATIVE_COMMAND, "status": "passed", "positive_byte_cases": 38, "raw_refusal_cases": 18}
    report["qualified_checkout"] = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout.strip()
    report["workflow_run_id"] = os.environ.get("GITHUB_RUN_ID")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print("Python and native admission: 38 exact byte cases; 18 native raw refusals; all 20 Python boundary outcomes match")


if __name__ == "__main__":
    main()
