#!/usr/bin/env python3
"""Reproduce the pinned APS byte comparisons and a changed-expectation control."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent


def run_fixture(path: str) -> dict[str, Any]:
    """Run the published crate against one fixture and return its report."""
    result = subprocess.run(
        ["cargo", "run", "--quiet", "--locked", "--manifest-path", "runner/Cargo.toml", "--", path],
        cwd=HERE,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def without_runtime(report: dict[str, Any]) -> dict[str, Any]:
    """Exclude compiler metadata from the deterministic result comparison."""
    return {key: value for key, value in report.items() if key != "runtime_version"}


def check_fixture(entry: dict[str, Any]) -> None:
    """Check the source digest, every output row, and a negative control."""
    path = HERE / entry["path"]
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
        raise ValueError(f"fixture digest differs: {entry['path']}")
    version = path.stem.rsplit("-", 1)[1]
    expected = json.loads((HERE / "results" / f"{version}.json").read_text())
    actual = run_fixture(entry["path"])
    if without_runtime(actual) != without_runtime(expected):
        raise ValueError(f"reproduction differs: {entry['path']}")
    if actual["summary"] != {"total": entry["cases"], "byte_match": entry["cases"], "sha256_match": entry["cases"]}:
        raise ValueError(f"canonical bytes or digests differ: {entry['path']}")
    check_negative_control(json.loads(raw), entry["cases"])
    print(f"{version}: {entry['cases']}/{entry['cases']} byte and digest matches; negative control detected")


def check_negative_control(fixture: dict[str, Any], total: int) -> None:
    """Change one expected byte and digest, then require one mismatched row."""
    vector = fixture["vectors"][0]
    altered = bytearray.fromhex(vector["canonical_bytes_hex"])
    altered[-1] ^= 1
    vector["canonical_bytes_hex"] = altered.hex()
    vector["canonical_sha256"] = hashlib.sha256(altered).hexdigest()
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "changed-expectation.json"
        path.write_text(json.dumps(fixture))
        result = run_fixture(str(path))
    if result["summary"] != {"total": total, "byte_match": total - 1, "sha256_match": total - 1}:
        raise ValueError("changed-expectation control did not produce exactly one mismatch")
    mismatches = [case["name"] for case in result["cases"] if not case["byte_match"] or not case["sha256_match"]]
    if mismatches != [vector["name"]]:
        raise ValueError("changed-expectation control mismatched another case")


def main() -> None:
    """Reproduce both pinned fixtures and fail on changed results."""
    manifest = json.loads((HERE / "MANIFEST.json").read_text())
    for entry in manifest["fixtures"]:
        check_fixture(entry)


if __name__ == "__main__":
    main()
