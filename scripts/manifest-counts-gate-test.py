#!/usr/bin/env python3
"""Tests for scripts/manifest-counts-gate.py.

Each refusal case writes one manifest broken in exactly one way into a scratch git
repository and asks the gate; the accepting cases show the gate is not one that refuses
everything. The last case runs the gate on this repository.

Usage: python3 scripts/manifest-counts-gate-test.py
Exit 0 when every case holds; 1 on a summary of the failures.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load() -> object:
    spec = importlib.util.spec_from_file_location(
        "manifest_counts_gate", HERE / "manifest-counts-gate.py"
    )
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load the gate")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = _load()
ENTRIES = [{"id": "a"}, {"id": "b"}, {"id": "c"}]


def findings_for(manifest: dict[str, object] | None, raw: str | None = None) -> list[str]:
    """The gate's findings for a scratch repository holding exactly this one manifest."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        directory = root / "vectors-example"
        directory.mkdir()
        text = raw if raw is not None else json.dumps(manifest)
        (directory / "MANIFEST.json").write_text(text, encoding="utf-8")
        subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
        return gate.check(root)  # type: ignore[attr-defined, no-any-return]


def expect(label: str, findings: list[str], needle: str | None) -> str | None:
    """None when the findings are what the case expects, else the reason it failed."""
    if needle is None:
        return None if not findings else f"{label}: expected a pass, got {findings}"
    if len(findings) != 1 or needle not in findings[0]:
        return f"{label}: expected one finding containing {needle!r}, got {findings}"
    return None


def main() -> int:
    cases = [
        (
            "a corpus without a counts block is refused",
            findings_for({"vectors": ENTRIES}),
            "carries no counts block",
        ),
        (
            "an empty counts block is refused",
            findings_for({"vectors": ENTRIES, "counts": {}}),
            "carries no counts block",
        ),
        (
            "counts that do not sum to the entries are refused",
            findings_for({"vectors": ENTRIES, "counts": {"accept": 1, "reject": 1}}),
            "summing to 2",
        ),
        (
            "a non-integer count is refused",
            findings_for({"vectors": ENTRIES, "counts": {"accept": "3"}}),
            "not a non-negative integer",
        ),
        (
            "a boolean count is refused",
            findings_for({"vectors": ENTRIES, "counts": {"accept": True, "reject": 2}}),
            "not a non-negative integer",
        ),
        (
            "a wrong declared total is refused",
            findings_for({"vectors": ENTRIES, "counts": {"accept": 1, "reject": 2, "total": 9}}),
            "declares a counts total of 9",
        ),
        (
            "a manifest that lists no entries is refused",
            findings_for({"counts": {"accept": 1}}),
            "lists no vectors",
        ),
        ("a manifest that is not JSON is refused", findings_for(None, raw="{"), "unreadable"),
        (
            "counts in the corpus's own words are accepted",
            findings_for(
                {"vectors": ENTRIES, "counts": {"failed": 1, "verified": 1, "notEstablished": 1}}
            ),
            None,
        ),
        (
            "a matching declared total is accepted",
            findings_for({"vectors": ENTRIES, "counts": {"accept": 1, "reject": 2, "total": 3}}),
            None,
        ),
        (
            "entries under the cases key are accepted",
            findings_for({"cases": ENTRIES, "counts": {"accept": 3}}),
            None,
        ),
    ]
    failures = [msg for label, found, needle in cases if (msg := expect(label, found, needle))]
    live = subprocess.run(
        [sys.executable, str(HERE / "manifest-counts-gate.py")],
        capture_output=True,
        text=True,
        check=False,
    )
    if live.returncode != 0:
        failures.append(f"this repository fails the gate: {live.stdout.strip()}")
    for failure in failures:
        print("FAIL:", failure)
    if failures:
        return 1
    print(f"ok: {len(cases) + 1} cases hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
