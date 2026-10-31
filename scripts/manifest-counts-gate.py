#!/usr/bin/env python3
"""Manifest counts gate: every corpus manifest carries a counts block that agrees with its entries.

A reader who clones the repository states a corpus's bucket split from its manifest, and
so does the outbound-count lint that checks letters against the published corpora. A
manifest with entries and no `counts` block leaves that split unestablished, and the lint
refuses every figure that depends on it. Thirty corpora reached that state because the
rule lived in no generator and no check. This gate is the check.

What it requires of every tracked `vectors*/MANIFEST.json`:

  * a non-empty `counts` object of non-negative integers, in the corpus's own verdict
    words (the words are not normalised, because a recipient who reads the manifest finds
    those words);
  * the members other than `total` sum to the number of entries the manifest lists;
  * a `total` member, where present, equals that sum.

Usage: python3 scripts/manifest-counts-gate.py
Exit 0 when every manifest holds; 1 and one line per defect otherwise.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ENTRY_KEYS = ("vectors", "cases", "entries")


def tracked_manifests(root: Path) -> list[Path]:
    """Every tracked `vectors*/MANIFEST.json`, from git, never from a directory walk."""
    out = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", "vectors*/MANIFEST.json"],
        capture_output=True,
        check=True,
    ).stdout.decode()
    return [root / rel for rel in out.split("\0") if rel and rel.count("/") == 1]


def entry_count(manifest: dict[str, object]) -> int | None:
    """How many entries the manifest lists, or None when it lists none."""
    for key in ENTRY_KEYS:
        entries = manifest.get(key)
        if isinstance(entries, list):
            return len(entries)
    return None


def defect(path: Path) -> str | None:
    """Why one manifest fails, or None when it holds."""
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return f"is unreadable ({exc})"
    if not isinstance(manifest, dict):
        return "is not a JSON object"
    entries = entry_count(manifest)
    if entries is None:
        return "lists no vectors, cases or entries"
    counts = manifest.get("counts")
    if not isinstance(counts, dict) or not counts:
        return "carries no counts block"
    for word, value in counts.items():
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            return f"has a counts member {word!r} that is not a non-negative integer"
    summed = sum(value for word, value in counts.items() if word != "total")
    if summed != entries:
        return f"lists {entries} entries and a counts block summing to {summed}"
    if "total" in counts and counts["total"] != summed:
        return f"declares a counts total of {counts['total']} while its buckets sum to {summed}"
    return None


def check(root: Path) -> list[str]:
    """One line per manifest that fails, naming the file and the reason."""
    findings = []
    for path in tracked_manifests(root):
        reason = defect(path)
        if reason is not None:
            findings.append(f"FAIL: {path.relative_to(root)} {reason}")
    return findings


def main() -> int:
    manifests = tracked_manifests(REPO_ROOT)
    if not manifests:
        print("FAIL: no tracked vectors*/MANIFEST.json was found, so nothing was checked.")
        return 1
    findings = check(REPO_ROOT)
    for line in findings:
        print(line)
    if findings:
        print(f"{len(findings)} of {len(manifests)} manifests fail.")
        return 1
    print(
        f"ok: {len(manifests)} of {len(manifests)} manifests carry counts that match their entries."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
