#!/usr/bin/env python3
"""Fail unless the repository's Latest GitHub release is its newest corpus tag.

The corpus is released under bare `v<major>.<minor>.<patch>` tags. Sub-package
releases (`dsse-npm-v*`, `jcs-admit-*`, `agent-evidence-vocabulary-v*`, ...) must
never be Latest, because the repository page and `releases/latest` then point
at a package release instead of the corpus.

Usage: check-latest-release.py <owner/repo>   (needs `gh` and a checkout with tags)
"""
from __future__ import annotations

import re
import subprocess
import sys

CORPUS_TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")


def newest_corpus_tag(tags: list[str]) -> str | None:
    """Return the highest `v<x>.<y>.<z>` tag in tags, or None."""
    found: list[tuple[tuple[int, ...], str]] = []
    for tag in tags:
        match = CORPUS_TAG.match(tag)
        if match:
            found.append((tuple(int(part) for part in match.groups()), tag))
    return max(found)[1] if found else None


def verdict(tags: list[str], latest: str) -> str | None:
    """Return an error string, or None when Latest is the newest corpus tag."""
    newest = newest_corpus_tag(tags)
    if newest is None:
        return "no v<major>.<minor>.<patch> tag exists, so there is nothing to compare"
    if latest != newest:
        return f"Latest release is {latest!r}, but the newest corpus tag is {newest!r}"
    return None


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    tags = subprocess.run(
        ["git", "tag", "--list", "v*"], check=True, capture_output=True, text=True
    ).stdout.split()
    latest = subprocess.run(
        ["gh", "api", f"repos/{argv[1]}/releases/latest", "--jq", ".tag_name"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    error = verdict(tags, latest)
    if error:
        print(f"::error::{error}")
        return 1
    print(f"Latest release {latest} is the newest corpus tag")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
