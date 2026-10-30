#!/usr/bin/env python3
"""Check that every vector family, case and admission policy docs/aimm-levels.md names exists at its pin.

The page pins agent-evidence-vectors to a tag and agent-evidence-admission to a
commit in one HTML comment. This reads both trees from the GitHub API (with GITHUB_TOKEN when set, so a
shared CI runner address does not hit the anonymous rate limit) and fails
when a cited path is absent at the pin, so the table can never name a family the
pinned release does not ship.

Exit 0: every cited path exists. Exit 1: at least one is missing, each named.
Exit 2: the page or a tree could not be read, so nothing was checked.
"""
import json
import os
import pathlib
import re
import sys
import urllib.request

PAGE = pathlib.Path(__file__).resolve().parent.parent / "docs" / "aimm-levels.md"
PINS = re.compile(r"<!-- pins: vectors=(\S+) admission=([0-9a-f]{40}) -->")
CODE = re.compile(r"`([^`\s]+)`")
TREE_URL = "https://api.github.com/repos/probityai/{repo}/git/trees/{ref}?recursive=1"


def parse(text):
    """Return (vectors_ref, admission_ref, vector_paths, admission_paths) cited in table rows."""
    pins = PINS.search(text)
    if pins is None:
        raise ValueError("no pins comment in the page")
    vector_paths, admission_paths = set(), set()
    for line in text.splitlines():
        if not re.match(r"\|\s*L[1-5]\s*\|", line):
            continue
        cells = line.strip().strip("|").split("|")
        if len(cells) != 3:
            raise ValueError(f"table row does not have three cells: {line}")
        vector_paths.update(CODE.findall(cells[1]))
        admission_paths.update(CODE.findall(cells[2]))
    if not vector_paths:
        raise ValueError("no vector family cited in any table row")
    return pins.group(1), pins.group(2), vector_paths, admission_paths


def missing(cited, tree_paths):
    """Return the cited paths that are not a path in the tree, sorted."""
    return sorted(p for p in cited if p not in tree_paths)


def fetch_tree(repo, ref):
    """Return the set of every path in repo at ref."""
    req = urllib.request.Request(TREE_URL.format(repo=repo, ref=ref))
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = json.load(resp)
    if body.get("truncated"):
        raise ValueError(f"{repo} tree at {ref} came back truncated")
    return {entry["path"] for entry in body["tree"]}


def main():
    try:
        vref, aref, vpaths, apaths = parse(PAGE.read_text(encoding="utf-8"))
        vtree = fetch_tree("agent-evidence-vectors", vref)
        atree = fetch_tree("agent-evidence-admission", aref)
    except (OSError, ValueError, KeyError) as exc:
        print(f"check did not run: {exc}", file=sys.stderr)
        return 2
    gone = [f"agent-evidence-vectors@{vref}: {p}" for p in missing(vpaths, vtree)]
    gone += [f"agent-evidence-admission@{aref[:12]}: {p}" for p in missing(apaths, atree)]
    for line in gone:
        print(f"missing at pin: {line}", file=sys.stderr)
    if gone:
        return 1
    print(f"ok: {len(vpaths)} vector paths and {len(apaths)} admission paths exist at their pins")
    return 0


if __name__ == "__main__":
    sys.exit(main())
