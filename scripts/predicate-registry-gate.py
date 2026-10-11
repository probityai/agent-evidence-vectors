#!/usr/bin/env python3
"""Predicate registry gate: every type URI this host answers for is registered.

A `predicateType` under https://probityai.github.io/agent-evidence-vectors/predicate/
is written by a producer inside the bytes it signs, so it cannot move after it is
published and it must not 404. The Pages build serves one page per heading in
spec/predicates/REGISTRY.md and nothing else, so a URI that appears in the tree
but not in the registry is a URI that 404s.

That happened twice. `predicate/v1/self-reported-record` was named by its
contract and by every member of vectors-self-reported-record/, and
`predicate/v1/govops-trace-record` sat inside the signed DSSE payloads of the
GovOps TRACE members, and neither was registered. The registry said a missing
URI would be "visible in review"; nobody reviewing a base64 payload can see one.

So this reads the tracked tree the way a verifier would. It collects every URI
under the prefix that appears in a tracked file, both as text and inside any
base64 run that decodes to UTF-8 (a DSSE payload, or a payload quoted inside a
JSON string), and refuses when one is not a registry heading.

    python3 scripts/predicate-registry-gate.py
    python3 scripts/predicate-registry-gate.py --root <checkout>

Exit 0 when every URI found is registered. Exit 1 when one is not, and also when
the scan finds no URI at all: this repository defines predicates, so an empty
scan means the read path is broken, not that the tree is clean.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

PREFIX = "https://probityai.github.io/agent-evidence-vectors/predicate/"
URI_RE = re.compile(re.escape(PREFIX) + r"(v\d+/[a-z0-9-]+)")
# The same heading shape docs/site/build.py reads to decide which pages exist.
HEADING_RE = re.compile(r"^### `predicate/(v\d+)/([a-z0-9-]+)`$", re.MULTILINE)
BASE64_RUN_RE = re.compile(rb"[A-Za-z0-9+/_-]{40,}={0,2}")
REGISTRY = Path("spec/predicates/REGISTRY.md")


def registered(root: Path) -> set[str]:
    """The `vN/name` of every registry heading."""
    text = (root / REGISTRY).read_text(encoding="utf-8")
    return {f"{version}/{name}" for version, name in HEADING_RE.findall(text)}


def decoded(run: bytes) -> str | None:
    """The UTF-8 text a base64 or base64url run decodes to, if it decodes."""
    padded = run + b"=" * (-len(run) % 4)
    for decode in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            return decode(padded).decode("utf-8")
        except (binascii.Error, ValueError):
            continue
    return None


def found(root: Path) -> dict[str, dict[str, set[str]]]:
    """Every URI under the prefix in the tracked tree, by where it was seen."""
    listing = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z"], capture_output=True, check=True
    ).stdout
    seen: dict[str, dict[str, set[str]]] = defaultdict(lambda: {"text": set(), "signed": set()})
    for name in filter(None, listing.decode("utf-8").split("\0")):
        path = root / name
        if not path.is_file():
            continue
        data = path.read_bytes()
        for match in URI_RE.finditer(data.decode("latin-1")):
            seen[match.group(1)]["text"].add(name)
        for run in BASE64_RUN_RE.finditer(data):
            text = decoded(run.group(0))
            if text is None:
                continue
            for match in URI_RE.finditer(text):
                seen[match.group(1)]["signed"].add(name)
    return seen


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    root = parser.parse_args().root.resolve()

    uris = found(root)
    if not uris:
        print(
            f"FAIL: no URI under {PREFIX} was found in the tracked tree, so nothing "
            "was compared. That is a broken read, not a clean tree.",
            file=sys.stderr,
        )
        return 1
    known = registered(root)
    missing = sorted(set(uris) - known)
    if missing:
        print(
            f"FAIL: {len(missing)} predicate type URI(s) appear in the tree but not "
            f"in {REGISTRY}, so the Pages site will answer 404 for them:",
            file=sys.stderr,
        )
        for uri in missing:
            where = uris[uri]
            print(f"  {PREFIX}{uri}", file=sys.stderr)
            for kind in ("signed", "text"):
                files = sorted(where[kind])
                if files:
                    shown = ", ".join(files[:3]) + (" ..." if len(files) > 3 else "")
                    print(f"    {kind}: {len(files)} file(s): {shown}", file=sys.stderr)
        print(
            f"\nAdd a `### \\`predicate/<version>/<name>\\`` entry to {REGISTRY}. "
            "Do not change the URI: records already carry it.",
            file=sys.stderr,
        )
        return 1
    signed = sum(1 for where in uris.values() if where["signed"])
    print(
        f"ok: {len(uris)} predicate type URI(s) under the pages host appear in the "
        f"tree, {signed} of them inside signed payloads, and every one is registered"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
