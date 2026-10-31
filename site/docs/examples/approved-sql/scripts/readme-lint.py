#!/usr/bin/env python3
"""Fail a README that has outgrown its first screen.

A README is read by someone deciding in half a minute whether to use the
project, and by an agent that loads it whole. Both are served by the same
short page: what it is, who it is for, a pinned install line, an example that
runs, the status, and links to the detail in docs/. This check holds a README
to that shape with three rules:

1. Prose words, outside fenced code, HTML tags and link targets, stay at or
   under --max-words (default 600). That is the 60th percentile, 585 words,
   rounded up, of thirty-two READMEs from sigstore, in-toto, SLSA, OPA, DSSE, OpenSSF
   and the most-used Rust crates and Python packages, counted with this counter
   on 2026-09-27. Their median is 503.
2. A fenced code block (the install line or the example) opens within the
   first --first-screen lines (default 45).
3. Every relative link and image in the README resolves to a file in the
   repository, so text moved into docs/ cannot leave a dead pointer behind.

Exit 0 when the README passes, 1 when a rule fails, 2 when it cannot be read.
Standard library only, so any repository can run it without installing anything.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

DEFAULT_MAX_WORDS = 600
DEFAULT_FIRST_SCREEN = 45

FENCE = re.compile(r"^\s*(```|~~~)")
LINK_TARGET = re.compile(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
SRC_OR_HREF = re.compile(r"""\b(?:src|href)=["']([^"']+)["']""")
REF_DEF = re.compile(r"^\s*\[[^\]]+\]:\s*(\S+)", re.MULTILINE)
EXTERNAL = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|#|//)", re.IGNORECASE)


def split_code(text: str) -> tuple[list[str], int | None]:
    """Return the non-code lines and the 1-based line of the first fence."""
    prose: list[str] = []
    first_fence: int | None = None
    inside = False
    for number, line in enumerate(text.splitlines(), start=1):
        if FENCE.match(line):
            if first_fence is None:
                first_fence = number
            inside = not inside
            continue
        if not inside:
            prose.append(line)
    return prose, first_fence


def prose_words(text: str) -> int:
    """Words a reader reads: fenced code, HTML tags, URLs and markup removed."""
    lines, _ = split_code(text)
    body = "\n".join(lines)
    body = re.sub(r"<!--.*?-->", " ", body, flags=re.DOTALL)
    body = re.sub(r"<[^>]+>", " ", body)
    body = REF_DEF.sub(" ", body)
    body = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"\1", body)
    body = re.sub(r"\]\([^)]*\)", "]", body)
    body = re.sub(r"https?://\S+", " ", body)
    body = re.sub(r"[#*_`>|\[\]-]", " ", body)
    return len([w for w in body.split() if re.search(r"\w", w)])


def relative_targets(text: str) -> list[str]:
    lines, _ = split_code(text)
    body = "\n".join(lines)
    found = LINK_TARGET.findall(body) + SRC_OR_HREF.findall(body) + REF_DEF.findall(body)
    return [t for t in found if not EXTERNAL.match(t)]


def check(readme: Path, max_words: int, first_screen: int) -> list[str]:
    text = readme.read_text(encoding="utf-8")
    failures: list[str] = []
    words = prose_words(text)
    if words > max_words:
        failures.append(
            f"{readme}: {words} prose words, over the limit of {max_words}. Move the detail "
            "into docs/ and link to it; keep what it is, who it is for, the pinned install "
            "line, a runnable example, the status and the links."
        )
    _, fence = split_code(text)
    if fence is None or fence > first_screen:
        where = (
            "has no fenced code block"
            if fence is None
            else f"opens its first code block on line {fence}"
        )
        failures.append(
            f"{readme}: {where}; the install line or example must open within the first "
            f"{first_screen} lines."
        )
    root = readme.resolve().parent
    for target in relative_targets(text):
        path = target.split("#", 1)[0].split("?", 1)[0]
        if path and not (root / path).exists():
            failures.append(
                f"{readme}: relative link '{target}' resolves to no file in the repository."
            )
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("readme", nargs="?", default="README.md", type=Path)
    parser.add_argument("--max-words", type=int, default=DEFAULT_MAX_WORDS)
    parser.add_argument("--first-screen", type=int, default=DEFAULT_FIRST_SCREEN)
    args = parser.parse_args(argv)
    try:
        failures = check(args.readme, args.max_words, args.first_screen)
    except OSError as exc:
        print(f"readme-lint: could not read {args.readme}: {exc}", file=sys.stderr)
        return 2
    if failures:
        print("\n".join(failures))
        return 1
    text = args.readme.read_text(encoding="utf-8")
    words = prose_words(text)
    print(f"readme-lint: {args.readme} passes ({words} of {args.max_words} prose words).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
