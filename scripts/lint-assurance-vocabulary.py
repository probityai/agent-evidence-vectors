#!/usr/bin/env python3
"""Keep the two identity-and-record scales apart.

Identity assurance is measured in levels (spec/predicates/identity-assurance-levels.md).
Record custody is measured in grades (the record grades page). The words are not
interchangeable, so each page uses only its own word and carries one cross-link line, marked
``<!-- crosslink -->``, that names both. A violation exits 1 and names the file and line.

Exempt: fenced code blocks, inline code spans, and the cross-link line itself. The names of
existing suites and functions (``evidence-grade-floor/v1``, ``act_grade``) therefore pass
when written as code.

Usage: lint-assurance-vocabulary.py [--root DIR]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

#: page path (relative to the root) -> the word the page must not use
PAGES = {
    "spec/predicates/identity-assurance-levels.md": re.compile(r"\bgrad(?:e|es|ed|ing)\b", re.I),
    "spec/predicates/record-grades.md": re.compile(r"\blevels?\b", re.I),
}
MARKER = "<!-- crosslink -->"
_CODE = re.compile(r"`[^`\n]*`")


def prose_lines(text: str) -> list[tuple[int, str]]:
    """(line number, line) for every line outside a fenced block, code spans blanked."""
    out, fenced = [], False
    for number, line in enumerate(text.splitlines(), start=1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if not fenced:
            out.append((number, _CODE.sub("", line)))
    return out


def check(path: Path, word: re.Pattern[str]) -> list[str]:
    """The violations on one page."""
    text = path.read_text(encoding="utf-8")
    errors = []
    marked = [n for n, line in enumerate(text.splitlines(), start=1) if MARKER in line]
    if len(marked) != 1:
        errors.append(f"{path}: needs exactly one {MARKER} line, found {len(marked)}")
    for number, line in prose_lines(text):
        if number in marked:
            continue
        match = word.search(line)
        if match:
            errors.append(f"{path}:{number}: forbidden word {match.group(0)!r}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args(argv)
    root = Path(args.root)
    errors: list[str] = []
    present = 0
    for relative, word in PAGES.items():
        path = root / relative
        if path.exists():
            present += 1
            errors.extend(check(path, word))
    if not present:
        errors.append("neither scale's page exists under the root")
    for error in errors:
        print(error)
    print(f"checked {present} of {len(PAGES)} pages, {len(errors)} violations")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
