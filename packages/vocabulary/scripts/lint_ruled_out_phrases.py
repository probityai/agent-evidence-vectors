#!/usr/bin/env python3
"""Refuse any tracked text carrying a construction that is ruled out here.

WHY THIS EXISTS, and it is not a style preference.

Three phrasings are ruled out in everything this project publishes. They are not
wrong English. They are a cadence this project has decided not to write in, and
the decision is not re-litigated per sentence.

The failure this prevents is specific and it has already happened here. On
2026-08-30 one of them shipped into `vocabulary.yaml` inside a commit whose
entire purpose was rewriting that passage. Nothing caught it, and the reason
nothing caught it is worth stating: this repository already HAS a
forbidden-string scan, and the rule looked covered. That scan hashes fixed-length
windows, and its declared window lengths cannot match an eleven-character phrase.
So a guard existed, the rule was written down, and the two never touched.

A rule with no check is a rule that survives exactly as long as whoever last read
it is paying attention. This file is the check.

WHAT THIS DOES NOT DO. It does not read fenced code blocks, where a quoted
transcript or a third party's own text may legitimately contain anything. It does
not read `.githooks/`, whose contents are shared byte-identically with sibling
repositories and cannot be edited here alone without breaking that property. Both
exemptions are narrow, and both are stated here where a reader meets them, never
left silent in the code.

It also holds ITSELF to the rule. Only the three compiled pattern lines are
exempt, because they have to spell what they forbid. Every other line in this
file, this sentence included, is checked. The first version exempted the whole
path, and the paragraph you are reading carried a violation for as long as that
lasted.

Exit 0 clean, 1 finding, 2 refused.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent

#: Extensions carrying prose this project publishes. A crosswalk filed by an
#: outside contributor is theirs, so `crosswalk/` is excluded below; the template
#: is ours and is checked.
_SUBJECT_SUFFIXES = (".md", ".yaml", ".yml", ".cff", ".py")

#: Paths never read. `.githooks/commit-msg` declares itself the canonical copy of
#: a gate shared byte-identically across repositories; editing it here alone
#: silently desynchronises every sibling, which is a worse defect than the cadence
#: it would remove. Fixing it means one pass over every copy, tracked elsewhere.
_EXEMPT_PREFIXES = (".githooks/",)

#: A filed crosswalk is a third party's own words about their own system. We do
#: not impose our cadence on somebody else's filing.
_EXEMPT_DIRS = ("crosswalk/",)

#: The ruled-out constructions, word-boundary anchored so "rather" alone survives
#: and "instead" on its own survives.
_RULED_OUT = (
    (re.compile(r"\brather than\b", re.IGNORECASE), "rather than"),
    (re.compile(r"\binstead of\b", re.IGNORECASE), "instead of"),
    (re.compile(r"\bI would rather\b", re.IGNORECASE), "I would rather"),
)


def _tracked() -> list[str] | None:
    """Every tracked path, or None if git could not answer."""
    result = subprocess.run(
        ["git", "-C", str(_ROOT), "ls-files"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return None
    return [line for line in result.stdout.splitlines() if line]


#: This file has to spell the three phrases to match them, so the lines holding
#: the patterns are exempt. NOT the whole file: an earlier version exempted the
#: path outright and the prose above went unchecked as a result, which is the
#: same shape as the guard this file was written to replace, where a rule existed
#: and covered nothing. A checker that cannot be checked is not a checker.
_SELF = "scripts/lint_ruled_out_phrases.py"


def _self_exempt_line(line: str) -> bool:
    """True for a line in THIS file that must contain a ruled-out phrase.

    Only the compiled patterns qualify. Every other line here, comment and
    docstring alike, is prose this project publishes and is held to the rule it
    enforces on everything else.
    """
    stripped = line.strip()
    return stripped.startswith("(re.compile(") and "_RULED_OUT" not in stripped


def _in_scope(rel: str) -> bool:
    if rel.startswith(_EXEMPT_PREFIXES) or rel.startswith(_EXEMPT_DIRS):
        return False
    return rel.endswith(_SUBJECT_SUFFIXES)


def _blank_fenced(text: str) -> str:
    """Blank fenced blocks, preserving offsets so line numbers stay true.

    A fence holds bytes shown verbatim, most often somebody else's output or
    somebody else's prose. Imposing our cadence on quoted material would mean
    editing a quotation to satisfy a linter, which is the one repair never
    allowed here.
    """
    out = list(text)
    inside = False
    for match in re.finditer(r"^.*$", text, re.MULTILINE):
        if match.group(0).lstrip().startswith("```"):
            inside = not inside
            continue
        if inside:
            for i in range(match.start(), match.end()):
                out[i] = " "
    return "".join(out)


def main() -> int:
    tracked = _tracked()
    if tracked is None:
        print(
            "lint_ruled_out_phrases: REFUSED -- `git ls-files` failed, so the "
            "subject set could not be built and NOTHING was checked. An empty "
            "sweep is not a clean sweep.",
            file=sys.stderr,
        )
        return 2

    subjects = [rel for rel in tracked if _in_scope(rel)]
    if not subjects:
        print(
            "lint_ruled_out_phrases: REFUSED -- no tracked file matched "
            f"{_SUBJECT_SUFFIXES}. Either the repository layout moved or this is "
            "running from the wrong root. Nothing was checked.",
            file=sys.stderr,
        )
        return 2

    findings: list[str] = []
    for rel in subjects:
        try:
            raw = (_ROOT / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            print(
                f"lint_ruled_out_phrases: REFUSED -- {rel} could not be read: {exc}",
                file=sys.stderr,
            )
            return 2
        prose = _blank_fenced(raw)
        lines = prose.splitlines()
        for pattern, label in _RULED_OUT:
            for hit in pattern.finditer(prose):
                line = prose.count("\n", 0, hit.start()) + 1
                if rel == _SELF and _self_exempt_line(lines[line - 1]):
                    continue
                start = max(0, hit.start() - 45)
                end = min(len(prose), hit.end() + 45)
                context = " ".join(prose[start:end].split())
                findings.append(f"  {rel}:{line}  {label!r}\n      ...{context}...")

    if findings:
        print(
            f"lint_ruled_out_phrases: {len(findings)} finding(s) across "
            f"{len(subjects)} tracked file(s).",
            file=sys.stderr,
        )
        for finding in findings:
            print(finding, file=sys.stderr)
        print(
            "\nThese go to zero in anything this project publishes.\n"
            "Rewrite the sentence: a comma and a plain negative, a full stop and "
            "a second sentence, or drop the contrast entirely.\n"
            "Do not reach for a per-sentence exemption. One shipped into "
            "vocabulary.yaml on 2026-08-30 inside a commit that was rewriting "
            "that very passage, which is why this check exists.",
            file=sys.stderr,
        )
        return 1

    print(
        f"lint_ruled_out_phrases: {len(subjects)} tracked file(s) clean of "
        f"{len(_RULED_OUT)} ruled-out construction(s). Fenced blocks and "
        f"{len(_EXEMPT_PREFIXES) + len(_EXEMPT_DIRS)} path prefix(es) exempt, "
        "each for a stated reason in this file's header."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
