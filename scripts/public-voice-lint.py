#!/usr/bin/env python3
"""Public-voice lint: public documentation is written for a stranger.

A README or a page under docs/ is read by someone who has never seen how this
repository is maintained. Text written as a note to the maintainers reads as
noise to them: a status in brackets ("(fixed)"), a tracker id, the name of an
internal process step, a timestamp to the minute, an apology for an earlier
version. This lint refuses those patterns so they are caught before a reader
sees them.

Usage:
    python3 scripts/public-voice-lint.py                 # README.md, top-level *.md, docs/**/*.md
    python3 scripts/public-voice-lint.py PATH [PATH ...]  # only these files
    python3 scripts/public-voice-lint.py --allowlist FILE

Exit status: 0 clean, 1 findings, 2 usage error.

Allowlist: one entry per line, three fields separated by a TAB:

    <path glob>	<rule>	<exact matched text, or * for any>

A line starting with # is a comment. An entry allows the matched text for that
rule in every file the glob matches (fnmatch, so * also crosses /). Keep each
entry narrow and put the reason in a comment above it. A private name is never
allowed.

The script is shared byte for byte between repositories; repository-specific
exceptions go in the allowlist, never in this file.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import itertools
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ALLOWLIST = Path(__file__).resolve().parent / "public-voice-allowlist.txt"

# Names that must not appear in public text, stored as sha256 digests of the
# lower-case name so this file does not itself carry them.
PRIVATE_DIGESTS = frozenset(
    {
        "ff46cb3423072dda756e1f5f85b61468775c572a60442eee89230d3b403cee73",
        "fdc58962560c17c901b0a98b7a2fe84ad9a579ae713c239aa0613f32e81b2459",
        "f4521cf41941408881f7bfc5feab341734d96ff1362cc644e40c4818a3000097",
        "796b96b06d15c09fc98e184ab0c2362f46974689ad5561c4fff1f67b4e29410a",
        "e670f86162b6d9412469057a4f40b1a3a612fdb698aed14e51bde9a92f5a9efe",
        "c2b290a06fe3cf85e792c0bdafe5eae18815ea540f7cd5f35143428e7467cf7e",
        "5f37fa91cbe67c135be74012208a361604d8d4f471f36ed0426b7d6d2d5e6e42",
    }
)



# Each rule: (id, compiled pattern, what a reader is told).
RULES: list[tuple[str, re.Pattern[str], str]] = [
    (
        "status-note",
        re.compile(
            r"\((?:fixed|pending|stale|wip|todo|tbd|temporary|placeholder|corrected|"
            r"updated|resolved|done)\)",
            re.IGNORECASE,
        ),
        "a status in brackets is a note to maintainers; state the fact instead",
    ),
    (
        "marker",
        re.compile(r"\b(?:TODO|FIXME|XXX|TBD|WIP)\b(?!\.md)"),
        "a work marker in published text; finish the sentence or remove it",
    ),
    (
        "process",
        re.compile(
            r"\b(?:lanes?|lane reports?|lane worktrees?|momentum (?:push|path|landing)|"
            r"merge[- ]queue|(?:board|backlog) rows?|rulings?(?![- ]\d\b)|"
            r"per the (?:ruling|decision|directive)|"
            r"(?:the )?operator(?:-accepted|(?:'s)? (?:ruled|ruling|decided|decision|directive|"
            r"approved|approval|acceptance|accepted|asked|said|wants))|we decided|SSOT|"
            r"single source of truth|per the integrator|the integrator's (?:order|request)|"
            r"(?:the same|this|our) scheduled run|double[- ]count(?:ed|ing|s)?|"
            r"fixed at|session handoff|wind[- ]down|merge freeze|release freeze|"
            r"(?:push|pre-push|landing|queue|send|writing) gates?)\b",
            re.IGNORECASE,
        ),
        "this describes how we maintain the repository, not what the reader gets",
    ),
    (
        "decision-id",
        re.compile(r"\b(?:P-(?!(?:224|256|384|521)\b)\d{1,3}[a-z]?|DEC-\d{8}-\d{3})\b"),
        "an internal decision number means nothing to a reader",
    ),
    (
        "tracker-id",
        # An upper-case hyphenated id of three or more parts, at least two of them
        # words: the shape of an internal work-item key. Standard names that share
        # the shape (algorithm suites, registries) are excluded by their first part.
        re.compile(
            r"\b(?!(?:CVE|CWE|GHSA|GCVE|RFC|ISO|SEP|PEP|KEP|EIP|BIP|ERC|TLS|SHA|AES|UTF|IEC|"
            r"NIST|SOC|ASI|LLM|OSV|RUSTSEC|PYSEC|CAPEC|HMAC|ECDSA|EDDSA|RSA|PSS|DSA|KEM|"
            r"SLH|JWS|JWT|COSE|CBOR|DSSE|JCS|SPDX|SLSA|OWASP|FIPS|PKCS|IEEE|ANSI|HTTP|"
            r"CHACHA|XCHACHA|ARGON|PBKDF|HKDF|BLAKE|KECCAK|SECP|BRAINPOOL)-)"
            r"(?=(?:[A-Z0-9]*-)*[A-Z]{3,}[A-Z0-9]*-(?:[A-Z0-9]*-)*[A-Z]{3,})"
            r"[A-Z][A-Z0-9]+(?:-[A-Z0-9]{2,}){2,}\b"
            # A file name or link text is the thing itself, not a pointer to it.
            r"(?!\.[A-Za-z]|\])"
        ),
        "a tracker id is an internal pointer; describe the thing instead",
    ),
    (
        "timestamp",
        re.compile(
            r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}|"
            r"\b\d{1,2}:\d{2}\s?(?:AM|PM|a\.m\.|p\.m\.)?\s?(?:UTC|ET|EST|EDT|PT|PST|PDT|GMT)\b",
        ),
        "a time to the minute; a date is enough for a reader",
    ),
    (
        "correction",
        re.compile(
            r"\b(?:sorry|apologi[sz]e[sd]?|apologies|was wrong|our (?:mistake|error)|"
            r"my (?:mistake|error)|mis-?counted|previously (?:said|read|stated|claimed|showed)|"
            r"(?:this|the) (?:page|line|section|figure|number|count|badge) "
            r"(?:previously|used to|once) (?:said|read|showed|stated|say|read|show)|"
            r"corrected (?:on|in|from|after))\b",
            re.IGNORECASE,
        ),
        "narrating a correction is for us; state the current fact",
    ),
    (
        "agent",
        re.compile(
            r"\b(?:main session|lane session|session running it|Co-Authored-By|"
            r"(?:generated|written|drafted) "
            r"(?:by|with) (?:Claude|ChatGPT|Codex|Gemini|an AI|AI|an LLM|a model))\b",
            re.IGNORECASE,
        ),
        "names how the text was produced, not what it says",
    ),
    (
        "company",
        re.compile(
            r"\b(?:our company|our startup|Probity (?:Inc|LLC|Labs|Corp)\b\.?)",
            re.IGNORECASE,
        ),
        "public text here does not speak for a company",
    ),
]

FENCE = re.compile(r"^\s*(```|~~~)")
INLINE_CODE = re.compile(r"`[^`\n]*`")
HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
LINK_TARGET = re.compile(r"\]\([^)\s]*(?:\s+\"[^\"]*\")?\)")
AUTOLINK = re.compile(r"<https?://[^>\s]+>|https?://\S+")
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9._-]+)*")


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    text: str
    excerpt: str


def digest(word: str) -> str:
    return hashlib.sha256(word.encode("utf-8")).hexdigest()


def private_name_candidates(token: str) -> set[str]:
    """Every spelling of a token a private name could hide in."""
    token = token.lower().strip(".-_/")
    out = {token}
    parts = [p for p in token.split("/") if p]
    out.update(parts)
    out.update(f"{a}/{b}" for a, b in itertools.pairwise(parts))
    for part in parts:
        dotted = part.split(".")
        out.update(".".join(dotted[i:]) for i in range(len(dotted)))
        out.update(dotted)
        for piece in dotted:
            words = re.split(r"[-_]", piece)
            for i in range(len(words)):
                for j in range(i + 1, min(len(words), i + 4) + 1):
                    out.add("-".join(words[i:j]))
    return {c for c in out if c}


def private_names(line: str, digests: frozenset[str]) -> list[str]:
    hits = []
    for match in TOKEN.finditer(line):
        if any(digest(c) in digests for c in private_name_candidates(match.group(0))):
            hits.append(match.group(0))
    return hits


def prose_lines(text: str) -> list[tuple[int, str, str]]:
    """(line number, prose with code and link targets removed, raw line)."""
    text_no_comments = HTML_COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    out = []
    in_fence = False
    for number, (raw, line) in enumerate(
        zip(text.splitlines(), text_no_comments.splitlines(), strict=True), start=1
    ):
        if FENCE.match(line):
            in_fence = not in_fence
            out.append((number, "", raw))
            continue
        if in_fence:
            out.append((number, "", raw))
            continue
        prose = INLINE_CODE.sub(" ", line)
        prose = LINK_TARGET.sub("]", prose)
        prose = AUTOLINK.sub(" ", prose)
        out.append((number, prose, raw))
    return out


def lint_text(
    path: str, text: str, digests: frozenset[str] = PRIVATE_DIGESTS
) -> list[Finding]:
    findings = []
    for number, prose, raw in prose_lines(text):
        excerpt = raw.strip()[:160]
        for name in private_names(raw, digests):
            findings.append(Finding(path, number, "private-name", name, excerpt))
        for rule, pattern, _ in RULES:
            for match in pattern.finditer(prose):
                findings.append(Finding(path, number, rule, match.group(0), excerpt))
    return findings


def load_allowlist(path: Path) -> set[tuple[str, str, str]]:
    entries: set[tuple[str, str, str]] = set()
    if not path.exists():
        return entries
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = line.split("\t")
        if len(fields) != 3 or not all(f.strip() for f in fields):
            raise SystemExit(f"{path}:{number}: expected <path>\\t<rule>\\t<text>")
        entries.add((fields[0].strip(), fields[1].strip(), fields[2].strip()))
    return entries


def allowed(finding: Finding, entries: set[tuple[str, str, str]]) -> bool:
    if finding.rule == "private-name":
        return False
    for path, rule, text in entries:
        if (
            rule == finding.rule
            and fnmatch.fnmatchcase(finding.path, path)
            and (text == "*" or text.lower() == finding.text.lower())
        ):
            return True
    return False


def default_paths(root: Path) -> list[Path]:
    try:
        listed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True,
            capture_output=True,
        ).stdout.decode("utf-8")
        files = [Path(p) for p in listed.split("\0") if p]
    except (OSError, subprocess.CalledProcessError):
        files = [p.relative_to(root) for p in root.rglob("*.md")]
    chosen = []
    for rel in files:
        if rel.suffix.lower() != ".md":
            continue
        if rel.name == "README.md" or len(rel.parts) == 1 or "docs" in rel.parts[:-1]:
            chosen.append(root / rel)
    return sorted(chosen)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Refuse internal-voice text in public docs.")
    parser.add_argument("paths", nargs="*", type=Path)
    parser.add_argument("--allowlist", type=Path, default=DEFAULT_ALLOWLIST)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)

    paths = args.paths or default_paths(args.root)
    entries = load_allowlist(args.allowlist)
    messages = {rule: why for rule, _, why in RULES}
    messages["private-name"] = "a private name in public text"

    total = 0
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"{path}: cannot read: {exc}", file=sys.stderr)
            return 2
        try:
            shown = str(path.resolve().relative_to(args.root.resolve()))
        except ValueError:
            shown = str(path)
        for finding in lint_text(shown, text):
            if allowed(finding, entries):
                continue
            total += 1
            print(
                f"{finding.path}:{finding.line}: {finding.rule}: "
                f"{finding.text!r}: {messages[finding.rule]}\n    {finding.excerpt}"
            )
    print(f"public-voice-lint: {len(paths)} files, {total} findings", file=sys.stderr)
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
