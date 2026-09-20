#!/usr/bin/env python3
"""Stable citations from source code into the predicate specification.

WHY THIS EXISTS. The source used to cite the specification by LINE NUMBER --
``spec:req-fields-fields-divide-identity-whose-signature@80666d820c397ce5``, ``spec:req-fields-there-second-use-these-three@260bfd9c41c35939`` -- and ``spec/README.md`` said the vendored
copy was kept byte-verbatim "precisely so the line numbers the source cites stay
accurate". A line number addresses one revision of one file. It cannot survive a
reflow, an inserted paragraph, or a section move, and it survives a REWORD of the
very sentence it cites, which is the one change a citation exists to catch. So the
scheme was wrong in both directions at once: it broke on edits that changed
nothing normative, and it stayed silent on the edit that changed everything.

Splitting the 152,102-byte document into a registry-sized page plus five
companions made that unavoidable rather than merely fragile: every one of those
line numbers addressed a 2,383-line file that no longer exists.

WHAT REPLACES IT. Two halves, and neither works without the other:

  1. An ANCHOR in the specification source, ``<a id="req-..."></a>`` on its own
     line, immediately before the text it names. The form is the one the in-toto
     attestation repository already uses for its own field-type definitions
     (``spec/v0.1.0/field_types.md``), and ``.markdownlint.yaml`` there sets
     ``MD033: false``, so inline HTML is allowed rather than tolerated.
  2. A DIGEST of the anchored text, normalized so that reflowing survives and
     rewording does not.

A citation is then ``spec:<anchor-id>@<16-hex>``: the id says WHERE, the digest
says WHAT. Moving the section moves the anchor and the digest is unchanged.
Rewording the requirement changes the digest and the gate fails closed. That is
the property line numbers could never have.

THE EXTENT RULE, stated because a digest over an undefined span means nothing.
An anchor covers the ``blocks`` markdown blocks that follow it, where a block is
a maximal run of consecutive non-blank lines. The count is recorded in the
manifest rather than inferred from the next anchor, so anchors may NEST and
OVERLAP -- which they must, because the specification cites both a subsection and
individual bullets inside it.

NORMALIZATION. Every run of whitespace collapses to one space and the result is
stripped. Nothing else is touched: not case, not punctuation, not the backticks
around an identifier. So a hard-wrap at a different column is invisible and a
changed word is not.

WHY A 16-HEX PREFIX INLINE. The manifest carries the full SHA-256. A comment
carries 64 bits of it, which is enough that no reword collides and short enough
that the comment stays readable. The gate checks the prefix against the digest it
recomputes, so a stale inline digest fails even when the manifest was updated.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

ANCHOR_RE = re.compile(r'^<a id="(?P<id>[A-Za-z0-9][A-Za-z0-9._-]*)"></a>$')
CITATION_RE = re.compile(
    r"spec:(?P<body>[A-Za-z0-9][A-Za-z0-9._-]*@[0-9a-f]{16}"
    r"(?:,[A-Za-z0-9][A-Za-z0-9._-]*@[0-9a-f]{16})*)"
)
# A LINE-NUMBER CITATION MAY CARRY A SPACE AFTER ITS COMMA, and the first version
# of this pattern did not allow one. `spec:req-fields-fields-divide-identity-whose-signature@80666d820c397ce5,req-fields-within-attestation-these-members-syntax@5c41c3e34a850fd5` therefore matched
# only its first half: the migration rewrote that half, left `, 1744-1746` behind
# as orphaned digits, and the residual check -- which looked for `spec:` followed
# by a digit -- could not see the leftover because the leftover has no `spec:` in
# front of it. Twelve citations were damaged that way before the control below
# caught them. Both halves of the lesson are encoded here: the pattern admits the
# space, and ORPHAN_TAIL_RE looks for the wreckage the pattern used to leave.
LEGACY_CITATION_RE = re.compile(
    r"spec:[0-9]+(?:-[0-9]+)?(?:,\s*[0-9]+(?:-[0-9]+)?)*"
)
ORPHAN_TAIL_RE = re.compile(
    r"spec:[A-Za-z0-9][A-Za-z0-9._-]*@[0-9a-f]{16}(?:,[A-Za-z0-9][A-Za-z0-9._-]*@[0-9a-f]{16})*"
    r",\s*[0-9]"
)
INLINE_PREFIX_LEN = 16
MANIFEST_REL = "spec/CITATION-ANCHORS.json"
SCHEMA_VERSION = 2


def normalize(text: str) -> str:
    """Collapse every run of whitespace to one space and strip."""
    return " ".join(text.split())


def digest(text: str) -> str:
    return hashlib.sha256(normalize(text).encode("utf-8")).hexdigest()


def blocks_of(lines: list[str]) -> list[list[str]]:
    """Split lines into maximal runs of consecutive non-blank lines."""
    out: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if line.strip():
            current.append(line)
        elif current:
            out.append(current)
            current = []
    if current:
        out.append(current)
    return out


def find_anchor(lines: list[str], anchor_id: str) -> int | None:
    """Return the 0-based index of the anchor line, or None when absent."""
    for i, line in enumerate(lines):
        m = ANCHOR_RE.match(line.strip())
        if m and m.group("id") == anchor_id:
            return i
    return None


def anchored_text(lines: list[str], anchor_index: int, blocks: int) -> str | None:
    """The text an anchor covers: the next `blocks` blocks after it.

    Returns None when the file does not contain that many blocks after the
    anchor, which is a structural failure and never an empty string -- an empty
    string would digest to a stable value and read as a match.
    """
    if blocks < 1:
        return None
    rest = lines[anchor_index + 1 :]
    got = blocks_of(rest)
    # An anchor immediately followed by another anchor line would otherwise take
    # that anchor as its first block; anchors are not specification text.
    got = [b for b in got if not all(ANCHOR_RE.match(x.strip()) for x in b)]
    if len(got) < blocks:
        return None
    return "\n".join("\n".join(b) for b in got[:blocks])


# How a record's text is FOUND, which is not the same question as whether it
# changed. "anchor" is the normal case: the file carries `<a id="...">` and the
# text is the blocks after it. "digest" exists for a file this repository may not
# edit -- the vendored upstream specification, whose bytes are pinned to an
# upstream commit so that an outside implementer can diff the two and certify no
# version skew. Inserting an anchor line into that file would break the pin, so
# its anchors are addressed by the digest of the prose instead of by a marker in
# it. Detection strength is unchanged: a reworded requirement matches no block
# and fails by name. What is lost is only the ability to say where the text used
# to sit, and the record already fixes the file.
#
# The locator is DECLARED per record, never inferred and never a fallback. A
# resolver that tried the marker and then quietly tried the digest would report a
# missing anchor as a pass, which is the failure this whole file exists to avoid.
LOCATOR_ANCHOR = "anchor"
LOCATOR_DIGEST = "digest"
LOCATORS = (LOCATOR_ANCHOR, LOCATOR_DIGEST)


@dataclass(frozen=True)
class AnchorRecord:
    anchor_id: str
    file: str
    blocks: int
    sha256: str
    excerpt: str
    locator: str = LOCATOR_ANCHOR
    why: str = ""

    def as_json(self) -> dict:
        out = {
            "file": self.file,
            "blocks": self.blocks,
            "sha256": self.sha256,
            "excerpt": self.excerpt,
        }
        if self.locator != LOCATOR_ANCHOR:
            out["locator"] = self.locator
            out["why"] = self.why
        return out


def digest_located_text(lines: list[str], blocks: int, want: str) -> str | None:
    """The run of `blocks` consecutive blocks whose digest is `want`, or None.

    Returns None rather than an empty string when nothing matches, for the reason
    anchored_text gives: an empty string digests to a stable value and would read
    as a match.
    """
    runs = blocks_of(lines)
    for i in range(len(runs) - blocks + 1):
        text = "\n".join("\n".join(b) for b in runs[i : i + blocks])
        if digest(text) == want:
            return text
    return None


def excerpt_of(text: str, limit: int = 140) -> str:
    n = normalize(text)
    return n if len(n) <= limit else n[: limit - 1] + "…"


def load_manifest(repo_root: Path) -> dict[str, AnchorRecord]:
    path = repo_root / MANIFEST_REL
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schemaVersion") != SCHEMA_VERSION:
        raise ValueError(
            f"{MANIFEST_REL} is schemaVersion {data.get('schemaVersion')}, "
            f"this build reads {SCHEMA_VERSION}"
        )
    records: dict[str, AnchorRecord] = {}
    for aid, rec in data["anchors"].items():
        locator = rec.get("locator", LOCATOR_ANCHOR)
        if locator not in LOCATORS:
            raise ValueError(
                f"{MANIFEST_REL}: anchor {aid} declares locator {locator!r}; "
                f"this build reads {LOCATORS}"
            )
        if locator != LOCATOR_ANCHOR and not rec.get("why"):
            raise ValueError(
                f"{MANIFEST_REL}: anchor {aid} is {locator}-located and states no reason; "
                "a record that departs from the normal form says why in the record"
            )
        records[aid] = AnchorRecord(
            aid, rec["file"], rec["blocks"], rec["sha256"], rec.get("excerpt", ""),
            locator, rec.get("why", ""),
        )
    return records


def write_manifest(repo_root: Path, records: dict[str, AnchorRecord], note: str) -> None:
    path = repo_root / MANIFEST_REL
    payload = {
        "schemaVersion": SCHEMA_VERSION,
        "generatedBy": "scripts/gen_spec_anchors.py",
        "note": note,
        "normalization": "every run of whitespace collapses to one space, then strip; nothing else changes",
        "extentRule": (
            "an anchor covers the `blocks` maximal runs of non-blank lines that follow it; "
            "the count is recorded rather than inferred, so anchors may nest and overlap"
        ),
        "inlineForm": "spec:<anchor-id>@<first 16 hex of sha256>",
        "anchors": {aid: records[aid].as_json() for aid in sorted(records)},
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def parse_citation(body: str) -> list[tuple[str, str]]:
    """`a@deadbeef...,b@cafe...` -> [(anchor_id, inline_prefix), ...]"""
    out = []
    for part in body.split(","):
        aid, _, pref = part.partition("@")
        out.append((aid, pref))
    return out


def source_files(repo_root: Path) -> list[Path]:
    out: list[Path] = []
    for pattern in ("*.go", "*.py"):
        for p in sorted(repo_root.rglob(pattern)):
            rel = p.relative_to(repo_root).as_posix()
            if rel.startswith((".git/", "node_modules/", ".venv/")):
                continue
            out.append(p)
    return out
