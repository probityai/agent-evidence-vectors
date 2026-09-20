#!/usr/bin/env python3
"""Spec anchor gate.

The corpus cites the vendored predicate specification two ways. Code comments
use ``spec:<anchor-id>@<digest>``, which ``scripts/spec-drift-gate.py`` checks. Tables a reader
scans -- the vector generator, the interpretation registries, and the documents
generated from them -- use ``Lnnn`` and ``Lnnn-mmm`` anchors, and until this gate
existed nothing checked those at all.

They rotted, exactly as line numbers into a periodically re-vendored file always
will. The anchors were migrated by hand once and then left behind by eleven
successive re-vendorings, so by the time anyone looked they addressed prose
hundreds of lines away from the rules they claimed to cite. A wrong anchor is
worse than no anchor, because it reads as evidence that a vector was written
against a passage it was never written against.

Two questions have to stay answered, and they need different checks.

*Does the anchor resolve?* Every endpoint must be inside the file, ordered, and
on a line that carries text. This is cheap and catches the crude failures, and
it is nowhere near sufficient: a line-range check passes for any number that
happens to land on prose, which is why anchors sat hundreds of lines wrong
while the sibling citation gate ran green on every build.

*Does the anchor still address the text it was recorded against?* This is the
question that catches the rot, and answering it needs something committed to
compare with. ``spec/ANCHOR-PINS.json`` records, for every citation, a digest of
the span's text plus its opening and closing lines in plain sight. The gate
recomputes and fails, naming the citation and printing both excerpts, the moment
an anchor addresses different bytes than the ones it was pinned to.

The pin machinery lives in ``scripts/specpins.py``, because the ``spec:NNN``
spelling needs the same record for the same reason and a second copy of the rule
would be free to drift from this one. What stays here is what is genuinely
particular to the anchors: which files carry them, what a citation belongs to,
and the generated tables that must be regenerated when the anchors move. The
shared module documents why the pin is keyed by the citing site rather than by
the line range, which is the property the whole check rests on.

Why this is the right strength. It is deliberately weaker than checking the
anchor against the wording of the claim beside it: it never requires the cited
passage to contain particular words, so upstream may rewrite that passage freely
and ``scripts/vendor-spec.py`` re-pins in the same pass that remaps the anchors,
which keeps an ordinary re-vendor a one-command operation. It is much stronger
than a range check, because it fails on precisely the event that defines the
defect, an anchor coming to address prose it was not drawn around. And because
the pin carries readable excerpts rather than a bare digest, a changed anchor
shows up in review as the prose it now points at, sitting next to the claim it
is supposed to support, which is the one part of the judgement a numeric gate
cannot make on anyone's behalf.

An anchor may also shrink, and that is the same defect wearing a friendlier
shape. A range that still opens on its subject and now closes before prose it
used to cover asserts the same claim over less of the document than it was drawn
around, so ``--sync`` refuses it and prints the lines it dropped, whether they
were lost by a remap or removed by hand. Narrowing an anchor onto the paragraph
that actually states a rule is a correction and stays available, by name, one
key at a time. The point is only that it is said rather than assumed.

*Was the anchor ever aimed at the rule in the first place?* The two questions
above share a blind spot and it is total. Both are asked about the text an
anchor was recorded against, and an anchor recorded a sentence early addresses
that text perfectly: the pins agree with themselves forever, so the check does
not merely miss the defect, it preserves it. Registry decision 8 carried twelve
forcing vectors and anchored three lines that held the tail of an unrelated
paragraph about ``doesNotAssert`` and a field label, while the timestamp profile
it interprets began eight lines further down. The same shape was reported from
outside for condition aee-c-108, which is what says it is a class rather than a
typing slip.

So a third question is asked, of the anchors that carry the most weight: those a
registry decision records for a reading it calls forced. The span must cover a
sentence that states a rule, that rule must name something the decision names,
and the span may not be widened across a heading until those two become free.

The heading half of that was too weak, and the measurement that says so is the
one worth keeping. Restore each of the four wrong anchors, then widen it upward
without ever reaching the rule it was supposed to cite, and three of the four
pass: decisions 6 and 14 at L795-886 and decision 8 at L1581-1672, each of them
satisfying the term question on a rule about a different member ninety lines
away. Not one crosses a heading, because this document does not put its members
in sections -- `coverage` and `attackResults` are defined a hundred lines apart
under one heading. What sits between them is a field definition label, `name`
_type, required_, and that is the boundary the corrections were actually drawn
to: every anchor this change corrected opens on one. So the fourth question is
whether a span reached its rule by running past the label that opens the next
member, and it is asked of anchors that have already answered the other three,
because it is a question about how they answered them. Re-running the same
sweep with it in place, no upward widening of those three passes at any width up
to four hundred lines, which is the whole distance to the previous heading, and
none of the thirty-three anchors on record is refused.

What it does not close is the same escape where a section defines no members.
Decision 7's wrong anchor still passes eight lines wider, at L222-234, on two
sentences in Prerequisites that state no obligation and say so: "restating the
requirement would add a check that could never be the one to fail" and "the
`observationVocabulary` digest carries no rule of its own here". Both are read
as stating a rule, the first on the bare word never and the second on cannot,
and both name a term decision 7 names. Narrowing what counts as stating a rule
would reach them, and was measured: dropping the bare never refuses thirty-nine
sentences, two of which are the only rule a correct anchor covers, so it trades
one wrong acceptance for two wrong refusals and is not adopted here.

The sharp version of the first half -- the span must contain an RFC 2119
obligation -- was measured before it was adopted and rejected on the numbers.
Sixteen of the thirty-three anchors on record carry no RFC 2119 sentence at all,
because this document states roughly two thirds of its obligations as a
consequence: what is invalid, what is malformed, what covers nothing, what a
verifier cannot do. It also hangs whole lists off a single stem MUST and then
writes five items as bare noun phrases. A rule refusing sixteen correct anchors
is a rule that gets switched off, so what counts as stating a rule is the
keywords plus a closed list of this document's own consequence constructions,
plus inheritance from a list stem. Under that reading the refusals fell to four
of thirty-three, and all four were the same class: decisions 6, 8 and 14 each
stopped one sentence short of the consequence they quote, and decision 7 sat
eight lines above its rule, on the anti-splice paragraph rather than on the
version rejection it describes. Every one was corrected against the text rather
than waived, which is the test of a threshold worth keeping.

The half that discriminates is the second. Rule-bearing sentences are not rare
here -- three hundred and one of eight hundred and fifteen -- so covering one is
weak evidence on its own, and the gate prints that density every run so a reader
can watch for it going vacuous. Requiring the covered rule to name a term the
decision names, in the specification's controlled vocabulary of backticked
identifiers and cited RFCs, is what makes a wrongly aimed anchor fail. The
heading rule closes the obvious way around: an anchor stretched over a whole
section contains some rule naming some term and would otherwise pass by width.

*Is each of these questions still being asked of anything?* Every question above
is asked of the rows a selector picks out, and a selector that picks out nothing
does not fail: it reports on a smaller set and prints a total that reads as
complete. This gate shipped in that state. Its vector-row selector was spelled
``bad-\\d`` and matched zero of the two hundred and nine reject-index rows from
the day identifiers became content digests, so every vector row in the corpus
was dropped out of the per-row comparison into a weaker whole-file question that
passes whenever some unrelated entry cites the same line -- and neighbouring
rules here share spans constantly, so that is the ordinary case, not the exotic
one. The commit that introduced an anchor the reader could not see asserted in
its own message that the reader takes spans from every cell of every vector row.

So every selector declares what it is aimed at, and ``dead_selectors`` refuses a
run in which any of them matches nothing. A pattern matching zero rows is either
a defect or a deliberate expectation; there is no third case, and the deliberate
one has to say so in ``Selector.silent``, in writing, before it passes. It runs
on ``--sync`` as well, because a synchronise performed through a dead selector
writes a ledger missing every citation that selector would have found and
reports the smaller number as the whole of them.

The count is not a proof of aim and must not be read as one. That a pattern
matches rows says the read path works; it does not say the rows are the right
ones. What it removes is the failure where a reader stops reading entirely,
which is the one this repository keeps having.

What none of it does is decide whether a freshly written anchor cites the right
rule. Nothing mechanical can read a claim and judge which paragraph settles it.
The gate makes that a review question with the evidence attached rather than an
invisible one, and it makes the systematic failure, hundreds of anchors going
quietly wrong at once because a re-vendor moved the prose, impossible to commit.

Usage:
    python3 scripts/spec-anchor-gate.py             # check
    python3 scripts/spec-anchor-gate.py --aim-only  # only the aim question
    python3 scripts/spec-anchor-gate.py --sync      # rewrite the pin ledger
    python3 scripts/spec-anchor-gate.py --sync --accept-reaim <citation-key>
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass

from specpins import (
    REPO_ROOT,
    Cited,
    Ledger,
    orphan_failures,
    pinned_failures,
    report,
    resolution_failures,
    spec_state,
    sync,
)

# ONE definition of a published identifier, imported rather than restated. A
# commit that fixed four silent droppers shipped with five, because one reader
# kept its own copy of a shared pattern; when identifiers changed shape that
# copy stopped matching and dropped its rows without complaint.
sys.path.insert(0, str(REPO_ROOT / "vectors"))
from gen_manifest import VECTOR_ID, VECTOR_ID_PATTERN  # noqa: E402

SPEC_REL = "spec/predicates/adversarial-execution-evidence.md"

LEDGER = Ledger(
    path=REPO_ROOT / "spec" / "ANCHOR-PINS.json",
    spec_rel=SPEC_REL,
    token_field="anchor",
    noun="anchor",
    article="an",
    token_re=re.compile(r"L(\d+)(?:-(\d+))?"),
)

# Files whose anchors are written by hand. The pin ledger is synced from these
# and from nothing else, so a generated file that was not regenerated after a
# re-vendor still carries the old anchors, finds no pin for them, and fails.
AUTHORED = (
    "vectors/reject/gen_invalid_vectors.py",
    "vectors/interpretation-decisions.json",
    "vectors/coverage-unforced.json",
    "vectors/CHANGES.md",
    "docs/interpretation-decisions-open.md",
    # The accept generator's anchor map. An accept vector can cite a span and
    # one does, and until this line the citation was checked by nothing: the
    # file was in neither list, so the accept index's anchor found no pin, and
    # a re-vendor that moved the line would have gone through unremarked. The
    # gap was written down in docs/UNCITED-OBLIGATIONS.md at the time it was
    # opened, which is the only reason it was still findable.
    "vectors/accept/gen_valid_vectors.py",
)

# Files generated from those. Their anchors are checked but never pinned.
GENERATED = (
    "vectors/reject/INDEX.md",
    "docs/COVERAGE-MATRIX.md",
    "vectors/accept/INDEX.md",
)

ANCHOR_RE = re.compile(r"\bL(\d+)(?:-(\d+))?\b")

REMEDY = (
    "An anchor that no longer addresses the text it was pinned to is citing "
    "prose it was not drawn around. Re-vendor with scripts/vendor-spec.py, "
    "which remaps the anchors and re-pins them, or correct the anchor by hand "
    "and run this gate with --sync. Regenerate the corpus and the coverage "
    "matrix so the generated tables carry the corrected anchors too."
)

@dataclass(frozen=True)
class Selector:
    """A row pattern, the files it is aimed at, and what it is for.

    The aim is declared rather than left implicit because a pattern's match
    count is the only thing that says it is still a reader. Nothing else does:
    a dead selector produces no error, no empty output and no missing row, only
    a total that is smaller than it should be and reads as complete.
    """

    name: str
    pattern: re.Pattern[str]
    files: tuple[str, ...]
    # A written reason this selector is expected to match nothing, or None when
    # it must match something. There is no third case, and a selector that
    # matches nothing without saying so in this field is refused.
    silent: str | None = None


# What a citation belongs to. A pin has to be found again after the spec has
# moved under it, so it is filed under the thing doing the citing rather than
# under a line number: this vector, this condition, this registry decision, this
# section of prose. Adding a vector then disturbs one entry instead of shifting
# every entry below it.
OWNER_SELECTORS = (
    Selector(
        "a reject vector",
        re.compile(r'^vec\("([a-z0-9-]+)"'),
        ("vectors/reject/gen_invalid_vectors.py",),
    ),
    # A condition table row. The anchor cell is matched loosely because a row may
    # carry several anchors; requiring a single one filed the extra anchors of a
    # multi-anchor condition under whichever row happened to precede it.
    Selector(
        "a condition table row",
        re.compile(r'^\s*(\d+): \("L'),
        ("vectors/reject/gen_invalid_vectors.py",),
    ),
    Selector(
        "a registry entry",
        re.compile(r'^\s*"id":\s*"?([^",]+)"?,'),
        ("vectors/interpretation-decisions.json", "vectors/coverage-unforced.json"),
    ),
    Selector(
        "a prose section",
        re.compile(r"^#{1,6}\s+(.+?)\s*$"),
        (
            "vectors/CHANGES.md",
            "docs/interpretation-decisions-open.md",
            "vectors/reject/gen_invalid_vectors.py",
            "vectors/accept/gen_valid_vectors.py",
        ),
    ),
    Selector(
        "generator prose",
        re.compile(r"^def (\w+)"),
        (
            "vectors/reject/gen_invalid_vectors.py",
            "vectors/accept/gen_valid_vectors.py",
        ),
    ),
    # The accept generator's anchor map: one slug-keyed entry per accept vector
    # that cites a span. It is matched ahead of nothing and after everything,
    # because its lines are indented and no earlier pattern reaches them.
    Selector(
        "an accept anchor-map entry",
        re.compile(r"^\s*'([a-z0-9-]+)':\s*'L"),
        ("vectors/accept/gen_valid_vectors.py",),
    ),
    # The map itself, so the prose above its first entry is filed under the map
    # rather than under whatever comment happened to precede it. A key built out
    # of a sentence changes whenever the sentence is reworded, which turns an
    # edit to a comment into an orphaned pin.
    Selector(
        "a module-level map",
        re.compile(r"^([A-Z][A-Z0-9_]*): *dict\["),
        (
            "vectors/accept/gen_valid_vectors.py",
            "vectors/reject/gen_invalid_vectors.py",
        ),
    ),
)

OWNERS = tuple(selector.pattern for selector in OWNER_SELECTORS)


@dataclass(frozen=True)
class Anchor(Cited):
    """A citation plus the row it belongs to, which only the generated tables
    need: a generated row is compared against the row its own source records."""

    owner: str


# The row a generated table line belongs to. A generated table is checked against
# the source it was generated from, and that comparison is only meaningful per
# row: asking whether an anchor appears anywhere in the authored set passes for a
# stale row whenever the number it carries is still cited by some unrelated
# entry, which is common here because neighbouring rules share spans.
# A vector row of either index. The identifier is VECTOR_ID_PATTERN, imported
# rather than restated: this selector used to carry its own `bad-\d` spelling
# and it matched zero of the two hundred and nine reject rows from the day
# identifiers became content digests, so the per-row comparison below stopped
# happening for every vector in the corpus and the file's total went on reading
# as complete. It is one more reader in this repository to die of a private copy
# of a published identifier -- scripts/count-gate-test.py already names a sixth
# and no list of them is authoritative, which is the argument for one spelling
# rather than for counting them.
GENERATED_ROWS = (
    Selector(
        "a vector row",
        re.compile(rf"^\|\s*`?({VECTOR_ID_PATTERN})`?\s*\|"),
        ("vectors/reject/INDEX.md", "vectors/accept/INDEX.md"),
    ),
    Selector(
        "a reject-index condition row",
        re.compile(r"^\|\s*aee-c-(\d+)\s*\|"),
        ("vectors/reject/INDEX.md",),
    ),
    Selector(
        "a coverage-matrix row",
        re.compile(r"^\|\s*(D\d+|U\d+)\s"),
        ("docs/COVERAGE-MATRIX.md",),
    ),
)

# Where the published identifier of a vector is resolved back to the slug its
# generator files the vector's anchors under. A vector is named after its own
# bytes, so nothing about the identifier spells the slug and no committed file
# carries the pairing: the slug surface is label-bearing, which is the whole
# reason content addressing replaced it, so the generators write the map as a
# build intermediate and it is not committed.
IDENTIFIER_MAPS = (
    REPO_ROOT / ".build" / "aee-accept-ids.json",
    REPO_ROOT / ".build" / "aee-reject-ids.json",
)

_SLUGS: dict[str, str] | None = None


def vector_slugs() -> dict[str, str]:
    """Published identifier to slug, or a refusal naming the map that is absent.

    A MISSING MAP IS A DID-NOT-RUN AND NEVER A RUN-WITH-DEFAULTS, for the same
    reason the reject generator says so about the same files. Reading a missing
    map as an empty one resolves no row, files every vector row under no owner,
    and drops all of them into the weaker whole-file question -- which is the
    exact state this gate has just been fixed out of, arrived at silently and
    with a green run to show for it.
    """
    global _SLUGS
    if _SLUGS is not None:
        return _SLUGS
    loaded: dict[str, str] = {}
    for path in IDENTIFIER_MAPS:
        if not path.is_file():
            raise SystemExit(
                f"FAIL: the identifier map {path.relative_to(REPO_ROOT)} is not "
                "there, so no published vector identifier resolves to the slug "
                "its generator files anchors under, and every vector row of "
                "every index would be compared by the weaker whole-file "
                "question instead of against its own source row. Run "
                "vectors/accept/gen_valid_vectors.py and then "
                "vectors/reject/gen_invalid_vectors.py; each writes its map on "
                "every run."
            )
        entries: dict[str, str] = json.loads(path.read_text(encoding="utf-8"))
        if not entries:
            raise SystemExit(
                f"FAIL: the identifier map {path.relative_to(REPO_ROOT)} is "
                "empty, which resolves nothing and agrees with everything. "
                "Re-run the generator that writes it."
            )
        loaded.update({vid: slug for slug, vid in entries.items()})
    _SLUGS = loaded
    return _SLUGS


def dead_selectors() -> list[str]:
    """Every selector that matches no row of any file it is aimed at.

    This is the check that makes the defect above unrepeatable, and it is here
    rather than in a test because a selector dies between runs of a gate, not
    between edits to one. A pattern that matches nothing is either a defect or
    a deliberate expectation; there is no third case, and the deliberate one has
    to say so in ``Selector.silent`` before this will pass it.

    It is deliberately a count and not a proof of aim. Showing that a pattern
    matches rows says the read path works; it does not say the rows are the
    right ones, and nothing mechanical here can. What it removes is the failure
    where a reader stops reading entirely and reports a total that looks whole.
    """
    failures: list[str] = []
    for selector in OWNER_SELECTORS + GENERATED_ROWS:
        matched = 0
        unreadable: list[str] = []
        for rel in selector.files:
            path = REPO_ROOT / rel
            if not path.is_file():
                unreadable.append(rel)
                continue
            matched += sum(
                1
                for line in path.read_text(encoding="utf-8").splitlines()
                if selector.pattern.match(line)
            )
        if unreadable:
            failures.append(
                f"the selector for {selector.name} is aimed at "
                f"{', '.join(unreadable)}, which cannot be read, so its match "
                "count means nothing either way."
            )
            continue
        if matched and selector.silent:
            failures.append(
                f"the selector for {selector.name} is recorded as matching "
                f"nothing on purpose ({selector.silent}), and it matched "
                f"{matched} row(s) in {', '.join(selector.files)}. A recorded "
                "expectation that has stopped being true is re-read rather "
                "than left standing."
            )
        if not matched and not selector.silent:
            failures.append(
                f"the selector for {selector.name} "
                f"({selector.pattern.pattern}) matches no row of "
                f"{', '.join(selector.files)}. A row selector that matches "
                "nothing reads every one of those files as carrying no rows at "
                "all, and every count derived from it stays plausible. Either "
                "the pattern has gone stale against a spelling the files now "
                "use -- which is what happened when identifiers became content "
                "digests -- or the expectation is deliberate and belongs in "
                "Selector.silent in writing."
            )
    return failures


def owner_of(line: str) -> str | None:
    for pattern in OWNERS:
        m = pattern.match(line)
        if m:
            return m.group(1).strip()
    return None


def row_owner(line: str) -> str | None:
    """The identifier in a generated table row's first cell, in the spelling the
    authored source files it under.

    Translating between the two spellings is the whole of this function and the
    reason it exists. The matrix prints a registry decision as ``D13`` where the
    registry records the id ``13``; an index prints a vector as the digest of its
    own bytes where the generator records it under the slug somebody typed. A
    selector that matched the row but returned the published spelling would key
    every vector row to an owner no authored file has, and each one would fall
    into the weaker whole-file branch below -- a per-row check that matches every
    row and compares none of them, which looks from the outside exactly like a
    per-row check that is working.
    """
    for selector in GENERATED_ROWS:
        m = selector.pattern.match(line)
        if m:
            name = m.group(1)
            if VECTOR_ID.match(name):
                slugs = vector_slugs()
                if name not in slugs:
                    raise SystemExit(
                        f"FAIL: the index row for {name} names a vector no "
                        "generator identifier map carries, so its anchors "
                        "cannot be compared against the source row that "
                        "records them. Defaulting to the published identifier "
                        "here would key the row to an owner no authored file "
                        "has and quietly downgrade it to the whole-file "
                        "question. Re-run the generators."
                    )
                return slugs[name]
            return name[1:] if name[0] == "D" and name[1:].isdigit() else name
    return None


def collect(paths: tuple[str, ...]) -> list[Anchor]:
    found: list[Anchor] = []
    for rel in paths:
        path = REPO_ROOT / rel
        if not path.is_file():
            continue
        owner = "-"
        seen: dict[str, int] = {}
        for lineno, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            named = owner_of(line)
            if named:
                owner = named
            for m in ANCHOR_RE.finditer(line):
                lo = int(m.group(1))
                hi = int(m.group(2)) if m.group(2) else lo
                base = f"{rel}::{owner}"
                seen[base] = seen.get(base, -1) + 1
                found.append(
                    Anchor(
                        key=f"{base}#{seen[base]}",
                        token=m.group(0),
                        lo=lo,
                        hi=hi,
                        site=f"{rel}:{lineno}",
                        owner=row_owner(line) or owner,
                    )
                )
    return found


def generated_failures(
    generated: list[Anchor], authored: list[Anchor], spec: list[str]
) -> list[str]:
    """A generated table carries the anchors its source carries, so a row naming
    an anchor its own source does not is a row that was written before the
    anchors moved and never regenerated, leaving a reader a stale table and no
    warning.

    The question is asked per row. Asking whether the anchor appears anywhere in
    the authored set is this same check with the row thrown away, and it passes
    for a stale row whenever the number it carries is still cited by some other
    entry. Neighbouring rules here share spans constantly, so that is the common
    case rather than the exotic one, and the check was answering a question
    nobody had asked.
    """
    live_rows: dict[str, set[str]] = {}
    for cite in authored:
        live_rows.setdefault(cite.owner, set()).add(cite.token)
    live = {c.token for c in authored}
    failures: list[str] = []
    for cite in generated:
        failures.extend(
            f"{cite.site}: {cite.token} {b}"
            for b in resolution_failures(cite, spec)
        )
        row = live_rows.get(cite.owner)
        if row is not None and cite.token not in row:
            failures.append(
                f"{cite.site}: {cite.token} is not among the anchors the source "
                f"records for {cite.owner} ({', '.join(sorted(row))}), so this "
                "generated row was not regenerated after the anchors moved."
            )
        # An anchor in a generated file's prose rather than in one of its rows
        # has no row to key on, so it keeps the weaker whole-file question.
        elif row is None and cite.token not in live:
            failures.append(
                f"{cite.site}: {cite.token} is cited by no source file, so this "
                "generated table was not regenerated after the anchors moved."
            )
    return failures


def keyed_split(generated: list[Anchor], authored: list[Anchor]) -> tuple[int, int]:
    """How many generated anchors got the per-row question, and how many the
    weaker whole-file one.

    Printed on every run for the same reason the aim check prints its rule
    density: the failure this gate has actually suffered is not a comparison
    that disagrees, it is a comparison that stops being made. When the vector-row
    selector died, this ratio fell from three hundred and fifty-one keyed to
    ninety-eight and no output anywhere changed. A number that moves when a
    reader goes blind has to be in front of somebody.
    """
    live_owners = {cite.owner for cite in authored}
    keyed = sum(1 for cite in generated if cite.owner in live_owners)
    return keyed, len(generated) - keyed


# --------------------------------------------------------------------------
# Is the anchor drawn around the rule the decision is about?
# --------------------------------------------------------------------------

DECISIONS_REL = "vectors/interpretation-decisions.json"

HEADING_RE = re.compile(r"^#{1,6}\s")
# The other boundary this document draws, and the one its member sections are
# actually built out of. Under a single heading the specification defines member
# after member, each opened by a line of the form `name` _type, required_, and
# between two of those lines sits one field's whole definition. A markdown
# heading is nowhere near them: `coverage` and `attackResults` are defined a
# hundred lines apart under one heading, so a span may run from one field's rules
# into another's without crossing anything the heading rule can see.
#
# That is not hypothetical. Every corrected anchor in this registry is a field
# definition drawn from its label to the end of its rules -- decision 6 opens on
# `coverage` at L879, decision 8 on `issuedAt` at L1672 -- and decision 8's
# original defect straddled the `issuedAt` label rather than sitting inside it.
# The line the corrections were drawn to is the line the check has to know about.
FIELD_LABEL_RE = re.compile(r"^`[A-Za-z][A-Za-z0-9_.\[\]]*`\s+_[^_]+_\s*$")
FENCE_RE = re.compile(r"^\s*(?:```|~~~)")
ITEM_RE = re.compile(r"^(?:[-*]\s|\d+\.\s)")
# A sentence ends at a full stop or a semicolon followed by space. The
# semicolon is a terminator here because this specification states most of its
# list-borne rules as semicolon-separated clauses, and reading such a list as
# one enormous sentence would let any anchor anywhere in the list inherit the
# rule stated in a clause fifteen lines away.
SENTENCE_END_RE = re.compile(r"(?<!e\.g)(?<!i\.e)(?<!vs)(?<!cf)[.;](?=\s|$)")

# The RFC 2119 keywords, which are the obvious half of what states a rule.
KEYWORD_RE = re.compile(
    r"\b(?:MUST NOT|MUST|REQUIRED|SHALL NOT|SHALL|SHOULD NOT|SHOULD)\b"
)

# The other half, and the reason the obvious rule alone is the wrong rule. This
# document states roughly two thirds of its obligations as a consequence rather
# than as a keyword: what makes a statement invalid, what makes it malformed,
# what covers nothing, what a verifier cannot do. Each construction below was
# read out of the specification rather than guessed at, and each one is a
# consequence a conformance vector can be written against, which is the test for
# admitting it. Widening this list past that test is how the check goes vacuous,
# so the gate prints the resulting density on every run.
CONSEQUENCE_RE = re.compile(
    r"\b(?:is|are|makes?|leaves?|renders?)\s+(?:the\s+\w+\s+|it\s+|them\s+)?"
    r"(?:in)?valid\b"
    r"|\bcovers?\s+nothing\b"
    r"|\b(?:is|are|makes?)\s+(?:the\s+\w+\s+)?malformed\b"
    r"|\bmust\b"
    r"|\bcannot\b"
    r"|\bmay\s+not\b"
    r"|\bnever\b"
    r"|\bfail(?:s|-closed)\b"
    r"|\brejects?\b|\brejected\b"
    r"|\bexactly\s+equals?\b"
)

# The third way this document states a rule: by fixing a value exactly. The run
# binding pre-image is written as a definition -- the digest "is the lowercase
# 64-hex SHA-256 of the RFC 8785 canonicalization of" a named object -- and
# carries no consequence word at all, yet a statement deriving anything else
# fails, so a vector can be written against it, which is the same test the
# consequence list is admitted under. Reading definitions as non-normative
# marked the whole of the Prerequisites section as citing nothing.
DEFINITION_RE = re.compile(
    r"\bis\s+the\s+(?:lowercase\s+)?[\w-]+\s+SHA-256\b"
    r"|\bis\s+defined\b|\bare\s+defined\b"
    r"|\bis\s+derived\b|\bare\s+derived\b"
    r"|\brecomputes?\b"
)

# The specification's controlled vocabulary: the identifiers it writes in
# backticks, plus the RFCs it cites by number. Both are spellings a reader
# cannot vary, which is what makes them usable as evidence that a sentence and a
# decision are about the same thing. Ordinary prose words are not, and a check
# built on word overlap alone scores every sentence in the document as vaguely
# relevant to every decision.
TERM_RE = re.compile(r"`([A-Za-z][A-Za-z0-9_.]*(?:\[\d\])?[A-Za-z0-9_.]*)`")
RFC_RE = re.compile(r"\bRFC\s?(\d{3,5})\b")
SHORTEST_TERM = 4

AIM_REMEDY = (
    "An anchor is the evidence that a registry decision reads a rule the "
    "document actually states. Read the span, find the sentence that carries "
    "the rule the decision interprets, and redraw the anchor around it; then "
    "re-pin with python3 scripts/spec-anchor-gate.py --sync --accept-reaim "
    "<key> and regenerate the tables built from the registry."
)


@dataclass(frozen=True)
class Sentence:
    """One sentence of the specification, with the lines it occupies.

    ``stem`` is the text that introduces the list this sentence is an item of,
    empty when it is not one. A list here routinely states its rule once, in the
    stem, and then spends five items saying what the rule ranges over: the
    coverage validity list opens "the following MUST hold or the attestation is
    invalid" and every item under it is a bare noun phrase. Judging those items
    without the stem marks five correct anchors as citing no rule at all.
    """

    lo: int
    hi: int
    text: str
    stem: str



def prose_blocks(spec: list[str]) -> list[list[tuple[int, str]]]:
    """The specification's paragraphs, outside fenced blocks, each line numbered.

    A fenced block is skipped rather than parsed: a schema is not prose, carries
    no rule a sentence-level check can read, and its punctuation would split
    into fragments that match anything.
    """
    blocks: list[list[tuple[int, str]]] = []
    block: list[tuple[int, str]] = []
    fenced = False
    for lineno, raw in enumerate(spec, start=1):
        if FENCE_RE.match(raw):
            fenced = not fenced
        elif fenced:
            continue
        elif raw.strip():
            block.append((lineno, raw.strip()))
            continue
        if block:
            blocks.append(block)
            block = []
    if block:
        blocks.append(block)
    return blocks


def list_items(lines: list[tuple[int, str]]) -> list[list[tuple[int, str]]]:
    """One paragraph split at each list-item marker, the lead text kept first."""
    groups: list[list[tuple[int, str]]] = []
    current: list[tuple[int, str]] = []
    for lineno, text in lines:
        if ITEM_RE.match(text) and current:
            groups.append(current)
            current = [(lineno, text)]
        else:
            current.append((lineno, text))
    if current:
        groups.append(current)
    return groups


def sentences_of(spec: list[str]) -> list[Sentence]:
    """Split the specification into sentences that know which lines they sit on.

    Fenced blocks are skipped: a schema block is not prose, carries no rule a
    sentence-level check can read, and its punctuation would split into
    fragments that match anything.
    """
    blocks = prose_blocks(spec)

    found: list[Sentence] = []
    carried = ""
    for lines in blocks:
        listed = ITEM_RE.match(lines[0][1]) is not None
        joined = " ".join(text for _, text in lines)
        if not listed:
            # A paragraph ending in a colon introduces the list that follows it,
            # across the blank line that separates them in the source.
            carried = joined if joined.rstrip().endswith(":") else ""
        groups = list_items(lines)
        lead = groups[0]
        inner = (
            " ".join(text for _, text in lead)
            if len(groups) > 1 and not ITEM_RE.match(lead[0][1])
            else ""
        )
        for group in groups:
            item = ITEM_RE.match(group[0][1]) is not None
            stem = (inner or (carried if listed else "")) if item else ""
            found.extend(split_group(group, stem))
    return found


def split_group(group: list[tuple[int, str]], stem: str) -> list[Sentence]:
    """Cut one paragraph or list item into sentences, keeping the line numbers.

    The line a sentence starts on is the line whose text the sentence's first
    character came from, which is the whole point: an anchor is a line range and
    a rule is a sentence, and the off-by-a-sentence defect lives exactly in the
    gap between the two.
    """
    text = " ".join(part for _, part in group)
    offsets: list[tuple[int, int]] = []
    cursor = 0
    for lineno, part in group:
        offsets.append((cursor, lineno))
        cursor += len(part) + 1

    def line_at(position: int) -> int:
        lineno = offsets[0][1]
        for offset, candidate in offsets:
            if offset <= position:
                lineno = candidate
        return lineno

    found: list[Sentence] = []
    start = 0
    ends = [m.end() for m in SENTENCE_END_RE.finditer(text)] + [len(text)]
    for end in ends:
        if end <= start:
            continue
        body = text[start:end].strip()
        if body:
            found.append(
                Sentence(
                    lo=line_at(start),
                    hi=line_at(max(end - 1, start)),
                    text=body,
                    stem=stem,
                )
            )
        start = end
    return found


def states_a_rule(sentence: Sentence) -> bool:
    for candidate in (sentence.text, sentence.stem):
        if candidate and (
            KEYWORD_RE.search(candidate)
            or CONSEQUENCE_RE.search(candidate)
            or DEFINITION_RE.search(candidate)
        ):
            return True
    return False


def vocabulary(spec: list[str]) -> frozenset[str]:
    words = {
        term.lower()
        for line in spec
        for term in TERM_RE.findall(line)
        if len(term) >= SHORTEST_TERM
    }
    return frozenset(words | {f"rfc{number}" for line in spec for number in RFC_RE.findall(line)})


def terms_of(text: str, vocab: frozenset[str]) -> frozenset[str]:
    lowered = text.lower()
    found = {f"rfc{number}" for number in RFC_RE.findall(text)}
    for term in vocab:
        if term.startswith("rfc"):
            continue
        if re.search(rf"(?<![a-z0-9_.]){re.escape(term)}(?![a-z0-9_])", lowered):
            found.add(term)
    return frozenset(found)


@dataclass(frozen=True)
class Subject:
    """One registry decision's anchor, and the words the decision uses.

    The subject text is the decision's title, its reading and the names of the
    vectors that force it. All three are written by the same hand as the anchor
    and none of them is derived from the anchor, so agreement between them is
    evidence rather than a tautology.
    """

    decision: int
    token: str
    lo: int
    hi: int
    words: str


def decision_subjects() -> tuple[list[Subject], list[str]]:
    """Every anchor recorded by a decision the registry calls forced, plus the
    entries that could not be read as one.

    Only the forced decisions. An unforced decision records where it would look
    if someone wrote the vector, and holding a placeholder to the standard of a
    citation would make the registry harder to be honest in, which is the one
    thing it exists for.

    The unreadable ones are returned rather than skipped, and that is the same
    argument the gate makes about a decision whose vocabulary is empty. An
    anchor spelled with an en dash, or written as prose, or a forced decision
    carrying no anchor at all, drops out of every question asked below and takes
    the count printed at the end down by one, which is a number nothing asserts.
    Skipping it reports an untested anchor as a passing one. Every forced
    decision in the registry today carries at least one anchor and every anchor
    parses, so this refuses nothing that exists and closes the door on the way
    an anchor could stop being checked without anyone seeing it.
    """
    source = REPO_ROOT / DECISIONS_REL
    prose = vector_prose()
    raw = json.loads(source.read_text(encoding="utf-8"))
    subjects: list[Subject] = []
    unreadable: list[str] = []
    for entry in raw.get("decisions", []):
        if entry.get("classification") != "forced":
            continue
        words = " ".join(
            [
                str(entry.get("title", "")),
                str(entry.get("reading", "")),
                # What the forcing vectors DO, not what they are called.
                #
                # This used to splice the vector identifiers in with their
                # hyphens turned into spaces, which worked only for as long as
                # an identifier was a description: `bad-205-payload-missing-
                # runbinding` contributed `payload` and `runbinding` to the
                # vocabulary this anchor is judged against. Identifiers are
                # digests of the vector's own bytes now, deliberately carrying
                # no description at all, so that source went silent -- and a
                # silent source here does not fail, it quietly shrinks the term
                # set until an anchor is judged against almost nothing.
                #
                # The description still exists; it is in the index row beside
                # each vector, which is where a person reads it too.
                " ".join(prose.get(v, "") for v in entry.get("forcingVectors", [])),
            ]
        )
        anchors = entry.get("specAnchors", [])
        if not anchors:
            unreadable.append(
                f"decision {entry.get('id')} is classified forced and records no "
                "anchor, so the reading it calls forced cites nothing and no "
                "question below is asked of it."
            )
        for anchor in anchors:
            m = ANCHOR_RE.fullmatch(str(anchor))
            if m is None:
                unreadable.append(
                    f"decision {entry.get('id')} records {str(anchor)!r}, which "
                    "is not a line anchor this gate can read, so it is not "
                    "checked. An unreadable anchor is an untested one, not a "
                    "passing one; write it as Lnnn or Lnnn-mmm."
                )
                continue
            lo = int(m.group(1))
            hi = int(m.group(2)) if m.group(2) else lo
            subjects.append(
                Subject(
                    decision=int(entry.get("id", 0)),
                    token=str(anchor),
                    lo=lo,
                    hi=hi,
                    words=words,
                )
            )
    return subjects, unreadable



def vector_prose() -> dict[str, str]:
    """Identifier -> the sentence its index row uses to describe it.

    One descriptive column per index, chosen rather than joining every cell:
    the condition ids and spec anchors in the other columns would add terms the
    row never claims, which would widen every anchor's aim test instead of
    aiming it.
    """
    out: dict[str, str] = {}
    for rel, column in (
        ("vectors/accept/INDEX.md", 3),
        ("vectors/reject/INDEX.md", 2),
        ("vectors/indeterminate/INDEX.md", 2),
    ):
        path = REPO_ROOT / rel
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line.startswith("|"):
                continue
            cells = [c.strip() for c in line.strip("|").split("|")]
            if len(cells) <= column:
                continue
            vid = cells[0].strip("`")
            if VECTOR_ID.match(vid):
                out[vid] = cells[column]
    if not out:
        raise SystemExit(
            "no index row described any vector, so every forced decision would "
            "be judged against its title and reading alone. An empty read here "
            "weakens the aim test silently, which is the one thing it must not do."
        )
    return out


def nearest_rule(
    rules: list[Sentence],
    subject: Subject,
    wanted: frozenset[str],
    terms: dict[int, frozenset[str]],
) -> str:
    """Where to look instead, preferring a rule the decision itself names.

    The nearest rule by line number is often the wrong suggestion: prose here is
    dense with rules about neighbouring fields, and an anchor sitting one
    sentence above its subject is usually within a line or two of some other
    field's obligation. Sending the reader there would reproduce the defect one
    field over.
    """
    named = [s for s in rules if terms.get(id(s), frozenset()) & wanted]
    pool = named or rules
    if not pool:
        return ""
    closest = min(
        pool,
        key=lambda s: min(abs(s.lo - subject.lo), abs(s.lo - subject.hi)),
    )
    if named:
        return (
            " The nearest sentence that states a rule this decision names "
            f"begins at L{closest.lo}."
        )
    return f" The nearest sentence that states a rule begins at L{closest.lo}."


def field_labels(spec: list[str]) -> list[int]:
    """The lines that open a member's definition.

    Returned as a list rather than tested in place because an empty one is a
    finding: this document defines its members this way throughout, so a run that
    finds none has lost the instrument rather than found a document without
    fields, and ``aim_report`` refuses on that instead of reporting a pass the
    check did not earn.
    """
    return [n for n, line in enumerate(spec, start=1) if FIELD_LABEL_RE.match(line)]


def aim_failures(
    spec: list[str], subjects: list[Subject], sentences: list[Sentence]
) -> list[str]:
    """Four questions, asked of every anchor a forced decision records.

    *Does the span carry a rule at all?* Decision 8 anchored three lines that
    held the tail of an unrelated paragraph and a field label, while the rule it
    interprets began eight lines further down, and the pin check could not see
    it: a wrong anchor addresses the text it was recorded against perfectly
    well, and both fields were pinned, so the disagreement was preserved rather
    than found.

    *Is the rule one this decision is about?* The first question alone is weak,
    because a rule-bearing sentence is not rare here. This one is what
    discriminates: the rule the span carries has to name something the decision
    names, in the specification's own controlled vocabulary.

    *Was the span widened until the first two questions became free?* An anchor
    stretched across a heading covers a whole section, is certain to contain
    some rule naming some term, and answers both questions by width rather than
    by aim. So a span may not cross a heading.

    *Did it reach its rule by running into the next field's definition?* The
    heading question closes width only between sections, and this document does
    not put its members in sections. Measured on the four defects this check was
    built for, restoring each wrong anchor and then widening it upward without
    ever reaching the rule below made three of the four pass: decision 6 at
    L795-886, decision 8 at L1581-1672, decision 14 at L795-886, each satisfying
    the term question on a rule about a different member ninety lines away. No
    heading is crossed in any of them, because none of them leaves the section.
    Each one does cross a field definition, so the last question is asked last:
    of an anchor that has already answered the other three, whether it answered
    them by running past the label that opens the next member.
    """
    vocab = vocabulary(spec)
    rules = [s for s in sentences if states_a_rule(s)]
    terms = {id(s): terms_of(s.text, vocab) for s in rules}
    labels = field_labels(spec)
    failures: list[str] = []
    for subject in subjects:
        crossed = [
            lineno
            for lineno in range(subject.lo, min(subject.hi, len(spec)) + 1)
            if HEADING_RE.match(spec[lineno - 1])
        ]
        if crossed:
            failures.append(
                f"decision {subject.decision} anchor {subject.token} crosses the "
                f"heading at L{crossed[0]} ({spec[crossed[0] - 1].strip()!r}). A "
                "span that crosses a heading cites two parts of the document as "
                "one rule, and satisfies every other question here by width "
                "rather than by aim."
            )
            continue
        wanted = terms_of(subject.words, vocab)
        covered = [s for s in rules if s.lo <= subject.hi and s.hi >= subject.lo]
        if not covered:
            inside = [
                s for s in sentences if s.lo <= subject.hi and s.hi >= subject.lo
            ]
            opens = inside[0].text[:72] if inside else "(no prose)"
            failures.append(
                f"decision {subject.decision} anchor {subject.token} covers no "
                f"sentence that states a rule; it opens on {opens!r}."
                + nearest_rule(rules, subject, wanted, terms)
            )
            continue
        if not wanted:
            failures.append(
                f"decision {subject.decision} anchor {subject.token} cannot be "
                "tested for aim: the decision's title, reading and forcing "
                "vectors name no term of the specification's controlled "
                "vocabulary, so there is nothing to agree with. This is an "
                "untested anchor, not a passing one."
            )
            continue
        aimed = [s for s in covered if terms[id(s)] & wanted]
        if not aimed:
            here = sorted({t for s in covered for t in terms[id(s)]})
            failures.append(
                f"decision {subject.decision} anchor {subject.token} covers a "
                "rule, but not one this decision is about: the rules in the "
                f"span name {here or ['nothing']}, and the decision names "
                f"{sorted(wanted)}, which share nothing."
                + nearest_rule(rules, subject, wanted, terms)
            )
            continue
        # Opening on a label is how every corrected anchor here is drawn: the
        # span starts at the member's name and runs to the end of its rules. So
        # the refusal is for a label the span RUNS PAST, never for the one it
        # begins on, and the distinction is the whole difference between an
        # anchor drawn around a field definition and one drawn through it.
        ran_past = [n for n in labels if subject.lo < n <= subject.hi]
        if ran_past:
            failures.append(
                f"decision {subject.decision} anchor {subject.token} runs past "
                f"the field definition that opens at L{ran_past[0]} "
                f"({spec[ran_past[0] - 1].strip()!r}), so the rules it cites "
                "belong to more than one member. An anchor may open on a field "
                "definition and cover it; reaching a rule by continuing into "
                "the next member's is width, not aim."
            )
    return failures


def aim_report(spec: list[str]) -> int:
    """The verdict on aim, refusing every count of nothing.

    Four of these refusals are the instrument reporting on itself. A splitter
    that stops finding sentences, a vocabulary that stops finding terms, a
    collector that stops finding anchors and a field-label pattern that stops
    finding member definitions all look identical from outside to a corpus with
    nothing wrong with it, and this repository has shipped that exact green line
    before. The last of the four is the newest and the easiest to lose: the
    label pattern is the only thing that refuses a span widened into a
    neighbouring member, it matches a spelling upstream is free to reflow, and
    matching nothing would make it silent rather than loud.
    """
    sentences = sentences_of(spec)
    rules = [s for s in sentences if states_a_rule(s)]
    labels = field_labels(spec)
    if not labels:
        print(
            "FAIL: no field definition was found in the specification, so "
            "nothing bounds an anchor inside a section and the width question "
            "is not being asked. This document opens every member with a line "
            "of the form `name` _type, required_; a run that finds none has "
            "lost the pattern, not found a document without members.",
            file=sys.stderr,
        )
        return 1
    if not sentences or not rules:
        print(
            "FAIL: no sentence in the specification states a rule, so the aim "
            "check has no subject and its result means nothing. The sentence "
            "splitter or the rule vocabulary has stopped matching the "
            "document.",
            file=sys.stderr,
        )
        return 1
    subjects, unreadable = decision_subjects()
    if not subjects:
        print(
            f"FAIL: no anchors were collected from {DECISIONS_REL}, so the aim "
            "check checked nothing and its result means nothing.",
            file=sys.stderr,
        )
        return 1
    failures = unreadable + aim_failures(spec, subjects, sentences)
    decisions = len({s.decision for s in subjects})
    if failures:
        print(
            f"FAIL: {len(failures)} anchor(s) are not drawn around a rule this "
            f"registry decision is about (of {len(subjects)} checked):",
            file=sys.stderr,
        )
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print(f"\n{AIM_REMEDY}", file=sys.stderr)
        return 1
    print(
        f"OK: {len(subjects)} anchor(s) on {decisions} forced decision(s) are "
        f"drawn around a rule the decision names, none of them running past a "
        f"field definition ({len(rules)} of {len(sentences)} spec sentences "
        f"state a rule; {len(labels)} member definitions bound them)."
    )
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--sync",
        action="store_true",
        help="rewrite the pin ledger from the anchors as they now stand",
    )
    ap.add_argument(
        "--aim-only",
        action="store_true",
        help="ask only whether each decision anchor is drawn around its rule",
    )
    ap.add_argument(
        "--accept-reaim",
        action="append",
        default=[],
        metavar="KEY",
        help="one citation key whose move onto different prose is intended",
    )
    args = ap.parse_args(argv[1:])
    # Before anything reads a row: every selector that decides WHICH rows get
    # read must prove it still matches some. This runs on --sync too, because a
    # synchronise performed through a dead selector writes a ledger missing
    # every citation the selector would have found and reports the smaller
    # number as the whole of them.
    dead = dead_selectors()
    if dead:
        print(
            f"FAIL: {len(dead)} row selector(s) read nothing they are aimed at:",
            file=sys.stderr,
        )
        for failure in dead:
            print(f"  {failure}", file=sys.stderr)
        return 1
    if args.sync:
        return sync(LEDGER, list(collect(AUTHORED)), set(args.accept_reaim))

    spec, _digest = spec_state(SPEC_REL)
    if args.aim_only:
        return aim_report(spec)
    if not LEDGER.path.is_file():
        print(
            f"FAIL: {LEDGER.path.relative_to(REPO_ROOT)} is missing; create it "
            "with python3 scripts/spec-anchor-gate.py --sync",
            file=sys.stderr,
        )
        return 1
    pins: dict[str, dict[str, str]] = json.loads(
        LEDGER.path.read_text(encoding="utf-8")
    ).get("citations", {})
    authored = collect(AUTHORED)
    generated = collect(GENERATED)
    failures = pinned_failures(list(authored), pins, spec, LEDGER)
    failures += generated_failures(generated, authored, spec)
    failures += orphan_failures(pins, list(authored), LEDGER)
    pinned = report(failures, len(authored) + len(generated), LEDGER, REMEDY)
    keyed, unkeyed = keyed_split(generated, authored)
    print(
        f"OK: {keyed} of {keyed + unkeyed} generated anchor(s) were compared "
        f"against the source row that records them; {unkeyed} sit in prose with "
        "no row to key on and kept the whole-file question."
    )
    # Both verdicts are printed on every run. They answer different questions --
    # whether an anchor still addresses its recorded text, and whether it was
    # ever aimed at the right rule -- and a run that stopped at the first
    # failure would hide the second behind the first for as long as the first
    # took to fix.
    return pinned or aim_report(spec)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
