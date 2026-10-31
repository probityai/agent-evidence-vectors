#!/usr/bin/env python3
"""Count gate: a corpus count is derived, and a bare integer standing for one is
not writable by hand.

Why a count needs a gate at all
-------------------------------
This corpus has been 125, 138, 140, 149, 153, 154, 156, 158, 165, 175 and 179
vectors, and it is larger again now. vectors/MANIFEST.json says by how much and
this sentence deliberately does not, because the census below reads no integer in
this file, so a live count written here would be exactly the unchecked cache the
gate exists to refuse. Every one of those historical numbers was typed into prose
in several places at once and the copies went stale at different rates, until two
documents in this repository disagreed about the size of the same corpus while
both looked authoritative. A count is a DERIVED fact. It has exactly one source,
and every appearance of it elsewhere is a cache with no invalidation.

The sources are named once, here:

  vectors/MANIFEST.json      the corpus as it stands: total, accept, reject
  vectors/CHANGES.md         the per-revision ledger, and so every size the
                             corpus has ever had; its head row is checked
                             against the manifest, which is what stops the
                             ledger and the corpus drifting apart
  docs/FORCING-BASELINE.json what the corpus forces: the four outcome counts,
                             the site total, the annotated sites
  docs/INDEPENDENT-RUNS.json the scores an outside reader posted, spelled as
                             posted

Check, not emit
---------------
The published counts are CHECKED against those sources rather than written into
the documents by a generator. Three reasons, and the first is a recorded decision
rather than a preference.

A generator that rewrites a span cannot fail. If the prose is a pure function of
the source it can only ever restate what it just read, and the check that the
sentence around the number still makes sense is not weakened but absent.
scripts/independent-runs-gate.py makes this argument at length for the
independence column and scripts/specpins.py makes it for line-range pins; the
same argument holds here, and holding it in two shapes in one repository would be
worse than holding it in one.

Second, the numbers live inside sentences that argue. A sentence of the shape
"N rules forced, N seen-but-tolerated, N unforced, N unmeasurable" sits in a
paragraph explaining why the four outcomes are kept apart. An emitter would have
to either drop that argument or carry it inside a script no reviewer of the
README opens.

Third, an emitting generator over a reviewed artifact defeats the review gate: a
reviewer approves prose and a later run rewrites it underneath them. A check
refuses instead, which leaves the author writing the sentence and the gate
refusing the number inside it.

The cost of checking is that a claim site has to be declared to be checked, and
that is exactly the hole the second half of this gate exists to close.

Banning the bare integer
------------------------
A gate that re-checks the counts it already knows about cannot catch the next one
somebody types into a new paragraph. So the second half is a CENSUS: it finds
every integer in the tracked prose that is shaped like a corpus count and refuses
unless something accounts for it.

What makes an integer count-shaped, mechanically:

  RATIO      `N/M` or `N of M`. Every score this repository publishes is written
             that way, and a denominator is a corpus size by construction.
  NOUN       a digit run immediately followed by `vectors`, optionally through
             `accept` or `reject`.
  VALUE      the integer equals a count the sources currently publish. This is
             the load-bearing rule and it is worth stating why: a count that is
             CORRECT when it is written necessarily equals the source. So
             requiring every source-valued integer to be accounted for catches
             the exact defect -- somebody types today's number, and it is nobody's
             job to revisit it -- for any wording, any noun, any file. The other
             two rules catch the smaller case of a count that was wrong when it
             was written.

Values below twenty are ambiguous with ordinary prose, so for those VALUE fires
only next to a word from the closed vocabulary in SMALL_VALUE_NOUNS below.

VALUE does not fire on a MEASUREMENT: an integer whose own syntax says it is a
size, a width, a length or an index (`64 hex characters`, `64-bit`, `{64}`,
`len(s) != 64`, `digest[:16]`). MEASURES below lists those contexts and argues
why they are the only ones. An integer with no such context stays count-shaped,
so a number whose context is ambiguous still needs one of the accounts below.

Forms that are not counts are masked before any of this runs: spec anchors
(`L157-165`, `spec:req-fields-row-per-executed-attack-attackid@73a2f29b13fa08fa`),
vector ids and id lists (`ok-006/007/029`),
condition ids, RFC numbers, upstream issue numbers, dates, version strings and
hex digests.

A count-shaped integer is accounted for in one of five ways, and every one of
them is a statement somebody had to make on purpose:

  1. it sits inside a declared claim below, whose value comes from a source;
  2. it sits inside a span another gate is declared to own, named in DELEGATED;
  3. it sits inside a declared FROZEN span -- a figure that records a past event
     and must NOT track the corpus, each carrying the reason it is frozen;
  4. it is revision-attributed: the sentence it sits in names a suiteRevision,
     and the ledger row for that revision carries the value. This is the route a
     writer should reach for first, because it is the only one that also tells
     the READER the number is a snapshot: `passed all 165 vectors (suiteRevision
     11)` says so on its face;
  5. it sits in vectors/CHANGES.md under `## suiteRevision N` and the value is a
     size the corpus had at or before N. A changelog entry is scoped by the
     heading it sits under, which is the same reason scripts/independent-runs-gate.py
     exempts that file from its not-run check.

Anything else fails, naming the file, the line, the integer and the five routes.

What this cannot catch
----------------------
A count spelled in words. "one hundred and eighty-six vectors" is invisible to
every rule here, and so is "four sites" once the value four stops being the
annotated-site count. The declared claims cover the two word-spelled counts this
repository publishes today; a third would go unnoticed until it went stale.

A count that was wrong when it was written, next to a noun outside the two-word
vocabulary, whose value collides with nothing. "the suite ships 400 files" passes.
The VALUE rule closes this for every count that is correct at the time of writing,
which is the case that actually occurs, and nothing closes it for a number that
was never right.

A count in a file this census does not read: JSON and other data files (they are
sources or generated), the vendored predicate text under spec/predicates/ (its
bytes are upstream's and scripts/spec-drift-gate.py owns them), and
docs/COVERAGE-MATRIX.md (generated end to end and gated by
scripts/coverage-matrix-gate.py --check). Go is read for `//` and `/* */`
comments only, so a count inside a Go string literal is not seen.

Revision attribution is satisfied by any revision the sentence names, not by the
right one. A sentence naming two revisions accepts a value belonging to either.
Tightening that would mean parsing which clause a number belongs to, which is a
reading rather than a match.

Where the mechanism lives
-------------------------
The rule above is general and its subject is not. Everything below this line is
about THIS corpus -- its sources, its claim sites, its frozen incidents, its
vocabulary -- while the machinery that reads prose, masks the non-counts, finds
the count-shaped integers and resolves each against a declaration is in
scripts/countcensus.py, which knows about none of that. It is a library because a
consumer in another repository now runs the same rule over a different subject,
and one rule implemented twice is two rules that will disagree. The argument for
the rule stays here; only the code moved.

Usage:
    python3 scripts/count-gate.py
    python3 scripts/count-gate.py --root <staged copy>   (what its own tests run)
Exit 0 when every published count is derived and every count-shaped integer is
accounted for; 1 on any disagreement, naming each one.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from countcensus import (
    Census,
    Claim,
    Covered,
    Delegated,
    Frozen,
    Quantities,
    Token,
    check_claims,
    check_declarations,
    read_tracked,
    run_census,
)

# ONE definition of a published identifier, imported rather than restated. A
# commit that fixed four silent droppers shipped with five, because one reader
# kept its own copy of a shared pattern; when identifiers changed shape that
# copy stopped matching and dropped its rows without complaint.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "vectors"))
from gen_manifest import VECTOR_ID_PATTERN  # noqa: E402

# The tree under check. `--root` points it at a staged copy, which is how
# scripts/count-gate-test.py mutates one file and asserts the refusal without
# ever editing the repository it is testing.
REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_REL = "vectors/MANIFEST.json"
#: The second corpus. It arrived with release v0.8.0 and this gate did not model
#: it, so the README could say `conformance vectors 272` -- correct for the only
#: manifest the gate knew, and understating a repository that ships two corpora --
#: while every check passed. The count was never wrong; the SCOPE was, which is
#: the same shape as a citation that resolves to the wrong line.
AGENT_ACTION_MANIFEST_REL = "vectors-ai-agent-action/MANIFEST.json"
#: The third corpus, for the artifact-binding contract beside the predicate. It
#: is modelled here from the day it lands rather than after a count in the README
#: goes stale, which is the sequence the note above records for the second one.
#: Its counts are keyed by VERDICT rather than by accept and reject, because that
#: corpus answers three outcomes and a two-bucket model of it would have to drop
#: one -- the not-established bucket, which is the only one it exists to test.
#: That verdict keying is why it stays wired by hand instead of joining
#: EXTRA_CORPORA below, whose readers model two buckets.
BINDING_MANIFEST_REL = "vectors-artifact-binding/MANIFEST.json"
#: Every further corpus, one line each, naming its directory. A directory listed
#: here has its three counts read from its own MANIFEST.json and admitted as
#: derived quantities, and the one sentence its INDEX.md publishes them in is
#: checked against them. One line is the whole registration on purpose: the three
#: corpora above are wired in by hand, each in five places, and a fourth wired the
#: same way would be a fifth chance to wire one of the five wrong. What a new
#: corpus owes in exchange is that sentence, in the shape claims_for_corpus below
#: expects, which is a small price for a count nobody can restate unchecked.
EXTRA_CORPORA: tuple[str, ...] = (
    "vectors-anchor-stream",
    "vectors-acs-core",
    "vectors-mcp-record-contract",
    "vectors-mcp-response-phase",
    "vectors-w3c-report",
    "vectors-observed-effect",
    "vectors-ai-generation",
    "vectors-receipt-signature",
    "vectors-agent-audit-record",
    "vectors-admission",
)
CHANGES_REL = "vectors/CHANGES.md"
BASELINE_REL = "docs/FORCING-BASELINE.json"
RUNS_REL = "docs/INDEPENDENT-RUNS.json"


def source(rel: str) -> Path:
    return REPO_ROOT / rel


# `## suiteRevision 16 (the corpus is regenerable, and was measured to prove it)`
REVISION_HEADING = re.compile(r"^## suiteRevision (\d+)\b", re.MULTILINE)
# `- Corpus: **186 vectors (46 accept, 140 reject)**, up from 179.` and the
# unbolded spelling the earlier entries use.
# The indeterminate group is optional because the ledger is history: every
# revision before the bucket existed declares a two-part row, and a regex that
# demanded three parts would fail on rows that were complete when written.
CORPUS_ROW = re.compile(
    r"Corpus:\s*\*{0,2}(\d+) vectors \((\d+) accept, (\d+) reject"
    r"(?:, (\d+) indeterminate)?\)",
    re.MULTILINE,
)

# Numbers this repository spells as words. Only the counts actually published
# that way need an entry; a value with no spelling here is checked as digits.
WORDS = {1: "one", 2: "two", 3: "three", 4: "four", 5: "five", 6: "six", 7: "seven"}


# --------------------------------------------------------------------------
# The sources
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Sources:
    """Every count this repository is entitled to publish, and where it came from."""

    total: int
    accept: int
    reject: int
    indeterminate: int
    revision: int
    forced: int
    tolerated: int
    unforced: int
    unmeasurable: int
    sites: int
    annotated: int
    ledger: dict[int, tuple[int, int, int, int]]
    figures: frozenset[str]
    #: The second corpus, and the predicate version each corpus declares. A
    #: predicate version is as derived as a count and rots the same way: it is
    #: written into prose, the specification moves, and the prose keeps its old
    #: number while looking authoritative. Both are read from the `predicateType`
    #: the corpus manifest declares, so neither is typed by hand anywhere.
    agent_action_total: int
    agent_action_accept: int
    agent_action_reject: int
    #: The artifact-binding corpus, counted by verdict. ``binding_verified`` and
    #: the two beside it are deliberately NOT added to ``current()`` below: every
    #: one of them is a single-digit value that collides with ordinary prose, and
    #: the census's VALUE rule at that magnitude produces false positives only.
    #: They are grounded by the declared claims instead, exactly as the second
    #: corpus's counts are.
    binding_total: int
    binding_verified: int
    binding_failed: int
    binding_not_established: int
    predicate_version: str
    agent_action_predicate_version: str
    #: One row per directory in EXTRA_CORPORA: (directory, total, accept, reject).
    extra: tuple[tuple[str, int, int, int], ...] = ()

    def current(self) -> dict[int, str]:
        """The values that must not be typed by hand, and what each one is.

        A value two sources both publish names BOTH of them. This map used to be
        a plain dict literal, so a collision resolved by insertion order and the
        loser vanished: when a registered corpus came to hold 32 vectors and the
        forcing baseline already recorded 32 seen-but-tolerated rules, the census
        told a reader that a sentence about tolerated rules carried a corpus
        total. The refusal was correct that the integer was unaccounted for and
        wrong about what it was, which sends the next person to the wrong file --
        the exact failure scripts/count-gate-test.py asserts against. Collisions
        are expected rather than rare here, because every count in this
        repository is a small integer drawn from the same range, so the map is
        built by accumulation and nothing is dropped by ordering.
        """
        by_value: dict[int, list[str]] = {}
        for value, noun in self._published():
            nouns = by_value.setdefault(value, [])
            if noun not in nouns:
                nouns.append(noun)
        return {value: " and ".join(nouns) for value, nouns in by_value.items()}

    def noun_bound(self) -> frozenset[int]:
        """The values whose only source is a per-kind count of a registered corpus.

        A corpus total stays count-shaped wherever it appears. The accept and
        reject counts of the registered corpora do not: each is one of a dozen
        small integers, and read bare they refused a sentence about 42 one-field
        pairs in another project's corpus, an issue number and a line range, on
        the revision that grew a corpus into that value. Beside a count noun
        they still fire. A value some other source also publishes is not
        noun-bound, because that source's reading still applies.
        """
        per_kind = {
            value
            for _, total, accept, reject in self.extra
            for value in (accept, reject, *(v for v in (total,) if v in PROTOCOL_CONSTANTS))
        }
        other = {
            value
            for value, noun in self._published()
            if not noun.startswith(("the accept count of ", "the reject count of "))
            and not (noun.startswith("the corpus total of ") and value in PROTOCOL_CONSTANTS)
        }
        return frozenset(per_kind - other)

    def _published(self) -> tuple[tuple[int, str], ...]:
        """Every (value, what it is) pair the sources publish, order preserved."""
        return (
            (self.total, "the corpus total"),
            (self.accept, "the accept count"),
            (self.reject, "the reject count"),
            # The indeterminate count is deliberately NOT here. This map drives
            # the census's VALUE rule, which fires on any integer equal to a
            # published count, and the bucket is two vectors: `2` collides with
            # "GATE 2", "version 2" and "the second pass" throughout this
            # repository, all of them within the small-value window of a noun in
            # SMALL_VALUE_NOUNS. Every one of those would fail as an unaccounted
            # count. The value is not unchecked -- it is grounded harder than the
            # census could ground it, by manifest_integrity_failures against the
            # entries and the files on disk, by head_row_failures against the
            # changelog, and by the three declared claims that publish the corpus
            # as a whole -- so what the exclusion drops is a heuristic that
            # produces only false positives at this magnitude.
            (self.revision, "the current suiteRevision"),
            (self.forced, "the count of forced rules"),
            (self.tolerated, "the count of seen-but-tolerated rules"),
            (self.unforced, "the count of unforced rules"),
            (self.unmeasurable, "the count of unmeasurable rules"),
            (self.sites, "the count of mutation sites"),
            (self.annotated, "the count of annotated sites"),
            # A registered corpus's counts, and only the ones large enough to
            # be unambiguous. This is the same exclusion the indeterminate
            # bucket carries above, for the same measured reason: a count of 8
            # collides with "Decision 8", a count of 15 with a pinned line
            # range, and a count of 7 with the ordinal in a sentence about six
            # diverging vectors, and every one of those sits within the
            # small-value window of a word in SMALL_VALUE_NOUNS. Admitting them
            # produced four refusals against prose that claims nothing about
            # any corpus, on the revision that registered a corpus of that
            # size. What the exclusion drops is a value heuristic; what still
            # grounds these counts is stronger than the heuristic was -- the
            # declared claim against the corpus's own index sentence, checked
            # here, and that corpus is grounded in the manifest
            # against its entries and its files before this gate reads it.
            *(
                (value, f"the {noun} of {directory}")
                for directory, total, accept, reject in self.extra
                for value, noun in (
                    (total, "corpus total"),
                    (accept, "accept count"),
                    (reject, "reject count"),
                )
                if value >= SMALL_VALUE
            ),
        )

    def historical(self) -> dict[int, set[int]]:
        """Value -> the revisions whose ledger row carries it."""
        out: dict[int, set[int]] = {}
        for rev, row in self.ledger.items():
            for value in row:
                # A revision predating the indeterminate bucket carries zero of
                # them, and admitting 0 here would exempt every "0" written next
                # to a count noun in a revision-naming sentence. An absent bucket
                # is not a size the corpus ever published.
                if value:
                    out.setdefault(value, set()).add(rev)
        return out


def revision_ledger() -> dict[int, tuple[int, int, int, int]]:
    """Every size the corpus has had, read from the changelog that owns revision
    numbering.

    One row per `## suiteRevision N` heading, taken from the `Corpus:` line
    inside that section. A section with no such line is a failure rather than a
    skip: a revision that declares no size makes every later reference to that
    revision's corpus unaccountable.
    """
    changes = source(CHANGES_REL)
    text = changes.read_text(encoding="utf-8")
    headings = list(REVISION_HEADING.finditer(text))
    if not headings:
        raise SystemExit(
            f"FAIL: {CHANGES_REL} carries no '## suiteRevision N' "
            "heading, so nothing says what size the corpus has ever been."
        )
    ledger: dict[int, tuple[int, int, int, int]] = {}
    for index, heading in enumerate(headings):
        end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
        row = CORPUS_ROW.search(text, heading.end(), end)
        if row is None:
            raise SystemExit(
                f"FAIL: {CHANGES_REL} has no 'Corpus: N vectors "
                f"(A accept, R reject)' line under suiteRevision {heading.group(1)}, so "
                "that revision declares no size and every reference to its corpus is "
                "unaccountable."
            )
        ledger[int(heading.group(1))] = (
            int(row.group(1)),
            int(row.group(2)),
            int(row.group(3)),
            int(row.group(4) or 0),
        )
    return ledger


def predicate_version(manifest: dict[str, object]) -> str:
    """The version segment of a manifest's declared predicateType, e.g. `0.7`.

    Read from the manifest rather than from a constant in this file, because a
    constant here would be the unchecked cache the whole gate exists to refuse.
    The trailing segment is the version by the in-toto predicateType convention
    (`https://in-toto.io/attestation/<name>/v<version>`); a URI that does not end
    that way is a refusal rather than a guess, because a predicate version this
    gate cannot read is one it must not certify.
    """
    declared = manifest.get("predicateType")
    if not isinstance(declared, str):
        raise SystemExit(
            "FAIL: a corpus manifest declares no predicateType string, so no "
            "predicate version can be derived from it."
        )
    tail = declared.rsplit("/", 1)[-1]
    if not tail.startswith("v") or not tail[1:]:
        raise SystemExit(
            f"FAIL: a corpus manifest declares predicateType {declared!r}, whose "
            "final segment is not the `v<version>` the in-toto convention puts "
            "there, so the version cannot be read rather than guessed."
        )
    return tail[1:]


def load_sources() -> Sources:
    manifest = json.loads(source(MANIFEST_REL).read_text(encoding="utf-8"))
    agent_action = json.loads(source(AGENT_ACTION_MANIFEST_REL).read_text(encoding="utf-8"))
    binding = json.loads(source(BINDING_MANIFEST_REL).read_text(encoding="utf-8"))
    baseline = json.loads(source(BASELINE_REL).read_text(encoding="utf-8"))
    runs = json.loads(source(RUNS_REL).read_text(encoding="utf-8"))
    ledger = revision_ledger()
    counts = baseline["counts"]
    return Sources(
        total=len(manifest["vectors"]),
        accept=manifest["counts"]["accept"],
        reject=manifest["counts"]["reject"],
        indeterminate=manifest["counts"]["indeterminate"],
        revision=max(ledger),
        forced=counts["KILLED"],
        tolerated=counts["SILENT"],
        unforced=counts["DEAD"],
        unmeasurable=counts["INCONCLUSIVE"],
        sites=len(baseline["sites"]),
        annotated=len(baseline["annotations"]),
        ledger=ledger,
        figures=frozenset(
            str(figure["figure"]) for run in runs["runs"] for figure in run.get("figures", [])
        ),
        agent_action_total=len(agent_action["vectors"]),
        agent_action_accept=agent_action["counts"]["accept"],
        agent_action_reject=agent_action["counts"]["reject"],
        binding_total=len(binding["vectors"]),
        binding_verified=binding["counts"]["verified"],
        binding_failed=binding["counts"]["failed"],
        binding_not_established=binding["counts"]["notEstablished"],
        predicate_version=predicate_version(manifest),
        agent_action_predicate_version=predicate_version(agent_action),
        extra=extra_corpora(),
    )


def extra_corpora() -> tuple[tuple[str, int, int, int], ...]:
    """The three counts each registered corpus publishes, read from its manifest.

    Read rather than declared: the manifest's own counts are checked against its
    entries by aee-verify before this gate sees them, so the
    chain a published total has to satisfy runs sentence, manifest, entries,
    files, and no link in it is checkable against itself.
    """
    rows: list[tuple[str, int, int, int]] = []
    for directory in EXTRA_CORPORA:
        payload = json.loads(source(f"{directory}/MANIFEST.json").read_text(encoding="utf-8"))
        entries = payload["vectors"]
        accept = sum(1 for entry in entries if entry.get("kind") == "accept")
        reject = sum(1 for entry in entries if entry.get("kind") == "reject")
        declared = payload.get("counts", {})
        if declared.get("accept") != accept or declared.get("reject") != reject:
            raise SystemExit(
                f"FAIL: {directory}/MANIFEST.json declares {declared} and carries "
                f"{{'accept': {accept}, 'reject': {reject}}}. Every count this gate "
                "publishes for that corpus descends from this field, so it may not "
                "disagree with the entries it counts."
            )
        rows.append((directory, len(entries), accept, reject))
    return tuple(rows)


def claims_for_corpus(directory: str, total: int, accept: int, reject: int) -> tuple[Claim, ...]:
    """The one sentence a registered corpus publishes its counts in.

    The wording is fixed so that registration stays one line. A corpus whose
    INDEX.md words it differently fails here, which is the intended cost: three
    counts in three sentences apart is three places to go stale at three rates,
    and this repository has already had two documents disagree about the size of
    one corpus while both looked authoritative.

    The wording says "of which" rather than equating the total to the sum,
    because a corpus may carry a third bucket for members whose property its
    specification cannot express, and a sentence asserting an arithmetic that
    happens to hold today is a sentence that goes false when one arrives.
    """
    index = f"{directory}/INDEX.md"
    return (
        Claim(
            index,
            f"{directory}: the corpus total",
            "This corpus is ",
            " vectors, of which ",
            str(total),
        ),
        Claim(
            index,
            f"{directory}: the accept count",
            " vectors, of which ",
            " a conformant verifier must not fail closed on and ",
            str(accept),
        ),
        Claim(
            index,
            f"{directory}: the reject count",
            "must not fail closed on and ",
            " it must reject.",
            str(reject),
        ),
    )


def manifest_integrity_failures(src: Sources) -> list[str]:
    """The root source is grounded in the files, not in a field it declares.

    ``counts`` in the manifest is written by the generator and is as hand-typable
    as any sentence. Every number this gate publishes descends from it, so it is
    checked three ways -- the declared counts, the entries that carry them, and
    the vector files on disk -- before any of them is used. A root that only
    agreed with itself would make the whole gate a check that cannot fail.
    """
    manifest = json.loads(source(MANIFEST_REL).read_text(encoding="utf-8"))
    out: list[str] = []
    total_entries = len(manifest["vectors"])
    on_disk = len(list((REPO_ROOT / "vectors" / "statements").glob("*.json")))
    if total_entries != on_disk:
        out.append(
            f"vectors/MANIFEST.json carries {total_entries} entr(ies) and "
            f"vectors/statements/ holds {on_disk} file(s). Every published count "
            "descends from this field, so it may not disagree with the corpus it "
            "counts."
        )
    for kind, declared in (
        ("accept", src.accept),
        ("reject", src.reject),
        ("indeterminate", src.indeterminate),
    ):
        entries = sum(1 for v in manifest["vectors"] if v.get("kind") == kind)
        # Counted against the manifest alone, because one flat directory of
        # content-addressed statements cannot be split by verdict -- which is
        # exactly why it is flat. The directory is still grounded, in the total
        # below, and vectors/gen_manifest.py refuses a file with no row and a
        # row with no file before any of this is read.
        if declared == entries:
            continue
        out.append(
            f"vectors/MANIFEST.json: it declares {declared} {kind} vector(s) and "
            f"carries {entries} {kind} entr(ies). "
            "Every published count descends from this field, so it may not disagree "
            "with the corpus it counts."
        )
    if src.total != len(manifest["vectors"]):
        out.append(
            f"vectors/MANIFEST.json: the total {src.total} is not the number of "
            f"entries it carries ({len(manifest['vectors'])})."
        )
    return out


INDEX_HEADING = re.compile(r"^## Vectors \((\d+)\)$", re.MULTILINE)
# A published identifier, anchored, in the spelling gen_manifest.py reads it: the
# reject index backticks its ids and the accept index does not. A published
# identifier is a digest of the vector's own bytes. It carries no family, which
# is the point: a table row used to name the verdict in its first cell, and so
# did the filename and the directory.
INDEX_ROW_ID = re.compile(rf"^`?({VECTOR_ID_PATTERN})`?$")
# The vector table is the one whose first column is called `vector`. An index
# carries other tables -- the reject index has a digest-preimage table of
# 64-hex rows -- so the identifier cannot be what tells a vector row from
# another table's row: that is the very thing being checked.
INDEX_TABLE_HEADER = "vector"
# Which family of the corpus each index table is the table of.
INDEX_FAMILY = {
    "vectors/accept/INDEX.md": "accept",
    "vectors/reject/INDEX.md": "reject",
    "vectors/indeterminate/INDEX.md": "indeterminate",
}


def vector_table_rows(text: str) -> tuple[list[str], list[str]]:
    """The vector table's row identifiers, and the rows that carry none.

    Scoped by the table's HEADER rather than by the identifier, because matching
    the identifier is what a reader of this table must not use to decide whether
    a line is a vector row: a row whose first cell stopped matching would simply
    not be a row, the table would be one vector shorter, and every count derived
    from it would still agree with every other. vectors/gen_manifest.py learned
    that and refuses such a row; this gate declared in a comment that it mirrored
    that reader while running a looser regex over the whole file, so a row the
    generator would refuse outright was invisible here. That is the sixth silent
    dropper of the same campaign, and it lived inside the sentence claiming it
    could not.

    Returns the identifiers found and the first cells that are not identifiers.
    An unreadable row is returned to be reported, never dropped.
    """
    ids: list[str] = []
    unreadable: list[str] = []
    inside = False
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("|"):
            inside = False
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        first = cells[0] if cells else ""
        if first == INDEX_TABLE_HEADER:
            inside = True
            continue
        if not inside:
            continue
        if first and set(first) <= {"-", ":"}:
            continue  # the header's underline
        if match := INDEX_ROW_ID.match(first):
            ids.append(match.group(1))
            continue
        unreadable.append(first)
    return ids, unreadable


def index_failures(texts: dict[str, str], covered: dict[str, list[Covered]]) -> list[str]:
    """Each index table carries exactly one row per corpus vector of its family.

    This used to check a `## Vectors (N)` heading against the table beneath it,
    and said in its own docstring what that cost: it catches a heading that has
    drifted from its table and it CANNOT catch a table that has drifted from the
    corpus. It then ran green through exactly that, for five vectors, until the
    manifest generator refused to run.

    Both sides now come from outside the file. The heading is compared with the
    manifest's entries for that family, and the rows are compared with the
    manifest's ids, in both directions and counting duplicates. The manifest is
    not a free-standing authority either -- manifest_integrity_failures grounds
    its counts in the vector files on disk before any of this is read -- so the
    chain a row has to satisfy runs table, manifest, directory, and no link in it
    is checkable against itself.
    """
    manifest = json.loads(source(MANIFEST_REL).read_text(encoding="utf-8"))
    by_family: dict[str, list[str]] = {}
    for vector in manifest["vectors"]:
        by_family.setdefault(str(vector["kind"]), []).append(str(vector["id"]))
    out: list[str] = []
    for rel, text in sorted(texts.items()):
        family = INDEX_FAMILY.get(rel)
        if family is None:
            continue
        expected = by_family.get(family, [])
        rows, unreadable = vector_table_rows(text)
        if unreadable:
            out.append(
                f"{rel}: {sorted(unreadable)} sit in the vector table and name no "
                "identifier this corpus publishes. A row that cannot be read is a "
                "vector dropped from every count derived from this table, and the "
                "counts would still agree with each other. Fix the row, or teach "
                "vectors/gen_manifest.py's VECTOR_ID the new shape."
            )
        for heading in INDEX_HEADING.finditer(text):
            covered.setdefault(rel, []).append(
                Covered(heading.start(), heading.end(), "the vector-table heading")
            )
            if int(heading.group(1)) != len(expected):
                out.append(
                    f"{rel}: the vector-table heading says {heading.group(1)} and "
                    f"vectors/MANIFEST.json carries {len(expected)} {family} "
                    "vector(s)."
                )
        out.extend(row_reconciliation_failures(rel, rows, expected))
    return out


def row_reconciliation_failures(rel: str, rows: list[str], expected: list[str]) -> list[str]:
    """One row per corpus vector of this family, in both directions, with duplicates.

    Both sides come from outside the file, so a table cannot satisfy this by
    agreeing with itself.
    """
    out: list[str] = []
    seen: dict[str, int] = {}
    for vid in rows:
        seen[vid] = seen.get(vid, 0) + 1
    if duplicated := sorted(vid for vid, n in seen.items() if n > 1):
        out.append(
            f"{rel}: {duplicated} each carry more than one row. A vector with two "
            "rows is a vector whose two rows can disagree."
        )
    if missing := [vid for vid in expected if vid not in seen]:
        out.append(
            f"{rel}: the corpus carries {missing} and this table has no row for "
            "them, so nothing here says what they test."
        )
    if extra := sorted(set(rows) - set(expected)):
        out.append(f"{rel}: {extra} have a row here and no entry in vectors/MANIFEST.json.")
    return out


def head_row_failures(src: Sources) -> list[str]:
    """The changelog's newest row is the manifest, or the ledger is not the corpus.

    Every historical size in this gate is read from that ledger, so a head row
    that disagrees with the manifest would let the whole file drift away from the
    corpus while every rule below it kept passing.
    """
    row = src.ledger[src.revision]
    if row == (src.total, src.accept, src.reject, src.indeterminate):
        return []
    return [
        f"vectors/CHANGES.md: suiteRevision {src.revision} declares "
        f"{row[0]} vectors ({row[1]} accept, {row[2]} reject, {row[3]} "
        f"indeterminate) and vectors/MANIFEST.json carries {src.total} "
        f"({src.accept} accept, {src.reject} reject, {src.indeterminate} "
        "indeterminate). The changelog is the ledger every historical count "
        "in this repository resolves through, so its newest row is the manifest or "
        "nothing else can be trusted."
    ]


# --------------------------------------------------------------------------
# Half one: the declared claims
# --------------------------------------------------------------------------


RECORDING = "vectors-anchor-stream/recordings/anchors-verify-v0.10.json"

#: Every site in the catalog drafts and their generated bodies that publishes a count
#: descending from the recording: (file, name, prefix, suffix, which figure).
REPLY_SITES: tuple[tuple[str, str, str, str, str], ...] = (
    ("docs/proposals/catalog-1-body.md", "reply: corpus total",
     "27 of its ", " members agree with v0.10.", "total"),
    ("docs/proposals/catalog-pr-body.md", "pr body: agreeing members",
     "Today 27 of the ", " members agree with anchors-verify-v0.10.", "total"),
    ("docs/proposals/catalog-pr-body.md", "pr body: the gate that would be red",
     "A gate demanding ", " would go red", "total"),
    ("docs/proposals/catalog-pr-body.md", "pr body: members that disagree",
     "It stays silent about the ", " that already disagree", "disagree"),
    ("docs/proposals/catalog-pr-body.md", "pr body: the verifier's member count",
     "exits 0 over ", " members, 12 accept", "total"),
    ("docs/proposals/packets/catalog-pr.md", "pr draft: the verifier's member count",
     "prints `members: ", "`, `accept", "total"),
    ("docs/proposals/packets/catalog-pr.md", "pr draft: the recording's member count",
     "anchors-verify-v0.10.json`, ", " members, 27 true", "total"),
    ("docs/proposals/packets/catalog-pr.md", "pr draft: agreeing members",
     "Today 27 of the ", " members agree with anchors-verify-v0.10.", "total"),
    ("docs/proposals/packets/catalog-pr.md", "pr draft: the gate that would be red",
     "A gate demanding ", " would go red", "total"),
    ("docs/proposals/packets/catalog-pr.md", "pr draft: members that disagree",
     "It stays silent about the ", " that already disagree", "disagree"),
    ("docs/proposals/packets/catalog-pr.md", "pr draft: the verifier's member count in prose",
     "exits 0 over ", " members, 12 accept", "total"),
    ("docs/proposals/packets/catalog-pr.md", "pr draft: the agreement ratio",
     "|\n| ", " members agree with `anchors-verify-v0.10`", "ratio"),
    ("docs/proposals/packets/catalog-1.md", "reply draft: corpus total",
     "27 of its ", " members agree with v0.10.", "total"),
)


def reply_claims(src: Sources) -> tuple[Claim, ...]:
    """The counts the catalog drafts publish, every one derived from the recording.

    The drafts quote how many corpus members a published verifier agrees with and how
    many it does not. Both descend from one file: the recording names every member and
    whether it agreed, so each figure is read off it rather than typed beside the last
    one. A recording refreshed against a new tag moves every site in the same commit or
    this gate refuses. The generated bodies carry the same sentences, so they carry the
    same claims.
    """
    recorded = json.loads(Path(RECORDING).read_text(encoding="utf-8"))
    (members,) = recorded.values()
    agreeing = sum(1 for agrees in members.values() if agrees)
    figures = {
        "total": str(len(members)),
        "disagree": str(len(members) - agreeing),
        "ratio": f"{agreeing} of {len(members)}",
    }
    return tuple(
        Claim(path, name, prefix, suffix, figures[which])
        for path, name, prefix, suffix, which in REPLY_SITES
    )


W3C_REPORT_DIR = "vectors-w3c-report"


def w3c_selection_claims() -> tuple[Claim, ...]:
    """The section 10 selection the w3c-report README states, by the generator's rule.

    The README restates the split INDEX.md prints, by hand. At v0.18.0 it said
    the selection "stays" 41 to reject and 124 to accept, in the release that
    moved 42 members from reject to accept; the split before that release was
    83 and 82, so "stays" was true of the size and false of the split. The
    split is read here from the manifest by the same selection() the generator
    renders INDEX.md with, so the rule has one implementation and the README
    sentence fails here the day the manifest's split moves.
    """
    spec = importlib.util.spec_from_file_location(
        "w3c_report_gen_vectors", source(f"{W3C_REPORT_DIR}/gen_vectors.py")
    )
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load {W3C_REPORT_DIR}/gen_vectors.py")
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    manifest = json.loads(source(f"{W3C_REPORT_DIR}/MANIFEST.json").read_text(encoding="utf-8"))
    chosen = generator.selection(manifest)["selected"]
    total = chosen["reject"] + chosen["accept"]
    return (
        Claim(
            f"{W3C_REPORT_DIR}/README.md",
            "the section 10 selection and its split",
            "The section 10 selection is ",
            " to accept.",
            f"{total} members, {chosen['reject']} to reject and {chosen['accept']}",
        ),
    )


def claims(src: Sources) -> tuple[Claim, ...]:
    """Every live count this repository publishes, and what the sources say it is.

    The hand-wired claims below, plus three per directory in EXTRA_CORPORA. A
    registered corpus publishes its counts in one fixed sentence, so the claims
    for it are generated from the registration instead of being typed out a
    fourth time.
    """
    return declared_claims(src) + reply_claims(src) + w3c_selection_claims() + tuple(
        claim
        for directory, total, accept, reject in src.extra
        for claim in claims_for_corpus(directory, total, accept, reject)
    )


def scitt_cose_counts() -> dict[str, int]:
    """The SCITT/COSE corpus counts, tallied from its entries as extra_corpora does.

    That corpus is judged by its own checker and is not in EXTRA_CORPORA, so its
    size is claimed by hand below; the figures still come from a tally of the
    manifest's entries, checked against the counts it declares, rather than from
    the declared field alone.
    """
    payload = json.loads(source("vectors-scitt-cose/MANIFEST.json").read_text(encoding="utf-8"))
    entries = payload["vectors"]
    tally = {kind: 0 for kind in ("accept", "reject", "indeterminate")}
    for position, entry in enumerate(entries, start=1):
        kind = entry.get("kind") if isinstance(entry, dict) else None
        if not isinstance(kind, str) or kind not in tally:
            raise SystemExit(
                f"FAIL: vectors-scitt-cose/MANIFEST.json member {position} has "
                f"unsupported kind {kind!r}; every member must be accept, reject "
                "or indeterminate before its count can be claimed."
            )
        tally[kind] += 1
    declared = payload.get("counts", {})
    if not isinstance(declared, dict) or any(
        isinstance(declared.get(kind), bool) for kind in tally
    ):
        raise SystemExit(
            "FAIL: vectors-scitt-cose/MANIFEST.json counts must be an object of "
            "numeric counts; boolean values are not counts."
        )
    if any(declared.get(kind) != tally[kind] for kind in tally):
        raise SystemExit(
            f"FAIL: vectors-scitt-cose/MANIFEST.json declares {declared} and carries "
            f"{tally}. The counts this gate claims for that corpus descend from this "
            "field, so it may not disagree with the entries it counts."
        )
    return {"total": len(entries), **tally}


def declared_claims(src: Sources) -> tuple[Claim, ...]:
    """The claim sites written out one at a time, each against its own sentence."""
    gemara = json.loads(source("interop/gemara-method-link/MANIFEST.json").read_text())
    scitt = scitt_cose_counts()
    rev = src.revision
    corpus = (
        f"{src.total} vectors ({src.accept} accept, {src.reject} reject, "
        f"{src.indeterminate} indeterminate)"
    )
    return (
        Claim(
            "interop/gemara-method-link/README.md",
            "the Gemara profile case count",
            "The ",
            " cases use complete Policy and EvaluationLog",
            str(len(gemara["cases"])),
        ),
        # The SCITT/COSE corpus is judged by its own checker and is not in
        # EXTRA_CORPORA, so its size is claimed here against its manifest: once
        # in the Go reader's comment and once, with the breakdown, in the profile.
        Claim(
            "corpora/scittcose.go",
            "the SCITT/COSE corpus size the Go reader's comment states",
            "vectors-scitt-cose/ carries ",
            " members and a",
            str(scitt["total"]),
        ),
        Claim(
            "profiles/scitt-cose.md",
            "the SCITT/COSE corpus size the profile states",
            "`vectors-scitt-cose/` carries ",
            " members, ",
            str(scitt["total"]),
        ),
        Claim(
            "profiles/scitt-cose.md",
            "the SCITT/COSE accept count the profile states",
            " members, ",
            " accept, ",
            str(scitt["accept"]),
        ),
        Claim(
            "profiles/scitt-cose.md",
            "the SCITT/COSE reject count the profile states",
            " accept, ",
            " reject and ",
            str(scitt["reject"]),
        ),
        Claim(
            "profiles/scitt-cose.md",
            "the SCITT/COSE indeterminate count the profile states",
            " reject and ",
            " indeterminate, and each one cites",
            str(scitt["indeterminate"]),
        ),
        Claim(
            "docs/guides/corpora.md",
            "the AEE predicate version, in the opening sentence",
            "**Adversarial Execution Evidence**, predicate version ",
            ", and **AI Agent",
            src.predicate_version,
        ),
        Claim(
            "docs/guides/corpora.md",
            "the AI Agent Action predicate version, in the opening sentence",
            "**AI Agent\nAction**, predicate version ",
            ", proposed in",
            src.agent_action_predicate_version,
        ),
        Claim(
            "docs/research/corpus-measurements.md",
            "what a full replay reports, in the forcing section",
            "the suite still reports ",
            ", exit 0. A rail with no",
            f"{src.total} of {src.total}",
        ),
        Claim(
            "docs/research/corpus-measurements.md",
            "the size of the mutation sweep",
            "notices -- ",
            " single-site weakenings of",
            str(src.sites),
        ),
        Claim(
            "docs/research/corpus-measurements.md",
            "the four forcing outcomes",
            "tighten-only ratchet: **",
            ".** The four outcomes",
            f"{src.forced} rules forced, {src.tolerated} seen-but-tolerated, "
            f"{src.unforced} unforced, {src.unmeasurable}\nunmeasurable",
        ),
        Claim(
            "docs/research/corpus-measurements.md",
            "how many forcing sites carry an annotation",
            "The baseline annotates ",
            " sites as",
            WORDS.get(src.annotated, str(src.annotated)),
        ),
        Claim(
            "docs/research/corpus-measurements.md",
            "the nightly sweep's size",
            "sweeps all ",
            " sites nightly",
            str(src.sites),
        ),
        Claim(
            "docs/IMPLEMENTATION-REPORT.md",
            "the corpus line in the document header comment",
            f"Corpus SSOT: vectors/MANIFEST.json (suiteRevision {rev}, ",
            ").",
            f"{src.total} vectors: {src.accept} accept, {src.reject} reject, "
            f"{src.indeterminate} indeterminate",
        ),
        Claim(
            "docs/IMPLEMENTATION-REPORT.md",
            "the reference-corpus section",
            f"`vectors/MANIFEST.json`, suiteRevision {rev}: **",
            "**.",
            corpus,
        ),
        Claim(
            "docs/IMPLEMENTATION-REPORT.md",
            "the implementations table, the first-party result cells",
            f"reference corpus, suiteRevision {rev} | **",
            "** |",
            f"{src.total} / {src.total}",
            occurrences=2,
        ),
        Claim(
            "docs/IMPLEMENTATION-REPORT.md",
            "the scoping paragraph on what agreement does not say",
            "Nor does agreement on ",
            " vectors say anything",
            str(src.total),
        ),
        Claim(
            "BUILD-NOTES.md",
            "the verified-state paragraph, what the replay covers",
            "sibling vector suite: ",
            ", both key policies",
            f"{src.accept} accept vectors, {src.reject} reject vectors, "
            f"{src.indeterminate} indeterminate vectors",
        ),
        Claim(
            "BUILD-NOTES.md",
            "the verified-state paragraph, the strict-pass total",
            "and empty), all ",
            " strict passes.",
            str(src.total),
        ),
        Claim(
            "crosswalks/aee-to-ave.md",
            "the provenance paragraph's statement of this corpus",
            "The conformance suite is at revision ",
            ", per vectors/MANIFEST.json.",
            f"{rev} with {src.total} vectors, {src.accept} accept, {src.reject} "
            f"reject and {src.indeterminate} indeterminate",
        ),
        Claim(
            ".github/workflows/ci.yml",
            "the vector-replay step name",
            "on the Python rail (must be ",
            ")",
            f"{src.total}/{src.total}",
        ),
        Claim(
            ".github/workflows/ci.yml",
            "the forcing job's note on what a vector count does not measure",
            "the suite still reports ",
            ", exit 0. The only way",
            f"{src.total} of {src.total}",
        ),
        Claim(
            ".github/workflows/ci.yml",
            "the forcing job's measured scope",
            "that carries between machines: ",
            " sites and",
            f"{src.forced} of {src.sites}",
        ),
        Claim(
            ".github/workflows/forcing-nightly.yml",
            "the nightly sweep's measured scope",
            "16-worker workstation: ",
            " sites,",
            str(src.sites),
        ),
        Claim(
            "TODO.md",
            "the open item on what the operator set cannot express",
            "not even as a gap. ",
            " sites is the size of what can be asked",
            str(src.sites),
        ),
    )


DELEGATED: tuple[Delegated, ...] = (
    # The W3C report corpus's section 10 selection. Its index is rendered from
    # the corpus manifest by the generator, and the regenerability gate refuses
    # an index the generator would not write, so each figure in this sentence is
    # the manifest's own count. It was reported only when the ACS-Core total
    # walked onto its accept count.
    Delegated(
        "vectors-w3c-report/INDEX.md",
        "the section 10 selection's reject and accept counts",
        r"reject and \d+ to accept",
        "vectors-w3c-report/gen_vectors.py",
    ),
    # The same index's count of members excluded under a proposed rule, rendered
    # from that manifest by the same generator. It was reported only when the
    # audit record corpus's accept count, at -00 regeneration, walked onto it.
    Delegated(
        "vectors-w3c-report/INDEX.md",
        "the members counted apart as excluded under a proposed rule",
        r"excluded-under-proposed-rule, \d+ members",
        "vectors-w3c-report/gen_vectors.py",
    ),
    # The AAE v1.4.0 binding package. Its integers are vector identifiers
    # (aae-enforce-vector-25 and its file prefixes), the size of the pinned
    # upstream set, the run's printed tallies, and the draft's resource bounds.
    # The package tests pin every input by digest, assert the 26-file set and
    # the printed line, and exercise both sides of each bound.
    *(Delegated("interop/aae-verdict-binding-v1/" + name,
                "AAE v1.4.0 vector ids, set size, tallies and bounds", pattern,
                "interop/aae-verdict-binding-v1/test_aae_binding.py")
      for name, pattern in (
          ("README.md", r"\d+/\d+ vectors reproduced, \d+/\d+ cases"),
          ("README.md", r"All \d+ enforce vectors"),
          ("README.md", r"\(vector \d+\)"),
          ("OUTPUT-CONTRACT.md", r"\d+/\d+ vectors reproduced, \d+/\d+ cases"),
          ("OUTPUT-CONTRACT.md", r"all \d+ vectors reproduced"),
          ("OUTPUT-CONTRACT.md", r"vectors \d+ and \d+"),
          ("PROFILE.md", r"depth at most \d+"),
          ("check_report.py", r"all \d+ vectors reproduced"),
          ("gen_cases.py", r'vector\("\d+"\)'),
          ("gen_cases.py", r"Vector \d+:"),
          ("kernel.py", r"at most \d+, non-empty strings"),
          ("pins.py", r"The \d+ enforce vectors"),
          ("pins.py", r"aae-enforce-vector-\d+"),
          ("reproduce.py", r"aae-enforce-vector-\d+"),
          ("test_aae_binding.py",
           r'\("\d+", "prior_verdict_permit"\), \("\d+", "prev_core_digest_mismatch"\)'),
          ("test_aae_binding.py", r"\d+/\d+ vectors reproduced, \d+/\d+ cases"),
      )),
    # The CCS draft-10 reader package. Its ratios are what the reader measured
    # over the pinned CCS v1.4.0 corpus (receipts, cases, hops), not this
    # corpus. test_ccs_reader.py reruns the reader on the vendored bytes and
    # asserts each figure against the committed results.
    *(Delegated("interop/ccs-draft10-reader/README.md",
                "CCS v1.4.0 reader tallies over receipts, cases and hops", pattern,
                "interop/ccs-draft10-reader/test_ccs_reader.py")
      for pattern in (
          r"verifies \d+ of \d+",
          r"bytes for \d+ of \d+",
          r"agrees with the corpus on \d+ of \d+ cases",
          r"in \d+ of \d+ receipts",
          r"`args_digest` in \d+ of \d+",
          r"\d+ of \d+ receipts use that form",
          r"matches in \d+ of \d+ once",
          r"in \d+ of \d+ hops",
      )),
    # The TR-ANC-002 comparison table: each row's agreement count is the corpus
    # size less the pin's recorded disagreements. test_record.py derives every
    # row from pins.json and the manifest, and compare.py holds each pin's
    # record to the live TRACE sources.
    Delegated(
        "interop/trace-anchor-tr-anc/README.md",
        "TR-ANC-002 agreement per pinned TRACE commit",
        r"\| \d+ of \d+ \| \d+ \|",
        "interop/trace-anchor-tr-anc/test_record.py",
    ),
    # The AgentID action_ref v2 recompute prints its own tallies; the reader
    # exits nonzero unless every upstream check and domain case holds, and
    # test_reader.py asserts the two totals.
    Delegated(
        "interop/agentid-action-ref-v2/README.md",
        "the reader's printed upstream-check and domain-case tallies",
        r"upstream checks \d+/\d+, domain cases \d+/\d+",
        "interop/agentid-action-ref-v2/test_reader.py",
    ),
    # These transport and fixture values have no corpus population meaning.
    # The real process, nonce and large-member controls hold their contracts.
    *(
        Delegated(path, name, pattern, "scripts/pre-push-pool-test.py")
        for path, name, pattern in (
            ("scripts/pre-push-pool.py", "the fixed hexadecimal nonce width",
             r"\[0-9a-f\]\{\d+\}"),
            ("scripts/pre-push-pool-test.py", "the cancellation fixture wait in seconds",
             r"time\.sleep\(\d+\)"),
            ("scripts/pre-push-pool-test.py", "the large-member fixture block count",
             r"for _ in range\(\d+\):"),
        )
    ),
    # The W3C report corpus's per-requirement mutation tally. The file is emitted
    # by that corpus's generator and held byte-identical by the regenerability
    # gate, so every figure in its table belongs to that ledger, not this one.
    Delegated(
        "vectors-w3c-report/MUTATION-SWEEP.md",
        "the per-requirement mutation tally rows",
        r"\| `W3C-R-\d+` \| \d+ \| \d+ \| \d+ \|",
        "scripts/regenerability-gate.py",
    ),
    Delegated(
        "interop/govops-capability-id/source/jcs-admit/README.md",
        "numeric example in the exact pinned admission source",
        r"1e\+?30",
        "interop/govops-capability-id/qualify.py",
    ),
    # The pinned JEP manifest and run.py validate these separate populations.
    *(Delegated(path, "pinned JEP pilot populations", pattern,
                "interop/jep-core07-reader/run.py")
      for path, pattern in (
          (".github/workflows/jep-core07-reader.yml", r"25/4/8"),
          ("interop/jep-core07-reader/PROTOCOL.md", r"25 validation assertions"),
          ("interop/jep-core07-reader/PROTOCOL.md", r"36 covered files"),
          ("interop/jep-core07-reader/PROTOCOL.md", r"25/4/8"),
          ("interop/jep-core07-reader/README.md", r"25 validation"),
          ("interop/jep-core07-reader/run.py", r"25/4/8"),
      )),

    # These are encoding widths and JSON resource bounds, not corpus tallies.
    # The candidate's tests bind the exact prose to fixed byte answers and
    # exercise both sides of the declared depth and node budgets.
    *(
        Delegated(
            "interop/action-tuple-framed-v1/PROFILE.md",
            "the framed tuple's encoding widths and JSON resource budgets",
            pattern,
            "interop/action-tuple-framed-v1/test_reader.py",
        )
        for pattern in (
            r"Unsigned \d+-bit big-endian UTF-8 byte count",
            r"depth at most \d+ and at most [\d,]+ value nodes",
        )
    ),
    Delegated(
        "interop/action-tuple-framed-v1/test_reader.py",
        "the fixed-byte test's exact encoding-width prose check",
        r"Unsigned \d+-bit big-endian UTF-8 byte count",
        "interop/action-tuple-framed-v1/test_reader.py",
    ),
    # The optional AgentID reader bounds a JWKS input, not a vector corpus.
    # Its tests exercise the limit on both sides and read the prose cap back
    # against MAX_KEYS. Match only those bounded technical statements.
    Delegated(
        "interop/agentid-offline/README.md",
        "the AgentID reader's JWKS resource budget",
        r"Its key count is bounded at \d+",
        "interop/agentid-offline/test_reader.py",
    ),
    Delegated(
        "interop/agentid-offline/reader.py",
        "the AgentID key-selection docstring's resource budget",
        r"Select exactly one public Ed25519 verification key from at most \d+ entries",
        "interop/agentid-offline/test_reader.py",
    ),
    *(
        Delegated(
            path,
            "the AgentID JWKS cardinality diagnostic",
            r"JWKS must contain between \d+ and \d+ keys",
            "interop/agentid-offline/test_reader.py",
        )
        for path in (
            "interop/agentid-offline/reader.py",
            "interop/agentid-offline/test_reader.py",
        )
    ),
    # The action's report retention default is a number of days, not a count
    # of anything in the corpus; it equals the suiteRevision by coincidence.
    # action-retention-test.py holds the input, its default and the runner guide row.
    *(
        Delegated(path, "the action's report retention default in days", pattern,
                  "scripts/action-retention-test.py")
        for path, pattern in (
            ("docs/guides/runner.md", r"uploaded report \(default: `\d+`\)"),
            ("action.yml", r"The default, \d+, is what"),
            ("action.yml", r'default: "\d+"'),
            ("scripts/action-retention-test.py", r'OLD_DEFAULT = "\d+"'),
        )
    ),
    # A row of the accepted-complexity table is a gocyclo measurement of one Go
    # function, re-measured and gated by complexity-table-gate.py. Gate0's 36
    # collided with the seen-but-tolerated count when the forcing baseline moved.
    Delegated(
        "docs/architecture/DESIGN_DECISIONS.md",
        "the accepted-complexity table's measured values",
        r"(?m)^\| `[^`]+` `[^`]+` \| \d+ \|",
        "scripts/complexity-table-gate.py",
    ),
    # ---- the measured complexity values in the rationale table.
    # Each is what gocyclo reported for one function, and the accepted-complexity
    # gate holds them against a fresh measurement. One of them came to equal the
    # suiteRevision when the corpus grew, which is the arithmetic coincidence this
    # route exists for: the value is not a count of anything in the corpus and
    # re-deriving it here would read a second ledger for a figure another gate owns.
    Delegated(
        "docs/complexity-rationales.toml",
        "the measured complexity of each accepted function",
        r"complexity\s*=\s*\d+",
        "scripts/complexity-table-gate.py",
    ),
    Delegated(
        "docs/IMPLEMENTATION-REPORT.md",
        "the implementations table, the vendored-set cells",
        r"its\s+vendored\s+set\s+\(\d+\s+vectors\)",
        "scripts/consumer-lag-gate.py",
    ),
    Delegated(
        "docs/IMPLEMENTATION-REPORT.md",
        "note 2's vendoring sentence",
        r"each\s+vendor\s+all\s+\d+\s+vectors\s+of\s+suiteRevision\s+\d+\s+byte-for-byte",
        "scripts/consumer-lag-gate.py",
    ),
    Delegated(
        "docs/IMPLEMENTATION-REPORT.md",
        "note 2's replay sentence",
        r"and\s+replays\s+the\s+full\s+\d+\.",
        "scripts/consumer-lag-gate.py",
    ),
    Delegated(
        "docs/IMPLEMENTATION-REPORT.md",
        "note 2's opening, the revision the rails carry",
        r"\*\*The\s+consumer\s+rails\s+carry\s+the\s+suiteRevision-\d+\s+corpus\.\*\*",
        "scripts/consumer-lag-gate.py",
    ),
    Delegated(
        "docs/research/independence.md",
        "the independence section's scoping sentence",
        r"It\s+has\s+not\s+been\s+run\s+against\s+suiteRevision\s+[\d,\s]*(?:and|or)\s+\d+,",
        "scripts/independent-runs-gate.py",
    ),
    Delegated(
        "docs/IMPLEMENTATION-REPORT.md",
        "note 1's scoping sentence",
        r"The\s+checker\s+has\s+not\s+been\s+run\s+against\s+suiteRevision"
        r"\s+[\d,\s]*(?:and|or)\s+\d+,",
        "scripts/independent-runs-gate.py",
    ),
    Delegated(
        "docs/IMPLEMENTATION-REPORT.md",
        "the implementations table, the not-run enumerations",
        r"suiteRevisions\s+[\d,\s]*(?:and|or)\s+\d+\s+not\s+run\s+by",
        "scripts/independent-runs-gate.py",
    ),
    Delegated(
        "docs/IMPLEMENTATION-REPORT.md",
        "the feature-coverage paragraph's span of unread revisions",
        r"\*\*suiteRevision\s+\d+\s+through\s+\d+\*\*",
        "scripts/independent-runs-gate.py",
    ),
    # The accept-anchor measurement: how many of the conditions a refusal cites
    # are also cited by a vector that must be accepted. Both halves are derived
    # from the manifest on every run and ratcheted against
    # docs/ACCEPT-ANCHOR-BASELINE.json, so the gate that owns them is the one
    # that recomputes them rather than this census.
    Delegated(
        "vectors/CHANGES.md",
        "the accept-anchor traceability figure",
        r"That\s+second\s+number\s+is\s+\d+\s+of\s+\d+\s+today,",
        "scripts/accept-anchor-gate.py",
    ),
    Delegated(
        "vectors/CHANGES.md",
        "the accept-anchor parent-pairing figure",
        r"all\s+\d+\s+reject\s+vectors\s+declare\s+a\s+parent",
        "scripts/accept-anchor-gate.py",
    ),
    # The one-mutation relation: how many reject vectors are exactly one
    # mutation from the accept vector they declare, and how many are declared
    # to need more. Both are recomputed on every run over the committed
    # vectors, and the gate that computes them reads these two sentences back,
    # so the owner is the one that measures rather than this census.
    Delegated(
        "vectors/CHANGES.md",
        "the one-mutation figure",
        r"\*\*\d+\s+of\s+the\s+\d+\s+reject\s+vectors\s+are\s+now\s+"
        r"exactly\s+one\s+mutation\s+from\s+their\s+declared\s*\n?\s*"
        r"parent",
        "scripts/accept-anchor-gate.py",
    ),
    Delegated(
        "vectors/CHANGES.md",
        "the declared multi-mutation count",
        r"The\s+remaining\s+\d+\s+cannot\s+express\s+their\s+declared\s+"
        r"fault",
        "scripts/accept-anchor-gate.py",
    ),
)


FROZEN: tuple[Frozen, ...] = (
    Frozen(
        'DISPOSITIONS.md',
        'the JSON nesting depth bound made normative at 128',
        'The bound was made normative at 128 with its counting',
        'A protocol constant, not a count of any corpus: the I-JSON nesting depth bound, '
        'or the shell exit status offset for a signal. It met the audit record corpus '
        'total of 128 by coincidence.',
    ),
    Frozen(
        'vectors/CHANGES.md',
        'the nesting depth bound the revision 5 fix names',
        'below: with the bound at 128, no vector fails that checker',
        'A protocol constant, not a count of any corpus: the I-JSON nesting depth bound, '
        'or the shell exit status offset for a signal. It met the audit record corpus '
        'total of 128 by coincidence.',
    ),
    Frozen(
        'vectors/CHANGES.md',
        'the nesting depth bound a normative change fixed',
        'JSON nesting depth is bounded at 128, with the counting',
        'A protocol constant, not a count of any corpus: the I-JSON nesting depth bound, '
        'or the shell exit status offset for a signal. It met the audit record corpus '
        'total of 128 by coincidence.',
    ),
    Frozen(
        'vectors-spoofed-tool-output/gen_vectors.py',
        'the shell exit status of a process killed by a signal',
        'the run was killed by a signal (128 plus',
        'A protocol constant, not a count of any corpus: the I-JSON nesting depth bound, '
        'or the shell exit status offset for a signal. It met the audit record corpus '
        'total of 128 by coincidence.',
    ),
    # ---- a count from a past audit, recorded in the change history.
    Frozen(
        'vectors/CHANGES.md',
        "the number of loop sites a past audit enumerated in aee/",
        'it enumerated 53 sites in `aee/`',
        'A count of source sites an audit enumerated in the reference verifier at the time '
        'the entry was written. It is history, does not track any corpus, and met the '
        'observed-effect reject count by coincidence.',
    ),
    # ---- the output of a published, immutable release, shown as it prints.
    Frozen(
        'README.md',
        "the last line the pinned v0.19.0 package prints for its default corpus",
        'totals: 288 vectors, 288 pass, 0 fail',
        'The output of `uvx agent-evidence-vectors==0.19.0`, the release the README pins, for '
        'the suiteRevision 32 corpus that wheel ships. A published wheel does not change, so '
        'the line must match that wheel and not the corpus on main; the release that moves the '
        'pin re-records it.',
    ),
    # ---- settings and arithmetic that are not counts of anything in a corpus.
    Frozen(
        'interop/govops-capability-id/pyproject.toml',
        "the ruff line width of the govops-capability-id reader",
        'line-length = 140',
        'A formatter setting in an interop reader\'s project file. It is a line width, not a '
        'count, and met the acs-core corpus total by coincidence when that corpus reached 140.',
    ),
    Frozen(
        'scripts/pre-push-identity-scan-test.py',
        "the decode budget a nested member costs in the identity scan's test",
        '70 members need 140',
        'Arithmetic about the identity scan\'s decode cap: each nested member costs two '
        'decodes. It is not a corpus count, and met the acs-core corpus total by coincidence '
        'when that corpus reached 140.',
    ),
    # ---- an outside implementer's reported results, recorded as posted.
    Frozen(
        'RUNS.md',
        "an outside author's reported raw-path result",
        '`7a3197d`: raw 53/53, signing',
        'A result an outside implementer reported for a past run against his own case set. It '
        'records that report as posted and must not track this corpus.',
    ),
    Frozen(
        'docs/VERIFIERS.md',
        "agmi's corpus-drift job result, as its CI reported it",
        '14 of 14 answered, 0 disagreements',
        'The result an outside verifier\'s own CI job reported for the anchored-chain cases at the '
        'run the row links. It records that run and must not track this corpus.',
    ),
    Frozen(
        'RUNS.md',
        "an outside author's reported signing, verify and negative-control results",
        '57/57, verify 57/57 and negative control 53/57',
        'Results an outside implementer reported for a past run against his own case set. They '
        'record that report as posted and must not track this corpus.',
    ),
    Frozen(
        'docs/runs/observed-effect-verdict-words.md',
        "an outside reader's rerun heading, as reported",
        'Rerun at efe2dd9: 46 of 46',
        'The verdict-word result an outside implementer reported for one rerun of his reader at '
        'efe2dd9 against the observed-effect manifest. It records that run and must not track this '
        'corpus.',
    ),
    Frozen(
        'docs/runs/observed-effect-verdict-words.md',
        "an outside reader's rerun outcomes, as reported",
        '12 of 12 accepts, 46 of 46 rejects',
        'The outcomes an outside implementer reported for the same rerun at efe2dd9. They record '
        'that run and must not track this corpus.',
    ),
    # ---- integers that equal a figure of this corpus at suiteRevision 31 and
    # count something else: a file count, a date, a byte length, a pull request
    # number, or a result recorded once. Each records what it says and none of
    # them tracks the corpus.
    Frozen(
        '.github/workflows/e2-reproduction.yml',
        "the interop package's input file count",
        'hash-check all 31 inputs',
        'An integer that counts something other than this corpus and equals one of its figures by'
        ' coincidence: the number of input files the priorseal reproduction fetches.',
    ),
    Frozen(
        'interop/aps-priorseal-e2-2026-09-30/README.md',
        'the priorseal input file count, fetch step',
        'downloads the 31 files and checks',
        'An integer that counts something other than this corpus and equals one of its figures by'
        ' coincidence: the number of input files the priorseal reproduction fetches.',
    ),
    Frozen(
        'interop/aps-priorseal-e2-2026-09-30/README.md',
        'the priorseal input file count, CI step',
        'checks all 31 inputs, and',
        'An integer that counts something other than this corpus and equals one of its figures by'
        ' coincidence: the number of input files the priorseal reproduction fetches.',
    ),
    Frozen(
        'interop/aps-priorseal-e2-2026-09-30/SPEC-GAPS.md',
        'a comment number in a third-party thread',
        'aeoess (comment 31): "The fixtures',
        "An integer that counts something other than this corpus and equals one of its figures by"
        " coincidence: the number of a comment in another project's thread.",
    ),
    Frozen(
        'crosswalks/aee-to-trace-and-runtime-trace.md',
        'the date of an IETF draft, header',
        '`draft-marques-asqav-compliance-receipts-08`, dated 31 August 2026 and expiring',
        'An integer that counts something other than this corpus and equals one of its figures by'
        ' coincidence: the day of the month an IETF draft is dated.',
    ),
    Frozen(
        'crosswalks/aee-to-trace-and-runtime-trace.md',
        'the date of an IETF draft, sources',
        '`draft-marques-asqav-compliance-receipts-08`, dated 31 August 2026.',
        'An integer that counts something other than this corpus and equals one of its figures by'
        ' coincidence: the day of the month an IETF draft is dated.',
    ),
    Frozen(
        'docs/W3C-V01-CONFORMANCE-APPENDIX.md',
        'the pass count of the report written at tag v0.12.0',
        '`v0.12.0` (239 fail, 31 pass, 2 inconclusive),',
        'The breakdown of a report written against the corpus at a past tag. It describes that '
        'tag and must not track the current corpus.',
    ),
    Frozen(
        'docs/INTEROP-EVIDENCE.md',
        'the comment count of a third-party thread on the day it was read',
        'carried 48 comments and 0 reviews',
        'A count of the comments on another project\'s thread, read once on a stated day. It '
        'records that reading and equals the ACS-Core corpus total by coincidence.',
    ),
    Frozen(
        'scripts/_decoding.py',
        'the statement files in the measured identity-scan range',
        'range carrying 31 statement files',
        'The size of one commit range measured once when the decoding scan was built. It records '
        'that measurement and must not track the corpus.',
    ),
    Frozen(
        'scripts/_decoding.py',
        'the findings the measured identity-scan range produced',
        'host produced 31 findings, 20',
        'The finding count of one commit range measured once when the decoding scan was built. It'
        ' records that measurement and must not track the corpus.',
    ),
    Frozen(
        'scripts/pre-push-identity-scan.py',
        'the statement files in the measured identity-scan range',
        'carrying 31 statement files',
        'The size of one commit range measured once when the decoding scan was built. It records '
        'that measurement and must not track the corpus.',
    ),
    Frozen(
        'scripts/pre-push-identity-scan.py',
        'the findings the measured identity-scan range produced',
        'produced 31 findings, 20',
        'The finding count of one commit range measured once when the decoding scan was built. It'
        ' records that measurement and must not track the corpus.',
    ),
    Frozen(
        'scripts/pre-push-identity-scan-test.py',
        'the statement files in the measured identity-scan range',
        '31 statement files',
        'The size of one commit range measured once when the decoding scan was built. It records '
        'that measurement and must not track the corpus.',
    ),
    Frozen(
        'scripts/pre-push-identity-scan-test.py',
        'the findings the measured identity-scan range produced',
        'host produced 31',
        'The finding count of one commit range measured once when the decoding scan was built. It'
        ' records that measurement and must not track the corpus.',
    ),
    Frozen(
        'scripts/regenerability-gate.py',
        'the member count of a sibling corpus',
        'digest and all 31 identifiers',
        'The member count of a different corpus at the time a regeneration renamed its members. '
        'It records that event and must not track this corpus.',
    ),
    Frozen(
        'scripts/spec-anchor-gate-test.py',
        'the case count of a past test-directory incident',
        'whether any of the 31 cases held.',
        'The size of a test directory at the time of a past teardown fault. It records that '
        'incident and must not track the corpus.',
    ),
    Frozen(
        'docs/proposals/catalog-1-body.md',
        'a witness prefix byte length in a quoted verifier error',
        'witness prefix byte length 164 does not equal',
        'An integer that counts something other than this corpus and equals one of its figures by'
        ' coincidence: a byte length in a verifier error message quoted verbatim.',
    ),
    Frozen(
        'docs/proposals/packets/catalog-1.md',
        'a witness prefix byte length in a quoted verifier error',
        'witness prefix byte length 164 does not equal',
        'An integer that counts something other than this corpus and equals one of its figures by'
        ' coincidence: a byte length in a verifier error message quoted verbatim.',
    ),
    Frozen(
        'vectors-receipt-signature/gen_vectors.py',
        'the zero-byte length of the upstream key-seed recipe',
        "suite's recipe: 31 zero bytes and",
        'An integer that counts something other than this corpus and equals one of its figures by'
        ' coincidence: a byte length fixed by an upstream test-vector recipe.',
    ),
    Frozen(
        'vectors-receipt-signature/gen_vectors.py',
        'the zero-byte length of the upstream key seeds',
        '"31 zero bytes and',
        'An integer that counts something other than this corpus and equals one of its figures by'
        ' coincidence: a byte length fixed by an upstream test-vector recipe.',
    ),
    Frozen(
        'vectors/reject/INDEX.md',
        'the length of a truncated digest',
        'truncated to 63 hex chars; verbatim',
        "An integer that counts something other than this corpus and equals one of its figures by"
        " coincidence: the length of a digest truncated by one character, a property of SHA-256's"
        " hex form.",
    ),
    Frozen(
        'vectors/reject/gen_invalid_vectors.py',
        'the length of a truncated digest',
        'truncated to 63 hex chars; verbatim',
        "An integer that counts something other than this corpus and equals one of its figures by"
        " coincidence: the length of a digest truncated by one character, a property of SHA-256's"
        " hex form.",
    ),
    # Author-produced measurements made before CI integration. Only these exact
    # dated spans are historical; the README's live case count is derived above.
    *(
        Frozen(
            "interop/gemara-method-link/RUN.md",
            name,
            span,
            "Author-produced 2026-09-30 package at commit "
            "9bd6f42a1905c0c967c512251a280592250869d9. Original suite manifest "
            "b0cda7d30ce37f6fb48ee6778b992ffcdd8f365469c3c77f5229b02f9fb1a4c9, "
            "tests 893ddcc8dd7ff7840eb4e9620821567d36782f6e45ff8d60f6fc46372af3aa64, "
            "reader/control report manifest "
            "5448e5684565ea3c4211aa41ffe9a9998ad24c35b6ae6e42e125695e1accb70c. "
            "These figures describe that recorded run, not an independent reader.",
        )
        for name, span in (
            ("the Gemara original suite size", "Original 32-test suite manifest SHA-256"),
            ("the Gemara author reader result", "Bundled reader: 20/20 matching answers."),
            ("the Gemara self-adapter result", "Bundled reader through stdin adapter: 20/20."),
            ("the Gemara accept-all result", "Accept-all control: 3/20 matching answers, exit 1."),
            ("the Gemara original pytest result", "pytest: 32 passed."),
            ("the Gemara license-only case count", "The 20 case files, four upstream source files"),
            ("the Gemara license-only test boundary", "the 32 pytest tests were not repeated."),
        )
    ),
    # ---- three figures that came to collide with the ACS-Core reject count when
    # the sealed-session witness pair added two reject members. Each records a
    # past measurement of an unrelated thing, so the corpus growing does not
    # make any of them wrong.
    Frozen(
        ".github/workflows/ci.yml",
        "the historical unpinned-emission count in the CI comment",
        "24 unpinned emissions between them",
        "A measurement of the main corpus taken before ok-055 and bad-986 "
        "pinned their emissions. It counts emissions, not ACS-Core members.",
    ),
    Frozen(
        "docs/reference/verifier-contract.md",
        "the historical unpinned-emission count in the verifier contract",
        "counted nineteen vectors with 24 unpinned emissions",
        "The same pre-closure measurement as the CI comment, quoted in the "
        "verifier contract. It counts emissions, not ACS-Core members.",
    ),
    Frozen(
        "TODO.md",
        "the quantifier operator's taken-branch DEAD-site count",
        "and 24 of them carry",
        "A mutation-run figure for the quantifier operator: DEAD sites that "
        "carry branch: taken. It counts mutation sites, not ACS-Core members.",
    ),
    # ---- three figures that came to collide with the ACS-Core corpus when the
    # wrong-signer family grew it to 43 members and 26 rejects. Each counts
    # something else, so the corpus growing does not make any of them wrong.
    Frozen(
        "crosswalks/aee-to-ave.md",
        "the evidence-basis engine table, the pattern row",
        "| pattern | 43 |",
        "A count of AVE records citing one engine, read from another project's "
        "published corpus on a stated date. It is not a size of this corpus.",
    ),
    Frozen(
        "TODO.md",
        "the quantifier operator's DEAD-site count",
        "records 26 DEAD sites",
        "A mutation-run figure for the quantifier operator. It counts mutation "
        "sites, not ACS-Core members.",
    ),
    Frozen(
        "docs/research/independence.md",
        "the revision pair in the historical account",
        "26 and 27 in the historical account",
        "Two suiteRevision numbers of the main corpus named in a past account. "
        "They are revisions, not ACS-Core members.",
    ),
    # ---- two figures that came to collide with the ACS-Core corpus when the
    # silent-hook member grew it to 44 members and 27 rejects: a cell of the
    # AVE crosswalk and a test key's last byte. Neither is a size of this
    # corpus. The SCITT/COSE corpus size, which collided at the same time, is a
    # live count and is claimed against that corpus's manifest in
    # declared_claims rather than frozen here.
    Frozen(
        "crosswalks/aee-to-ave.md",
        "the detection-stage table, the static_detection row",
        "| static_detection | 44 |",
        "A count of AVE records at one detection stage, read from that project's "
        "published records on a stated date. It is not a size of this corpus.",
    ),
    Frozen(
        "vectors-agent-audit-record/gen_vectors.py",
        "the last byte of the agent test key",
        '"00" * 31 + "44"',
        "The final byte of a fixed Ed25519 test key in the audit-record "
        "generator. It is key material, not a count of anything.",
    ),
    # The W3C v0.1 text's own count of the delta-related pairs re-cut against it.
    # It is a figure of that text (section 10, list message 2026Sep/0087), and it
    # came to equal the audit record corpus's reject count when revision 02 of
    # that draft added six reject members; the two are unrelated.
    Frozen(
        "docs/guides/corpora.md",
        "the W3C v0.1 delta-related pair count",
        "42 delta-related pairs recut against v0.1",
        "A figure of the W3C reporting format v0.1 text, section 10 (list message "
        "2026Sep/0087): the delta-related pairs re-cut against v0.1. It records "
        "what that text says, not a count of any manifest.",
    ),
    # The section 10 split of vectors-w3c-report before v0.18.0, which our list
    # post of 7 October 2026 stated and Kenne Ives recomputed. It is what the
    # manifest at corpusDigest f00d4443... says, and it must not follow the
    # current split, which the claim in w3c_selection_claims checks.
    Frozen(
        "vectors-w3c-report/README.md",
        "the section 10 split before v0.18.0",
        "but 83 to reject and 82 to accept, at corpusDigest",
        "The split at an earlier corpusDigest, named in the sentence, and the "
        "figure posted to the W3C list on 7 October 2026. A published digest is "
        "never mutated, so its split must not track the current manifest.",
    ),
    # The section 10 split of vectors-w3c-report at v0.18.1 and v0.18.2, before
    # the prior-run binding members joined it. It is what the manifest at
    # corpusDigest f9e58e62... says, and like the split above it must not follow
    # the current one.
    Frozen(
        "vectors-w3c-report/README.md",
        "the section 10 split at v0.18.1 and v0.18.2",
        "the selection was 165 members, 41 to reject and 124 to",
        "The split at an earlier corpusDigest, named in the sentence. A published "
        "digest is never mutated, so its split must not track the current manifest.",
    ),
    Frozen(
        "vectors-agent-audit-record/README.md",
        "the first outside reader's posted score on the revision 01 corpus",
        "It agreed on 47 of 47 members of v0.16.0, the revision 01",
        "Mayur Agnihotri's run of his own reader against release v0.16.0, as he "
        "posted it in ietf-wg-wimse/draft-ietf-wimse-aims#144 (comment "
        "5934905211, 2026-10-01). The sentence names the release it was run "
        "against, and the corpus growing since does not change what that run "
        "scored; interop/wimse-agent-audit-record-reader-2026-10-01 pins it.",
    ),
    # ---- figures that came to collide with the audit record corpus when its
    # Section 5.3 write-chain members took it to 71. Each is a row count of a
    # table in the NIST AI 300-1 draft, a fixed property of that published PDF.
    Frozen(
        "interop/nist-ai-300-1/README.md",
        "the row IDs the census reads in each of the four NIST AI 300-1 tables",
        "157 IDs in the same order: 7, 8, 71 and 71",
        "The number of row IDs in Tables 1, 2, A.2.1 and A.3.1 of the NIST AI "
        "300-1 draft, read by extract.py. They are properties of that PDF and do "
        "not move with any corpus.",
    ),
    Frozen(
        "interop/nist-ai-300-1/README.md",
        "the row count of NIST AI 300-1 Table A.2.1",
        "| Table A.2.1: Default AI dataset profile | A.2 | 71 |",
        "The rows of Table A.2.1 of the NIST AI 300-1 draft, a property of that "
        "PDF, not a count of any corpus.",
    ),
    Frozen(
        "interop/nist-ai-300-1/README.md",
        "the row count of NIST AI 300-1 Table A.3.1",
        "| Table A.3.1: Default AI model profile | A.3 | 71 |",
        "The rows of Table A.3.1 of the NIST AI 300-1 draft, a property of that "
        "PDF, not a count of any corpus.",
    ),
    # This one came to collide with the ACS-Core corpus total when families
    # acs-f-18 and acs-f-19 took it to 139.
    Frozen(
        "interop/nist-ai-300-1/README.md",
        "the rules the NIST AI 300-1 manifest derives from the draft's four tables",
        "members over 139 rules",
        "The number of rules MANIFEST.json derives from the rows of Tables 1, 2, "
        "A.2.1 and A.3.1 of the NIST AI 300-1 draft, as check_vectors.py prints "
        "it. A property of that PDF's tables, not a count of any corpus.",
    ),
    Frozen(
        "interop/nist-ai-300-1/test_check_vectors.py",
        "the Table A.2.1 row count a census mutation test feeds the checker",
        "table-a.2.1 has 72 rows by its cell grid and 71 by extract.py",
        "A test fixture describing a broken census of NIST AI 300-1 Table A.2.1, "
        "whose real row count is 71. It does not move with any corpus.",
    ),
    # ---- four figures that came to collide with suiteRevision 29.
    # Each records something measured once, and none is a count of this corpus.
    # They are frozen rather than corrected because the corpus growing does not
    # change how many releases another project had published, how many agents sat
    # in a past debate, which lines a function occupies in another repository, or
    # what one historical revision of this suite contained. Rewriting any of them
    # to follow the revision would state a measurement nobody took.
    Frozen(
        "docs/SIGNING-PRECEDENT.md",
        "the survey row for sigstore-conformance, as read",
        "| sigstore/sigstore-conformance | Sigstore client conformance suite "
        "| 29 | 0 | 0 | 29 releases listed |",
        "One row of a survey of third-party repositories, recording what the "
        "release API returned on the day it was queried. The count belongs to "
        "that project and that date.",
    ),
    Frozen(
        "docs/SIGNING-PRECEDENT.md",
        "the releases each sibling conformance suite had published, as read",
        "8 and 29 of them",
        "Release counts of two third-party repositories on the day they were "
        "read. Neither tracks this corpus, and re-deriving them would require "
        "reading two projects this gate does not fetch.",
    ),
    Frozen(
        "docs/interpretation-decisions-open.md",
        "the size of the adversarial debate the direction converged from",
        "29-agent adversarial debate",
        "How many agents a past debate ran. The debate has not re-run, and the "
        "number is a fact about that pass rather than a measurement of the "
        "corpus as it stands.",
    ),
    Frozen(
        "docs/proposals/harbor-3123-regrade-from-archive.md",
        "the line range of read_artifact_manifest in the third-party repository",
        "regrade.py:191-212",
        "A line range in a citation into harbor-framework/harbor at a pinned "
        "commit. It is a location, not a count, and its upper bound coming to "
        "equal the reject count is arithmetic coincidence.",
    ),
    Frozen(
        "vectors/CHANGES.md",
        "the accept-and-reject split one historical revision replayed",
        "29 accept and 97 reject",
        "What one earlier revision of this suite contained. A published "
        "suiteRevision is never mutated in place, so its figures must not "
        "follow later growth.",
    ),
    # ---- the remap figure in the corpus changelog.
    # A changelog entry says what one pass did on the day it ran. This one
    # records that the completing pass of that revision moved 110 anchors onto
    # new line numbers, and the value collides with the reject count of
    # vectors-w3c-report purely by arithmetic coincidence. Recomputing it
    # against today's corpus would describe a remap nobody performed, which is
    # the exact substitution this route exists to refuse.
    Frozen(
        "vectors/CHANGES.md",
        "the anchors the completing pass remapped, as performed",
        "110 `Lnnn` anchors onto the new line numbers",
        "A count of what one historical pass moved, not a measurement of the "
        "corpus as it stands. The corpus has grown since; the pass has not "
        "re-run, and restating its figure against later bytes would attribute "
        "work to a pass that never saw them.",
    ),
    # ---- the nightly sweep's wall time, in the workflow that runs it.
    # The comment records one timing taken on one workstation and says it has
    # not been re-measured. Its lower bound came to equal the reject count of
    # vectors-w3c-report by arithmetic coincidence when that corpus grew; a
    # wall-clock figure is not a corpus size and must not track one.
    Frozen(
        ".github/workflows/forcing-nightly.yml",
        "the nightly sweep's wall time, as measured on one workstation",
        "137-264 seconds",
        "A timing of one sweep on one machine, recorded with the caveat that it "
        "has not been re-measured. It counts nothing this repository publishes, "
        "so it can neither be derived here nor be allowed to move when a corpus "
        "changes.",
    ),
    # ---- the disensor comparison in the W3C appendix.
    # The appendix reports what `origin/derive_pairs.py` answered on 18
    # September against a THIRD PARTY's corpus, NicolasRocchia/disensor. It is
    # not a figure about this repository and it is not derivable here: checking
    # it would mean cloning somebody else's repository from inside a gate that
    # is hermetic by design. The sentence already dates the measurement and
    # names the script, which is what the reader needs; what it must not do is
    # track this corpus. The appendix is generated, so the same sentence is
    # declared twice -- once where a reader meets it and once in the generator
    # that emits it -- and each is asserted at one occurrence, so a third copy
    # appearing anywhere fails here.
    Frozen(
        "docs/W3C-V01-CONFORMANCE-APPENDIX.md",
        "the disensor disagreement figure, as re-derived on 18 September",
        "0 vectors disagreeing with their declared expectation",
        "One run of a named script against an external corpus on a stated date. "
        "It measures NicolasRocchia/disensor and nothing this repository "
        "publishes, so it can neither be derived here nor be allowed to move "
        "when this corpus changes.",
    ),
    # The reject entries carrying expected.codes at tag v0.11.1: a count over
    # eight manifests at a past tag, re-derivable from that tag by the command
    # the sentence prints. It equals the W3C corpus total by coincidence since
    # the integer -0 pair took that corpus to 269 members.
    Frozen(
        "docs/W3C-V01-CONFORMANCE-APPENDIX.md",
        "the expected.codes count at tag v0.11.1",
        "315 reject entries across the eight manifests of `agent-evidence-vectors` at tag "
        "`v0.11.1`, 269 carry",
        "A count over the manifests at a past tag, re-derived from that tag by the command the "
        "sentence prints. It describes v0.11.1 and must not track the current corpus.",
    ),
    Frozen(
        "scripts/gen-w3c-appendix.py",
        "the expected.codes count at tag v0.11.1, in the appendix generator",
        "315 reject entries across the eight manifests of `agent-evidence-vectors` at tag "
        "`v0.11.1`, 269 carry",
        "The generator source of the appendix sentence above, frozen for the same reason and "
        "asserted separately so the two cannot drift apart without one of them failing.",
    ),
    Frozen(
        "scripts/gen-w3c-appendix.py",
        "the disensor disagreement figure in the appendix generator",
        "0 vectors disagreeing with their declared expectation",
        "The generator source of the appendix sentence above, frozen for the "
        "same reason and asserted separately so the two cannot drift apart "
        "without one of them failing.",
    ),
    # ---- the figures a posted outside run carried, transcribed into RUNS.md.
    # A run figure records what somebody else's build answered on the day it
    # ran, against the corpus as it then stood. It must NOT track this corpus:
    # rewriting one when the corpus grows would describe a rerun nobody
    # performed, and the whole value of the independence column is that it says
    # what was actually posted. docs/INDEPENDENT-RUNS.json is the gated ledger
    # for the same runs; these declarations cover the reader-facing scoreboard.
    Frozen(
        "RUNS.md",
        "the a2a-jcs-v01 raw canonicaliser score",
        "53/53, target `rfc8785`",
        (
            "A path score an outside implementation posted for the a2a-jcs-v01 corpus, "
            "which lives in a2aproject/a2a-tck and not here, at corpus commit 97b0072. "
            "Its denominator is that corpus's size, not any corpus in this tree, and "
            "it records one past run of one commit."
        ),
    ),
    Frozen(
        "RUNS.md",
        "the a2a-jcs-v01 card signing score",
        "| 57/57, target `card-signing-input` |",
        (
            "A path score an outside implementation posted for the a2a-jcs-v01 corpus, "
            "which lives in a2aproject/a2a-tck and not here, at corpus commit 97b0072. "
            "Its denominator is that corpus's size, not any corpus in this tree, and "
            "it records one past run of one commit."
        ),
    ),
    Frozen(
        "RUNS.md",
        "the a2a-jcs-v01 card verify score",
        "57/57, target `card-signing-input`, refusal class",
        (
            "A path score an outside implementation posted for the a2a-jcs-v01 corpus, "
            "which lives in a2aproject/a2a-tck and not here, at corpus commit 97b0072. "
            "Its denominator is that corpus's size, not any corpus in this tree, and "
            "it records one past run of one commit."
        ),
    ),
    Frozen(
        "RUNS.md",
        "the a2a-jcs-v01 verify score before the fix, narrow class",
        "then scored 52/57",
        (
            "A path score an outside implementation posted for the a2a-jcs-v01 corpus, "
            "which lives in a2aproject/a2a-tck and not here, at corpus commit 97b0072. "
            "Its denominator is that corpus's size, not any corpus in this tree, and "
            "it records one past run of one commit."
        ),
    ),
    Frozen(
        "RUNS.md",
        "the agent audit record corpus size an outside reader ran",
        "at release 0.16.0, 47 members, corpus digest",
        (
            "The size of vectors-agent-audit-record at release 0.16.0, pinned by its "
            "corpus digest, as an outside reader ran it on 2026-10-01. It records one "
            "past run of one release and does not track the corpus as it grows."
        ),
    ),
    Frozen(
        "RUNS.md",
        "the agent audit record outside run score",
        "47 of 47 agree: 9 accept members valid, 36 reject members malformed",
        (
            "The score an outside reader posted for vectors-agent-audit-record at "
            "release 0.16.0. It records one past run of one release, and its figures "
            "are that release's counts, not the corpus as it grows."
        ),
    ),
    Frozen(
        "RUNS.md",
        "the a2a-jcs-v01 verify score before the fix, ValueError",
        "it scored 54/57",
        (
            "A path score an outside implementation posted for the a2a-jcs-v01 corpus, "
            "which lives in a2aproject/a2a-tck and not here, at corpus commit 97b0072. "
            "Its denominator is that corpus's size, not any corpus in this tree, and "
            "it records one past run of one commit."
        ),
    ),
    Frozen(
        "RUNS.md",
        "the a2a-jcs-v01 verify score rescored with the narrow class",
        "gives 57/57 on the verify path",
        (
            "A path score an outside implementation posted for the a2a-jcs-v01 corpus, "
            "which lives in a2aproject/a2a-tck and not here, at corpus commit 97b0072. "
            "Its denominator is that corpus's size, not any corpus in this tree, and "
            "it records one past run of one commit."
        ),
    ),
    Frozen(
        "RUNS.md",
        "the a2a-jcs-v01 verify score of the parent commit",
        "and 52/57",
        (
            "A path score an outside implementation posted for the a2a-jcs-v01 corpus, "
            "which lives in a2aproject/a2a-tck and not here, at corpus commit 97b0072. "
            "Its denominator is that corpus's size, not any corpus in this tree, and "
            "it records one past run of one commit."
        ),
    ),
    Frozen(
        "RUNS.md",
        "the suiteRevision-28 run's per-outcome figures, as posted",
        "61/61 accepts, 209/209 rejects, 2/2 indeterminate",
        "The outcome split an outside verifier posted against suiteRevision 28 "
        "(its own index says revision 27) at Rul1an/aee-checker#21. Frozen to "
        "that run: the accept and reject "
        "totals equal the corpus's own at the time, which is the collision this "
        "census exists to surface, and restating either against a later corpus "
        "would attribute a run to bytes it never saw.",
    ),
    Frozen(
        "RUNS.md",
        "the moltrust-api author's four reported results, as posted on A2A#1882",
        "raw 53/53, signing 57/57, verify 57/57 and negative control 53/57",
        "Results an outside author reported for his own runner on two named "
        "corpus states. They record a past run of another project's code and "
        "must not track this corpus.",
    ),
    Frozen(
        "RUNS.md",
        "the suiteRevision-28 run's reason-parity figure, as posted",
        "80/209",
        "A reason-parity figure its own author reports and declines to promote. "
        "It is not verdict parity and not a corpus size; it is one measurement "
        "of one build against one revision.",
    ),
    Frozen(
        "RUNS.md",
        "the revision the outside run was measured on",
        "| suiteRevision | 28, which the checker's own index labels revision 27",
        "The corpus revision at the suite commit the run pinned, read from that "
        "commit's CHANGES.md, beside the checker's own label for the same run. It "
        "records a past run and must not track the corpus.",
    ),
    Frozen(
        "RUNS.md",
        "the reporter's own sentence about what the frozen build spanned",
        "250 \u2192 272 vectors",
        "A quotation, transcribed verbatim from the posting. The corpus sizes "
        "in it are the endpoints of the advance he measured across, not a claim "
        "about the corpus as it now stands, and editing a quoted sentence to "
        "track a later corpus would misquote him.",
    ),
    Frozen(
        "docs/research/external-records.md",
        "the independent Rust verifier's score, as posted",
        "scores 272/272 on suiteRevision 28",
        "What one outside build answered against suiteRevision 28, which its own "
        "index labels revision 27, with its author recording that the build was "
        "frozen before the corpus moved. The revision is named in the same "
        "sentence, so the figure is readable against the corpus it was measured "
        "on rather than against this one.",
    ),
    Frozen(
        "docs/research/external-records.md",
        "the blind RFC 8785 run's figures, as posted",
        "ran the 57 RFC 8785 vectors blind against argentum-core before opening "
        "the generators: 57/57",
        "A blind outside run of the RFC 8785 canonicalization vectors as that "
        "set stood when it was run. Both the set size and the score belong to "
        "that run; tracking either against a later corpus would describe a "
        "rerun nobody performed and would destroy what blind means here.",
    ),
    Frozen(
        "docs/research/external-records.md",
        "the reproduction figure an outside maintainer posted, as posted",
        "recorded 258/258 in his own repository",
        "What the VATE maintainer's own regeneration answered on the day he ran "
        "it, against the corpus as it then stood, transcribed into the adoption "
        "block. Its denominator is that day's corpus, not this one: restating it "
        "against a later corpus would attribute a rerun to somebody who never "
        "performed one, which is the whole point of quoting an outside run.",
    ),
    Frozen(
        "vectors-aci/FINDINGS.md",
        "the compliance score the ACI specification asks a reference implementation for",
        "Pass ACI Validator checks with a score of 100/100",
        "A figure inside a verbatim quotation of another specification's own "
        "conformance requirement. Its denominator is that specification's "
        "scoring scheme, which no section of it defines, and that missing "
        "definition is the finding the sentence exists to report. Deriving it "
        "from anything here would make their unstated arithmetic look like ours.",
    ),
    Frozen(
        "vectors-aci/FINDINGS.md",
        "the line range where the ACI validator's undocumented arithmetic lives",
        "238-258 for a manifest and 304-311 for the deployment",
        "A line-range citation into another project's source file, not a count. "
        "The second endpoint happens to equal a rule tally here, which is what "
        "brought it to the census; it names a position in somebody else's code "
        "and tracks their file rather than any quantity of ours.",
    ),
    Frozen(
        "vectors-aci/FINDINGS.md",
        "the ACI example manifests a strict date reading rejects",
        "rejects 18 of 18",
        "A measurement of another repository's example files, taken on the day "
        "they were read. Their example count is theirs to change, and rewriting "
        "this when a corpus here grows would restate their tree as ours.",
    ),
    Frozen(
        "docs/HELD-OUT-CONFORMANCE.md",
        "the quoted 19-of-19 lookup-table score from the upstream premortem",
        "scored 19/19 and exited 0",
        "A figure inside a verbatim quotation of somebody else's premortem, "
        "recording what a discard-everything adapter scored against their suite "
        "on the day they ran it. It is not a count of anything in this "
        "repository and its denominator is their corpus, so deriving it here "
        "would restate their past run as our present one.",
    ),
    Frozen(
        "vectors/CHANGES.md",
        "the suiteRevision-18 citation remap tally",
        "moved 28 `spec:NNN`",
        "A count of citations remapped when the specification was re-vendored, "
        "recorded at suiteRevision 18. It collided with the corpus's own "
        "revision number the moment that number reached 28, which is the "
        "collision this census exists to surface. Declared rather than "
        "rewritten: rewriting it would restate a past run as a present one.",
    ),
    # ---- measurements taken while building the reading-differential harness,
    # the uncited-obligation sweep and the expectation-slack gate. Every one of
    # these records what a run produced on the day it ran. The corpus has since
    # grown to the value several of them happen to contain, which is the
    # collision this census exists to surface and the reason each is declared
    # rather than rewritten: rewriting a figure when the corpus grows would be
    # inventing a rerun nobody performed.
    Frozen(
        "vectors/CHANGES.md",
        "the suiteRevision-15 mutation campaign's byte-identical tally",
        "316 were killed, 250 were",
        "A mutation tally, not a corpus size. It became visible the moment the "
        "corpus itself reached 250, which is the same collision recorded above "
        "for a complexity reading at suiteRevision 15.",
    ),
    Frozen(
        "vectors/CHANGES.md",
        "the suiteRevision-12 re-mint tally of vectors with no record identity",
        "32 carry no decodable record identity",
        "What one re-mint left byte-identical at suiteRevision 12, not a "
        "property of the corpus as it now stands. It collided with the "
        "seen-but-tolerated count when the quantifier operator joined the "
        "campaign and moved that tally to 32. Rewriting it to the current "
        "figure would describe a re-mint nobody performed.",
    ),
    Frozen(
        "scripts/condition-forcing-gate-test.py",
        "the fixture quoting that tally",
        "316 were killed, 250 were",
        "The test pins the sentence above verbatim, so the figure is the same "
        "past measurement read a second time rather than a second claim.",
        occurrences=2,
    ),
    Frozen(
        "scripts/reading-differential.py",
        "the review revisions the missing instrument was found across",
        "revisions 2, 8, 13 and 25",
        "Revision identifiers, not a count. The last of them equals the current "
        "suiteRevision because the review and the corpus advanced together.",
    ),
    Frozen(
        "scripts/reading-differential.py",
        "the corpus size when a masked reading read as settled",
        "248 of 248",
        "The measurement that motivated the harness, taken before bad-1017 and "
        "ok-054 existed. Restating it against the corpus as it now stands would "
        "describe a run that never happened.",
    ),
    Frozen(
        "scripts/reading-differential.py",
        "the driver-edit measurement",
        "195 of 250",
        "A recorded attack result: an edit outside the rail moved this many "
        "vectors and scored REPORT-ONLY, which is why an edit outside the rail "
        "is now refused.",
    ),
    Frozen(
        "scripts/reading-differential-test.py",
        "the same driver-edit measurement, in the case that pins it",
        "195 of 250",
        "The test asserts the behaviour the figure above records, so the number "
        "is one measurement cited twice rather than two claims.",
    ),
    Frozen(
        "spec/READINGS.toml",
        "the same driver-edit measurement, in the ledger comment",
        "195 of 250",
        "The ledger explains beside the readings why an edit outside the rail is "
        "not a reading, and cites the measurement that established it.",
    ),
    Frozen(
        "scripts/expectation-slack-gate.py",
        "the replay that stayed green under the widening edit",
        "250 of 250",
        "The record of an attack: widening an expectation left every verdict "
        "green while destroying the property one vector exists for. The figure "
        "is what the replay reported at that moment.",
    ),
    Frozen(
        "scripts/uncited-obligations-proof.py",
        "what the ratchet measured while its row reader was dead",
        "32 of the 46 cited obligations",
        "A reading taken of the BROKEN reader, not of the corpus: the row "
        "selector named identifiers that had stopped matching, so the ratchet "
        "saw the condition registry alone. The figure records what a run "
        "produced before the reader was fixed, and rewriting it when the corpus "
        "grows would restate a past run as a present one. The second half is a "
        "live quantity the ratchet prints on every run.",
    ),
    Frozen(
        "scripts/uncited-obligations-proof.py",
        "the coverage measurement this work moved",
        "55 obligations cited to 57",
        "A before-and-after reading of obligation coverage. The first figure "
        "equals the accept-vector count by coincidence and is not a corpus "
        "quantity.",
    ),
    Frozen(
        "scripts/uncited-obligations-proof-test.py",
        "the same coverage measurement, restated in the test's docstring",
        "to 57 while the anchor gate",
        "The second figure of the before-and-after coverage reading frozen "
        "above, as the test that pins it restates it. An obligation count, "
        "equal to the observed-effect corpus total only by coincidence.",
    ),
    Frozen(
        "spec/CITATION-MIGRATION.md",
        "the anchor count the citation migration produced",
        "119 citation sites migrated, 57 anchors",
        "A count of specification anchors at the migration revision named in "
        "the same document. It is not a size of any corpus and equals the "
        "observed-effect corpus total only by coincidence.",
    ),
    Frozen(
        "scripts/uncited-obligations-proof.py",
        "the replay taken beside that measurement",
        "250 of 250 green",
        "The corpus replay recorded alongside the coverage figure above.",
    ),
    Frozen(
        "scripts/uncited-obligations-proof-test.py",
        "the same coverage measurement, in the case that pins it",
        "55 obligations cited",
        "The test asserts the movement the figure above records.",
    ),
    Frozen(
        "docs/UNCITED-OBLIGATIONS.md",
        "the coverage measurement this work moved",
        "rose from 55 obligations cited to 57",
        "The prose record of the same before-and-after reading the proof script carries.",
    ),
    Frozen(
        "docs/UNCITED-OBLIGATIONS.md",
        "the replay taken beside that measurement",
        "both rails ran 250 of 250 green",
        "The corpus replay recorded alongside the coverage figure above.",
    ),
    Frozen(
        "docs/UNCITED-OBLIGATIONS.md",
        "the condition-span measurement behind the reverse question",
        "62 of\n98 condition-registry spans",
        "A measurement of how many condition spans contain no RFC 2119 sentence. "
        "Its denominator counts registry spans, not vectors.",
    ),
    Frozen(
        "docs/UNCITED-OBLIGATIONS.md",
        "the coverage reading at the time of writing",
        "55 of 67 obligations and 2 of 7",
        "The state of the measurement when this document was written. The gate "
        "prints the current figures on every run, which is where a reader goes "
        "for today's numbers.",
    ),
    Frozen(
        "scripts/complexity-table-gate.py",
        "the drift incident's Go-side measurement",
        "``evaluateKind`` from 24 to 28",
        "A gocyclo reading taken at suiteRevision 15, not a claim about the corpus. "
        "It became visible only when the revision counter reached the same value, "
        "which is the collision the MASKS note above already records happening at "
        "suiteRevision 20: a digit that names a complexity, read as a count because "
        "a published quantity happened to equal it.",
    ),
    Frozen(
        "scripts/complexity-table-gate.py",
        "the drift incident's other Go-side measurement",
        "grew from 33 to 34",
        "The same gocyclo reading at suiteRevision 15, for Gate0. It surfaced when "
        "the AI generation corpus was registered with a total that happens to equal "
        "the second figure, the collision the entry above describes, arriving "
        "through a corpus total instead of the revision counter.",
    ),
    # ---- 38, the AI generation corpus total after revision 0.1.4 added the
    # four upstream-signed members. Each integer below is a complexity reading or
    # a leaf count that happens to equal it, the same collision the 34 entries
    # above record, arriving through a corpus total a second time.
    Frozen(
        ".golangci.yml",
        "the gocyclo ceiling the linter's own message is phrased against",
        "means the build fails at 38",
        "A linter threshold: gocyclo reports strictly above 37, so 38 is the first "
        "failing complexity. It counts branches in one function and was written "
        "before the AI generation corpus reached the same total.",
    ),
    Frozen(
        "scripts/complexity-table-gate.py",
        "the drift incident's reading for verify",
        "``verify`` grew from 38 to 45",
        "The same gocyclo drift incident as the entries above, for verify. It "
        "surfaced when the AI generation corpus total reached 38.",
    ),
    Frozen(
        "scripts/complexity-table-gate.py",
        "the example table row the complexity parser reads",
        "its `complexity = 38`",
        "An example of the complexity table's TOML shape in a parser comment. The "
        "number is a recorded complexity, not a corpus size.",
    ),
    Frozen(
        "vectors/reject/gen_invalid_vectors.py",
        "the leaf count of one reject member's control pair",
        "38 leaves compared",
        "How many leaves one shipped pair of reject vectors has, which the "
        "comment uses to show the pair differs in exactly one. It is a property "
        "of that member, not of the AI generation corpus.",
    ),
    Frozen(
        "docs/reference/verifier-contract.md",
        "the external-rail contract, the shipped CLI's score",
        "it scored 0 of 186.",
        "An incident record. The CLI scored zero against the corpus as it stood, and "
        "a figure that tracked the corpus would be inventing a rerun nobody did.",
    ),
    Frozen(
        ".github/workflows/ci.yml",
        "the external-rail step's note",
        "186 the first time anybody tried",
        "The same incident, recorded where the step that now prevents it runs.",
    ),
    Frozen(
        ".github/workflows/ci.yml",
        "the forcing-test step's note",
        "scored 0 of 186 while its unit test passed",
        "The same incident, cited as the reason a gate's own tests assert refusals.",
    ),
    Frozen(
        "crosswalks/aee-to-ave.md",
        "the evidence-basis table's semgrep row",
        "| semgrep | 52 |",
        "A reading of ANOTHER project's corpus, taken on the date the document "
        "states, and it collides with this suite's accept count only by "
        "coincidence. Tracking it to the accept count would rewrite a fact "
        "about 59 AVE records into a fact about these vectors.",
    ),
    Frozen(
        "crosswalks/aee-to-ave.md",
        "the opening line's AVE record count",
        "against AVE's 59 published records",
        "A count of AVE's published records, read on the date the document "
        "states. It equals the observed-effect corpus total only by "
        "coincidence and must not track it.",
    ),
    Frozen(
        "crosswalks/aee-to-ave.md",
        "the counting note's AVE record count",
        "derived from the 59 records in the records directory",
        "A count of AVE's published records, read on the date the document "
        "states. It equals the observed-effect corpus total only by "
        "coincidence and must not track it.",
    ),
    Frozen(
        "crosswalks/aee-to-ave.md",
        "the provenance paragraph's AVE record count",
        "on 2026-07-28, 59 in total",
        "A count of AVE's published records, read on the date the document "
        "states. It equals the observed-effect corpus total only by "
        "coincidence and must not track it.",
    ),
    Frozen(
        "crosswalks/aee-to-ave.md",
        "the provenance paragraph's upstream tree size",
        "carried a 59-record tree",
        "A count of AVE's published records, read on the date the document "
        "states. It equals the observed-effect corpus total only by "
        "coincidence and must not track it.",
    ),
    Frozen(
        "crosswalks/aee-to-owasp-and-atlas.md",
        "the provenance note's AVE corpus size",
        "derive from the same 59-record corpus",
        "A count of AVE's published records, read on the date the document "
        "states. It equals the observed-effect corpus total only by "
        "coincidence and must not track it.",
    ),
    Frozen(
        "scripts/crosswalk-gen.py",
        "the docstring's account of the old record_count",
        "`record_count: 59`",
        "A count of AVE's published records, read on the date the document "
        "states. It equals the observed-effect corpus total only by "
        "coincidence and must not track it.",
    ),
    Frozen(
        "vectors/CHANGES.md",
        "suiteRevision 15's mutation-campaign tally",
        "19 were seen and tolerated",
        "The result of a campaign run against a corpus of 179 vectors, recorded "
        "in the revision section that reports it. It equals the current "
        "suiteRevision by coincidence and must not follow it.",
    ),
    Frozen(
        "cmd/aee-verify/main.go",
        "the -json flag's comment",
        "scored 0 of 186 against the corpus it ships",
        "The same incident, recorded at the line that caused it.",
    ),
    Frozen(
        "cmd/aee-verify/main_test.go",
        "the machine-readable-output test's comment",
        "while scoring 0 of 186 as an",
        "The same incident, recorded at the test that did not catch it.",
    ),
    Frozen(
        "scripts/external-rail-gate.py",
        "the gate's own reason for existing",
        "the shipped CLI scored 0 of 186:",
        "The same incident. This gate exists because of it.",
    ),
    Frozen(
        "scripts/external-rail-gate.py",
        "the refusal message's account of the incident",
        "how the shipped CLI came to score 0 of 186 unnoticed.",
        "The same incident, quoted to whoever trips this gate.",
    ),
    Frozen(
        "scripts/forcing-gate-test.py",
        "the list of checks that could not fail",
        "scored 0 of 186 while its own unit test",
        "The same incident, cited among the checks that ran green while enforcing nothing.",
    ),
    Frozen(
        "docs/interpretation-decisions-open.md",
        "the coverage-partition decision's parity note",
        "so 134/134 parity was intact",
        "A parity figure at the revision the divergence was found, not a corpus size.",
    ),
    Frozen(
        "crosswalks/aee-to-ave.md",
        "the stage/layer correlation in the AVE corpus",
        "37 of 44 static records are content",
        "A count of the AVE crosswalk corpus read on a stated date, not of this "
        "corpus. Its source is another project's published records.",
    ),
    Frozen(
        "crosswalks/aee-to-ave.md",
        "the evidence-basis engine table, the llm row",
        "| llm | 25 |",
        "A count of AVE records citing one engine, read from another project's "
        "published corpus on a stated date. It is not a size of this corpus and "
        "collides with the current suiteRevision only by coincidence.",
    ),
    Frozen(
        "scripts/consumer-lag-gate.py",
        "the two remembered lags",
        "two rails sat at 140 vectors while this repository published 149",
        "The lag as it was measured. Both figures are sizes this corpus has had, and "
        "moving either would erase the event that made this gate necessary.",
    ),
    Frozen(
        "docs/HELD-OUT-CONFORMANCE.md",
        "the external-witness-basis measurement quoted from another project's tracker",
        "puts 132 of 132 enforcement obligations at no external witness basis",
        "A count of another specification's obligations, measured against that "
        "specification on the day it was measured. It says nothing about the size "
        "of any corpus here, and rewriting it when a corpus grows would restate "
        "somebody else's reading of somebody else's document.",
    ),
    Frozen(
        "docs/HELD-OUT-CONFORMANCE.md",
        "the lookup-table measurement quoted from another project's issue tracker",
        "scored 19 of 19 against a published suite and exited 0",
        "A score another project recorded against its own suite on the day it "
        "ran it. It is quoted as the evidence the design answers, and it is not "
        "a measurement of anything here; rewriting it when this repository's "
        "corpus changes size would restate somebody else's past run.",
    ),
    Frozen(
        "docs/INTEROP-EVIDENCE.md",
        "the honest form of a figure, quoted verbatim from the record that published it",
        '"24 vectors, 0 hard failures"',
        "Another project's own sentence about its own run, quoted because the "
        "criterion turns on the difference between that wording and the whole "
        "numerator a table carried instead. Both figures belong to that record "
        "and to the day it ran; neither counts anything here.",
    ),
    Frozen(
        "scripts/condition-forcing-crosscheck.py",
        "the reconciliation sentence this gate matches, quoted in its own comment",
        "316 in the released note + 12 killed only by vectors added",
        "The reconciliation the crosscheck asserts, quoted so a reader of the "
        "regex can see the sentence it is matching. Both figures record what one "
        "campaign found on the day it ran, and one of them collided with the "
        "accept count of a corpus registered afterwards. Rewriting either when a "
        "different corpus grows would restate a past run as a present one.",
    ),
    Frozen(
        "TODO.md",
        "the quantifier-operator entry, the universals LOOP_FIRST found",
        "found 31 universals this corpus does not force as universals",
        "What one mutation operator found on the day it was written, in a row "
        "that is still open for the cases it does not cover. It collided with "
        "the size of a corpus registered afterwards, which is the collision this "
        "census exists to surface; rewriting it when a different corpus grows "
        "would restate a past run as a present one.",
    ),
    Frozen(
        "TODO.md",
        "the forcing-measurement entry, what a full replay reported",
        "the suite still reports 186 of 186, exit 0. `cmd/mutgen` enumerates 590 single-site",
        "A dated completed-work entry. The figures are the measurement as it stood "
        "when the work landed.",
    ),
    Frozen(
        "TODO.md",
        "the forcing-measurement entry, the baseline it wrote",
        "331 KILLED, 17 SILENT, 237 DEAD, 5 INCONCLUSIVE.",
        "The same dated entry: the baseline as written, not as it stands.",
    ),
    Frozen(
        "docs/research/corpus-measurements.md",
        "the condition-registry section's account of the unresolvable ids",
        "so 17 ids cited by accept vectors",
        "A count of condition ids that resolved to nothing before the registry was "
        "widened, and a past defect rather than a live quantity. Its collision with "
        "a forcing outcome is a coincidence of value, not of meaning.",
    ),
    Frozen(
        "vectors/reject/INDEX.md",
        "the condition-registry paragraph's account of the unresolvable ids",
        "which left 17 ids cited by vectors and resolvable",
        "The same past defect, recorded in the registry it was found in.",
    ),
    Frozen(
        ".github/workflows/ci.yml",
        "the condition-registry step's note",
        "# 17 ids were cited by live vectors and registered nowhere",
        "The same past defect, recorded at the step that now reconciles both directions.",
    ),
    Frozen(
        "scripts/condition-registry-gate.py",
        "the gate's account of the ids that resolved nowhere",
        "registered nowhere: 17 of them",
        "The same past defect. This gate exists because of it.",
    ),
    Frozen(
        "vectors/reject/gen_invalid_vectors.py",
        "the generated registry paragraph's account of the unresolvable ids",
        'which left 17 ids cited by vectors and resolvable"',
        "The same past defect, in the generator that emits the sentence into the reject index.",
    ),
    Frozen(
        "vectors/CHANGES.md",
        "the suiteRevision-15 entry's account of the first mutation measurement",
        "590 single-site weakening changes across every rail file",
        "A changelog entry. The sweep was that size when the measurement was run, "
        "and a published revision is never mutated in place.",
    ),
    Frozen(
        "TODO.md",
        "the completed CI-label correction",
        "Correct the CI vector-replay label 138 -> 140",
        "A dated completed-work entry naming the edit it made.",
    ),
    Frozen(
        "scripts/condition-forcing-gate.py",
        "the reconstruction comment's account of the superseded projection",
        "24 of 78 conditions weak",
        "The projection as it was quoted, over a corpus the working tree no longer "
        "holds. The whole point of the code beneath this comment is that the figure "
        "is reconstructed rather than remembered, so tracking it to the corpus would "
        "erase the number the reconstruction exists to check itself against.",
    ),
    Frozen(
        "CODE_OF_CONDUCT.md",
        "the Contributor Covenant's own canonical URL path segment",
        "2/1",
        "Not a ratio. The Contributor Covenant publishes its version 2.1 text at a "
        "URL whose path literally reads /version/2/1/code_of_conduct.html; the "
        "digits name that document's own version number, external to this "
        "repository and outside anything the corpus could grow to collide with. "
        "The URL appears twice in this file (inline, then as the reference-link "
        "definition it resolves to), both copies verbatim from the upstream text.",
        occurrences=2,
    ),
    # ---- the two synthetic figures in the independence gate's own self-test.
    # A gate's self-test feeds it fixed input and asserts what it answers. These
    # two are that input: a score on a fabricated attempt, and a sentence the test
    # appends to a temporary file to check that a figure can attach to an attempt
    # through prose alone. Neither is a measurement of any corpus, and both must
    # stay exactly what they are: a fixture that tracked the corpus would change
    # what the test means every time the corpus grew, which is the one thing a
    # test's input may never do. They are ratio-shaped because the parser under
    # test only reads ratios, so the census sees a denominator and asks -- rightly,
    # since it cannot tell a fixture from a claim, and this is the answer.
    Frozen(
        "scripts/independent-runs-gate-test.py",
        "the fabricated score on the synthetic attempt",
        '"figure": "9/9", "role": "score"',
        "Input to a self-test, not a figure about a corpus. The gate asserts that "
        "this value attaches to the attempt it is given; deriving it from the "
        "corpus would make the assertion move with bytes the test never reads.",
    ),
    Frozen(
        "scripts/independent-runs-gate-test.py",
        "the synthetic prose sentence the attachment case appends",
        "The contained dispatch at actions/runs/35194072925 returned 9/9.",
        "The one sentence the prose-attachment case writes into a temporary file, "
        "naming a dispatch and a score together. It is the input that proves the "
        "prose path works and describes no run of this corpus.",
    ),
    # ---- what the OLD size cap did, in the scanner test that raised it.
    # The sentence explains why a cap sized against one envelope per input became
    # a cap on members once the same bytes were repacked as a corpus, and it
    # reports what the old cap reached. That is a past behaviour of a retired
    # constant, not a measurement of anything present: re-deriving it against the
    # current cap would describe a run nobody made and delete the reason the cap
    # was raised.
    Frozen(
        "scripts/pre-push-identity-scan-test.py",
        "what the retired size cap reached before it was raised",
        "this reaches 64 of 70 and fails",
        "A past behaviour of a cap that no longer ships. The figure explains why "
        "the constant was raised; tracking it to the present would erase that.",
    ),
    # ---- two integers whose context does not say whether they count or measure.
    # MEASURES takes an integer out of the census only where its own syntax says
    # it measures, and these two say it only through the sentence before them, so
    # the census refuses them, as it should, the day a corpus reaches 64, until
    # something accounts for them.
    Frozen(
        "scripts/_decoding.py",
        "what the retired item cap reported over a 100-envelope corpus",
        "reported 64 of its 100\n# hosts",
        "A measurement taken once, at a cap of 128 items that no longer ships: how "
        "many hosts the decoder reported before it stopped looking. It counts hosts "
        "in a staged input, not members of any corpus here.",
    ),
    Frozen(
        "spec/README.md",
        "the length of a full anchor digest",
        "`CITATION-ANCHORS.json` carries the full 64",
        "The length in hex characters of a full SHA-256 anchor digest, named by the "
        "sentence before it, which gives the inline form's 16. It is a property of "
        "SHA-256, not a count of anything in a corpus.",
    ),
    # ---- the number-family page. The one figure on it that is not a vector id
    # is a property of RFC 8785's own Appendix B table, so it does not track any
    # corpus here.
    Frozen(
        "docs/NUMBER-FAMILY-BALANCE.md",
        "the size of RFC 8785's Appendix B Table 1, as the family quotes it",
        "holds the 24 rows of Appendix B",
        "The number of Appendix B Table 1 rows that have a JSON representation, "
        "one vector each. It is a property of the RFC's own table rather than of "
        "any corpus here, and the family exists to carry exactly that table.",
    ),
    Frozen(
        'packaging/agent_evidence_vectors/w3cintake.py',
        "the objection window of the group's process, in hours",
        'the 48-hour objection window that followed it',
        "A duration in the W3C group's own process, in hours. It counts nothing"
        ' in this corpus and equals its total only by coincidence.',
    ),
    Frozen(
        'packaging/agent_evidence_vectors/w3cintake.py',
        'the criterion number the exit-rule field answers',
        '``exit-rule`` (criterion 4)',
        "A criterion number in the group's published intake criteria. It names "
        'a criterion and counts nothing in this corpus.',
    ),
    Frozen(
        'packaging/agent_evidence_vectors/w3cintake.py',
        'the criterion and delta numbers a docstring cites',
        'Criterion 4 and delta 5: each refusal',
        "A criterion number and a delta number from the group's published "
        'intake criteria. They name text and count nothing in this corpus.',
    ),
    Frozen(
        'scripts/gen-intake-records.py',
        "the independent reader's verdict count for the receipt-signature corpus",
        '25/25 verdicts agree',
        'A result the independent reader recorded for a past run against the '
        'release the record names. It records that run as reported and must not'
        ' track this corpus.',
    ),
    Frozen(
        'scripts/gen-intake-records.py',
        "the independent reader's verdict count for the main corpus",
        '285/285 verdicts agree',
        'A result the independent reader recorded for a past run against the '
        'release the record names. It records that run as reported and must not'
        ' track this corpus.',
    ),
    Frozen(
        'scripts/gen-intake-records.py',
        "the independent reader's verdict count for the W3C report corpus",
        '235/235 verdicts agree',
        'A result the independent reader recorded for a past run against the '
        'release the record names. It records that run as reported and must not'
        ' track this corpus.',
    ),
    Frozen(
        'scripts/gen-intake-records.py',
        "the independent reader's verdict count for the anchored-chain corpus",
        '14/14 verdicts agree',
        'A result the independent reader recorded for a past run against the '
        'release the record names. It records that run as reported and must not'
        ' track this corpus.',
    ),
    Frozen(
        'scripts/gen-intake-records.py',
        "the independent reader's structure-level total across twelve corpora",
        '382/382 across the twelve corpora read at this depth',
        'A result the independent reader recorded for a past run against the '
        'release the record names. It records that run as reported and must not'
        ' track this corpus.',
    ),
    Frozen(
        'vectors-w3c-intake/INDEX.md',
        "the fixture's own wording of a two-member selection",
        'so 2 of 2 printed as a clean run',
        'The description of a rejected fixture: a selection of two members, '
        'both named in the record. It describes that fixture and does not track'
        ' the corpus.',
    ),
    Frozen(
        'vectors-w3c-intake/gen_vectors.py',
        "the fixture's own wording of a two-member selection",
        'the result never returned it, so 2 of 2',
        'The description of a rejected fixture: a selection of two members, '
        'both named in the record. It describes that fixture and does not track'
        ' the corpus.',
    ),
    Frozen(
        'docs/USED-BY.md',
        "a third party's recorded replay of the invocation-axes corpus",
        'replays the invocation-axes corpus, 25 of 25 cases, in its CI',
        'What one named third-party repository reported for one named workflow run '
        'on the date it ran, with the run linked in the same row. It records that '
        'run and does not track the corpus.',
    ),
    Frozen(
        'docs/USED-BY.md',
        "a third party's recorded replay of the receipt-signature corpus",
        'actions/runs/38343248903), 25 of 25 vectors pass',
        'What one named third-party repository reported for one named workflow run '
        'on the date it ran, with the run linked in the same row. It records that '
        'run and does not track the corpus.',
    ),
)


# --------------------------------------------------------------------------
# Half two: the census
# --------------------------------------------------------------------------

# Forms that carry digits and are not counts. Masked to same-length filler before
# any trigger runs, so offsets into the file stay exact.
MASKS = tuple(
    re.compile(pattern)
    for pattern in (
        # Two spellings, and this is the one place both are correct. These MASK
        # prose so an identifier's digits are not read as a corpus count. The
        # retired form still occurs throughout vectors/CHANGES.md, which is
        # history and is not rewritten, so it still needs masking; the current
        # form carries digit runs of its own and needs it too. Recall over
        # prose, not an identity test -- an identity test that also matched
        # `ok-006` is the confusion the shared definition exists to prevent.
        # A SOURCE LINE REFERENCE is not a count, and three of them arrived in one
        # document: `aee/commitments.go:209`, `aee/statement.go:112` and
        # `aee/validity.go:272`. Each collided with a live figure -- the reject
        # count, one corpus's accept count, and the corpus total -- so the census
        # read a line number as a claim about the corpus and refused prose that
        # claims nothing. The collision is the whole point of the VALUE rule and
        # it has no way to tell the two apart by value alone; the shape is what
        # separates them. A path, an extension, a colon and a line number is a
        # coordinate into a file, and it moves when the file moves, which is the
        # opposite of a figure that must be re-derived when the corpus grows.
        #
        # Recall over prose, as with the ids below: masking a digit too many costs
        # nothing here, and masking one too few manufactures a refusal.
        r"\b[\w./-]+\.(?:go|py|sh|toml|ya?ml|json|md):\d+(?:-\d+)?\b",
        r"\b(?:ok|bad)-\d+(?:/\d+)*",  # retired ids and id lists: ok-006/007/029
        rf"\b{VECTOR_ID_PATTERN}\b",  # current ids: v0099f25838779fcc
        # Condition ids. This is a RECALL pattern and not an identity test, and
        # the difference is worth the paragraph because the two are one character
        # apart and fail in opposite directions.
        #
        # Identity -- "is this string a condition id?" -- is asked in exactly one
        # place, scripts/condition-registry-gate.py, and it is asked anchored at
        # BOTH ends and zero-intolerant, because `aee-c-07` is not `aee-c-7` in
        # another spelling, it is an id nothing can cite. This line asks a
        # different question: does a digit sitting HERE belong to an identifier
        # rather than to a quantity? Masking one digit too many costs nothing;
        # masking one too few manufactures a refusal against prose that claims
        # nothing. Even with the trailing boundary below, this pattern still
        # accepts `aee-c-07`, so it remains the WRONG pattern to copy into an
        # identity test. Anchor the copy at both ends and refuse the leading zero.
        #
        # The trailing \b was absent until it was measured, and the measurement is
        # what licenses adding it rather than an appeal to symmetry. The only
        # tracked strings where the two forms disagree are `aee-c-4x` and
        # `aee-c-3x`, the deliberately malformed ids the condition-registry gate
        # and its suite write in order to prove they are refused. Re-derive the
        # list with:
        #     git grep -nE 'aee-c-[0-9]+[A-Za-z_]'
        # In every such string a letter is glued to the last digit, and that is
        # precisely what both census triggers require the absence of: NOUN wants
        # whitespace and then the noun, and the bare-value trigger wants a word
        # boundary. A digit run with a letter stuck to it can fire neither,
        # masked or not -- so the looser form was protecting a shape that was
        # never reachable, and the census reads the same integers across the same
        # files either way. Re-derive that equivalence rather than trusting this
        # sentence: swap the two forms and compare the last line this gate prints,
        # which names both the integers examined and the files read. Deleting the
        # pattern outright is the control that proves the masking is load-bearing
        # at all -- an id whose digits equal a published corpus count is reported
        # the moment nothing masks it.
        r"\baee-c-\d+\b",
        # Condition identifiers of the self-reported-record corpus, srr-c-N. The
        # same class as the two ids masked here and at `w3c-f-\d+` below, and it
        # arrived the same way: `srr-c-5` sits a few characters from the word
        # "rule" in that corpus's Go reader, the small-value vocabulary looks 32
        # characters either side of an integer for exactly that noun, and 5 is the
        # count of unmeasurable rules the forcing sources publish. So the gate
        # reported an identifier as a stale copy of a derived count. An id is not a
        # count and is not entitled to one of the five routes; freezing the one
        # collision would leave the class open for srr-c-6 at the next value the
        # counter reaches. Re-derive the family with:
        #     git grep -ohE '\bsrr-c-[0-9]+\b' | sort -u
        r"\bsrr-c-\d+\b",
        # Draft OWASP MCP requirement and threat identifiers, MCPVS-N and MCPTM-N,
        # minted once in vectors-mcp-owasp/REGISTRY.json. They are named, never
        # counted: `MCPVS-4` sits in a threat page a few characters from words
        # the small-value vocabulary reads as nouns, and 4 and 5 equal counts the
        # forcing sources publish, so unmasked the gate reported identifiers as
        # stale copies of derived counts. Re-derive the family with:
        #     git grep -ohE '\bMCP(VS|TM)-[0-9]+\b' | sort -u
        r"\bMCP(?:VS|TM)-\d+\b",
        # Disposition-row identifiers, DC-NN. A row in the objection ledger is
        # named, not counted, and the number is as much an identifier as a vector
        # id is. Unmasked it collides on value with whatever small count the
        # sources happen to publish -- DC-04 against the annotated-site count --
        # and the collision fires because a neighbouring row cites a path
        # carrying the word "vectors", which is a coincidence of vocabulary and
        # not a claim about anything.
        r"\bDC-\d+\b",
        # A revision NUMBER names a revision; it is an identifier, not a count.
        # Masked here and read from the unmasked text by ATTRIBUTION below, which
        # is the one place a revision number is allowed to settle a value.
        r"(?:suite)?[Rr]evisions?[-\s]+(?:[#>*]+\s*)?\d+(?:\s+through\s+\d+)?",
        r"\bL\d+(?:-\d+)?\b",  # spec anchors in the vector tables
        r"spec:\d+(?:-\d+)?",  # spec line citations in the sources
        r"\b\d{4}-\d{2}-\d{2}\b",  # dates
        # A CLOCK TIME, masked here rather than beside its sibling shapes below
        # because the masks substitute in order: the zero-padded rule
        # `\b0\d+\b` further down blanks the `00` minutes of `10:00:30`, and
        # the clock shape can no longer match the remains, so the seconds field
        # was read as a bare integer. It surfaced the day the suiteRevision
        # reached 30 and a fixture's `T10:00:30.000Z` was reported against it.
        # The rationale for the shape itself is in the comment further down.
        r"(?<!\d)\d{1,2}:\d{2}:\d{2}(?:\.\d+)?(?!\d)",
        # A WORKFLOW LIMIT. `timeout-minutes: 30` and `retention-days: 30` are
        # settings of a CI job and of an uploaded artifact; they count nothing
        # in any corpus. The key has to sit next to the number, so a bare
        # quantity in a workflow is still read and still checked.
        r"\b(?:timeout-minutes|retention-days):\s*\d+",
        # Five shapes that count nothing, all found the day the observed-effect
        # corpus reached 80 members and twelve sites were reported against it: a
        # PERCENTAGE (`an 80% floor`), the VALUE OF A COMMAND-LINE OPTION
        # (`--threshold 80`, `"--first-screen", "80"`), a RUN OF HEX OCTETS
        # (`ED A0 80`, the CESU-8 spelling of a surrogate; written before the
        # requirement-id mask below, which would otherwise take `A0` and leave
        # the `80`), a PERCENT-ENCODED OCTET (`%80`), and a BYTE SIZE written
        # with a thousands separator (`80,438 bytes`, whose `438 bytes` the byte
        # mask already took). A ratio, a setting, an encoding and a size are not
        # claims about a corpus, and a corpus total walks onto each of them.
        r"\b\d+(?:\.\d+)?%",
        r"--[a-z][\w-]*[\"']?,?\s*[\"']?\d+",
        r"\b[A-F][0-9A-F](?:\s[0-9A-F]{2})+\b",
        r"%[0-9A-Fa-f]{2}",
        r"\b\d{1,3}(?:,\d{3})+[\s-]?bytes?\b",
        # A NETWORK ADDRESS WITH A PORT (`1.2.3.4:80`): the port names a service.
        r"\b\d{1,3}(?:\.\d{1,3}){3}:\d+\b",
        r"RFC\s*\d+",  # RFC numbers
        # Standards NAMES. A digit inside the name of a standard names the
        # document and counts nothing: IEEE 754 is not 754 of anything, and
        # neither is ISO 7064. Written as a body-name alternation rather than
        # one literal per collision because the RFC line above already proves
        # the shape recurs, and each new standard the prose cites would
        # otherwise arrive as a fresh false refusal against text claiming
        # nothing. The canonicalization argument this corpus publishes cites
        # floating-point and checksum standards by name throughout.
        #
        # The designator is the WHOLE identifier, not its first number: `NIST SP
        # 800-184` is one document, and masking only `NIST SP 800` left `-184`
        # to be read as a count the day the audit-record corpus reached 184. So
        # the number may continue through `-`, `/`, `:` or `.` segments
        # (`800-184`, `27001:2022`, `8601-1`) and a revision suffix (`63r3`).
        # The same applies to the other publication identifiers the prose cites:
        # a CVE or CWE id, an IETF BCP or STD number, and a draft name with its
        # two-digit version (`draft-ietf-foo-bar-04`).
        r"\b(?:IEEE|ISO|IEC|ANSI|ECMA|FIPS|(?:NIST\s+)?(?:SP|IR)|BCP|STD)[\s-]*\d+"
        r"(?:[-/:.]\d+)*(?:r\d+)?",
        r"\bCVE-\d{4}-\d{4,}\b",
        r"\bCWE-\d+\b",
        r"\bdraft-[a-z0-9]+(?:-[a-z0-9]+)*-\d{2}\b",
        # Encoding names. The digit in UTF-16 is part of the name of a character
        # encoding and never a quantity of anything, and this corpus argues about
        # UTF-16 code-unit ordering in a dozen places. It went unmasked only
        # because no published count had yet collided with it, which is the
        # false-positive mode this gate's own prose warns about.
        r"\bUTF-\d+\b",
        # A cron schedule. Every field of one is a clock position and none of
        # them counts anything: `31 6 * * 2` is minute thirty-one past hour six
        # on a Tuesday. It stayed invisible only while no published quantity
        # equalled a field of the two schedules in .github/workflows, and it
        # became visible the moment a third corpus registered at a size the
        # minute field happens to hold. This gate's own prose predicted the
        # shape: a cron minute is the first example it gives of what the
        # small-value window kept reporting.
        r"cron:\s*[\"']\s*[-\d,*/\s]+[\"']",
        # An issue, pull-request or discussion number in a GitHub URL. It is the
        # same identifier the `#\d+` mask below already exempts, spelled as a
        # path, and it counts nothing. It surfaced when the ACS-Core reject count
        # reached the number of an issue of this repository that a run record
        # links to twice in one sentence; a per-site freeze would have to be
        # rewritten every time a count walked onto another issue number, which
        # is the argument the w3c rule-id mask gives against freezing an id.
        r"https?://github\.com/[\w.-]+/[\w.-]+/(?:issues|pull|discussions)/\d+",
        r"#\d+",  # upstream issue and pull-request numbers
        # The same identifier written as words, `issue 184`, in link text, a table
        # cell or a docstring. It surfaced when the audit-record corpus total reached
        # the number of the upstream issue that the ACS-Core wire probes cite.
        r"\bissues?\s+\d+\b",
        # A PEP 508 version bound in a quoted requirement string. `"cryptography>=43"`
        # names a release of a dependency and counts nothing; the version-string
        # mask below needs a dot and this form has none. It stayed invisible only
        # while no published count equalled a bare major version, and surfaced
        # when the ACS-Core corpus grew to that value.
        r"[\"'][A-Za-z][\w.-]*(?:\[[\w,-]+\])?(?:>=|<=|==|~=|!=|<|>)\d+",
        # A duration. "43 seconds" and "43 ms" measure time, never a quantity of
        # vectors, rules or sites, and both surfaced on the same collision.
        r"\b\d+\s*(?:ms|milliseconds?|seconds?|minutes?|hours?)\b",
        r"\bv?\d+\.\d+(?:\.\d+)*\b",  # version strings
        r"\bgo\d[\d.]*",  # toolchain versions
        r"\b[0-9a-f]{7,}\b",  # digests and short commit ids
        r"\b[A-Za-z]\d+\b",  # requirement ids: D18, U1, P7
        # Code points, byte sizes and registry decision ids, masked for the same
        # reason UTF-16 above is: each is a digit that names something rather
        # than counting anything, and each stayed invisible only while no
        # published quantity had collided with it. They collided at
        # suiteRevision 20, which appears in this tree as `U+0020` seven times,
        # as a 20 MiB parse bound, and as two registry decision numbers -- none
        # of them a claim about the corpus, and all of them reported as
        # unaccounted the moment the revision counter reached that value.
        r"U\+[0-9A-Fa-f]{4,6}",  # Unicode code points: U+0020
        r"\\u[0-9A-Fa-f]{4}",  # escaped code points:
        # A numbered rule of a registered corpus, `Rule 22` or `rule 29`, names a
        # row of that corpus's requirement table. It is an identifier, and the
        # W3C reader's docstrings spell every rule that way, so its numbers
        # collided with the suiteRevision and a reject count while claiming
        # nothing about either.
        r"\b[Rr]ules?\s+\d{1,3}\b",
        # A line reference, `Lines 417 to 429` or `line 80`, names a place in a
        # file and counts nothing. A pin of that shape collided with the unforced
        # count when the forcing baseline moved from 404 to 417 rules.
        r"\b[Ll]ines?\s+\d+(?:\s*(?:to|-)\s*\d+)?\b",
        r"\b0\d+\b",  # zero-padded: a count is never written 0020
        r"\b\d+\s*(?:<<|>>)\s*\d+\b",  # shift expressions: 20 << 20
        r"\b\d+\s*[KMGT]i?B\b",  # byte sizes: 20 MiB
        # A length in bytes, spelled out. The sibling of the mask above and
        # added for the same reason it was: `32-byte ed25519 public key` names
        # the size of a key and counts nothing about this corpus, and it stayed
        # invisible only while no published quantity equalled 32. The
        # seen-but-tolerated tally reached 32 when the quantifier operator
        # joined the campaign, and six ed25519 key lengths across four files
        # were reported as unaccounted counts on the same run. The unit is
        # required to be adjacent, so this exempts an integer that says what it
        # measures and never one written as a bare quantity: no count this
        # repository publishes is spelled `447 bytes`.
        r"\b\d+[\s-]?bytes?\b",
        # The same length with one word naming what fills it. RFC 5869's default
        # salt is quoted in the ACS 0.1.4 corpus as `a string of 32 zero bytes`,
        # and the word between number and unit was all that kept the mask above
        # from reading it as a length: it was reported as the anchor-stream
        # total five times across the index and the generator. The filler words
        # are listed rather than matched as any word, so `41 reject bytes` or any
        # other noun phrase is still read.
        r"\b\d+\s+(?:zero|null|NUL|random|raw)[\s-]bytes?\b",
        # A line number, spelled out. Same family as the two above: the digit
        # names a POSITION in a file and counts nothing, and it stayed invisible
        # only while no published quantity equalled it. The reject count reached
        # 209 when twelve quantifier vectors landed, and the sentence in
        # docs/UNCITED-OBLIGATIONS.md recording that a sentence beginning on
        # line 210 was attributed to line 209 was reported as an unaccounted
        # count on the same run. The word has to sit next to the number, so an
        # integer written as a bare quantity is still checked, and no count this
        # repository publishes is spelled `line 209`. Spec anchors already have
        # their own mask above; this one covers the prose that discusses them.
        r"\blines?\s+\d+\b",
        # An HTTP status, spelled as prose. Same family as the line numbers
        # above: `returns 404` names a response a server gave and counts
        # nothing, and it stayed invisible only while no published quantity
        # equalled it. The unforced tally reached 404 when the admission rules
        # joined the forcing campaign, and every sentence saying a predicate
        # type URI returns 404 was reported as an unaccounted count on the same
        # run. The verb or article has to sit next to the number, so `404
        # unforced` and `404 DEAD` are still read and checked.
        r"\b(?:HTTP|returns?|returned|an?|the|temporarily|will)\s+404\b",
        r"\b404ed\b",
        r"\bdecisions?\s+\d+",  # interpretation-registry decision ids
        # The w3c-report rule ids. Same family as `aee-c-NN` above, and added
        # for the reason that family's comment predicts: the digit names a rule
        # and counts nothing, and it stayed invisible only while no published
        # quantity equalled it. These ids ran `w3c-f-1` to `w3c-f-28` when this
        # mask was added (the family keeps growing), and the
        # census reports an integer that equals the CURRENT suiteRevision -- so
        # the collision arrived the day the counter reached 28 and landed on
        # `w3c-f-28`, five times across the corpus index and its generator.
        # Freezing those five would have been wrong in a way worth stating: the
        # counter keeps moving, `w3c-f-29` collides at the next revision and
        # `w3c-f-30` at the one after, so the freeze would have to be rewritten
        # every revision forever while the class stayed open. An id is not a
        # count and is not entitled to one of the five routes.
        # Re-derive the family with:
        #     git grep -ohE '\bw3c-f-[0-9]+\b' | sort -u
        # The upper-case siblings, `W3C-R-001` upward, are zero-padded by
        # construction and are already masked by the `\b0\d+\b` rule above.
        r"\bw3c-f-\d+\b",
        # A rule or a section, named by its number. Both are POSITIONS in a
        # document, exactly like the line numbers and decision ids masked above,
        # and both were reported the moment the revision counter reached a value
        # one of them holds: a docstring reading "rule 28" and an appendix
        # sentence reading "sections 3 and 4". The noun has to sit BEFORE the
        # number, so a genuine quantity written the other way round -- "28
        # rules", which is how every count in this repository is spelled -- is
        # still read and still checked. That asymmetry is the whole reason these
        # are safe, and it is the same one the line-number mask relies on.
        r"\brules?\s+\d+\b",
        r"\bsections?\s+\d+(?:\s+and\s+\d+)*\b",
        # The four shapes below all arrived on one run, when the fifth corpus was
        # registered and reserved 49 and 41. Thirteen sites were reported at once
        # and not one of them had changed or claimed anything about a corpus, so
        # they belong to the same family as `\d+ bytes` and `line \d+` above: the
        # shape says what the digit measures, and what it measures is not vectors.
        # They are written as SHAPES rather than frozen per site on purpose -- the
        # w3c rule-id comment above gives the argument, and a freeze would have to
        # be rewritten every time a count walked onto another clock second.
        #
        # A CLOCK TIME. `"timestamp": "2026-08-18T14:33:41.882Z"` inside four
        # fixture records read as the reject count, because a seconds field is a
        # two-digit integer and 41 is a second like any other. A time of day
        # counts nothing and the colons are what separate it from a quantity.
        #
        # The boundary is written as a digit lookaround rather than `\b`, and the
        # first draft of this mask used `\b` and matched nothing at all: in an
        # ISO-8601 instant the hour is preceded by the date separator `T`, which
        # is a word character, so there is no word boundary in front of `14` in
        # `2026-08-18T14:33:41.882Z` and the whole time slipped past. Five sites
        # still failed while the mask looked right.
        # (The clock-time mask itself is applied earlier, right after the date
        # mask: see the comment there for why its position matters.)
        # A LENGTH IN LINES, the `\d+ bytes` argument in the other unit. Six
        # sites measure a stream: `default branch carries 49 lines`, `main held 49
        # lines at read time`, `(24 vs 49 lines)`. The unit must be adjacent, so a
        # bare quantity is still read; this repository publishes no count spelled
        # `49 lines`, exactly as it publishes none spelled `447 bytes`.
        #
        # The `from N lines to M` idiom comes FIRST because the masks substitute
        # in order and the second number carries no unit of its own: the sentence
        # `main went from 24 lines to 49` states one measurement in two halves,
        # and blanking the first half would leave the second reading as a bare
        # quantity.
        r"\bfrom\s+\d+\s+lines?\s+to\s+\d+\b",
        r"\b\d+\s+lines?\b",
        # AN OCCURRENCE COUNT IN HISTORY. `it occurs 49 times` in .githooks/README.md
        # measures how often a word appears across four repositories' commits. It
        # is a quantity, but not of this corpus, and nothing here derives it.
        r"\b\d+\s+times\b",
        # AN EXPONENT AND A DURATION. Both arrived when the agent audit record
        # corpus reached 68 members: `2**68` and `two-to-the-68` name the double
        # RFC 8785 Appendix B row 9 serializes (four sites in the ai-agent-action
        # corpus and its index), and `had run 68 days` measures how long a thread
        # had been open. A power's exponent and a span of days count nothing here,
        # this repository publishes no count spelled either way, and they are
        # written as shapes for the reason the rule-id mask above gives: a freeze
        # per site would have to move every time a corpus total walked onto one.
        r"\b\d+\*\*\d+\b",
        # The same power written with a caret: `2^53`, the I-JSON integer bound,
        # met the observed-effect reject count when that corpus reached 53.
        r"\b\d+\^\d+\b",
        r"\bto-the-\d+\b",
        r"\b\d+\s+days?\b",
        # A NUMERIC RANGE. `(90-100 Full Compliance, 70-89 Partial, 50-69 Minimal,
        # 0-49 Non-Compliant)` quotes an upstream document's scoring bands, and the
        # tail of the last band is the corpus total. A hyphen-joined pair with no
        # spaces is a range wherever it appears; no count in this repository is
        # written that way, and a subtraction would carry spaces.
        r"\b\d{1,4}-\d{1,4}\b",
    )
)

# The contexts that make an integer a MEASUREMENT, read by the VALUE trigger only.
#
# Why this exists. The VALUE rule fires on an integer for its value alone, and
# every corpus here is a small integer that grows one member at a time, so each
# new size walks onto every integer the prose already uses for something else.
# When the audit record corpus reached 64 members, 104 sentences that state a
# SHA-256 digest is 64 hex characters, that a field is 64 bits, or that a regex
# repeats `{64}` times were each refused as an unaccounted corpus total. The
# corpus had not moved under any of them; the value had moved onto them. Masking
# or freezing them one at a time is what this gate did at 43, 59, 63 and 68, and
# it was going to keep doing it at every size a corpus could reach. The byte-size
# and byte-length masks above are the same argument made for one unit each; this
# list makes it once for every unit of size or width.
#
# What decides. A measurement says so in its own syntax: a unit of size or width
# directly after the integer, a regex repetition bound, a length comparison, a
# subscript or slice. Those contexts and nothing else take an integer out of the
# VALUE rule. A count of a corpus never takes one of these units: there is no
# claim form in this repository that counts members in bits, characters or
# bytes. The test suite holds that line from both sides, with every real claim
# form planted at a live value and refused, and with every measure form accepted.
#
# What does not decide. The ABSENCE of a count noun takes nothing out. A bare
# integer equal to a corpus total, with no unit and no count noun, is still
# refused until something accounts for it, because "the full 64" may be a length
# and may be a count and only its writer knows which. Two such sentences are
# frozen above with what each one measures.
MEASURE_UNIT = r"(?:hex(?:adecimal)?|bits?|bytes?|octets?|nibbles?|char(?:acter)?s?|digits?)"
# Words that may sit between the integer and its unit without changing what is
# measured: `64 lowercase hex characters`, `<64 lowercase hex>`.
MEASURE_MODIFIER = r"(?:lower-?case|upper-?case|ascii|raw|hex(?:adecimal)?)"
MEASURES = tuple(
    re.compile(pattern)
    for pattern in (
        # A size or a width: `64 hex characters`, `64-hex`, `NOT-64-HEX`,
        # `64 bits`, `a 64-bit integer`, `64 lowercase hex`. The unit may follow
        # a line break, because prose here is hard-wrapped. It must END the
        # compound: in `64 hex-encoded vectors` the hyphen carries on to the noun
        # the integer counts, so that is a count and stays one.
        rf"(?i)(?<![\w.])\d+(?:[-\s]+{MEASURE_MODIFIER}){{0,2}}[-\s]+{MEASURE_UNIT}\b(?!-\w)",
        # A regex repetition bound: `[0-9a-f]{64}`, `\d{2,64}`. The brace has to
        # follow the thing it repeats, so a bare `{64}` in prose is not one.
        r"(?<=[\]).\w}])\{\d*(?:,\d*)?\}",
        # A length comparison, either way round: `len(s) != 64`, `x.length === 64`.
        r"\b(?:len\([^()\n]{0,80}\)|\.length)\s*(?:[!=]==?|[<>]=?)\s*\d+",
        r"\b\d+\s*(?:[!=]==?|[<>]=?)\s*(?:len\(|[\w.]+\.length\b)",
        # A subscript or a slice: `digest[:16]`, `parts[2]`. The bracket has to
        # follow what it indexes, so a bracketed number in prose is not one.
        r"(?<=[\w)\]])\[\s*-?\d*\s*(?::\s*-?\d*\s*){0,2}\]",
    )
)

NOUN = re.compile(r"\b(\d{1,4})\s+(?:accept |reject )?vectors?\b", re.IGNORECASE)
# A revision the sentence names, in every spelling this repository uses. The
# optional comment marker is not decoration: these sentences are hard-wrapped
# inside `#` comment blocks, so `revision` and its number routinely sit on
# different lines with a marker between them.
ATTRIBUTION = re.compile(r"(?:suite)?[Rr]evisions?[-\s]+(?:[#>*]+\s*)?(\d+)")
# Below this, an integer is ambiguous with ordinary prose and only counts when it
# sits next to one of the words below.
#
# Raised from 20 to 21 at suiteRevision 20, when the revision counter walked into
# the band this threshold describes. A bare 20 is exactly as ambiguous in prose
# as a bare 19: on the day the corpus reached revision 20 the census reported a
# cron minute, a `head -20`, a URL fragment and a 20 MiB parse bound as
# unaccounted counts, none of which had changed and none of which is a claim
# about anything. The alternative was a mask per context, which chases the
# collision instead of naming it. Nothing real is lost: a genuine quantity of 20
# is still caught, because the words that make it a quantity are below.
#
# Raised again from 21 to 22 at suiteRevision 21, for the same reason and by the
# same argument: the counter moved one more step into the ambiguous band. What it
# reported this time was `1e21` in the JCS number tests -- the integer 10^21, a
# value that must be rejected by the safe-integer profile and is not a count of
# anything -- twice, plus a bare 21 in a design record. The threshold walking up
# behind the revision counter is expected and is not a weakening: the counter will
# keep moving, and each step is one more small integer that prose can use
# innocently. The check that survives is the one below, which asks whether a count
# NOUN sits beside the number.
#
# Raised again from 22 to 23 at suiteRevision 22, when the admission corpus grew
# to 22 vectors and its total walked into the band: bare 22s in workflow node
# versions, test fixtures and prose were reported as unaccounted corpus totals,
# none of them a claim about that corpus. The same argument holds.
SMALL_VALUE = 23
# An integer this repository already uses as a protocol constant rather than a
# count. A registered corpus whose total reaches one of these is noun-bound, like
# its per-kind counts: read bare it refused fifty-six sentences about the I-JSON
# nesting depth bound of 128 on the revision that grew vectors-agent-audit-record
# to 128 members, none of them a claim about that corpus. Beside a count noun it
# still fires, and the corpus total stays checked against its manifest by the
# declared claims and manifest_integrity_failures.
PROTOCOL_CONSTANTS = frozenset({128})
SMALL_VALUE_NOUNS = re.compile(
    r"(?i)\b(?:vectors?|suiteRevisions?|revisions?|sites?|rules?|forced|unforced|"
    r"tolerated|unmeasurable|annotations?|KILLED|SILENT|DEAD|INCONCLUSIVE)\b"
)
# How far either side of an integer the small-value vocabulary is looked for.
SMALL_VALUE_WINDOW = 32

READ_SUFFIXES = frozenset({".md", ".yml", ".yaml", ".py", ".go", ".toml"})
EXEMPT: dict[str, str] = {
    "docs/COVERAGE-MATRIX.md": (
        "generated end to end from the interpretation registry and gated by "
        "scripts/coverage-matrix-gate.py --check"
    ),
    "docs/FORCING-HONESTY.md": (
        "generated end to end from the manifest, the forcing baseline, the condition "
        "registry and the rail's code set, and gated by "
        "scripts/condition-forcing-gate.py --check"
    ),
}
EXEMPT_PREFIXES: dict[str, str] = {
    "docs/paper/": (
        "a paper section about named past releases (0.12.0, 0.17.4, 0.18.1) and a "
        "recorded experiment; every figure is pinned to its tag and digest in the same "
        "table and is recounted by docs/paper/w3c-v01/recount.py and "
        "claim-downgrade/run.sh, so none of them may track the current corpus"
    ),
    "spec/predicates/": (
        "vendored upstream bytes; scripts/spec-drift-gate.py owns them and an edit "
        "here is a re-vendor, not a count"
    ),
    "vectors-poc-evidence/": (
        "a standalone corpus whose counts are owned by its CORPUS-MANIFEST.json: "
        "vectors-poc-evidence/tests assert case_count and the per-kind counts against the "
        "files on disk, and the builder's --check refuses a corpus that differs; the "
        "integers in its prose and builder notes are requirement ids, tree sizes and "
        "record indexes of the Proof-of-Control draft, not counts of this repository"
    ),
    "crates/jcs-admit/": (
        "a standalone crate with its own Cargo tests, interop fixtures and recorded "
        "run output; its integers are byte widths, nesting-depth bounds, upstream "
        "event counts and the figures of its own mutation sweep and incumbent "
        "measurement, none of them a count of this repository's corpora, which this "
        "gate's declared claims and manifests check"
    ),
    "crates/dsse/": (
        "a standalone crate with its own Cargo tests (the crate-dsse job); its "
        "integers are key and signature widths in bytes and its own test totals, "
        "none of them a count of this repository's corpora, which this gate's "
        "declared claims and manifests check"
    ),
    "actions/admission/": (
        "a standalone Action whose pytest suite (the actions-admission job) asserts "
        "its own outputs; its integers are the sizes and ratios of its test data, "
        "none of them a count of this repository's corpora"
    ),
    "packages/admission/": (
        "a standalone package with its own pytest and conformance suite (the "
        "package-admission job). Its per-rail vector counts and verdict tallies come "
        "from profiles/MEASUREMENTS.json, which scripts/profile-map-gate.py pins to a "
        "corpus digest and refuses when the corpus has moved; its other integers are "
        "obligation counts of its own registries and ids of the specifications it cites"
    ),
    "packages/vocabulary/": (
        "a standalone package whose vocabulary, crosswalks and tests are held by its "
        "own checks (the package-vocabulary job); its integers are dated measurements "
        "recorded in the entry that states the date, regulation and article numbers, "
        "and test data, none of them a live count of this repository's corpora"
    ),
    "pages/vocab/": (
        "content-addressed snapshots of packages/vocabulary/vocabulary.yaml; each "
        "file name is the digest of its bytes, so an edit changes the name, and the "
        "integers inside are the source's dated measurements and citations"
    ),
    "vectors-ai-agent-action/spec-vendored/": (
        "vendored upstream bytes; the manifest's specDigest owns them, "
        "aee-verify refuses a copy whose bytes moved, "
        "and every integer inside belongs to the upstream document rather than to "
        "this corpus"
    ),
    # A registered corpus vendors the text it certifies against, and those bytes
    # are upstream's. Derived from the registration rather than listed per
    # corpus, so registering one stays one line: a corpus whose vendored copy
    # had to be exempted by hand would be a second line that a reader could
    # forget, and forgetting it reports somebody else's section numbering as an
    # unaccounted count of ours.
    **{
        f"{directory}/spec-vendored/": (
            "vendored upstream bytes; the corpus manifest's digest owns them, its "
            "aee-verify refuses a copy whose bytes moved, and every integer "
            "inside belongs to the upstream document rather than to this corpus"
        )
        for directory in EXTRA_CORPORA
    },
}

# The files whose count-shaped integers are CONTROL DATA rather than claims about
# the corpus, so the census reads no integer in them.
#
# This is not a convenience. Everything the census would find in these files is
# control data: the declaration tables name the very values they check, the
# refusal message quotes the routes a writer may take, the worked examples in the
# prose above are the sentences other files are checked against, an ordinal list
# marker and a regex repetition bound are digits that stand for nothing, and the
# tests write deliberately WRONG values into a staged copy to prove the refusal
# fires. A census over its own control data reports its vocabulary as unaccounted
# prose, which is what it did: seventy refusals, every one of them in these
# files, on the revision that introduced them.
#
# The class widened once, and the widening is the honest description rather than
# the original one. It was first written as "this gate's own subject", which
# described the three files it then held; a mutation rig for a DIFFERENT gate hits
# the identical wall, because a rig that proves a published figure is checked has
# to name that figure to retype it. What licenses the exemption is not whose gate
# the file belongs to, it is that the rig asserts the value is present before
# replacing it -- so a figure that goes stale fails the rig by name, which is
# strictly louder than the census refusal it is being excused from. A rig that
# retyped a value without asserting it first would not qualify.
#
# What it costs is one live count in the prose above, and that is not left
# unchecked: it is declared as a claim like any other, so a corpus that grows
# still fails here. Only the census is skipped; the claims, the delegations and
# the frozen figures are all still read out of these files.
SELF = {
    "scripts/count-gate.py": "this gate's own declarations, examples and vocabulary",
    "scripts/count-gate-test.py": (
        "the deliberately wrong values this gate's tests write to prove it refuses"
    ),
    "scripts/countcensus.py": (
        "the census engine's own vocabulary and worked examples, which are the "
        "shapes it looks for rather than claims about anything"
    ),
    "scripts/condition-forcing-crosscheck-test.py": (
        "the published figures this rig retypes to prove the crosscheck refuses a "
        "page that drifted; rig_text asserts each one is present before replacing "
        "it, so a stale figure fails the rig rather than passing the census"
    ),
}


def changelog_scope(text: str, position: int) -> int | None:
    """The revision whose section an offset sits in, for vectors/CHANGES.md."""
    scope: int | None = None
    for heading in REVISION_HEADING.finditer(text):
        if heading.start() > position:
            break
        scope = int(heading.group(1))
    return scope


def changelog_route(rel: str, text: str, token: Token, quantities: Quantities) -> str | None:
    """Route 5: a changelog entry is scoped by the heading it sits under.

    A revision section may cite any size the corpus had at or before that
    revision, which is the same reason scripts/independent-runs-gate.py exempts
    that file from its not-run check.
    """
    if rel != CHANGES_REL:
        return None
    scope = changelog_scope(text, token.start)
    if scope is not None and all(
        any(revision <= scope for revision in quantities.historical.get(value, ()))
        for value in token.values
    ):
        return f"a size the corpus had at or before suiteRevision {scope}"
    return None


def quantities(src: Sources) -> Quantities:
    """What the sources currently publish, what they have published, what was posted."""
    return Quantities(
        current=src.current(),
        noun_bound=src.noun_bound(),
        historical=src.historical(),
        posted=src.figures,
        posted_why="a score docs/INDEPENDENT-RUNS.json records as posted",
    )


CENSUS = Census(
    masks=MASKS,
    nouns=((NOUN, "an integer counting vectors"),),
    small_value_nouns=SMALL_VALUE_NOUNS,
    measures=MEASURES,
    small_value=SMALL_VALUE,
    small_value_window=SMALL_VALUE_WINDOW,
    attribution=ATTRIBUTION,
    attribution_why="revision-attributed by the sentence it sits in",
    scope_route=changelog_route,
    self_files=SELF,
)


# --------------------------------------------------------------------------


def collect() -> tuple[list[str], int, int, int]:
    src = load_sources()
    texts = read_tracked(REPO_ROOT, READ_SUFFIXES, EXEMPT, EXEMPT_PREFIXES)
    failures = manifest_integrity_failures(src)
    failures.extend(head_row_failures(src))
    claim_out, covered = check_claims(claims(src), texts)
    failures.extend(claim_out)
    failures.extend(check_declarations(DELEGATED, FROZEN, texts, covered))
    failures.extend(index_failures(texts, covered))
    measured: list[tuple[str, int, int]] = []
    census_out, examined = run_census(CENSUS, quantities(src), texts, covered, measured)
    failures.extend(census_out)
    return failures, len(texts), examined, len(measured)


def main(argv: list[str]) -> int:
    global REPO_ROOT
    parser = argparse.ArgumentParser(description="check every published corpus count")
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="the tree to check; a staged copy when the gate's own tests run it",
    )
    REPO_ROOT = parser.parse_args(argv[1:]).root.resolve()
    failures, files, examined, measured = collect()
    if failures:
        print(f"FAIL: {len(failures)} count claim(s) do not hold:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print(
            "\nA count is derived. Fix a wrong value by correcting the prose to what "
            "the sources say, never by editing a source to match the prose. Account "
            "for a new count-shaped integer in one of five ways: declare it as a "
            "claim in scripts/count-gate.py so it is checked; name the gate that "
            "already owns it in DELEGATED; freeze it in FROZEN with the reason it "
            "records a past event; attribute it in the prose itself, which is the "
            "route that also tells the reader "
            "(`passed all 165 vectors (suiteRevision 11)`); or delete the number, "
            "which is right whenever it cannot be derived and is not history.",
            file=sys.stderr,
        )
        return 1
    print(
        f"OK: every published count is derived from its source, and all {examined} "
        f"count-shaped integer(s) across {files} tracked file(s) are accounted for. "
        f"{measured} integer(s) equal to a published count were read as "
        "measurements (a size, a width, a length or an index), not counts."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
