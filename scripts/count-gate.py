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


def claims(src: Sources) -> tuple[Claim, ...]:
    """Every live count this repository publishes, and what the sources say it is.

    The hand-wired claims below, plus three per directory in EXTRA_CORPORA. A
    registered corpus publishes its counts in one fixed sentence, so the claims
    for it are generated from the registration instead of being typed out a
    fourth time.
    """
    return declared_claims(src) + reply_claims(src) + tuple(
        claim
        for directory, total, accept, reject in src.extra
        for claim in claims_for_corpus(directory, total, accept, reject)
    )


def declared_claims(src: Sources) -> tuple[Claim, ...]:
    """The claim sites written out one at a time, each against its own sentence."""
    rev = src.revision
    corpus = (
        f"{src.total} vectors ({src.accept} accept, {src.reject} reject, "
        f"{src.indeterminate} indeterminate)"
    )
    return (
        Claim(
            "README.md",
            "the AEE vector-count badge, its image",
            "badge/AEE%20vectors-",
            "-e8951c",
            str(src.total),
        ),
        Claim(
            "README.md",
            "the AEE vector-count badge, its alt text",
            'alt="',
            ' AEE conformance vectors"',
            str(src.total),
        ),
        Claim(
            "README.md",
            "the AI Agent Action vector-count badge, its image",
            "badge/AI%20Agent%20Action%20vectors-",
            "-e8951c",
            str(src.agent_action_total),
        ),
        Claim(
            "README.md",
            "the AI Agent Action vector-count badge, its alt text",
            'alt="',
            ' AI Agent Action conformance vectors"',
            str(src.agent_action_total),
        ),
        Claim(
            "README.md",
            "the artifact-binding vector-count badge, its image",
            "badge/artifact--binding%20vectors-",
            "-e8951c",
            str(src.binding_total),
        ),
        Claim(
            "README.md",
            "the artifact-binding vector-count badge, its alt text",
            'alt="',
            ' artifact-binding conformance vectors"',
            str(src.binding_total),
        ),
        Claim(
            "README.md",
            "the AEE predicate version, in the badge",
            "badge/predicate-in--toto%20AEE%20v",
            "-6f57c2",
            src.predicate_version,
        ),
        Claim(
            "README.md",
            "the AEE predicate version, in the opening sentence",
            "**Adversarial Execution Evidence**, predicate version ",
            ", and **AI Agent",
            src.predicate_version,
        ),
        Claim(
            "README.md",
            "the AI Agent Action predicate version, in the opening sentence",
            "**AI Agent\nAction**, predicate version ",
            ", proposed in",
            src.agent_action_predicate_version,
        ),
        Claim(
            "README.md",
            "what a full replay reports, in the forcing section",
            "the suite still reports ",
            ", exit 0. A rail with no",
            f"{src.total} of {src.total}",
        ),
        Claim(
            "README.md",
            "the size of the mutation sweep",
            "notices — ",
            " single-site weakenings of",
            str(src.sites),
        ),
        Claim(
            "README.md",
            "the four forcing outcomes",
            "tighten-only ratchet: **",
            ".** The four outcomes",
            f"{src.forced} rules forced, {src.tolerated} seen-but-tolerated, "
            f"{src.unforced} unforced, {src.unmeasurable}\nunmeasurable",
        ),
        Claim(
            "README.md",
            "how many forcing sites carry an annotation",
            "is a gap — and",
            "sites carry an annotation saying",
            WORDS.get(src.annotated, str(src.annotated)),
        ),
        Claim(
            "README.md",
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
        "README.md",
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
        "the suiteRevision-28 run's per-outcome figures, as posted",
        "61/61 accepts, 209/209 rejects, 2/2 indeterminate",
        "The outcome split an outside verifier posted against suiteRevision 28 "
        "(its own index says revision 27) at Rul1an/aee-checker#21. Frozen to that run: the accept and reject "
        "totals equal the corpus's own at the time, which is the collision this "
        "census exists to surface, and restating either against a later corpus "
        "would attribute a run to bytes it never saw.",
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
        "README.md",
        "the independent Rust verifier's score, as posted",
        "scores 272/272 on suiteRevision 28",
        "What one outside build answered against suiteRevision 28, which its own "
        "index labels revision 27, with its author recording that the build was "
        "frozen before the corpus moved. The revision is named in the same "
        "sentence, so the figure is readable against the corpus it was measured "
        "on rather than against this one.",
    ),
    Frozen(
        "README.md",
        "the blind RFC 8785 run's figures, as posted",
        "ran the 57 RFC 8785 vectors blind against argentum-core before opening "
        "the generators: 57/57",
        "A blind outside run of the RFC 8785 canonicalization vectors as that "
        "set stood when it was run. Both the set size and the score belong to "
        "that run; tracking either against a later corpus would describe a "
        "rerun nobody performed and would destroy what blind means here.",
    ),
    Frozen(
        "README.md",
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
        "README.md",
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
        "two rails sat at 140 vectors while this repository",
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
        "README.md",
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
        '{"figure": "9/9", "role": "score"',
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
        r"RFC\s*\d+",  # RFC numbers
        # Standards NAMES. A digit inside the name of a standard names the
        # document and counts nothing: IEEE 754 is not 754 of anything, and
        # neither is ISO 7064. Written as a body-name alternation rather than
        # one literal per collision because the RFC line above already proves
        # the shape recurs, and each new standard the prose cites would
        # otherwise arrive as a fresh false refusal against text claiming
        # nothing. The canonicalization argument this corpus publishes cites
        # floating-point and checksum standards by name throughout.
        r"\b(?:IEEE|ISO|IEC|ANSI|ECMA|FIPS|NIST\s+SP)[\s-]*\d+",
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
        r"#\d+",  # upstream issue and pull-request numbers
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
        r"\bdecisions?\s+\d+",  # interpretation-registry decision ids
        # The w3c-report rule ids. Same family as `aee-c-NN` above, and added
        # for the reason that family's comment predicts: the digit names a rule
        # and counts nothing, and it stayed invisible only while no published
        # quantity equalled it. These ids run `w3c-f-1` to `w3c-f-28`, and the
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
        # The upper-case siblings `W3C-R-001` to `W3C-R-028` are zero-padded by
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
        r"(?<!\d)\d{1,2}:\d{2}:\d{2}(?:\.\d+)?(?!\d)",
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
        # A NUMERIC RANGE. `(90-100 Full Compliance, 70-89 Partial, 50-69 Minimal,
        # 0-49 Non-Compliant)` quotes an upstream document's scoring bands, and the
        # tail of the last band is the corpus total. A hyphen-joined pair with no
        # spaces is a range wherever it appears; no count in this repository is
        # written that way, and a subtraction would carry spaces.
        r"\b\d{1,4}-\d{1,4}\b",
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
SMALL_VALUE = 22
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
    "spec/predicates/": (
        "vendored upstream bytes; scripts/spec-drift-gate.py owns them and an edit "
        "here is a re-vendor, not a count"
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
        historical=src.historical(),
        posted=src.figures,
        posted_why="a score docs/INDEPENDENT-RUNS.json records as posted",
    )


CENSUS = Census(
    masks=MASKS,
    nouns=((NOUN, "an integer counting vectors"),),
    small_value_nouns=SMALL_VALUE_NOUNS,
    small_value=SMALL_VALUE,
    small_value_window=SMALL_VALUE_WINDOW,
    attribution=ATTRIBUTION,
    attribution_why="revision-attributed by the sentence it sits in",
    scope_route=changelog_route,
    self_files=SELF,
)


# --------------------------------------------------------------------------


def collect() -> tuple[list[str], int, int]:
    src = load_sources()
    texts = read_tracked(REPO_ROOT, READ_SUFFIXES, EXEMPT, EXEMPT_PREFIXES)
    failures = manifest_integrity_failures(src)
    failures.extend(head_row_failures(src))
    claim_out, covered = check_claims(claims(src), texts)
    failures.extend(claim_out)
    failures.extend(check_declarations(DELEGATED, FROZEN, texts, covered))
    failures.extend(index_failures(texts, covered))
    census_out, examined = run_census(CENSUS, quantities(src), texts, covered)
    failures.extend(census_out)
    return failures, len(texts), examined


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
    failures, files, examined = collect()
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
        f"count-shaped integer(s) across {files} tracked file(s) are accounted for."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
