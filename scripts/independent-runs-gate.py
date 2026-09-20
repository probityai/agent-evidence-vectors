#!/usr/bin/env python3
"""Independent-run gate: the column about someone else's implementation may not
outlive the runs it describes.

The one claim this repository exists to make rests on a single outside reader.
Everything else here is five implementations by one author sharing one reading of
RFC 8785 and RFC 7493, which is a drift check rather than corroboration. So the
independence column is the most consequential prose in the tree, and its value is
entirely that it is an accurate record of what someone else actually ran. A
figure invented there would be worse than no figure, and so, less obviously,
would a stale scope: the sentence that says which revisions were NOT run is what
stops a reader inferring that the unnamed ones were.

That sentence had rotted three times over, in three different documents, each
naming a different set. The suite was at revision 14 while the README said the
checker had not been run against 7, 8, 9 or 10, the implementation report said 7,
8 or 9, and the report's own table said 7 through 9. Every one of those was true
when it was written. Each stopped being true the next time the corpus moved, and
nothing anywhere disagreed with them, because nothing read them. Worse than the
lag was what all three shared: none of them named revision 4 at all. That
revision changed no vector -- its 140 files carry the revision-3 verdicts and
codes -- but it is where encoding well-formedness and the 128-deep nesting bound
became normative over a corpus that, in its own changelog's words, exercised
neither. A revision-3 pass is therefore not a revision-4 pass, and this checker
is the proof: it scored 140/140 at revision 3 and still read the nesting bound as
256 when revision 5 published.

So the not-run set stops being a thing anyone writes down. ``docs/
INDEPENDENT-RUNS.json`` records the runs -- one row per posted run, with the
score exactly as posted, the venue it was posted at, the classification its
author gave it, and the checker source digest and suite commit where those were
posted -- and the not-run set is what is left of 1..current after the rows are
removed. The current revision is read from ``vectors/CHANGES.md``, the
per-revision changelog that owns revision numbering, rather than from a number
typed here, because a revision number written in the ledger could only ever
agree with itself.

Why this gate reads hand-written prose instead of generating it
---------------------------------------------------------------

This repository does both. ``docs/COVERAGE-MATRIX.md`` is generated end to end
and gated with --check, and that is right for it: it is a table, its cells are
joins over two JSON files, and there is no argument in it for a generator to
lose.

The sentences here are the opposite shape. The not-run set is one clause inside a
paragraph that argues -- that revision 4 is on the list for a different reason
than revision 7 is, that a directed 153/153 is not the same evidence as a blind
125/125, that a figure moves the column only because a record was posted with it.
Its author's own wording is quoted in it verbatim because paraphrasing it would
soften it. A generated span would have to either drop that argument, which is
most of what makes the column trustworthy, or carry it inside a script that no
reviewer of the README ever opens.

There is a second reason, and it is the one specpins.py already names about
line-range pins: a generated span cannot fail. If the prose is a pure function of
the ledger, it can only ever restate what it just read, and the check that the
surrounding argument still matches the facts is not weakened but absent. The
defect being closed here is a person writing a set and not revisiting it when the
corpus moved. Generating the set removes the person, and with them the sentence
in which the set has to make sense. Checking it keeps the person writing the
argument and refuses when the set inside it has stopped being true.

The cost of that choice is that a claim site has to be declared here to be
checked. So each site is matched on the fixed words around the enumeration, and a
site that no longer matches is a failure by name rather than a silently skipped
check -- the same reason code-contract-gate.py matches its const block on the
comment text rather than on the constant names.

What it does not catch
----------------------

``vectors/CHANGES.md`` is exempt, deliberately. Its per-revision entries carry
not-run sentences too, and those are historical: each was true of the revision it
sits under and is scoped by sitting there, so correcting them would be rewriting
a changelog rather than fixing a claim. The consequence is real and is recorded
rather than papered over: a not-run claim written into a NEW changelog entry is
not checked by anything, and only the three documents whose sites are declared
below are.

Nor does it police the direction "a directed run described as unprompted".
It asserts the partition the ledger draws is internally consistent (a run its
author called directed may not be flagged unprompted) and that each unprompted
run is named where the report reserves that description, but whether a paragraph
elsewhere leans on a figure it should not is a reading, not a match, and a gate
that pretended otherwise would be measuring prose shape.

A dispatch that returned nothing
--------------------------------

A row in ``runs`` is what licenses a figure, and every row there carries a
``figures`` array, so the file had no shape at all for a dispatch that was
authorised, ran, and produced no score. Two such dispatches existed before this
array did, and the gate could not see either of them: it reads ``runs``, and
nothing else was written down. The file's own opening comment already argued the
other way -- an absent field and an unrecorded fact read the same in a diff --
which is why the fix is an ``attempts`` array rather than a silence.

An attempt carries ``figures: null`` beside a note saying why there is none, and
carries no ``suiteRevision`` at all. That omission is enforced rather than
observed: the not-run set is computed over ``runs``, so a suiteRevision on an
attempt would shrink that set and let a dispatch with no figure license the very
figure it does not have. What it binds instead is the corpus commit, the checker
ref, the authorization packet, the dispatch, and where the artifacts survive with
how long for. ``outcome`` is a closed token so that "it produced no score" cannot
be written two ways.

Usage: python3 scripts/independent-runs-gate.py
Exit 0 when the published prose is the ledger; 1 on any disagreement.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER = REPO_ROOT / "docs" / "INDEPENDENT-RUNS.json"
CHANGES = REPO_ROOT / "vectors" / "CHANGES.md"
README = REPO_ROOT / "README.md"
REPORT = REPO_ROOT / "docs" / "IMPLEMENTATION-REPORT.md"

# `## suiteRevision 14 (the vendored text catches up with the corpus)`
REVISION_HEADING = re.compile(r"^## suiteRevision (\d+)\b", re.MULTILINE)
# `4, 7, 8, 9, 10, 11, 12, 13 or 14` and the `and` spelling the table cells use.
# No capturing group, so it can be embedded in a site pattern.
ENUMERATION = r"\d+(?:, \d+)*(?:,? (?:and|or) \d+)?"
SCORE = re.compile(r"^\d+/\d+$")
EVIDENCE = ("blind", "first-run-unchanged-build", "directed")
# The two documents that publish the independence column. A run's headline figure
# has to be stated in both or in neither.
#
# Annotated rather than inferred: unannotated, this is a tuple of its own two
# literal values, and a set built from it will not difference against the set of
# paths read out of a run record, which is an ordinary set of strings. These are
# document paths that happen to be known here, not a closed enumeration.
PUBLISHING_DOCS: tuple[str, ...] = ("README.md", "docs/IMPLEMENTATION-REPORT.md")
# A value this repository can source, or a note saying it cannot. Exactly one,
# because a field left null with nothing beside it and a field nobody thought
# about are the same field in a diff.
SOURCED_OR_EXPLAINED = (
    ("date", "dateNote"),
    ("checkerSourceDigest", "digestNote"),
    ("suiteCommit", "suiteCommitNote"),
)


@dataclass(frozen=True)
class Site:
    """One place the not-run set is published, found by the words around it.

    ``opens`` and ``closes`` are the fixed prose either side of the
    enumeration, and ``occurrences`` is how many times that shape must appear in
    the file. The count is asserted rather than assumed so that deleting a claim,
    or duplicating one into a second paragraph that will then rot on its own,
    fails here instead of passing.
    """

    path: Path
    label: str
    opens: str
    closes: str
    occurrences: int


SITES = (
    Site(
        README,
        "the independence section's scoping sentence",
        "It has not been run against suiteRevision ",
        ", so this suite publishes no score for it at any of them.",
        1,
    ),
    Site(
        REPORT,
        "note 1, the run history",
        "The checker has not been run against suiteRevision ",
        ", so this report publishes no score for it at any of them.",
        1,
    ),
    Site(
        REPORT,
        "the implementations table, the verified-against cell",
        "suiteRevisions ",
        " not run by its author",
        1,
    ),
    Site(
        REPORT,
        "the implementations table, the result cell",
        "suiteRevisions ",
        " not run by author (see note 1)",
        1,
    ),
)

# The revision the corpus is at, restated in the report's own prose. It is the
# input to the derivation below, so a stale copy of it would let a correct
# not-run set sit under a heading naming the wrong corpus. Checked as literals
# rather than by regex: rewording one fails loudly here, which is the intent.
CURRENT_REVISION_LITERALS = (
    ("Corpus SSOT: vectors/MANIFEST.json (suiteRevision {n},", 1),
    ("`vectors/MANIFEST.json`, suiteRevision {n}:", 1),
    ("| reference corpus, suiteRevision {n} |", 2),
)


def normalize(text: str) -> str:
    """Collapse every run of whitespace, so a paragraph rewrapped in a repo file
    is the same prose. Line numbers are lost with the line breaks; failures name
    the file and the claim instead, which is what a reader needs to find them."""
    return " ".join(text.split())


def read(path: Path) -> str:
    return normalize(path.read_text(encoding="utf-8"))


def current_revision() -> tuple[int, list[str]]:
    """The revision the corpus is at, read from the changelog that owns revision
    numbering, plus any reason that reading cannot be trusted."""
    seen = sorted({int(n) for n in REVISION_HEADING.findall(CHANGES.read_text("utf-8"))})
    if not seen:
        return 0, [
            "vectors/CHANGES.md carries no '## suiteRevision N' heading, so nothing "
            "says which revision the corpus is at and the not-run set has no domain."
        ]
    gaps = sorted(set(range(1, seen[-1] + 1)) - set(seen))
    if gaps:
        listed = ", ".join(str(g) for g in gaps)
        return seen[-1], [
            f"vectors/CHANGES.md jumps: it names suiteRevision {seen[-1]} but has no "
            f"entry for {listed}. The not-run set is computed over 1..current, so a "
            "missing entry would silently make a revision unaccountable."
        ]
    return seen[-1], []


def _run_field_failures(run: dict[str, Any], current: int) -> list[str]:
    """Everything one row must carry to license a figure in the prose."""
    rev = run.get("suiteRevision")
    where = f"run at suiteRevision {rev}"
    out: list[str] = []
    if not isinstance(rev, int) or not 1 <= rev <= current:
        return [f"{where}: suiteRevision must be an integer in 1..{current}."]
    out.extend(_figure_shape_failures(run, where))
    if not str(run.get("posting", "")).strip():
        out.append(
            f"{where}: names no posting. A score with no record behind it may not be "
            "published, so it may not be recorded here either."
        )
    if run.get("evidence") not in EVIDENCE:
        out.append(f"{where}: evidence must be one of {', '.join(EVIDENCE)}.")
    if run.get("unprompted") is not (run.get("evidence") != "directed"):
        out.append(
            f"{where}: a run its author called directed may not be flagged unprompted, "
            "and a run its author did not call directed may not be flagged prompted."
        )
    out.extend(_pair_failures(run, where))
    return out


def headline(run: dict[str, Any]) -> str:
    """The figure a run is known by. Every other figure it carries is a
    qualification of this one."""
    for figure in run.get("figures", []):
        if figure.get("role") == "score":
            return str(figure.get("figure", ""))
    return ""


def _figure_shape_failures(run: dict[str, Any], where: str) -> list[str]:
    figures: list[dict[str, Any]] = run.get("figures", [])
    out = [
        f"{where}: the figure {f.get('figure')!r} must be spelled exactly as posted, "
        "as 'N/M', and must name at least one document that carries it."
        for f in figures
        if not SCORE.match(str(f.get("figure", ""))) or not f.get("carriedIn")
    ]
    scores = [f for f in figures if f.get("role") == "score"]
    if len(scores) != 1:
        out.append(
            f"{where}: exactly one figure is the run's headline (role 'score'); "
            f"{len(scores)} are."
        )
        return out
    carried = {str(c.get("file")) for c in scores[0].get("carriedIn", [])}
    missing = sorted(set(PUBLISHING_DOCS) - carried)
    if missing:
        out.append(
            f"{where}: the headline figure is not recorded as carried in "
            f"{', '.join(missing)}. Both documents publish this column, so both state "
            "the figure or the run has no business being cited in either."
        )
    return out


def _pair_failures(run: dict[str, Any], where: str) -> list[str]:
    out: list[str] = []
    for value, note in SOURCED_OR_EXPLAINED:
        has_value = run.get(value) is not None
        has_note = run.get(note) is not None
        if has_value == has_note:
            out.append(
                f"{where}: exactly one of {value} and {note} must be set. Recording "
                "neither leaves a reader unable to tell an unrecorded fact from an "
                "overlooked field; recording both says the value is and is not known."
            )
    return out


# An attempt is a dispatch that ran and returned no figure, and the closed set of
# ways that can happen is spelled once here so the file cannot say the same thing
# two ways. `withheld` is a gate refusing publication, `completed-no-figure` is a
# run that finished and publishes no score by its own design, and `void` is a
# dispatch that never reached a terminal state.
ATTEMPT_OUTCOMES = ("withheld", "completed-no-figure", "void")
# Exactly the keys an attempt carries, asserted as a set rather than checked one
# at a time. An unexpected key fails as loudly as a missing one, because the
# whole point of this shape is that a reader can tell an unrecorded fact from an
# overlooked field, and a row carrying a field nothing here reads is the second
# thing wearing the clothes of the first. `suiteRevision` is absent on purpose
# and its absence is enforced: the not-run set is computed over `runs`, so a
# suiteRevision on an attempt would shrink that set and let a dispatch with no
# figure license the figure it does not have.
ATTEMPT_FIELDS = frozenset(
    {
        "attempt",
        "implementation",
        "suiteCommit",
        "suiteCommitNote",
        "checkerRef",
        "checkerSourceDigest",
        "digestNote",
        "packet",
        "dispatch",
        "date",
        "dateNote",
        "outcome",
        "figures",
        "figuresNote",
        "artifacts",
        "posting",
        "note",
    }
)
# Every locator an attempt records is a URL that was resolved before it was
# written down. A bare identifier would be a fact nobody can check from here.
URL = re.compile(r"^https://\S+$")
# `.../actions/runs/35194072925` -- the dispatch identifier, which is what the
# prose check below looks for in the two publishing documents.
RUN_ID = re.compile(r"/actions/runs/(\d+)")
SENTENCE = re.compile(r"(?<=[.!?]) ")
# A figure as the prose states one. Reused against a sentence rather than a whole
# field, so it is not anchored like SCORE is.
FIGURE_IN_PROSE = re.compile(r"\b\d+/\d+\b")


def attempt_failures(attempts: list[dict[str, Any]]) -> list[str]:
    """Every attempt carries the whole shape, and no attempt carries a figure."""
    out: list[str] = []
    seen: set[str] = set()
    for attempt in attempts:
        name = str(attempt.get("attempt", "")).strip()
        where = f"attempt {name or '(unnamed)'}"
        if not name:
            out.append(
                f"{where}: names no attempt. A dispatch nothing can be referred to by "
                "cannot be discussed in the thread it was authorised in."
            )
        elif name in seen:
            out.append(f"{where}: recorded twice; one row per dispatch.")
        seen.add(name)
        out.extend(_attempt_shape_failures(attempt, where))
        out.extend(_pair_failures(attempt, where))
    return out


def _attempt_shape_failures(attempt: dict[str, Any], where: str) -> list[str]:
    out: list[str] = []
    keys = set(attempt)
    for missing in sorted(ATTEMPT_FIELDS - keys):
        out.append(
            f"{where}: carries no {missing}. This file records null beside a note "
            "rather than leaving a field out, because an absent field and an "
            "unrecorded fact read the same in a diff."
        )
    for extra in sorted(keys - ATTEMPT_FIELDS):
        reason = (
            "the not-run set is computed over the runs array, so a suiteRevision here "
            "would shrink it and let a dispatch with no figure license one"
            if extra == "suiteRevision"
            else "nothing here reads it, so it is a fact recorded where no check can see it"
        )
        out.append(f"{where}: carries an unexpected field {extra!r}: {reason}.")
    out.extend(_attempt_value_failures(attempt, where))
    return out


def _attempt_value_failures(attempt: dict[str, Any], where: str) -> list[str]:
    out: list[str] = []
    if attempt.get("figures") is not None:
        out.append(
            f"{where}: figures must be null. An attempt is a dispatch that returned no "
            "figure; a row that carries one is a run, and a run belongs in the runs "
            "array where the not-run set and the carried-in counts can check it."
        )
    if not str(attempt.get("figuresNote", "") or "").strip():
        out.append(
            f"{where}: figures is null and figuresNote says nothing. The note is what "
            "makes the null a record rather than a gap."
        )
    if attempt.get("outcome") not in ATTEMPT_OUTCOMES:
        out.append(
            f"{where}: outcome must be one of {', '.join(ATTEMPT_OUTCOMES)}, so that "
            "'it produced no score' cannot be written two ways."
        )
    for field in ("packet", "dispatch", "posting"):
        if not URL.match(str(attempt.get(field, ""))):
            out.append(
                f"{where}: {field} must be a resolved https URL. An identifier nobody "
                "can follow from here is not a record of anything."
            )
    out.extend(_artifact_failures(attempt.get("artifacts"), where))
    if not str(attempt.get("note", "") or "").strip():
        out.append(f"{where}: carries no note saying what the dispatch was and was not.")
    return out


def _artifact_failures(artifacts: Any, where: str) -> list[str]:
    if not isinstance(artifacts, list) or not artifacts:
        return [
            f"{where}: artifacts must list at least one location. What an attempt "
            "leaves behind is the only thing a reader can check it against, and where "
            "that expires belongs beside it."
        ]
    out: list[str] = []
    for artifact in artifacts:
        if not URL.match(str(artifact.get("url", ""))):
            out.append(f"{where}: an artifact names no resolved https url.")
        if not str(artifact.get("retention", "") or "").strip():
            out.append(
                f"{where}: the artifact {artifact.get('url')!r} records no retention. "
                "An artifact with no expiry beside it reads as permanent, and these "
                "are not."
            )
    return out


def attempt_prose_failures(attempts: list[dict[str, Any]]) -> list[str]:
    """An attempt licenses no figure, and the two publishing documents are read
    for the one way that can be broken by prose alone.

    The ledger checks above stop an attempt from CARRYING a figure. They say
    nothing about a paragraph that names the dispatch and a score in one breath,
    which is how a run that measured nothing about this corpus would come to read
    as one that did. So for every attempt, any sentence in either publishing
    document that names its dispatch identifier must state no figure. This is a
    match on a sentence rather than a reading of an argument, and it is deliberately
    the narrowest thing that closes the gap: it does not decide whether a nearby
    paragraph leans on the attempt, which would be measuring prose shape.
    """
    out: list[str] = []
    for rel in PUBLISHING_DOCS:
        text = read(REPO_ROOT / rel)
        for sentence in SENTENCE.split(text):
            out.extend(_sentence_failures(attempts, rel, sentence))
    return out


def _sentence_failures(attempts: list[dict[str, Any]], rel: str, sentence: str) -> list[str]:
    figures = FIGURE_IN_PROSE.findall(sentence)
    if not figures:
        return []
    out: list[str] = []
    for attempt in attempts:
        found = RUN_ID.search(str(attempt.get("dispatch", "")))
        if found and found.group(1) in sentence:
            out.append(
                f"{rel}: a sentence names the dispatch of attempt "
                f"{attempt.get('attempt')!r} and the figure(s) {', '.join(figures)}. "
                "That dispatch returned no figure, and this file records why beside a "
                "null; a sentence carrying both invites a reader to take one as the "
                "other."
            )
    return out

def ledger_failures(runs: list[dict[str, Any]], current: int) -> list[str]:
    out: list[str] = []
    seen: set[int] = set()
    for run in runs:
        out.extend(_run_field_failures(run, current))
        rev = run.get("suiteRevision")
        if isinstance(rev, int):
            if rev in seen:
                out.append(f"suiteRevision {rev} is recorded twice; one row per run.")
            seen.add(rev)
    return out


def not_run(runs: list[dict[str, Any]], current: int) -> list[int]:
    ran = {r["suiteRevision"] for r in runs if isinstance(r.get("suiteRevision"), int)}
    return [n for n in range(1, current + 1) if n not in ran]


def site_failures(site: Site, expected: list[int]) -> list[str]:
    pattern = re.compile(re.escape(site.opens) + f"({ENUMERATION})" + re.escape(site.closes))
    hits = pattern.findall(read(site.path))
    rel = site.path.relative_to(REPO_ROOT)
    if len(hits) != site.occurrences:
        return [
            f"{rel}: {site.label} was found {len(hits)} time(s), expected "
            f"{site.occurrences}. The claim is matched on the words around it "
            f"({site.opens.strip()!r} ... {site.closes.strip()!r}); rewording or "
            "deleting it fails here rather than quietly leaving the set unchecked."
        ]
    return [f"{rel}: {site.label} {why}" for hit in hits for why in _hit_failures(hit, expected)]


def _hit_failures(hit: str, expected: list[int]) -> list[str]:
    read_back = [int(n) for n in re.findall(r"\d+", hit)]
    if read_back != sorted(set(read_back)):
        return [f"lists {hit!r}, which is not in ascending order without repeats."]
    if read_back != expected:
        return [
            f"names suiteRevision(s) {hit!r}, but the ledger has no run for "
            f"{', '.join(str(n) for n in expected)}.\n"
            f"      A reader takes the named set as current and infers the unnamed "
            f"revisions were run. Correct the sentence, or record the missing run in "
            f"docs/INDEPENDENT-RUNS.json with the record and source digest it was "
            f"posted with."
        ]
    return []


def figure_failures(runs: list[dict[str, Any]]) -> list[str]:
    """Every posted figure must still appear, spelled as posted, in every document
    the ledger records as carrying it.

    Checking only the headline is not enough, and that gap is why this reads a
    per-figure list. The qualifications are where a column gets quietly inflated:
    a revision-2 pass reads very differently when the unchanged build scored
    132/138 than when it scored 138/138, and only one of those was posted.
    A run's secondary figures are not required to appear everywhere -- the
    revision-5 148/149 is carried by the changelog alone -- so where each one is
    carried is recorded rather than assumed.

    Presence is not a census either, and where a figure is stated several times
    the count is what closes the gap: asking only whether 153/153 still appears
    somewhere in the README says nothing about the two other places it appears,
    any one of which could be altered under a passing gate. The two publishing
    documents therefore record how many times each figure is stated and the count
    is asserted. ``vectors/CHANGES.md`` records ``null`` and is asked for presence
    only, because it is append-only history: a later entry citing an earlier
    figure legitimately adds a mention, and counting there would turn ordinary
    history-writing red.
    """
    out: list[str] = []
    cache: dict[str, str] = {}
    for run in runs:
        for figure in run.get("figures", []):
            for where in figure.get("carriedIn", []):
                rel = str(where.get("file"))
                text = cache.setdefault(rel, read(REPO_ROOT / rel))
                out.extend(_carried_failures(run, figure, where, rel, text))
    return out


def _carried_failures(
    run: dict[str, Any], figure: dict[str, Any], where: dict[str, Any], rel: str, text: str
) -> list[str]:
    fig = str(figure.get("figure"))
    said = f"{fig} as the {figure.get('role')} figure at suiteRevision {run['suiteRevision']}"
    want = where.get("times")
    found = text.count(fig)
    if want is None:
        return [] if found else [f"{rel}: the ledger records {said}, and it does not appear here."]
    if found != want:
        return [
            f"{rel}: the ledger records {said} as stated {want} time(s) here, and it "
            f"is stated {found}. Either a mention was altered, which is the defect "
            "this count exists to catch, or one was legitimately added or removed and "
            "the ledger has not been told."
        ]
    return []


def unprompted_failures(runs: list[dict[str, Any]], report: str) -> list[str]:
    """The figures that carry unprompted evidence are named as such in the
    report, and the ledger is what says which ones they are."""
    out: list[str] = []
    for run in runs:
        if not run.get("unprompted"):
            continue
        spelling = f"{headline(run)} at suiteRevision {run.get('suiteRevision')}"
        if spelling not in report:
            out.append(
                f"docs/IMPLEMENTATION-REPORT.md: the ledger calls {spelling} unprompted "
                "evidence, and the report does not name it that way."
            )
    return out


def quote_failures(quotes: list[dict[str, Any]]) -> list[str]:
    """The author's wording, verbatim, wherever this repository says it carries it.

    Two checks, and they protect different things.

    The verbatim check is the one that protects every quotation: the recorded text
    must appear, character for character after whitespace collapsing, in every
    document the row says carries it. Alter a published quotation by one word and
    it fails here. That check needs nothing but the row itself, so it holds for a
    quotation nothing else in the file relates to.

    The containment check protects a quotation against the OTHER excerpts of the
    same utterance. Where this repository carries a long form in one document and a
    shorter cut of it in another -- which it does, because the README states the
    author's full sentence and the report and changelog carry the clause -- the
    shorter one must be a contiguous substring of the fullest form, so a document
    cannot quietly carry a paraphrase that reads like a quotation of the same
    sentence. Both would still pass the verbatim check, because both would be
    faithfully reproduced from the ledger; it is only their disagreement with each
    other that shows one has drifted.

    That property is about ONE utterance, and it was originally written over the
    whole file: a single global longest, with every quotation required to be a
    substring of it. That only ever holds while the file records excerpts of one
    sentence. The moment a second run's author is quoted, the two quotations are
    unrelated wordings and neither contains the other, so registering a correct
    quotation failed -- and the sentence quoted from the revision-25 run was
    published in two documents while being unregisterable here, which is the
    protection mechanism preventing protection. The fix is to compute the fullest
    form per utterance rather than per file, which keeps the drift check exactly
    where it means something and removes the coupling between utterances that never
    meant anything.

    ``utterance`` is what names the group, not ``about``. ``about`` is the
    suiteRevision the quotation is about, and one run's author can say more than one
    thing; grouping on it would reinstate the same defect one level down, where two
    genuine quotations from one run would be required to contain each other. Rows
    sharing an utterance must agree on ``about``, because a disagreement there means
    one of them is mislabelled.

    A single-member group is checked by the verbatim rule and by nothing else: it is
    trivially its own fullest form. That is not a gap this check can close, because
    with one excerpt on record there is no second reading to disagree with. It is
    recorded here so that a lone quotation is not mistaken for one holding two
    independent checks.
    """
    out: list[str] = []
    groups: dict[str, list[dict[str, Any]]] = {}
    for quote in quotes:
        utterance = str(quote.get("utterance", "")).strip()
        if not utterance:
            out.append(
                f"docs/INDEPENDENT-RUNS.json: the recorded wording "
                f"{normalize(str(quote['text']))[:60]!r}... names no utterance. The "
                "fullest-form check is computed per utterance, so a row without one "
                "would be compared against unrelated wordings or against nothing."
            )
            continue
        groups.setdefault(utterance, []).append(quote)
    for utterance, group in groups.items():
        out.extend(_utterance_failures(utterance, group))
    for quote in quotes:
        text = normalize(str(quote["text"]))
        out.extend(
            f"{rel}: does not carry the author's wording verbatim: {text[:72]!r}..."
            for rel in quote.get("carriedIn", [])
            if text not in read(REPO_ROOT / str(rel))
        )
    return out


def _utterance_failures(utterance: str, group: list[dict[str, Any]]) -> list[str]:
    """Every excerpt of one utterance is a cut of the fullest one recorded of it."""
    out: list[str] = []
    abouts = sorted({str(q.get("about")) for q in group})
    if len(abouts) > 1:
        out.append(
            f"docs/INDEPENDENT-RUNS.json: the excerpts of {utterance!r} are recorded "
            f"as being about suiteRevision(s) {', '.join(abouts)}. One utterance is "
            "about one run, so one of these rows is mislabelled."
        )
    longest = max((normalize(str(q["text"])) for q in group), key=len)
    for quote in group:
        text = normalize(str(quote["text"]))
        if text not in longest:
            out.append(
                f"docs/INDEPENDENT-RUNS.json: the recorded wording {text[:60]!r}... is "
                f"not an excerpt of the fullest wording recorded of {utterance!r}, so "
                "one of the two is a paraphrase."
            )
    return out


def current_revision_failures(report: str, current: int) -> list[str]:
    out: list[str] = []
    for template, want in CURRENT_REVISION_LITERALS:
        literal = template.format(n=current)
        found = report.count(literal)
        if found != want:
            out.append(
                f"docs/IMPLEMENTATION-REPORT.md: {literal!r} appears {found} time(s), "
                f"expected {want}. vectors/CHANGES.md says the corpus is at "
                f"suiteRevision {current}, and the report restates that number here."
            )
    return out


def collect() -> tuple[list[str], int, list[int], int]:
    current, failures = current_revision()
    if failures:
        return failures, current, [], 0
    ledger: dict[str, Any] = json.loads(LEDGER.read_text(encoding="utf-8"))
    runs: list[dict[str, Any]] = ledger["runs"]
    failures = ledger_failures(runs, current)
    # The attempts array is required to exist, empty or not. Made optional it
    # would be indistinguishable from a file nobody has taught the shape to, and
    # the reason this array exists at all is that a dispatch returning nothing
    # used to be recorded nowhere.
    if "attempts" not in ledger:
        failures.append(
            "docs/INDEPENDENT-RUNS.json: carries no attempts array. A dispatch that "
            "ran and returned no figure has no shape in the runs array, because every "
            "row there carries figures; recording it nowhere is the gap this array "
            "closes, and an absent array and no attempts read the same in a diff."
        )
    attempts: list[dict[str, Any]] = ledger.get("attempts") or []
    failures.extend(attempt_failures(attempts))
    if failures:
        return failures, current, [], len(attempts)
    expected = not_run(runs, current)
    report = read(REPORT)
    for site in SITES:
        failures.extend(site_failures(site, expected))
    failures.extend(figure_failures(runs))
    failures.extend(unprompted_failures(runs, report))
    failures.extend(quote_failures(ledger["quotedWording"]))
    failures.extend(current_revision_failures(report, current))
    failures.extend(attempt_prose_failures(attempts))
    return failures, current, expected, len(attempts)


def main() -> int:
    failures, current, expected, attempts = collect()
    if failures:
        print(
            f"FAIL: {len(failures)} independent-run claim(s) do not hold:",
            file=sys.stderr,
        )
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print(
            "\ndocs/INDEPENDENT-RUNS.json is the record and the prose is derived from "
            "it. Never close one of these by adding a run that was not posted with a "
            "record and a source digest: an inaccurate independence claim is worse "
            "than no claim.",
            file=sys.stderr,
        )
        return 1
    listed = ", ".join(str(n) for n in expected) if expected else "none"
    print(
        f"OK: the corpus is at suiteRevision {current}; the independent checker has "
        f"posted no run for suiteRevision(s) {listed}, and every published claim "
        f"names exactly that set. {attempts} dispatch(es) that returned no figure are "
        "recorded as attempts, and none of them licenses one."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
