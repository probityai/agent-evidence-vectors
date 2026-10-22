#!/usr/bin/env python3
"""The count census, as a library: check declared claims, then refuse an
unaccounted count-shaped integer.

This module holds the MECHANISM. It holds no claim, no source path, no frozen
figure and no vocabulary about any particular corpus, because a second consumer
now runs the same rule over a different subject and two implementations of one
rule drifting apart is the defect class this repository has hit most often.

scripts/count-gate.py is the first consumer and its header argues the design at
length -- why the published counts are CHECKED and never emitted, why a census
is needed on top of the declared claims, what makes an integer count-shaped, the
five routes by which one is accounted for, and what the whole arrangement still
cannot catch. Read that file, not this one, for the argument. What follows here
is only what a consumer has to supply.

A consumer supplies four things:

  Quantities   what the sources currently publish (value -> what it is), what
               they have published before (value -> the attributions carrying
               it), and any exact figure some ledger records verbatim.
  the texts    the tracked files to read, from ``read_tracked``.
  Census       the masking rules, the count nouns, the small-value vocabulary,
               and the accounting routes that are not spans.
  declarations the Claim, Delegated and Frozen tables, which are statements
               somebody made on purpose about that consumer's own prose.

Nothing here reads a repository by itself. Every path arrives as an argument, so
a consumer may point the census at its own tree, at a sibling's, or at a staged
copy, and the gate's own tests can mutate a copy without touching the tree they
are testing.
"""

from __future__ import annotations

import io
import re
import subprocess
import tokenize
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------
# What a consumer declares
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Claim:
    """One published sentence carrying a derived count.

    ``opens`` and ``closes`` are the fixed prose either side of the value and
    ``expected`` is what the sources say belongs between them. ``occurrences`` is
    how many times the shape must appear: asserting the count is what makes a
    deleted claim, a reworded one, or a second copy that will then rot on its own
    fail here rather than pass unchecked.
    """

    path: str
    label: str
    opens: str
    closes: str
    expected: str
    occurrences: int = 1


@dataclass(frozen=True)
class Delegated:
    """A count-shaped span another gate already owns.

    Recorded rather than re-checked. Two gates checking one fact is harmless;
    two gates holding one ledger is not, and the value behind each of these comes
    from a ledger that is not this census's.
    """

    path: str
    label: str
    pattern: str
    owner: str


@dataclass(frozen=True)
class Frozen:
    """A figure that records a past event and must NOT track the source.

    An incident is not a measurement of the thing as it stands: a run that scored
    what it scored against the corpus of the day scored that, and rewriting the
    figure when the corpus grows would be inventing a rerun nobody did. Each entry
    carries the reason, and the occurrence count is asserted so that a copy of the
    sentence appearing somewhere new fails here.
    """

    path: str
    label: str
    text: str
    reason: str
    occurrences: int = 1


@dataclass(frozen=True)
class Covered:
    """One span of a file some declaration accounts for."""

    start: int
    end: int
    why: str


@dataclass(frozen=True)
class Token:
    """One count-shaped integer, with why it is count-shaped."""

    start: int
    end: int
    values: tuple[int, ...]
    figure: str
    trigger: str


# --------------------------------------------------------------------------
# What the sources say
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Quantities:
    """Every value a consumer's sources entitle it to publish.

    ``current`` drives the VALUE trigger: an integer equal to something the
    sources publish today is count-shaped wherever it appears, because a count
    that was CORRECT when it was written necessarily equals the source.

    ``historical`` is value -> the attributions whose ledger row carries it, and
    it is what lets a writer date a number in the prose itself. ``posted`` holds
    figures spelled exactly as some ledger records them, which is a different
    kind of accounting from a value: it is the string, not the integer.
    """

    current: Mapping[int, str]
    historical: Mapping[int, set[int]] = field(default_factory=dict)
    #: Values in ``current`` that are count-shaped only beside a count noun,
    #: the way a value below ``Census.small_value`` is. A per-kind count of a
    #: secondary corpus is one small integer among many a document uses for
    #: other things, and read bare it refused prose about pairs, line ranges
    #: and issue numbers every time a corpus grew into that value.
    noun_bound: frozenset[int] = frozenset()
    posted: frozenset[str] = frozenset()
    posted_why: str = "a figure a ledger records as posted"


# --------------------------------------------------------------------------
# What makes an integer count-shaped
# --------------------------------------------------------------------------

RATIO = re.compile(r"\b(\d{1,4})\s*(?:/|\s+of\s+)\s*(\d{1,4})\b")
INTEGER = re.compile(r"\b\d{1,4}\b")

# The route that resolves a token by where it sits rather than by a declared
# span: given the file, its text and the token, either a reason or None.
ScopeRoute = Callable[[str, str, Token, Quantities], str | None]


@dataclass(frozen=True)
class Census:
    """The rules by which a consumer's prose is read.

    ``masks`` blank out digit-carrying forms that are not counts, to same-length
    filler, so every offset into the file stays exact. ``nouns`` pair a pattern
    whose first group is a digit run with the sentence naming what it counts.
    ``attribution`` is the pattern by which a sentence dates a number to a
    revision it names; ``scope_route`` is any further route a consumer needs, for
    prose whose position settles the question.

    ``measures`` are the contexts that make an integer a MEASUREMENT -- a length,
    a width, a size or an index -- and so not a count of anything. They are read
    by the VALUE trigger only, and that is the whole difference from a mask. The
    VALUE trigger is the one that fires on an integer for its value alone, and a
    value alone cannot tell `64 vectors` from `64 hex characters`: both equal a
    corpus that holds 64 members, and only the words beside the integer say which
    one counts the corpus. A measure says so positively, from a unit or a syntax
    that measures. Everything else stays count-shaped, including a bare integer
    whose context says nothing either way, so an ambiguous integer still needs an
    explicit account. The ratio and noun triggers do not consult this list,
    because their context already states a count.
    """

    masks: tuple[re.Pattern[str], ...]
    nouns: tuple[tuple[re.Pattern[str], str], ...]
    small_value_nouns: re.Pattern[str]
    measures: tuple[re.Pattern[str], ...] = ()
    small_value: int = 20
    small_value_window: int = 32
    attribution: re.Pattern[str] | None = None
    attribution_why: str = "revision-attributed by the sentence it sits in"
    scope_route: ScopeRoute | None = None
    self_files: Mapping[str, str] = field(default_factory=dict)


# --------------------------------------------------------------------------
# Reading the tree
# --------------------------------------------------------------------------


class TrackedUnreadable(RuntimeError):
    """A tracked path whose content could be read from neither place it lives.

    Raised rather than skipped. A census that dropped the file would report the
    figures in it as examined when nothing examined them, and would pass.
    """


#: Git modes whose blob is a file's bytes. A gitlink (160000) is a commit in
#: another repository and a symlink (120000) is the text of its target, so
#: neither can stand in for a file that is absent from disk.
_FILE_MODES = frozenset({"100644", "100755"})


def _git(repo_root: Path, *args: str, stdin: bytes | None = None) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo_root), *args],
        input=stdin,
        capture_output=True,
        check=True,
    ).stdout


def tracked_modes(repo_root: Path, ref: str | None = None) -> dict[str, tuple[str, str]]:
    """Every tracked path mapped to (mode, blob id).

    With no ``ref`` this is the index, which is what ``git ls-files`` lists;
    with one it is the tree at that ref. NUL-separated, so a path holding a
    space or a non-ASCII byte is one path and not several.
    """
    out: dict[str, tuple[str, str]] = {}
    if ref is None:
        # `<mode> <object> <stage>\t<path>`. An unmerged path carries stages
        # 1-3 and no stage 0; the lowest stage present stands for it, so the
        # path is still listed exactly once, as `ls-files` lists it.
        for entry in _git(repo_root, "ls-files", "-s", "-z").split(b"\0"):
            if not entry:
                continue
            meta, _, name = entry.partition(b"\t")
            mode, blob, stage = meta.decode("ascii").split()
            rel = name.decode("utf-8", "surrogateescape")
            if rel not in out or stage == "0":
                out[rel] = (mode, blob)
        return out
    # `<mode> <type> <object>\t<path>`
    for entry in _git(repo_root, "ls-tree", "-r", "-z", ref).split(b"\0"):
        if not entry:
            continue
        meta, _, name = entry.partition(b"\t")
        mode, _kind, blob = meta.decode("ascii").split()
        out[name.decode("utf-8", "surrogateescape")] = (mode, blob)
    return out


def tracked_files(repo_root: Path, ref: str | None = None) -> list[str]:
    """Everything git tracks, which is deliberately not everything on disk.

    A census that walked the filesystem would scan build output and a stale
    working copy and report a coverage it never had.
    """
    return sorted(tracked_modes(repo_root, ref))


def read_blobs(repo_root: Path, blobs: Mapping[str, str]) -> dict[str, bytes]:
    """The bytes of each blob, keyed as given, from ONE `git cat-file --batch`.

    A blob the object store does not hold is a refusal naming the path, never
    an empty file: that is what a promisor-less partial clone or a pruned
    object looks like, and an empty string would count as a file read.
    """
    wanted = sorted(set(blobs.values()))
    if not wanted:
        return {}
    raw = _git(repo_root, "cat-file", "--batch", stdin="".join(f"{b}\n" for b in wanted).encode())
    found: dict[str, bytes] = {}
    at = 0
    for blob in wanted:
        end = raw.index(b"\n", at)
        header = raw[at:end].decode("ascii").split()
        at = end + 1
        if len(header) != 3 or header[1] != "blob" or header[0] != blob:
            names = sorted(rel for rel, b in blobs.items() if b == blob)
            raise TrackedUnreadable(
                f"{', '.join(names)} is tracked as {blob}, and the object store "
                f"answered {' '.join(header)!r}. It is absent from disk too, so its "
                "text was read from nowhere and the census refuses rather than "
                "count it as read."
            )
        size = int(header[2])
        found[blob] = raw[at : at + size]
        at += size + 1
    return {rel: found[blob] for rel, blob in blobs.items()}


class TrackedTree:
    """The tracked files of one checkout, readable whether or not they are on disk.

    WHY THIS EXISTS (2026-09-27). Every read here used to be `open()` on the
    working tree, and a lane worktree is now a SPARSE checkout: full checkouts
    are refused once a disk is under its floor, so a lane materialises only the
    paths it edits. A tracked file outside the cone is in the index and in HEAD
    and absent from disk, and the census died on it with FileNotFoundError --
    which blocked every send from every sparse lane, since the consumer gate
    reads the whole outbound set, not only the lane's own files. Skipping the
    absent file is not a repair: the census would then under-count and pass.

    THE RULE FOR WHICH BYTES A PATH READS AS:

      * present on disk as a regular file -> the DISK bytes. An unmodified file
        is byte-identical to its blob, so this changes nothing for it; a file
        with an uncommitted edit -- the body a send is about to post -- is read
        as edited, which is what every consumer read before this class existed.
      * tracked and absent from disk -> the BLOB recorded for it: in the index
        when ``ref`` is None, which is what ``git ls-files`` lists, or in the
        tree at ``ref`` when the consumer's subject set is a commit. Absent
        covers a sparse-checkout exclusion, a skip-worktree bit, and a file
        deleted and not yet committed alike, and in each the recorded blob is
        the file's tracked content.
      * neither -> not a file. ``is_file`` says False and ``read_bytes`` raises.

    So a sparse checkout reads exactly what a full checkout of the same commit
    reads, and the census counts the same integers in both.
    """

    def __init__(self, repo_root: Path, ref: str | None = None) -> None:
        self.root = repo_root
        self.ref = ref
        self.modes = tracked_modes(repo_root, ref)
        self._blobs: dict[str, bytes] = {}
        # directory -> the names directly inside it, built once: a consumer asks
        # this for every directory holding a subject file, thousands per run.
        self.children: dict[str, set[str]] = {}
        for rel in self.modes:
            child = rel
            parent = rel.rpartition("/")[0]
            while True:
                seen = parent in self.children
                self.children.setdefault(parent, set()).add(child.rpartition("/")[2])
                if seen or not parent:
                    break
                child, parent = parent, parent.rpartition("/")[0]

    def on_disk(self, rel: str) -> bool:
        return (self.root / rel).is_file()

    def is_file(self, rel: str) -> bool:
        if self.on_disk(rel):
            return True
        entry = self.modes.get(rel)
        return entry is not None and entry[0] in _FILE_MODES

    def is_dir(self, rel: str) -> bool:
        return rel in self.children or (self.root / rel).is_dir()

    def names(self, rel: str) -> list[str]:
        """The entries directly inside directory ``rel``: on disk, tracked, or both."""
        found = set(self.children.get(rel, ()))
        directory = self.root / rel
        if directory.is_dir():
            found |= {child.name for child in directory.iterdir()}
        return sorted(found)

    def prefetch(self, rels: Iterable[str]) -> None:
        """Read every absent tracked path in ``rels`` with one batch call."""
        pending = {
            rel: self.modes[rel][1]
            for rel in rels
            if rel not in self._blobs
            and rel in self.modes
            and self.modes[rel][0] in _FILE_MODES
            and not self.on_disk(rel)
        }
        self._blobs.update(read_blobs(self.root, pending))

    def read_bytes(self, rel: str) -> bytes:
        if self.on_disk(rel):
            return (self.root / rel).read_bytes()
        entry = self.modes.get(rel)
        if entry is None:
            raise FileNotFoundError(
                f"{rel} is neither on disk nor tracked at {self.ref or 'the index'} in {self.root}"
            )
        if entry[0] not in _FILE_MODES:
            raise TrackedUnreadable(
                f"{rel} is absent from disk and tracked with mode {entry[0]}, "
                "which is not a file's bytes, so it has no text to read."
            )
        if rel not in self._blobs:
            self.prefetch([rel])
        return self._blobs[rel]

    def read_text(self, rel: str) -> str:
        return self.read_bytes(rel).decode("utf-8")


def read_tracked(
    repo_root: Path,
    suffixes: Iterable[str],
    exempt: Mapping[str, str] | None = None,
    exempt_prefixes: Mapping[str, str] | None = None,
    paths: Sequence[str] | None = None,
    ref: str | None = None,
) -> dict[str, str]:
    """The tracked text this census reads, keyed by path relative to the root.

    ``paths`` narrows the set to an explicit list, for a consumer whose subject
    is a named surface rather than a whole repository; without it every tracked
    file of a listed suffix is read. Content follows :class:`TrackedTree`'s
    rule, so a sparse checkout reads what a full one reads.

    A named path that is neither on disk nor tracked is ABSENT from the result
    rather than an error, and every named-path consumer compares the keys it
    got against the paths it asked for and reports the difference by name. A
    tracked path whose content cannot be read raises :class:`TrackedUnreadable`.
    """
    wanted = frozenset(suffixes)
    exempt = exempt or {}
    exempt_prefixes = exempt_prefixes or {}
    tree = TrackedTree(repo_root, ref)
    chosen = [
        rel
        for rel in (sorted(tree.modes) if paths is None else paths)
        if rel not in exempt
        and not any(rel.startswith(p) for p in exempt_prefixes)
        and Path(rel).suffix in wanted
        # Tracked, or on disk: a tracked path that is not a file's bytes stays
        # in and raises when read, rather than dropping out of the count here.
        and (rel in tree.modes or tree.on_disk(rel))
    ]
    tree.prefetch(chosen)
    return {rel: tree.read_text(rel) for rel in chosen}


def prose_regions(rel: str, text: str) -> list[tuple[int, int]]:
    """The regions of a file that are prose a reader is offered.

    Markdown, YAML and TOML are prose throughout. Python contributes its comments
    and string literals, which is where its gates publish their arguments and
    their refusal messages. Go contributes its comments only.
    """
    suffix = Path(rel).suffix
    if suffix == ".py":
        return python_prose(text)
    if suffix == ".go":
        return [m.span() for m in re.finditer(r"//[^\n]*|/\*[\s\S]*?\*/", text)]
    return [(0, len(text))]


def python_prose(text: str) -> list[tuple[int, int]]:
    starts = line_starts(text)
    regions: list[tuple[int, int]] = []
    try:
        tokens = list(tokenize.generate_tokens(io.StringIO(text).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        # A file this census cannot tokenize is a file it cannot claim to have read.
        raise SystemExit(
            "FAIL: a tracked Python file did not tokenize, so its prose was not "
            "scanned. A census that silently skips a file reports an absence it "
            "never measured."
        ) from None
    for token in tokens:
        if token.type not in (tokenize.COMMENT, tokenize.STRING):
            continue
        start = starts[token.start[0] - 1] + token.start[1]
        end = starts[token.end[0] - 1] + token.end[1]
        regions.append((start, end))
    return regions


def line_starts(text: str) -> list[int]:
    starts = [0]
    for index, char in enumerate(text):
        if char == "\n":
            starts.append(index + 1)
    return starts


# --------------------------------------------------------------------------
# Half one: the declared claims
# --------------------------------------------------------------------------


def flex(text: str) -> str:
    """A pattern matching ``text`` with every whitespace run free to rewrap.

    Repository files are hard-wrapped and rewrapped freely, so a claim matched on
    literal bytes would fail on a reflow that changed nothing. Leading and
    trailing whitespace is preserved as a requirement, which is what keeps
    ``"and empty), all "`` from matching ``"...all"`` with no separator.
    """
    parts = re.split(r"(\s+)", text)
    return "".join(r"\s+" if part.isspace() else re.escape(part) for part in parts)


def claim_pattern(opens: str, closes: str) -> re.Pattern[str]:
    return re.compile(flex(opens) + r"([\s\S]{0,80}?)" + flex(closes))


def normalize(text: str) -> str:
    return " ".join(text.split())


def check_claims(
    declared: Sequence[Claim], texts: Mapping[str, str]
) -> tuple[list[str], dict[str, list[Covered]]]:
    """Check every declared claim, and record the spans they account for."""
    failures: list[str] = []
    covered: dict[str, list[Covered]] = {}
    for claim in declared:
        text = texts.get(claim.path)
        if text is None:
            failures.append(
                f"{claim.path}: {claim.label} is declared against a file this gate "
                "does not read. Either the file moved or the declaration is wrong; "
                "an unreadable claim site is a check that cannot run."
            )
            continue
        hits = list(claim_pattern(claim.opens, claim.closes).finditer(text))
        if len(hits) != claim.occurrences:
            failures.append(
                f"{claim.path}: {claim.label} was found {len(hits)} time(s), expected "
                f"{claim.occurrences}. The claim is matched on the words around it "
                f"({normalize(claim.opens)!r} ... {normalize(claim.closes)!r}); "
                "rewording or deleting it fails here rather than quietly leaving the "
                "count unchecked."
            )
            continue
        for hit in hits:
            covered.setdefault(claim.path, []).append(
                Covered(hit.start(), hit.end(), f"the declared claim {claim.label!r}")
            )
            if normalize(hit.group(1)) != normalize(claim.expected):
                failures.append(
                    f"{claim.path}: {claim.label} says {normalize(hit.group(1))!r} "
                    f"where the sources say {normalize(claim.expected)!r}."
                )
    return failures, covered


def check_declarations(
    delegated: Sequence[Delegated],
    frozen_spans: Sequence[Frozen],
    texts: Mapping[str, str],
    covered: dict[str, list[Covered]],
) -> list[str]:
    """Delegated and frozen spans: find them, or say they are gone.

    A declaration that matches nothing is not a harmless leftover. It is a span
    this gate reports as accounted for, over prose that no longer exists.
    """
    failures: list[str] = []
    for spec in delegated:
        text = texts.get(spec.path, "")
        hits = list(re.finditer(spec.pattern, text))
        if not hits:
            failures.append(
                f"{spec.path}: {spec.label} is delegated to {spec.owner} and no longer "
                "appears. Either it was reworded, in which case both gates need "
                "telling, or it was deleted and this delegation is now a span nothing "
                "owns."
            )
        for hit in hits:
            covered.setdefault(spec.path, []).append(
                Covered(hit.start(), hit.end(), f"owned by {spec.owner}")
            )
    for frozen in frozen_spans:
        text = texts.get(frozen.path, "")
        hits = list(re.finditer(flex(frozen.text), text))
        if len(hits) != frozen.occurrences:
            failures.append(
                f"{frozen.path}: the frozen figure {frozen.label!r} was found "
                f"{len(hits)} time(s), expected {frozen.occurrences}. It is frozen "
                f"because: {frozen.reason} A copy appearing somewhere new is a second "
                "site that will be read as current."
            )
        for hit in hits:
            covered.setdefault(frozen.path, []).append(
                Covered(hit.start(), hit.end(), f"frozen: {frozen.label}")
            )
    return failures


# --------------------------------------------------------------------------
# Half two: the census
# --------------------------------------------------------------------------


def mask(census: Census, text: str) -> str:
    """Blank out the non-count forms, preserving every offset."""
    for pattern in census.masks:
        text = pattern.sub(lambda m: "░" * len(m.group(0)), text)
    return text


def count_tokens(
    census: Census,
    quantities: Quantities,
    masked: str,
    regions: Sequence[tuple[int, int]],
    measured: list[tuple[int, int]] | None = None,
) -> list[Token]:
    """Every count-shaped integer inside the prose regions.

    ``measured``, when given, receives the span of every integer that equals a
    published count and that a measure context excludes. The caller reports how
    many there were, so an exclusion is a number a reader sees, never a silent
    drop.
    """
    live = quantities.current
    found: dict[tuple[int, int], Token] = {}
    for start, end in regions:
        window = masked[start:end]
        measures = [m.span() for pattern in census.measures for m in pattern.finditer(window)]
        for hit in RATIO.finditer(window):
            span = (start + hit.start(), start + hit.end())
            found[span] = Token(
                span[0],
                span[1],
                (int(hit.group(1)), int(hit.group(2))),
                f"{hit.group(1)}/{hit.group(2)}",
                "a ratio, whose denominator is a corpus size by construction",
            )
        for pattern, trigger in census.nouns:
            for hit in pattern.finditer(window):
                span = (start + hit.start(1), start + hit.end(1))
                found.setdefault(
                    span,
                    Token(span[0], span[1], (int(hit.group(1)),), hit.group(1), trigger),
                )
        for hit in INTEGER.finditer(window):
            value = int(hit.group(0))
            if value not in live:
                continue
            span = (start + hit.start(), start + hit.end())
            needs_noun = value < census.small_value or value in quantities.noun_bound
            if needs_noun and not near_noun(census, window, hit.start(), hit.end()):
                continue
            # Checked last, so ``measured`` holds exactly the integers this rule
            # took out and none another rule had already passed over.
            if span not in found and any(
                low <= hit.start() and hit.end() <= high for low, high in measures
            ):
                if measured is not None:
                    measured.append(span)
                continue
            found.setdefault(
                span,
                Token(
                    span[0],
                    span[1],
                    (value,),
                    hit.group(0),
                    f"an integer equal to {live[value]}",
                ),
            )
    return dedupe(sorted(found.values(), key=lambda token: token.start))


def dedupe(tokens: list[Token]) -> list[Token]:
    """A ratio is one token, not three.

    A score written as a fraction fires the ratio trigger over the whole figure
    and the value trigger over each half. Reporting three would ask a writer to
    account for the same figure three times, and the ratio is the form that
    carries the meaning: it is a score, and a run ledger records scores.
    """
    ratios = [token for token in tokens if "/" in token.figure]
    return [
        token
        for token in tokens
        if token in ratios
        or not any(ratio.start <= token.start and token.end <= ratio.end for ratio in ratios)
    ]


def near_noun(census: Census, window: str, start: int, end: int) -> bool:
    around = window[max(0, start - census.small_value_window) : end + census.small_value_window]
    return census.small_value_nouns.search(around) is not None


def sentence_at(text: str, start: int, end: int) -> str:
    """The sentence an integer sits in.

    Bounded by a blank line, a table-cell pipe, or sentence-ending punctuation
    followed by whitespace. Wide enough to carry the revision a writer attributes
    a number to and narrow enough that a revision mentioned three sentences away
    does not.
    """
    left = max(
        (
            text.rfind(bound, 0, start) + len(bound)
            for bound in (". ", ".\n", "; ", ":\n", "\n\n", "|", "**")
            if text.rfind(bound, 0, start) != -1
        ),
        default=0,
    )
    right = min(
        (
            position
            for position in (text.find(bound, end) for bound in (". ", ".\n", "\n\n", "|", "**"))
            if position != -1
        ),
        default=len(text),
    )
    return text[left:right]


def accounted(
    census: Census,
    quantities: Quantities,
    rel: str,
    text: str,
    token: Token,
    spans: Sequence[Covered],
) -> str | None:
    """Why this integer is accounted for, or None if nothing accounts for it."""
    for span in spans:
        if span.start <= token.start and token.end <= span.end:
            return span.why
    if token.figure in quantities.posted:
        return quantities.posted_why
    historical = quantities.historical
    if census.attribution is not None:
        sentence = sentence_at(text, token.start, token.end)
        named = {int(n) for n in census.attribution.findall(sentence)}
        if named and all(
            value in historical and historical[value] & named for value in token.values
        ):
            return census.attribution_why
    if census.scope_route is not None:
        return census.scope_route(rel, text, token, quantities)
    return None


def run_census(
    census: Census,
    quantities: Quantities,
    texts: Mapping[str, str],
    covered: Mapping[str, list[Covered]],
    measured: list[tuple[str, int, int]] | None = None,
) -> tuple[list[str], int]:
    """Refuse every count-shaped integer nothing accounts for.

    Returns the refusals and how many count-shaped integers were examined. The
    second number is the point rather than decoration: a census with an empty
    subject set passes every run while enforcing nothing. ``measured``, when
    given, receives (path, start, end) for every integer a measure context took
    out of the census, for the same reason.
    """
    failures: list[str] = []
    examined = 0
    for rel, text in sorted(texts.items()):
        if rel in census.self_files:
            continue
        regions = prose_regions(rel, text)
        spans_measured: list[tuple[int, int]] = []
        tokens = count_tokens(census, quantities, mask(census, text), regions, spans_measured)
        if measured is not None:
            measured.extend((rel, low, high) for low, high in spans_measured)
        examined += len(tokens)
        spans = covered.get(rel, [])
        starts = line_starts(text)
        for token in tokens:
            if accounted(census, quantities, rel, text, token, spans) is not None:
                continue
            line = sum(1 for start in starts if start <= token.start)
            where = normalize(sentence_at(text, token.start, token.end))[:120]
            failures.append(
                f"{rel}:{line}: {token.figure!r} is {token.trigger}, and nothing "
                f"accounts for it.\n      In: {where!r}"
            )
    return failures, examined
