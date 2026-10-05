#!/usr/bin/env python3
"""Tests for scripts/count-gate.py.

Almost every case below asserts a REFUSAL, and that is the point. This
repository has a documented history of checks that ran green while enforcing
nothing -- a shipped verifier that scored zero against the whole corpus while its
own unit test passed, a drop count that was a hardcoded literal, a conformance
oracle that recorded a crashed evaluation as a denial, and a ground-truth
comparison that agreed with itself because both sides shared a blind spot. A
count gate that could not go red would be the next one, and it would be worse
than the others, because the thing it exists to catch is precisely a number that
looks right.

Every case runs against a STAGED COPY of this repository rather than fixtures,
and never against the repository itself. Fixtures would prove the decision
functions and nothing about whether the gate is pointed at anything: the claims
are declared against real prose in real files, so a fixture tree would fail every
one of them for the wrong reason and a green fixture run would say nothing. The
copy is a real git checkout of the tracked files, one file in it is broken in
exactly one way, and the gate is asked.

The accepting cases are there to show the refusals are not a gate that
refuses everything, and one of them is the case that matters most: a NEW count,
written today, with its revision attributed in the prose, is accepted. If that
failed, the only way to satisfy this gate would be to never write a number, and
a gate nobody can satisfy gets deleted.

Usage: python3 scripts/count-gate-test.py
Exit 0 when every case holds; 1 on the first summary of failures.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "count-gate.py"

Mutation = Callable[[Path], None]
Case = tuple[str, Mutation, tuple[str, ...]]


def stage(destination: Path) -> None:
    """Copy the tracked tree into a fresh git checkout.

    The gate enumerates what it reads with `git ls-files`, which is deliberate --
    a census that walked the filesystem would scan build output and a stale
    working copy and report a coverage it never had. So the copy has to be a git
    repository too, and staging it is what makes the copy's file list the same
    list the real gate would see.
    """
    listed = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "ls-files"],
        capture_output=True,
        text=True,
        check=True,
    )
    for rel in listed.stdout.split():
        source = REPO_ROOT / rel
        if not source.is_file():
            continue
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    for command in (
        ["git", "init", "-q"],
        ["git", "add", "-A"],
    ):
        subprocess.run(command, cwd=destination, check=True, capture_output=True)


def run(root: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(GATE), "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def edit(root: Path, rel: str, old: str, new: str) -> None:
    """Replace exactly one occurrence, or refuse to run a case that asserts nothing.

    A mutation that silently matched nothing would leave the copy correct, the
    gate green, and the case recorded as a passing refusal test. That is the
    shape this whole file exists to keep out of the repository.
    """
    path = root / rel
    text = path.read_text(encoding="utf-8")
    if text.count(old) != 1:
        raise SystemExit(
            f"test setup: {rel} carries {text.count(old)} copies of {old[:48]!r}, so "
            "this case would assert nothing. Fix the case, never the gate."
        )
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def retype(root: Path, rel: str, pattern: str) -> None:
    """Add one to the number `pattern` captures, so the claim states a wrong figure.

    A case that names the RIGHT value in order to replace it restates a measured
    number in a second place, and goes stale the moment the measurement moves.
    Two of the cases below did, one when the campaign gained a site and one when
    a rule stopped being recorded as forced, and a rig that no longer matches
    stops the run instead of proving anything. Perturbing whatever the claim
    currently carries keeps the case pinned to the shape it is testing.

    A second match is refused for the reason a missing one is: the case would
    still run, and it would be asserting something about whichever site the
    pattern happened to reach first.
    """
    path = root / rel
    text = path.read_text(encoding="utf-8")
    found = list(re.finditer(pattern, text))
    if len(found) != 1:
        raise SystemExit(
            f"test setup: {len(found)} site(s) in {rel} match {pattern!r}, so this "
            "case would assert nothing. Fix the case, never the gate."
        )
    start, end = found[0].span(1)
    path.write_text(text[:start] + str(int(found[0].group(1)) + 1) + text[end:], encoding="utf-8")


def reword(root: Path, rel: str, pattern: str, replacement: str) -> None:
    """Rewrite the one span `pattern` matches, without restating what it says now.

    A span the gate locates by regex has to be broken by regex too. Anchoring the
    mutation on the span's current text copies the figure inside it into this
    file, where nothing re-measures it: the case named a corpus size the report
    had already moved past by the time the consumer rails re-vendored, and a rig
    that no longer matches stops the run instead of proving anything. The
    replacement carries no figure either, so the only thing the gate can object
    to is the span having gone missing.
    """
    path = root / rel
    text = path.read_text(encoding="utf-8")
    found = list(re.finditer(pattern, text))
    if len(found) != 1:
        raise SystemExit(
            f"test setup: {len(found)} span(s) in {rel} match {pattern!r}, so this "
            "case would assert nothing. Fix the case, never the gate."
        )
    start, end = found[0].span()
    path.write_text(text[:start] + replacement + text[end:], encoding="utf-8")


def forcing_figure(root: Path, key: str) -> int:
    """One live figure out of the staged forcing baseline.

    Two cases below plant prose carrying a number that IS a published count, so
    the census has something to object to. Typing that number is what made them
    rot: both named a figure the campaign had since moved past, and an integer
    equal to nothing is exactly the case they were meant to distinguish.
    """
    loaded = json.loads((root / "docs" / "FORCING-BASELINE.json").read_text(encoding="utf-8"))
    if key == "annotations":
        return len(loaded["annotations"])
    return len(loaded["sites"]) if key == "sites" else int(loaded["counts"][key])


def corpus_figure(root: Path, key: str) -> int:
    """One live figure out of the staged manifest, for the same reason.

    The corpus grows, and every case that named a size in order to break it or to
    plant it had to be re-typed on the revision that moved it. The manifest is
    where the gate reads these figures from, so it is where the cases read them
    from too.
    """
    loaded = json.loads((root / "vectors" / "MANIFEST.json").read_text(encoding="utf-8"))
    return len(loaded["vectors"]) if key == "total" else int(loaded["counts"][key])


def agent_action_figure(root: Path, key: str) -> int:
    """The same, for the second corpus.

    A sibling rather than a parameter on `corpus_figure`, because the two corpora
    are independent artifacts that happen to share a manifest shape: they carry
    different predicates, move on different schedules, and a case that reads the
    wrong one must fail to compile rather than quietly assert about the other.
    """
    loaded = json.loads(
        (root / "vectors-ai-agent-action" / "MANIFEST.json").read_text(encoding="utf-8")
    )
    return len(loaded["vectors"]) if key == "total" else int(loaded["counts"][key])


def manifest_predicate_version(root: Path, corpus: str) -> str:
    """The version a corpus manifest declares, read the way the gate reads it.

    Read rather than named, for the reason `corpus_figure` gives about sizes: a
    case that hard-codes `0.7` in order to break it restates a measured value in
    a second place and goes stale the moment the predicate moves, which is the
    exact event this case exists to catch.
    """
    loaded = json.loads((root / corpus / "MANIFEST.json").read_text(encoding="utf-8"))
    return str(loaded["predicateType"]).rsplit("/v", 1)[-1]


def revise(root: Path, rel: str, edit: Callable[[str], str]) -> None:
    """Rewrite a SOURCE, so a claim that no longer matches it is the finding.

    `retype` perturbs a claim site and asks whether the gate notices the prose is
    wrong. This asks the opposite and more important question: the source moves,
    nobody touches the prose, and the prose is now stale while still looking
    authoritative. That is the direction a version number actually rots in.

    A no-op edit is refused for the same reason `retype` refuses a missing match:
    the case would still run and would be asserting nothing.
    """
    path = root / rel
    before = path.read_text(encoding="utf-8")
    after = edit(before)
    if after == before:
        raise SystemExit(
            f"test setup: revising {rel} changed nothing, so this case would "
            "assert nothing. Fix the case, never the gate."
        )
    path.write_text(after, encoding="utf-8")


def head_row(root: Path) -> None:
    """Add one to the total on the changelog's NEWEST row, whichever row that is.

    Naming the row in full is what kept breaking here: the anchor had to carry
    the trailing clause as well as the three counts, because revisions that
    change nothing share a count triple with the one before them, and it had to
    be re-anchored on every revision that landed. The newest revision is read
    from the headings instead, so the case follows the ledger rather than
    restating one of its rows.
    """
    path = root / "vectors" / "CHANGES.md"
    text = path.read_text(encoding="utf-8")
    revisions = [int(n) for n in re.findall(r"^## suiteRevision (\d+)\b", text, re.M)]
    if not revisions:
        raise SystemExit(
            "test setup: vectors/CHANGES.md declares no revision, so this case would "
            "assert nothing. Fix the case, never the gate."
        )
    heading = re.search(rf"^## suiteRevision {max(revisions)}\b", text, re.M)
    if heading is None:
        raise SystemExit(
            f"test setup: vectors/CHANGES.md has no heading for suiteRevision "
            f"{max(revisions)}, so this case would assert nothing. Fix the case, "
            "never the gate."
        )
    row = re.compile(r"Corpus:\s*\*{0,2}(\d+) vectors").search(text, heading.end())
    if row is None:
        raise SystemExit(
            f"test setup: suiteRevision {max(revisions)} declares no corpus size in "
            "vectors/CHANGES.md, so this case would assert nothing. Fix the case, "
            "never the gate."
        )
    start, end = row.span(1)
    path.write_text(text[:start] + str(int(row.group(1)) + 1) + text[end:], encoding="utf-8")


def append(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.write_text(path.read_text(encoding="utf-8") + text, encoding="utf-8")


def create(root: Path, rel: str, text: str) -> None:
    """Write a file that was not there, refusing to overwrite one that was.

    A case that creates a path the corpus already carries changes no count, the
    gate passes, and the case records a refusal nobody made. The identifier this
    is called with is a fixed one rather than a real digest precisely so it
    cannot collide -- and a guard is cheaper than the assumption.
    """
    path = root / rel
    if path.exists():
        raise SystemExit(
            f"test setup: {rel} is already in the staged tree, so creating it "
            "changes nothing and this case would assert nothing. Fix the case, "
            "never the gate."
        )
    path.write_text(text, encoding="utf-8")


def remove_first_statement(root: Path) -> None:
    """Delete the statement file the staged manifest's first entry points at.

    The file is chosen from the manifest rather than named here, so the case
    keeps deleting a real vector after the corpus is regenerated and every
    identifier changes. A name typed in here would stop matching, the deletion
    would be a no-op, and the case would record a refusal nobody made -- which is
    exactly what the two cases it replaces did.
    """
    manifest = json.loads((root / "vectors" / "MANIFEST.json").read_text(encoding="utf-8"))
    target = root / "vectors" / str(manifest["vectors"][0]["file"])
    if not target.is_file():
        raise SystemExit(
            f"test setup: {target} is not a file, so this case would assert "
            "nothing. Fix the case, never the gate."
        )
    target.unlink()


# The sentences a case expects back name figures too, and one that quotes the
# right figure rots exactly as fast as a mutation that quotes it. These are read
# from the manifest the staged copy is copied from, so they are the same figures
# the gate will have measured, and a case that says which number it expects to
# see refused keeps saying it after the corpus moves.
TOTAL = corpus_figure(REPO_ROOT, "total")
AGENT_ACTION_TOTAL = agent_action_figure(REPO_ROOT, "total")
PREDICATE_VERSION = manifest_predicate_version(REPO_ROOT, "vectors")
ACCEPT = corpus_figure(REPO_ROOT, "accept")
REJECT = corpus_figure(REPO_ROOT, "reject")
INDETERMINATE = corpus_figure(REPO_ROOT, "indeterminate")
# A per-kind count of a registered corpus, read from its own manifest. The
# census treats it as count-shaped only beside a count noun, and these cases
# hold both sides of that line.
OBSERVED_EFFECT_REJECT = int(
    json.loads(
        (REPO_ROOT / "vectors-observed-effect" / "MANIFEST.json").read_text(encoding="utf-8")
    )["counts"]["reject"]
)


# --------------------------------------------------------------------------
# Half one: a published count drifts, is reworded, or is duplicated
# --------------------------------------------------------------------------

CLAIM_CASES: list[Case] = [
    (
        "the Gemara live case count is retyped",
        lambda root: retype(
            root,
            "interop/gemara-method-link/README.md",
            r"The (\d+) cases use complete",
        ),
        ("the Gemara profile case count says",),
    ),
    (
        "the Gemara manifest grows without its live prose count",
        lambda root: revise(
            root,
            "interop/gemara-method-link/MANIFEST.json",
            lambda text: json.dumps(
                {**json.loads(text), "cases": json.loads(text)["cases"] + [{}]}
            ),
        ),
        ("the Gemara profile case count says",),
    ),
    (
        "the Gemara historic author result is retyped",
        lambda root: retype(
            root, "interop/gemara-method-link/RUN.md", r"Bundled reader: (\d+)/\d+"
        ),
        ("the Gemara author reader result", "was found 0 time(s)"),
    ),
    (
        "the Gemara historic author result disappears",
        lambda root: reword(
            root,
            "interop/gemara-method-link/RUN.md",
            r"Bundled reader: \d+/\d+ matching answers\.",
            "Bundled reader: historic result removed.",
        ),
        ("the Gemara author reader result", "was found 0 time(s)"),
    ),
    (
        "a published count drifts from the corpus",
        lambda root: retype(
            root,
            "docs/research/corpus-measurements.md",
            r"the suite still reports (\d+) of \d+",
        ),
        (f"says '{TOTAL + 1} of {TOTAL}' where the sources say '{TOTAL} of {TOTAL}'",),
    ),
    (
        "an unregistered count for the second corpus appears in the corpus guide",
        lambda root: append(
            root,
            "docs/guides/corpora.md",
            f"\nThe AI Agent Action corpus holds {AGENT_ACTION_TOTAL} vectors.\n",
        ),
        ("docs/guides/corpora.md:", "an integer counting vectors"),
    ),
    (
        # A predicate version rots exactly like a count: written into prose, the
        # specification moves, and the prose keeps its old number while looking
        # authoritative. This is the case the operator reported -- a README
        # reading v0.7 beside a v0.8.0 release, with nothing able to say whether
        # that was drift or two different axes.
        "a predicate version drifts from the manifest that declares it",
        lambda root: revise(
            root,
            "vectors/MANIFEST.json",
            lambda text: text.replace(
                f"adversarial-execution-evidence/v{PREDICATE_VERSION}",
                "adversarial-execution-evidence/v99.0",
            ),
        ),
        (
            f"the AEE predicate version, in the opening sentence says "
            f"'{PREDICATE_VERSION}' where the sources say '99.0'",
        ),
    ),
    (
        "a forcing count drifts from the baseline",
        lambda root: retype(
            root,
            "docs/research/corpus-measurements.md",
            r"ratchet: \*\*(\d+) rules forced",
        ),
        ("the four forcing outcomes says",),
    ),
    (
        "a claim is reworded, so the check would silently stop running",
        # No number here on purpose: this case is about the WORDING the claim is
        # anchored on, and naming the figure beside it is what made the case rot.
        lambda root: edit(root, "docs/research/corpus-measurements.md", "sweeps all ", "covers "),
        ("the nightly sweep's size was found 0 time(s), expected 1",),
    ),
    (
        "a claim is duplicated into a second paragraph that will rot on its own",
        # The duplicate carries the figure the claim carries, because a second
        # paragraph that agrees with the first today is the thing this case is
        # about: it is right until the corpus moves, and then nothing corrects it.
        lambda root: append(
            root,
            "docs/IMPLEMENTATION-REPORT.md",
            f"\nNor does agreement on {corpus_figure(root, 'total')} vectors say "
            "anything about tomorrow.\n",
        ),
        ("the scoping paragraph on what agreement does not say was found 2 time(s), expected 1",),
    ),
    (
        "a delegated span is reworded, leaving it owned by nobody",
        # Matched the way the gate declares the span, and replaced by prose that
        # states no figure at all: the case is about the span disappearing, and
        # a number on either side of the edit is a copy of a measurement.
        lambda root: reword(
            root,
            "docs/IMPLEMENTATION-REPORT.md",
            r"and replays the full \d+\.",
            "and replays every vector in that set.",
        ),
        ("is delegated to scripts/consumer-lag-gate.py and no longer appears",),
    ),
    (
        "a frozen incident figure is quietly made to track the corpus",
        lambda root: edit(
            root,
            "docs/reference/verifier-contract.md",
            "it scored 0 of 186.",
            "it scored 0 of 190.",
        ),
        (
            "the frozen figure \"the external-rail contract, the shipped CLI's "
            'score" was found 0 time(s)',
        ),
    ),
    (
        "a moved predicate version drifts in the corpus guide",
        lambda root: retype(
            root,
            "docs/guides/corpora.md",
            r"\*\*Adversarial Execution Evidence\*\*, predicate version (\d+)\.\d+",
        ),
        (
            "docs/guides/corpora.md:",
            "the AEE predicate version, in the opening sentence says",
        ),
    ),
    (
        "a moved independent run figure changes",
        lambda root: retype(
            root,
            "docs/research/external-records.md",
            r"scores (\d+)/\d+ on suiteRevision",
        ),
        (
            'the frozen figure "the independent Rust verifier\'s score, as posted" '
            "was found 0 time(s)",
        ),
    ),
    (
        "a moved historic condition figure changes",
        lambda root: retype(
            root,
            "docs/research/corpus-measurements.md",
            r"so (\d+) ids cited by accept vectors",
        ),
        (
            'the frozen figure "the condition-registry section\'s account of the unresolvable ids" '
            "was found 0 time(s)",
        ),
    ),
    (
        "a moved word-spelled annotation count is rewritten",
        lambda root: reword(
            root,
            "docs/research/corpus-measurements.md",
            r"The baseline annotates \w+ sites as",
            f"The baseline annotates {forcing_figure(root, 'annotations') + 1} sites as",
        ),
        ("how many forcing sites carry an annotation says",),
    ),
    (
        "a moved independence delegation disappears",
        lambda root: reword(
            root,
            "docs/research/independence.md",
            r"It\s+has\s+not\s+been\s+run\s+against\s+suiteRevision\s+[\d,\s]*(?:and|or)\s+\d+,",
            "Its later-revision run status is omitted,",
        ),
        ("the independence section's scoping sentence", "no longer appears"),
    ),
    (
        "a moved action-retention declaration disappears",
        lambda root: reword(
            root,
            "docs/guides/runner.md",
            r"uploaded report \(default: `\d+`\)",
            "uploaded report (default omitted)",
        ),
        ("the action's report retention default in days", "no longer appears"),
    ),
]

# --------------------------------------------------------------------------
# Half two: a NEW hand-written count appears where nothing declared one
# --------------------------------------------------------------------------

CENSUS_CASES: list[Case] = [
    (
        "a new paragraph states today's corpus size",
        lambda root: append(
            root,
            "BUILD-NOTES.md",
            f"\nThe corpus holds {corpus_figure(root, 'total')} files as this is written.\n",
        ),
        (f"'{TOTAL}' is an integer equal to the corpus total",),
    ),
    (
        "a new paragraph states today's accept count",
        lambda root: append(
            root,
            "BUILD-NOTES.md",
            f"\nOf those, {corpus_figure(root, 'accept')} are statements a verifier accepts.\n",
        ),
        (f"'{ACCEPT}' is an integer equal to the accept count",),
    ),
    (
        "a new paragraph counts vectors at a size the corpus has never had",
        lambda root: append(root, "BUILD-NOTES.md", "\nThe suite ships 192 vectors in total.\n"),
        ("'192' is an integer counting vectors",),
    ),
    (
        "a new paragraph states a score",
        lambda root: append(
            root, "BUILD-NOTES.md", "\nAn outside rail scored 200/200 against it.\n"
        ),
        ("'200/200' is a ratio",),
    ),
    (
        "a small forcing count is written next to the word it counts",
        lambda root: append(
            root,
            "BUILD-NOTES.md",
            f"\nThe ratchet records {forcing_figure(root, 'SILENT')} rules as tolerated.\n",
        ),
        ("is an integer equal to the count of seen-but-tolerated rules",),
    ),
    (
        "a count is attributed to a revision whose ledger row does not carry it",
        lambda root: append(
            root,
            "BUILD-NOTES.md",
            "\nThe corpus of suiteRevision 3 held 231 vectors.\n",
        ),
        ("'231' is an integer counting vectors",),
    ),
    (
        "a count appears in a Go comment",
        lambda root: append(
            root,
            "cmd/mutgen/main.go",
            "\n// The corpus this walks holds 231 vectors.\n",
        ),
        ("cmd/mutgen/main.go:", "'231' is an integer counting vectors"),
    ),
    (
        "a count appears in a Python docstring",
        lambda root: append(
            root,
            "scripts/coverage-gate.py",
            '\ndef _note() -> None:\n    """It is replayed over 231 vectors."""\n',
        ),
        ("scripts/coverage-gate.py:", "'231' is an integer counting vectors"),
    ),
    (
        "a count appears in a CI step name",
        lambda root: append(
            root,
            ".github/workflows/ci.yml",
            f"\n# A later note: the nightly sweep covers {forcing_figure(root, 'sites')} sites.\n",
        ),
        ("is an integer equal to the count of mutation sites",),
    ),
    (
        "a changelog entry cites a size the corpus did not have by then",
        lambda root: edit(
            root,
            "vectors/CHANGES.md",
            "## suiteRevision 1 (first public release)",
            "## suiteRevision 1 (first public release)\n\n- A note added later: 231 vectors.",
        ),
        ("'231' is an integer counting vectors",),
    ),
]

# --------------------------------------------------------------------------
# The sources themselves
# --------------------------------------------------------------------------

SOURCE_CASES: list[Case] = [
    (
        "the manifest's declared count disagrees with the entries it carries",
        lambda root: retype(root, "vectors/MANIFEST.json", r'"accept": (\d+)'),
        (f"it declares {ACCEPT + 1} accept vector(s) and carries {ACCEPT} accept entr(ies)",),
    ),
    (
        # Aimed at vectors/statements/, because that is where a vector file is.
        # It used to create one in vectors/accept/, and when the corpus flattened
        # into one content-addressed directory that path stopped being a place a
        # vector could be: the case went on writing a file nothing reads, the gate
        # went on passing, and a case asserting a refusal recorded a refusal that
        # was never made.
        "a vector file is added without the manifest hearing about it",
        lambda root: create(root, "vectors/statements/v0000000000000999.json", "{}\n"),
        (f"carries {TOTAL} entr(ies) and vectors/statements/ holds {TOTAL + 1} file(s)",),
    ),
    (
        "the changelog's newest row drifts from the manifest",
        # The row is found through the revision numbering rather than by its own
        # text. Two revisions can carry the same three counts, so the row text
        # never identified which row was being edited on its own, and every
        # revision that landed left the anchor naming a row that was no longer
        # the newest.
        head_row,
        (
            f"declares {TOTAL + 1} vectors ({ACCEPT} accept, {REJECT} reject, "
            f"{INDETERMINATE} indeterminate)",
        ),
    ),
    (
        "a vector index heading drifts from the corpus",
        lambda root: retype(root, "vectors/reject/INDEX.md", r"## Vectors \((\d+)\)"),
        (
            f"the vector-table heading says {REJECT + 1} and vectors/MANIFEST.json "
            f"carries {REJECT} reject vector(s)",
        ),
    ),
    (
        # The third family gets the same closure, in both directions, because a
        # bucket whose table nothing reconciles against the manifest is exactly
        # how five vectors once sat in a directory with no row behind them.
        "the indeterminate index heading drifts from the corpus",
        lambda root: retype(root, "vectors/indeterminate/INDEX.md", r"## Vectors \((\d+)\)"),
        (
            f"the vector-table heading says {INDETERMINATE + 1} and "
            f"vectors/MANIFEST.json carries {INDETERMINATE} indeterminate vector(s)",
        ),
    ),
    (
        # The other direction. One flat directory cannot be split by verdict, so
        # the per-family variant of the case above no longer says anything the
        # case above does not; a file that DISAPPEARS does, and it is the half a
        # generator that only ever adds rows would never exercise.
        "a vector file disappears without the manifest hearing about it",
        remove_first_statement,
        (f"carries {TOTAL} entr(ies) and vectors/statements/ holds {TOTAL - 1} file(s)",),
    ),
    # The case the old heading check could not make. Its two sides lived in one
    # file, so a table short of the corpus and a heading agreeing with that short
    # table passed, which is what five vectors did until the manifest generator
    # refused to run. Deleting a row now leaves the heading untouched and fails
    # anyway, because the row is compared with the corpus and not with the
    # heading above it.
    (
        "an index table loses a row while its heading still agrees with it",
        lambda root: edit(
            root,
            "vectors/reject/INDEX.md",
            "| `v03547f8918e0d7dc` |",
            "| skipped-v03547f8918e0d7dc |",
        ),
        ("the corpus carries ['v03547f8918e0d7dc'] and this table has no row for them",),
    ),
    (
        # The extra row names a WELL-FORMED identifier the corpus does not carry.
        # It used to name `ok-902-invented`, a slug from the naming scheme the
        # corpus retired, and once identifiers became digests the gate's row scan
        # no longer recognised that cell as a row at all -- so the case that
        # asserted the gate refuses an extra row was passing an input the gate
        # could not see. A case about an extra row has to state a row.
        "an index table carries a row for a vector the corpus does not have",
        lambda root: edit(
            root,
            "vectors/accept/INDEX.md",
            "| v18bdbadef67b38f4 |",
            "| v18bdbadef67b38f4 |\n| v0000000000000902 | fail | aee-c-1 | none |",
        ),
        ("['v0000000000000902'] have a row here and no entry",),
    ),
    (
        # And the input the case above used to carry, asserted for what it
        # actually is. A row inside the vector table whose first cell names no
        # identifier is the sixth silent dropper: it is not a row to any reader,
        # so the table is one vector shorter and every count derived from it
        # still agrees with every other.
        "a vector table row names no identifier, so no reader counts it",
        lambda root: edit(
            root,
            "vectors/accept/INDEX.md",
            "| v18bdbadef67b38f4 |",
            "| v18bdbadef67b38f4 |\n| ok-902-invented | fail | aee-c-1 | none |",
        ),
        ("['ok-902-invented'] sit in the vector table and name no identifier",),
    ),
    (
        "one vector is given two index rows, which are then free to disagree",
        lambda root: edit(
            root,
            "vectors/accept/INDEX.md",
            "| v18bdbadef67b38f4 |",
            "| v18bdbadef67b38f4 | fail | aee-c-1 | a second row |\n| v18bdbadef67b38f4 |",
        ),
        ("['v18bdbadef67b38f4'] each carry more than one row",),
    ),
]

CENSUS_CASES.append(
    (
        "a registered corpus's reject count typed beside a count noun",
        lambda root: append(
            root,
            "BUILD-NOTES.md",
            f"\nThe sweep records {OBSERVED_EFFECT_REJECT} unforced rules today.\n",
        ),
        ("equal to the reject count of vectors-observed-effect",),
    )
)

# --------------------------------------------------------------------------
# The accepting cases
# --------------------------------------------------------------------------

ACCEPT_CASES: list[Case] = [
    (
        "the repository as it stands",
        lambda root: None,
        ("are accounted for",),
    ),
    (
        "a new count whose revision is attributed in the prose",
        lambda root: append(
            root,
            "BUILD-NOTES.md",
            "\nThe checker cleared all 140 vectors of suiteRevision 3.\n",
        ),
        ("are accounted for",),
    ),
    (
        "a registered corpus's reject count used bare for something else",
        lambda root: append(
            root,
            "BUILD-NOTES.md",
            f"\nThe other project publishes {OBSERVED_EFFECT_REJECT} one-field pairs.\n",
        ),
        ("are accounted for",),
    ),
    (
        "a numbered rule is an identifier, not a count",
        lambda root: append(
            root,
            "BUILD-NOTES.md",
            f"\nRule {OBSERVED_EFFECT_REJECT} of the report table reads the control.\n",
        ),
        ("are accounted for",),
    ),
    (
        "ordinary numbers that stand for nothing about the corpus",
        lambda root: append(
            root,
            "BUILD-NOTES.md",
            "\nThe timeout is 900 seconds and the read buffer is 4096 bytes.\n",
        ),
        ("are accounted for",),
    ),
]


def copy_staged(template: Path, destination: Path) -> None:
    """Give one case its own copy of the staged checkout.

    Staging hashes every tracked file into a fresh index, which cost about five
    seconds a case, forty-four times a run. The template is staged once and each
    case gets a byte copy of it, `.git` included: the same index entries, the
    same objects and the same files, so `git ls-files` and every blob read see
    what a fresh stage would have given them. The case then edits only its own
    copy, so no case can see another's mutation.
    """
    shutil.copytree(template, destination, symlinks=True)


def workers() -> int:
    """How many cases run at once: COUNT_GATE_TEST_WORKERS, else up to four.

    Each case is one single-threaded gate process, so this pool is the only layer
    here that owns parallelism and the number is the number of processes. The
    default never exceeds the processors this process may use, and never exceeds
    four, so a run on a loaded workstation adds at most four busy processes.
    """
    raw = os.environ.get("COUNT_GATE_TEST_WORKERS", "")
    if raw:
        if not raw.isdigit() or int(raw) < 1:
            raise SystemExit(
                f"COUNT_GATE_TEST_WORKERS={raw!r} is not a positive integer; refusing "
                "to guess a worker count."
            )
        return int(raw)
    return max(1, min(4, len(os.sched_getaffinity(0))))


def judge(case: Case, want_refusal: bool, root: Path, template: Path) -> str | None:
    """Run one case in its own copy and return its failure, or None if it holds."""
    name, mutate, phrases = case
    copy_staged(template, root)
    mutate(root)
    code, output = run(root)
    if want_refusal and code == 0:
        return f"{name}: the gate accepted it"
    if not want_refusal and code != 0:
        return f"{name}: the gate refused it:\n{output}"
    missing = [phrase for phrase in phrases if phrase not in output]
    if missing:
        return (
            f"{name}: the right exit status, and the output does not carry "
            f"{missing!r}. A refusal that names the wrong thing sends the next "
            f"person to the wrong file.\n{output}"
        )
    return None


def main() -> int:
    groups = (
        ("claim", CLAIM_CASES, True),
        ("census", CENSUS_CASES, True),
        ("source", SOURCE_CASES, True),
        ("accept", ACCEPT_CASES, False),
    )
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        template = tmp / "template"
        template.mkdir()
        stage(template)
        # Every case is submitted, and every result is collected in submission
        # order, so the report reads the same as the serial run did. A case that
        # raises (a rig that no longer matches its file) re-raises here when its
        # result is read, exactly as it stopped the serial run.
        with ThreadPoolExecutor(max_workers=workers()) as pool:
            futures = [
                pool.submit(judge, case, want_refusal, tmp / f"{group}{index}", template)
                for group, cases, want_refusal in groups
                for index, case in enumerate(cases)
            ]
            for future in futures:
                failure = future.result()
                if failure is not None:
                    failures.append(failure)
    total = len(CLAIM_CASES) + len(CENSUS_CASES) + len(SOURCE_CASES) + len(ACCEPT_CASES)
    if len(futures) != total:
        raise SystemExit(f"judged {len(futures)} case(s) of {total}; refusing to report a pass")
    if failures:
        print(f"FAIL: {len(failures)} of {total} case(s) do not hold:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    refusals = total - len(ACCEPT_CASES)
    print(
        f"OK: {total} case(s), of which {refusals} assert a refusal the gate makes "
        "and name the sentence it makes it about."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
