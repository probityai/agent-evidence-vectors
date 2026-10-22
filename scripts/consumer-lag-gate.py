#!/usr/bin/env python3
"""Consumer-lag gate: this corpus may not move without the copies of it moving.

The corpus is authored here and vendored byte-for-byte into the consumer rails
that replay it. Each rail keeps a stamp recording a content digest over the
vectors it carries, and each rail's own build recomputes that digest and fails
if a vendored file was edited. That half was wired and it works.

The other half was not wired at all. Nothing anywhere asked whether a rail's
copy was the current corpus, so the refresh ran when somebody remembered, and
twice it was not remembered: two rails sat at 140 vectors while this repository
published 149, and by the next revision they sat at 154 and 153 against 165. A
timestamp profile enforced on every rail and published in the manifest was
pinned by no vector any consumer replayed. The gap is not that anyone ignored a
red build. There was no red build to ignore.

No build can see two repositories at once, so the check has to live where the
change that causes the lag happens, which is here. This gate compares the corpus
each rail is recorded as carrying in ``vectors/CONSUMERS.json`` against the
corpus the LATEST RELEASE the default branch carries publishes, and fails naming
any copy that is behind. A release that changes the corpus therefore reddens
this repository from the moment its tag is on the default branch until every
rail has been refreshed, rather than leaving a lag that only shows up when
someone thinks to count files in another tree.

The reference is a published release and not the checked-out tree, nor the
default branch's tip, and that distinction is the whole of this gate's timing.

A rail vendors what this repository has published. It cannot vendor a branch
nobody has merged, because there is nothing to fetch: the branch tip is not
reachable from the remote's default branch and a vendoring script pointed at it
would record a digest describing a commit that may never exist anywhere else.
So a branch that adds vectors creates no obligation on any rail while it is a
branch, and measuring against the checked-out tree invented one -- it demanded
that the rails already carry a corpus they had no way to obtain.

That is not a strict gate, it is a deadlock, and it was reached: the push of a
branch bumping the corpus was refused because the rails were behind that
branch, the rails could only be refreshed from a published corpus, and the
corpus could not be published because the push was refused. A gate that cannot
be satisfied before the action it gates is unsatisfiable by construction, and
the only thing an unsatisfiable gate teaches is the bypass flag.

The same argument, one step further, is why the reference is a release tag and
not the default branch's tip. Until 2026-10-16 it was the tip, on the reading
that a rail vendors whatever the default branch carries. Since 2026-09-30 that
reading is false: the vendoring script every rail uses (``vendor_aee_corpus.py``
in the consumer repository, its section "WHY NOT THE DEFAULT BRANCH") vendors
only from a named release tag, never from a branch or a commit, so that a
rail's own CI is not a function of this repository's merge queue. So a merge
that changed the corpus created an obligation no rail could meet: the rails
could only move to a release, no release carried the merged corpus, and the
default branch stayed red until someone cut one. That is the deadlock above in
a new place, and it was reached on 2026-10-16, when two corpus merges reddened
the default branch and every open pull request with it.

Measured against the latest release the obligation is preserved and arrives
when it becomes real. While the change is a branch, and after it lands but
before a release carries it, the latest release still publishes the old
corpus, the rails carry it, and the gate is green. The instant a release tag
carrying the new corpus is on the default branch, every rail is genuinely
behind, and the gate is red on the default branch and stays red until the rails
are refreshed to that release and the ledger records it. Nothing here can clear
that: the ledger digests are read from the copies, so regenerating the corpus,
re-deriving a digest or re-running any generator moves the reference further
from the ledger rather than closer to it.

"Latest release" is exact: the highest ``vMAJOR.MINOR.PATCH`` tag whose commit
the default branch carries. A tag cut on a branch that has not landed is not
yet a release the default branch publishes, and a clone that holds such a tag
locally must not measure against it. A clone with no release tag the default
branch carries cannot say which corpus a rail could vendor, and reports that
the check did not run.

What the default branch and the release publish is read from each one's own
tree, with the same digest function applied to the same files, and not from the
``corpusDigest`` field it happens to carry. A field is a leftover until something recomputes it,
and trusting one here would let a default branch whose manifest was never
regenerated hand this gate a stale reference that every stale copy then agrees
with. The field is checked against those files instead, on the default branch
and on the release, so a default branch that does not publish the corpus it has
fails here, naming the default branch rather than the branch being pushed.

The ledger identifies each copy by an opaque id and records nothing else about
it. Which checkout an id refers to is supplied on the command line at sync time
and never written down here, because this repository is the artifact offered in
standards correspondence and it stays neutral about who consumes it. The gate
does not need to know: it needs to know how many copies exist and what each one
carries.

The two modes are deliberately asymmetric.

``--check`` is what CI runs. It reads this repository and nothing else, so it
needs no sibling checkout, no credential and no network. It does need the
default branch's ref and its release tags to be present locally, which is why
the workflow that runs it checks out with full history and tags; when either
cannot be resolved the check reports that it did not run, and never that the
copies are current.

``--sync`` rewrites the ledger, and it does so by reading each rail's own stamp
rather than by writing down the digest it just computed here. That distinction
is the whole reason the ledger is trustworthy: a sync that copied this
repository's digest into the ledger would make the check a function of its own
input, so it could never fail and the ledger would record an intention instead
of a fact. Reading the rail means a sync run against a stale copy records the
stale digest and the check stays red. The only way to green is to actually
refresh the copy, which is the outcome the gate exists to force.

``--sync`` also refuses to guess where a copy lives. Every id in the ledger must
be given a directory on the command line, because these repositories have linked
worktrees on different branches sitting beside each other, and a sync that
silently read the wrong tree would record a digest describing a checkout nobody
is shipping. An id given a directory that the ledger does not yet carry is added
to it, with its digest read from that copy's stamp like every other row. That is
the only way to widen this ledger, and it exists because the alternative was
adding a row by hand to a file whose own comment says not to: a rail nobody
registered is a rail this gate reports success about, so registering one had to
be a command rather than an edit.

The other half of the gate is that the ledger is what the published prose says.
``docs/IMPLEMENTATION-REPORT.md`` states, in a note and in one cell per rail, how
many vectors the rails vendor and at which revision. Those sentences were written
by hand at suiteRevision 6 and were still saying so at suiteRevision 14, through
eight re-vendors that moved every copy underneath them, because nothing read
them. So each is declared below and matched on the fixed words around its number
against the corpus this repository publishes -- the same discipline
``scripts/independent-runs-gate.py`` applies to the independence column, applied
here to the ledger that owns this fact rather than folded into that gate, which
would give one gate two unrelated ledgers and two unrelated failure vocabularies.

One of those checks is not about a number. The report names one rail per cell,
and the count of those cells must equal the count of rows in the ledger, so a
rail advertised in the table with nothing recorded about it fails here. That is
the hole this half was built for: the table named three rails, the ledger carried
two, and the missing one was the one no copy of this corpus was ever compared
against.

What it does not catch: a release that lands and is never followed by a
refresh goes red here and stays red, which is the intended outcome, but it goes
red on the default branch rather than on the change that caused it. The branch
that bumped the corpus passed, correctly, because at the time it was checked no
rail was behind anything. Whoever cuts the release owns the refresh, and the
only signal that they do is a red default branch. Nothing in this repository can make that
signal arrive earlier without demanding a rail vendor an unpublished commit,
which is the deadlock above.

Nor does it catch a copy that is refreshed, synced here, and then
reverted. The ledger would still name the digest that copy carried at sync time,
and this gate would stay green until the next sync. The rail's own stamp check
does not catch it either, since a revert plus a re-stamp is internally
consistent. Closing it needs this repository to read the rail, which is the
cross-repository read this gate is built to avoid, so it is recorded here rather
than papered over. Nor does the cell count see a vendored copy that no document
advertises and no row records: the report and the ledger would agree with each
other, and the copy would be invisible to both.

Usage:
    python3 scripts/consumer-lag-gate.py --check
    python3 scripts/consumer-lag-gate.py --sync --copy <id>=<vendored-dir> ...
"""

from __future__ import annotations

import argparse
import io
import json
import re
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS = REPO_ROOT / "vectors"
LEDGER = VECTORS / "CONSUMERS.json"

# The digest function lives with the generator that publishes its output, and is
# imported rather than restated. It was written out twice, here and there, and two
# copies of the definition of "the same corpus" inside one repository is the defect
# this gate exists to catch, arrived at from the inside.
sys.path.insert(0, str(VECTORS))
from gen_manifest import corpus_digest, corpus_files  # noqa: E402

MANIFEST = VECTORS / "MANIFEST.json"
REPORT = REPO_ROOT / "docs" / "IMPLEMENTATION-REPORT.md"
STAMP_NAME = "VENDOR-STAMP.json"

# `## suiteRevision 14 (the vendored text catches up with the corpus)`
REVISION_HEADING = re.compile(r"^## suiteRevision (\d+)\b", re.MULTILINE)

# The branch whose corpus a consumer rail can actually vendor. A rail fetches
# this repository at its default branch; a tip nobody has merged is reachable
# from no remote ref, so it is not something any rail could carry and not
# something this gate may require one to carry. Overridable only so the tests
# can stage a repository of their own, never so a red run can be argued green:
# the workflow step passes no ref and gets this one.
DEFAULT_PUBLISHED_REF = "origin/main"

# A release tag, as the vendoring script reads one: three dotted integers after a
# ``v``, and nothing else. Pre-release or suffixed names are not releases a rail
# can be pinned to, so they are not candidates for the reference.
RELEASE_TAG = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")

_LEDGER_COMMENT = (
    "How many copies of this corpus are vendored into consumer rails, and the "
    "corpus each one carries, read from that copy's own vendor stamp by "
    "scripts/consumer-lag-gate.py --sync. The ids are opaque: which checkout each "
    "one refers to is given on the command line at sync time and deliberately not "
    "recorded here. Do not hand-edit -- a digest typed here rather than measured "
    "makes the gate report an intention instead of a fact, and a row added here "
    "rather than registered with --sync records a copy nothing ever read."
)


def publication_failures(published: str) -> list[str]:
    """The corpus digest a consumer will read must be the corpus this repository has.

    A rail's currency check is one fetch of ``vectors/MANIFEST.json`` and one string
    comparison, so the whole of it rests on that field being a measurement rather than
    a leftover. Nothing else would notice if it stopped being one: the manifest is
    regenerated from the INDEX tables, and a corpus edit that never reached a
    regeneration leaves a field describing the vectors as they were, which every rail
    then agrees with. That is the original defect in a new place -- a stale number and
    a copy that matches it, agreeing with each other and with nothing else -- so the
    number is recomputed from the files here, in the gate that already computes it for
    the ledger, rather than trusted because a generator wrote it once.
    """
    if not MANIFEST.is_file():
        return [
            f"{MANIFEST.relative_to(REPO_ROOT)} is missing, so this repository "
            "publishes no corpus digest and no consumer rail can establish whether "
            "its vendored copy is current."
        ]
    recorded = json.loads(MANIFEST.read_text(encoding="utf-8")).get("corpusDigest")
    if not isinstance(recorded, str) or not recorded:
        return [
            f"{MANIFEST.relative_to(REPO_ROOT)} carries no corpusDigest. That field is "
            "the only thing a consumer rail can fetch to learn it is behind; without "
            "it every rail's currency check reports that it could not run. Regenerate "
            "with python3 vectors/gen_manifest.py."
        ]
    if recorded != published:
        return [
            f"{MANIFEST.relative_to(REPO_ROOT)} publishes corpusDigest "
            f"{recorded[:16]}... but these vectors hash to {published[:16]}.... The "
            "manifest was not regenerated after the corpus changed, so a rail still on "
            "the old corpus would fetch the old digest, agree with it, and pass. "
            "Regenerate with python3 vectors/gen_manifest.py."
        ]
    return []


@dataclass(frozen=True)
class Published:
    """The corpus one published ref carries: the default branch, or a release.

    Every field is measured from that branch's own files rather than read from a
    number it records about itself, and they are measured from ONE extraction of
    ONE commit so they cannot describe two different states of the corpus.
    """

    ref: str
    commit: str
    digest: str
    vectors: int
    revision: int


def _git(args: list[str], doing: str) -> bytes:
    """Run one git command, or refuse to say anything about the world.

    A failure here is never reported as an absence. "the default branch has no
    such corpus" and "this command could not run" are indistinguishable from the
    exit status alone, and only one of them is a finding, so neither is claimed:
    the caller stops with the exact command and git's own words.
    """
    proc = subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args], capture_output=True, check=False
    )
    if proc.returncode != 0:
        detail = proc.stderr.decode("utf-8", "replace").strip()
        raise SystemExit(
            f"FAIL: this check DID NOT RUN, so it reports nothing about the "
            f"vendored copies. {doing} needs `git {' '.join(args)}`, which exited "
            f"{proc.returncode}: {detail}"
        )
    return proc.stdout


def _revision_in(changes: str, where: str) -> int:
    """The revision a changelog is at, read from the headings that own revision
    numbering rather than from a number restated in this script, which could only
    ever agree with itself."""
    seen = sorted(int(n) for n in REVISION_HEADING.findall(changes))
    if not seen:
        raise SystemExit(
            f"FAIL: {where} carries no '## suiteRevision N' heading, so nothing "
            "says which revision the copies are being checked against."
        )
    return seen[-1]


def published_corpus(ref: str) -> Published:
    """Measure the corpus a published ref carries, from that ref's own files.

    The whole tree under ``vectors/`` is extracted from one commit and the digest
    function this repository already owns is applied to it, so "the same corpus"
    has one definition here rather than one for the checked-out tree and a looser
    one for the branch it is compared against.

    The manifest field that branch publishes is then checked against those files.
    That field is what a rail fetches, so a branch whose manifest was never
    regenerated publishes a digest describing vectors it no longer has, and every
    copy still on those vectors agrees with it. Reading the field as the reference
    would make this gate green on exactly that state; measuring the files and
    holding the field to them makes it red, and names the branch at fault.
    """
    resolved = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "--verify", "--quiet",
         f"{ref}^{{commit}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    commit = resolved.stdout.strip()
    if resolved.returncode != 0 or not commit:
        raise SystemExit(
            f"FAIL: this check DID NOT RUN. The published ref {ref!r} does not "
            "resolve to a commit in this repository, so nothing here knows which "
            "corpus the consumer rails could have vendored, and a copy that is "
            "current and a copy that is behind look identical. Fetch the default "
            "branch (`git fetch origin main`, or check out with full history in "
            "CI) and run this again."
        )
    archive = _git(
        ["archive", "--format=tar", commit, "vectors"],
        f"measuring the corpus published at {ref}",
    )
    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(path=tmp, filter="data")
        root = Path(tmp) / "vectors"
        if not root.is_dir():
            raise SystemExit(
                f"FAIL: {ref} carries no vectors/ directory, so it publishes no "
                "corpus for any consumer rail to vendor."
            )
        # The DEFAULT BRANCH's tree, which is a FOREIGN tree rather than this
        # corpus: it is what a consumer rail could actually have fetched. It was
        # read through a two-layout dispatch for exactly as long as the
        # comparison spanned the revision that flattened the corpus. That
        # revision has now reached the default branch, so there is one layout
        # again and the historical reader was deleted with the dispatch.
        digest = corpus_digest(str(root))
        vectors = len(corpus_files(str(root)))
        changes = root / "CHANGES.md"
        manifest = root / "MANIFEST.json"
        for needed in (changes, manifest):
            if not needed.is_file():
                raise SystemExit(
                    f"FAIL: {ref} carries no vectors/{needed.name}, so what it "
                    "publishes cannot be established."
                )
        revision = _revision_in(
            changes.read_text(encoding="utf-8"), f"{ref}:vectors/CHANGES.md"
        )
        recorded = json.loads(manifest.read_text(encoding="utf-8")).get("corpusDigest")
    if recorded != digest:
        raise SystemExit(
            f"FAIL: {ref} does not publish the corpus it has. Its "
            f"vectors/MANIFEST.json carries corpusDigest {str(recorded)[:16]}... "
            f"while its own vectors hash to {digest[:16]}.... That field is the "
            "one thing a consumer rail fetches, so every rail still on the older "
            "corpus would agree with it and this gate would report copies as "
            "current that are not. Fix it on that branch: regenerate with "
            "python3 vectors/gen_manifest.py."
        )
    return Published(
        ref=ref, commit=commit, digest=digest, vectors=vectors, revision=revision
    )


def latest_release(default_ref: str) -> str:
    """The newest release tag the default branch carries: the corpus a rail can vendor.

    Read from the tags present here, because ``--check`` reads this repository and
    nothing else. A tag whose commit the default branch does not carry is skipped,
    not refused: it names a release that has not landed, which no consumer can yet
    be required to carry. Finding none is a check that did not run, never a pass,
    because without a release nothing here knows which corpus a rail could have
    vendored, and a current copy and a stale one look the same.
    """
    listed = _git(
        ["for-each-ref", "--format=%(refname:strip=2)", "refs/tags/"],
        "choosing the release the consumer rails are measured against",
    ).decode("utf-8")
    candidates = sorted(
        (
            (tuple(int(part) for part in match.groups()), name)
            for name in listed.split()
            if (match := RELEASE_TAG.match(name))
        ),
        reverse=True,
    )
    for _version, name in candidates:
        landed = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "merge-base", "--is-ancestor",
             f"refs/tags/{name}^{{commit}}", f"{default_ref}^{{commit}}"],
            capture_output=True,
            check=False,
        )
        if landed.returncode == 0:
            return f"refs/tags/{name}"
        if landed.returncode != 1:
            detail = landed.stderr.decode("utf-8", "replace").strip()
            raise SystemExit(
                f"FAIL: this check DID NOT RUN. Asking whether {default_ref} "
                f"carries release {name} exited {landed.returncode}: {detail}"
            )
    raise SystemExit(
        f"FAIL: this check DID NOT RUN. No release tag (vMAJOR.MINOR.PATCH) whose "
        f"commit {default_ref} carries is present in this repository, so nothing "
        "here knows which release the consumer rails could have vendored, and a "
        "copy that is current and a copy that is behind look identical. Fetch the "
        "tags (`git fetch --tags origin`, or check out with full history and tags "
        "in CI) and run this again."
    )


def load_ledger() -> list[dict[str, str]]:
    """The recorded copies, or a hard failure if nothing records them."""
    if not LEDGER.is_file():
        raise SystemExit(
            f"FAIL: {LEDGER.relative_to(REPO_ROOT)} is missing, so nothing records "
            "how many copies of this corpus exist. Create it with --sync."
        )
    entries: list[dict[str, str]] = json.loads(LEDGER.read_text(encoding="utf-8"))[
        "copies"
    ]
    return entries


def write_ledger(entries: list[dict[str, str]]) -> None:
    LEDGER.write_text(
        json.dumps({"$comment": _LEDGER_COMMENT, "copies": entries}, indent=2) + "\n",
        encoding="utf-8",
    )


def stamp_digest(vendored: Path, copy_id: str) -> str:
    """Read the corpus digest a copy recorded for itself."""
    stamp = vendored / STAMP_NAME
    if not stamp.is_file():
        raise SystemExit(
            f"FAIL: copy {copy_id} has no {STAMP_NAME} under the directory given for "
            "it. Either that directory is the wrong checkout, or the rail has never "
            "been vendored into."
        )
    recorded = json.loads(stamp.read_text(encoding="utf-8")).get("corpusDigest")
    if not isinstance(recorded, str):
        raise SystemExit(f"FAIL: the stamp for copy {copy_id} records no corpusDigest.")
    return recorded


def sync(dirs: dict[str, Path]) -> int:
    entries = load_ledger()
    recorded = {e["id"] for e in entries}
    missing = sorted(recorded - set(dirs))
    if missing:
        print(
            "FAIL: --sync needs a directory for every recorded copy, and none was "
            f"given for: {', '.join(missing)}. Pass --copy <id>=<vendored-dir>. The "
            "directories are not guessed, because a linked worktree on another "
            "branch sits beside each of these repositories.",
            file=sys.stderr,
        )
        return 1
    # A copy named for the first time joins the ledger here, reading its stamp
    # like every other row. Registering it is deliberately the same operation as
    # refreshing it, because the two failures are the same failure: a row whose
    # digest nobody measured and a copy no row names both make the check report
    # on a corpus it never looked at.
    added = [copy_id for copy_id in dirs if copy_id not in recorded]
    entries.extend({"id": copy_id, "corpusDigest": ""} for copy_id in added)
    for entry in entries:
        entry["corpusDigest"] = stamp_digest(dirs[entry["id"]], entry["id"])
    write_ledger(entries)
    print(f"read {len(entries)} stamp(s) into {LEDGER.relative_to(REPO_ROOT)}")
    if added:
        print(f"newly recorded: {', '.join(added)}")
    return 0


@dataclass(frozen=True)
class Claim:
    """One published sentence about what the vendored copies carry.

    ``opens`` and ``closes`` are the fixed prose either side of the value, and
    ``expected`` is the value the ledger and the corpus say belongs between
    them. ``occurrences`` is how many times that shape must appear: asserting
    the count is what makes a deleted claim, a reworded one, or a fourth rail
    added to the table fail here rather than pass unchecked.
    """

    label: str
    opens: str
    closes: str
    expected: str
    occurrences: int


def claims(copies: int, pub: Published) -> tuple[Claim, ...]:
    """What the report must say, derived from what this gate just measured.

    Every claim below is a sentence about what the RAILS carry, so every one of
    them is measured against the corpus the rails could have vendored -- the
    latest release's -- and not against the checked-out tree or the default
    branch's tip. A branch that adds vectors does not make these sentences wrong,
    and neither does its merge, because the rails still vendor what the latest
    release publishes; the release does, and that is the revision at which they
    have to be rewritten, alongside the refresh they describe.
    """
    vectors = str(pub.vectors)
    revision = str(pub.revision)
    return (
        Claim(
            "note 2's opening, the revision the rails carry",
            "**The consumer rails carry the suiteRevision-",
            " corpus.**",
            revision,
            1,
        ),
        Claim(
            "note 2's vendoring sentence",
            "each vendor all ",
            " byte-for-byte",
            f"{vectors} vectors of suiteRevision {revision}",
            1,
        ),
        Claim(
            "note 2's replay sentence",
            "and replays the full ",
            ".",
            vectors,
            1,
        ),
        Claim(
            "the implementations table, one verified-against cell per rail",
            "its vendored set (",
            " vectors)",
            vectors,
            copies,
        ),
    )


def _normalize(text: str) -> str:
    """Collapse every run of whitespace, so a paragraph rewrapped in a repo file
    is the same prose. Line numbers go with the line breaks; failures name the
    claim instead, which is what a reader needs to find it."""
    return " ".join(text.split())


# How much text may sit between a claim's opening and closing markers. It is a
# regex repetition bound measured in CHARACTERS and it counts nothing: it is not
# a vector count, a revision, or a number of rails. It is named rather than
# written inline because a bare integer in a repository whose census reads every
# count-shaped integer collides with whatever live count happens to equal it,
# and the collision it actually hit was the accept-vector count.
_CLAIM_SPAN_CHARS = 60


def claim_failures(copies: int, pub: Published) -> list[str]:
    published = _normalize(REPORT.read_text(encoding="utf-8"))
    rel = REPORT.relative_to(REPO_ROOT)
    out: list[str] = []
    for claim in claims(copies, pub):
        pattern = re.compile(
            re.escape(claim.opens) + f"(.{{0,{_CLAIM_SPAN_CHARS}}}?)"
            + re.escape(claim.closes)
        )
        hits = pattern.findall(published)
        if len(hits) != claim.occurrences:
            out.append(
                f"{rel}: {claim.label} was found {len(hits)} time(s), expected "
                f"{claim.occurrences}. The claim is matched on the words around it "
                f"({claim.opens.strip()!r} ... {claim.closes.strip()!r}); rewording "
                "or deleting it fails here rather than quietly leaving the ledger "
                "unpublished, and the count for the table is the number of rows in "
                "the ledger, so a rail named there with no copy recorded fails too."
            )
            continue
        out.extend(
            f"{rel}: {claim.label} says {hit!r} where the corpus this repository "
            f"publishes says {claim.expected!r}."
            for hit in hits
            if hit != claim.expected
        )
    return out


def check(published_ref: str, release_ref: str | None) -> int:
    entries = load_ledger()
    published = corpus_digest(str(VECTORS))
    # First, because everything after it is about copies of a corpus, and this is
    # about whether the corpus is legible from outside at all. A rail that cannot read
    # a digest here cannot tell current from stale in either direction, so it reports
    # that its check did not run -- which is red, but red for the wrong reason, and the
    # right place to fix it is here.
    unpublished = publication_failures(published)
    if unpublished:
        print(
            "FAIL: this repository does not publish the corpus it has, so no consumer "
            "rail can check its own copy against it:",
            file=sys.stderr,
        )
        for failure in unpublished:
            print(f"  {failure}", file=sys.stderr)
        return 1
    # The default branch must publish the corpus it has, whatever release the
    # rails are measured against: its manifest field is what a reader of the
    # default branch fetches, so a stale one is a defect there now and is the
    # reference the next release would ship.
    published_corpus(published_ref)
    # What the rails could have vendored: the latest release the default branch
    # carries, because the vendoring script pins rails to release tags only.
    # Established after the checks above and before anything is said about a
    # copy, because every sentence from here on is a comparison against it and a
    # comparison against a reference that could not be read is not a result.
    pub = published_corpus(release_ref or latest_release(published_ref))
    behind = [e for e in entries if e.get("corpusDigest") != pub.digest]
    if behind:
        print(
            f"FAIL: {len(behind)} vendored cop(ies) do not carry the corpus the "
            f"latest release publishes ({pub.digest[:16]}..., {pub.ref} at "
            f"{pub.commit[:12]}):",
            file=sys.stderr,
        )
        for e in behind:
            print(
                f"  {e['id']} carries {str(e.get('corpusDigest'))[:16]}...",
                file=sys.stderr,
            )
        print(
            "\nRefresh each copy with the vendoring script that owns it, then re-run "
            "this gate with --sync so the ledger records what those copies now carry. "
            "Editing the ledger instead records an intention: the digests in it are "
            "read from the copies, never typed, and no regeneration here can move "
            "them.",
            file=sys.stderr,
        )
        return 1
    stale = claim_failures(len(entries), pub)
    if stale:
        print(
            "FAIL: every recorded copy carries the published corpus, but the report "
            "and that ledger do not agree:",
            file=sys.stderr,
        )
        for failure in stale:
            print(f"  {failure}", file=sys.stderr)
        print(
            "\nThese sentences are the only place a reader learns what the rails "
            "replay, and no rail can correct them: a lagging copy and its own stamp "
            "agree with each other perfectly. Rewrite them to the values above, or, "
            "if the disagreement is a count, register the rail the report names with "
            "--sync so there is a copy behind it.",
            file=sys.stderr,
        )
        return 1
    print(
        f"OK: {len(entries)} vendored cop(ies) carry the corpus the latest release "
        f"publishes ({pub.digest[:16]}..., {pub.ref} at {pub.commit[:12]}), and the "
        "report says so."
    )
    return 0


def parse_dirs(pairs: list[str]) -> dict[str, Path]:
    dirs: dict[str, Path] = {}
    for pair in pairs:
        copy_id, sep, where = pair.partition("=")
        if not sep:
            raise SystemExit(f"FAIL: --copy wants <id>=<vendored-dir>, got {pair!r}")
        dirs[copy_id] = Path(where).expanduser().resolve()
    return dirs


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="gate the ledger (what CI runs)")
    ap.add_argument(
        "--sync",
        action="store_true",
        help="rewrite the ledger from each copy's own vendor stamp",
    )
    ap.add_argument(
        "--copy",
        action="append",
        default=[],
        metavar="ID=DIR",
        help="the vendored corpus directory for one recorded copy, required by --sync",
    )
    ap.add_argument(
        "--published-ref",
        default=DEFAULT_PUBLISHED_REF,
        metavar="REF",
        help=(
            "the default branch: it must publish the corpus it has, and the "
            "release the rails are measured against is the newest one it carries "
            f"(default {DEFAULT_PUBLISHED_REF})"
        ),
    )
    ap.add_argument(
        "--release-ref",
        default=None,
        metavar="REF",
        help=(
            "measure the rails against this ref instead of the newest release "
            "tag the default branch carries (for staged tests only)"
        ),
    )
    args = ap.parse_args(argv[1:])
    if args.sync and sync(parse_dirs(args.copy)) != 0:
        return 1
    return check(args.published_ref, args.release_ref)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
