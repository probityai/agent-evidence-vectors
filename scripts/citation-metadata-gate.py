#!/usr/bin/env python3
"""Citation-metadata gate: the two files that decide how this corpus is cited
must parse, must agree with each other, and must carry an identifier that is
arithmetically well-formed.

Why this exists. `.zenodo.json` and `CITATION.cff` are the entire citation
identity of a repository whose stated purpose is to be cited by a conformance
requirement. Nothing checked them. They were correct on the day they were
written and checked by nothing on any day after, which is the same shape as a
gate that has never been watched to fail: it reads as a safeguard and holds
nothing up.

The failure modes this refuses, each of which is silent without it:

1. `CITATION.cff` stops being valid YAML. GitHub's "Cite this repository" panel
   then disappears with no error anywhere a maintainer would look, so the
   repository loses its citation affordance and still looks fine.
2. The two files DRIFT. They carry the author independently, so an edit to one
   is not an edit to the other, and a citation generated from the archive would
   then disagree with a citation generated from the repository.
3. The identifier acquires a typo. An ORCID is not an opaque string: its final
   character is an ISO 7064 MOD 11-2 check digit over the first fifteen, so a
   transposed or altered digit is DETECTABLE arithmetic rather than a thing
   somebody has to notice by eye. A wrong-but-plausible identifier resolves to
   the wrong person or to nothing, and does so quietly.
4. `.zenodo.json` states the SIZE of the corpus it deposits, and that number is
   typed. It said suite revision 20, 231 vectors, 54 accept and 175 reject while
   the corpus stood at revision 25, 250 vectors, 55 accept and 193 reject: five
   revisions of drift in the one file whose numbers cannot be corrected after
   the fact. Every other stale count in this repository is a file edit away from
   right. This one mints a DOI, and a DOI's metadata is what anybody who cites
   the corpus quotes from then on.

Why this file, rather than scripts/count-gate.py. That gate reads the tracked
prose of this repository and refuses an unaccounted count-shaped integer, and it
never saw this defect for a mechanical reason worth stating: its READ_SUFFIXES
are `.md`, `.yml`, `.yaml`, `.py`, `.go` and `.toml`. `.zenodo.json` is `.json`
and `CITATION.cff` is `.cff`, so neither file was ever read, and widening that
set to `.json` would pull in the manifest, the forcing baseline and every vector
in the corpus -- files whose integers are data rather than prose. The census is a
LIBRARY for exactly this reason (scripts/countcensus.py holds the mechanism and
no subject), so the citation surface becomes a second consumer of the same rule
over its own two named files. One implementation, two subjects.

The counts here are CHECKED and never emitted, for the reason count-gate.py
argues at length: a generator that rewrites the span it just read cannot fail,
and the sentence carrying the number is a sentence that argues.

Usage:
  uv run python scripts/citation-metadata-gate.py
  uv run python scripts/citation-metadata-gate.py --deposit
  uv run python scripts/citation-metadata-gate.py --root <tree>

Exit 0 when both files parse, agree, and are well-formed; 1 on any disagreement.
`--deposit` is the preflight for the irreversible act. It additionally requires
that the release CITATION.cff names carries the very corpus `.zenodo.json`
describes, because a deposit cut from a branch that has moved past the tag mints
a permanent record of a corpus no tag ever held.
Needs pyyaml, which is in the dev extra. A missing parser is a FAILURE, not a
skip: a gate that skips when its parser is absent is how an unparsed file gets
called checked.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from countcensus import (
    Census,
    Claim,
    Covered,
    Quantities,
    check_claims,
    read_tracked,
    run_census,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
ZENODO_REL = ".zenodo.json"
CFF_REL = "CITATION.cff"
MANIFEST_REL = "vectors/MANIFEST.json"
CHANGES_REL = "vectors/CHANGES.md"
PYPROJECT_REL = "pyproject.toml"
LOCK_REL = "uv.lock"

ORCID_PREFIX = "https://orcid.org/"


def zenodo_path() -> Path:
    return REPO_ROOT / ZENODO_REL


def cff_path() -> Path:
    return REPO_ROOT / CFF_REL


def orcid_check_digit_ok(identifier: str) -> bool:
    """ISO 7064 MOD 11-2 over the first fifteen digits, as ORCID specifies.

    Returns False for anything malformed rather than raising, because the caller
    reports; a checksum routine that throws on bad input turns a finding into a
    traceback.
    """
    digits = identifier.replace("-", "")
    if len(digits) != 16:
        return False
    body, check = digits[:15], digits[15].upper()
    if not body.isdigit():
        return False
    total = 0
    for ch in body:
        total = (total + int(ch)) * 2
    remainder = total % 11
    result = (12 - remainder) % 11
    expected = "X" if result == 10 else str(result)
    return check == expected


def read_zenodo() -> tuple[dict[str, Any] | None, list[str]]:
    path = zenodo_path()
    if not path.is_file():
        return None, [f"{ZENODO_REL} is absent; the archive deposit has no metadata"]
    try:
        data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as e:
        return None, [f"{ZENODO_REL} is not valid JSON: {e}"]
    return data, []


def read_cff() -> tuple[dict[str, Any] | None, list[str]]:
    path = cff_path()
    if not path.is_file():
        return None, [f"{CFF_REL} is absent; the repository has no citation affordance"]
    try:
        import yaml  # noqa: PLC0415
    except ImportError as e:
        return None, [
            f"pyyaml is not installed, so {CFF_REL} could not be parsed ({e}). "
            "This gate fails rather than skips: an unparsed file must never be "
            "reported as a checked one."
        ]
    try:
        data: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        return None, [
            f"{CFF_REL} is not valid YAML: {e}. GitHub's citation panel "
            "disappears silently when this happens."
        ]
    if not isinstance(data, dict):
        return None, [f"{CFF_REL} does not parse to a mapping"]
    return data, []


def _zenodo_people(data: dict[str, Any]) -> list[dict[str, Any]]:
    creators = data.get("creators")
    return [c for c in creators if isinstance(c, dict)] if isinstance(creators, list) else []


def _cff_people(data: dict[str, Any]) -> list[dict[str, Any]]:
    authors = data.get("authors")
    return [a for a in authors if isinstance(a, dict)] if isinstance(authors, list) else []


def check_identifiers(
    zenodo: dict[str, Any], cff: dict[str, Any]
) -> list[str]:
    """Every identifier present is well-formed, and the two files agree."""
    errors: list[str] = []

    z_people = _zenodo_people(zenodo)
    c_people = _cff_people(cff)
    if not z_people:
        errors.append(".zenodo.json declares no creators")
    if not c_people:
        errors.append("CITATION.cff declares no authors")
    if errors:
        return errors

    if len(z_people) != len(c_people):
        errors.append(
            f"the two files name a different number of people "
            f"({len(z_people)} in .zenodo.json, {len(c_people)} in CITATION.cff); "
            "a citation from the archive would not match one from the repository"
        )

    z_ids = sorted(str(c["orcid"]) for c in z_people if c.get("orcid"))
    c_ids = sorted(
        str(a["orcid"]).removeprefix(ORCID_PREFIX) for a in c_people if a.get("orcid")
    )
    if z_ids != c_ids:
        errors.append(
            f"the identifiers disagree: .zenodo.json has {z_ids or 'none'}, "
            f"CITATION.cff has {c_ids or 'none'} (compared with the URL prefix "
            "removed, which is the form each format wants)"
        )

    for ident in set(z_ids) | set(c_ids):
        if not orcid_check_digit_ok(ident):
            errors.append(
                f"{ident!r} fails the ISO 7064 MOD 11-2 check digit an ORCID "
                "carries, so it is a typo rather than an identifier"
            )

    # The URL form is what CITATION.cff wants; a bare identifier there is
    # accepted by some readers and dropped by others.
    for a in c_people:
        raw = a.get("orcid")
        if raw is not None and not str(raw).startswith(ORCID_PREFIX):
            errors.append(
                f"CITATION.cff carries {raw!r} without the {ORCID_PREFIX} prefix; "
                "that form is silently dropped by some readers"
            )
    return errors


# --------------------------------------------------------------------------
# What the two files agree about besides the people
# --------------------------------------------------------------------------


def fold(text: object) -> str:
    return " ".join(str(text).split())


def check_agreement(zenodo: dict[str, Any], cff: dict[str, Any]) -> list[str]:
    """Title, licence, keywords and repository: one subject or two records.

    Each of these is carried independently by both files, so an edit to one is
    not an edit to the other, and the archive record and the repository record
    then describe subtly different artifacts under one name. The keyword sets
    had already parted: `.zenodo.json` carried `evidence` and `CITATION.cff` did
    not, which is a discovery surface present in one index and absent from the
    other for no reason anybody chose.
    """
    errors: list[str] = []
    if fold(zenodo.get("title")) != fold(cff.get("title")):
        errors.append(
            f"the titles disagree: .zenodo.json has {fold(zenodo.get('title'))!r}, "
            f"CITATION.cff has {fold(cff.get('title'))!r}"
        )
    if fold(zenodo.get("license")) != fold(cff.get("license")):
        errors.append(
            f"the licences disagree: .zenodo.json has {zenodo.get('license')!r}, "
            f"CITATION.cff has {cff.get('license')!r}"
        )
    z_words = {fold(k) for k in zenodo.get("keywords") or []}
    c_words = {fold(k) for k in cff.get("keywords") or []}
    if z_words != c_words:
        errors.append(
            "the keyword sets disagree; only in .zenodo.json: "
            f"{sorted(z_words - c_words) or 'none'}, only in CITATION.cff: "
            f"{sorted(c_words - z_words) or 'none'}"
        )
    repo = fold(cff.get("repository-code")).rstrip("/")
    linked = {
        fold(r.get("identifier")).rstrip("/")
        for r in zenodo.get("related_identifiers") or []
        if isinstance(r, dict)
    }
    if repo and repo not in linked:
        errors.append(
            f"CITATION.cff points at {repo!r} and .zenodo.json relates the deposit "
            f"to {sorted(linked) or 'nothing'}; a deposit that does not name its "
            "own source is not traceable back to it"
        )
    return errors


def locked_version() -> str | None:
    """The version `uv.lock` pins for this project, or None if it pins none.

    Read by pattern rather than by a TOML parse of the whole lock, because the
    only thing wanted here is the one `[[package]]` table whose source is this
    directory: every other version in the file belongs to a dependency and must
    not be compared to anything.
    """
    path = REPO_ROOT / LOCK_REL
    if not path.is_file():
        return None
    locked = tomllib.loads(path.read_text(encoding="utf-8"))
    for package in locked.get("package", []):
        if not isinstance(package, dict):
            continue
        source = package.get("source")
        if isinstance(source, dict) and source.get("virtual") == ".":
            return fold(package.get("version"))
    return None


def check_version(cff: dict[str, Any]) -> list[str]:
    """The released version is one fact, and THREE files state it.

    `pyproject.toml` is what a build stamps, `CITATION.cff` is what a citation
    quotes, and `uv.lock` is what a locked install resolves. Nothing tied the
    first two together, so a release bump in one was a silent no-op in the other.

    The lock joined them on 2026-09-20 and it joined them the hard way: the 0.12.0
    bump edited four files, the lock was not one of them, and the mismatch
    surfaced only because a site build happened to invoke uv, which rewrote the
    line as a side effect. A version carried by a file no gate reads is a version
    that travels by accident. An ABSENT lock is not a failure -- a checkout that
    does not lock its own dependencies is a legitimate shape -- but a lock that
    pins a DIFFERENT version is, because a locked install then resolves bytes
    under a version nobody released.
    """
    path = REPO_ROOT / PYPROJECT_REL
    if not path.is_file():
        return [f"{PYPROJECT_REL} is absent, so the released version has no source"]
    project = tomllib.loads(path.read_text(encoding="utf-8")).get("project", {})
    declared = fold(project.get("version"))
    cited = fold(cff.get("version"))
    if declared != cited:
        return [
            f"CITATION.cff cites version {cited!r} and {PYPROJECT_REL} declares "
            f"{declared!r}; a citation names a release that was never built"
        ]
    locked = locked_version()
    if locked is not None and locked != declared:
        return [
            f"{PYPROJECT_REL} declares version {declared!r} and {LOCK_REL} pins "
            f"{locked!r}; a locked install resolves a version that was never released"
        ]
    return []


DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _git(root: Path, *arguments: str) -> str | None:
    """A git read, or None when it did not succeed. Never a value on failure."""
    done = subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode != 0:
        return None
    return done.stdout.strip()


def commit_date(root: Path, ref: str) -> str | None:
    """The committer date of what `ref` points at, as UTC `YYYY-MM-DD`."""
    return _git(
        root, "show", "-s", "--format=%cd", "--date=format-local:%Y-%m-%d",
        f"{ref}^{{commit}}")


def newest_release_tag(root: Path) -> tuple[str, str] | None:
    """The most recently dated `v*` tag, as (name, date), or None if there is none."""
    listed = _git(root, "for-each-ref", "--format=%(refname:short)", "refs/tags/v*")
    if not listed:
        return None
    # The COMMIT date of each tag, not the tag object's own creation date. An
    # annotated tag carries both, they are not the same date, and the field being
    # checked is about the released contents rather than about when somebody ran
    # `git tag`. Resolving each one separately costs a handful of git calls over
    # a handful of tags and removes a whole class of off-by-a-day disagreement.
    rows = [(name, commit_date(root, name)) for name in listed.split()]
    dated = [(name, date) for name, date in rows if date]
    if not dated:
        return None
    return max(dated, key=lambda row: row[1])


def check_release_date(cff: dict[str, Any]) -> list[str]:
    """`date-released` is the date of the release it names, and nothing else.

    The defect: the value stood at 2026-08-12 through two version bumps. It was
    written for 0.7.0, carried unchanged into 0.8.0 and 0.9.0 -- `git diff v0.8.0
    v0.9.0 -- CITATION.cff` shows one changed line, the version, and the date
    untouched -- and the tag it then described was cut on 2026-09-02. GitHub's
    citation panel renders that field verbatim, so the repository told every
    citer a release date three weeks before the release. `check_version` above
    tied the two version fields together and said nothing about the date, so a
    field that moves on exactly the same occasions as the version was checked by
    nothing.

    The rule has three arms because the field has three honest states, and a
    two-arm branch over three states approves the one it never named:

    1. The tag `v<version>` EXISTS. Then the date is not a matter of judgement:
       it is the committer date of that tag's commit, and any other value is a
       claim about a release that can be checked and is false.
    2. The tag does not exist yet, and there is at least one earlier `v*` tag.
       The version is being prepared, so the true release date is not yet
       knowable. What IS knowable is the window: not earlier than the last
       release (a date before it is a value carried forward, which is this
       defect) and not later than the commit being described (a date after it is
       a release that has not happened). The window only ever grows at the top,
       so a correct value stays correct as commits land, and arm 1 binds it
       exactly the moment the tag is cut.
    3. There are no `v*` tags at all -- a fresh checkout, or the staged copy this
       gate's own test builds. Then only the upper bound is checkable, and it is
       checked. What cannot be established is reported as unchecked rather than
       assumed to hold.
    """
    raw = cff.get("date-released")
    if raw is None:
        return [
            "CITATION.cff carries no date-released. GitHub's citation panel renders "
            "that field, and its absence is not a neutral state: the citation it "
            "generates then dates the release to nothing."
        ]
    released = fold(raw)
    if not DATE_PATTERN.match(released):
        return [
            f"CITATION.cff has date-released {released!r}, which is not a "
            "YYYY-MM-DD date. A citation quotes it verbatim."
        ]
    version = fold(cff.get("version"))
    tag = f"v{version}"
    tagged = commit_date(REPO_ROOT, tag)
    if tagged is not None:
        if released != tagged:
            return [
                f"CITATION.cff dates the release {released} and tag {tag} is on a "
                f"commit dated {tagged}. The date-released field is the date of the "
                "release it names; every citer quotes it, and it moves whenever the "
                "version does."
            ]
        return []
    head = commit_date(REPO_ROOT, "HEAD")
    if head is None:
        return [
            f"no tag {tag!r} resolves and HEAD does not resolve either, so nothing "
            "here can say what release date would be true. This is reported rather "
            "than passed over: an unchecked field is not a checked one."
        ]
    if released > head:
        return [
            f"CITATION.cff dates the release {released} and the commit it describes "
            f"is dated {head}. A release cannot predate its own contents."
        ]
    newest = newest_release_tag(REPO_ROOT)
    if newest is None:
        return []
    name, date = newest
    if released < date:
        return [
            f"CITATION.cff dates version {version} at {released}, which is earlier "
            f"than tag {name} on {date}. A date-released older than the previous "
            "release is a value carried forward from it rather than a date of this "
            f"one; set it no earlier than {date} until {tag} exists, and to that "
            "tag's commit date once it does."
        ]
    return []


# --------------------------------------------------------------------------
# The corpus the deposit describes
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Corpus:
    """The corpus as it stands, derived rather than declared."""

    revision: int
    total: int
    accept: int
    reject: int
    indeterminate: int
    digest: str


REVISION_HEADING = re.compile(r"^## suiteRevision (\d+)\b", re.MULTILINE)
CORPUS_ROW = re.compile(
    r"Corpus:\s*\*{0,2}(\d+) vectors \((\d+) accept, (\d+) reject"
    r"(?:, (\d+) indeterminate)?\)",
    re.MULTILINE,
)


def read_corpus(root: Path) -> tuple[Corpus | None, list[str]]:
    """Three readings of one corpus, and a refusal if they disagree.

    The manifest's `counts` field is written by a generator and is as typable as
    any sentence, so it is never the sole authority here: it is checked against
    the entries the manifest carries and against the vector files on disk, and
    the head row of the changelog is checked against all three. A deposit is
    permanent, so the number it publishes descends from a root that has been
    made to agree with itself in four ways rather than one.
    """
    manifest_path = root / MANIFEST_REL
    changes_path = root / CHANGES_REL
    if not manifest_path.is_file() or not changes_path.is_file():
        return None, [
            f"{MANIFEST_REL} or {CHANGES_REL} is absent, so nothing says what size "
            "the corpus being deposited is"
        ]
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    errors: list[str] = []
    kinds: dict[str, int] = {}
    # Per-kind against the ROWS, because one flat directory of
    # content-addressed statements holds every kind and cannot be split by
    # verdict -- which is exactly why it is flat. The directory is still in the
    # chain: the total below is grounded in it.
    for kind in ("accept", "reject", "indeterminate"):
        declared = int(manifest["counts"][kind])
        carried = sum(1 for v in entries if v.get("kind") == kind)
        kinds[kind] = declared
        if declared == carried:
            continue
        errors.append(
            f"{MANIFEST_REL}: it declares {declared} {kind} vector(s) and carries "
            f"{carried} entr(ies)"
        )
    on_disk = len(list((root / "vectors" / "statements").glob("*.json")))
    if on_disk != len(entries):
        errors.append(
            f"{MANIFEST_REL}: it carries {len(entries)} entr(ies) and "
            f"vectors/statements/ holds {on_disk} file(s)"
        )
    total = len(entries)
    if sum(kinds.values()) != total:
        errors.append(
            f"{MANIFEST_REL}: the per-kind counts sum to {sum(kinds.values())} and "
            f"the manifest carries {total} entr(ies)"
        )

    text = changes_path.read_text(encoding="utf-8")
    headings = REVISION_HEADING.findall(text)
    row = CORPUS_ROW.search(text)
    if not headings or row is None:
        errors.append(
            f"{CHANGES_REL} carries no revision heading or no head corpus row, so "
            "the deposit has no revision number to name"
        )
        return None, errors
    revision = max(int(h) for h in headings)
    head = (int(row.group(1)), int(row.group(2)), int(row.group(3)), int(row.group(4) or 0))
    stands = (total, kinds["accept"], kinds["reject"], kinds["indeterminate"])
    if head != stands:
        errors.append(
            f"{CHANGES_REL}: its head row says {head} (total, accept, reject, "
            f"indeterminate) and {MANIFEST_REL} says {stands}"
        )
    if errors:
        return None, errors
    return (
        Corpus(
            revision=revision,
            total=total,
            accept=kinds["accept"],
            reject=kinds["reject"],
            indeterminate=kinds["indeterminate"],
            digest=str(manifest["corpusDigest"]),
        ),
        [],
    )


# --------------------------------------------------------------------------
# The counts inside the deposit description
# --------------------------------------------------------------------------


def deposit_claims(corpus: Corpus) -> list[Claim]:
    """Every count-bearing span of the deposit description, and what it must say.

    Matched on the prose either side of the value, so rewording the sentence or
    deleting it fails here rather than quietly leaving the number unchecked.
    """
    return [
        Claim(
            ZENODO_REL,
            "the deposited suite revision",
            "This deposit covers suite revision ",
            " of the corpus",
            str(corpus.revision),
        ),
        Claim(
            ZENODO_REL,
            "the deposited corpus total",
            "of the corpus: ",
            " vectors, of which",
            str(corpus.total),
        ),
        Claim(
            ZENODO_REL,
            "the deposited accept count",
            "vectors, of which ",
            " accept,",
            str(corpus.accept),
        ),
        Claim(
            ZENODO_REL,
            "the deposited reject count",
            " accept, ",
            " reject and",
            str(corpus.reject),
        ),
        Claim(
            ZENODO_REL,
            "the deposited indeterminate count",
            " reject and ",
            " are indeterminate",
            str(corpus.indeterminate),
        ),
        Claim(
            ZENODO_REL,
            "the deposited corpus digest",
            "fixed by the corpus digest ",
            " recorded in vectors/MANIFEST.json",
            corpus.digest,
        ),
    ]


# Digit-carrying forms in these two files that are not corpus counts, blanked to
# same-length filler so every offset into the file stays exact: an ORCID, a
# semantic version, the CFF schema version, an SPDX identifier, a hexadecimal
# digest and any URL.
MASKS = (
    re.compile(r"\d{4}-\d{4}-\d{4}-\d{3}[\dXx]"),
    re.compile(r"\b\d+\.\d+(?:\.\d+)?\b"),
    re.compile(r"\b[A-Za-z][A-Za-z0-9]*-\d+(?:\.\d+)*\b"),
    re.compile(r"\b[0-9a-f]{40,}\b"),
    re.compile(r"https?://\S+"),
)

CENSUS = Census(
    masks=MASKS,
    nouns=(
        (re.compile(r"\b(\d+)\s+vectors\b"), "a digit run counting vectors"),
        (
            re.compile(r"\b(\d+)\s+(?:accept|reject|indeterminate)\b"),
            "a digit run counting one family of the corpus",
        ),
        (
            re.compile(r"\bsuite\s+revision\s+(\d+)\b"),
            "a digit run naming a suite revision",
        ),
    ),
    small_value_nouns=re.compile(
        r"vector|accept|reject|indeterminate|revision|corpus|suite"
    ),
)


def quantities(corpus: Corpus) -> Quantities:
    """The values these two files are entitled to publish.

    The indeterminate count is deliberately absent for the reason
    scripts/count-gate.py gives: the bucket is two vectors, and `2` collides with
    ordinary prose everywhere. It is not left unchecked -- read_corpus grounds it
    in the entries, the files on disk and the changelog, and deposit_claims
    publishes it as a declared span.
    """
    return Quantities(
        current={
            corpus.total: "the corpus total",
            corpus.accept: "the accept count",
            corpus.reject: "the reject count",
            corpus.revision: "the current suiteRevision",
        }
    )


def check_counts(corpus: Corpus) -> tuple[list[str], int]:
    """The declared claims, then a census over the whole citation surface.

    The claims catch the count that has gone stale. The census catches the next
    count-shaped integer somebody types into either file, which is the defect
    that produced this gate: a number nothing was reading.
    """
    texts = read_tracked(
        REPO_ROOT, {".json", ".cff"}, paths=[ZENODO_REL, CFF_REL]
    )
    missing = [rel for rel in (ZENODO_REL, CFF_REL) if rel not in texts]
    if missing:
        return [
            f"{', '.join(missing)} is not tracked by git, so the census read no "
            "text for it and would report a coverage it never had"
        ], 0
    failures, covered = check_claims(deposit_claims(corpus), texts)
    spans: dict[str, list[Covered]] = dict(covered)
    census_out, examined = run_census(CENSUS, quantities(corpus), texts, spans)
    return failures + census_out, examined


# --------------------------------------------------------------------------
# The preflight for the irreversible act
# --------------------------------------------------------------------------


def check_deposit_readiness(cff: dict[str, Any], corpus: Corpus) -> list[str]:
    """The release being cited must hold the corpus being deposited.

    A DOI's metadata is permanent and quotable. `CITATION.cff` tells a citer to
    name the released version rather than the branch, so a deposit whose numbers
    come from a branch that has moved past that tag mints a record of a corpus no
    release ever held -- and nobody can later tell which one was meant.
    """
    version = fold(cff.get("version"))
    tag = f"v{version}"
    shown = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "show", f"{tag}:{MANIFEST_REL}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if shown.returncode != 0:
        return [
            f"CITATION.cff cites version {version!r} and no tag {tag!r} resolves in "
            f"this repository ({fold(shown.stderr)[:120]}). A deposit has to be cut "
            "from a release, because the record it mints cannot be re-cut."
        ]
    tagged = json.loads(shown.stdout)["counts"]
    stands = {
        "accept": corpus.accept,
        "reject": corpus.reject,
        "indeterminate": corpus.indeterminate,
    }
    if {k: int(v) for k, v in tagged.items()} != stands:
        return [
            f"the working tree describes {stands} and tag {tag} holds "
            f"{ {k: int(v) for k, v in tagged.items()} }. Depositing now would mint "
            "a permanent record whose counts belong to no release. Tag the corpus "
            "being deposited, bump the version in pyproject.toml and CITATION.cff, "
            "then deposit."
        ]
    return []


def main() -> int:
    global REPO_ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=REPO_ROOT,
        help="the tree to check; a staged copy when this gate's own test runs it",
    )
    parser.add_argument(
        "--deposit",
        action="store_true",
        help="additionally require that the cited release holds the deposited corpus",
    )
    args = parser.parse_args()
    REPO_ROOT = args.root.resolve()

    zenodo, errors = read_zenodo()
    cff, cff_errors = read_cff()
    errors = errors + cff_errors
    examined = 0
    if zenodo is not None and cff is not None:
        errors += check_identifiers(zenodo, cff)
        errors += check_agreement(zenodo, cff)
        errors += check_version(cff)
        errors += check_release_date(cff)
    corpus, corpus_errors = read_corpus(REPO_ROOT)
    errors += corpus_errors
    if corpus is not None:
        count_errors, examined = check_counts(corpus)
        errors += count_errors
        if args.deposit and cff is not None:
            errors += check_deposit_readiness(cff, corpus)

    if errors:
        print(
            f"FAIL: the citation metadata is not self-consistent "
            f"({len(errors)} problem(s)):",
            file=sys.stderr,
        )
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    if examined == 0:
        print(
            "FAIL: the census examined no count-shaped integer at all. An empty "
            "subject set passes every run while enforcing nothing, which is the "
            "state this gate exists to be distinguishable from.",
            file=sys.stderr,
        )
        return 1
    print(
        "OK: both citation files parse, name the same people, agree on title, "
        "licence, keywords and source, carry a version the build declares and a "
        "release date consistent with the tag that holds it, and "
        f"every identifier passes its check digit. {examined} count-shaped "
        "integer(s) across the citation surface are accounted for, and every "
        "count the deposit publishes descends from vectors/MANIFEST.json."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
