#!/usr/bin/env python3
"""Tests for scripts/citation-metadata-gate.py.

Every case but two asserts a REFUSAL, and here that matters more than it does
anywhere else in this repository. A count typed into a README goes stale and is
corrected by an edit. A count typed into `.zenodo.json` goes stale and is minted
into a DOI, whose metadata is permanent, quotable, and not correctable by anyone
who later notices. `.zenodo.json` had already drifted five revisions -- it said
suite revision 20, 231 vectors, 54 accept, 175 reject -- and nothing in the
repository was reading it, because the count gate reads `.md`, `.yml`, `.yaml`,
`.py`, `.go` and `.toml`, and this file is `.json`. The gate that now reads it
has to be watched to go red, or it is the same safeguard the old one was.

Every case runs against a STAGED COPY of this repository, never against the
repository itself: the claims are declared against real prose in real files, so
a fixture tree would fail every one of them for the wrong reason and prove
nothing about whether the gate is pointed at anything. The copy is a real git
checkout, because the census enumerates what it reads with `git ls-files`.

The two accepting cases are there to show this is not a gate that refuses
everything, and the second is the one that matters: an ordinary number that
stands for nothing about the corpus is left alone. A gate nobody can satisfy
gets deleted.

Usage: uv run --extra dev python scripts/citation-metadata-gate-test.py
Exit 0 when every case holds; 1 on the first summary of failures.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "citation-metadata-gate.py"

ZENODO = ".zenodo.json"
CFF = "CITATION.cff"

Mutation = Callable[[Path], None]
Case = tuple[str, Mutation, tuple[str, ...]]


def stage(destination: Path) -> None:
    """Copy the tracked tree into a fresh git checkout.

    The census enumerates its subject with `git ls-files` rather than by walking
    the filesystem, so a copy that was not a git repository would present it with
    an empty file list and a green run that read nothing.
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
    for command in (["git", "init", "-q"], ["git", "add", "-A"]):
        subprocess.run(command, cwd=destination, check=True, capture_output=True)
    # And a COMMIT, because the gate now reads dates off the history: the release
    # date is checked against the commit being described and against the tags that
    # exist. A checkout with no HEAD is not a state any real clone is in, and
    # staging one would have the gate report "nothing here can say", which is a
    # true statement about an unreal tree.
    subprocess.run(
        [
            "git",
            "-c",
            "user.email=citation-gate-test@example.invalid",
            "-c",
            "user.name=citation gate test",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "staged copy",
        ],
        cwd=destination,
        check=True,
        capture_output=True,
    )


def tag(root: Path, name: str) -> None:
    """Tag HEAD in a staged copy. `tag.gpgsign` is off: this machine signs tags
    by default, and a test that reaches for a signing key fails for the
    environment rather than for the thing under test."""
    subprocess.run(
        ["git", "-c", "tag.gpgsign=false", "tag", name],
        cwd=root,
        check=True,
        capture_output=True,
    )


def head_date(root: Path) -> str:
    """The committer date of the staged copy's one commit, as UTC YYYY-MM-DD."""
    done = subprocess.run(
        ["git", "show", "-s", "--format=%cd", "--date=format-local:%Y-%m-%d", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return done.stdout.strip()


def set_release_date(root: Path, value: str) -> None:
    reword(root, CFF, r'date-released: "[^"]+"', f'date-released: "{value}"')


def run(root: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(GATE), "--root", str(root)],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.returncode, proc.stdout + proc.stderr


def retype(root: Path, rel: str, pattern: str) -> None:
    """Add one to the number `pattern` captures, so the file states a wrong figure.

    A case that names the RIGHT value in order to replace it restates a measured
    number in a second place, where nothing re-measures it, and goes stale the
    moment the corpus moves -- which is the defect under test. Perturbing
    whatever the file currently carries keeps the case pinned to the shape.

    A second match is refused for the reason a missing one is: the case would
    still run, and would be asserting something about whichever site the pattern
    reached first.
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
    path.write_text(
        text[:start] + str(int(found[0].group(1)) + 1) + text[end:], encoding="utf-8"
    )


def reword(root: Path, rel: str, pattern: str, replacement: str) -> None:
    """Rewrite the one span `pattern` matches, without restating what it says now.

    The replacement carries no figure, so the only thing the gate can object to
    is the span having gone missing.
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


def append(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.write_text(path.read_text(encoding="utf-8") + text, encoding="utf-8")


def corpus_total(root: Path) -> int:
    """The live corpus size out of the staged manifest.

    One case below plants a number that IS a published count, so the census has
    something to object to. Typing that number here is what would make the case
    rot: an integer equal to nothing is exactly the case it is meant to be
    distinguished from.
    """
    import json  # noqa: PLC0415

    loaded = json.loads((root / "vectors" / "MANIFEST.json").read_text(encoding="utf-8"))
    return len(loaded["vectors"])


# A stale figure in the deposit description: the defect this gate was built for,
# once per number the description publishes.
STALE_CASES: list[Case] = [
    (
        "the deposited suite revision has drifted from the changelog",
        lambda root: retype(root, ZENODO, r"suite revision (\d+) of the corpus"),
        ("the deposited suite revision",),
    ),
    (
        "the deposited corpus total has drifted from the manifest",
        lambda root: retype(root, ZENODO, r"of the corpus: (\d+) vectors"),
        ("the deposited corpus total",),
    ),
    (
        "the deposited accept count has drifted from the manifest",
        lambda root: retype(root, ZENODO, r"of which (\d+) accept"),
        ("the deposited accept count",),
    ),
    (
        "the deposited reject count has drifted from the manifest",
        lambda root: retype(root, ZENODO, r"accept, (\d+) reject"),
        ("the deposited reject count",),
    ),
    (
        "the deposited corpus digest names bytes the manifest does not",
        lambda root: reword(
            root,
            ZENODO,
            r"fixed by the corpus digest [0-9a-f]{40,}",
            "fixed by the corpus digest " + "0" * 64,
        ),
        ("the deposited corpus digest",),
    ),
    (
        "the sentence carrying every count is reworded away",
        lambda root: reword(
            root,
            ZENODO,
            r"This deposit covers suite revision [^.]*\.",
            "This deposit covers the corpus.",
        ),
        ("was found 0 time(s)",),
    ),
]

# A count-shaped integer typed into the citation surface that nothing accounts
# for: the next instance of the same defect, in whatever wording it arrives.
CENSUS_CASES: list[Case] = [
    (
        "a live corpus size typed into the citation record",
        lambda root: append(
            root, CFF, f"notes: the suite ships {corpus_total(root)} vectors\n"
        ),
        ("nothing accounts for it",),
    ),
]

# The archive record and the repository record describing different artifacts.
DRIFT_CASES: list[Case] = [
    (
        "the two files carry different keyword sets",
        lambda root: reword(root, CFF, r"\n  - evidence", ""),
        ("keyword sets disagree",),
    ),
    (
        "the two files carry different titles",
        # Pinned to the title as it stands. It was pinned to the previous title
        # and the rename removed that line, so this case refused to run rather
        # than assert nothing, which is the design working: a case whose
        # mutation cannot be built is a case that proves nothing, and it says so
        # instead of passing.
        lambda root: reword(root, CFF, r" for agent execution evidence",
                            " for agent-execution-evidence"),
        ("titles disagree",),
    ),
    (
        "the cited version names a release the build does not declare",
        # The patch component is `\d+` and not `0`. It was `0`, which made the
        # pattern match only releases whose patch number happened to be zero, so
        # the first patch release turned this case into one that could not build
        # its mutation. It refused rather than assert nothing, which is the
        # design, but the shape it is pinned to is a version and not a version
        # ending in zero.
        lambda root: retype(root, CFF, r"\nversion: 0\.(\d+)\.\d+"),
        ("cites version",),
    ),
]

# The root the deposit's numbers descend from, made to disagree with itself.
SOURCE_CASES: list[Case] = [
    (
        "the manifest declares more accept vectors than it carries",
        lambda root: retype(root, "vectors/MANIFEST.json", r'"accept": (\d+)'),
        ("it declares",),
    ),
]

def declared_version_tag() -> Mutation:
    """Set a known-wrong date, then tag the staged copy at the version it declares.

    Arm 1 of the gate's rule binds date-released to the commit date of the tag
    named `v<version>`, so the case has to tag whatever version the file carries
    rather than a version somebody wrote down when the case was added.
    """

    def mutate(root: Path) -> None:
        set_release_date(root, "2026-01-01")
        text = (root / CFF).read_text(encoding="utf-8")
        found = re.search(r"\nversion: (\S+)", text)
        if found is None:
            raise SystemExit(
                "test setup: CITATION.cff in the staged copy declares no version, so "
                "this case cannot know which tag to create and would assert nothing. "
                "Fix the case, never the gate."
            )
        tag(root, f"v{found.group(1)}")

    return mutate


def dated_tag(name: str) -> Mutation:
    """Set a known-wrong release date, then tag the staged copy.

    A named function rather than a lambda pairing two calls: both helpers return
    None, so a tuple expression would give the case a Mutation returning
    tuple[None, None] and every type checker in this repository refuses it.
    """

    def mutate(root: Path) -> None:
        set_release_date(root, "2026-01-01")
        tag(root, name)

    return mutate


# The release date, which moves on exactly the same occasions as the version and
# was checked by nothing. It stood at 2026-08-12 through two version bumps while
# the tag it described was cut on 2026-09-02.
DATE_CASES: list[Case] = [
    # Each of these two SETS the date it needs rather than relying on the
    # committed one being wrong. They used to tag the staged copy and let the
    # repository's own stale value supply the disagreement, which worked only
    # while that value was stale: the staged copy's single commit is made today,
    # so the moment date-released became today's date -- which is exactly what
    # cutting a release makes it -- neither case could construct its mutation
    # and both reported that the gate had accepted a defect it was never shown.
    (
        "the tag exists and the date is not its commit date",
        declared_version_tag(),
        # The version is not named here. It used to be, as "tag v0.10.0", and the
        # first patch release moved the file out from under the case: the gate
        # looks for the tag matching the version the file declares, found no
        # v0.10.1, and answered from a different arm of its rule. The phrase
        # below belongs to arm 1 and to no other, which is what the case is
        # actually asserting.
        ("is on a commit dated",),
    ),
    (
        "the date is older than the previous release",
        dated_tag("v0.9.0"),
        ("earlier than tag v0.9.0",),
    ),
    (
        "the date is after the commit it describes",
        lambda root: set_release_date(root, "2999-01-01"),
        ("cannot predate its own contents",),
    ),
    (
        "the date is not a date",
        lambda root: set_release_date(root, "spring"),
        ("is not a YYYY-MM-DD date",),
    ),
    (
        "there is no date at all",
        lambda root: reword(root, CFF, r'\ndate-released: "[^"]+"', ""),
        ("carries no date-released",),
    ),
]

def released_at_its_tag(root: Path) -> None:
    """The state the rule prescribes: a tag, and the date of that tag's commit."""
    set_release_date(root, head_date(root))
    fixture_commit(root, "date the historical release")
    tag(root, f"v{source_version(root)}")


def source_version(root: Path) -> str:
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return str(project["project"]["version"])


def fixture_commit(root: Path, message: str) -> None:
    subprocess.run(["git", "add", "-A"], cwd=root, check=True, capture_output=True)
    subprocess.run(
        ["git", "-c", "user.email=citation-gate-test@example.invalid", "-c",
         "user.name=citation gate test", "-c", "commit.gpgsign=false", "commit",
         "--allow-empty", "-qm", message],
        cwd=root, check=True, capture_output=True,
    )


def newer_divergent_release(root: Path, *, advance: bool) -> None:
    """A newer release on another branch, with an exact old or advanced HEAD."""
    released_at_its_tag(root)
    historical = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root,
                                check=True, capture_output=True, text=True).stdout.strip()
    fixture_commit(root, "a release cut separately from the default branch")
    major, minor, patch = (int(part) for part in source_version(root).split("."))
    tag(root, f"v{major}.{minor + 1}.{patch}")
    # Reset is confined to this disposable fixture, never a real source checkout.
    subprocess.run(["git", "reset", "--hard", historical], cwd=root,
                   check=True, capture_output=True)
    if advance:
        fixture_commit(root, "default branch advances without release metadata")


IDENTITY_CASES: list[Case] = [
    (
        "advanced source metadata misses a divergent newer release",
        lambda root: newer_divergent_release(root, advance=True),
        ("source metadata still names", "not the exact cited historical checkout"),
    ),
]


ACCEPT_CASES: list[Case] = [
    ("the repository as it stands", lambda root: None, ("are accounted for",)),
    (
        "the version is tagged and the date is that tag's commit date",
        released_at_its_tag,
        ("release date consistent with the tag",),
    ),
    (
        "an exact historical release remains valid with a newer divergent tag",
        lambda root: newer_divergent_release(root, advance=False),
        ("are accounted for",),
    ),
    (
        "an ordinary number that stands for nothing about the corpus",
        lambda root: append(root, CFF, "notes: the rail reads a 4096 byte buffer\n"),
        ("are accounted for",),
    ),
]


def check(group: str, cases: list[Case], want_refusal: bool, tmp: Path) -> list[str]:
    failures: list[str] = []
    for index, (name, mutate, phrases) in enumerate(cases):
        root = tmp / f"{group}{index}"
        root.mkdir()
        stage(root)
        mutate(root)
        code, output = run(root)
        if want_refusal and code == 0:
            failures.append(f"{name}: the gate accepted it")
            continue
        if not want_refusal and code != 0:
            failures.append(f"{name}: the gate refused it:\n{output}")
            continue
        missing = [phrase for phrase in phrases if phrase not in output]
        if missing:
            failures.append(
                f"{name}: the right exit status, and the output does not carry "
                f"{missing!r}. A refusal that names the wrong thing sends the next "
                f"person to the wrong file.\n{output}"
            )
    return failures


def main() -> int:
    failures: list[str] = []
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        failures.extend(check("stale", STALE_CASES, True, tmp))
        failures.extend(check("census", CENSUS_CASES, True, tmp))
        failures.extend(check("drift", DRIFT_CASES, True, tmp))
        failures.extend(check("source", SOURCE_CASES, True, tmp))
        failures.extend(check("date", DATE_CASES, True, tmp))
        failures.extend(check("identity", IDENTITY_CASES, True, tmp))
        failures.extend(check("accept", ACCEPT_CASES, False, tmp))
    total = (
        len(STALE_CASES)
        + len(CENSUS_CASES)
        + len(DRIFT_CASES)
        + len(SOURCE_CASES)
        + len(DATE_CASES)
        + len(IDENTITY_CASES)
        + len(ACCEPT_CASES)
    )
    if failures:
        print(f"FAIL: {len(failures)} of {total} case(s) do not hold:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    refusals = total - len(ACCEPT_CASES)
    print(
        f"OK: {total} case(s), of which {refusals} assert a refusal the gate makes "
        "and name the figure it makes it about."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
