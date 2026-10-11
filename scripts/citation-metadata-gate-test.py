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

import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Callable
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "citation-metadata-gate.py"

ZENODO = ".zenodo.json"
CFF = "CITATION.cff"

Mutation = Callable[[Path], None]
Case = tuple[str, Mutation, tuple[str, ...]]


# A staged copy holds every tracked file as a loose object, so the first commit
# starts a background `git gc --auto` that can still be writing under `.git`
# when TemporaryDirectory removes the copy; CI failed on 2026-10-05 with
# "Directory not empty: release-order/.git". The same three settings, and the
# measurement behind them, are in spec-anchor-gate-test.py.
QUIESCENT = {
    "maintenance.auto": "false",
    "gc.auto": "0",
    "gc.autoDetach": "false",
}


def stage(destination: Path, dated: bool = True) -> None:
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
    for command in (
        ["git", "init", "-q"],
        *[["git", "config", key, value] for key, value in QUIESCENT.items()],
        ["git", "add", "-A"],
    ):
        subprocess.run(command, cwd=destination, check=True, capture_output=True)
    original_text = (destination / CFF).read_text(encoding="utf-8")
    original = yaml.safe_load(original_text)
    preferred = original.get("preferred-citation")
    if not isinstance(preferred, dict):
        raise AssertionError("the source candidate must name a published citation")
    published_text = original_text.split("preferred-citation:", 1)[0]
    published_text = re.sub(
        r"^version: \S+$",
        "version: " + str(preferred["version"]),
        published_text,
        flags=re.MULTILINE,
    )
    # A release cut from an undated source candidate carries no top-level
    # date-released; its date is the tagged commit's. Both shapes are published.
    if dated:
        published_text += 'date-released: "' + str(preferred["date-released"]) + '"\n'
    (destination / CFF).write_text(published_text, encoding="utf-8")
    subprocess.run(["git", "add", "-A"], cwd=destination, check=True, capture_output=True)
    instant = str(preferred["date-released"]) + "T12:00:00+0000"
    commit_with_dates(destination, instant, instant)
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=citation gate test",
            "-c",
            "user.email=citation-gate-test@example.invalid",
            "-c",
            "tag.gpgsign=false",
            "tag",
            "-a",
            "v" + str(preferred["version"]),
            "-m",
            "published citation fixture",
        ],
        cwd=destination,
        check=True,
        capture_output=True,
    )
    preferred["commit"] = subprocess.check_output(
        ["git", "rev-parse", "HEAD"],
        cwd=destination,
        text=True,
    ).strip()
    tag_object = subprocess.check_output(
        ["git", "rev-parse", "refs/tags/v" + str(preferred["version"])],
        cwd=destination,
        text=True,
    ).strip()
    preferred["identifiers"][0]["value"] = (
        "https://api.github.com/repos/probityai/agent-evidence-vectors/git/tags/" + tag_object
    )
    original_text = re.sub(
        r"^  commit: \S+$", "  commit: " + preferred["commit"], original_text, flags=re.MULTILINE
    )
    original_text = re.sub(
        r"(^      value: https://api.github.com/[^\n]+/git/tags/)\S+",
        lambda match: match.group(1) + tag_object,
        original_text,
        flags=re.MULTILINE,
    )
    (destination / CFF).write_text(original_text, encoding="utf-8")
    fixture_commit(destination, "prepare an undated source candidate")


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
    """The staged commit's stored calendar date, as YYYY-MM-DD."""
    done = subprocess.run(
        ["git", "show", "-s", "--format=%cs", "HEAD"],
        cwd=root,
        capture_output=True,
        text=True,
        check=True,
    )
    return done.stdout.strip()


def set_release_date(root: Path, value: str | None) -> None:
    path = root / CFF
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"^date-released:[^\n]*\n", "", text, flags=re.MULTILINE)
    if value is not None:
        text += f'date-released: "{value}"\n'
    path.write_text(text, encoding="utf-8")


def run(root: Path, timezone: str | None = None) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(GATE), "--root", str(root)],
        capture_output=True,
        text=True,
        env={**os.environ, "TZ": timezone} if timezone is not None else None,
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
    source_text = text.split("preferred-citation:", 1)[0] if rel == CFF else text
    found = list(re.finditer(pattern, source_text))
    if len(found) != 1:
        raise SystemExit(
            f"test setup: {len(found)} site(s) in {rel} match {pattern!r}, so this "
            "case would assert nothing. Fix the case, never the gate."
        )
    start, end = found[0].span(1)
    path.write_text(text[:start] + str(int(found[0].group(1)) + 1) + text[end:], encoding="utf-8")


def reword(root: Path, rel: str, pattern: str, replacement: str) -> None:
    """Rewrite the one span `pattern` matches, without restating what it says now.

    The replacement carries no figure, so the only thing the gate can object to
    is the span having gone missing.
    """
    path = root / rel
    text = path.read_text(encoding="utf-8")
    source_text = text.split("preferred-citation:", 1)[0] if rel == CFF else text
    found = list(re.finditer(pattern, source_text))
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
        lambda root: append(root, CFF, f"notes: the suite ships {corpus_total(root)} vectors\n"),
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
        lambda root: reword(
            root, CFF, r" for agent execution evidence", " for agent-execution-evidence"
        ),
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


def published_date(value: str | None) -> Mutation:
    def mutate(root: Path) -> None:
        released_at_its_tag(root)
        set_release_date(root, value)

    return mutate


DATE_CASES: list[Case] = [
    (
        "the published date differs from its tagged contents",
        published_date("2026-01-01"),
        ("is on a commit dated",),
    ),
    (
        "the published date is after its tagged contents",
        published_date("2999-01-01"),
        ("is on a commit dated",),
    ),
    ("the published date is not a date", published_date("spring"), ("is not a YYYY-MM-DD date",)),
    ("the published date is missing", published_date(None), ("carries no date-released",)),
    (
        "the candidate claims a date inside the old allowed window",
        lambda root: set_release_date(root, head_date(root)),
        ("source candidate must not carry date-released",),
    ),
]


def released_at_its_tag(root: Path) -> None:
    """The state the rule prescribes: a tag, and the date of that tag's commit."""
    path = root / CFF
    text = path.read_text(encoding="utf-8")
    path.write_text(text.split("preferred-citation:", 1)[0], encoding="utf-8")
    set_release_date(root, head_date(root))
    fixture_commit(root, "date the historical release")
    tag(root, f"v{source_version(root)}")


def source_version(root: Path) -> str:
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    return str(project["project"]["version"])


def fixture_commit(root: Path, message: str) -> None:
    subprocess.run(["git", "add", "-A"], cwd=root, check=True, capture_output=True)
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
            "--allow-empty",
            "-qm",
            message,
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )


def newer_divergent_release(root: Path, *, advance: bool) -> None:
    """A newer release on another branch, with an exact old or advanced HEAD."""
    released_at_its_tag(root)
    historical = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()
    fixture_commit(root, "a release cut separately from the default branch")
    major, minor, patch = (int(part) for part in source_version(root).split("."))
    tag(root, f"v{major}.{minor + 1}.{patch}")
    # Reset is confined to this disposable fixture, never a real source checkout.
    subprocess.run(
        ["git", "reset", "--hard", historical], cwd=root, check=True, capture_output=True
    )
    if advance:
        fixture_commit(root, "default branch advances without release metadata")


def publication_field(key: str, value: object) -> Mutation:
    def mutate(root: Path) -> None:
        path = root / CFF
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        data["preferred-citation"][key] = value
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    return mutate


def omit_publication(root: Path) -> None:
    path = root / CFF
    text = path.read_text(encoding="utf-8")
    path.write_text(text.split("preferred-citation:", 1)[0], encoding="utf-8")


IDENTITY_CASES: list[Case] = [
    (
        "duplicate source versions are ambiguous",
        lambda root: append(root, CFF, "version: " + source_version(root) + "\n"),
        ("duplicate citation keys",),
    ),
    (
        "duplicate published commits are ambiguous",
        lambda root: append(root, CFF, "  commit: " + "0" * 40 + "\n"),
        ("duplicate citation keys",),
    ),
    (
        "candidate omits the published identity",
        omit_publication,
        ("complete preferred published citation",),
    ),
    (
        "preferred source commit is false",
        publication_field("commit", "0" * 40),
        ("preferred-citation commit differs",),
    ),
    (
        "preferred tag object is false",
        publication_field("identifiers", []),
        ("exact annotated tag object",),
    ),
    (
        "preferred published date is false",
        publication_field("date-released", "2026-01-01"),
        ("preferred-citation date-released differs",),
    ),
    (
        "preferred release URL is false",
        publication_field("url", "https://example.invalid/"),
        ("preferred-citation url differs",),
    ),
    (
        "preferred citation authors differ from published bytes",
        publication_field("authors", []),
        ("authors differs from the published citation bytes",),
    ),
    (
        "preferred version names an absent publication",
        publication_field("version", "0.16.99"),
        ("published tag v0.16.99 does not resolve",),
    ),
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
        ("published citation bound to its tag",),
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


def check(
    group: str, cases: list[Case], want_refusal: bool, tmp: Path, dated: bool = True
) -> list[str]:
    failures: list[str] = []
    for index, (name, mutate, phrases) in enumerate(cases):
        root = tmp / f"{group}{index}"
        root.mkdir()
        stage(root, dated)
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


TIMEZONES = ("UTC", "America/New_York", "Pacific/Kiritimati")
DATED_CUTS = (
    ("2026-10-04T20:23:15-0400", "2026-10-05T00:23:15+0000", "2026-10-04", "2026-10-05"),
    ("2026-10-05T00:23:15+1400", "2026-10-04T10:23:15+0000", "2026-10-05", "2026-10-04"),
)


def commit_with_dates(root: Path, committer: str, author: str) -> None:
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=citation gate test",
            "-c",
            "user.email=citation-gate-test@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "--allow-empty",
            "-m",
            "dated release",
        ],
        cwd=root,
        env={**os.environ, "GIT_COMMITTER_DATE": committer, "GIT_AUTHOR_DATE": author},
        check=True,
        capture_output=True,
    )


def timezone_date_checks(tmp: Path) -> list[str]:
    """Bind to the committer's date across midnight, rather than the observer's.

    The author uses the same instant with a different calendar date. Both the
    author-date shortcut and conversion to the runner's date must fail these
    controls. An adjacent wrong date must still be refused in every timezone.
    """
    failures: list[str] = []
    for index, (committer, author, expected, wrong) in enumerate(DATED_CUTS):
        root = tmp / f"timezone{index}"
        root.mkdir()
        stage(root)
        path = root / CFF
        text = path.read_text(encoding="utf-8")
        path.write_text(text.split("preferred-citation:", 1)[0], encoding="utf-8")
        subprocess.run(["git", "add", "-A"], cwd=root, check=True, capture_output=True)
        commit_with_dates(root, committer, author)
        version = re.search(r"^version: (\S+)$", (root / CFF).read_text(), re.MULTILINE)
        assert version is not None, "the staged citation has no version to tag"
        tag(root, f"v{version.group(1)}")
        for timezone in TIMEZONES:
            set_release_date(root, expected)
            code, output = run(root, timezone)
            if code != 0:
                failures.append(f"stored committer date {expected} under {timezone}:\n{output}")
            set_release_date(root, wrong)
            code, output = run(root, timezone)
            if code == 0 or f"commit dated {expected}" not in output:
                failures.append(f"wrong release date {wrong} under {timezone}:\n{output}")
    return failures


def candidate_publication_checks(tmp: Path) -> list[str]:
    """A private candidate tag neither publishes the candidate nor permits a date."""
    root = tmp / "candidate-publication"
    root.mkdir()
    stage(root)
    tag(root, "v" + source_version(root))
    failures: list[str] = []
    for timezone in TIMEZONES:
        code, output = run(root, timezone)
        if code != 0:
            failures.append(f"undated candidate with a private tag under {timezone}:\n{output}")
        set_release_date(root, head_date(root))
        code, output = run(root, timezone)
        if code == 0 or "source candidate must not carry date-released" not in output:
            failures.append(f"invented candidate release date under {timezone}:\n{output}")
        set_release_date(root, None)
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
        failures.extend(check("undated-accept", ACCEPT_CASES[:1], False, tmp, dated=False))
        failures.extend(
            check("undated-identity", IDENTITY_CASES[2:6], True, tmp, dated=False)
        )
        failures.extend(timezone_date_checks(tmp))
        failures.extend(candidate_publication_checks(tmp))
    total = (
        len(STALE_CASES)
        + len(CENSUS_CASES)
        + len(DRIFT_CASES)
        + len(SOURCE_CASES)
        + len(DATE_CASES)
        + len(IDENTITY_CASES)
        + len(ACCEPT_CASES)
        + 2 * len(DATED_CUTS) * len(TIMEZONES)
        + 2 * len(TIMEZONES)
    )
    if failures:
        print(f"FAIL: {len(failures)} of {total} case(s) do not hold:", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        return 1
    refusals = total - len(ACCEPT_CASES) - (len(DATED_CUTS) + 1) * len(TIMEZONES)
    print(
        f"OK: {total} case(s), of which {refusals} assert a refusal the gate makes "
        "and name the figure it makes it about."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
