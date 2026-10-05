#!/usr/bin/env python3
"""Check the distribution page against the shipped repository.

The release recipe must match ``docs/reference/release-verification.md`` byte
for byte. Its heading and fence must exist in both pages. Every advertised tag
must match ``CITATION.cff``, and the install path must match ``go.mod`` both in
the working tree and at the pinned tag.

The corpus table and run form must name exactly the tracked manifest set.
``scripts/count-gate.py`` checks published vector counts separately.

Usage: ``python3 scripts/distribution-gate.py [--root <tree>]``.
Exit 0 when every check passes, otherwise 1 with the disagreements.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

RECIPE_REL = "docs/reference/release-verification.md"
PAGE_REL = "DISTRIBUTION.md"
CITATION_REL = "CITATION.cff"
GOMOD_REL = "go.mod"
FORM_REL = ".github/ISSUE_TEMPLATE/independent-run.yml"
INSTALL_PAGES = ("README.md", PAGE_REL, "docs/guides/runner.md")

#: The page's one pinned install command, captured as (package path, tag). One
#: pattern rather than one per reader: the tag check and the module-path check
#: must rule on the SAME line, and two regexes over one line is how they come to
#: rule on different ones.
INSTALL_LINE = re.compile(r"^go install (\S+)@(v\S+)\s*$", re.MULTILINE)

#: The heading both files put the verification recipe under. Matching on the
#: heading rather than on a line number keeps the gate working when either file
#: is reorganised, and makes a renamed heading a loud failure instead of a quiet
#: one: the recipe is findable by its own name or it is not findable.
RECIPE_HEADING = "Verify a release without trusting us"

#: The heading in DISTRIBUTION.md whose table lists the corpora. Same argument.
CORPORA_HEADING = "The corpora this repository ships"

FENCE = "```"


class GateError(Exception):
    """The page disagrees with the repository."""


def _read(root: Path, rel: str) -> str:
    path = root / rel
    if not path.exists():
        raise GateError(f"{rel} does not exist, so nothing about it can be checked")
    return path.read_text(encoding="utf-8")


def _recipe_section(text: str, rel: str) -> str:
    """Return the text after the single required recipe heading."""
    markers = list(re.finditer(rf"^#+[ \t]+{re.escape(RECIPE_HEADING)}[ \t]*$", text, re.MULTILINE))
    if not markers:
        raise GateError(f"{rel} has no heading '{RECIPE_HEADING}'")
    if len(markers) != 1:
        raise GateError(f"{rel} has {len(markers)} headings '{RECIPE_HEADING}'; expected one")
    return text[markers[0].end() :]


def recipe_block(text: str, rel: str) -> str:
    """Return the first complete recipe fence, including its language tag.

    Parameters
    ----------
    text : str
        Markdown source containing one ``RECIPE_HEADING``.
    rel : str
        Repository path used in failure messages.

    Returns
    -------
    str
        The exact fenced block compared by :func:`_recipe_and_tag_failures`.

    Raises
    ------
    GateError
        The heading is absent or repeated, the recipe is missing, or its fence
        is unclosed. A block in a later section does not satisfy this heading.
    """
    section = _recipe_section(text, rel)
    start = re.search(r"^```[^\n]*$", section, re.MULTILINE)
    if start is None:
        raise GateError(f"{rel} has the heading '{RECIPE_HEADING}' and no fenced block under it")
    if re.search(r"^#{1,6}(?:[ \t]+[^\n]*)?$", section[: start.start()], re.MULTILINE):
        raise GateError(f"{rel} has the heading '{RECIPE_HEADING}' and no fenced block under it")
    remainder = section[start.end() :]
    end = re.search(r"^```[ \t]*$", remainder, re.MULTILINE)
    if end is None:
        raise GateError(f"{rel}: the fenced block under '{RECIPE_HEADING}' is never closed")
    return section[start.start() : start.end() + end.end()]


def released_version(text: str) -> str:
    """The `version` field of CITATION.cff, read without a YAML parser.

    A parser is the right tool and scripts/citation-metadata-gate.py uses one.
    This gate stays dependency-free on purpose: it is the gate that guards the
    page telling a stranger how to check a release, and a gate that cannot run
    in a fresh clone guards nothing there.
    """
    found = re.findall(r"^version:\s*(\S+)\s*$", text, re.MULTILINE)
    if len(found) != 1:
        raise GateError(
            f"{CITATION_REL} carries {len(found)} top-level `version:` lines; exactly one is "
            "readable. Two spellings of the released version is the drift this checks for."
        )
    return str(found[0]).strip("'\"")


def tags_claimed(page: str, recipe: str) -> dict[str, str]:
    """Every place the inbound page or the recipe commits to a version.

    Keyed by what the reader would be doing when they read it, because the
    failure message has to say which sentence sends them to the wrong bytes.
    """
    claims: dict[str, str] = {}

    checkout = re.search(r"^git checkout (v\S+)\s*$", recipe, re.MULTILINE)
    if checkout is None:
        raise GateError(
            "the verification recipe does not check out a tag. A recipe run on the default "
            "branch establishes which bytes the branch had today and nothing a citation can name."
        )
    claims["the recipe's `git checkout`"] = checkout.group(1)

    install = INSTALL_LINE.search(page)
    if install is None:
        raise GateError(
            f"{PAGE_REL} has no `go install ...@vX` line. `@latest` moves, and a verifier that "
            "moves cannot be what a reported run was run with."
        )
    claims["the `go install` pin"] = install.group(2)

    heading = re.search(r"^#+\s+The tag to cite\s*$\s*\n\s*`(v[^`]+)`", page, re.MULTILINE)
    if heading is None:
        raise GateError(
            f"{PAGE_REL} has no 'The tag to cite' section opening with a backticked tag. "
            "The tag a citation should name is the first thing an arriving reader needs."
        )
    claims["the tag-to-cite section"] = heading.group(1)

    # Every remaining backticked version token on the page, found by shape
    # rather than by a pattern per sentence. The three claims above each needed
    # their own regex, so each new sentence that names a tag would need a fourth
    # and a fifth, and the one nobody wrote is the one that goes stale. The page
    # is inbound and cites the current release, so a version token on it that is
    # not the released one is wrong by construction -- including inside a
    # sentence about some other repository, which is where the next one landed.
    for token in sorted(set(re.findall(r"`(v\d+\.\d+\.\d+)`", page))):
        claims.setdefault(f"the backticked version token `{token}`", token)
    return claims


def declared_module(text: str, rel: str) -> str:
    """The module path a `go.mod` declares, read without a Go toolchain.

    Exactly one top-level `module` line is readable. Two is not a longer answer,
    it is two spellings of what this repository publishes, which is the drift
    this whole gate exists to refuse.
    """
    found = re.findall(r"^module\s+(\S+)\s*$", text, re.MULTILINE)
    if len(found) != 1:
        raise GateError(
            f"{rel} carries {len(found)} top-level `module` lines; exactly one is readable."
        )
    return str(found[0])


def module_at_tag(root: Path, tag: str) -> str:
    """The module path `go.mod` declared at `tag`, read from the object store.

    This is the byte-for-byte content the module proxy serves as
    `<proxy>/<path>/@v/<tag>.mod`, which is why no network call is needed to
    learn what a consumer's toolchain will be told.

    A tag this clone does not hold raises rather than returning anything. "The
    tag is absent" and "the tag declares a different path" are different states
    and must never print the same way: a clone with no tags would otherwise turn
    the check into a pass.
    """
    shown = subprocess.run(
        ["git", "-C", str(root), "show", f"{tag}:{GOMOD_REL}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if shown.returncode != 0:
        raise GateError(
            f"{GOMOD_REL} at {tag} could not be read ({shown.stderr.strip() or 'git failed'}), "
            f"so whether the module path resolves at {tag} was NOT checked. This is not a pass: "
            "a tag this clone does not hold and a tag declaring the wrong path report the same "
            "way from here. Fetch the tags and run again."
        )
    return declared_module(shown.stdout, f"{GOMOD_REL} at {tag}")


def _module_path_failures(root: Path, page: str) -> list[str]:
    """The page's install path must be ours, and must resolve at the pinned tag."""
    try:
        module = declared_module(_read(root, GOMOD_REL), GOMOD_REL)
    except GateError as exc:
        return [str(exc)]
    install = INSTALL_LINE.search(page)
    if install is None:
        return []  # A page with no install line is already a failure above.
    package, tag = install.group(1), install.group(2)

    found: list[str] = []
    if package != module and not package.startswith(f"{module}/"):
        found.append(
            f"{PAGE_REL} tells a reader to `go install {package}@{tag}` and {GOMOD_REL} "
            f"declares this module as `{module}`. The page sends a stranger to a path this "
            "repository does not publish, which is the one command on the page they cannot "
            "recover from by reading the repository."
        )
    try:
        at_tag = module_at_tag(root, tag)
    except GateError as exc:
        return found + [str(exc)]
    if at_tag != module:
        found.append(
            f"the `go install` pin names {tag}, and {GOMOD_REL} at {tag} declares the module "
            f"as `{at_tag}` while this tree declares `{module}`. Tags are immutable, so that "
            f"is what the module proxy serves for {tag}: `go get {module}@{tag}` fails with "
            f"'module declares its path as: {at_tag}'. Pin a tag cut after the path moved."
        )
    return found


def tracked_corpora(root: Path) -> dict[str, str]:
    """Directory -> the suite name its manifest declares, for every tracked corpus.

    Enumerated from `git ls-files` rather than from a directory walk, for the
    reason scripts/release-digests.py gives: the tracked tree is what a tag
    publishes, so an untracked corpus on disk is not in the release and a
    tracked corpus missing from disk is a failure rather than a shorter list.
    """
    listed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "*/MANIFEST.json"],
        capture_output=True,
        text=True,
        check=True,
    )
    corpora: dict[str, str] = {}
    for rel in sorted(listed.stdout.split()):
        if rel.count("/") != 1 or not rel.endswith("/MANIFEST.json"):
            continue
        directory = rel.split("/")[0]
        if not (directory == "vectors" or directory.startswith("vectors-")):
            continue
        path = root / rel
        if not path.exists():
            raise GateError(f"{rel} is tracked and absent from disk")
        manifest = json.loads(path.read_text(encoding="utf-8"))
        suite = manifest.get("suite")
        if not isinstance(suite, str) or not suite:
            raise GateError(f"{rel} declares no `suite`, so the table has nothing to agree with")
        corpora[directory] = suite
    if not corpora:
        raise GateError("no tracked corpus manifest was found; refusing to call the table correct")
    return corpora


def tabled_corpora(page: str) -> dict[str, str]:
    """Directory -> suite name, as the inbound page's corpora table states them."""
    marker = re.search(rf"^#+\s+{re.escape(CORPORA_HEADING)}\s*$", page, re.MULTILINE)
    if marker is None:
        raise GateError(f"{PAGE_REL} has no heading '{CORPORA_HEADING}'")
    section = page[marker.end() :]
    following = re.search(r"^#+\s+\S", section, re.MULTILINE)
    if following is not None:
        section = section[: following.start()]
    rows: dict[str, str] = {}
    for line in section.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        directory = cells[0].strip("`").rstrip("/")
        suite = cells[1].strip("`")
        if directory == "vectors" or directory.startswith("vectors-"):
            if directory in rows:
                raise GateError(f"{PAGE_REL} tables `{directory}/` twice")
            rows[directory] = suite
    if not rows:
        raise GateError(
            f"{PAGE_REL}: the '{CORPORA_HEADING}' section tables no corpus. An empty table "
            "reads as a repository that ships none."
        )
    return rows


def offered_corpora(form: str) -> set[str]:
    """The corpus directories the independent-run form offers as choices.

    Read without a YAML parser for the reason released_version gives. The shape
    is fixed by the form: a dropdown's options are quoted scalars in a block
    list, and only the corpus dropdown's options are directory names.
    """
    offered = {
        match.group(1).rstrip("/")
        for match in re.finditer(r'^\s*-\s*"(vectors[^"]*)"\s*$', form, re.MULTILINE)
    }
    if not offered:
        raise GateError(
            f"{FORM_REL} offers no corpus to report a run against. A reporting path that "
            "cannot name the corpus collects a figure about nothing."
        )
    return offered


def _recipe_and_tag_failures(reference: str, page: str, citation: str) -> list[str]:
    """Compare recipe bytes and check every advertised tag against the release."""
    found: list[str] = []
    try:
        reference_recipe = recipe_block(reference, RECIPE_REL)
        page_recipe = recipe_block(page, PAGE_REL)
    except GateError as exc:
        return [str(exc)]

    if reference_recipe != page_recipe:
        found.append(
            f"the verification recipe differs between {RECIPE_REL} and {PAGE_REL}. "
            "Update both copies together."
        )
    try:
        version = released_version(citation)
        for where, tag in tags_claimed(page, page_recipe).items():
            if tag != f"v{version}":
                found.append(
                    f"{where} names {tag}; {CITATION_REL} says the released version is "
                    f"{version}. A page that sends a citation to a version the citation "
                    "file does not know about names bytes no tag holds."
                )
    except GateError as exc:
        found.append(str(exc))
    return found


def _corpus_failures(root: Path, page: str, form: str) -> list[str]:
    """The table and the run form must both hold exactly the tracked corpus set."""
    found: list[str] = []
    try:
        tracked = tracked_corpora(root)
        tabled = tabled_corpora(page)
        offered = offered_corpora(form)
    except GateError as exc:
        return [str(exc)]

    for directory in sorted(set(tracked) - set(tabled)):
        found.append(
            f"`{directory}/` is a tracked corpus and {PAGE_REL} does not table it. "
            "An arriving reader is never told it exists."
        )
    for directory in sorted(set(tabled) - set(tracked)):
        found.append(
            f"{PAGE_REL} tables `{directory}/` and no such corpus is tracked. "
            "The page advertises bytes the release does not carry."
        )
    for directory in sorted(set(tracked) & set(tabled)):
        if tracked[directory] != tabled[directory]:
            found.append(
                f"`{directory}/` declares suite `{tracked[directory]}` in its manifest and "
                f"{PAGE_REL} tables it as `{tabled[directory]}`."
            )
    for directory in sorted(set(tracked) - offered):
        found.append(
            f"`{directory}/` is a tracked corpus and {FORM_REL} does not offer it. "
            "A run against it cannot be reported by the route we ask people to use."
        )
    for directory in sorted(offered - set(tracked)):
        found.append(f"{FORM_REL} offers `{directory}/` and no such corpus is tracked.")
    return found


def _pin_failures(text: str, rel: str, label: str, pattern: re.Pattern[str],
                  expected: str, group: int = 1) -> list[str]:
    pins = [match.group(group) for match in pattern.finditer(text)]
    if not pins:
        return [f"{rel} has no pinned {label} command"]
    return [f"{rel}: {label} pin {pin} differs from release {expected}"
            for pin in pins if pin != expected]


def _consumer_pin_failures(root: Path, citation: str) -> list[str]:
    """Check the current consumer entry points, including Python and Action pins."""
    found: list[str] = []
    try:
        version = released_version(citation)
    except GateError as exc:
        return [str(exc)]
    patterns = (
        ("Go install", INSTALL_LINE, f"v{version}", 2),
    )
    for rel in INSTALL_PAGES:
        try:
            text = _read(root, rel)
        except GateError as exc:
            found.append(str(exc))
            continue
        for label, pattern, expected, group in patterns:
            found.extend(_pin_failures(text, rel, label, pattern, expected, group))
        found.extend(_python_install_failures(root, text, rel, version))
        if rel == "docs/guides/runner.md":
            action = re.compile(r"^- uses: probityai/agent-evidence-vectors@(\S+)", re.MULTILINE)
            found.extend(_pin_failures(text, rel, "GitHub Action", action, f"v{version}"))
    return found


def _source_install_failures(root: Path, pins: list[str], rel: str,
                             version: str) -> list[str]:
    """Match documented source bytes to the local release tag, without authenticating it."""
    selected = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", f"refs/tags/v{version}^{{commit}}"],
        capture_output=True, text=True, check=False,
    )
    if selected.returncode != 0:
        return [f"{rel}: Python source install tag v{version} does not resolve; fetch tags"]
    expected = "git+https://github.com/probityai/agent-evidence-vectors@" + selected.stdout.strip()
    return [f"{rel}: Python install pin {pin} differs from release source {expected}"
            for pin in pins if pin != expected]


def _python_install_failures(root: Path, text: str, rel: str, version: str) -> list[str]:
    """Check registry or source pins; registry availability is qualified separately."""
    registry = re.compile(r"^uvx agent-evidence-vectors==(\S+)", re.MULTILINE)
    source = re.compile(r"^uvx --from (\S+) agent-evidence-vectors(?:\s|$)", re.MULTILINE)
    source_pins = source.findall(text)
    commands = re.findall(r"^uvx(?:\s[^\n]*)?$", text, re.MULTILINE)
    if not commands:
        return [f"{rel} has no pinned Python install command"]
    found = [f"{rel}: unrecognized Python install command: {command}"
             for command in commands if not registry.match(command) and not source.match(command)]
    if source_pins:
        found.extend(_source_install_failures(root, source_pins, rel, version))
    if registry.search(text):
        found.extend(_pin_failures(text, rel, "Python install", registry, version))
    return found


def failures(root: Path) -> list[str]:
    """Every disagreement, collected rather than raised one at a time.

    A page wrong in two ways should print two lines. A gate that stops at the
    first fault turns one push into as many pushes as there are faults, and the
    second fault is then found by whoever the first fix was supposed to help.
    """
    try:
        reference = _read(root, RECIPE_REL)
        page = _read(root, PAGE_REL)
        citation = _read(root, CITATION_REL)
        form = _read(root, FORM_REL)
    except GateError as exc:
        return [str(exc)]

    return (
        _recipe_and_tag_failures(reference, page, citation)
        + _consumer_pin_failures(root, citation)
        + _module_path_failures(root, page)
        + _corpus_failures(root, page, form)
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    args = parser.parse_args()

    found = failures(args.root)
    if found:
        print("distribution-gate: the inbound page disagrees with the repository.")
        for line in found:
            print(f"  - {line}")
        return 1
    print(
        "OK: the verification recipe is one recipe, every tag on the inbound page is the "
        "released version, the `go install` path is this module's and resolves at the tag "
        "it pins, and the corpora table and the run form both name the tracked corpus set."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
