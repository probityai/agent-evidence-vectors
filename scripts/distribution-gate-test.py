#!/usr/bin/env python3
"""Mutation proof for ``distribution-gate.py``.

A gate nobody has watched fail is a gate nobody has watched. Each case below
breaks one of the things the gate is for, in the shape that break would actually
arrive in, and requires a refusal that names it.

The recipe case edits one command in the inbound copy, which is how the drift
would really happen: somebody fixes a command in the README where it is
explained and never opens the second copy. The tag case bumps `CITATION.cff` and
leaves the prose behind, which is the ordering a release takes -- the citation
file is what a deposit reads, so it moves first. Four corpus cases cover the four
directions separately: a tracked corpus with no row, a row with no corpus, a
tracked corpus the run form does not offer, and an option the corpus set no
longer holds. They are separate cases because a gate that catches one of them can
be written without catching the others, and a missing-from-the-form corpus in
particular fails silently in the only place a stranger is asked to report a run.
A fifth renames a suite. Four more cover the module path: an install path that
is not this module's, a pinned tag whose `go.mod` declares a different path
(which is the shape a renamed owner leaves behind, and the shape that shipped),
a pinned tag this clone does not hold (which must report as a check that did not
run, never as a pass), and a `go.mod` with two module lines. The last case
renames the heading the recipe is found under, which is the failure that would
otherwise turn the whole recipe check into a no-op while the gate still printed
OK.

Two guards make the cases mean something. Every mutation hashes the file it
edits before and after and refuses when they match, so a mutation that silently
missed cannot report success. And the control asserts the unmutated copy passes,
so a gate that fails on everything cannot masquerade as a gate that catches
these.

The staged copy is a real git repository, initialised, committed AND TAGGED,
because the gate reads two things out of git on purpose: it enumerates corpora
with `git ls-files`, since the tracked tree is what a tag publishes, and it reads
`go.mod` at the pinned tag, since that is the byte-for-byte content a module
proxy serves for that tag. A test that handed it a bare directory would be
testing a different enumeration and skipping the tag read entirely.

The staged page's install path is REPAIRED to the staged `go.mod`'s module path
before the control runs, and the repair is asserted rather than assumed. That is
not the test papering over the tree: the tree it copies genuinely fails this
check right now, because every released tag predates the module path moving and
the page therefore still pins the old spelling on purpose. A control that failed
would make all thirteen refusals below meaningless, so the fixture is built in
the state the tree reaches when that tag is cut, and the tree's own current
failure is the gate doing its job rather than a case to encode here.

Usage: python3 scripts/distribution-gate-test.py
Exit 0 when every case behaves; 1 otherwise.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE_REL = Path("scripts") / "distribution-gate.py"
README_REL = Path("README.md")
PAGE_REL = Path("DISTRIBUTION.md")
CITATION_REL = Path("CITATION.cff")
GOMOD_REL = Path("go.mod")
FORM_REL = Path(".github") / "ISSUE_TEMPLATE" / "independent-run.yml"
INSTALL_LINE = re.compile(r"^go install (\S+)@(v\S+)\s*$", re.MULTILINE)
OTHER_OWNER = "github.com/not-this-owner/agent-evidence-vectors"


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _module_of(root: Path) -> str:
    found = re.findall(r"^module\s+(\S+)\s*$", (root / GOMOD_REL).read_text(), re.MULTILINE)
    assert len(found) == 1, f"the staged go.mod carries {len(found)} module lines"
    return str(found[0])


def _install_of(root: Path) -> tuple[str, str]:
    found = INSTALL_LINE.search((root / PAGE_REL).read_text(encoding="utf-8"))
    assert found is not None, "the staged page carries no `go install ...@vX` line"
    return found.group(1), found.group(2)


def _repair_install_path(root: Path) -> None:
    """Point the staged page's install command at the staged module path.

    Asserted as a POST-condition rather than as a diff, so this keeps holding
    once the tree itself names the current path and the repair becomes a no-op.
    """
    module = _module_of(root)
    package, tag = _install_of(root)
    suffix = package.rsplit("/cmd/", 1)[-1] if "/cmd/" in package else ""
    wanted = f"{module}/cmd/{suffix}" if suffix else module
    page = root / PAGE_REL
    page.write_text(
        page.read_text(encoding="utf-8").replace(
            f"go install {package}@{tag}", f"go install {wanted}@{tag}", 1
        ),
        encoding="utf-8",
    )
    fixed, _ = _install_of(root)
    if fixed != module and not fixed.startswith(f"{module}/"):
        raise AssertionError(
            f"the staged page still installs from {fixed!r}, which is not under {module!r}"
        )


def _staged_copy(tmp: Path) -> Path:
    """A committed, tagged git repository holding everything the gate reads."""
    root = tmp / "tree"
    (root / "scripts").mkdir(parents=True)
    (root / FORM_REL.parent).mkdir(parents=True)
    shutil.copy2(REPO_ROOT / GATE_REL, root / GATE_REL)
    for rel in (README_REL, PAGE_REL, CITATION_REL, FORM_REL, GOMOD_REL):
        shutil.copy2(REPO_ROOT / rel, root / rel)
    for manifest in sorted(REPO_ROOT.glob("vectors*/MANIFEST.json")):
        target = root / manifest.parent.name / "MANIFEST.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(manifest, target)
    _repair_install_path(root)
    _git(root, "init", "--quiet")
    _git(root, "config", "user.email", "gate@example.invalid")
    _git(root, "config", "user.name", "gate")
    # Pinned locally rather than inherited. A developer with `tag.gpgsign true`
    # in their global config turns the lightweight tag below into a signed
    # annotated one, which git then refuses for want of a message -- so the
    # fixture would fail on their machine and pass in CI, for a reason that has
    # nothing to do with what is under test.
    _git(root, "config", "tag.gpgSign", "false")
    _git(root, "config", "commit.gpgSign", "false")
    _git(root, "add", "-A")
    _git(root, "commit", "--quiet", "-m", "staged")
    # The tag the page pins has to exist and has to carry this go.mod, because
    # that pair is exactly what the gate reads: the module path a consumer is
    # told to fetch, at the version they are told to pin it to.
    _git(root, "tag", _install_of(root)[1])
    return root


def _run_gate(root: Path) -> tuple[int, str]:
    proc = subprocess.run(
        [sys.executable, str(root / GATE_REL), "--root", str(root)],
        capture_output=True,
        text=True,
        cwd=str(root),
    )
    return proc.returncode, proc.stdout + proc.stderr


def _edit(root: Path, rel: Path, change: Callable[[str], str]) -> None:
    path = root / rel
    before = path.read_text(encoding="utf-8")
    after = change(before)
    if _digest(before) == _digest(after):
        raise AssertionError(f"the mutation of {rel} changed nothing, so the case tests nothing")
    path.write_text(after, encoding="utf-8")


def case_recipe_drift(root: Path) -> str:
    """One command fixed in the README and not in the copy."""
    _edit(
        root,
        PAGE_REL,
        lambda text: text.replace(
            "python3 scripts/release-digests.py --check",
            "python3 scripts/release-digests.py --verify",
            1,
        ),
    )
    return "the verification recipe differs"


def case_tag_behind(root: Path) -> str:
    """The citation file moves to the next release and the prose does not."""
    _edit(
        root,
        CITATION_REL,
        lambda text: text.replace("version: 0.11.1", "version: 0.12.0", 1),
    )
    return "the released version is"


def case_untabled_corpus(root: Path) -> str:
    """A corpus lands and the inbound page never mentions it."""
    directory = root / "vectors-untabled"
    directory.mkdir()
    (directory / "MANIFEST.json").write_text(
        json.dumps({"suite": "untabled-conformance", "counts": {"accept": 1, "reject": 1}}),
        encoding="utf-8",
    )
    _git(root, "add", "-A")
    _git(root, "commit", "--quiet", "-m", "a corpus with no row")
    return "does not table it"


def case_unoffered_corpus(root: Path) -> str:
    """A corpus a reporter cannot name on the form we point them at."""
    _edit(
        root,
        FORM_REL,
        lambda text: text.replace('        - "vectors-aci/"\n', "", 1),
    )
    return "does not offer it"


def case_phantom_option(root: Path) -> str:
    """An option outliving the corpus it offers."""
    _edit(
        root,
        FORM_REL,
        lambda text: text.replace(
            '        - "vectors-aci/"\n',
            '        - "vectors-aci/"\n        - "vectors-withdrawn/"\n',
            1,
        ),
    )
    return "offers `vectors-withdrawn/`"


def case_stale_tag_in_prose(root: Path) -> str:
    """A version token in an ordinary sentence, left behind by a release.

    The three tag claims are each found by their own regex, so a tag named in a
    sentence none of them describes -- the releases row of the identifier table
    names one -- would be owned by nothing. This breaks that token and nothing
    else, so it fails only if the shape-based sweep is doing the work.
    """
    _edit(
        root,
        PAGE_REL,
        lambda text: text.replace(
            "`v0.11.1` is current",
            "`v0.9.0` is current",
            1,
        ),
    )
    return "the backticked version token `v0.9.0`"


def case_phantom_row(root: Path) -> str:
    """A row outlives the corpus it advertises."""
    _edit(
        root,
        PAGE_REL,
        lambda text: text.replace(
            "| `vectors-aci/` |",
            "| `vectors-withdrawn/` | `withdrawn-conformance` | nothing that ships |\n"
            "| `vectors-aci/` |",
            1,
        ),
    )
    return "no such corpus is tracked"


def case_suite_renamed(root: Path) -> str:
    """A corpus renames its suite and the table keeps the old name."""
    manifest = root / "vectors-aci" / "MANIFEST.json"
    loaded = json.loads(manifest.read_text(encoding="utf-8"))
    loaded["suite"] = "aci-renamed"
    _edit(root, Path("vectors-aci") / "MANIFEST.json", lambda _: json.dumps(loaded, indent=2))
    return "tables it as"


def case_install_path_not_ours(root: Path) -> str:
    """The page installs from a module path this repository does not publish."""
    package, tag = _install_of(root)
    _edit(
        root,
        PAGE_REL,
        lambda text: text.replace(
            f"go install {package}@{tag}", f"go install {OTHER_OWNER}/cmd/aee-verify@{tag}", 1
        ),
    )
    return "does not publish"


def case_tag_predates_the_module_path(root: Path) -> str:
    """The pinned tag was cut before the module path moved.

    Built the way it really arrives: the tag stays where it is, on a commit
    whose `go.mod` declares the old path, while the working tree moves on. Every
    proxy endpoint but `.mod` answers 200 for both spellings in that state,
    which is why it shipped.
    """
    module = _module_of(root)
    _, tag = _install_of(root)
    gomod = root / GOMOD_REL
    current = gomod.read_text(encoding="utf-8")
    gomod.write_text(current.replace(module, OTHER_OWNER, 1), encoding="utf-8")
    _git(root, "commit", "--quiet", "-a", "-m", "the module path before it moved")
    _git(root, "tag", "-f", tag)
    gomod.write_text(current, encoding="utf-8")
    _git(root, "commit", "--quiet", "-a", "-m", "move the module path")
    return "declares the module as"


def case_pinned_tag_absent(root: Path) -> str:
    """A tag the clone does not hold must read as a check that did not run."""
    _git(root, "tag", "-d", _install_of(root)[1])
    return "was NOT checked"


def case_two_module_lines(root: Path) -> str:
    """Two spellings of what this repository publishes is not a longer answer."""
    _edit(
        root,
        GOMOD_REL,
        lambda text: text + f"\nmodule {OTHER_OWNER}\n",
    )
    return "top-level `module` lines"


def case_heading_renamed(root: Path) -> str:
    """The recipe stops being findable by its own name."""
    _edit(
        root,
        README_REL,
        lambda text: text.replace(
            "## Verify a release without trusting us",
            "## Checking a release",
            1,
        ),
    )
    return "has no heading"


CASES: tuple[tuple[str, Callable[[Path], str]], ...] = (
    ("a command fixed in one copy of the recipe and not the other", case_recipe_drift),
    ("the citation file released ahead of the prose", case_tag_behind),
    ("a version token in prose left behind by a release", case_stale_tag_in_prose),
    ("a tracked corpus with no row on the inbound page", case_untabled_corpus),
    ("a tracked corpus the run form does not offer", case_unoffered_corpus),
    ("a run-form option for a corpus that is not tracked", case_phantom_option),
    ("a row for a corpus that is not tracked", case_phantom_row),
    ("a corpus whose suite name the table still spells the old way", case_suite_renamed),
    (
        "an install command for a module path this repository does not publish",
        case_install_path_not_ours,
    ),
    ("a pinned tag cut before the module path moved", case_tag_predates_the_module_path),
    ("a pinned tag this clone does not hold", case_pinned_tag_absent),
    ("a go.mod declaring the module path twice", case_two_module_lines),
    ("the recipe's heading renamed out from under the gate", case_heading_renamed),
)


def main() -> int:
    failures: list[str] = []

    with tempfile.TemporaryDirectory() as raw:
        control = _staged_copy(Path(raw))
        code, output = _run_gate(control)
        if code != 0:
            failures.append(
                "the control failed: the unmutated tree does not pass, so every refusal below "
                f"would be meaningless.\n{output}"
            )

    for label, mutate in CASES:
        with tempfile.TemporaryDirectory() as raw:
            root = _staged_copy(Path(raw))
            try:
                expected = mutate(root)
            except AssertionError as exc:
                failures.append(f"{label}: {exc}")
                continue
            code, output = _run_gate(root)
            if code == 0:
                failures.append(f"{label}: the gate passed a tree it must refuse.\n{output}")
            elif expected not in output:
                failures.append(
                    f"{label}: the gate refused but said nothing about it. Expected the refusal "
                    f"to contain {expected!r}.\n{output}"
                )

    if failures:
        print("distribution-gate-test: FAILED")
        for line in failures:
            print(f"  - {line}")
        return 1
    print(f"OK: the control passes and all {len(CASES)} mutations are refused by name.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
