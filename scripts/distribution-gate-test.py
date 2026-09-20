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
A fifth renames a suite. The last case renames the heading the recipe is found
under, which is the failure that would otherwise turn the whole recipe check into
a no-op while the gate still printed OK.

Two guards make the cases mean something. Every mutation hashes the file it
edits before and after and refuses when they match, so a mutation that silently
missed cannot report success. And the control asserts the unmutated copy passes,
so a gate that fails on everything cannot masquerade as a gate that catches
these.

The staged copy is a real git repository, initialised and committed, because the
gate enumerates corpora with `git ls-files` on purpose: the tracked tree is what
a tag publishes. A test that handed it a bare directory would be testing a
different enumeration from the one that ships.

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
FORM_REL = Path(".github") / "ISSUE_TEMPLATE" / "independent-run.yml"


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def _staged_copy(tmp: Path) -> Path:
    """A committed git repository holding everything the gate reads."""
    root = tmp / "tree"
    (root / "scripts").mkdir(parents=True)
    (root / FORM_REL.parent).mkdir(parents=True)
    shutil.copy2(REPO_ROOT / GATE_REL, root / GATE_REL)
    for rel in (README_REL, PAGE_REL, CITATION_REL, FORM_REL):
        shutil.copy2(REPO_ROOT / rel, root / rel)
    for manifest in sorted(REPO_ROOT.glob("vectors*/MANIFEST.json")):
        target = root / manifest.parent.name / "MANIFEST.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(manifest, target)
    _git(root, "init", "--quiet")
    _git(root, "config", "user.email", "gate@example.invalid")
    _git(root, "config", "user.name", "gate")
    _git(root, "add", "-A")
    _git(root, "commit", "--quiet", "-m", "staged")
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


def released_version(root: Path) -> str:
    """The version CITATION.cff declares, read rather than hardcoded.

    Two cases below used to name the version of the day as a literal, and a
    release turned both of them into no-ops: the mutation replaced a string the
    page no longer contained, the page came back unchanged, and a case that
    changes nothing asserts nothing. It was caught by the harness refusing a
    mutation that edited no bytes, which is the only reason it was not a pair of
    green cases testing nothing for a whole release cycle.
    """
    text = (root / CITATION_REL).read_text(encoding="utf-8")
    found = re.findall(r"^version:\s*(\S+)\s*$", text, re.MULTILINE)
    if len(found) != 1:
        raise SystemExit(
            f"test setup: {CITATION_REL} carries {len(found)} version lines; "
            "the cases below mutate relative to exactly one."
        )
    return str(found[0]).strip("'\"")


def case_tag_behind(root: Path) -> str:
    """The citation file moves to the next release and the prose does not."""
    current = released_version(root)
    _edit(
        root,
        CITATION_REL,
        lambda text: text.replace(f"version: {current}", "version: 99.0.0", 1),
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
    current = released_version(root)
    _edit(
        root,
        PAGE_REL,
        lambda text: text.replace(
            f"`v{current}` is current",
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
