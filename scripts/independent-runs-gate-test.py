#!/usr/bin/env python3
"""Tests for the attempts half of scripts/independent-runs-gate.py.

The gate read ``runs`` and nothing else, and every row of ``runs`` carries a
``figures`` array, so a dispatch that was authorised, ran and produced no score
had no shape in the file and was invisible to the check. Two such dispatches
existed before the ``attempts`` array did. The cases below are about the one
property that array has to hold: an attempt records the dispatch and licenses no
figure, in the ledger and in the prose derived from it.

Every case runs against a STAGED COPY of the real files, never against the
repository itself, and the first case runs the copy unmutated. That first case is
not decoration: the gate's claims are declared against real prose in real
documents, so a fixture tree would refuse every case for the wrong reason and
would prove nothing about whether the gate is pointed at anything. A mutation
that refuses is only evidence when the same tree without it accepts.

Usage: python3 scripts/independent-runs-gate-test.py
Exit 0 when every case holds; 1 on a summary of the failures.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
# Everything the gate reads: the ledger, the changelog that owns revision
# numbering, the two publishing documents, and the third document one figure is
# carried by. Copying the whole tree would work and would say less -- this list
# is the gate's own read set, and a file added to it that is not staged here
# fails loudly in the first case rather than quietly in a later one.
STAGED = (
    "scripts/independent-runs-gate.py",
    "docs/INDEPENDENT-RUNS.json",
    "docs/IMPLEMENTATION-REPORT.md",
    "docs/research/independence.md",
    "vectors/CHANGES.md",
)
LEDGER = "docs/INDEPENDENT-RUNS.json"
INDEPENDENCE = "docs/research/independence.md"
# How many attempts the ledger holds, read from the ledger rather than written
# down here. The first case asserts that the gate's accepting output names the
# number it found, and a literal in this file would be a second place that number
# lives: it was written as two, a third dispatch was recorded, and the case then
# failed for the count rather than for anything the gate does.
ATTEMPT_COUNT = len(json.loads((REPO_ROOT / LEDGER).read_text(encoding="utf-8"))["attempts"])

Mutation = Callable[[Path], None]
# name, what to do to the staged copy, whether the gate must accept, and words
# its output has to carry.
Case = tuple[str, Mutation, bool, tuple[str, ...]]


def stage(destination: Path) -> None:
    for rel in STAGED:
        source = REPO_ROOT / rel
        if not source.is_file():
            raise SystemExit(f"{rel} is not a file in this repository; nothing to stage.")
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def run(root: Path) -> tuple[int, str]:
    done = subprocess.run(
        [sys.executable, str(root / "scripts" / "independent-runs-gate.py")],
        capture_output=True,
        text=True,
        check=False,
    )
    return done.returncode, done.stdout + done.stderr


def edit(root: Path, change: Callable[[dict[str, Any]], None]) -> None:
    path = root / LEDGER
    ledger = json.loads(path.read_text(encoding="utf-8"))
    change(ledger)
    path.write_text(json.dumps(ledger, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def unchanged(root: Path) -> None:
    del root


def figures_not_null(root: Path) -> None:
    """The negative the whole array exists for: an attempt carrying a figure.

    Recorded this way it would read exactly like a measured run, in a file whose
    runs array is what licenses a figure in the published prose.
    """

    def change(ledger: dict[str, Any]) -> None:
        ledger["attempts"][0]["figures"] = [
            {
                "figure": "9/9",
                "role": "score",
                "carriedIn": [{"file": INDEPENDENCE, "times": 1}],
            }
        ]

    edit(root, change)


def note_removed(root: Path) -> None:
    def change(ledger: dict[str, Any]) -> None:
        del ledger["attempts"][1]["figuresNote"]

    edit(root, change)


def open_outcome(root: Path) -> None:
    def change(ledger: dict[str, Any]) -> None:
        ledger["attempts"][0]["outcome"] = "did not really work out"

    edit(root, change)


def carries_revision(root: Path) -> None:
    """A suiteRevision on an attempt shrinks the not-run set, which is how a
    dispatch with no figure would come to license one."""

    def change(ledger: dict[str, Any]) -> None:
        ledger["attempts"][0]["suiteRevision"] = 27

    edit(root, change)


def label_dropped(root: Path) -> None:
    def change(ledger: dict[str, Any]) -> None:
        del ledger["runs"][0]["runLabel"]

    edit(root, change)


def label_same_code(root: Path) -> None:
    """A run of the author's own code by someone else is a reproduction, and it
    may not count toward independence however it is described."""

    def change(ledger: dict[str, Any]) -> None:
        ledger["runs"][0]["runLabel"] = "second-party-same-code"

    edit(root, change)


def array_removed(root: Path) -> None:
    def change(ledger: dict[str, Any]) -> None:
        del ledger["attempts"]

    edit(root, change)


def artifacts_emptied(root: Path) -> None:
    def change(ledger: dict[str, Any]) -> None:
        ledger["attempts"][1]["artifacts"] = []

    edit(root, change)


def retention_dropped(root: Path) -> None:
    def change(ledger: dict[str, Any]) -> None:
        ledger["attempts"][0]["artifacts"][0]["retention"] = ""

    edit(root, change)


def unresolved_dispatch(root: Path) -> None:
    def change(ledger: dict[str, Any]) -> None:
        ledger["attempts"][1]["dispatch"] = "run 35194072925"

    edit(root, change)


def prose_pairs_figure_with_dispatch(root: Path) -> None:
    """The one way a figure can attach to an attempt through prose alone: a
    sentence naming the dispatch and a score together."""
    path = root / INDEPENDENCE
    path.write_text(
        path.read_text(encoding="utf-8")
        + "\n\nThe contained dispatch at actions/runs/35194072925 returned 9/9.\n",
        encoding="utf-8",
    )


def replace_prose(root: Path, old: str, new: str) -> None:
    path = root / INDEPENDENCE
    text = path.read_text(encoding="utf-8")
    assert old in text, f"mutation anchor {old!r} moved"
    path.write_text(text.replace(old, new, 1), encoding="utf-8")


def scope_removed(root: Path) -> None:
    replace_prose(
        root,
        "It has not been run against suiteRevision ",
        "The historical list of unrun revisions is ",
    )


def scope_changed(root: Path) -> None:
    replace_prose(
        root,
        "It has not been run against suiteRevision 4, ",
        "It has not been run against suiteRevision 3, ",
    )


def figure_changed(root: Path) -> None:
    ledger = json.loads((root / LEDGER).read_text(encoding="utf-8"))
    figure = str(ledger["runs"][0]["figures"][0]["figure"])
    numerator, denominator = figure.split("/")
    replace_prose(root, figure, f"{int(numerator) - 1}/{denominator}")


def quotation_changed(root: Path) -> None:
    replace_prose(root, "This one is directed, and more so", "This one was directed, and more so")


def stale_publication_location(root: Path) -> None:
    def change(ledger: dict[str, Any]) -> None:
        ledger["runs"][0]["figures"][0]["carriedIn"][0]["file"] = "README.md"

    edit(root, change)


def roster_label_outside_set(root: Path) -> None:
    def change(ledger: dict[str, Any]) -> None:
        ledger["roster"][1]["label"] = "mostly independent"

    edit(root, change)


def roster_consent_removed(root: Path) -> None:
    def change(ledger: dict[str, Any]) -> None:
        del ledger["roster"][2]["consent"]

    edit(root, change)


def roster_posted_without_thread(root: Path) -> None:
    def change(ledger: dict[str, Any]) -> None:
        ledger["roster"][2]["consentThread"] = None

    edit(root, change)


def roster_removed(root: Path) -> None:
    def change(ledger: dict[str, Any]) -> None:
        del ledger["roster"]

    edit(root, change)


CASES: tuple[Case, ...] = (
    (
        "a roster label outside the three labels is refused",
        roster_label_outside_set,
        False,
        ("roster", "label"),
    ),
    (
        "a roster row without consent is refused",
        roster_consent_removed,
        False,
        ("roster", "consent"),
    ),
    (
        "a roster row whose consent names no thread is refused",
        roster_posted_without_thread,
        False,
        ("roster", "consentThread"),
    ),
    (
        "a ledger with no roster is refused",
        roster_removed,
        False,
        ("carries no roster",),
    ),
    (
        "the staged copy, unmutated, is accepted",
        unchanged,
        True,
        (
            f"{ATTEMPT_COUNT} dispatch(es) that returned no figure",
            "none of them licenses one",
        ),
    ),
    (
        "an attempt carrying a figure is refused",
        figures_not_null,
        False,
        ("figures must be null", "belongs in the runs array"),
    ),
    (
        "an attempt whose figuresNote was deleted is refused",
        note_removed,
        False,
        ("carries no figuresNote",),
    ),
    (
        "an outcome outside the closed set is refused",
        open_outcome,
        False,
        ("outcome must be one of", "completed-no-figure"),
    ),
    (
        "an attempt carrying a suiteRevision is refused",
        carries_revision,
        False,
        ("unexpected field 'suiteRevision'", "would shrink it"),
    ),
    (
        "a run with no runLabel is refused",
        label_dropped,
        False,
        ("runLabel must be one of", "second-party-same-code"),
    ),
    (
        "a same-code run cannot stand in the independence column",
        label_same_code,
        False,
        ("runLabel is second-party-same-code", "only an independent run"),
    ),
    (
        "a ledger with no attempts array at all is refused",
        array_removed,
        False,
        ("carries no attempts array",),
    ),
    (
        "an attempt leaving no artifacts behind is refused",
        artifacts_emptied,
        False,
        ("artifacts must list at least one location",),
    ),
    (
        "an artifact with no retention beside it is refused",
        retention_dropped,
        False,
        ("records no retention", "reads as permanent"),
    ),
    (
        "a dispatch recorded as something other than a URL is refused",
        unresolved_dispatch,
        False,
        ("must be a resolved https URL",),
    ),
    (
        "prose naming an attempt's dispatch and a figure in one sentence is refused",
        prose_pairs_figure_with_dispatch,
        False,
        ("names the dispatch of attempt", "invites a reader to take one as the other"),
    ),
    (
        "the moved not-run claim cannot be removed",
        scope_removed,
        False,
        (INDEPENDENCE, "scoping sentence was found 0 time(s)"),
    ),
    (
        "the moved not-run set must still match the ledger",
        scope_changed,
        False,
        (INDEPENDENCE, "but the ledger has no run for"),
    ),
    (
        "a posted score cannot change on the moved page",
        figure_changed,
        False,
        (INDEPENDENCE, "125/125", "a mention was altered"),
    ),
    (
        "a recorded quotation cannot change on the moved page",
        quotation_changed,
        False,
        (INDEPENDENCE, "does not carry the author's wording verbatim"),
    ),
    (
        "the publication record cannot point back to the old README",
        stale_publication_location,
        False,
        ("headline figure is not recorded as carried in", INDEPENDENCE),
    ),
)


def main() -> int:
    failures: list[str] = []
    for name, mutate, must_pass, needles in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "copy"
            root.mkdir()
            stage(root)
            mutate(root)
            code, output = run(root)
        passed = code == 0
        if passed != must_pass:
            failures.append(
                f"{name}: the gate {'accepted' if passed else 'refused'} (exit {code}) "
                f"where it had to {'accept' if must_pass else 'refuse'}.\n{output}"
            )
            continue
        silent = [needle for needle in needles if needle not in output]
        for needle in silent:
            failures.append(
                f"{name}: the gate reached the right verdict without saying {needle!r}, "
                f"so its output does not name what it found.\n{output}"
            )
        if not silent:
            print(f"  ok  {name}")
    if failures:
        print(f"\nFAIL: {len(failures)} case(s) did not hold:\n", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}\n", file=sys.stderr)
        return 1
    print(f"\nOK: {len(CASES)} case(s) held.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
