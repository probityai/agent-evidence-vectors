#!/usr/bin/env python3
"""The interoperability-evidence criterion, as a checker.

    python3 check_run_record.py <record.json> [...]
    python3 check_run_record.py --json <record.json>

A cross-run claim is evidence when a third party can obtain the same result
from what is published and compare it byte for byte. That reduces to four
inputs, and this checker looks for exactly those four:

    inputs      the artifact under test, at an immutable reference
    runner      the thing that ran, at an immutable reference or by digest
    invocation  the command line, verbatim
    output      the result, published, with a digest

Two further declarations do not decide whether a result can be obtained. They
decide what it means, so they are reported separately rather than folded into
the verdict:

    counting rule   what a figure's denominator counts, and how a member that
                    was not scored is counted
    independence    one of independent, self-report, or undeclared

A record missing any of the four is not re-checkable, and the checker names
which one. A record carrying all four is re-checkable, and whether it is
*independent* evidence, and whether its headline figure means what it appears
to mean, are the two separate questions the flags answer.

Three answers come back, and they are separate on purpose. `recheckable` says
whether a third party can obtain the same result. `figureMeansWhatItSays` says
whether the headline agrees with its own counting rule. `independence` is one of
independent, self-report or undeclared, and the last of those three is the
only one that is a defect in the record. A record can be fully
re-checkable, carry a figure nobody should quote, and be a self-report, and
folding those into one verdict is how each of them disappears.

Exit 0 when every record checked is re-checkable, its figure is honest, and
its independence is declared. A self-report is worth publishing and passes; a
record that leaves a reader to guess which one it is does not.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

#: A reference is immutable when nothing can move it. A full commit identifier
#: and a digest qualify. A branch name, a tag name and a bare version string do
#: not: a tag is a name its owner can re-point, and one project in this area
#: published a tag against the wrong commit and left it in place rather than
#: moving it, which is the honest response and also the proof that moving one
#: is possible.
IMMUTABLE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64}|sha256:[0-9a-f]{64})$")

REQUIRED = ("inputs", "runner", "invocation", "output")


def immutable_ref(value: object) -> bool:
    return isinstance(value, str) and bool(IMMUTABLE.match(value.strip()))


def check_side(side: dict, label: str) -> list[str]:
    """One direction of a cross-run: what a third party would need to redo it."""
    missing: list[str] = []
    inputs = side.get("inputs") or {}
    runner = side.get("runner") or {}
    output = side.get("output") or {}

    if not immutable_ref(inputs.get("ref")):
        missing.append(
            f"{label}: the inputs carry no immutable reference. A repository "
            "name and a version string name a thing that can change under the "
            "claim; a commit identifier or a digest names bytes."
        )
    if not immutable_ref(runner.get("ref")) and not immutable_ref(runner.get("digest")):
        missing.append(
            f"{label}: the runner carries no immutable reference and no digest. "
            "Naming the library the runner was built on is not naming the "
            "runner: the driver that loaded the inputs and emitted the result "
            "is the part a third party has to have."
        )
    invocation = side.get("invocation")
    if not isinstance(invocation, str) or not invocation.strip():
        missing.append(
            f"{label}: no invocation is published, so a third party cannot know "
            "what was asked of the runner, only what the runner is."
        )
    if not immutable_ref(output.get("digest")):
        missing.append(
            f"{label}: the result carries no digest, so a third party who "
            "re-runs it has nothing to compare against."
        )
    elif not output.get("published"):
        missing.append(
            f"{label}: the result carries a digest and is not published, so the "
            "digest is a claim about a file nobody else can hold."
        )
    return missing


def check_record(record: dict) -> dict:
    """The verdict for one run record, and the two declarations beside it."""
    sides = record.get("sides") or []
    missing: list[str] = []
    if not sides:
        missing.append("the record names no side that ran anything")
    for index, side in enumerate(sides, 1):
        missing.extend(check_side(side, side.get("label") or f"side {index}"))

    notes: list[str] = []
    honest_figure = check_figure(record.get("figure") or {}, notes)
    stance = check_independence(record.get("independence") or {}, notes)
    for side in sides:
        if not side.get("environment"):
            notes.append(
                f"{side.get('label') or 'a side'}: no environment is recorded. A "
                "result that turns out not to depend on the runtime is a "
                "stronger result, and nobody can establish that from a record "
                "that never named one."
            )
    return {
        "recheckable": not missing,
        "figureMeansWhatItSays": honest_figure,
        "independence": stance,
        "missing": missing,
        "notes": notes,
    }


def check_figure(figure: dict, notes: list[str]) -> bool:
    """Whether the headline agrees with its own counting rule."""
    honest_figure = True
    if figure and not figure.get("countingRule"):
        notes.append(
            "the headline figure states no counting rule. A figure written as "
            "N of N is read as N passes; when some members were deliberately "
            "not scored, the same run is also honestly describable as N members "
            "with no failures, and those are different claims."
        )
        return False
    if not figure:
        return True
    scored = figure.get("scored")
    total = figure.get("total")
    # Each unscored entry says how many members it covers, because a reason
    # covering four members and a reason covering one are one entry each and
    # the count is the only thing that reconciles with the total.
    withheld = sum(entry.get("count", 0) for entry in figure.get("notScored") or [])
    if isinstance(scored, int) and isinstance(total, int):
        if scored + withheld != total:
            honest_figure = False
            notes.append(
                f"the figure says {scored} scored of {total} and its unscored "
                f"entries account for {withheld}, which do not add up."
            )
        if scored != total and figure.get("headline") == f"{total} of {total}":
            honest_figure = False
            notes.append(
                f"the headline reads {total} of {total} and {scored} members "
                "were scored. The unscored members are enumerated, which is "
                "the honest half; the headline is the half that is read."
            )
    return honest_figure


def check_independence(independence: dict, notes: list[str]) -> str:
    """Three answers, not two.

    "Undeclared" is a defect in the record; "self-report" is a fact about the
    run that the record states, and the second is worth publishing while the
    first leaves a reader guessing.
    """
    if not independence.get("declared"):
        notes.append(
            "independence is not declared. Whether the party that ran the "
            "inputs authored them decides whether the result is independent "
            "evidence or a self-report, and a reader cannot infer it."
        )
        return "undeclared"
    if independence.get("runnerAuthoredInputs"):
        notes.append(
            "the party that ran the inputs authored them, so the result is a "
            "self-report. That is worth publishing and it is not independent "
            "evidence, and the record says so, which is the point."
        )
        return "self-report"
    return "independent"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="check a cross-run record")
    parser.add_argument("record", nargs="+", help="one or more run-record JSON files")
    parser.add_argument("--json", dest="as_json", action="store_true")
    args = parser.parse_args(argv[1:])

    report = {}
    worst = 0
    for path in args.record:
        with open(path, encoding="utf-8") as handle:
            record = json.load(handle)
        verdict = check_record(record)
        report[path] = verdict
        if (
            not verdict["recheckable"]
            or not verdict["figureMeansWhatItSays"]
            or verdict["independence"] == "undeclared"
        ):
            worst = 1

    if args.as_json:
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return worst

    for path, verdict in report.items():
        state = "re-checkable" if verdict["recheckable"] else "NOT re-checkable"
        figure = "figure honest" if verdict["figureMeansWhatItSays"] else "FIGURE MISLEADS"
        party = verdict["independence"]
        print(f"{path}: {state}, {figure}, {party}")
        for line in verdict["missing"]:
            print(f"  missing  {line}")
        for line in verdict["notes"]:
            print(f"  note     {line}")
    return worst


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
