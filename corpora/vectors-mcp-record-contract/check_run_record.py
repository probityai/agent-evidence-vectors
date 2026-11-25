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

A v0.1 report of the W3C Agent Conformance and Benchmarking Community Group is
read directly, with no mapping step:

    python3 check_run_record.py --v01 <records-directory>
    python3 check_run_record.py --v01 <records-directory>/reports/<name>.json

The records directory holds `reports/<name>.json`, `configs/<name>.json`,
`run.json` and `SHA256SUMS`, and a README beside it that prints the command.
Every value comes from one of those files and nothing is invented, so a value
that is not there is reported as missing. See `read_v01_report` for where each
of the four inputs and the two declarations is read from.

Exit 2 means the checker could not read what it was given (a file that is not a
run record, a v0.1 report passed without --v01, a records directory with a file
missing). That is never an answer about the record, so it is never exit 1.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

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

V01_FORMAT = "public-agent-conformance/report/v0.1"

#: A reference after an at sign in a configuration's `checker` field, for
#: example `owner/repo@<commit>/path` or `verify.mjs@sha256:<digest>`.
CHECKER_REF = re.compile(r"@([^\s/,]+)")


class Unreadable(Exception):
    """The input is not in a shape this checker can read; never a finding."""


def _load_json(path: Path, what: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise Unreadable(f"{what} is missing: {path}") from None
    except (OSError, ValueError) as error:
        raise Unreadable(f"{what} cannot be read as JSON ({path}): {error}") from None
    if not isinstance(value, dict):
        raise Unreadable(f"{what} is not a JSON object: {path}")
    return value


def _sums(path: Path) -> dict[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise Unreadable(f"SHA256SUMS cannot be read ({path}): {error}") from None
    found: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            found[parts[1].strip().lstrip("*")] = parts[0].lower()
    return found


def _invocation(records: Path, run: dict) -> tuple[str | None, list[str]]:
    """The command as the README prints it, verbatim.

    run.json carries a template with placeholders, which is a command that was
    never run in that form. The README beside the records directory prints the
    one that was; the line is the one that runs the same script the template
    names, with flags and no placeholder.
    """
    template = run.get("command")
    script = None
    if isinstance(template, str):
        for token in template.split():
            if re.search(r"\.(py|mjs|js|sh)$", token):
                script = token.rsplit("/", 1)[-1]
                break
    readme = records.parent / "README.md"
    if not script or not readme.is_file():
        return None, []
    pattern = re.compile(r"(?<![\w./-])" + re.escape(script) + r"\s+--\S")
    lines = []
    for line in readme.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if "`" in text or "<" in text or not pattern.search(text):
            continue
        if text not in lines:
            lines.append(text)
    if len(lines) == 1:
        return lines[0], []
    if lines:
        return None, [f"the README prints {len(lines)} different commands that run {script}, so the invocation is ambiguous"]
    return None, []


def _runner(config: dict) -> dict:
    """The runner's reference, read from the configuration's `checker` field.

    Every `@reference` in it must be immutable: a commit or a digest. When one
    is not, that one is reported, so a runner that names a tag is flagged
    rather than passed on the strength of its sibling.
    """
    refs = CHECKER_REF.findall(str(config.get("checker") or ""))
    if not refs:
        return {}
    mutable = [ref for ref in refs if not immutable_ref(ref)]
    return {"ref": (mutable or refs)[0]}


def read_v01_report(report: Path, invocation: str | None = None) -> tuple[dict, list[str], list[str]]:
    """A run record built from a v0.1 report and the files beside it.

    Returns the record, then the problems that make it not re-checkable, then
    the problems that make its figure mislead. Where each value is read from:

    inputs      configs/<name>.json `inputs`, when it names exactly one artifact
    runner      configs/<name>.json `checker`, every `@reference` in it
    invocation  the README line that runs the script run.json's command names
    output      SHA256SUMS' line for reports/<name>.json, published when the
                file hashes to that digest
    environment run.json `environment`
    figure      the report's roll-up; scored and total are recounted from checks
    independence run.json `runner-wrote` against the names of the inputs
    """
    if report.parent.name != "reports":
        raise Unreadable(f"{report} is not under a reports/ directory of a records directory")
    records = report.parent.parent
    body = _load_json(report, "the report")
    if body.get("format") != V01_FORMAT:
        raise Unreadable(f"{report} is not a {V01_FORMAT} report (format: {body.get('format')!r})")
    name = report.stem
    config = _load_json(records / "configs" / f"{name}.json", f"configs/{name}.json")
    run = _load_json(records / "run.json", "run.json")
    sums = _sums(records / "SHA256SUMS")
    problems: list[str] = []
    misleading: list[str] = []

    inputs = config.get("inputs") or {}
    ref = None
    if len(inputs) == 1:
        digest = next(iter(inputs.values())).get("sha256")
        ref = f"sha256:{digest}" if digest else None
    else:
        problems.append(
            f"{name}: the configuration names {len(inputs)} input artifacts, and "
            "the criterion reads one immutable reference per side."
        )

    runner = _runner(config)

    if invocation is None:
        invocation, more = _invocation(records, run)
        problems.extend(f"{name}: {line}" for line in more)

    listed = sums.get(f"reports/{name}.json")
    actual = hashlib.sha256(report.read_bytes()).hexdigest()
    output: dict = {}
    if listed:
        output = {"digest": f"sha256:{listed}", "published": listed == actual}
        if listed != actual:
            problems.append(
                f"{name}: SHA256SUMS lists {listed} for the report and the file "
                f"published beside it hashes to {actual}."
            )

    checks = body.get("checks") or []
    recount: dict[str, int] = {}
    for check in checks:
        state = check.get("state")
        recount[state] = recount.get(state, 0) + 1
    passed = recount.get("pass", 0)
    roll = body.get("roll-up") or {}
    figure: dict = {}
    if roll:
        claimed = (roll.get("pass"), roll.get("declared"))
        figure = {
            "headline": f"{claimed[0]} of {claimed[1]}",
            "scored": passed,
            "total": len(checks),
            "countingRule": config.get("pass-rule"),
            "notScored": [
                {"reason": str(state), "count": count}
                for state, count in sorted(recount.items(), key=lambda item: str(item[0]))
                if state != "pass"
            ],
        }
        if claimed != (passed, len(checks)):
            misleading.append(
                f"{name}: the roll-up claims {claimed[0]} of {claimed[1]} and the "
                f"checks array holds {passed} passing of {len(checks)}."
            )

    wrote = run.get("runner-wrote")
    record = {
        "sides": [
            {
                "label": name,
                "inputs": {"ref": ref},
                "runner": runner,
                "invocation": invocation,
                "output": output,
                "environment": run.get("environment"),
            }
        ],
        "figure": figure,
        "independence": {
            "declared": isinstance(wrote, list),
            "runnerAuthoredInputs": bool(set(inputs) & set(wrote or [])),
        },
    }
    return record, problems, misleading


def check_v01_report(report: Path, invocation: str | None = None) -> dict:
    """check_record over a v0.1 report, with what reading it added."""
    record, problems, misleading = read_v01_report(report, invocation)
    verdict = check_record(record)
    verdict["missing"].extend(problems)
    verdict["recheckable"] = not verdict["missing"]
    if misleading:
        verdict["figureMeansWhatItSays"] = False
        verdict["notes"].extend(misleading)
    return verdict


def v01_reports(argument: str) -> list[Path]:
    """The reports a --v01 argument names: one report, or a records directory."""
    path = Path(argument)
    if path.is_dir():
        found = sorted((path / "reports").glob("*.json"))
        if not found:
            raise Unreadable(f"{path} holds no reports/*.json")
        return found
    if path.is_file():
        return [path]
    raise Unreadable(f"{argument} does not exist")


def refuse_other_shape(record: object, path: str) -> None:
    """A file that is not a run record is unreadable, not unrecheckable."""
    if isinstance(record, dict) and record.get("format") == V01_FORMAT:
        raise Unreadable(f"{path} is a {V01_FORMAT} report, not a run record; run with --v01")
    if not isinstance(record, dict) or not {"sides", "figure", "independence"} & set(record):
        raise Unreadable(f"{path} has none of sides, figure or independence, so it is not a run record")


def read_arguments(args: argparse.Namespace) -> tuple[dict, bool]:
    """Every verdict for the arguments, and whether any could not be read."""
    report: dict = {}
    unreadable = False
    for argument in args.record:
        try:
            if args.v01:
                for path in v01_reports(argument):
                    report[str(path)] = check_v01_report(path, args.invocation)
                continue
            with open(argument, encoding="utf-8") as handle:
                record = json.load(handle)
            refuse_other_shape(record, argument)
            report[argument] = check_record(record)
        except (Unreadable, OSError, ValueError) as error:
            print(f"cannot read {argument}: {error}", file=sys.stderr)
            unreadable = True
    return report, unreadable


def has_finding(verdict: dict) -> bool:
    return (
        not verdict["recheckable"]
        or not verdict["figureMeansWhatItSays"]
        or verdict["independence"] == "undeclared"
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="check a cross-run record")
    parser.add_argument("record", nargs="+", help="one or more run-record JSON files")
    parser.add_argument("--json", dest="as_json", action="store_true")
    parser.add_argument(
        "--v01",
        action="store_true",
        help=f"read {V01_FORMAT} reports: each argument is a records directory "
        "or one reports/<name>.json",
    )
    parser.add_argument(
        "--invocation",
        help="with --v01: the command, verbatim, when no README beside the records prints it",
    )
    args = parser.parse_args(argv[1:])

    report, unreadable = read_arguments(args)
    worst = 2 if unreadable else int(any(has_finding(v) for v in report.values()))

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
