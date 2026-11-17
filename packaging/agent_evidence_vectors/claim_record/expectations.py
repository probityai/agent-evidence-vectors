"""Build an evaluation-claim case set and results from an expectation table and a run's output.

A CI job that already decides pass or fail against an expectation table (a Tamarin
`prove.sh` table, a JUnit report, a TAP stream, a flat `id|expected` table) holds
everything an evaluation claim needs. This module turns the two files into the case set
and results that :func:`reader.emit` takes:

* the case set comes from the expectation table, and every case carries its expected
  outcome as `expect`, so the case-set digest binds the table;
* a case passes when the observed outcome equals the expected one, fails when it differs,
  and is not run when the output has no line for it or reports a timeout;
* an output line naming no expectation row is returned as a warning, never dropped
  silently and never admitted into the record;
* an id the output reports twice with different outcomes is refused: a later line must
  never turn a failure into a pass;
* with a witness lemma, a property whose witness shows no trace (expected falsified, or
  not passed) is reported not run with a warning, since its proof holds vacuously.

Formats:

  table     expectations `<id>|<expected>`, output `<id>|<observed>`; the id is every
            field but the last, so `model|flags|lemma|expected` rows work unchanged.
  tamarin   expectations as `table`; output blocks headed `== <model>|<flags>` followed by
            Tamarin summary lines `<lemma> (<quantifier>): verified|falsified ... (<n> steps)`.
            The quantifier read there becomes the case's `quantifier`.
  junit     expectations as `table` (expected `pass` or `fail`); output a JUnit XML report,
            each testcase id `<classname>.<name>`; failure or error is fail, skipped is not run.
  tap       expectations as `table`; output TAP 13 test points, id the description: `ok` /
            `not ok` lines starting in the first column, so an indented line (a YAML
            diagnostic block, a TAP 14 subtest) is never read as a result; the directive
            starts at the first `#` not escaped as `\\#`, and `# SKIP` or `# TODO` is not run.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET  # noqa: S405 - the report is the caller's own CI output
from typing import Any

from .reader import CASE_SET_SCHEMA, MalformedInput, claims_every_trace, exhibits_trace

FORMATS = ("table", "tamarin", "junit", "tap")
OUTCOMES = ("verified", "falsified", "pass", "fail")
NOT_RUN = ("timeout", "error", "not_run", "incomplete")
_TAMARIN = re.compile(
    r"^\s*(?P<lemma>[A-Za-z0-9_]+)\s+\((?P<quantifier>all-traces|exists-trace)\):\s+"
    r"(?P<outcome>verified|falsified|analysis incomplete)"
)
_TAP = re.compile(r"^(?P<status>ok|not ok)\b(?:\s+\d+)?(?:\s+-)?\s*(?P<rest>.*)$")


def parse_table(text: str, vocabulary: tuple[str, ...]) -> dict[str, str]:
    """`<id>|<value>` rows; blank lines and `#` comments are skipped; ids are unique."""
    rows: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip().strip('"')
        if not line or line.startswith("#"):
            continue
        if "|" not in line:
            raise MalformedInput(f"line {number}: no `|` separates the id from its value")
        case_id, value = line.rsplit("|", 1)
        if value not in vocabulary:
            raise MalformedInput(f"line {number}: {value!r} is not one of {list(vocabulary)}")
        if case_id in rows:
            raise MalformedInput(f"line {number}: {case_id!r} appears twice")
        rows[case_id] = value
    return rows


def _record(observed: dict[str, str], case_id: str, outcome: str) -> None:
    """Keep one outcome per id; a repeated id must repeat its outcome."""
    if observed.get(case_id, outcome) != outcome:
        raise MalformedInput(
            f"the output reports {case_id!r} twice, as {observed[case_id]!r} and {outcome!r}"
        )
    observed[case_id] = outcome


def _tamarin(text: str) -> tuple[dict[str, str], dict[str, str], list[str]]:
    observed: dict[str, str] = {}
    quantifiers: dict[str, str] = {}
    stray: list[str] = []
    variant: str | None = None
    for raw in text.splitlines():
        if raw.startswith("== "):
            variant = raw[3:].strip()
            continue
        match = _TAMARIN.match(raw)
        if match is None:
            continue
        if variant is None:
            stray.append(f"output line {raw.strip()!r} comes before any `== ` variant header")
            continue
        case_id = f"{variant}|{match['lemma']}"
        outcome = match["outcome"]
        _record(observed, case_id, "timeout" if outcome == "analysis incomplete" else outcome)
        if quantifiers.get(case_id, match["quantifier"]) != match["quantifier"]:
            raise MalformedInput(f"the output reports {case_id!r} under two quantifiers")
        quantifiers[case_id] = match["quantifier"]
    return observed, quantifiers, stray


def _junit(text: str) -> dict[str, str]:
    root = ET.fromstring(text)  # noqa: S314 - see the import
    observed: dict[str, str] = {}
    for case in root.iter("testcase"):
        case_id = f"{case.get('classname', '')}.{case.get('name', '')}".lstrip(".")
        if case.find("skipped") is not None:
            _record(observed, case_id, "not_run")
        elif case.find("failure") is not None or case.find("error") is not None:
            _record(observed, case_id, "fail")
        else:
            _record(observed, case_id, "pass")
    return observed


def _tap_split(rest: str) -> tuple[str, str]:
    """A test point's description and directive: the directive starts at the first `#`
    that `\\` does not escape, and `\\#` and `\\\\` read as `#` and `\\` (TAP 13)."""
    description: list[str] = []
    chars = iter(rest)
    for char in chars:
        if char == "\\":
            following = next(chars, "")
            description.append(following if following in ("#", "\\") else char + following)
        elif char == "#":
            return "".join(description), "".join(chars)
        else:
            description.append(char)
    return "".join(description), ""


def _tap(text: str) -> dict[str, str]:
    observed: dict[str, str] = {}
    for raw in text.splitlines():
        # A test point starts in the first column; a YAML block or a subtest is indented.
        match = _TAP.match(raw.rstrip())
        if match is None:
            continue
        description, directive = _tap_split(match["rest"])
        if directive.strip().upper().startswith(("SKIP", "TODO")):
            _record(observed, description.strip(), "not_run")
        else:
            _record(observed, description.strip(), "pass" if match["status"] == "ok" else "fail")
    return observed


def observe(fmt: str, output: str) -> tuple[dict[str, str], dict[str, str], list[str]]:
    """The observed outcome per id, the quantifier per id where the output states one, and
    a warning per result line the format cannot attribute to an id."""
    if fmt == "tamarin":
        return _tamarin(output)
    if fmt == "junit":
        return _junit(output), {}, []
    if fmt == "tap":
        return _tap(output), {}, []
    if fmt == "table":
        return parse_table(output, OUTCOMES + NOT_RUN), {}, []
    raise MalformedInput(f"format {fmt!r} is not one of {list(FORMATS)}")


def from_expectations(
    fmt: str,
    expectations: str,
    output: str,
    *,
    name: str,
    revision: str,
    witness_lemma: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """The case set, the results for :func:`reader.emit`, and the warnings.

    With ``witness_lemma``, every case whose expected outcome is a claim over every trace
    (all-traces expected `verified`, or exists-trace expected `falsified`) names as its
    witness the case `<same variant>|<witness_lemma>` when the table holds it; the profile
    decides whether a case without one is refused. With a witness lemma, such a case that
    passed with no witness showing a trace is reported not run, since its proof holds
    vacuously.
    """
    expected = parse_table(expectations, OUTCOMES)
    observed, quantifiers, stray = observe(fmt, output)
    cases = []
    for case_id, expect in expected.items():
        case: dict[str, Any] = {"id": case_id, "requirement": "required", "expect": expect}
        if case_id in quantifiers:
            case["quantifier"] = quantifiers[case_id]
        cases.append(case)
    if witness_lemma is not None:
        for case in cases:
            variant = case["id"].rsplit("|", 1)[0]
            witness = f"{variant}|{witness_lemma}"
            if claims_every_trace(case) and witness in expected and witness != case["id"]:
                case["witness"] = witness
    passed = [c for c, want in expected.items() if observed.get(c) == want]
    failed = [c for c, want in expected.items()
              if c in observed and observed[c] in OUTCOMES and observed[c] != want]
    warnings = stray + [f"output names {c!r}, which has no expectation row" for c in observed
                        if c not in expected]
    by_id = {c["id"]: c for c in cases}
    # Until nothing changes: a witness moved to not run takes its dependants with it,
    # whatever order the table lists them in.
    changed = True
    while changed:
        changed = False
        for case in cases:
            named = case.get("witness")
            unwitnessed = witness_lemma is not None and claims_every_trace(case)
            if case["id"] not in passed or (named is None and not unwitnessed):
                continue
            if named is None or not exhibits_trace(by_id[named]) or named not in passed:
                passed.remove(case["id"])
                changed = True
                shown = f"its witness {named} shows no trace" if named else "it names no witness"
                warnings.append(
                    f"{case['id']} holds vacuously: {shown}, so it is reported not run")
    case_set = {"schema": CASE_SET_SCHEMA, "name": name, "revision": revision, "cases": cases}
    return case_set, {"passed": passed, "failed": failed}, warnings
