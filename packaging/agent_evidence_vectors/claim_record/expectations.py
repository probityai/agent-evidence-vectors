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
  tap       expectations as `table`; output TAP 13 `ok` / `not ok` lines, id the description;
            a `# SKIP` or `# TODO` directive is not run.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET  # noqa: S405 - the report is the caller's own CI output
from typing import Any

from .reader import CASE_SET_SCHEMA, MalformedInput, exhibits_trace

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


def _tamarin(text: str) -> tuple[dict[str, str], dict[str, str]]:
    observed: dict[str, str] = {}
    quantifiers: dict[str, str] = {}
    variant: str | None = None
    for raw in text.splitlines():
        if raw.startswith("== "):
            variant = raw[3:].strip()
            continue
        match = _TAMARIN.match(raw)
        if match is None or variant is None:
            continue
        case_id = f"{variant}|{match['lemma']}"
        outcome = match["outcome"]
        observed[case_id] = "timeout" if outcome == "analysis incomplete" else outcome
        quantifiers[case_id] = match["quantifier"]
    return observed, quantifiers


def _junit(text: str) -> dict[str, str]:
    root = ET.fromstring(text)  # noqa: S314 - see the import
    observed: dict[str, str] = {}
    for case in root.iter("testcase"):
        case_id = f"{case.get('classname', '')}.{case.get('name', '')}".lstrip(".")
        if case.find("skipped") is not None:
            observed[case_id] = "not_run"
        elif case.find("failure") is not None or case.find("error") is not None:
            observed[case_id] = "fail"
        else:
            observed[case_id] = "pass"
    return observed


def _tap(text: str) -> dict[str, str]:
    observed: dict[str, str] = {}
    for raw in text.splitlines():
        match = _TAP.match(raw.strip())
        if match is None:
            continue
        description, _, directive = match["rest"].partition("#")
        if directive.strip().upper().startswith(("SKIP", "TODO")):
            observed[description.strip()] = "not_run"
        else:
            observed[description.strip()] = "pass" if match["status"] == "ok" else "fail"
    return observed


def observe(fmt: str, output: str) -> tuple[dict[str, str], dict[str, str]]:
    """The observed outcome per id, and the quantifier per id where the output states one."""
    if fmt == "tamarin":
        return _tamarin(output)
    if fmt == "junit":
        return _junit(output), {}
    if fmt == "tap":
        return _tap(output), {}
    if fmt == "table":
        return parse_table(output, OUTCOMES + NOT_RUN), {}
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

    With ``witness_lemma``, every all-traces case expected `verified` names as its witness
    the case `<same variant>|<witness_lemma>` when the table holds it; the profile decides
    whether a case without one is refused.
    """
    expected = parse_table(expectations, OUTCOMES)
    observed, quantifiers = observe(fmt, output)
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
            if (case.get("quantifier"), case["expect"]) == ("all-traces", "verified") and \
                    witness in expected and witness != case["id"]:
                case["witness"] = witness
    passed = [c for c, want in expected.items() if observed.get(c) == want]
    failed = [c for c, want in expected.items()
              if c in observed and observed[c] in OUTCOMES and observed[c] != want]
    warnings = [f"output names {c!r}, which has no expectation row" for c in observed
                if c not in expected]
    by_id = {c["id"]: c for c in cases}
    for case in cases:
        named = case.get("witness")
        if named is None or case["id"] not in passed:
            continue
        if not exhibits_trace(by_id[named]) or named not in passed:
            passed.remove(case["id"])
            warnings.append(f"{case['id']} holds vacuously: its witness {named} shows no "
                            "trace, so it is reported not run")
    case_set = {"schema": CASE_SET_SCHEMA, "name": name, "revision": revision, "cases": cases}
    return case_set, {"passed": passed, "failed": failed}, warnings
