"""Grade a record set on the agent identity assurance ladder, levels 0 to 6.

A record set names one subject, an agent, and lists findings: what a reader of some other
suite concluded about one piece of evidence about that agent. The grade is a pure function
of the set. It re-judges no evidence, so a verifier that already reads each suite composes
this function over its own findings, and a verifier that reads none of them can still be
checked on this one.

Each level has one test, and a level is claimed only with every lower level:

====  =======================  =============================================================
Test  Name                     Proved by a finding of ...
====  =======================  =============================================================
T0    declared-subject         the set names a subject (nothing verifies it)
T1    issuer-signed-marker     ``agent-principal-binding/v1`` ``agent_bound`` or
                               ``agent-did-identity-binding/v1`` ``subject_bound``
T2    marker-survives          ``actor-marker-survival/v1`` ``marker_survives``
T3    holder-bound             ``holder-bound-credential/v1`` ``holder_bound``
T4    narrowing-chain          ``delegator-right/v1`` ``entitled``
T5    no-unmarked-credential   ``credential-reachability/v1`` ``contained_verified``
T6    out-of-reach-record      ``evidence-grade-floor/v1`` ``grade_derived`` at ``rung``
                               E2 or above
====  =======================  =============================================================

A finding counts toward a test when its suite is one the test names, it is about the set's
subject (the string compared exactly), and it is an ``accept`` with a reason the test names.
A refusal never counts and is never outvoted: if any finding of the test's suites about the
subject is a ``reject``, the test fails ``finding_refused``, whatever else the set holds.

The answer is ``accept`` with reason ``level=<n> next=<test>:<why>``, or ``next=none`` at
level 6. ``<why>`` is the first failing test's cause: ``no_finding``, ``subject_mismatch``,
``finding_refused:<reason>``, ``reason_not_proving:<reason>``, ``rung_below_floor:<rung>``
or ``rung_missing``. A set the reader cannot read is ``reject`` with one of the codes in
:data:`CHECKS`. Two findings that disagree about one piece of evidence are ``finding_conflict``,
and so are two findings that put one digest under different suites or different subjects.

The verifier contract: ``<verifier> <case-dir>/record.json --json`` prints one JSON object
with ``decision`` and ``reason`` and exits 0 for ``accept`` and 1 for ``reject``.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any

from agent_evidence_vectors.monitorcoverage import _fixture_error, _validated_entries, run_corpus

from . import strictjson

SUITE = "identity-assurance-levels/v1"
CONTRACT_ID = (
    "https://probityai.github.io/agent-evidence-vectors/predicate/v1/identity-assurance-levels"
)
ACCEPT, REJECT = "accept", "reject"
EXIT_FOR = {ACCEPT: 0, REJECT: 1}
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "record_malformed",
    "finding_malformed",
    "finding_conflict",
)
RUNGS = ("E0", "E1", "E2", "E3", "E4")
FLOOR_RUNG = "E2"
#: (test, name, {suite: reasons that prove it}); T0 has no suite.
TESTS: tuple[tuple[str, str, dict[str, frozenset[str]]], ...] = (
    ("T0", "declared-subject", {}),
    (
        "T1",
        "issuer-signed-marker",
        {
            "agent-principal-binding/v1": frozenset({"agent_bound"}),
            "agent-did-identity-binding/v1": frozenset({"subject_bound"}),
        },
    ),
    ("T2", "marker-survives", {"actor-marker-survival/v1": frozenset({"marker_survives"})}),
    ("T3", "holder-bound", {"holder-bound-credential/v1": frozenset({"holder_bound"})}),
    ("T4", "narrowing-chain", {"delegator-right/v1": frozenset({"entitled"})}),
    (
        "T5",
        "no-unmarked-credential",
        {"credential-reachability/v1": frozenset({"contained_verified"})},
    ),
    ("T6", "out-of-reach-record", {"evidence-grade-floor/v1": frozenset({"grade_derived"})}),
)
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-identity-assurance"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-identity-assurance"
)
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")

Record = dict[str, Any]


class Malformed(ValueError):
    """The set does not have the shape this contract reads; the message is the check code."""


def _text(value: Any) -> bool:
    return isinstance(value, str) and value != "" and value == value.strip()


def _finding(item: Any) -> None:
    if not isinstance(item, dict):
        raise Malformed("finding_malformed")
    required = {"suite", "decision", "reason", "subject", "evidence"}
    if not required <= set(item) <= required | {"rung"}:
        raise Malformed("finding_malformed")
    if not (_text(item["suite"]) and _text(item["reason"]) and _text(item["subject"])):
        raise Malformed("finding_malformed")
    if item["decision"] not in (ACCEPT, REJECT):
        raise Malformed("finding_malformed")
    if "rung" in item and item["rung"] not in RUNGS:
        raise Malformed("finding_malformed")
    evidence = item["evidence"]
    pointer = {"corpus", "member", "file"}
    if not isinstance(evidence, dict) or "sha256" not in evidence:
        raise Malformed("finding_malformed")
    if set(evidence) - {"sha256"} not in (set(), pointer):
        raise Malformed("finding_malformed")
    if not isinstance(evidence["sha256"], str) or not _HEX64.match(evidence["sha256"]):
        raise Malformed("finding_malformed")
    if any(not _text(evidence[m]) for m in pointer & set(evidence)):
        raise Malformed("finding_malformed")


def _shape(record: Record) -> list[dict[str, Any]]:
    """The findings of a well-formed set, or Malformed carrying the check code."""
    if "contractId" not in record:
        raise Malformed("contract_id_missing")
    if record["contractId"] != CONTRACT_ID:
        raise Malformed("contract_id_unknown")
    if set(record) != {"contractId", "subject", "findings"}:
        raise Malformed("record_malformed")
    if not _text(record["subject"]) or not isinstance(record["findings"], list):
        raise Malformed("record_malformed")
    findings: list[dict[str, Any]] = record["findings"]
    for item in findings:
        _finding(item)
    seen: dict[tuple[str, str, str], tuple[str, str | None, str]] = {}
    owner: dict[str, tuple[str, str]] = {}
    for item in findings:
        digest = item["evidence"]["sha256"]
        key = (item["suite"], item["subject"], digest)
        answer = (item["decision"], item.get("rung"), item["reason"])
        if seen.setdefault(key, answer) != answer:
            raise Malformed("finding_conflict")
        # One piece of evidence is one record of one suite about one subject: the same bytes
        # cannot be a binding, a proof of possession and a delegation at once, and cannot be
        # about two agents. Without this a single digest listed under six suites grades level 6.
        if owner.setdefault(digest, (item["suite"], item["subject"])) != (
            item["suite"],
            item["subject"],
        ):
            raise Malformed("finding_conflict")
    return findings


def _cause(test: str, reasons: dict[str, frozenset[str]], mine: list[dict[str, Any]],
           any_named: bool) -> str | None:
    """None when the test passes, else why it fails."""
    if not any_named:
        return "no_finding"
    if not mine:
        return "subject_mismatch"
    for item in mine:
        if item["decision"] == REJECT:
            return f"finding_refused:{item['reason']}"
    for item in mine:
        if item["reason"] not in reasons[item["suite"]]:
            return f"reason_not_proving:{item['reason']}"
    if test == "T6":
        for item in mine:
            rung = item.get("rung")
            if rung is None:
                return "rung_missing"
            if RUNGS.index(rung) < RUNGS.index(FLOOR_RUNG):
                return f"rung_below_floor:{rung}"
    return None


def grade(record: Record, skip: frozenset[str] = frozenset()) -> tuple[int, str, str | None]:
    """(level, first failing test, why) for a well-formed set. ``skip`` names tests to
    treat as passing, for the corpus's mutation check only."""
    findings = _shape(record)
    level = 0
    for test, _name, reasons in TESTS[1:]:
        named = [f for f in findings if f["suite"] in reasons]
        mine = [f for f in named if f["subject"] == record["subject"]]
        why = None if test in skip else _cause(test, reasons, mine, bool(named))
        if why is not None:
            return level, test, why
        level += 1
    return level, "none", None


def judge(record: Record, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The decision and reason for one decoded set."""
    try:
        level, test, why = grade(record, skip)
    except Malformed as refusal:
        return {"decision": REJECT, "reason": str(refusal)}
    return {
        "decision": ACCEPT,
        "reason": f"level={level} next=" + ("none" if why is None else f"{test}:{why}"),
    }


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load(path: Path) -> Any:
    return strictjson.loads(path.read_text(encoding="utf-8"))


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record file."""
    try:
        record = _load(record_path)
    except (ValueError, UnicodeDecodeError):
        return {"decision": REJECT, "reason": "record_malformed"}
    if not isinstance(record, dict):
        return {"decision": REJECT, "reason": "record_malformed"}
    return judge(record, skip)


def retained(record: Record) -> dict[str, Any]:
    """What a verifier keeps: the subject and the digest of every piece of evidence."""
    try:
        findings = _shape(record)
    except (Malformed, KeyError, TypeError, ValueError, AttributeError):
        return {"subject": None, "evidence": []}
    return {
        "subject": record["subject"],
        "evidence": sorted({f["evidence"]["sha256"] for f in findings}),
    }


def _external_answer(command: list[str], record: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run(
            [*command, str(record), "--json"],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"verifier did not run: {exc}"
    try:
        answer = strictjson.loads(result.stdout)
        observed = {key: answer[key] for key in ("decision", "reason")}
    except (ValueError, KeyError, TypeError):
        return True, f"verifier returned no decision (exit {result.returncode})"
    if EXIT_FOR.get(str(observed["decision"])) != result.returncode:
        return True, f"exit {result.returncode} disagrees with decision {observed['decision']}"
    return True, observed


def check(
    verifier: str | list[str] | None = None,
    root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every set, through the named verifier or the reference reader."""
    import shlex

    try:
        entries, manifest_error = _validated_entries(root, SUITE)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    if manifest_error:
        return 0, [manifest_error]
    command = shlex.split(verifier) if isinstance(verifier, str) else verifier
    if command is not None and not command:
        return 0, ["verifier command is empty"]
    errors: list[str] = []
    answered = 0
    for entry in entries:
        name, directory = entry["id"], root / entry["path"]
        fixture_error = _fixture_error(directory, entry)
        if fixture_error:
            errors.append(f"{name}: {fixture_error}")
            continue
        record_path = directory / "record.json"
        if retained(_load(record_path)) != entry["retained"]:
            errors.append(f"{name}: declared retained fields do not hold")
        observed: dict[str, Any] | str
        if command is None:
            ran, observed = True, verify(record_path, skip)
        else:
            ran, observed = _external_answer(command, record_path)
        answered += int(ran)
        if isinstance(observed, str):
            errors.append(f"{name}: {observed}")
        elif observed != entry["expected"]:
            errors.append(f"{name}: expected {entry['expected']}, got {observed}")
    return answered, errors


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    return run_corpus(SUITE, check, root, verifier, report_path, rail_note)


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("record", nargs="?", help="grade one record.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every record through this verifier instead")
    args = parser.parse_args(argv)
    if args.record:
        answer = verify(Path(args.record))
        print(
            json.dumps(answer, sort_keys=True)
            if args.json
            else f"{answer['decision']} {answer['reason']}"
        )
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(_load(ROOT / "MANIFEST.json")["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
