"""Judge the done-contract and done-receipt corpora, and the three that build on them.

Five corpora share one reader, because they share one question: given the records
of a coding agent's run, what does an outside verifier conclude? ``done-contract``
asks it of a sealed contract. ``done-receipt`` asks it of a whole run and of the
receipt that summarises the run. ``spoofed-tool-output``, ``test-tampering`` and
``grader-isolation`` ask it of the runs in which an agent fabricates a tool run,
edits what it is graded by, or reaches the grader.

A member is a directory of records and, for each check the manifest declares, the
consumer's case and policy for it. The reader derives each declared check's verdict
(or the code of the rule a record breaks), and, when all five checks are declared,
the receipt's two verdicts over them: the outcome, the integrity and ``accepted``.
The manifest declares the same thing: the corpus never states a verdict the reader
does not recompute.

These corpora have no external-verifier contract: a named verifier is refused.
probity-verify, the implementation the rules come from, is replayed over every member
by ``vectors-done-receipt/crosscheck_probity_verify.py``.
"""

from __future__ import annotations

import argparse
import json
import shlex
from collections.abc import Callable
from pathlib import Path
from typing import Any

from . import donechecks as checks
from . import donerecords as rec
from .donerecords import RecordError

CONTRACT_SUITE = "done-contract/v2"
RECEIPT_SUITE = "done-receipt/v2"
SPOOFED_SUITE = "spoofed-tool-output/v2"
TAMPERING_SUITE = "test-tampering/v2"
GRADER_SUITE = "grader-isolation/v2"
SUITES = (CONTRACT_SUITE, RECEIPT_SUITE, SPOOFED_SUITE, TAMPERING_SUITE, GRADER_SUITE)
CONTRACT_TYPE = "https://w3id.org/agent-evidence/predicate/v1/done-contract"
RECEIPT_TYPE = checks.RECEIPT_TYPE
STATEMENT_TYPE = checks.STATEMENT_TYPE
# Every check a member can declare, in the order the reader runs and reports them.
DECLARABLE = (*checks.CLAIM_TYPES, checks.RECEIPT)
ROOT_PARENT = Path(__file__).resolve().parent


# --- the done-contract statement ------------------------------------------------------------


def _statement(data: bytes) -> dict[str, Any]:
    """The in-toto Statement envelope: type, predicate type and one digest-keyed subject."""
    statement = rec.fields(rec.strict_json(data, "statement"), "statement",
                           {"_type", "subject", "predicateType", "predicate"})
    if statement["_type"] != STATEMENT_TYPE:
        raise RecordError("statement_type_wrong")
    if statement["predicateType"] != CONTRACT_TYPE:
        raise RecordError("statement_predicate_type_wrong")
    subject = statement["subject"]
    if not isinstance(subject, list) or len(subject) != 1:
        raise RecordError("statement_subject_malformed")
    entry = subject[0]
    ok = (isinstance(entry, dict) and set(entry) == {"name", "digest"}
          and isinstance(entry["name"], str) and entry["name"]
          and isinstance(entry["digest"], dict) and set(entry["digest"]) == {"sha256"}
          and isinstance(entry["digest"]["sha256"], str)
          and rec.HEX64.fullmatch(entry["digest"]["sha256"]))
    if not ok:
        raise RecordError("statement_subject_malformed")
    return statement


def judge_contract(member: Path) -> dict[str, Any]:
    """A contract record and the Statement that carries it."""
    statement_bytes = rec.read_member_file(member, "statement.json", "member_unreadable")
    contract_bytes = rec.read_member_file(member, "contract.json", "member_unreadable")
    if statement_bytes is None or contract_bytes is None:
        raise RecordError("member_incomplete", str(member.name))
    try:
        statement = _statement(statement_bytes)
        record = rec.contract(contract_bytes)
        if statement["subject"][0]["digest"]["sha256"] != rec.sha256(contract_bytes):
            raise RecordError("statement_subject_unbound")
        if statement["predicate"] != record:
            raise RecordError("statement_predicate_differs")
    except RecordError as exc:
        return {"verdict": "invalid", "code": exc.code}
    return {"verdict": "valid"}


# --- one member ---------------------------------------------------------------------------


def judge_checks(member: Path, declared: list[str]) -> dict[str, Any]:
    """Each declared check's verdict and, over all five, the receipt's two verdicts."""
    verdicts: dict[str, dict[str, Any]] = {}
    out: dict[str, Any] = {"checks": {}}
    for claim_type in DECLARABLE:
        if claim_type not in declared:
            continue
        try:
            verdicts[claim_type] = checks.run_check(claim_type, member)
        except RecordError as exc:
            out["checks"][claim_type] = {"refused": exc.code}
            continue
        out["checks"][claim_type] = checks.projection(verdicts[claim_type])
    if all(claim_type in verdicts for claim_type in checks.CLAIM_TYPES):
        derived = checks.axes(verdicts)
        out.update(outcome=checks.axis_projection(derived["outcome"]),
                   integrity=checks.axis_projection(derived["integrity"]),
                   accepted=derived["accepted"])
    return out


def judge_member(suite: str, member: Path, declared: list[str]) -> dict[str, Any]:
    """What the reader derives for one member."""
    if suite == CONTRACT_SUITE:
        try:
            return {"contract": judge_contract(member)}
        except RecordError as exc:
            return {"refused": exc.code}
    return judge_checks(member, declared)


# --- corpus ---------------------------------------------------------------------------------


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def corpus_digest(entries: list[dict[str, Any]]) -> str:
    return rec.sha256(_json(entries))


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {p.name for p in directory.iterdir() if p.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(rec.sha256((directory / name).read_bytes()) != value for name, value in files.items()):
        return "fixture digest mismatch"
    return None


def validated_entries(root: Path, suite: str) -> tuple[list[dict[str, Any]], str | None]:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    if manifest.get("suite") != suite:
        return [], "unexpected suite"
    if corpus_digest(entries) != manifest["corpusDigest"]:
        return [], "manifest digest mismatch"
    if not entries or len({entry["id"] for entry in entries}) != len(entries):
        return [], "empty or duplicate vector identifiers"
    if any(entry.get("path") != f"cases/{entry['id']}" for entry in entries):
        return [], "case path does not match identifier"
    if {p.name for p in (root / "cases").iterdir() if p.is_dir()} != {e["id"] for e in entries}:
        return [], "case directories do not match manifest"
    return entries, None


def declared_view(entry: dict[str, Any]) -> dict[str, Any]:
    """The expectation a manifest entry declares, without the prose around it."""
    return dict(entry["expected"])


def _compare(entry: dict[str, Any], got: dict[str, Any]) -> str | None:
    want = declared_view(entry)
    return None if got == want else f"expected {want}, got {got}"


def check(suite: str, root: Path | None = None) -> tuple[int, list[str]]:
    """Check every member through the reference reader.

    Returns the number of members answered and every disagreement.
    """
    base = root or _default_root(suite)
    try:
        entries, problem = validated_entries(base, suite)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        return 0, [f"invalid corpus: {exc}"]
    if problem:
        return 0, [problem]
    errors: list[str] = []
    answered = 0
    for entry in entries:
        directory = base / entry["path"]
        fixture = _fixture_error(directory, entry)
        if fixture:
            errors.append(f"{entry['id']}: {fixture}")
            continue
        declared = list(entry.get("checks", []))
        got = judge_member(suite, directory, declared)
        answered += 1
        finding = _compare(entry, got)
        if finding:
            errors.append(f"{entry['id']}: {finding}")
    return answered, errors


def _default_root(suite: str) -> Path:
    name = "vectors-" + suite.split("/")[0]
    packaged = ROOT_PARENT / "corpora" / name
    return packaged if packaged.exists() else ROOT_PARENT.parents[1] / name


def run(suite: str, root: str, verifier: list[str] | None, report_path: str,
        rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    if verifier is not None:
        print(f"the verifier {shlex.join(verifier)!r} did NOT run: the corpus {suite!r} is "
              "judged only by this package's own reader and has no external-verifier contract")
        return 2
    directory = Path(root)
    answered, errors = check(suite, directory)
    try:
        manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
        total = len(manifest["vectors"])
    except (OSError, ValueError, KeyError, TypeError):
        manifest, total = {}, 0
    for error in errors:
        print(error)
    print(f"{suite}: reference reader answered {answered} of {total} cases, "
          f"{len(errors)} disagreements")
    if not answered or not total:
        print("no report written: no case was answered")
        return 2
    report = {
        "suite": suite, "rail": "own-reader",
        "verifier": {"command": None, "vectorsExecuted": answered, "note": rail_note},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {"vectors": total, "conform": total - len(errors), "fail": len(errors),
                   "suiteRefusals": 0},
        "failures": errors,
    }
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    return 1 if errors or answered != total else 0


def runner(suite: str) -> Callable[[str, list[str] | None, str, str], int]:
    """The ``run`` entry the harness calls for one suite."""
    def call(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
        return run(suite, root, verifier, report_path, rail_note)
    return call


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("suite", choices=SUITES)
    parser.add_argument("corpus", nargs="?",
                        help="the corpus directory (default: the packaged one)")
    args = parser.parse_args(argv)
    root = Path(args.corpus) if args.corpus else None
    answered, errors = check(args.suite, root)
    for error in errors:
        print(error)
    print(f"answered {answered} cases, {len(errors)} disagreements")
    return 1 if errors or not answered else 0


if __name__ == "__main__":
    raise SystemExit(main())
