"""Conformance result records: one signed statement per run of a corpus by an implementation.

The format is specified in ``docs/CONFORMANCE-RESULT.md``. A record is a DSSE envelope around an
in-toto Statement v1 whose predicate says who ran which corpus revision, how independent the run
was, and what it scored. The statement's subject is the evidence of the run (a posted run row,
or the list of per-case verdicts) and its digest is recomputed by anyone holding that evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__, dsse

PREDICATE_TYPE = "https://github.com/probityai/agent-evidence/blob/main/packages/admission/docs/CONFORMANCE-RESULT.md"
STATEMENT = "https://in-toto.io/Statement/v1"
RUN_LABELS = ("author-produced", "second-party-same-code", "independent")
EVIDENCE = ("blind", "directed", "first-run-unchanged-build", "measured")
KINDS = ("replayed-row", "local-run")
_FIGURE = re.compile(r"^(0|[1-9][0-9]*)/(0|[1-9][0-9]*)$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def canonical(value: object) -> bytes:
    """Sorted-key compact UTF-8 JSON. Equals RFC 8785 for the strings, integers, booleans and nulls used here."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def digest_of(value: object) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def parse_figure(figure: str) -> tuple[int, int]:
    """``"125/130"`` as (125, 130); the passed count never exceeds the total."""
    match = _FIGURE.match(figure) if isinstance(figure, str) else None
    if not match or int(match[1]) > int(match[2]):
        raise ValueError(f"not a passed/total figure: {figure!r}")
    return int(match[1]), int(match[2])


def build_statement(subject_name: str, subject_digest: str, predicate: dict) -> dict:
    return {
        "_type": STATEMENT,
        "subject": [{"name": subject_name, "digest": {"sha256": subject_digest}}],
        "predicateType": PREDICATE_TYPE,
        "predicate": predicate,
    }


def _runner(kind: str) -> dict:
    return {"kind": kind, "name": "agent-evidence-admission", "version": __version__}


def statement_from_row(implementation: str, row: dict) -> dict:
    """The record for one row of a posted-runs file (``docs/INDEPENDENT-RUNS.json`` of the vectors)."""
    scores = []
    for figure in row["figures"]:
        passed, total = parse_figure(figure["figure"])
        scores.append({"role": figure["role"], "passed": passed, "total": total})
    predicate = {
        "implementation": implementation,
        "suite": {"revision": row["suiteRevision"], "commit": row.get("suiteCommit")},
        "runLabel": row["runLabel"],
        "evidence": row["evidence"],
        "scores": scores,
        "posting": row.get("posting"),
        "date": row.get("date"),
        "runner": _runner("replayed-row"),
    }
    problems = validate_predicate(predicate)
    if problems:
        raise ValueError("; ".join(problems))
    return build_statement(f"run:{implementation}@suite-revision-{row['suiteRevision']}", digest_of(row), predicate)


def validate_predicate(predicate: object) -> list[str]:
    """Every reason the predicate is not a conformance result; empty when it is one."""
    if not isinstance(predicate, dict):
        return ["predicate-not-object"]
    problems = []
    for key in ("implementation", "posting", "date"):
        value = predicate.get(key)
        if not (isinstance(value, str) and value) and not (value is None and key != "implementation"):
            problems.append(f"field-invalid:{key}")
    suite = predicate.get("suite")
    if not isinstance(suite, dict) or not isinstance(suite.get("revision"), int) or isinstance(suite.get("revision"), bool) or suite["revision"] < 1:
        problems.append("field-invalid:suite.revision")
    if isinstance(suite, dict) and suite.get("commit") is not None and not isinstance(suite.get("commit"), str):
        problems.append("field-invalid:suite.commit")
    if predicate.get("runLabel") not in RUN_LABELS:
        problems.append("field-invalid:runLabel")
    if predicate.get("evidence") not in EVIDENCE:
        problems.append("field-invalid:evidence")
    runner = predicate.get("runner")
    if not isinstance(runner, dict) or runner.get("kind") not in KINDS:
        problems.append("field-invalid:runner.kind")
    problems.extend(_score_problems(predicate.get("scores")))
    return problems


def _score_problems(scores: object) -> list[str]:
    if not isinstance(scores, list) or not scores:
        return ["field-invalid:scores"]
    problems = []
    for score in scores:
        ints = isinstance(score, dict) and all(
            isinstance(score.get(k), int) and not isinstance(score.get(k), bool) and score[k] >= 0 for k in ("passed", "total")
        )
        if not ints or not isinstance(score.get("role"), str) or not score["role"] or score["passed"] > score["total"]:
            problems.append("field-invalid:scores")
            break
    return problems


@dataclass
class Verdict:
    """Outcome of checking one record: ``ok`` and, when not, every reason."""

    ok: bool
    reasons: list[str] = field(default_factory=list)
    implementation: str | None = None
    revision: int | None = None
    keyid: str | None = None

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "reasons": self.reasons,
            "implementation": self.implementation,
            "suiteRevision": self.revision,
            "keyid": self.keyid,
        }


def verify_record(envelope: object, trusted: dict[str, bytes], source: object | None = None) -> Verdict:
    """Check the signature, the statement shape, the predicate and, given ``source``, the subject digest."""
    try:
        opened = dsse.open_envelope(envelope, trusted)
        statement = json.loads(opened.payload)
    except (ValueError, UnicodeDecodeError) as error:
        return Verdict(False, [f"envelope-invalid:{error}"])
    reasons = _statement_problems(statement)
    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    if not reasons and source is not None:
        wanted = statement["subject"][0]["digest"]["sha256"]
        if digest_of(source) != wanted:
            reasons.append("subject-digest-mismatch")
    suite = predicate.get("suite") if isinstance(predicate, dict) else None
    implementation = predicate.get("implementation") if isinstance(predicate, dict) else None
    return Verdict(
        not reasons,
        reasons,
        implementation if isinstance(implementation, str) else None,
        suite.get("revision") if isinstance(suite, dict) and isinstance(suite.get("revision"), int) else None,
        opened.keyid,
    )


def _statement_problems(statement: object) -> list[str]:
    if not isinstance(statement, dict) or statement.get("_type") != STATEMENT:
        return ["statement-type-invalid"]
    if statement.get("predicateType") != PREDICATE_TYPE:
        return ["predicate-type-unsupported"]
    subjects = statement.get("subject")
    digest = subjects[0].get("digest", {}).get("sha256") if isinstance(subjects, list) and len(subjects) == 1 and isinstance(subjects[0], dict) and isinstance(subjects[0].get("digest"), dict) else None
    reasons = [] if isinstance(digest, str) and _HEX64.match(digest) else ["subject-invalid"]
    return reasons + validate_predicate(statement.get("predicate"))


def run_corpus(manifest: dict, command: Sequence[str], base: Path, timeout: float = 60.0) -> list[dict]:
    """Run ``command <input>`` for every case; the exit code is the verdict.

    Exit 0 is accept, exit 1 is refuse, anything else (including a timeout or a command that will
    not start) is ``errored``, so a broken implementation never reads as a refusal.
    """
    results = []
    for case in manifest["cases"]:
        verdict = "errored"
        try:
            done = subprocess.run([*command, str(base / case["input"])], capture_output=True, timeout=timeout, check=False)
            verdict = {0: "accept", 1: "refuse"}.get(done.returncode, "errored")
        except (OSError, subprocess.TimeoutExpired):
            pass
        results.append({"id": case["id"], "expect": case["expect"], "verdict": verdict})
    return results


def statement_from_results(implementation: str, manifest: dict, results: list[dict], run_label: str, evidence: str) -> dict:
    """The record for a local run: one score row, and the per-case verdict list as the subject."""
    passed = sum(1 for r in results if r["verdict"] == r["expect"])
    predicate = {
        "implementation": implementation,
        "suite": {"revision": manifest["suite"]["revision"], "commit": manifest["suite"].get("commit")},
        "runLabel": run_label,
        "evidence": evidence,
        "scores": [{"role": "score", "passed": passed, "total": len(results)}],
        "posting": None,
        "date": None,
        "runner": _runner("local-run"),
    }
    problems = validate_predicate(predicate)
    if problems:
        raise ValueError("; ".join(problems))
    return build_statement(f"results:{implementation}@suite-revision-{manifest['suite']['revision']}", digest_of(results), predicate)
