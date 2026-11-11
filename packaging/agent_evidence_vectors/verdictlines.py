"""Corpus verdict lines: one shared answer format for every verifier's corpus mode.

A verifier's corpus mode prints one JSON object per line, one line per member of
every corpus it was handed, in the shape ``vectors/verdict-line.schema.json``
defines. This module checks such output in three steps, stdlib only, like the
rail beside it:

* ``validate_line`` holds one line to the schema;
* ``check`` holds one verifier's whole output to the corpus manifests: every
  member answered exactly once, nothing answered that no manifest lists, the
  corpus digest the line names is the manifest's, and every applicable verdict
  (and the normative fields the manifest declares) matches what the manifest
  expects. ``not-applicable`` is never a pass: it is counted, and refused
  unless the caller allows it for that verifier;
* ``agree`` compares several verifiers' outputs member by member. A member is
  compared among the verifiers that answered it; a member no two verifiers
  answered is reported, because a four-way check that compared nothing on it
  must not read as agreement.

Command line::

    python -m agent_evidence_vectors.verdictlines check --corpus DIR [--corpus DIR ...]
        [--allow-not-applicable] LINES.jsonl
    python -m agent_evidence_vectors.verdictlines agree --corpus DIR [...]
        [--allow-not-applicable NAME ...] [--min-answering N] LINES.jsonl LINES.jsonl ...

Both print one JSON summary and exit 0 when every check holds, 1 when one does
not, 2 when an input cannot be read.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any

SCHEMA_ID = "https://probityai.github.io/agent-evidence-vectors/schema/verdict-line/v1"
VERDICTS = ("accept", "reject", "not-applicable", "error")
ANSWERED = frozenset({"accept", "reject"})
LINE_KEYS = frozenset(
    {"schema", "suite", "corpusDigest", "vector", "verdict", "reason", "result", "verifier"}
)
REQUIRED_KEYS = LINE_KEYS - {"result"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")

# The manifest's own verdict tokens, mapped onto the shared two answers.
TOKEN_TO_VERDICT = {"valid": "accept", "invalid": "reject", "allow": "accept", "deny": "reject"}


def validate_line(line: Any) -> list[str]:
    """Every way ``line`` departs from verdict-line v1, or an empty list."""
    if not isinstance(line, dict):
        return ["a verdict line is a JSON object"]
    errors: list[str] = []
    for rule in (_keys_ok, _identity_ok, _verdict_ok, _reason_ok, _result_ok, _verifier_ok):
        errors.extend(rule(line))
    return errors


def _keys_ok(line: dict[str, Any]) -> list[str]:
    errors = []
    missing = sorted(REQUIRED_KEYS - line.keys())
    if missing:
        errors.append(f"missing {', '.join(missing)}")
    extra = sorted(line.keys() - LINE_KEYS)
    if extra:
        errors.append(f"unknown member(s) {', '.join(extra)}")
    return errors


def _identity_ok(line: dict[str, Any]) -> list[str]:
    errors = []
    if "schema" in line and line["schema"] != SCHEMA_ID:
        errors.append(f"schema is {line['schema']!r}, not {SCHEMA_ID!r}")
    errors += [f"{k}: a non-empty string" for k in ("suite", "vector")
               if k in line and not _nonempty(line[k])]
    digest = line.get("corpusDigest", "0" * 64)
    if not (isinstance(digest, str) and HEX64.match(digest)):
        errors.append("corpusDigest: 64 lowercase hex digits")
    return errors


def _verdict_ok(line: dict[str, Any]) -> list[str]:
    if "verdict" in line and line["verdict"] not in VERDICTS:
        return [f"verdict {line['verdict']!r} is not one of {', '.join(VERDICTS)}"]
    return []


def _reason_ok(line: dict[str, Any]) -> list[str]:
    if "reason" not in line:
        return []
    reason, verdict = line["reason"], line.get("verdict")
    if reason is not None and not _nonempty(reason):
        return ["reason: a non-empty string or null"]
    if reason is None and verdict in ("reject", "not-applicable", "error"):
        return [f"reason: required on a {verdict} line"]
    return []


def _result_ok(line: dict[str, Any]) -> list[str]:
    if "result" not in line:
        return []
    errors = [] if _nonempty(line["result"]) else ["result: a non-empty string"]
    if line.get("verdict") != "accept":
        errors.append("result: only an accept line carries one")
    return errors


def _verifier_ok(line: dict[str, Any]) -> list[str]:
    if "verifier" not in line:
        return []
    verifier = line["verifier"]
    if (
        isinstance(verifier, dict)
        and set(verifier) == {"name", "version"}
        and all(_nonempty(verifier[k]) for k in ("name", "version"))
    ):
        return []
    return ["verifier: exactly a non-empty name and version"]


def _nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


@dataclass(frozen=True)
class Expectation:
    """What a manifest says one member must be answered with."""

    verdicts: frozenset[str]
    result: str | None
    # Reasons the manifest names for the member, and whether a reason outside
    # them fails conformance (normative) or is a reason-parity datum only.
    reasons: frozenset[str]
    reason_normative: bool
    excluded: str | None


@dataclass
class Corpus:
    suite: str
    digest: str
    path: str
    members: dict[str, Expectation]


class CorpusError(ValueError):
    """A corpus manifest this module cannot read expectations from."""


def load_corpus(path: str) -> Corpus:
    """Read a corpus directory's MANIFEST.json into per-member expectations.

    Two manifest shapes carry a per-member answer: ``expected.verdict``
    (valid or invalid, the AEE shape) and ``expected.decision`` (allow or deny,
    with a reason). A manifest whose members carry neither is refused by name:
    a member with no stated answer cannot be checked, and passing it would be a
    check that did not run.
    """
    try:
        with open(os.path.join(path, "MANIFEST.json"), encoding="utf-8") as handle:
            manifest = json.load(handle)
    except (OSError, ValueError) as exc:
        raise CorpusError(f"{path}: MANIFEST.json unreadable: {exc}") from exc
    suite, digest = manifest.get("suite"), manifest.get("corpusDigest")
    if not _nonempty(suite) or not (isinstance(digest, str) and HEX64.match(digest)):
        raise CorpusError(f"{path}: MANIFEST.json names no suite or no corpusDigest")
    entries = manifest.get("vectors")
    if not isinstance(entries, list) or not entries:
        raise CorpusError(f"{path}: MANIFEST.json lists no members under \"vectors\"")
    normative = set(((manifest.get("comparisonSurface") or {}).get("normative")) or [])
    members: dict[str, Expectation] = {}
    for entry in entries:
        vid = entry.get("id") if isinstance(entry, dict) else None
        if not isinstance(vid, str) or not vid or vid in members:
            raise CorpusError(f"{path}: member id {vid!r} is missing or repeated")
        members[vid] = _expectation(path, entry, normative)
    return Corpus(suite=suite, digest=digest, path=path, members=members)


def _expectation(path: str, entry: dict[str, Any], normative: set[str]) -> Expectation:
    expected = entry.get("expected") or {}
    excluded = expected.get("unmeasurableBecause")
    excluded = excluded if _nonempty(excluded) else None
    if "decision" in expected:
        verdict = TOKEN_TO_VERDICT.get(expected["decision"])
        if verdict is None:
            raise CorpusError(f"{path}: {entry['id']}: decision {expected['decision']!r}")
        reason = expected.get("reason")
        reason = reason if isinstance(reason, str) and reason else None
        # A decision corpus states the reason as part of the answer unless its
        # manifest names a narrower normative surface.
        reason_normative = not normative or "reason" in normative
        return Expectation(
            frozenset({verdict}), None, frozenset({reason}) if reason else frozenset(),
            reason_normative and reason is not None, excluded,
        )
    if "verdict" in expected:
        verdict = TOKEN_TO_VERDICT.get(expected["verdict"])
        if verdict is None:
            raise CorpusError(f"{path}: {entry['id']}: verdict {expected['verdict']!r}")
        verdicts = {verdict}
        readings = expected.get("readings") if entry.get("kind") == "indeterminate" else None
        reasons = {str(c) for c in expected.get("codes") or []}
        if isinstance(readings, dict) and readings:
            # An indeterminate member admits every answer one of its declared
            # readings predicts (the rail's admissible_verdicts rule).
            predicted = {str(v) for v in readings.values()}
            reasons |= predicted
            verdicts = ({"accept"} if "valid" in predicted else set()) | (
                {"reject"} if predicted - {"valid"} else set()
            )
        result = expected.get("result") if verdict == "accept" else None
        return Expectation(
            frozenset(verdicts),
            result if _nonempty(result) and "result" in (normative or {"result"}) else None,
            frozenset(reasons),
            "codes" in normative,
            excluded,
        )
    raise CorpusError(
        f"{path}: {entry.get('id')}: the member states no expected verdict or decision"
    )


@dataclass
class Report:
    verifier: dict[str, str] | None = None
    lines: int = 0
    answered: int = 0
    not_applicable: int = 0
    errors: int = 0
    reason_parity: dict[str, int] = field(default_factory=lambda: {"match": 0, "differ": 0})
    failures: list[str] = field(default_factory=list)
    verdicts: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)

    def ok(self) -> bool:
        return not self.failures

    def summary(self) -> dict[str, Any]:
        return {
            "verifier": self.verifier,
            "lines": self.lines,
            "answered": self.answered,
            "notApplicable": self.not_applicable,
            "errors": self.errors,
            "reasonParity": self.reason_parity,
            "failures": self.failures,
            "ok": self.ok(),
        }


def parse_lines(text: str) -> tuple[list[Any], list[str]]:
    """Each non-empty line of ``text`` parsed as JSON, and every line that is not."""
    parsed, bad = [], []
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        try:
            parsed.append(json.loads(raw))
        except ValueError:
            bad.append(f"line {number}: not JSON")
    return parsed, bad


def check(text: str, corpora: list[Corpus], *, allow_not_applicable: bool = False) -> Report:
    """Hold one verifier's corpus-mode output to the schema and the manifests."""
    report = Report()
    lines, bad = parse_lines(text)
    report.failures.extend(bad)
    by_suite = {c.suite: c for c in corpora}
    if len(by_suite) != len(corpora):
        report.failures.append("two corpora handed in name the same suite")
    for line in lines:
        report.lines += 1
        problems = validate_line(line)
        if problems:
            report.failures.append(f"line {report.lines}: " + "; ".join(problems))
            continue
        _check_line(report, line, by_suite, allow_not_applicable)
    for corpus in corpora:
        missing = [v for v in corpus.members if (corpus.suite, v) not in report.verdicts]
        if missing:
            report.failures.append(
                f"{corpus.suite}: {len(missing)} of {len(corpus.members)} member(s) unanswered, "
                f"first {missing[0]}"
            )
    if report.lines == 0:
        report.failures.append("no verdict lines at all")
    return report


def _check_line(
    report: Report, line: dict[str, Any], by_suite: dict[str, Corpus], allow_na: bool
) -> None:
    where = f"{line['suite']} {line['vector']}"
    if report.verifier is None:
        report.verifier = line["verifier"]
    elif line["verifier"] != report.verifier:
        report.failures.append(
            f"{where}: verifier {line['verifier']} differs from {report.verifier}"
        )
    expect = _locate(report, line, by_suite, where)
    if expect is None:
        return
    verdict = line["verdict"]
    if verdict == "error":
        report.errors += 1
        report.failures.append(f"{where}: the verifier could not answer ({line['reason']})")
    elif verdict == "not-applicable":
        report.not_applicable += 1
        if not allow_na:
            report.failures.append(
                f"{where}: not-applicable from a verifier held to the whole corpus"
            )
    else:
        report.answered += 1
        if expect.excluded is None:
            _score(report, line, expect, where)


def _locate(
    report: Report, line: dict[str, Any], by_suite: dict[str, Corpus], where: str
) -> Expectation | None:
    """The member's expectation, recording the line; None when it has none."""
    corpus = by_suite.get(line["suite"])
    if corpus is None:
        report.failures.append(f"{where}: no corpus handed in has this suite")
        return None
    if line["corpusDigest"] != corpus.digest:
        report.failures.append(f"{where}: corpusDigest is not the manifest's {corpus.digest}")
    key = (line["suite"], line["vector"])
    if key in report.verdicts:
        report.failures.append(f"{where}: answered twice")
        return None
    expect = corpus.members.get(line["vector"])
    if expect is None:
        report.failures.append(f"{where}: no such member in the manifest")
        return None
    report.verdicts[key] = line
    return expect


def _score(report: Report, line: dict[str, Any], expect: Expectation, where: str) -> None:
    verdict = line["verdict"]
    if verdict not in expect.verdicts:
        wanted = " or ".join(sorted(expect.verdicts))
        report.failures.append(f"{where}: {verdict}, the manifest expects {wanted}")
        return
    if expect.result is not None and line.get("result") != expect.result:
        report.failures.append(
            f"{where}: result {line.get('result')!r}, expected {expect.result!r}"
        )
    if (expect.reasons and verdict == "reject") or expect.reason_normative:
        hit = line["reason"] in expect.reasons
        report.reason_parity["match" if hit else "differ"] += 1
        if expect.reason_normative and not hit:
            report.failures.append(
                f"{where}: reason {line['reason']!r}, expected {sorted(expect.reasons)}"
            )


def agree(reports: list[Report], *, min_answering: int = 2) -> dict[str, Any]:
    """Compare several checked outputs member by member.

    Members are compared among the verifiers that answered them (accept or
    reject). A disagreement on any member fails. A member fewer than
    ``min_answering`` verifiers answered fails too, so that a comparison that
    compared nothing never reads as agreement.
    """
    keys = sorted(set().union(*(r.verdicts for r in reports))) if reports else []
    disagreements, thin = [], []
    compared_by: dict[int, int] = {}
    for key in keys:
        answers = {
            (r.verifier or {}).get("name", f"#{i}"): r.verdicts[key]["verdict"]
            for i, r in enumerate(reports)
            if key in r.verdicts and r.verdicts[key]["verdict"] in ANSWERED
        }
        compared_by[len(answers)] = compared_by.get(len(answers), 0) + 1
        if len(answers) < min_answering:
            thin.append(f"{key[0]} {key[1]}: answered by {len(answers)}")
        elif len(set(answers.values())) != 1:
            disagreements.append(
                f"{key[0]} {key[1]}: " + ", ".join(f"{k}={v}" for k, v in sorted(answers.items()))
            )
    failures = [f for r in reports for f in r.failures]
    return {
        "members": len(keys),
        "answeredBy": {str(k): v for k, v in sorted(compared_by.items())},
        "disagreements": disagreements,
        "underAnswered": thin,
        "verifiers": [r.summary() for r in reports],
        "ok": not failures and not disagreements and not thin and bool(keys),
    }


def make_line(
    corpus: Corpus | tuple[str, str],
    vector: str,
    verdict: str,
    reason: str | None,
    verifier: tuple[str, str],
    result: str | None = None,
) -> dict[str, Any]:
    """Build one verdict line; producers in Python call this rather than spelling the keys."""
    suite, digest = (corpus.suite, corpus.digest) if isinstance(corpus, Corpus) else corpus
    line: dict[str, Any] = {
        "schema": SCHEMA_ID,
        "suite": suite,
        "corpusDigest": digest,
        "vector": vector,
        "verdict": verdict,
        "reason": reason,
        "verifier": {"name": verifier[0], "version": verifier[1]},
    }
    if result is not None and verdict == "accept":
        line["result"] = result
    return line


def dumps(line: dict[str, Any]) -> str:
    """One line, keys sorted, no whitespace: the form every producer prints."""
    return json.dumps(line, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agent-evidence-vectors verdict-lines")
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("check", help="hold one verifier's output to the schema and manifests")
    one.add_argument("--corpus", action="append", required=True, metavar="DIR")
    one.add_argument("--allow-not-applicable", action="store_true")
    one.add_argument("lines")
    many = sub.add_parser("agree", help="check several verifiers' outputs and compare them")
    many.add_argument("--corpus", action="append", required=True, metavar="DIR")
    many.add_argument(
        "--allow-not-applicable", action="append", default=[], metavar="NAME",
        help="a verifier name allowed to answer not-applicable (repeatable)",
    )
    many.add_argument("--min-answering", type=int, default=2)
    many.add_argument("lines", nargs="+")
    args = parser.parse_args(argv)
    try:
        corpora = [load_corpus(path) for path in args.corpus]
        texts = [_read(path) for path in ([args.lines] if args.command == "check" else args.lines)]
    except (CorpusError, OSError) as exc:
        print(json.dumps({"ok": False, "notRun": str(exc)}))
        return 2
    if args.command == "check":
        report = check(texts[0], corpora, allow_not_applicable=args.allow_not_applicable)
        print(json.dumps(report.summary(), sort_keys=True))
        return 0 if report.ok() else 1
    reports = []
    for text in texts:
        lines, _ = parse_lines(text)
        name = next(
            (ln.get("verifier", {}).get("name") for ln in lines if isinstance(ln, dict)
             and isinstance(ln.get("verifier"), dict)), None,
        )
        reports.append(check(text, corpora, allow_not_applicable=name in args.allow_not_applicable))
    summary = agree(reports, min_answering=args.min_answering)
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["ok"] else 1


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8") as handle:
        return handle.read()


if __name__ == "__main__":
    sys.exit(main())
