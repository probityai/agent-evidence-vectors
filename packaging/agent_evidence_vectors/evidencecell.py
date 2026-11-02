"""Check one signed decision-table cell: who coded it, against which closed codes.

An incident decision table crosses evidence states (rows) with responses
(columns). Each cell records what the table says, or that it says nothing, and
how well the source documents support it. ``incident-evidence-cell/v1`` makes
one cell one record: an in-toto Statement v1 whose subjects are the source
documents the cell was coded from, by SHA-256, and whose predicate carries

``cell``
    ``table``, ``row`` and ``column``, each a non-empty string;
``state``
    an ``evidence_state`` code as the URI its term page emits,
    ``https://w3id.org/agent-evidence/vocab/v1/evidence_state#ES3``;
``response``
    one value of the vocabulary term ``response_function``;
``supportLabel``
    ``supported``, ``unsupported`` or ``unknown``;
``value`` or ``notAddressed``
    exactly one: what the cell records, or ``{"reason": ...}`` for an empty cell;
``producer``
    ``{"id": <https URL>}``, the party that coded the cell;
``issuedAt``
    an RFC 3339 UTC time ending in ``Z``;
``registryDigest``
    ``{"sha256": <hex>}``, the vocabulary registry snapshot the codes were read
    against;
``doesNotAssert``
    a non-empty list of sentences, which must include :data:`DISCLAIMER`.

The producer signs the Statement in a DSSE envelope with its own key. A
signature shows who coded a cell, never that the cell is true, and the record
says so in its own bytes.

The reader applies five checks in order and names the first that fails:

1. the Statement has exactly ``_type``, ``subject``, ``predicateType`` and
   ``predicate``, with the in-toto v1 type, a non-empty subject list of named
   SHA-256 digests, this predicate type and an object predicate
   (``statement_malformed``);
2. the predicate has exactly its members, each of its type, with exactly one of
   ``value`` and ``notAddressed`` (``predicate_malformed``);
3. ``state``, ``response`` and ``supportLabel`` are inside their closed sets
   (``closed_vocabulary_violation``);
4. an empty cell is labelled ``unknown``: nothing supports or refutes a cell
   the table leaves empty (``empty_cell_labelled``);
5. ``doesNotAssert`` carries the exact disclaimer sentence
   (``truth_disclaimer_missing``).

A record that passes all five is ``allow`` with reason ``cell_recorded``.

Judge your own cells::

    python -m agent_evidence_vectors.evidencecell record.json [more.json ...] --json

prints one JSON object per record carrying ``record``, ``decision`` and
``reason``; it exits 0 when every record is ``allow``, 1 when any is ``deny``
and 2 when any cannot be read. With no record it replays this package's corpus;
``--verifier`` replays it through another verifier instead, under the contract
every decision corpus shares: ``<verifier> <case-dir>/record.json --json``
prints ``decision`` and ``reason`` and exits 0 for ``allow`` and 1 for ``deny``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from agent_evidence_vectors import monitorcoverage as _shared

SUITE = "incident-evidence-cell/v1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = ("https://probityai.github.io/agent-evidence-vectors/predicate/v1/"
                  "incident-evidence-cell")
STATE_TERM = "https://w3id.org/agent-evidence/vocab/v1/evidence_state"
STATES = tuple(f"{STATE_TERM}#ES{n}" for n in range(9))
RESPONSES = ("monitoring_increase", "notification", "restriction", "isolation", "pause",
             "remediation", "restoration")
SUPPORT_LABELS = ("supported", "unsupported", "unknown")
DISCLAIMER = "The signature shows who coded this cell, not that the cell is true."
#: The vocabulary registry snapshot the corpus codes were read against: the SHA-256
#: of pages/vocab/v1/registry/sha256-<this hex>.yaml in this repository. The reader
#: checks a record's digest for its form only.
REGISTRY_DIGEST = "161bd780e265a99f27365c81bee12f5006ebb4e785a9563608ae98c52878a523"
ALLOW, DENY = "allow", "deny"
ALLOWED_REASON = "cell_recorded"
EXIT_FOR = {ALLOW: 0, DENY: 1}
CHECKS = (
    "statement_malformed",
    "predicate_malformed",
    "closed_vocabulary_violation",
    "empty_cell_labelled",
    "truth_disclaimer_missing",
)
STATEMENT = ("_type", "predicate", "predicateType", "subject")
REQUIRED = ("cell", "doesNotAssert", "issuedAt", "producer", "registryDigest", "response",
            "state", "supportLabel")
CONTENT = ("notAddressed", "value")
HEX = re.compile(r"[0-9a-f]{64}")
HTTPS = re.compile(r"https://[A-Za-z0-9.-]+(:[0-9]+)?(/[\x21-\x7e]*)?")
UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?Z")
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-incident-evidence-cell" if (_HERE / "corpora").exists()
        else _HERE.parents[1] / "corpora" / "vectors-incident-evidence-cell")

Record = dict[str, Any]


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _object(value: Any, keys: tuple[str, ...]) -> bool:
    return isinstance(value, dict) and set(value) == set(keys)


def _digest(value: Any) -> bool:
    return (_object(value, ("sha256",)) and isinstance(value["sha256"], str)
            and HEX.fullmatch(value["sha256"]) is not None)


def _utc(value: Any) -> bool:
    if not isinstance(value, str) or UTC.fullmatch(value) is None:
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _subject(value: Any) -> bool:
    return _object(value, ("digest", "name")) and _text(value["name"]) and _digest(value["digest"])


def _statement_malformed(record: Record) -> bool:
    subjects = record.get("subject")
    return (set(record) != set(STATEMENT)
            or record["_type"] != STATEMENT_TYPE
            or not isinstance(subjects, list) or not subjects
            or not all(_subject(subject) for subject in subjects)
            or record["predicateType"] != PREDICATE_TYPE
            or not isinstance(record["predicate"], dict))


def _predicate(record: Record) -> dict[str, Any]:
    predicate = record.get("predicate")
    return predicate if isinstance(predicate, dict) else {}


def _content_malformed(predicate: dict[str, Any]) -> bool:
    present = [key for key in CONTENT if key in predicate]
    if present == ["value"]:
        return not _text(predicate["value"])
    if present == ["notAddressed"]:
        reason = predicate["notAddressed"]
        return not (_object(reason, ("reason",)) and _text(reason["reason"]))
    return True


def _predicate_malformed(record: Record) -> bool:
    predicate = _predicate(record)
    if set(predicate) - set(CONTENT) != set(REQUIRED) or _content_malformed(predicate):
        return True
    cell, producer, sentences = (predicate["cell"], predicate["producer"],
                                 predicate["doesNotAssert"])
    return not (_object(cell, ("column", "row", "table")) and all(map(_text, cell.values()))
                and all(_text(predicate[key]) for key in ("response", "state", "supportLabel"))
                and _object(producer, ("id",)) and isinstance(producer["id"], str)
                and HTTPS.fullmatch(producer["id"]) is not None
                and _utc(predicate["issuedAt"]) and _digest(predicate["registryDigest"])
                and isinstance(sentences, list) and bool(sentences)
                and all(map(_text, sentences)))


def _outside_vocabulary(record: Record) -> bool:
    predicate = _predicate(record)
    return (predicate.get("state") not in STATES or predicate.get("response") not in RESPONSES
            or predicate.get("supportLabel") not in SUPPORT_LABELS)


def _empty_cell_labelled(record: Record) -> bool:
    predicate = _predicate(record)
    return "notAddressed" in predicate and predicate.get("supportLabel") != "unknown"


def _disclaimer_missing(record: Record) -> bool:
    sentences = _predicate(record).get("doesNotAssert")
    return not isinstance(sentences, list) or DISCLAIMER not in sentences


FAILURES: dict[str, Callable[[Record], bool]] = {
    "statement_malformed": _statement_malformed,
    "predicate_malformed": _predicate_malformed,
    "closed_vocabulary_violation": _outside_vocabulary,
    "empty_cell_labelled": _empty_cell_labelled,
    "truth_disclaimer_missing": _disclaimer_missing,
}


def retained(record: Record) -> dict[str, Any]:
    """The fields a verifier keeps: the column, the label, emptiness, subject count."""
    predicate = _predicate(record)
    cell = predicate.get("cell")
    column = cell.get("column") if isinstance(cell, dict) else None
    label = predicate.get("supportLabel")
    subjects = record.get("subject")
    return {"column": column if isinstance(column, str) else "",
            "empty": "notAddressed" in predicate,
            "subjects": len(subjects) if isinstance(subjects, list) else 0,
            "supportLabel": label if isinstance(label, str) else ""}


def _first_failure(record: Record, skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it. Every check is
    total over any JSON object, so a skipped earlier check never makes a later
    one raise.
    """
    for name in CHECKS:
        if name not in skip and FAILURES[name](record):
            return name
    return None


def _load(record_path: Path) -> Record:
    loaded = json.loads(record_path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("a record is a JSON object")
    return loaded


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record."""
    failure = _first_failure(_load(record_path), skip)
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    return {"decision": ALLOW, "reason": ALLOWED_REASON}


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every record, through the named verifier or the reference reader."""
    return _shared.check_corpus(root, SUITE, verify, retained, verifier, skip)


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    return _shared.run_corpus(SUITE, check, root, verifier, report_path, rail_note)


def _judge_records(paths: list[str], as_json: bool) -> int:
    worst = 0
    for name in paths:
        try:
            answer = verify(Path(name))
        except (OSError, ValueError) as exc:
            print(json.dumps({"record": name, "error": str(exc)}) if as_json
                  else f"{name}: unreadable: {exc}")
            worst = 2
            continue
        if as_json:
            print(json.dumps({"record": name, **answer}, sort_keys=True))
        else:
            print(f"{name}: {answer['decision']} {answer['reason']}")
        worst = max(worst, EXIT_FOR[answer["decision"]])
    return worst


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("records", nargs="*", help="judge these record.json files")
    parser.add_argument("--json", action="store_true", help="print each decision as JSON")
    parser.add_argument("--verifier", help="replay the corpus through this verifier instead")
    args = parser.parse_args(argv)
    if args.records:
        return _judge_records(args.records, args.json)
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    sys.exit(main())
