"""Judge one record against a requirement of a Trust over IP HTX pattern.

Each record is plain JSON in one of two shapes, and the reader names the first
check that fails.

Transaction confirmation (HTX P18.01 section 6, transaction controls must prevent
changed details from inheriting an earlier approval): ``confirmation`` holds the
``outcome`` and the ``request`` the person confirmed, and ``action`` holds the
``request`` about to be carried out.

1. the confirmation outcome is ``confirmed`` (``not-confirmed``);
2. the action's request equals the confirmed request as parsed JSON, so a
   changed, added or removed member is a different request
   (``request-changed-after-confirmation``).

Consent and disclosure (a proposal of this repository, since the HTX pattern
pages for it are not written yet): what is disclosed must be within what the
person agreed to share, for the stated purpose. ``consent`` holds the
``outcome``, the ``purpose``, the ``recipient``, the ``fields`` the person
agreed to (``required`` and ``optional_granted``) and the ``refused_optional``
fields, and ``disclosure`` holds the ``purpose``, ``recipient`` and ``fields``
about to be disclosed.

1. a disclosure of any field needs the outcome ``agreed`` (``not-agreed``);
2. the disclosure purpose is the consented one (``purpose-changed``);
3. the disclosure recipient is the consented one (``recipient-changed``);
4. no disclosed field is one the person refused (``refused-field-disclosed``);
5. every disclosed field is required or a granted optional one
   (``field-not-consented``).

A record that passes every check of its shape is ``allow``. A record in neither
shape is ``deny`` with ``record-shape-unknown``.

The external-verifier contract: ``<verifier> <case-dir>/record.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``allow`` and 1 for ``deny``.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from agent_evidence_vectors import strictjson
from agent_evidence_vectors.monitorcoverage import (
    ALLOW,
    DENY,
    EXIT_FOR,
    check_corpus,
    cli,
    run_corpus,
)

SUITE = "htx-cases/v1"
TRANSACTION, CONSENT = "transaction-confirmation", "consent-disclosure"
SHAPE_UNKNOWN = "record-shape-unknown"
ALLOWED_REASONS = {TRANSACTION: "request-matches-confirmation",
                   CONSENT: "disclosure-within-consent"}
CHECKS_FOR = {
    TRANSACTION: ("not-confirmed", "request-changed-after-confirmation"),
    CONSENT: ("not-agreed", "purpose-changed", "recipient-changed",
              "refused-field-disclosed", "field-not-consented"),
}
CHECKS = CHECKS_FOR[TRANSACTION] + CHECKS_FOR[CONSENT]
__all__ = ["ALLOW", "DENY", "EXIT_FOR", "SUITE", "check", "main", "verify"]
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-htx-cases" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "corpora" / "vectors-htx-cases")

Record = dict[str, Any]


def shape(record: Record) -> str | None:
    """Which of the two record shapes this is, or None."""
    if isinstance(record.get("confirmation"), dict) and isinstance(record.get("action"), dict):
        return TRANSACTION
    if isinstance(record.get("consent"), dict) and isinstance(record.get("disclosure"), dict):
        return CONSENT
    return None


def _allowed_fields(consent: Record) -> set[str]:
    fields = consent.get("fields", {})
    return set(fields.get("required", [])) | set(fields.get("optional_granted", []))


def _disclosed(record: Record) -> list[str]:
    return list(record["disclosure"].get("fields", []))


def retained(record: Record) -> dict[str, Any]:
    """The pattern and the outcome a verifier keeps."""
    kind = shape(record)
    if kind == TRANSACTION:
        return {"outcome": record["confirmation"].get("outcome"), "shape": kind}
    if kind == CONSENT:
        return {"disclosedFields": len(_disclosed(record)),
                "outcome": record["consent"].get("outcome"), "shape": kind}
    return {"shape": None}


def _transaction_failures(record: Record) -> dict[str, Callable[[], bool]]:
    confirmation, action = record["confirmation"], record["action"]
    return {
        "not-confirmed": lambda: confirmation.get("outcome") != "confirmed",
        "request-changed-after-confirmation":
            lambda: confirmation.get("request") != action.get("request"),
    }


def _consent_failures(record: Record) -> dict[str, Callable[[], bool]]:
    consent, disclosure = record["consent"], record["disclosure"]
    return {
        "not-agreed": lambda: consent.get("outcome") != "agreed" and bool(_disclosed(record)),
        "purpose-changed": lambda: disclosure.get("purpose") != consent.get("purpose"),
        "recipient-changed": lambda: disclosure.get("recipient") != consent.get("recipient"),
        "refused-field-disclosed":
            lambda: bool(set(_disclosed(record)) & set(consent.get("refused_optional", []))),
        "field-not-consented":
            lambda: not set(_disclosed(record)) <= _allowed_fields(consent),
    }


def _first_failure(record: Record, skip: frozenset[str]) -> str | None:
    """Name the first check of the record's shape it fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    """
    kind = shape(record)
    if kind is None:
        return SHAPE_UNKNOWN
    failures = (_transaction_failures if kind == TRANSACTION else _consent_failures)(record)
    for name in CHECKS_FOR[kind]:
        if name not in skip and failures[name]():
            return name
    return None


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record."""
    record: Record = strictjson.loads(record_path.read_text(encoding="utf-8"))
    failure = _first_failure(record, skip)
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    kind = shape(record)
    return {"decision": ALLOW, "reason": ALLOWED_REASONS[kind or TRANSACTION]}


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every record, through the named verifier or the reference reader."""
    return check_corpus(root, SUITE, verify, retained, verifier, skip)


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    return run_corpus(SUITE, check, root, verifier, report_path, rail_note)


def main(argv: list[str] | None = None) -> int:
    return cli(argv, __doc__, verify, check, ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
