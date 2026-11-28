"""Reconstruct what a record establishes about an agent's authority and its human escalation.

A hiring agent took a decision and escalated it to a designated human role. A later
reader, the receiver, has the record and must say what the evidence establishes: which
authority the agent held at the instant the question is asked, and how far the referral
travelled (referral, receipt, acknowledgement, acceptance and, where the decision class
requires it, closure by the designated role). The receiver preserves what is unresolved
or disputed and never infers authority, acceptance or a successful escalation where the
evidence for it is missing.

Every record is synthetic. It states the decision, the versions of the authority record
the agent acted under, what the reference to that record resolved to when the receiver
asked, the evidence slots of the escalation, and the instant the receiver evaluates at.
The reader checks in a fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the responsibility-escalation contract (``contract_id_unknown``);
3. the referral is evidenced (``referral_not_evidenced``);
4. no evidenced event falls after the evaluation instant
   (``event_after_evaluation_instant``);
5. the authority reference resolved (``reference_unavailable``);
6. the resolved version is the one in force at the read instant or the current one
   (``reference_inconsistent``);
7. the resolution did not return the current record in place of the version in force
   at the read instant (``current_record_resolved_not_decision_time``);
8. the version in force at the read instant holds the authority
   (``authority_not_held_at_read_instant``);
9. the receipt is evidenced (``receipt_not_evidenced``);
10. the acknowledgement is evidenced (``escalation_unanswered``);
11. the acknowledgement is by the designated role
    (``acknowledged_outside_designated_role``);
12. the authority still held when the acknowledgement was recorded
    (``authority_narrowed_before_acknowledgement``);
13. the acceptance is evidenced (``acceptance_not_evidenced``);
14. the acceptance is by the designated role (``accepted_outside_designated_role``);
15. where the record requires closure, the closure is evidenced
    (``closure_not_evidenced``);
16. the closure is by the designated role (``closed_outside_designated_role``);
17. the closure is recorded inside its window (``closed_late``).

The outcome tokens are ``established``, ``partial`` (some slots are evidenced and a later
one is not, or a step was taken by the wrong role or late), ``unresolved`` (the escalation
was not answered) and ``not_established`` (the authority or the referral itself cannot be
reconstructed). A record that passes every check is ``established``, with reason
``closed_as_accepted`` where closure is required and otherwise the instant its authority
was read at.

The external-verifier contract: ``<verifier> <case-dir>/record.json --json`` prints one
JSON object carrying ``decision`` and ``reason``, and exits 0 for ``established``, 1 for
``not_established``, 2 for ``partial`` and 3 for ``unresolved``.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agent_evidence_vectors import strictjson
from agent_evidence_vectors.identifiers import identifier, same_identifier
from agent_evidence_vectors.monitorcoverage import (
    _fixture_error,
    _validated_entries,
    run_corpus,
)

SUITE = "responsibility-escalation/v1"
CONTRACT_ID = identifier(
    "agent-evidence-vectors/predicate/v1/responsibility-escalation"
)
ESTABLISHED, PARTIAL, UNRESOLVED, NOT_ESTABLISHED = (
    "established",
    "partial",
    "unresolved",
    "not_established",
)
EXIT_FOR = {ESTABLISHED: 0, NOT_ESTABLISHED: 1, PARTIAL: 2, UNRESOLVED: 3}
SLOTS = ("referral", "receipt", "acknowledgement", "acceptance", "closure")
#: Each check in order, with the outcome token a failure of it carries.
CHECK_OUTCOME = {
    "contract_id_missing": NOT_ESTABLISHED,
    "contract_id_unknown": NOT_ESTABLISHED,
    "referral_not_evidenced": NOT_ESTABLISHED,
    "event_after_evaluation_instant": NOT_ESTABLISHED,
    "reference_unavailable": NOT_ESTABLISHED,
    "reference_inconsistent": NOT_ESTABLISHED,
    "current_record_resolved_not_decision_time": NOT_ESTABLISHED,
    "authority_not_held_at_read_instant": NOT_ESTABLISHED,
    "receipt_not_evidenced": PARTIAL,
    "escalation_unanswered": UNRESOLVED,
    "acknowledged_outside_designated_role": PARTIAL,
    "authority_narrowed_before_acknowledgement": PARTIAL,
    "acceptance_not_evidenced": PARTIAL,
    "accepted_outside_designated_role": PARTIAL,
    "closure_not_evidenced": PARTIAL,
    "closed_outside_designated_role": PARTIAL,
    "closed_late": PARTIAL,
}
CHECKS = tuple(CHECK_OUTCOME)
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-responsibility-escalation"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-responsibility-escalation"
)

Record = dict[str, Any]


def instant(text: str) -> datetime:
    """Parse a UTC instant written ``YYYY-MM-DDTHH:MM:SSZ``."""
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _slot(record: Record, name: str) -> dict[str, Any]:
    slots = record.get("escalation", {}).get("slots", {})
    found = slots.get(name)
    return found if isinstance(found, dict) else {}


def evidenced(record: Record, name: str) -> bool:
    """Whether the record evidences one slot of the escalation."""
    return _slot(record, name).get("evidenced") is True


def read_instant(record: Record) -> str | None:
    """The instant the authority is read at: the decision or the referral."""
    authority = record.get("authority", {})
    at: str | None
    if authority.get("readAt") == "referral":
        at = _slot(record, "referral").get("at")
    else:
        at = record.get("decision", {}).get("at")
    return at


def version_in_force(record: Record, when: str | None) -> dict[str, Any] | None:
    """The last version of the authority record effective at ``when``, or None."""
    if when is None:
        return None
    found = None
    for version in record.get("authority", {}).get("versions", []):
        if instant(version["effectiveFrom"]) <= instant(when):
            found = version
    return found


def _current(record: Record) -> dict[str, Any] | None:
    versions = record.get("authority", {}).get("versions", [])
    return versions[-1] if versions else None


def _returned(record: Record) -> str | None:
    returned: str | None = record.get("authority", {}).get("resolution", {}).get("returned")
    return returned


def _reference_inconsistent(record: Record) -> bool:
    ids = {v["id"] for v in record.get("authority", {}).get("versions", [])}
    held = version_in_force(record, read_instant(record))
    current = _current(record)
    returned = _returned(record)
    return returned not in ids or (
        returned != (held or {}).get("id") and returned != (current or {}).get("id")
    )


def _current_returned(record: Record) -> bool:
    held = version_in_force(record, read_instant(record))
    current = _current(record)
    returned = _returned(record)
    return returned != (held or {}).get("id") and returned == (current or {}).get("id")


def _after_evaluation(record: Record) -> bool:
    evaluated = instant(record["evaluatedAt"])
    times = [record.get("decision", {}).get("at")]
    times += [_slot(record, name).get("at") for name in SLOTS if evidenced(record, name)]
    return any(t is not None and instant(t) > evaluated for t in times)


def _by_designated(record: Record, name: str) -> bool:
    role = record.get("escalation", {}).get("designatedRole")
    return bool(_slot(record, name).get("by") == role)


def _closure_required(record: Record) -> bool:
    return record.get("escalation", {}).get("closure", {}).get("required") is True


def _narrowed_before_ack(record: Record) -> bool:
    held = version_in_force(record, _slot(record, "acknowledgement").get("at"))
    return held is None or held.get("holds") is not True


def _closed_late(record: Record) -> bool:
    due = record.get("escalation", {}).get("closure", {}).get("dueBy")
    return due is not None and instant(_slot(record, "closure")["at"]) > instant(due)


def _failures(record: Record) -> dict[str, Callable[[], bool]]:
    authority = record.get("authority", {})
    return {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: not same_identifier(
            record.get("contractId", CONTRACT_ID), CONTRACT_ID),
        "referral_not_evidenced": lambda: not evidenced(record, "referral"),
        "event_after_evaluation_instant": lambda: _after_evaluation(record),
        "reference_unavailable": lambda: (
            authority.get("resolution", {}).get("status") != "resolved"
        ),
        "reference_inconsistent": lambda: _reference_inconsistent(record),
        "current_record_resolved_not_decision_time": lambda: _current_returned(record),
        "authority_not_held_at_read_instant": lambda: (
            (version_in_force(record, read_instant(record)) or {}).get("holds") is not True
        ),
        "receipt_not_evidenced": lambda: not evidenced(record, "receipt"),
        "escalation_unanswered": lambda: not evidenced(record, "acknowledgement"),
        "acknowledged_outside_designated_role": lambda: not _by_designated(
            record, "acknowledgement"
        ),
        "authority_narrowed_before_acknowledgement": lambda: _narrowed_before_ack(record),
        "acceptance_not_evidenced": lambda: not evidenced(record, "acceptance"),
        "accepted_outside_designated_role": lambda: not _by_designated(record, "acceptance"),
        "closure_not_evidenced": lambda: (
            _closure_required(record) and not evidenced(record, "closure")
        ),
        "closed_outside_designated_role": lambda: (
            _closure_required(record) and not _by_designated(record, "closure")
        ),
        "closed_late": lambda: _closure_required(record) and _closed_late(record),
    }


def _first_failure(record: Record, skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each check is
    forced by some member or mutation; a verifier never sets it.
    """
    failures = _failures(record)
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name
    return None


def clean_reason(record: Record) -> str:
    """The reason a record that passes every check carries."""
    if _closure_required(record):
        return "closed_as_accepted"
    if record.get("authority", {}).get("readAt") == "referral":
        return "authority_held_at_referral_instant"
    return "authority_held_at_decision_time"


def judge(record: Record, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one parsed record."""
    failure = _first_failure(record, skip)
    if failure is not None:
        return {"decision": CHECK_OUTCOME[failure], "reason": failure}
    return {"decision": ESTABLISHED, "reason": clean_reason(record)}


def retained(record: Record) -> dict[str, Any]:
    """The read instant, the version in force there and the slots evidenced."""
    held = version_in_force(record, read_instant(record))
    return {
        "evidenced": "+".join(name for name in SLOTS if evidenced(record, name)) or "none",
        "inForce": (held or {}).get("id", "none"),
        "readAt": record.get("authority", {}).get("readAt", "decision"),
    }


def _load(record_path: Path) -> Record:
    loaded: Record = strictjson.loads(record_path.read_text(encoding="utf-8"))
    return loaded


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record file."""
    return judge(_load(record_path), skip)


def external_answer(command: list[str], path: Path) -> tuple[bool, dict[str, Any] | str]:
    """Run one external verifier on one record and read its decision."""
    try:
        result = subprocess.run(
            [*command, str(path), "--json"],
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
    """Check every record, through the named verifier or the reference reader."""
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
            ran, observed = external_answer(command, record_path)
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
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("record", nargs="?", help="judge one record.json with the reference reader")
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
    total = len(strictjson.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
