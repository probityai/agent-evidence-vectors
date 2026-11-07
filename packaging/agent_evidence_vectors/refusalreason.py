"""Judge one attestation response against the refusal vocabulary of an Internet-Draft.

draft-li-rttp-iqa-addressing-02, section 8.1, fixes a closed set of five refusal
reasons and says the reason of a refusal is the first value in the list whose
condition applies. Section 8.2 adds the null rule for the observation member of
the grant reference, and section 6.1 leaves the lease instant itself to a
declared convention. This corpus holds records from the Aicent Stack
conformance families aicent-grant-ref and aicent-lease-boundary (issue 453), each
anchored to a sentence of the draft.

Every record is one response an implementation produced and the facts it
answered over: which conditions of the vocabulary applied, what the relied-on
observation was, whether a diagnostic read followed, and, at the lease instant,
which boundary the deployment declared. The reader checks in a fixed order and
names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the refusal-reason-priority contract (``contract_id_unknown``);
3. the response carries a ``reason`` member (``reason_member_absent``);
4. the reason is null or one of the five values (``reason_outside_closed_set``);
5. at the lease instant the answer is a permit or ``evidence_expired``, the two
   boundary readings the draft licenses
   (``answer_outside_both_boundary_readings``);
6. no value is emitted when no condition applies (``refusal_without_condition``);
7. a permit is not emitted while a condition applies (``condition_ignored``);
8. the value emitted is the first applicable one, not a later one
   (``later_value_emitted``);
9. the observation member is null when the relied-on observation is absent or
   not fresh (``observation_backfilled``);
10. a diagnostic read does not move the grant's expiry
    (``evidence_renewed_by_diagnostic_read``).

A record that passes all ten is ``conformant`` with reason
``response_follows_source``, except at the lease instant, where the draft leaves
two cases open and the reader answers ``ambiguous``: no boundary is declared
(``boundary_undeclared``), or the declaration contradicts the answer
(``declaration_contradicts_use``; the author scores this nonconformant and the
draft attaches no consequence to a contradicting declaration, so the corpus
lists both readings).

The external-verifier contract: ``<verifier> <case-dir>/record.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``conformant``, 1 for ``nonconformant`` and 2 for ``ambiguous``.
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agent_evidence_vectors.monitorcoverage import (
    _fixture_error,
    _validated_entries,
    run_corpus,
)

SUITE = "refusal-reason-priority/v1"
CONTRACT_ID = (
    "https://probityai.github.io/agent-evidence-vectors/predicate/v1/refusal-reason-priority"
)
CONFORMANT, NONCONFORMANT, AMBIGUOUS = "conformant", "nonconformant", "ambiguous"
CONFORMANT_REASON = "response_follows_source"
EXIT_FOR = {CONFORMANT: 0, NONCONFORMANT: 1, AMBIGUOUS: 2}
#: The closed set of section 8.1, in the order of the draft's list.
FIVE = (
    "evidence_binding_mismatch",
    "evidence_expired",
    "authority_not_determined",
    "authority_revoked",
    "operation_not_permitted",
)
#: A permit at the lease instant or an expired refusal: the two licensed readings.
LEASE_READINGS: frozenset[str | None] = frozenset({None, "evidence_expired"})
NO_REASON: frozenset[str | None] = frozenset({None})
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "reason_member_absent",
    "reason_outside_closed_set",
    "answer_outside_both_boundary_readings",
    "refusal_without_condition",
    "condition_ignored",
    "later_value_emitted",
    "observation_backfilled",
    "evidence_renewed_by_diagnostic_read",
)
OPEN_QUESTIONS = ("boundary_undeclared", "declaration_contradicts_use")
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-refusal-reason-priority"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-refusal-reason-priority"
)

Record = dict[str, Any]


def applicable(facts: dict[str, Any]) -> list[str]:
    """The values of the closed set whose condition applies, in the draft's list order."""
    found = []
    if facts.get("bindingMismatch"):
        found.append("evidence_binding_mismatch")
    if facts.get("evidenceExpired"):
        found.append("evidence_expired")
    if facts.get("authority") in ("unreachable", "staleObservation"):
        found.append("authority_not_determined")
    if facts.get("authority") == "revoked":
        found.append("authority_revoked")
    if facts.get("operationPermitted") is False:
        found.append("operation_not_permitted")
    return found


def lease_only(facts: dict[str, Any]) -> bool:
    """A record at the lease instant whose only open question is the boundary."""
    return facts.get("leaseInstant") is not None and not applicable(facts)


def owed_values(facts: dict[str, Any]) -> frozenset[str | None]:
    """The values the draft licenses as the reason: the first applicable one, or none."""
    if lease_only(facts):
        return LEASE_READINGS
    found = applicable(facts)
    return frozenset({found[0]}) if found else NO_REASON


def _emitted(record: Record) -> str | None:
    reason = record["response"].get("reason")
    return None if reason is None else str(reason)


def _relied_fresh(facts: dict[str, Any]) -> bool:
    relied = facts.get("reliedOnObservation")
    return bool(relied is not None and relied.get("present") and relied.get("fresh"))


def _backfilled(record: Record) -> bool:
    facts = record["facts"]
    if facts.get("reliedOnObservation") is None or _relied_fresh(facts):
        return False
    return record["response"]["grantRef"].get("observationAsOfMs") is not None


def _renewed(record: Record) -> bool:
    facts = record["facts"]
    if facts.get("diagnosticRead") is None or _relied_fresh(facts):
        return False
    expires = record["response"]["grantRef"].get("expiresAtMs")
    return bool(expires is not None and expires > facts["grantExpiresAtMs"])


def _derived_boundary(lease: dict[str, Any]) -> str | None:
    """The reason a declared boundary owes at the lease instant, or None for a permit."""
    return None if lease.get("declaredBoundary") == "inclusive" else "evidence_expired"


def _open_question(record: Record) -> str | None:
    """The question section 6.1 leaves open for this record, or None."""
    facts = record["facts"]
    lease = facts.get("leaseInstant")
    if lease is None or applicable(facts):
        return None
    if lease.get("declaredBoundary") is None:
        return "boundary_undeclared"
    if _emitted(record) != _derived_boundary(lease):
        return "declaration_contradicts_use"
    return None


def retained(record: Record) -> dict[str, Any]:
    """The reason emitted and the values the draft licenses, as a verifier keeps them."""
    response = record["response"]
    emitted = "absent" if "reason" not in response else str(response["reason"])
    owed = sorted("null" if value is None else value for value in owed_values(record["facts"]))
    return {"emitted": emitted, "owed": "|".join(owed)}


def _first_failure(record: Record, skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    """
    response, facts = record["response"], record["facts"]

    def emitted() -> str | None:
        return _emitted(record)

    def wrong_value() -> bool:
        return not lease_only(facts) and emitted() not in owed_values(facts)

    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "reason_member_absent": lambda: "reason" not in response,
        "reason_outside_closed_set": lambda: (
            response.get("reason") is not None and response.get("reason") not in FIVE
        ),
        "answer_outside_both_boundary_readings": lambda: (
            lease_only(facts) and emitted() not in LEASE_READINGS
        ),
        "refusal_without_condition": lambda: (
            wrong_value() and owed_values(facts) == NO_REASON and emitted() is not None
        ),
        "condition_ignored": lambda: wrong_value() and emitted() is None,
        "later_value_emitted": lambda: (
            wrong_value() and emitted() is not None and owed_values(facts) != NO_REASON
        ),
        "observation_backfilled": lambda: _backfilled(record),
        "evidence_renewed_by_diagnostic_read": lambda: _renewed(record),
    }
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name
    return None


def _load(record_path: Path) -> Record:
    loaded: Record = json.loads(record_path.read_text(encoding="utf-8"))
    return loaded


def judge(record: Record, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one parsed record."""
    failure = _first_failure(record, skip)
    if failure is not None:
        return {"decision": NONCONFORMANT, "reason": failure}
    question = _open_question(record)
    if question is not None:
        return {"decision": AMBIGUOUS, "reason": question}
    return {"decision": CONFORMANT, "reason": CONFORMANT_REASON}


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
        answer = json.loads(result.stdout)
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
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
