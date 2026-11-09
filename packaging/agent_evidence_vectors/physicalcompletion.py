"""Judge what a verifier reported about physical completion against draft-noa-scitt-ai-agent-receipt-01.

The draft separates three claims about one action: pre-execution authorization,
the outcome a controller reported, and physical completion, which it defines as
an identified witness observing the intended effect against a criterion fixed
before execution (Section 2, Section 8.1). A receipt carries none of the last
two. Section 8.1 forbids reading physical completion out of a receipt, Section
8.2 forbids an unqualified "physical completion proven", and Section 8.3 keeps
the four absence results apart and forbids a negative finding about a world the
verifier did not observe. Section 1.5 leaves the physical-observation and
controller-outcome artifacts undefined, so a rule over their contents cannot be
failed under -01.

Every record is one presentation (the receipt, any controller outcome, any
transport acknowledgement, any physical-observation artifact and the verifier's
trust configuration) and the result a verifier reported for the
PHYSICAL_COMPLETION intent. The reader checks the profile's rules in a fixed
order and names the first that fails, which makes the record ``nonconformant``:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the physical-completion contract (``contract_id_unknown``);
3. the result carries a ``physicalCompletion`` member (``result_member_absent``);
4. no result is an unqualified proof: ``PROVEN`` or ``PHYSICAL_COMPLETION_PROVEN``,
   or ``PROVEN_TO_POLICY`` without the trust configuration that made it so
   (``proven_without_policy``);
5. the value is one of the closed set (``result_outside_vocabulary``);
6. ``CONFLICT``, a result the draft does not tokenise, is not presented as the
   profile's vocabulary (``untokenised_result_as_profile_token``);
7. completion is not reported from a receipt when no observation was presented
   (``completion_from_receipt``);
8. completion is not reported from a controller's report when no observation
   was presented (``completion_from_controller_report``);
9. ``NOT_SATISFIED`` is reported only when a presented observation says the
   criterion was not met (``negative_without_observation``);
10. with no observation presented, the result is ``NOT_PROVIDED``
    (``absence_not_reported_as_not_provided``).

A record that passes all ten is then read under the rules this corpus puts
forward for the artifacts Section 1.5 leaves undefined, drawn from the failure
model the draft fixes for them (Section 2, Sections 8.2 to 8.4). Where the
reported result differs from what those rules owe, -01 cannot decide and the
record is ``ambiguous``, with the proposal rule as its reason and both readings
listed. Otherwise it is ``conformant`` with reason ``result_follows_presentation``.

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

SUITE = "physical-completion/v1"
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/physical-completion"
PROFILE = "draft-noa-scitt-ai-agent-receipt-01"
CONFORMANT, NONCONFORMANT, AMBIGUOUS = "conformant", "nonconformant", "ambiguous"
CONFORMANT_REASON = "result_follows_presentation"
EXIT_FOR = {CONFORMANT: 0, NONCONFORMANT: 1, AMBIGUOUS: 2}
#: The four absence results of Section 8.3, which the draft tokenises.
ABSENCE = ("NOT_CLAIMED", "NOT_PROVIDED", "NOT_APPLICABLE", "INDETERMINATE")
#: The results the draft names and does not tokenise, spelled in this corpus's vocabulary.
NAMED = ("PROVEN_TO_POLICY", "NOT_SATISFIED", "CONFLICT")
CLOSED = ABSENCE + NAMED
#: Spellings of the unqualified proof Section 8.2 forbids.
UNQUALIFIED = ("PROVEN", "PHYSICAL_COMPLETION_PROVEN")
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "result_member_absent",
    "proven_without_policy",
    "result_outside_vocabulary",
    "untokenised_result_as_profile_token",
    "completion_from_receipt",
    "completion_from_controller_report",
    "negative_without_observation",
    "absence_not_reported_as_not_provided",
)
#: The proposal rules, in the order the reader applies them; -01 cannot fail any of them.
PROPOSAL = (
    "absence_reported_as_not_claimed",
    "observation_unauthenticated",
    "observation_unbound",
    "witness_unidentified",
    "witness_untrusted",
    "criterion_not_prefixed",
    "observation_outside_window",
    "conflict_erased",
    "conflict_drops_a_claim",
    "observation_outcome_not_reported",
)
BOTH_CLAIMS = frozenset({"controller", "witness"})
_HERE = Path(__file__).resolve().parent
ROOT = (
    _HERE / "corpora" / "vectors-physical-completion"
    if (_HERE / "corpora").exists()
    else _HERE.parents[1] / "corpora" / "vectors-physical-completion"
)

Record = dict[str, Any]


def _reported(record: Record) -> str | None:
    value = record["result"].get("physicalCompletion")
    return None if value is None else str(value)


def _observation(record: Record) -> dict[str, Any] | None:
    observation: dict[str, Any] | None = record["presented"].get("observation")
    return observation


def _controller(record: Record) -> str | None:
    outcome = record["presented"].get("controllerOutcome")
    return None if outcome is None else str(outcome.get("status"))


def _witness_reports_unmet(record: Record) -> bool:
    observation = _observation(record)
    return observation is not None and observation.get("criterionMet") is False


def proposal_owed(record: Record) -> tuple[str, frozenset[str]]:
    """The proposal rule that decides this presentation, and the results it owes.

    The first matching condition decides, in the order of ``PROPOSAL``.
    """
    presented = record["presented"]
    observation = _observation(record)
    if observation is None:
        return "absence_reported_as_not_claimed", frozenset({"NOT_PROVIDED"})
    if not observation.get("authenticated"):
        return "observation_unauthenticated", frozenset({"NOT_PROVIDED"})
    if not observation.get("boundToAction"):
        return "observation_unbound", frozenset({"NOT_PROVIDED"})
    witness = observation.get("witness")
    if not witness:
        return "witness_unidentified", frozenset({"INDETERMINATE"})
    if witness not in presented["trust"]["witnessesTrustedForPurpose"]:
        return "witness_untrusted", frozenset({"INDETERMINATE"})
    dispatched = presented["receipt"]["dispatchedAtMs"]
    if observation["criterionFixedAtMs"] >= dispatched:
        return "criterion_not_prefixed", frozenset({"INDETERMINATE"})
    if not dispatched <= observation["observedAtMs"] <= observation["windowEndMs"]:
        return "observation_outside_window", frozenset({"INDETERMINATE"})
    met = bool(observation.get("criterionMet"))
    controller = _controller(record)
    if controller is not None and (controller == "succeeded") != met:
        return "conflict_erased", frozenset({"CONFLICT"})
    return "observation_outcome_not_reported", frozenset(
        {"PROVEN_TO_POLICY" if met else "NOT_SATISFIED"}
    )


def _proposal_failure(record: Record, skip: frozenset[str]) -> str | None:
    """The proposal rule the reported result breaks, or None."""
    rule, owed = proposal_owed(record)
    reported = _reported(record)
    if rule in skip:
        return None
    if reported not in owed:
        return rule
    if reported == "CONFLICT" and "conflict_drops_a_claim" not in skip:
        sources = {str(claim.get("source")) for claim in record["result"].get("claims", [])}
        if sources != BOTH_CLAIMS:
            return "conflict_drops_a_claim"
    return None


def retained(record: Record) -> dict[str, str]:
    """The result reported and the results the corpus's rules owe, as a verifier keeps them."""
    result = record["result"]
    reported = "absent" if "physicalCompletion" not in result else str(_reported(record))
    _, owed = proposal_owed(record)
    return {"owed": "|".join(sorted(owed)), "reported": reported}


def _first_failure(record: Record, skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    """
    result = record["result"]
    reported = _reported(record)
    observed = _observation(record) is not None
    controller = _controller(record)

    def unqualified() -> bool:
        if reported in UNQUALIFIED:
            return True
        return reported == "PROVEN_TO_POLICY" and not result.get("trustConfiguration")

    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "result_member_absent": lambda: reported is None,
        "proven_without_policy": unqualified,
        "result_outside_vocabulary": lambda: reported not in CLOSED,
        "untokenised_result_as_profile_token": lambda: (
            reported == "CONFLICT" and result.get("vocabulary") == PROFILE
        ),
        "completion_from_receipt": lambda: (
            reported == "PROVEN_TO_POLICY" and not observed and controller is None
        ),
        "completion_from_controller_report": lambda: (
            reported == "PROVEN_TO_POLICY" and not observed and controller is not None
        ),
        "negative_without_observation": lambda: (
            reported == "NOT_SATISFIED" and not _witness_reports_unmet(record)
        ),
        "absence_not_reported_as_not_provided": lambda: (
            not observed and reported not in ("NOT_PROVIDED", "NOT_CLAIMED")
        ),
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
    question = _proposal_failure(record, skip)
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
