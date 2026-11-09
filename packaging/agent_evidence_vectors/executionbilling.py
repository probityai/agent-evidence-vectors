"""Judge one attempt's execution outcome against its billing finality.

An execution result and a final bill answer different questions. A call can
succeed and leave its bill open, so the money held for it stays held. A final
invoice, including one for zero, settles the bill and says nothing about
whether the call ran or what it did. And a settled bill is never permission to
dispatch the same attempt again.

Every record is one runtime's observation of one scenario against its spend
ledger: the scenario it was given (the account budget, the steps, and the
probes run in a fresh process after a reopen), and the attempt's state after
the initial reservation, after every step, after the steps, after the reopen,
after every probe and after a final reopen, with the claims the observation
declines to make. Each state carries the two axes and the dispatch state side
by side: ``executionOutcome``, ``billingFinality``, ``dispatchState``, the
known spend, the amount still held, the amount available for a new admission,
and whether liability is unbounded or the account frozen. Money is a
nonnegative integer in micro-USD; a boolean or a float is not money.

The reader checks in a fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the execution-billing-finality contract
   (``contract_id_unknown``);
3. the scenario, every state and every action have their shape, every amount
   is an integer and every flag a boolean (``record_malformed``);
4. every state carries ``dispatchState``, one of ``RESERVED``, ``POSSIBLE``
   and ``NOT_DISPATCHED`` (``dispatch_state_missing``);
5. ``externalEffect`` is ``NOT_EVALUATED`` and every claim boundary is
   declared (``claim_boundary_dropped``);
6. the state read after each reopen is the state written before it
   (``reopen_changed_state``);
7. an execution outcome other than ``UNKNOWN`` follows an accepted
   observation of that outcome, or a non-dispatch proof for
   ``NOT_DISPATCHED``; an invoice never settles it
   (``execution_outcome_without_observation``);
8. while billing is not final, the reservation less the known spend is still
   held, whatever the execution outcome
   (``held_released_before_final_billing``);
9. a dispatch is allowed only from a reserved attempt whose billing is unknown
   (``same_attempt_redispatched``);
10. once billing is final or in conflict, the dispatch state is no longer
    ``RESERVED``: an invoice that arrives before any recorded dispatch leaves
    the attempt ``POSSIBLE``, conservative bookkeeping that is not proof a
    dispatch happened (``dispatch_state_reserved_after_billing``);
11. a replay of an accepted invoice event is not new and does not finalize
    again (``invoice_replay_refinalized``).

A record that passes all eleven is ``allow`` with reason ``finality_held``.
A pass establishes no external effect, no invoice authenticity, no durability
beyond a normal reopen and no exactly-once behaviour across attempts.

The external-verifier contract: ``<verifier> <case-dir>/record.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``allow`` and 1 for ``deny``. The runtime contract, which drives a runtime's
ledger through the scenarios, is in ``executionbilling_runtime``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

SUITE = "execution-billing-finality/v1"
CONTRACT_ID = (
    "https://probityai.github.io/agent-evidence-vectors/predicate/v1/execution-billing-finality"
)
ALLOW, DENY = "allow", "deny"
ALLOWED_REASON = "finality_held"
EXIT_FOR = {ALLOW: 0, DENY: 1}
EXECUTION = ("UNKNOWN", "SUCCEEDED", "FAILED", "NOT_DISPATCHED")
BILLING = ("UNKNOWN", "FINAL", "CONFLICT")
DISPATCH = ("RESERVED", "POSSIBLE", "NOT_DISPATCHED")
MONEY = ("availableMicroUsd", "heldMicroUsd", "knownSpendMicroUsd")
FLAGS = ("frozen", "unbounded")
STATE_KEYS = frozenset({*MONEY, *FLAGS, "billingFinality", "executionOutcome", "dispatchState"})
RETURN_KEYS = frozenset({"dispatchAllowed", "newEvent", "newlyFinalized", "newlyReserved",
                         "stateChanged"})
EXCEPTIONS = ("AdmissionDenied", "ConfigurationConflict", "EvidenceConflict",
              "EvidenceValidationError", "UnknownAttempt")
COMMANDS = ("cost", "dispatch", "invoice", "non_dispatch", "outcome", "reserve", "unknown")
BOUNDARIES = ("external_effect_established", "invoice_authenticity", "production_durability",
              "upstream_acceptance")
STATES = ("initial", "observed", "reopened", "end", "endReopened")
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "record_malformed",
    "dispatch_state_missing",
    "claim_boundary_dropped",
    "reopen_changed_state",
    "execution_outcome_without_observation",
    "held_released_before_final_billing",
    "same_attempt_redispatched",
    "dispatch_state_reserved_after_billing",
    "invoice_replay_refinalized",
)
_HERE = Path(__file__).resolve().parent
_NAME = "vectors-execution-billing-finality"
ROOT = (_HERE / "corpora" / _NAME if (_HERE / "corpora").exists()
        else _HERE.parents[1] / "corpora" / _NAME)

Record = dict[str, Any]
State = dict[str, Any]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _is_money(value: object) -> bool:
    return type(value) is int and value >= 0


def _state_shape_ok(state: object) -> bool:
    """Every key but dispatchState present with its exact type; check 4 reads dispatchState."""
    if not isinstance(state, dict) or not set(state) <= STATE_KEYS:
        return False
    return (all(_is_money(state.get(key)) for key in MONEY)
            and all(type(state.get(key)) is bool for key in FLAGS)
            and state.get("executionOutcome") in EXECUTION
            and state.get("billingFinality") in BILLING)


def _step_ok(step: object) -> bool:
    return (isinstance(step, dict) and step.get("cmd") in COMMANDS
            and not set(step) & {"expected", "expect_return", "raises"})


def _action_ok(action: object) -> bool:
    if not isinstance(action, dict) or set(action) != {"exception", "return", "state"}:
        return False
    returned = action["return"]
    return ((action["exception"] is None or action["exception"] in EXCEPTIONS)
            and isinstance(returned, dict) and set(returned) <= RETURN_KEYS
            and all(type(value) is bool for value in returned.values())
            and _state_shape_ok(action["state"]))


def _scenario_ok(record: Record) -> bool:
    scenario = record.get("scenario")
    if not isinstance(scenario, dict) or set(scenario) != {"budget", "id", "probes", "steps"}:
        return False
    return (_is_money(scenario["budget"]) and isinstance(scenario["id"], str)
            and all(isinstance(scenario[key], list) and all(_step_ok(s) for s in scenario[key])
                    for key in ("probes", "steps")))


def malformed(record: object) -> bool:
    """Whether the record lacks the shape every later check reads."""
    if not isinstance(record, dict) or not _scenario_ok(record):
        return True
    scenario = record["scenario"]
    for key in ("steps", "probes"):
        items = record.get(key)
        if (not isinstance(items, list) or len(items) != len(scenario[key])
                or not all(_action_ok(a) for a in items)):
            return True
    return not all(_state_shape_ok(record.get(key)) for key in STATES)


def states(record: Record) -> Iterator[State]:
    """Every state the record carries, in the order the run produced them."""
    yield record["initial"]
    yield from (action["state"] for action in record["steps"])
    yield record["observed"]
    yield record["reopened"]
    yield from (action["state"] for action in record["probes"])
    yield record["end"]
    yield record["endReopened"]


def actions(record: Record) -> Iterator[tuple[dict[str, Any], dict[str, Any], State]]:
    """Each action with the scenario step it ran and the state it started from."""
    before = record["initial"]
    for step, action in zip(record["scenario"]["steps"], record["steps"], strict=True):
        yield step, action, before
        before = action["state"]
    before = record["reopened"]
    for step, action in zip(record["scenario"]["probes"], record["probes"], strict=True):
        yield step, action, before
        before = action["state"]


def _dispatch_state_missing(record: Record) -> bool:
    return any(state.get("dispatchState") not in DISPATCH for state in states(record))


def _boundary_dropped(record: Record) -> bool:
    claims = record.get("mustNotClaim")
    return (record.get("externalEffect") != "NOT_EVALUATED" or not isinstance(claims, list)
            or len(claims) != len({json.dumps(c) for c in claims})
            or set(map(json.dumps, claims)) != set(map(json.dumps, BOUNDARIES)))


def _reopen_changed(record: Record) -> bool:
    return record["reopened"] != record["observed"] or record["endReopened"] != record["end"]


def _outcome_unobserved(record: Record) -> bool:
    if record["initial"]["executionOutcome"] != "UNKNOWN":
        return True
    observed = {"UNKNOWN"}
    for step, action, _ in actions(record):
        if action["exception"] is None and step["cmd"] == "outcome":
            observed.add(str(step.get("value")))
        if action["exception"] is None and step["cmd"] == "non_dispatch":
            observed.add("NOT_DISPATCHED")
        if action["state"]["executionOutcome"] not in observed:
            return True
    return any(state["executionOutcome"] not in observed for state in states(record))


def _held_released(record: Record) -> bool:
    reserved = record["initial"]["heldMicroUsd"]
    return any(state["billingFinality"] == "UNKNOWN"
               and state["heldMicroUsd"] != max(0, reserved - state["knownSpendMicroUsd"])
               for state in states(record))


def _redispatched(record: Record) -> bool:
    return any(step["cmd"] == "dispatch" and step.get("attempt", "A") == "A"
               and action["return"].get("dispatchAllowed") is True
               and (before["dispatchState"] != "RESERVED" or before["billingFinality"] != "UNKNOWN")
               for step, action, before in actions(record))


def _reserved_after_billing(record: Record) -> bool:
    return any(state["billingFinality"] != "UNKNOWN" and state["dispatchState"] == "RESERVED"
               for state in states(record))


def _replay_refinalized(record: Record) -> bool:
    accepted: set[str] = set()
    for step, action, _ in actions(record):
        if step["cmd"] != "invoice" or "event" not in step:
            continue
        event = json.dumps([step["event"], step.get("amount")])
        if event in accepted and (action["return"].get("newEvent") is not False
                                  or action["return"].get("newlyFinalized") is not False):
            return True
        if action["exception"] is None:
            accepted.add(event)
    return False


def retained(record: Record) -> dict[str, Any]:
    """The scenario and the two axes with the dispatch state, as the run left them."""
    observed, end = record["observed"], record["end"]
    return {
        "billingFinality": observed["billingFinality"],
        "dispatchState": observed.get("dispatchState"),
        "endDispatchState": end.get("dispatchState"),
        "executionOutcome": observed["executionOutcome"],
        "heldMicroUsd": observed["heldMicroUsd"],
        "knownSpendMicroUsd": observed["knownSpendMicroUsd"],
        "scenario": record["scenario"]["id"],
    }


def _load(record_path: Path) -> Any:
    return json.loads(record_path.read_text(encoding="utf-8"))


def _first_failure(record: Record, skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it. The checks after
    ``record_malformed`` read a well-formed record only.
    """
    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "record_malformed": lambda: malformed(record),
        "dispatch_state_missing": lambda: _dispatch_state_missing(record),
        "claim_boundary_dropped": lambda: _boundary_dropped(record),
        "reopen_changed_state": lambda: _reopen_changed(record),
        "execution_outcome_without_observation": lambda: _outcome_unobserved(record),
        "held_released_before_final_billing": lambda: _held_released(record),
        "same_attempt_redispatched": lambda: _redispatched(record),
        "dispatch_state_reserved_after_billing": lambda: _reserved_after_billing(record),
        "invoice_replay_refinalized": lambda: _replay_refinalized(record),
    }
    for name in CHECKS:
        if failures[name]():
            if name not in skip:
                return name
            if name == "record_malformed":
                return None
    return None


def decide(record: Any, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one parsed record."""
    if not isinstance(record, dict):
        return {"decision": DENY, "reason": "record_malformed"}
    failure = _first_failure(record, skip)
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    return {"decision": ALLOW, "reason": ALLOWED_REASON}


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record file."""
    try:
        record = _load(record_path)
    except (OSError, ValueError):
        return {"decision": DENY, "reason": "record_malformed"}
    return decide(record, skip)


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(_sha((directory / name).read_bytes()) != digest for name, digest in files.items()):
        return "fixture digest mismatch"
    return None


def scenarios(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The runtime scenarios the allowed cases pair with, once each, in first-use order.

    A conforming runtime's ledger leaves every one of them allowed. Two rows that
    name one scenario with different bodies are a corpus error.
    """
    seen: dict[str, dict[str, Any]] = {}
    for entry in entries:
        scenario = (entry.get("runtime") or {}).get("scenario")
        if scenario is None:
            continue
        if seen.setdefault(scenario["id"], scenario) != scenario:
            raise ValueError(f"scenario {scenario['id']} differs between cases")
    return list(seen.values())


def shipped_scenarios(root: Path = ROOT) -> list[dict[str, Any]]:
    """The runtime scenarios of the corpus this package carries."""
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    return scenarios(manifest["vectors"])


def _validated_entries(root: Path) -> tuple[list[dict[str, Any]], str | None]:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    entries = manifest["vectors"]
    if _sha(_json(entries)) != manifest["corpusDigest"]:
        return [], "manifest digest mismatch"
    if manifest.get("suite") != SUITE:
        return [], "unexpected suite"
    if not entries or len({entry["id"] for entry in entries}) != len(entries):
        return [], "empty or duplicate vector identifiers"
    if any(entry.get("path") != f"cases/{entry['id']}" for entry in entries):
        return [], "case path does not match identifier"
    scenarios(entries)
    actual_dirs = {p.name for p in (root / "cases").iterdir() if p.is_dir()}
    if actual_dirs != {entry["id"] for entry in entries}:
        return [], "case directories do not match manifest"
    return entries, None


def _external_answer(command: list[str], path: Path) -> tuple[bool, dict[str, Any] | str]:
    try:
        result = subprocess.run([*command, str(path), "--json"], capture_output=True,
                                text=True, timeout=90, check=False)
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
    verifier: str | list[str] | None = None, root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every record, through the named verifier or the reference reader.

    Returns the number of records answered and every disagreement. A well-formed
    record whose retained fields differ from what its own fields give is a corpus
    error, whichever verifier is under test.
    """
    try:
        entries, manifest_error = _validated_entries(root)
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
        record = _load(record_path)
        if not malformed(record) and retained(record) != entry["retained"]:
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
    directory = Path(root)
    answered, errors = check(verifier, directory)
    try:
        manifest = json.loads((directory / "MANIFEST.json").read_text(encoding="utf-8"))
        total = len(manifest["vectors"])
    except (OSError, ValueError, KeyError, TypeError):
        manifest, total = {}, 0
    for error in errors:
        print(error)
    rail = "reference reader" if verifier is None else shlex.join(verifier)
    print(f"{SUITE}: {rail} answered {answered} of {total} cases, {len(errors)} disagreements")
    if not answered or not total:
        print("no report written: no case was answered")
        return 2
    report = {
        "suite": SUITE, "rail": "own-reader" if verifier is None else "external",
        "verifier": {"command": verifier, "vectorsExecuted": answered, "note": rail_note},
        "corpusDigest": manifest["corpusDigest"],
        "totals": {"vectors": total, "conform": total - len(errors), "fail": len(errors),
                   "suiteRefusals": 0},
        "failures": errors,
    }
    Path(report_path).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                                 encoding="utf-8")
    return 1 if errors or answered != total else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or SUITE).splitlines()[0])
    parser.add_argument("record", nargs="?",
                        help="judge one record.json with the reference reader")
    parser.add_argument("--json", action="store_true", help="print the decision as JSON")
    parser.add_argument("--verifier", help="run every record through this verifier instead")
    args = parser.parse_args(argv)
    if args.record:
        answer = verify(Path(args.record))
        print(json.dumps(answer, sort_keys=True) if args.json else
              f"{answer['decision']} {answer['reason']}")
        return EXIT_FOR[answer["decision"]]
    answered, errors = check(args.verifier)
    for error in errors:
        print(error)
    total = len(json.loads((ROOT / "MANIFEST.json").read_text(encoding="utf-8"))["vectors"])
    print(f"answered {answered} of {total} cases")
    return 1 if errors or answered != total else 0


if __name__ == "__main__":
    raise SystemExit(main())
