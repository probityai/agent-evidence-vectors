"""Judge one operation whose effect may have happened after its reply was lost.

A write can commit at the service that owns the effect and still look like a
failure to the caller: the reply is lost, the connection drops, the client
times out, or the worker that sent it is cut off from its lease. The caller
then does not know whether the effect happened, and the safe reading is that
it is UNKNOWN: a retry may repeat it, and capacity reserved for it stays
charged until the effect owner itself says what it holds.

Every record is one runtime's trail for one intended effect: the operation and
its idempotency key, each dispatch attempt with the reply it got, the leases
the dispatching workers held, the effect owner's reconciliation answers, the
effect count the owner's own ledger shows, the reservation held for the
operation, and the outcome the runtime reported. The reader checks in a fixed
order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the uncertain-effect contract (``contract_id_unknown``);
3. the operation and every attempt carry an idempotency key and an arguments
   digest (``operation_identity_missing``);
4. no attempt reuses the operation's idempotency key with other arguments
   (``idempotency_key_args_changed``);
5. every attempt was dispatched inside a lease its worker held, and before a
   lease with a higher fencing token was granted (``dispatch_beyond_lease``);
6. no attempt was dispatched after an attempt of unknown outcome unless the
   owner deduplicates by that same key inside its retention window, or a final
   reconciliation said the effect is absent (``retry_after_unknown``);
7. the owner's ledger shows at most one effect (``duplicate_effect``);
8. a reservation for an operation whose outcome is unknown is still charged,
   also after it expired (``unknown_released``);
9. the runtime did not report an unknown outcome as committed or not run
   (``outcome_settled_without_authority``);
10. the runtime reported the outcome the owner's answers settle
    (``outcome_disagrees_with_authority``).

The outcome the owner's answers settle is ``committed`` when an attempt was
confirmed or a reconciliation found the effect; ``not_run`` when no attempt has
an unknown reply, or a final reconciliation after the last unknown attempt
found it absent; and ``unknown`` otherwise. A reconciliation that is not final
(a lookup that can still miss a late commit) settles nothing. A record that
passes all ten is ``allow`` with reason ``effect_held``.

The external-verifier contract: ``<verifier> <case-dir>/record.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``allow`` and 1 for ``deny``. The runtime contract, which drives a runtime
against a counting effect owner, is in ``uncertaineffect_runtime``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

SUITE = "uncertain-effect/v1"
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/uncertain-effect"
ALLOW, DENY = "allow", "deny"
ALLOWED_REASON = "effect_held"
EXIT_FOR = {ALLOW: 0, DENY: 1}
# A reply that leaves the caller not knowing whether the effect happened.
UNKNOWN_REPLIES = ("timeout", "connection_lost")
REPLIES = ("confirmed", "no_effect", *UNKNOWN_REPLIES)
OUTCOMES = ("committed", "not_run", "unknown")
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "operation_identity_missing",
    "idempotency_key_args_changed",
    "dispatch_beyond_lease",
    "retry_after_unknown",
    "duplicate_effect",
    "unknown_released",
    "outcome_settled_without_authority",
    "outcome_disagrees_with_authority",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-uncertain-effect" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "vectors-uncertain-effect")

Record = dict[str, Any]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _at(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def _attempts(record: Record) -> list[dict[str, Any]]:
    return sorted(record["attempts"], key=lambda item: _at(item["dispatchedAt"]))


def _final_absent_between(record: Record, start: datetime, end: datetime | None) -> bool:
    """Whether a final reconciliation found the effect absent at or after ``start``."""
    return any(item["result"] == "absent" and item["final"] and _at(item["at"]) >= start
               and (end is None or _at(item["at"]) <= end)
               for item in record["reconciliations"])


def settled_outcome(record: Record) -> str:
    """The outcome the effect owner's own answers settle, at ``asOf``."""
    attempts = record["attempts"]
    if (any(item["reply"] == "confirmed" for item in attempts)
            or any(item["result"] == "present" for item in record["reconciliations"])):
        return "committed"
    unknown = [_at(item["dispatchedAt"]) for item in attempts
               if item["reply"] in UNKNOWN_REPLIES]
    if not unknown or _final_absent_between(record, max(unknown), None):
        return "not_run"
    return "unknown"


def retained(record: Record) -> dict[str, Any]:
    """The operation, key, attempt counts, owner effects and settled outcome a verifier keeps."""
    operation = record["operation"]
    return {
        "attempts": len(record["attempts"]),
        "idempotencyKey": str(operation.get("idempotencyKey") or ""),
        "operation": operation["id"],
        "outcome": settled_outcome(record),
        "ownerEffects": record["ownerEffects"],
        "unknownAttempts": sum(1 for item in record["attempts"]
                               if item["reply"] in UNKNOWN_REPLIES),
    }


def _identity_missing(record: Record) -> bool:
    items = [record["operation"], *record["attempts"]]
    return any(not item.get(key) for item in items for key in ("idempotencyKey", "argsDigest"))


def _key_args_changed(record: Record) -> bool:
    operation = record["operation"]
    return any(item.get("idempotencyKey") == operation.get("idempotencyKey")
               and item.get("argsDigest") != operation.get("argsDigest")
               for item in record["attempts"])


def _outside_lease(attempt: dict[str, Any], leases: list[dict[str, Any]]) -> bool:
    held = [lease for lease in leases if lease["worker"] == attempt.get("worker")
            and lease["fencingToken"] == attempt.get("fencingToken")]
    if not held:
        return True
    sent = _at(attempt["dispatchedAt"])
    lease = held[0]
    if not _at(lease["acquiredAt"]) <= sent < _at(lease["expiresAt"]):
        return True
    return any(other["fencingToken"] > lease["fencingToken"] and _at(other["acquiredAt"]) <= sent
               for other in leases)


def _beyond_lease(record: Record) -> bool:
    leases = record.get("leases") or []
    return bool(leases) and any(_outside_lease(item, leases) for item in record["attempts"])


def _protected_retry(record: Record, earlier: dict[str, Any], later: dict[str, Any]) -> bool:
    """Whether ``later`` may follow ``earlier``, whose outcome the caller did not learn."""
    owner = record["effectOwner"]
    sent, resent = _at(earlier["dispatchedAt"]), _at(later["dispatchedAt"])
    retention = owner.get("keyRetentionSeconds")
    deduplicated = (owner["deduplicatesByKey"]
                    and later.get("idempotencyKey") == earlier.get("idempotencyKey")
                    and (retention is None or (resent - sent).total_seconds() <= retention))
    return deduplicated or _final_absent_between(record, sent, resent)


def _unprotected_retry(record: Record) -> bool:
    attempts = _attempts(record)
    return any(not _protected_retry(record, earlier, later)
               for index, earlier in enumerate(attempts) if earlier["reply"] in UNKNOWN_REPLIES
               for later in attempts[index + 1:])


def _unknown_released(record: Record) -> bool:
    reservation = record.get("reservation")
    return (reservation is not None and settled_outcome(record) == "unknown"
            and not reservation["charged"])


def _settled_without_authority(record: Record) -> bool:
    return (settled_outcome(record) == "unknown"
            and record["reported"]["outcome"] in ("committed", "not_run"))


def _disagrees(record: Record) -> bool:
    settled = settled_outcome(record)
    return settled != "unknown" and record["reported"]["outcome"] != settled


def _load(record_path: Path) -> Record:
    loaded: Record = json.loads(record_path.read_text(encoding="utf-8"))
    return loaded


def _first_failure(record: Record, skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    """
    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "operation_identity_missing": lambda: _identity_missing(record),
        "idempotency_key_args_changed": lambda: _key_args_changed(record),
        "dispatch_beyond_lease": lambda: _beyond_lease(record),
        "retry_after_unknown": lambda: _unprotected_retry(record),
        "duplicate_effect": lambda: record["ownerEffects"] > 1,
        "unknown_released": lambda: _unknown_released(record),
        "outcome_settled_without_authority": lambda: _settled_without_authority(record),
        "outcome_disagrees_with_authority": lambda: _disagrees(record),
    }
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name
    return None


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record."""
    failure = _first_failure(_load(record_path), skip)
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    return {"decision": ALLOW, "reason": ALLOWED_REASON}


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(_sha((directory / name).read_bytes()) != digest for name, digest in files.items()):
        return "fixture digest mismatch"
    return None


def scenarios(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The runtime scenarios the cases pair with, once each, in first-use order.

    Each case row carries its scenario whole, so the corpus digest over the rows
    covers what a runtime is driven through. Two rows that name one scenario
    with different bodies are a corpus error.
    """
    seen: dict[str, dict[str, Any]] = {}
    for entry in entries:
        scenario = entry["runtime"]["scenario"]
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

    Returns the number of records answered and every disagreement. A record
    whose retained operation, key, counts or settled outcome differ from what
    its own fields give is a corpus error, whichever verifier is under test.
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
