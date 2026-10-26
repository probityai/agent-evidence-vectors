"""Judge one exclusive dispatch: a policy check, the fence taken to dispatch, the
effect and the commit of its result.

A policy check that reads shared state and a fence that takes an exclusive hold
on the context can each be correct while the pair is not: if the fence reads the
state itself, nothing shows it acted on the state the check saw, and if the hold
is shorter than the tool, a second dispatch can start while the first is still
running. Every record names the sequence number its check read, the sequence
number its fence appended after, the hold's time to live and renewals, the
effect's start and end, the commit time and the other attempts on the context.
The reader checks in a fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the dispatch-fence contract (``contract_id_unknown``);
3. the fence names the sequence number the check read, and it is that one
   (``fence_not_bound_to_check``);
4. no state event has a sequence number after the check's read and at or
   before the fence's append (``state_changed_between_check_and_fence``);
5. a declared maximum runtime longer than the hold's initial time to live is
   covered by a recorded renewal (``runtime_exceeds_hold``);
6. the effect ended at or before the hold's expiry, which is the latest of the
   initial expiry and every renewal's expiry (``hold_expired_before_effect_ended``);
7. no other proposal was admitted on the context from the fence's acquisition
   to the effect's end (``concurrent_dispatch_admitted``);
8. the commit was at or before the hold's expiry (``commit_after_hold_expired``).

A record that passes all eight is ``allow`` with reason ``exclusive``.

The external-verifier contract: ``<verifier> <case-dir>/record.json --json``
prints one JSON object carrying ``decision`` and ``reason``, and exits 0 for
``allow`` and 1 for ``deny``.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shlex
import subprocess
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

SUITE = "dispatch-fence/v1"
CONTRACT_ID = ("https://probityai.github.io/agent-evidence-observer/contract/"
               "dispatch-fence/v1")
ALLOW, DENY = "allow", "deny"
EXIT_FOR = {ALLOW: 0, DENY: 1}
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "fence_not_bound_to_check",
    "state_changed_between_check_and_fence",
    "runtime_exceeds_hold",
    "hold_expired_before_effect_ended",
    "concurrent_dispatch_admitted",
    "commit_after_hold_expired",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-dispatch-fence" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "vectors-dispatch-fence")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _when(value: Any) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def hold_expiry(record: dict[str, Any]) -> datetime:
    """The latest of the initial expiry and every renewal's expiry."""
    fence = record["fence"]
    initial = _when(fence["acquiredAt"]) + timedelta(seconds=fence["ttlSeconds"])
    return max([initial, *(_when(item["expiresAt"]) for item in fence.get("renewals", []))])


def hold_covers_commit(record: dict[str, Any]) -> bool:
    """Whether the hold lasted through both the effect and the commit."""
    expiry = hold_expiry(record)
    return bool(_when(record["effect"]["endedAt"]) <= expiry
                and _when(record["commit"]["at"]) <= expiry)


def _not_bound(record: dict[str, Any]) -> bool:
    expected = record["fence"].get("expectedSeq")
    return expected is None or bool(expected != record["check"]["readSeq"])


def _state_changed(record: dict[str, Any]) -> bool:
    read, append = record["check"]["readSeq"], record["fence"]["appendSeq"]
    return any(read < event["seq"] <= append for event in record["stateEvents"])


def _runtime_exceeds(record: dict[str, Any]) -> bool:
    declared = record["effect"].get("declaredMaxRuntimeSeconds")
    fence = record["fence"]
    return bool(declared is not None and declared > fence["ttlSeconds"]
                and not fence.get("renewals"))


def _concurrent(record: dict[str, Any]) -> bool:
    start, end = _when(record["fence"]["acquiredAt"]), _when(record["effect"]["endedAt"])
    return any(attempt["admitted"] and attempt["proposalId"] != record["proposalId"]
               and start <= _when(attempt["beganAt"]) <= end
               for attempt in record["otherAttempts"])


def _load(record_path: Path) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads(record_path.read_text(encoding="utf-8"))
    return loaded


def _first_failure(record: dict[str, Any], skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    """
    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "fence_not_bound_to_check": lambda: _not_bound(record),
        "state_changed_between_check_and_fence": lambda: _state_changed(record),
        "runtime_exceeds_hold": lambda: _runtime_exceeds(record),
        "hold_expired_before_effect_ended": lambda: (
            _when(record["effect"]["endedAt"]) > hold_expiry(record)),
        "concurrent_dispatch_admitted": lambda: _concurrent(record),
        "commit_after_hold_expired": lambda: _when(record["commit"]["at"]) > hold_expiry(record),
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
    return {"decision": ALLOW, "reason": "exclusive"}


def _fixture_error(directory: Path, entry: dict[str, Any]) -> str | None:
    files = entry["files"]
    actual = {path.name for path in directory.iterdir() if path.is_file()}
    if actual != set(files):
        return "file set changed"
    if any(_sha((directory / name).read_bytes()) != digest for name, digest in files.items()):
        return "fixture digest mismatch"
    return None


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
    whose declared hold property does not hold is a corpus error, whichever
    verifier is under test.
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
        if hold_covers_commit(_load(record_path)) != entry["holdCoversCommit"]:
            errors.append(f"{name}: declared hold property does not hold")
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
