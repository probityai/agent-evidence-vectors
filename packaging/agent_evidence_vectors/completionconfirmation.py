"""Judge whether a task reported complete has a confirmation bound to it.

An operation the enforcement point allowed is not thereby a completed one. The
agent that ran it can report it complete with nothing behind the report: no
confirmation record at all, a record for a different task or resource, a record
the acting agent wrote about itself, a record from before the operation was
authorized, one already used for another task, or a record whose own outcome is
unresolved or says the effect is absent. A verifier that accepts the claim on
the authorization decision and the agent's report alone accepts every one of
these.

The record holds the task, the authorization decision, the claim and the
confirmation (or ``null``). A claim that is not ``complete`` asserts nothing to
confirm: an outcome recorded as unresolved or failed is accepted as that and
establishes neither success nor absence of effect.

The reader checks in a fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the completion-confirmation contract
   (``contract_id_unknown``);
3. the record has the fields and types the contract names, and every time
   parses (``malformed_record``);
4. the claim's status is not ``complete``: ``allow``, reason
   ``no_completion_claimed``;
5. a confirmation is present (``completion_unconfirmed``);
6. the confirmation names the task's identifier, the authorization's
   identifier, and the task's operation, resource and argument digest
   (``confirmation_not_bound``);
7. the confirmation was written by an observer that is not the claiming agent,
   under that observer's trusted key (``confirmation_self_reported``);
8. the confirmation's identifier is not among the consumed ones
   (``confirmation_reused``);
9. the confirmation was observed at or after the authorization decision and at
   or before the decision time (``confirmation_outside_window``);
10. the confirmed outcome is not ``unresolved`` (``outcome_unresolved``);
11. the confirmed outcome is not ``absent``, the resource's statement that the
    effect did not happen (``outcome_contradicts_claim``).

A record that passes all eleven is ``allow`` with reason ``confirmed``.

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
from datetime import datetime
from pathlib import Path
from typing import Any

SUITE = "completion-confirmation/v1"
CONTRACT_ID = ("https://probityai.github.io/agent-evidence-vectors/contract/"
               "completion-confirmation/v1")
ALLOW, DENY = "allow", "deny"
EXIT_FOR = {ALLOW: 0, DENY: 1}
OUTCOMES = ("committed", "unresolved", "absent")
STATUSES = ("complete", "unresolved", "failed")
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "malformed_record",
    "no_completion_claimed",
    "completion_unconfirmed",
    "confirmation_not_bound",
    "confirmation_self_reported",
    "confirmation_reused",
    "confirmation_outside_window",
    "outcome_unresolved",
    "outcome_contradicts_claim",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-completion-confirmation" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "vectors-completion-confirmation")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _when(value: Any) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _texts(value: Any, names: tuple[str, ...]) -> bool:
    return isinstance(value, dict) and all(isinstance(value.get(n), str) for n in names)


def _confirmation_malformed(confirmation: Any) -> bool:
    names = ("confirmationId", "authorizationId", "taskId", "operation", "resource",
             "argsSha256", "observedBy", "keyId", "observedAt", "outcome")
    return confirmation is not None and (
        not _texts(confirmation, names) or confirmation["outcome"] not in OUTCOMES)


def _malformed(record: dict[str, Any]) -> bool:
    shape = (
        isinstance(record.get("decisionTime"), str)
        and _texts(record.get("task"), ("taskId", "operation", "resource", "argsSha256"))
        and _texts(record.get("authorization"), ("authorizationId", "taskId", "decidedAt"))
        and _texts(record.get("claim"), ("status", "claimedBy", "claimedAt"))
        and isinstance(record.get("trustedObservers"), dict)
        and isinstance(record.get("consumedConfirmationIds"), list)
        and "confirmation" in record
    )
    if not shape or record["claim"]["status"] not in STATUSES:
        return True
    if _confirmation_malformed(record["confirmation"]):
        return True
    times = [record["decisionTime"], record["authorization"]["decidedAt"],
             record["claim"]["claimedAt"]]
    if record["confirmation"] is not None:
        times.append(record["confirmation"]["observedAt"])
    try:
        for value in times:
            _when(value)
    except ValueError:
        return True
    return False


def _bound(record: dict[str, Any]) -> bool:
    task, auth, confirmation = record["task"], record["authorization"], record["confirmation"]
    return bool(
        confirmation["taskId"] == task["taskId"] == auth["taskId"]
        and confirmation["authorizationId"] == auth["authorizationId"]
        and all(confirmation[key] == task[key] for key in ("operation", "resource", "argsSha256")))


def _independent(record: dict[str, Any]) -> bool:
    confirmation = record["confirmation"]
    return bool(confirmation["observedBy"] != record["claim"]["claimedBy"]
                and record["trustedObservers"].get(confirmation["observedBy"])
                == confirmation["keyId"])


def _in_window(record: dict[str, Any]) -> bool:
    observed = _when(record["confirmation"]["observedAt"])
    return _when(record["authorization"]["decidedAt"]) <= observed <= _when(
        record["decisionTime"])


def _load(record_path: Path) -> dict[str, Any]:
    record: dict[str, Any] = json.loads(record_path.read_text(encoding="utf-8"))
    return record


def _first_failure(record: dict[str, Any], skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    ``no_completion_claimed`` is the one check that ends in an allow.
    """
    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "malformed_record": lambda: _malformed(record),
        "no_completion_claimed": lambda: record["claim"]["status"] != "complete",
        "completion_unconfirmed": lambda: record["confirmation"] is None,
        "confirmation_not_bound": lambda: not _bound(record),
        "confirmation_self_reported": lambda: not _independent(record),
        "confirmation_reused": lambda: record["confirmation"]["confirmationId"]
        in record["consumedConfirmationIds"],
        "confirmation_outside_window": lambda: not _in_window(record),
        "outcome_unresolved": lambda: record["confirmation"]["outcome"] == "unresolved",
        "outcome_contradicts_claim": lambda: record["confirmation"]["outcome"] == "absent",
    }
    for name in CHECKS:
        if name in skip:
            continue
        try:
            hit = failures[name]()
        except (KeyError, TypeError, ValueError, AttributeError):
            # A record the structural check would have refused. With that check
            # switched off, the failure is a different one, so the tests see it.
            return "unreadable_record" if "malformed_record" in skip else "malformed_record"
        if hit:
            return name
    return None


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record."""
    failure = _first_failure(_load(record_path), skip)
    if failure == "no_completion_claimed":
        return {"decision": ALLOW, "reason": "no_completion_claimed"}
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    return {"decision": ALLOW, "reason": "confirmed"}


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

    Returns the number of records answered and every disagreement.
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
