"""Judge delegated authority at the moment an agent dispatches an action.

An approval answers whether someone once agreed to an action. It does not answer
whether the authority behind it still held when the action left: a grant can be
revoked or expire between approval and dispatch, the evidence consulted can be
older than the deployment accepts, a later delegation hop can claim more than it
was given, and the bytes dispatched can differ from the bytes approved. Seven of
this corpus's denied records dispatch exactly the approved bytes; only the
authority evidence decides them.

Every record names the contract it is read under in ``contractId`` and states
the age of its authority evidence in ``evidenceAgeSeconds``. The reader checks
in a fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the authority-at-dispatch contract (``contract_id_unknown``);
3. ``evidenceAgeSeconds`` equals the decision time minus the evidence's
   observation time (``evidence_age_inconsistent``);
4. that age does not exceed the declared freshness limit
   (``authority_evidence_stale``);
5. no grant in the delegation chain was revoked at or before the decision
   time (``grant_revoked``);
6. the decision time falls inside every grant's validity window
   (``grant_expired``);
7. each hop's scope is a subset of the hop before it (``scope_amplified``);
8. the dispatched tool, target and bytes are the approved ones, and the tool is
   in the last hop's scope (``dispatch_not_approved``).

A record that passes all eight is ``allow`` with reason ``authorized``.

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

SUITE = "authority-at-dispatch/v1"
CONTRACT_ID = ("https://probityai.github.io/agent-evidence-observer/contract/"
               "authority-at-dispatch/v1")
ALLOW, DENY = "allow", "deny"
EXIT_FOR = {ALLOW: 0, DENY: 1}
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "evidence_age_inconsistent",
    "authority_evidence_stale",
    "grant_revoked",
    "grant_expired",
    "scope_amplified",
    "dispatch_not_approved",
)
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-authority-at-dispatch" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "vectors-authority-at-dispatch")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _when(value: Any) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _age_seconds(record: dict[str, Any]) -> float:
    evidence = record["authorityEvidence"]
    return (_when(record["decisionTime"]) - _when(evidence["observedAt"])).total_seconds()


def _revoked(record: dict[str, Any]) -> bool:
    decided = _when(record["decisionTime"])
    grants = {hop["grantId"] for hop in record["delegation"]}
    return any(entry["grantId"] in grants and _when(entry["revokedAt"]) <= decided
               for entry in record["authorityEvidence"].get("revokedGrants", []))


def _expired(record: dict[str, Any]) -> bool:
    decided = _when(record["decisionTime"])
    return any(not _when(hop["notBefore"]) <= decided < _when(hop["expiresAt"])
               for hop in record["delegation"])


def _amplified(record: dict[str, Any]) -> bool:
    hops = record["delegation"]
    return any(not set(later["scope"]) <= set(earlier["scope"])
               for earlier, later in zip(hops, hops[1:], strict=False))


def dispatch_matches_approval(record: dict[str, Any], dispatched: bytes) -> bool:
    """Whether the dispatched tool, target and bytes are exactly the approved ones."""
    approved, dispatch = record["approvedAction"], record["dispatch"]
    return bool(dispatch["tool"] == approved["tool"] and dispatch["target"] == approved["target"]
                and _sha(dispatched) == approved["payloadSha256"])


def _load(record_path: Path) -> tuple[dict[str, Any], bytes]:
    record = json.loads(record_path.read_text(encoding="utf-8"))
    dispatched = (record_path.parent / record["dispatch"]["payloadFile"]).read_bytes()
    return record, dispatched


def _first_failure(record: dict[str, Any], dispatched: bytes,
                   skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    """
    evidence = record["authorityEvidence"]
    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "evidence_age_inconsistent": lambda: evidence["evidenceAgeSeconds"] != _age_seconds(
            record),
        "authority_evidence_stale": lambda: evidence["evidenceAgeSeconds"] > evidence[
            "maxAgeSeconds"],
        "grant_revoked": lambda: _revoked(record),
        "grant_expired": lambda: _expired(record),
        "scope_amplified": lambda: _amplified(record),
        "dispatch_not_approved": lambda: not (
            dispatch_matches_approval(record, dispatched)
            and record["dispatch"]["tool"] in record["delegation"][-1]["scope"]),
    }
    for name in CHECKS:
        if name not in skip and failures[name]():
            return name
    return None


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one record."""
    failure = _first_failure(*_load(record_path), skip)
    if failure is not None:
        return {"decision": DENY, "reason": failure}
    return {"decision": ALLOW, "reason": "authorized"}


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
    whose declared approval property does not hold is a corpus error, whichever
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
        if dispatch_matches_approval(*_load(record_path)) != entry["dispatchMatchesApproval"]:
            errors.append(f"{name}: declared approval property does not hold")
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
