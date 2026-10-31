"""Judge whether an approval is bound to the exact use it is presented for.

An approval that is valid on its own can still be the wrong approval for a use.
It can share its identifier with a different approval, so a lookup by
identifier returns the wrong one. It can have been consumed already. It can be
signed under a key that is not the approver's. It can belong to a different
user who reached the server through the same OAuth client. It can cover a
different event, phase, tool, target or payload, including a payload changed
after the approval was given. Or the policy release that judged it may not have
been served at the time it was judged. Every denied record below carries an
approval that a verifier checking only the signature and expiry would accept.

The reader checks in a fixed order and names the first check that fails:

1. the record carries ``contractId`` (``contract_id_missing``);
2. ``contractId`` is the approval-binding contract (``contract_id_unknown``);
3. the use's ``approvalId`` is the identifier of the approval being checked; a
   use that names another approval, or none, is not judged against this one
   (``approval_not_cited``);
4. no other presented approval shares the approval's identifier with different
   content (``approval_id_ambiguous``);
5. the identifier is not among the consumed ones (``approval_replayed``);
6. no replacement accepted at or before the use has taken the approval's place
   (``approval_superseded``);
7. a use that claims ``authorityForm: renewed`` has a transition accepted at or
   before the use naming this approval as successor; a transition accepted
   later does not establish the renewal (``renewal_transition_missing``);
8. that transition binds the successor to exactly one predecessor
   (``renewal_binding_invalid``);
9. the approval's ``keyId`` is the trusted key of its approver
   (``key_not_bound``);
10. the use's principal is the approval's principal; a shared ``clientId`` does
    not stand in for the user (``principal_mismatch``);
11. the use's event and phase are the approved ones (``event_phase_mismatch``);
12. the used tool, target and payload bytes are the approved ones
    (``payload_mismatch``);
13. ``usedAt`` is at or after ``issuedAt`` and before ``expiresAt``
    (``approval_outside_validity``);
14. the effect the use names is not closed (``effect_already_closed``);
15. the policy release lookup answered (``comparison_unavailable``); an
    unanswered lookup is never read as a match;
16. the release was served at the decision time: first served at or before it,
    and last served at or after it minus the grace period
    (``release_not_served_at_decision``).

A record that passes all of them is ``allow`` with reason ``bound``.

Renewal by replacement is judged by checks 6, 7, 8 and 14. An approval B can
replace an earlier approval A over equal bounds. Equal bounds, the same
recorded decision and the same logical effect are three different identities,
so the record carries each one apart:

* every approval may carry a ``decisionId``, the recorded decision that
  authorised it;
* ``transitions`` lists the replacements the issuer recorded. An accepted
  ``exclusive-replacement`` names the predecessor approval and decision and the
  successor approval and decision, and takes effect at ``acceptedAt``;
* the use may claim ``authorityForm: renewed``. That is a claim about a
  transition and is never evidence that one was accepted;
* the use may name an ``effectKey``, and ``effectRegistry`` states that
  effect's lifecycle state. ``CONSUMED`` and ``UNCERTAIN_CLOSE`` are closed, so
  a new grant does not reopen them.

Check 6 refuses the predecessor because it was superseded, not because it
expired or was consumed, and it needs no execution under the successor. Checks 6
and 7 read a transition at the same instant: it counts from ``acceptedAt`` on,
for the predecessor it replaces and for the successor it establishes. Check 8
requires the presented records under the predecessor's identifier to agree, so
the predecessor resolves to one approval whatever the order of the list, the
transition to cite that predecessor's recorded decision, the successor's
decision to be distinct from it, and the predecessor and successor to hold equal
``BOUND_FIELDS``.

``comparison_unavailable`` is a deny, not an indeterminate outcome: the record
itself states that the lookup failed, so the specification is not silent about
the input, and a verifier that allows on a failed lookup has turned "not
checked" into "matched".

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

SUITE = "approval-binding/v1"
CONTRACT_ID = "https://probityai.github.io/agent-evidence-vectors/contract/approval-binding/v1"
ALLOW, DENY = "allow", "deny"
EXIT_FOR = {ALLOW: 0, DENY: 1}
# The order is the contract: a reader names the first check that fails.
CHECKS = (
    "contract_id_missing",
    "contract_id_unknown",
    "approval_not_cited",
    "approval_id_ambiguous",
    "approval_replayed",
    "approval_superseded",
    "renewal_transition_missing",
    "renewal_binding_invalid",
    "key_not_bound",
    "principal_mismatch",
    "event_phase_mismatch",
    "payload_mismatch",
    "approval_outside_validity",
    "effect_already_closed",
    "comparison_unavailable",
    "release_not_served_at_decision",
)
# The fields a renewal holds equal. Validity limits are not among them: a
# renewal is a fresh grant, so its own window is its own.
BOUND_FIELDS = ("event", "payloadSha256", "phase", "principal", "target", "tool")
REPLACEMENT = "exclusive-replacement"
CLOSED_EFFECT_STATES = ("CONSUMED", "UNCERTAIN_CLOSE")
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-approval-binding" if
        (_HERE / "corpora").exists() else _HERE.parents[1] / "vectors-approval-binding")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _when(value: Any) -> datetime:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00"))


def _ambiguous(record: dict[str, Any]) -> bool:
    approval = record["approval"]
    return any(other["approvalId"] == approval["approvalId"] and other != approval
               for other in record.get("presentedApprovals", []))


def _validity(record: dict[str, Any]) -> bool:
    approval, used = record["approval"], _when(record["use"]["usedAt"])
    return _when(approval["issuedAt"]) <= used < _when(approval["expiresAt"])


def _superseded(record: dict[str, Any]) -> bool:
    """Whether an accepted replacement had already taken this approval's place at the use."""
    approval, used = record["approval"], _when(record["use"]["usedAt"])
    return any(t["status"] == "accepted" and t["predecessorApprovalId"] == approval["approvalId"]
               and _when(t["acceptedAt"]) <= used for t in record.get("transitions", []))


def _accepted_into(record: dict[str, Any]) -> list[dict[str, Any]]:
    """The transitions into this approval that had been accepted by the use."""
    approval, used = record["approval"], _when(record["use"]["usedAt"])
    return [t for t in record.get("transitions", [])
            if t["status"] == "accepted" and t["successorApprovalId"] == approval["approvalId"]
            and _when(t["acceptedAt"]) <= used]


def _renewal_missing(record: dict[str, Any]) -> bool:
    return record["use"].get("authorityForm") == "renewed" and not _accepted_into(record)


def _renewal_invalid(record: dict[str, Any]) -> bool:
    """Whether the accepted transition into this approval fails to bind it to its predecessor."""
    if record["use"].get("authorityForm") != "renewed":
        return False
    approval, accepted = record["approval"], _accepted_into(record)
    return bool(accepted) and not any(_binds(record, approval, t) for t in accepted)


def _binds(record: dict[str, Any], approval: dict[str, Any], transition: dict[str, Any]) -> bool:
    # Identical copies are one predecessor; differing records under one
    # identifier are none, so the list order never picks between them.
    candidates: list[dict[str, Any]] = []
    for presented in record.get("presentedApprovals", []):
        if presented["approvalId"] == transition["predecessorApprovalId"] and (
                presented not in candidates):
            candidates.append(presented)
    if len(candidates) != 1 or transition["mode"] != REPLACEMENT:
        return False
    predecessor = candidates[0]
    decision = approval.get("decisionId")
    return bool(
        decision is not None and transition["successorDecisionId"] == decision
        and transition["predecessorDecisionId"] == predecessor.get("decisionId")
        and decision != predecessor.get("decisionId")
        and all(predecessor.get(f) == approval.get(f) for f in BOUND_FIELDS))


def _effect_closed(record: dict[str, Any]) -> bool:
    key = record["use"].get("effectKey")
    return key is not None and record.get("effectRegistry", {}).get(key) in CLOSED_EFFECT_STATES


def _served(record: dict[str, Any]) -> bool:
    release, decided = record["policyRelease"], _when(record["decisionTime"])
    grace = timedelta(seconds=release["graceSeconds"])
    return _when(release["firstServedAt"]) <= decided <= _when(release["lastServedAt"]) + grace


def use_matches_approval(record: dict[str, Any], used: bytes) -> bool:
    """Whether the used tool, target and payload bytes are exactly the approved ones."""
    approval, use = record["approval"], record["use"]
    return bool(use["tool"] == approval["tool"] and use["target"] == approval["target"]
                and _sha(used) == approval["payloadSha256"])


def _load(record_path: Path) -> tuple[dict[str, Any], bytes]:
    record = json.loads(record_path.read_text(encoding="utf-8"))
    used = (record_path.parent / record["use"]["payloadFile"]).read_bytes()
    return record, used


def _first_failure(record: dict[str, Any], used: bytes, skip: frozenset[str]) -> str | None:
    """Name the first check in ``CHECKS`` the record fails, or None.

    ``skip`` switches named checks off so the corpus's own tests can prove each
    check is forced by some member; a verifier never sets it.
    """
    approval, use = record["approval"], record["use"]
    failures: dict[str, Callable[[], bool]] = {
        "contract_id_missing": lambda: "contractId" not in record,
        "contract_id_unknown": lambda: record.get("contractId", CONTRACT_ID) != CONTRACT_ID,
        "approval_not_cited": lambda: use.get("approvalId") != approval["approvalId"],
        "approval_id_ambiguous": lambda: _ambiguous(record),
        "approval_replayed": lambda: approval["approvalId"] in record.get(
            "consumedApprovalIds", []),
        "approval_superseded": lambda: _superseded(record),
        "renewal_transition_missing": lambda: _renewal_missing(record),
        "renewal_binding_invalid": lambda: _renewal_invalid(record),
        "key_not_bound": lambda: record["trustedKeys"].get(approval["approver"]) != approval[
            "keyId"],
        "principal_mismatch": lambda: use["principal"] != approval["principal"],
        "event_phase_mismatch": lambda: (use["event"], use["phase"]) != (
            approval["event"], approval["phase"]),
        "payload_mismatch": lambda: not use_matches_approval(record, used),
        "approval_outside_validity": lambda: not _validity(record),
        "effect_already_closed": lambda: _effect_closed(record),
        "comparison_unavailable": lambda: record["policyRelease"]["lookup"] != "ok",
        "release_not_served_at_decision": lambda: not _served(record),
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
    return {"decision": ALLOW, "reason": "bound"}


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
    whose declared payload property does not hold is a corpus error, whichever
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
        if use_matches_approval(*_load(record_path)) != entry["useMatchesApproval"]:
            errors.append(f"{name}: declared payload property does not hold")
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
