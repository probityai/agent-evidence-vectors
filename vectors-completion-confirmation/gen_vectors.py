"""Build the completion-confirmation cases byte-identically.

Every case is one record of a task, the authorization decision for it, the
agent's claim about its outcome and the confirmation the claim rests on (or
none), read under the contract at ``contractId``. Each denied case departs from
a conformant record in one place: the confirmation's presence, its binding to
the task, its independence from the acting agent, its identifier, its time, or
its own stated outcome. The public wording the cases follow is in README.md.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "packaging"))

from agent_evidence_vectors import completionconfirmation as reader  # noqa: E402

SUITE = reader.SUITE
DECISION = "2026-10-26T12:00:00Z"
AUTHORIZED = "2026-10-26T11:58:00Z"
ARGS = hashlib.sha256(b'{"queue":"support","title":"Refund 7731"}\n').hexdigest()
OTHER_ARGS = hashlib.sha256(b'{"queue":"support","title":"Refund 7732"}\n').hexdigest()
GATEWAY = "system:resource-gateway"
GATEWAY_KEY = "gateway-key-2026-10"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def confirmation(**changes: Any) -> dict[str, Any]:
    """The confirmation every conformant record carries, with ``changes`` applied."""
    body: dict[str, Any] = {
        "argsSha256": ARGS, "authorizationId": "auth-0042", "confirmationId": "conf-0042",
        "keyId": GATEWAY_KEY, "observedAt": "2026-10-26T11:59:30Z", "observedBy": GATEWAY,
        "operation": "ticket.create", "outcome": "committed", "resource": "queue/support",
        "taskId": "task-0042",
    }
    body.update(changes)
    return body


def record(*, claim: dict[str, Any] | None = None, confirmed: dict[str, Any] | None | bool = True,
           observers: dict[str, str] | None = None, consumed: list[str] | None = None,
           contract: str | None = reader.CONTRACT_ID) -> dict[str, Any]:
    """One record; every argument is a departure from the conformant record.

    ``confirmed`` is True for the conformant confirmation, None for no
    confirmation, or the confirmation to carry.
    """
    body: dict[str, Any] = {
        "authorization": {"authorizationId": "auth-0042", "decidedAt": AUTHORIZED,
                          "taskId": "task-0042"},
        "claim": {"claimedAt": "2026-10-26T11:59:00Z", "claimedBy": "agent:dispatcher",
                  "status": "complete", **(claim or {})},
        "confirmation": confirmation() if confirmed is True else confirmed,
        "consumedConfirmationIds": consumed if consumed is not None else ["conf-0041"],
        "decisionTime": DECISION,
        "task": {"argsSha256": ARGS, "operation": "ticket.create", "resource": "queue/support",
                 "taskId": "task-0042"},
        "trustedObservers": observers if observers is not None else {GATEWAY: GATEWAY_KEY},
    }
    if contract is not None:
        body["contractId"] = contract
    return body


def broken(mutate: Any) -> dict[str, Any]:
    """The conformant record with one structural change applied by ``mutate``."""
    body = copy.deepcopy(record())
    mutate(body)
    return body


Case = tuple[str, dict[str, Any], str, str, str]


def cases() -> list[Case]:
    """Every case: id, record, expected decision and reason, and what it departs from."""
    return [
        ("allow-confirmed", record(), "allow", "confirmed",
         "control: the resource gateway confirmed the committed effect for this task"),
        ("allow-confirmed-at-authorization-instant",
         record(confirmed=confirmation(observedAt=AUTHORIZED)), "allow", "confirmed",
         "control: observed at the instant of the authorization decision"),
        ("allow-confirmed-at-decision-instant",
         record(confirmed=confirmation(observedAt=DECISION)), "allow", "confirmed",
         "control: observed at the instant of the decision"),
        ("allow-other-confirmation-consumed",
         record(consumed=["conf-0041", "conf-0040"]), "allow", "confirmed",
         "control: other confirmation identifiers were consumed for other tasks"),
        ("allow-unresolved-reported-as-unresolved",
         record(claim={"status": "unresolved"}, confirmed=confirmation(outcome="unresolved")),
         "allow", "no_completion_claimed",
         "control: the outcome is reported as unresolved, so no completion is claimed"),
        ("allow-failed-without-confirmation",
         record(claim={"status": "failed"}, confirmed=None), "allow", "no_completion_claimed",
         "control: the task is reported failed and there is nothing to confirm"),
        ("completion-claimed-without-confirmation", record(confirmed=None), "deny",
         "completion_unconfirmed",
         "the task is reported complete and no confirmation record exists"),
        ("confirmation-for-another-task",
         record(confirmed=confirmation(taskId="task-0041")), "deny", "confirmation_not_bound",
         "the confirmation names another task"),
        ("confirmation-for-another-authorization",
         record(confirmed=confirmation(authorizationId="auth-0041")), "deny",
         "confirmation_not_bound", "the confirmation names another authorization decision"),
        ("confirmation-for-another-resource",
         record(confirmed=confirmation(resource="queue/billing")), "deny",
         "confirmation_not_bound", "the confirmation covers a different protected resource"),
        ("confirmation-for-another-operation",
         record(confirmed=confirmation(operation="ticket.delete")), "deny",
         "confirmation_not_bound", "the confirmation covers a different operation"),
        ("confirmation-for-other-arguments",
         record(confirmed=confirmation(argsSha256=OTHER_ARGS)), "deny",
         "confirmation_not_bound", "the confirmation covers different consequential parameters"),
        ("confirmation-written-by-the-acting-agent",
         record(confirmed=confirmation(observedBy="agent:dispatcher", keyId="agent-key-1"),
                observers={GATEWAY: GATEWAY_KEY, "agent:dispatcher": "agent-key-1"}),
         "deny", "confirmation_self_reported",
         "the acting agent confirmed its own work, under a key it holds"),
        ("confirmation-observer-unknown",
         record(confirmed=confirmation(observedBy="system:unlisted")), "deny",
         "confirmation_self_reported", "the observer is not among the trusted observers"),
        ("confirmation-key-not-observers",
         record(confirmed=confirmation(keyId="gateway-key-2026-04")), "deny",
         "confirmation_self_reported",
         "the confirmation names a key other than the observer's trusted key"),
        ("confirmation-already-consumed",
         record(consumed=["conf-0041", "conf-0042"]), "deny", "confirmation_reused",
         "the confirmation identifier was already used for another task"),
        ("confirmation-before-authorization",
         record(confirmed=confirmation(observedAt="2026-10-26T11:57:59Z")), "deny",
         "confirmation_outside_window",
         "the confirmation was observed one second before the operation was authorized"),
        ("confirmation-after-decision",
         record(confirmed=confirmation(observedAt="2026-10-26T12:00:01Z")), "deny",
         "confirmation_outside_window", "the confirmation is dated after the decision"),
        ("outcome-unresolved-claimed-complete",
         record(confirmed=confirmation(outcome="unresolved")), "deny", "outcome_unresolved",
         "the confirmation records the outcome as unresolved while the agent claims completion"),
        ("outcome-absent-claimed-complete",
         record(confirmed=confirmation(outcome="absent")), "deny", "outcome_contradicts_claim",
         "the resource reports the effect absent while the agent claims completion"),
        ("malformed-confirmation-field-missing",
         broken(lambda r: r.pop("confirmation")), "deny", "malformed_record",
         "the record omits the confirmation field instead of stating none"),
        ("malformed-outcome-unknown",
         broken(lambda r: r["confirmation"].update(outcome="done")), "deny", "malformed_record",
         "the confirmed outcome is not one the contract names"),
        ("malformed-claim-status-unknown",
         broken(lambda r: r["claim"].update(status="completed")), "deny", "malformed_record",
         "the claim status is not one the contract names, so it cannot read as no claim"),
        ("malformed-claim-missing",
         broken(lambda r: r.pop("claim")), "deny", "malformed_record",
         "the record carries no claim"),
        ("malformed-time-unparseable",
         broken(lambda r: r["authorization"].update(decidedAt="earlier")), "deny",
         "malformed_record", "the authorization time is not an RFC 3339 instant"),
        ("malformed-observers-not-a-map",
         broken(lambda r: r.update(trustedObservers=[GATEWAY])), "deny", "malformed_record",
         "the trusted observers are a list instead of a map"),
        ("contract-id-missing", record(contract=None), "deny", "contract_id_missing",
         "the record names no contract"),
        ("contract-id-unknown", record(contract=reader.CONTRACT_ID.replace("/v1", "/v0")),
         "deny", "contract_id_unknown", "the record names a contract version that does not exist"),
    ]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base / entry["path"]
        declared = entry["files"]
        if {p.name for p in directory.iterdir() if p.is_file()} != set(declared):
            raise ValueError(f"{entry['id']}: file set changed")
        files = {name: _sha((directory / name).read_bytes()) for name in declared}
        if files != declared:
            raise ValueError(f"{entry['id']}: file digest mismatch")
        entries.append({**entry, "files": files})
    return _sha(_json(entries))


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    entries = []
    for name, body, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        data = _json(body)
        (directory / "record.json").write_bytes(data)
        entries.append({
            "edit": edit, "expected": {"decision": decision, "reason": reason},
            "files": {"record.json": _sha(data)}, "id": name, "path": f"cases/{name}",
        })
    manifest = {
        "contractId": reader.CONTRACT_ID, "corpusDigest": _sha(_json(entries)), "suite": SUITE,
        "verifierContract": "verifier record.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
