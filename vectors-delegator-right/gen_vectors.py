"""Build the delegator-right cases byte-identically.

Every case is one record of a delegated request, read under the contract at
``contractId``. The record carries the grant chain, the authoritative source's
entitlements to delegate and scope removals, and the propagation limit within
which a change at the source must reach enforcement. Each denied case departs
from a conformant record in one place: the delegator's entitlement, the
delegator's scope, an ancestor grant's scope, or the record's own form. The
public wording the cases follow is in README.md.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "packaging"))

from agent_evidence_vectors import delegatorright as reader  # noqa: E402

SUITE = reader.SUITE
DECISION = "2026-10-26T12:00:00Z"
LIMIT = 300
OPERATION = "ticket.create"
CHAIN_START = "2026-10-26T10:00:00Z"
CHAIN_END = "2026-10-26T14:00:00Z"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def hop(grant: str, grantor: str, grantee: str, scope: list[str],
        narrowings: list[dict[str, str]] | None = None,
        issued: str = CHAIN_START) -> dict[str, Any]:
    return {"expiresAt": CHAIN_END, "grantId": grant, "grantee": grantee, "grantor": grantor,
            "issuedAt": issued, "narrowings": narrowings or [], "scope": scope}


def right(principal: str, operation: str = OPERATION, start: str = "2026-10-01T00:00:00Z",
          until: str | None = None) -> dict[str, Any]:
    return {"from": start, "operation": operation, "principal": principal, "until": until}


ROOT_HOP = hop("grant-1", "human:approver-1", "agent:planner", [OPERATION, "ticket.read"])
SECOND_HOP = hop("grant-2", "agent:planner", "agent:dispatcher", [OPERATION])
PLANNER = right("agent:planner")


def record(*, chain: list[dict[str, Any]] | None = None,
           rights: list[dict[str, Any]] | None = None, operation: str = OPERATION,
           contract: str | None = reader.CONTRACT_ID) -> dict[str, Any]:
    """One record; every argument is a departure from the conformant record."""
    body: dict[str, Any] = {
        "chain": chain if chain is not None else [ROOT_HOP, SECOND_HOP],
        "decisionTime": DECISION,
        "propagationLimitSeconds": LIMIT,
        "request": {"agent": "agent:dispatcher", "operation": operation,
                    "resource": "queue/support"},
        "rights": rights if rights is not None else [PLANNER],
        "roots": ["human:approver-1"],
    }
    if contract is not None:
        body["contractId"] = contract
    return body


def broken(mutate: Any) -> dict[str, Any]:
    """The conformant record with one structural change applied by ``mutate``."""
    body = copy.deepcopy(record())
    mutate(body)
    return body


def _at(seconds_before: int) -> str:
    """An RFC 3339 instant ``seconds_before`` seconds before the decision."""
    moment = reader._when(DECISION) - timedelta(seconds=seconds_before)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


Case = tuple[str, dict[str, Any], str, str, str]


def cases() -> list[Case]:
    """Every case: id, record, expected decision and reason, and what it departs from."""
    narrow = [{"effectiveAt": _at(LIMIT), "operation": OPERATION}]
    narrow_inside = [{"effectiveAt": _at(LIMIT - 1), "operation": OPERATION}]
    narrow_other = [{"effectiveAt": _at(3600), "operation": "ticket.read"}]
    return [
        ("allow-root-direct", record(chain=[hop("grant-1", "human:approver-1",
                                                "agent:dispatcher", [OPERATION])], rights=[]),
         "allow", "entitled", "control: the root grants the operation directly"),
        ("allow-entitled-delegator", record(), "allow", "entitled",
         "control: the delegating agent was entitled to pass the operation on"),
        ("allow-entitlement-ended-within-limit",
         record(rights=[right("agent:planner", until=_at(LIMIT - 1))]), "allow", "entitled",
         "control: the entitlement ended one second inside the propagation limit"),
        ("allow-entitlement-ends-after-decision",
         record(rights=[right("agent:planner", until="2026-10-26T12:30:00Z")]), "allow",
         "entitled", "control: the entitlement ends after the decision"),
        ("allow-ancestor-narrowed-within-limit",
         record(chain=[hop("grant-1", "human:approver-1", "agent:planner",
                           [OPERATION, "ticket.read"], narrow_inside), SECOND_HOP]),
         "allow", "entitled",
         "control: the operation was removed from the parent grant one second inside the limit"),
        ("allow-ancestor-narrowed-other-operation",
         record(chain=[hop("grant-1", "human:approver-1", "agent:planner",
                           [OPERATION, "ticket.read"], narrow_other), SECOND_HOP]),
         "allow", "entitled",
         "control: a different operation was removed from the parent grant; this one remains"),
        ("allow-entitled-delegator-other-operation-too",
         record(rights=[PLANNER, right("agent:planner", "ticket.read")]), "allow", "entitled",
         "control: the delegator is entitled to another operation as well"),
        ("delegator-never-entitled", record(rights=[]), "deny", "delegator_not_entitled",
         "the delegating agent holds no entitlement to delegate any operation"),
        ("delegator-entitled-other-operation-only",
         record(rights=[right("agent:planner", "ticket.read")]), "deny",
         "delegator_not_entitled",
         "the delegating agent may delegate ticket.read, not the requested operation"),
        ("delegator-entitlement-began-after-issue",
         record(rights=[right("agent:planner", start="2026-10-26T10:30:00Z")]), "deny",
         "delegator_not_entitled", "the entitlement began after the grant was issued"),
        ("delegator-entitlement-ended-before-issue",
         record(rights=[right("agent:planner", until="2026-10-26T09:00:00Z")]), "deny",
         "delegator_not_entitled", "the entitlement had already ended when the grant was issued"),
        ("entitlement-another-principal",
         record(rights=[right("agent:other")]), "deny", "delegator_not_entitled",
         "a different agent holds the entitlement"),
        ("entitlement-removed-at-deadline",
         record(rights=[right("agent:planner", until=_at(LIMIT))]), "deny",
         "delegation_right_removed",
         "the entitlement ended exactly the propagation limit before the decision"),
        ("entitlement-removed-long-before",
         record(rights=[right("agent:planner", until=_at(3600))]), "deny",
         "delegation_right_removed", "the entitlement ended an hour before the decision"),
        ("ancestor-scope-removed-at-deadline",
         record(chain=[hop("grant-1", "human:approver-1", "agent:planner",
                           [OPERATION, "ticket.read"], narrow), SECOND_HOP]),
         "deny", "ancestor_scope_removed",
         "the operation was removed from the parent grant exactly the limit before the decision, "
         "with the child grant intact"),
        ("ancestor-scope-removed-in-last-grant",
         record(chain=[ROOT_HOP, hop("grant-2", "agent:planner", "agent:dispatcher",
                                     [OPERATION], narrow)]),
         "deny", "ancestor_scope_removed",
         "the operation was removed at the source from the grant the delegate itself holds"),
        ("delegate-scope-exceeds-delegator",
         record(chain=[ROOT_HOP, hop("grant-2", "agent:planner", "agent:dispatcher",
                                     [OPERATION, "ticket.delete"])]),
         "deny", "delegate_exceeds_delegator",
         "the second grant carries ticket.delete, which the first never held"),
        ("request-outside-granted-scope", record(operation="ticket.read",
                                                 chain=[ROOT_HOP, SECOND_HOP],
                                                 rights=[right("agent:planner", "ticket.read")]),
         "deny", "delegate_exceeds_delegator",
         "the delegate requests ticket.read, outside the scope of the grant it holds"),
        ("malformed-rights-field-missing",
         broken(lambda r: r.pop("rights")), "deny", "malformed_record",
         "the record omits the entitlements it is judged against"),
        ("malformed-limit-negative",
         broken(lambda r: r.update(propagationLimitSeconds=-1)), "deny", "malformed_record",
         "the propagation limit is negative"),
        ("malformed-limit-not-integer",
         broken(lambda r: r.update(propagationLimitSeconds="300")), "deny", "malformed_record",
         "the propagation limit is text"),
        ("malformed-decision-time",
         broken(lambda r: r.update(decisionTime="soon")), "deny", "malformed_record",
         "the decision time is not an RFC 3339 instant"),
        ("malformed-scope-not-list",
         broken(lambda r: r["chain"][0].update(scope=OPERATION)), "deny", "malformed_record",
         "a grant's scope is text instead of a list"),
        ("malformed-chain-empty",
         broken(lambda r: r.update(chain=[])), "deny", "malformed_record",
         "the grant chain is empty"),
        ("contract-id-missing", record(contract=None), "deny", "contract_id_missing",
         "the record names no contract"),
        ("contract-id-unknown",
         record(contract=reader.CONTRACT_ID.replace("/v1", "/v0")), "deny",
         "contract_id_unknown", "the record names a contract version that does not exist"),
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
