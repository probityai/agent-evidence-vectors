"""Build the authority-at-dispatch cases byte-identically.

Every case is one record of an attempted dispatch, read under the contract at
``contractId``, and the bytes the agent dispatched. The cases follow the
delegated-authority comparison in ``interop/authority-unreachable-2026-10-03/
CONTRACT.md`` of probityai/agent-evidence-observer at commit
``00e92b0a3fcf53376ebafc6cc9b4abde7e9fdc8c``: revocation after delegation,
a changed object or action, stale authority evidence, scope amplified across
delegation hops and an expired grant, each with the controls that keep a
verifier from denying everything.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "packaging"))

from agent_evidence_vectors import authoritydispatch as reader  # noqa: E402

SUITE = reader.SUITE
CONTRACT_SOURCE = {
    "repository": "https://github.com/probityai/agent-evidence-observer",
    "file": "interop/authority-unreachable-2026-10-03/CONTRACT.md",
    "commit": "00e92b0a3fcf53376ebafc6cc9b4abde7e9fdc8c",
}
DECISION = "2026-10-03T12:00:00Z"
APPROVED = b'{"queue":"support","title":"Refund 7731","body":"Customer asks for a refund."}\n'
CHANGED = b'{"queue":"support","title":"Refund 7731","body":"Refund approved in full."}\n'
MAX_AGE = 180


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _seconds(start: str, end: str) -> int:
    return int((reader._when(end) - reader._when(start)).total_seconds())


def hop(grant: str, grantor: str, grantee: str, scope: list[str],
        expires: str = "2026-10-03T13:00:00Z") -> dict[str, Any]:
    return {"expiresAt": expires, "grantId": grant, "grantee": grantee, "grantor": grantor,
            "notBefore": "2026-10-03T11:50:00Z", "scope": scope}


ONE_HOP = [hop("grant-1", "human:approver-1", "agent:planner",
               ["ticket.create", "ticket.read"])]
TWO_HOPS = [*ONE_HOP, hop("grant-2", "agent:planner", "agent:dispatcher", ["ticket.create"])]


def record(name: str, *, delegation: list[dict[str, Any]] | None = None,
           observed: str = "2026-10-03T11:59:30Z", age: int | None = None,
           revoked: list[dict[str, str]] | None = None, tool: str = "ticket.create",
           target: str = "queue/support", contract: str | None = reader.CONTRACT_ID
           ) -> dict[str, Any]:
    """One dispatch record; every argument is a departure from the allowed record."""
    body: dict[str, Any] = {
        "approvedAction": {"approvedAt": "2026-10-03T11:55:00Z", "payloadSha256": _sha(APPROVED),
                           "target": "queue/support", "tool": "ticket.create"},
        "attempt": {"attemptId": name, "runId": "run-2026-10-03-a"},
        "authorityEvidence": {
            "evidenceAgeSeconds": _seconds(observed, DECISION) if age is None else age,
            "maxAgeSeconds": MAX_AGE, "observedAt": observed, "revision": "status-snapshot-41",
            "revokedGrants": revoked or [], "source": "signed-status-snapshot"},
        "decisionTime": DECISION,
        "delegation": delegation or ONE_HOP,
        "dispatch": {"payloadFile": "dispatched.bin", "target": target, "tool": tool},
    }
    if contract is not None:
        body["contractId"] = contract
    return body


Case = tuple[str, dict[str, Any], bytes, str, str, str]


def cases() -> list[Case]:
    """Every case: id, record, dispatched bytes, expected decision and reason, and
    what the case departs from."""
    return [
        ("allow-direct", record("allow-direct"), APPROVED, "allow", "authorized",
         "control: one hop, fresh evidence, the approved bytes"),
        ("allow-two-hop-narrowing", record("allow-two-hop-narrowing", delegation=TWO_HOPS),
         APPROVED, "allow", "authorized",
         "control: the second hop narrows the first hop's scope"),
        ("allow-revoked-after-dispatch",
         record("allow-revoked-after-dispatch", delegation=TWO_HOPS,
                revoked=[{"grantId": "grant-1", "revokedAt": "2026-10-03T12:10:00Z"}]),
         APPROVED, "allow", "authorized",
         "control: a revocation recorded before dispatch takes effect ten minutes after it"),
        ("allow-evidence-age-at-limit",
         record("allow-evidence-age-at-limit", observed="2026-10-03T11:57:00Z"),
         APPROVED, "allow", "authorized",
         "control: the evidence is exactly as old as the freshness limit allows"),
        ("revoked-before-dispatch",
         record("revoked-before-dispatch", delegation=TWO_HOPS,
                revoked=[{"grantId": "grant-1", "revokedAt": "2026-10-03T11:58:00Z"}]),
         APPROVED, "deny", "grant_revoked",
         "the first hop's grant was revoked after delegation and before dispatch"),
        ("dispatched-bytes-differ", record("dispatched-bytes-differ"), CHANGED,
         "deny", "dispatch_not_approved",
         "the dispatched bytes differ from the bytes whose digest was approved"),
        ("dispatched-object-differs", record("dispatched-object-differs",
                                             target="queue/billing"),
         APPROVED, "deny", "dispatch_not_approved",
         "the approved bytes are dispatched to a different target"),
        ("dispatched-action-differs", record("dispatched-action-differs",
                                             tool="ticket.read"),
         APPROVED, "deny", "dispatch_not_approved",
         "an in-scope tool other than the approved one is dispatched"),
        ("stale-authority-evidence",
         record("stale-authority-evidence", observed="2026-10-03T11:55:00Z"),
         APPROVED, "deny", "authority_evidence_stale",
         "the authority evidence is 300 seconds old against a 180-second limit"),
        ("scope-amplified-across-hops",
         record("scope-amplified-across-hops", delegation=[
             *ONE_HOP, hop("grant-2", "agent:planner", "agent:dispatcher",
                           ["ticket.create", "ticket.delete"])]),
         APPROVED, "deny", "scope_amplified",
         "the second hop grants ticket.delete, which the first hop never held"),
        ("grant-expired",
         record("grant-expired", delegation=[hop("grant-1", "human:approver-1",
                                                 "agent:planner", ["ticket.create"],
                                                 expires="2026-10-03T11:59:00Z")]),
         APPROVED, "deny", "grant_expired", "dispatch one minute after the grant expired"),
        ("contract-id-missing", record("contract-id-missing", contract=None), APPROVED,
         "deny", "contract_id_missing", "the record names no contract"),
        ("contract-id-unknown",
         record("contract-id-unknown", contract=reader.CONTRACT_ID.replace("/v1", "/v0")),
         APPROVED, "deny", "contract_id_unknown", "the record names a contract version that "
         "does not exist"),
        ("evidence-age-inconsistent",
         record("evidence-age-inconsistent", observed="2026-10-03T11:50:00Z", age=30),
         APPROVED, "deny", "evidence_age_inconsistent",
         "the record states an age of 30 seconds for evidence observed 600 seconds "
         "before the decision"),
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
    for name, body, dispatched, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        files = {"dispatched.bin": dispatched, "record.json": _json(body)}
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        entries.append({
            "dispatchMatchesApproval": reader.dispatch_matches_approval(body, dispatched),
            "edit": edit, "expected": {"decision": decision, "reason": reason},
            "files": {key: _sha(value) for key, value in sorted(files.items())},
            "id": name, "path": f"cases/{name}",
        })
    manifest = {
        "contractId": reader.CONTRACT_ID, "contractSource": CONTRACT_SOURCE,
        "corpusDigest": _sha(_json(entries)), "suite": SUITE,
        "verifierContract": "verifier record.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
