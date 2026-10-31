"""Build the approval-binding cases byte-identically.

Every case is one record of an approval presented for a use, read under the
contract at ``contractId``, and the payload bytes of the use. Each denied case
changes one binding of an otherwise conformant record: the approval identifier,
the consumed set, the signing key, the user principal, the event or phase, the
tool, target or payload, the validity window, or the policy release that judged
the record. The motivating public fixes are listed in README.md.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent / "packaging"))

from agent_evidence_vectors import approvalbinding as reader  # noqa: E402

SUITE = reader.SUITE
DECISION = "2026-10-21T12:00:00Z"
APPROVED = b'{"path":"workspace/selection.json","bytes":"{\\"pick\\":7}"}\n'
MUTATED = b'{"path":"workspace/selection.json","bytes":"{\\"pick\\":7,\\"all\\":true}"}\n'
# A delete call whose only confirmation is a flag the model set in its own
# arguments, the pattern in google/adk-python issue 7655.
ASSERTED = (b'{"confirm_deletion":true,"create_backup":false,'
            b'"file_paths":["agent/root_agent.yaml"]}\n')
# The approval a verifier would have to synthesize from that flag: its approver
# is the calling agent and its key is the argument, so no key in trustedKeys
# stands behind it. Every other binding matches the use exactly.
ASSERTED_APPROVAL: dict[str, Any] = {
    "approver": "agent:builder-assistant", "keyId": "tool-argument:confirm_deletion",
    "payloadSha256": hashlib.sha256(ASSERTED).hexdigest(), "target": "agent/root_agent.yaml",
    "tool": "delete_files",
}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def approval(**changes: Any) -> dict[str, Any]:
    """The approval every conformant record carries, with ``changes`` applied."""
    body: dict[str, Any] = {
        "approvalId": "appr-0001", "approver": "human:reviewer-1", "clientId": "client-ide-7",
        "event": "tools/call", "expiresAt": "2026-10-21T12:05:00Z",
        "issuedAt": "2026-10-21T11:55:00Z", "keyId": "reviewer-1-key-2026-10",
        "payloadSha256": _sha(APPROVED), "phase": "pre-execution", "principal": "user:alice",
        "target": "workspace/selection.json", "tool": "file.save",
    }
    body.update(changes)
    return body


def record(*, presented: list[dict[str, Any]] | None = None,
           consumed: list[str] | None = None, key: str = "reviewer-1-key-2026-10",
           use: dict[str, Any] | None = None, release: dict[str, Any] | None = None,
           contract: str | None = reader.CONTRACT_ID,
           approved: dict[str, Any] | None = None) -> dict[str, Any]:
    """One record; every argument is a departure from the conformant record."""
    the_approval = approval(**(approved or {}))
    body: dict[str, Any] = {
        "approval": the_approval,
        "consumedApprovalIds": consumed or ["appr-0000"],
        "decisionTime": DECISION,
        "policyRelease": {"firstServedAt": "2026-10-21T09:00:00Z", "graceSeconds": 300,
                          "lastServedAt": "2026-10-21T12:30:00Z", "lookup": "ok",
                          "releaseId": "policy-release-41", **(release or {})},
        "presentedApprovals": presented if presented is not None else [the_approval],
        "trustedKeys": {"human:reviewer-1": key},
        "use": {"approvalId": "appr-0001", "clientId": "client-ide-7",
                "event": "tools/call", "payloadFile": "payload.bin", "phase": "pre-execution",
                "principal": "user:alice", "target": "workspace/selection.json",
                "tool": "file.save", "usedAt": DECISION, **(use or {})},
    }
    if contract is not None:
        body["contractId"] = contract
    return body


Case = tuple[str, dict[str, Any], bytes, str, str, str]


def cases() -> list[Case]:
    """Every case: id, record, used bytes, expected decision and reason, and what
    the case departs from."""
    return [
        ("allow-bound", record(), APPROVED, "allow", "bound",
         "control: every binding holds"),
        ("allow-other-approval-distinct-id",
         record(presented=[approval(), approval(approvalId="appr-0002", principal="user:bob")]),
         APPROVED, "allow", "bound",
         "control: another approval is presented under a different identifier"),
        ("allow-same-approval-presented-twice", record(presented=[approval(), approval()]),
         APPROVED, "allow", "bound",
         "control: the same approval appears twice with identical content"),
        ("allow-last-second-of-validity", record(use={"usedAt": "2026-10-21T12:04:59Z"}),
         APPROVED, "allow", "bound", "control: used one second before the approval expires"),
        ("allow-release-first-served-at-decision",
         record(release={"firstServedAt": DECISION}), APPROVED, "allow", "bound",
         "control: the release was first served exactly at the decision time"),
        ("allow-release-within-grace",
         record(release={"lastServedAt": "2026-10-21T11:55:00Z"}), APPROVED, "allow", "bound",
         "control: the release was last served exactly the grace period before the decision"),
        ("approval-id-reused-different-content",
         record(presented=[approval(), approval(principal="user:bob", tool="file.delete")]),
         APPROVED, "deny", "approval_id_ambiguous",
         "a second approval with the same identifier and different content is presented"),
        ("approval-already-consumed", record(consumed=["appr-0000", "appr-0001"]), APPROVED,
         "deny", "approval_replayed", "the approval identifier was already consumed"),
        ("approval-key-not-approvers", record(key="reviewer-1-key-2026-04"), APPROVED,
         "deny", "key_not_bound",
         "the approval names a key id other than the approver's trusted key"),
        ("approval-asserted-in-tool-arguments",
         record(approved=ASSERTED_APPROVAL,
                use={"tool": "delete_files", "target": "agent/root_agent.yaml"}),
         ASSERTED, "deny", "key_not_bound",
         "the only approval is a flag the model set in the tool arguments; its approver "
         "is the agent, which holds no key in trustedKeys"),
        ("same-client-other-user", record(use={"principal": "user:bob"}), APPROVED,
         "deny", "principal_mismatch",
         "another user reaches the approval through the same OAuth client"),
        ("event-differs", record(use={"event": "tasks/cancel"}), APPROVED, "deny",
         "event_phase_mismatch", "the approval is used for a different event"),
        ("phase-differs", record(use={"phase": "post-execution"}), APPROVED, "deny",
         "event_phase_mismatch", "the approval is used in a different phase"),
        ("payload-mutated-after-approval", record(), MUTATED, "deny", "payload_mismatch",
         "the payload was changed after the approval was given"),
        ("target-differs", record(use={"target": "workspace/secrets.json"}), APPROVED,
         "deny", "payload_mismatch", "the approved bytes go to a different target"),
        ("tool-differs", record(use={"tool": "file.delete"}), APPROVED, "deny",
         "payload_mismatch", "a different tool is used under the approval"),
        ("used-at-expiry", record(use={"usedAt": "2026-10-21T12:05:00Z"}), APPROVED, "deny",
         "approval_outside_validity", "used at the instant the approval expires"),
        ("used-before-issued", record(use={"usedAt": "2026-10-21T11:54:59Z"}), APPROVED,
         "deny", "approval_outside_validity", "used one second before the approval was issued"),
        ("release-lookup-unavailable", record(release={"lookup": "unavailable"}), APPROVED,
         "deny", "comparison_unavailable",
         "the policy release lookup failed; a failed lookup is not a match"),
        ("release-first-served-after-decision",
         record(release={"firstServedAt": "2026-10-21T12:00:01Z"}), APPROVED, "deny",
         "release_not_served_at_decision",
         "the release that judged the record was first served after the decision time"),
        ("release-retired-beyond-grace",
         record(release={"lastServedAt": "2026-10-21T11:54:59Z"}), APPROVED, "deny",
         "release_not_served_at_decision",
         "the release stopped being served more than the grace period before the decision"),
        ("contract-id-missing", record(contract=None), APPROVED, "deny",
         "contract_id_missing", "the record names no contract"),
        ("contract-id-unknown", record(contract=reader.CONTRACT_ID.replace("/v1", "/v0")),
         APPROVED, "deny", "contract_id_unknown",
         "the record names a contract version that does not exist"),
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
    for name, body, used, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True, exist_ok=True)
        files = {"payload.bin": used, "record.json": _json(body)}
        for filename, data in files.items():
            (directory / filename).write_bytes(data)
        entries.append({
            "edit": edit, "expected": {"decision": decision, "reason": reason},
            "files": {key: _sha(value) for key, value in sorted(files.items())},
            "id": name, "path": f"cases/{name}",
            "useMatchesApproval": reader.use_matches_approval(body, used),
        })
    manifest = {
        "contractId": reader.CONTRACT_ID, "corpusDigest": _sha(_json(entries)), "suite": SUITE,
        "verifierContract": "verifier record.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    verdict_words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
