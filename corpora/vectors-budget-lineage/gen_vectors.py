"""Build the budget-lineage cases byte-identically.

Every case is one principal's delegation tree: the grants each delegator issued,
the delegates' acceptances, the budgets the tree may spend from, the depth limit,
and every charge the accounting authority booked for the agents the grants name,
whatever budget each charge names. Each denied case is built so the check it
names is the first that fails and every earlier check passes, and each allowed
case is a control that keeps a verifier from denying everything.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import budgetlineage as reader  # noqa: E402

SUITE = reader.SUITE
PRINCIPAL = "principal-1"
BUDGET = "budget-1"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _t(minute: int) -> str:
    return f"2026-11-16T12:{minute:02d}:00Z"


def grant(gid: str, delegator: str, delegate: str, *, issued: int = 0,
          revoked: int | None = None, carve: tuple[str, int] | None = None) -> dict[str, Any]:
    """One grant as its delegator issued it."""
    item: dict[str, Any] = {"delegate": delegate, "delegator": delegator, "grantId": gid,
                            "issuedAt": _t(issued)}
    if revoked is not None:
        item["revokedAt"] = _t(revoked)
    if carve is not None:
        item["carve"] = {"id": carve[0], "limit": carve[1]}
    return item


def accept(item: dict[str, Any], *, minute: int | None = None) -> dict[str, Any]:
    """The delegate's acceptance of one grant."""
    issued = int(item["issuedAt"][14:16])
    return {"acceptedAt": _t(issued + 1 if minute is None else minute),
            "delegate": item["delegate"], "grantId": item["grantId"]}


def charge(rid: str, agent: str, units: int, *, budget: str = BUDGET, at: int = 10,
           decision: str = "admitted", outcome: str = "committed") -> dict[str, Any]:
    """One charge the accounting authority booked."""
    return {"agent": agent, "at": _t(at), "budget": budget,
            "decision": decision, "outcome": outcome if decision == "admitted" else "none",
            "requestId": rid, "units": units}


def build(name: str, grants: list[dict[str, Any]], ledger: list[dict[str, Any]], *,
          acceptances: list[dict[str, Any]] | None = None, max_depth: int = 3,
          limit: int = 10, **top: Any) -> dict[str, Any]:
    """A record over one tree; every grant is accepted unless ``acceptances`` says otherwise."""
    record: dict[str, Any] = {
        "acceptances": [accept(g) for g in grants] if acceptances is None else acceptances,
        "asOf": _t(30),
        "budget": {"id": BUDGET, "limit": limit, "unit": "units"},
        "contractId": reader.CONTRACT_ID,
        "delegations": grants, "ledger": ledger, "maxDepth": max_depth,
        "principal": PRINCIPAL, "recordId": f"record-{name}",
    }
    record.update(top)
    return {key: value for key, value in record.items() if value is not None}


Case = tuple[str, dict[str, Any], str, str, str]


def cases() -> list[Case]:  # noqa: PLR0915 -- one list of cases, read top to bottom
    """Every case: id, record, expected decision, expected reason, and what it shows."""
    ok = "lineage_held"
    pa = grant("g-a", PRINCIPAL, "agent-a")
    ab = grant("g-b", "agent-a", "agent-b", issued=1)
    bc = grant("g-c", "agent-b", "agent-c", issued=2)
    cd = grant("g-d", "agent-c", "agent-d", issued=3)
    two_hop = [pa, ab]
    within = [charge("r1", "agent-a", 3), charge("r2", "agent-b", 4)]

    def named(label: str, grants: list[dict[str, Any]], ledger: list[dict[str, Any]],
              **kw: Any) -> dict[str, Any]:
        return build(label, copy.deepcopy(grants), copy.deepcopy(ledger), **kw)

    unknown_cid = reader.CONTRACT_ID.replace("/v1", "/v0")
    negative = named("malformed-ledger-units-negative", two_hop, within)
    negative["ledger"][0]["units"] = -3
    not_list = named("malformed-delegations-not-list", two_hop, within)
    not_list["delegations"] = {"g-a": pa}
    carved = [grant("g-a", PRINCIPAL, "agent-a", carve=("budget-1/a", 6)), ab]
    revoked_b = [pa, grant("g-b", "agent-a", "agent-b", issued=1, revoked=5)]
    revoked_a = [grant("g-a", PRINCIPAL, "agent-a", revoked=5), ab]
    return [
        ("allow-two-hop-tree-within-budget",
         named("allow-two-hop-tree-within-budget", two_hop, within), "allow", ok,
         "control: the principal delegates to agent-a, agent-a to agent-b, and the two spend "
         "7 of 10 units of the principal's budget"),
        ("allow-carve-within-parent",
         named("allow-carve-within-parent", carved,
               [charge("r1", "agent-a", 3, budget="budget-1/a"),
                charge("r2", "agent-b", 3, budget="budget-1/a")]), "allow", ok,
         "control: agent-a holds a carve of 6 from the principal's 10 and its subtree spends 6"),
        ("allow-depth-at-limit",
         named("allow-depth-at-limit", [pa, ab, bc], [charge("r1", "agent-c", 2)]),
         "allow", ok, "control: agent-c sits at depth 3 against a limit of 3 and is charged"),
        ("allow-outsider-booked-elsewhere",
         named("allow-outsider-booked-elsewhere", two_hop,
               [*within, charge("r3", "agent-x", 9, budget="budget-9")]), "allow", ok,
         "control: agent-x was never delegated to, so its 9 units on another budget are "
         "not the tree's"),
        ("allow-revoked-delegate-books-elsewhere-after-revocation",
         named("allow-revoked-delegate-books-elsewhere-after-revocation", revoked_b,
               [charge("r1", "agent-a", 3), charge("r2", "agent-b", 8, budget="budget-9",
                                                    at=6)]), "allow", ok,
         "control: agent-b's grant was revoked at 12:05 and its charge on another budget "
         "came at 12:06"),
        ("allow-grandchild-after-parent-revoked-books-elsewhere",
         named("allow-grandchild-after-parent-revoked-books-elsewhere", revoked_a,
               [charge("r1", "agent-a", 3, at=4),
                charge("r2", "agent-b", 8, budget="budget-9", at=6)]), "allow", ok,
         "control: revoking agent-a at 12:05 removes agent-b with it, so agent-b's charge "
         "elsewhere at 12:06 is not the tree's"),
        ("allow-refused-elsewhere-not-charged",
         named("allow-refused-elsewhere-not-charged", two_hop,
               [*within, charge("r3", "agent-b", 8, budget="budget-9", decision="refused")]),
         "allow", ok,
         "control: agent-b asked another budget for 8 and was refused, so nothing was charged"),
        ("contract-id-missing", named("contract-id-missing", two_hop, within, contractId=None),
         "deny", "contract_id_missing", "the record names no contract"),
        ("contract-id-unknown",
         named("contract-id-unknown", two_hop, within, contractId=unknown_cid),
         "deny", "contract_id_unknown", "the record names a contract version that does not exist"),
        ("malformed-ledger-units-negative", negative, "deny", "malformed_record",
         "a charge carries a negative number of units"),
        ("malformed-delegations-not-list", not_list, "deny", "malformed_record",
         "the delegations are an object, not a list"),
        ("delegation-recorded-only-by-delegator",
         named("delegation-recorded-only-by-delegator", two_hop, within,
               acceptances=[accept(pa)]), "deny", "delegation_unilateral",
         "agent-a's grant to agent-b has no acceptance by agent-b: only the delegator says "
         "it handed the task over, so agent-b cannot be held to it"),
        ("delegation-claimed-only-by-delegate",
         named("delegation-claimed-only-by-delegate", two_hop, within,
               acceptances=[accept(pa), accept(ab),
                            {"acceptedAt": _t(4), "delegate": "agent-b", "grantId": "g-z"}]),
         "deny", "delegation_unilateral",
         "agent-b accepts a grant g-z that no delegator issued"),
        ("delegation-from-outside-tree",
         named("delegation-from-outside-tree",
               [pa, grant("g-b", "agent-x", "agent-b", issued=1)], within), "deny",
         "delegation_detached",
         "agent-b's authority comes from agent-x, which the principal never delegated to"),
        ("depth-reset-by-fresh-root",
         named("depth-reset-by-fresh-root", [pa, ab, bc, cd], [charge("r1", "agent-d", 2)]),
         "deny", "depth_limit_exceeded",
         "agent-d sits at depth 4 against a limit of 3 and was admitted, as a runtime that "
         "counts depth from a flow agent-c opened afresh would admit it"),
        ("carve-wider-than-parent",
         named("carve-wider-than-parent",
               [grant("g-a", PRINCIPAL, "agent-a", carve=("budget-1/a", 6)),
                grant("g-b", "agent-a", "agent-b", issued=1, carve=("budget-1/a/b", 9))],
               [charge("r1", "agent-b", 2, budget="budget-1/a/b")]), "deny",
         "carve_exceeds_parent",
         "agent-a holds 6 units and carves 9 for agent-b: the sub-agent's budget is wider "
         "than the one it inherits"),
        ("subagent-rerooted-budget",
         named("subagent-rerooted-budget", two_hop,
               [charge("r1", "agent-a", 6),
                charge("r2", "agent-b", 6, budget="budget-fresh-root")]), "deny",
         "charge_outside_lineage",
         "agent-b opened a fresh root and was charged 6 against a budget nobody delegated, "
         "while the principal's budget shows only agent-a's 6 of 10"),
        ("rerooted-charge-before-revocation",
         named("rerooted-charge-before-revocation", revoked_b,
               [charge("r1", "agent-a", 3), charge("r2", "agent-b", 8, budget="budget-9",
                                                    at=4)]), "deny",
         "charge_outside_lineage",
         "agent-b's charge on another budget came at 12:04, while its grant ran until 12:05"),
        ("rerooted-unknown-outcome",
         named("rerooted-unknown-outcome", two_hop,
               [charge("r1", "agent-a", 3),
                charge("r2", "agent-b", 5, budget="budget-fresh-root", outcome="unknown")]),
         "deny", "charge_outside_lineage",
         "agent-b's charge on a fresh root has an unknown outcome, which still counts"),
        ("overspend-across-subtrees",
         named("overspend-across-subtrees",
               [pa, grant("g-e", PRINCIPAL, "agent-e"), ab],
               [charge("r1", "agent-a", 4), charge("r2", "agent-b", 4),
                charge("r3", "agent-e", 4)]), "deny",
         "lineage_overspend",
         "three agents each spend 4, inside any per-agent limit of 5, and together spend 12 "
         "of the principal's 10"),
        ("overspend-inside-carve",
         named("overspend-inside-carve", carved,
               [charge("r1", "agent-b", 7, budget="budget-1/a")]), "deny",
         "lineage_overspend",
         "agent-b spends 7 from agent-a's carve of 6, though the principal's 10 would cover it"),
    ]


def corpus_digest(manifest: dict[str, Any], root: str) -> str:
    """Recompute the digest from the committed files, not their declared hashes."""
    base_dir = Path(root)
    entries = []
    for entry in manifest["vectors"]:
        directory = base_dir / entry["path"]
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
            "files": {"record.json": _sha(data)},
            "id": name, "path": f"cases/{name}", "retained": reader.retained(body),
        })
    manifest = {
        "contractId": reader.CONTRACT_ID,
        "corpusDigest": _sha(_json(entries)), "suite": SUITE,
        "verifierContract": "verifier record.json --json; exit 0 allow, 1 deny",
        "vectors": entries,
    }
    verdict_words = [entry["expected"]["decision"] for entry in entries]
    manifest["counts"] = {word: verdict_words.count(word) for word in sorted(set(verdict_words))}
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
