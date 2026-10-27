"""Build the aggregate-accounting cases byte-identically.

Every case is one record of the decisions an accounting authority took against
one budget shared by a principal and its delegation subtrees. Each denied case
is built so the check it names is the first that fails and every earlier check
passes, and each allowed case is a control that keeps a verifier from denying
everything.
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

from agent_evidence_vectors import aggregateaccounting as reader  # noqa: E402

SUITE = reader.SUITE
BOUND_MS = 200


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def request(rid: str, units: int, decision: str, *, subtree: str = "subtree-a",
            agent: str | None = None, outcome: str = "committed",
            latency: int = 20, reason: str | None = None) -> dict[str, Any]:
    """One decision, identifying the principal, subtree, budget and action."""
    admitted = decision == "admitted"
    item: dict[str, Any] = {
        "action": "pay-invoice", "agent": agent or f"agent-{rid}", "budget": "budget-1",
        "charged": admitted and outcome in reader.CHARGED_OUTCOMES,
        "decision": decision, "latencyMs": latency,
        "outcome": outcome if admitted else "none", "principal": "principal-1",
        "requestId": rid, "subtree": subtree, "units": units,
    }
    if reason:
        item["reason"] = reason
    if outcome == "unknown":
        item["reservationExpiresAt"] = "2026-10-27T12:05:00Z"
    return item


def build(name: str, decisions: list[dict[str, Any]], **top: Any) -> dict[str, Any]:
    """A record over ``decisions`` whose retained counts are the ones they give."""
    record: dict[str, Any] = {
        "asOf": "2026-10-27T12:10:00Z",
        "budget": {"id": "budget-1", "limit": 10, "remainingBefore": 10, "unit": "units"},
        "contractId": reader.CONTRACT_ID,
        "decisions": decisions, "latencyBoundMs": BOUND_MS,
        "principal": "principal-1", "recordId": f"record-{name}",
    }
    record["effectCounts"] = reader.effect_counts(record)
    record.update(top)
    return {key: value for key, value in record.items() if value is not None}


def _without(key: str) -> Any:
    def edit(record: dict[str, Any]) -> dict[str, Any]:
        del record["decisions"][0][key]
        return record
    return edit


def _miscounted(record: dict[str, Any]) -> dict[str, Any]:
    record["effectCounts"] = {**record["effectCounts"], "admitted": 1}
    return record


Case = tuple[str, dict[str, Any], str, str, str]


def cases() -> list[Case]:
    """Every case: id, record, expected decision, expected reason, and what it shows."""
    ok = "aggregate_held"
    two_fit = [request("r1", 4, "admitted"), request("r2", 4, "admitted")]
    race_ok = [request("r1", 6, "admitted"), request("r2", 6, "refused", reason="budget")]
    unknown = [request("r1", 5, "admitted", outcome="unknown"),
               request("r2", 6, "refused", reason="budget")]
    unknown_released = [request("r1", 5, "admitted", outcome="unknown")]
    unknown_released[0]["charged"] = False
    shared = [request("r1", 4, "admitted", subtree="subtree-a"),
              request("r2", 4, "admitted", subtree="subtree-b"),
              request("r3", 4, "refused", subtree="subtree-a", reason="budget")]
    three_over = [request("r1", 4, "admitted", subtree="subtree-a"),
                  request("r2", 4, "admitted", subtree="subtree-b"),
                  request("r3", 4, "admitted", subtree="subtree-c")]
    def named(label: str, decisions: list[dict[str, Any]], **top: Any) -> dict[str, Any]:
        return build(label, copy.deepcopy(decisions), **top)

    unknown_cid = reader.CONTRACT_ID.replace("/v1", "/v0")
    no_subtree = named("identity-missing-subtree", two_fit)
    del no_subtree["decisions"][1]["subtree"]
    no_action = named("identity-missing-action", two_fit)
    no_action["decisions"][0]["action"] = ""
    miscounted = _miscounted(named("effect-counts-disagree", two_fit))
    return [
        ("allow-concurrent-both-fit", named("allow-concurrent-both-fit", two_fit), "allow", ok,
         "control: 10 units left, two concurrent requests for 4 are both admitted"),
        ("allow-race-one-admitted", named("allow-race-one-admitted", race_ok), "allow", ok,
         "control: 10 units left, two racing requests for 6, one admitted and one refused"),
        ("allow-exact-fit-both-admitted",
         named("allow-exact-fit-both-admitted",
               [request("r1", 5, "admitted"), request("r2", 5, "admitted")]), "allow", ok,
         "control: two requests for 5 spend the 10 units exactly"),
        ("allow-unknown-outcome-stays-charged",
         named("allow-unknown-outcome-stays-charged", unknown), "allow", ok,
         "control: an unknown-outcome reservation of 5 stays charged past its expiry, "
         "so a request for 6 is refused"),
        ("allow-released-reservation-returns-units",
         named("allow-released-reservation-returns-units",
               [request("r1", 6, "admitted", outcome="released"),
                request("r2", 6, "admitted")]), "allow", ok,
         "control: a released reservation returns its units, so a second request for 6 fits"),
        ("allow-past-latency-bound-refused",
         named("allow-past-latency-bound-refused",
               [request("r1", 4, "refused", latency=450, reason="latency")]), "allow", ok,
         "control: the authority answered in 450 ms against a 200 ms bound and refused"),
        ("allow-past-latency-bound-held",
         named("allow-past-latency-bound-held",
               [request("r1", 4, "held", latency=450, reason="latency")]), "allow", ok,
         "control: the authority answered in 450 ms against a 200 ms bound and held"),
        ("allow-latency-at-bound-admitted",
         named("allow-latency-at-bound-admitted",
               [request("r1", 4, "admitted", latency=BOUND_MS)]), "allow", ok,
         "control: an answer in exactly 200 ms is inside the bound"),
        ("allow-two-subtrees-one-principal",
         named("allow-two-subtrees-one-principal", shared), "allow", ok,
         "control: two subtrees of one principal spend eight units of the budget "
         "and the third request is refused"),
        ("contract-id-missing", named("contract-id-missing", two_fit, contractId=None), "deny",
         "contract_id_missing", "the record names no contract"),
        ("contract-id-unknown", named("contract-id-unknown", two_fit, contractId=unknown_cid),
         "deny", "contract_id_unknown", "the record names a contract version that does not exist"),
        ("identity-missing-subtree", no_subtree, "deny", "accounting_identity_missing",
         "the second decision does not name its subtree"),
        ("identity-missing-action", no_action, "deny", "accounting_identity_missing",
         "the first decision carries an empty action"),
        ("latency-bound-admitted",
         named("latency-bound-admitted", [request("r1", 4, "admitted", latency=450)]), "deny",
         "latency_bound_admitted",
         "the authority answered in 450 ms against a 200 ms bound and the request was admitted"),
        ("unknown-outcome-released-after-expiry",
         named("unknown-outcome-released-after-expiry", unknown_released), "deny",
         "unknown_outcome_not_charged",
         "a reservation of 5 with an unknown outcome stopped being charged once it expired"),
        ("race-both-admitted",
         named("race-both-admitted", [request("r1", 6, "admitted"), request("r2", 6, "admitted")]),
         "deny", "aggregate_overspend",
         "two racing requests for 6 against 10 units were both admitted"),
        ("per-agent-limits-hold-aggregate-fails",
         named("per-agent-limits-hold-aggregate-fails", three_over, perAgentLimitUnits=5),
         "deny",
         "aggregate_overspend",
         "three subtrees each spent 4 under a per-agent limit of 5 and together "
         "spent twelve against a budget of ten"),
        ("fitting-request-refused",
         named("fitting-request-refused",
               [request("r1", 4, "admitted"), request("r2", 4, "refused", reason="budget")]),
         "deny", "fitting_request_refused",
         "the second request for 4 fitted beside the first and was refused for budget"),
        ("effect-counts-disagree", miscounted, "deny", "effect_counts_disagree",
         "the producer retained one admitted request where the decisions give two"),
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
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


if __name__ == "__main__":
    generate()
