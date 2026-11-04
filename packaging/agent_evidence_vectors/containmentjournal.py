"""Judge a multi-agent containment journal, and the blast-radius receipt beside it.

A defence for a system of cooperating agents says it contained a compromised
agent: it cut the agent's channels, isolated it, fell back safely when its own
detector failed, and let the agent back only on evidence. Each of those is a
claim a party who trusts neither the orchestrator nor the agents should be able
to recompute. A defence that rewrites the agents' communication graph (for
example TopoSHIELD, Huang et al. 2026, Findings of ACL 2026,
doi 10.18653/v1/2026.findings-acl.426) can only be checked against the
deliveries that follow each cut and the evidence that precedes each return, so
every such event is an entry of one hash-chained journal:

- ``topology``: the communication graph the run starts with;
- ``delivery``: one agent-to-agent message, whether the edge was in force and
  whether the router dropped it;
- ``decision``: a containment decision, with the new graph, the edges removed
  and added, the agents left with no outgoing edge, the label or input that
  steered it (``basis``) and, for a detector, its per-agent risk estimates and
  the message fields it reads;
- ``fallback``: the defence failed and replaced the graph, with the failure
  posture it declares;
- ``restart``, ``assessment``, ``restoration``: an agent restarted, its output
  assessed, and the decision to let it back, citing the earlier entries it
  rests on by digest;
- ``response``: a decision to act, continue or escalate after an alert;
- ``tool_call``: an agent called a tool.

The journal also states the defence's claims (``channelsClosed``,
``restorationGated``, ``defendedThroughout``, ``detectorDriven``,
``responseBoundSeconds``). The reader checks the rules below in order and names
the first that fails; a journal that passes every rule is ``allow`` with reason
``containment_consistent``. The checks, in order: the contract identifier; the
canonical form (integers only, printable ASCII strings, no repeated member);
the shape; the closed vocabularies; the chain (``seq`` contiguous, each
``prev`` the digest of the entry before, times in order); the starting
topology; the walk over the entries (each delivery against the graph in force,
each decision's deltas and estimates, each fallback's posture, each restart's
configuration digests, each assessment's availability, each admitted
restoration's cited evidence, each response's authority and timing); and the
run-level claims. The reason codes are the tuple ``CHECKS``.

An entry's digest is ``sha256:`` and the hex SHA-256 of the entry's canonical
bytes. Under the canonical-form rule those bytes are
``json.dumps(entry, sort_keys=True, separators=(",", ":"))``, which is RFC 8785
output for integer-only, ASCII-only values; that is why the rule exists.

When ``receipt.json`` sits beside the journal, it is a blast-radius receipt:
the agents a subject agent reached from one entry on, through deliveries the
router did not drop, and the deliveries and tool calls that reach involved. The
receipt is checked only when the journal is allowed, and the reader recomputes
the reach from the journal alone. A matching receipt is ``allow`` with reason
``blast_radius_consistent``.

The external-verifier contract: ``<verifier> <case-dir>/record.json --json``
prints one JSON object carrying ``decision`` and ``reason``, judging
``receipt.json`` too when it is present, and exits 0 for ``allow`` and 1 for
``deny``.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from agent_evidence_vectors.monitorcoverage import (
    ALLOW,
    DENY,
    EXIT_FOR,
    check_corpus,
    cli,
    run_corpus,
)

SUITE = "containment-journal/v1"
_BASE = "https://probityai.github.io/agent-evidence-vectors/predicate/v1/"
CONTRACT_ID = _BASE + "containment-journal"
RECEIPT_CONTRACT_ID = _BASE + "blast-radius-receipt"
ALLOWED_REASON = "containment_consistent"
RECEIPT_REASON = "blast_radius_consistent"
ZERO = "sha256:" + "0" * 64
CHECKS = (
    "contract_id_missing", "contract_id_unknown", "record_not_canonical", "record_malformed",
    "closed_vocabulary_violation", "chain_seq_gap", "chain_broken", "chain_time_reversed",
    "topology_missing", "edge_flag_mismatch", "drop_over_present_edge",
    "delivered_over_absent_edge", "edge_delta_mismatch", "isolated_set_mismatch",
    "topology_expansion_not_restriction", "detector_inputs_absent",
    "decision_not_supported_by_estimates", "reenable_without_restoration",
    "posture_contradicted", "remediation_not_evidenced", "restart_memory_not_cleared",
    "missing_score_coerced", "score_missing_unflagged", "restoration_without_evidence",
    "restoration_evidence_unresolved", "restoration_without_restart",
    "restoration_without_assessment", "restoration_evidence_not_scored",
    "restoration_evidence_self_witnessed", "restoration_evidence_above_threshold",
    "decision_without_authority", "response_time_inverted", "response_bound_exceeded",
    "advisory_claimed_as_enforced", "defended_claim_after_fail_open",
    "detector_output_uninformative",
)
RECEIPT_CHECKS = (
    "receipt_contract_id_missing", "receipt_contract_id_unknown", "receipt_malformed",
    "receipt_journal_mismatch", "blast_radius_understated", "blast_radius_overstated",
)
CLOSED = {
    "enforcement": ("advisory", "enforced"),
    "event": ("topology", "delivery", "decision", "fallback", "restart", "assessment",
              "restoration", "response", "tool_call"),
    "basis": ("detector_online_label", "detector_no_label", "random_rate_matched",
              "ground_truth_oracle", "fixed_schedule", "evidence_gate"),
    "responseFunction": ("restriction", "isolation", "restoration"),
    "failurePosture": ("fail_open", "fail_closed"),
    "availability": ("scored", "no_output", "judge_missing"),
    "witness": ("SELF", "EXTERNAL"),
    "decision": ("act", "continue", "escalate"),
}
# The members each event carries, past seq, prev, at and event.
EVENT_MEMBERS = {
    "topology": {"edges": "edges"},
    "delivery": {"sender": "agent", "receiver": "agent", "bodyDigest": "digest",
                 "edgeInForce": "bool", "dropped": "bool"},
    "decision": {"basis": "word", "responseFunction": "word", "edges": "edges",
                 "removed": "edges", "added": "edges", "isolated": "agents"},
    "fallback": {"edges": "edges", "failurePosture": "word", "error": "text"},
    "restart": {"agent": "agent", "remediated": "bool", "memoryCleared": "bool",
                "configBefore": "digest", "configAfter": "digest"},
    "assessment": {"agent": "agent", "score": "score", "availability": "word",
                   "witness": "word"},
    "restoration": {"agent": "agent", "admitted": "bool", "threshold": "score10",
                    "evidence": "digests", "ruleDigest": "digest"},
    "response": {"decision": "word", "alertAt": "time", "authority": "text",
                 "reason": "text"},
    "tool_call": {"agent": "agent", "tool": "text"},
}
DETECTOR_MEMBERS = {"riskEstimates": "estimates", "detectorInputs": "words"}
CLAIM_KINDS = {"channelsClosed": "bool", "restorationGated": "bool",
               "defendedThroughout": "bool", "detectorDriven": "bool",
               "responseBoundSeconds": "count"}
TOP_MEMBERS = {"contractId", "runId", "agents", "enforcement", "messageFields", "claims",
               "entries"}
__all__ = ["ALLOW", "CONTRACT_ID", "DENY", "EXIT_FOR", "RECEIPT_CONTRACT_ID", "SUITE",
           "check", "digest", "main", "verify"]
_HERE = Path(__file__).resolve().parent
ROOT = (_HERE / "corpora" / "vectors-containment-journal" if (_HERE / "corpora").exists()
        else _HERE.parents[1] / "corpora" / "vectors-containment-journal")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_DECIMAL = re.compile(r"[0-9]\.[0-9]{6}")
_LIMIT = 2**53

Record = dict[str, Any]


class Refusal(Exception):
    """A rule the record fails; its argument is the reason code."""


def canonical(value: Any) -> bytes:
    """RFC 8785 bytes of an integer-only, ASCII-only JSON value."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def digest(entry: Record) -> str:
    """The digest a later entry cites: sha256 over the entry's canonical bytes."""
    return "sha256:" + hashlib.sha256(canonical(entry)).hexdigest()


def _strict_load(path: Path) -> tuple[Any, bool]:
    """Parse JSON, reporting rather than hiding anything outside the canonical subset."""
    flags = {"bad": False}

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        keys = [key for key, _ in items]
        if len(set(keys)) != len(keys):
            flags["bad"] = True
        return dict(items)

    def bad_number(_: str) -> int:
        flags["bad"] = True
        return 0

    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs,
                       parse_float=bad_number, parse_constant=bad_number)
    return value, flags["bad"] or not _canonical_values(value)


def _canonical_values(value: Any) -> bool:
    if isinstance(value, bool) or value is None:
        return True
    if isinstance(value, int):
        return -_LIMIT < value < _LIMIT
    if isinstance(value, str):
        return all(0x20 <= ord(char) <= 0x7E for char in value)
    if isinstance(value, list):
        return all(_canonical_values(item) for item in value)
    if isinstance(value, dict):
        return all(_canonical_values(key) and _canonical_values(item)
                   for key, item in value.items())
    return False


def _at(stamp: str) -> datetime:
    return datetime.fromisoformat(stamp.replace("Z", "+00:00"))


def _is_time(value: Any) -> bool:
    """A time in the record's one spelling that names a real instant (no 30 February)."""
    if not isinstance(value, str) or _TIME.fullmatch(value) is None:
        return False
    try:
        _at(value)
    except ValueError:
        return False
    return True


def _sorted_unique(items: list[Any]) -> bool:
    return all(a < b for a, b in zip(items, items[1:], strict=False))


def _integer(value: Any, low: int, high: int | None = None) -> bool:
    return (isinstance(value, int) and not isinstance(value, bool) and value >= low
            and (high is None or value <= high))


def _listing(kind: str, value: Any, agents: set[str]) -> bool:
    """A sorted list without repeats, every item of the item kind."""
    return (isinstance(value, list) and all(_shape_ok(kind, v, agents) for v in value)
            and _sorted_unique(value))


def _edge(value: Any, agents: set[str]) -> bool:
    return (isinstance(value, list) and len(value) == 2 and value[0] != value[1]
            and all(_shape_ok("agent", end, agents) for end in value))


def _estimates(value: Any, agents: set[str]) -> bool:
    return (isinstance(value, dict) and set(value) == agents
            and all(isinstance(v, str) and _DECIMAL.fullmatch(v) for v in value.values()))


# Each member kind, as a predicate over the value and the run's agents.
_SHAPES: dict[str, Any] = {
    "bool": lambda v, _: isinstance(v, bool),
    "word": lambda v, _: isinstance(v, str),
    "text": lambda v, _: isinstance(v, str) and len(v) <= 300,
    "count": lambda v, _: _integer(v, 0),
    "score": lambda v, _: v is None or _integer(v, 0, 10),
    "score10": lambda v, _: _integer(v, 0, 10),
    "agent": lambda v, agents: isinstance(v, str) and v in agents,
    "digest": lambda v, _: isinstance(v, str) and _DIGEST.fullmatch(v) is not None,
    "time": lambda v, _: _is_time(v),
    "digests": lambda v, agents: isinstance(v, list)
    and all(_shape_ok("digest", item, agents) for item in v),
    "agents": lambda v, agents: _listing("agent", v, agents),
    "words": lambda v, agents: _listing("word", v, agents),
    "edges": lambda v, agents: isinstance(v, list)
    and all(_edge(item, agents) for item in v) and _sorted_unique(v),
    "estimates": _estimates,
}


def _shape_ok(kind: str, value: Any, agents: set[str]) -> bool:
    """Whether one member has the shape its kind names (closed words checked later)."""
    return bool(_SHAPES[kind](value, agents))


def _entry_malformed(entry: Any, agents: set[str]) -> bool:
    if not isinstance(entry, dict):
        return True
    base = {"seq": "count", "prev": "digest", "at": "time", "event": "word"}
    if any(name not in entry or not _shape_ok(kind, entry[name], agents)
           for name, kind in base.items()):
        return True
    members = dict(EVENT_MEMBERS.get(entry["event"], {}))
    if entry["event"] == "decision" and str(entry.get("basis", "")).startswith("detector_"):
        members.update(DETECTOR_MEMBERS)
    if entry["event"] == "response" and entry.get("decision") == "act":
        members["actedAt"] = "time"
    if entry["event"] in EVENT_MEMBERS and set(entry) != set(base) | set(members):
        return True
    return any(not _shape_ok(kind, entry[name], agents) for name, kind in members.items())


def _malformed(record: Record) -> bool:
    if set(record) != TOP_MEMBERS:
        return True
    agents = record["agents"]
    if (not isinstance(agents, list) or len(agents) < 2
            or not all(isinstance(a, str) for a in agents) or not _sorted_unique(agents)):
        return True
    names = set(agents)
    claims = record["claims"]
    if (not isinstance(record["runId"], str) or not isinstance(record["enforcement"], str)
            or not _shape_ok("words", record["messageFields"], names)
            or not isinstance(claims, dict) or not set(claims) <= set(CLAIM_KINDS)
            or any(not _shape_ok(CLAIM_KINDS[k], v, names) for k, v in claims.items())):
        return True
    entries = record["entries"]
    return (not isinstance(entries, list) or not entries
            or any(_entry_malformed(entry, names) for entry in entries))


def _closed_violation(record: Record) -> bool:
    if record["enforcement"] not in CLOSED["enforcement"]:
        return True
    for entry in record["entries"]:
        for member in ("event", "basis", "responseFunction", "failurePosture", "availability",
                       "witness", "decision"):
            if member in entry and entry[member] not in CLOSED[member]:
                return True
    return False


def _chain_broken(entries: list[Record]) -> bool:
    expected = ZERO
    for entry in entries:
        if entry["prev"] != expected:
            return True
        expected = digest(entry)
    return False


def _chain_failure(entries: list[Record], skip: frozenset[str]) -> str | None:
    """The first chain rule the entries fail, passing over any rule a test switched off."""
    rules = (
        ("chain_seq_gap",
         lambda: any(entry["seq"] != index for index, entry in enumerate(entries))),
        ("chain_broken", lambda: _chain_broken(entries)),
        ("chain_time_reversed",
         lambda: any(_at(b["at"]) < _at(a["at"]) for a, b in zip(entries, entries[1:],
                                                                 strict=False))),
        ("topology_missing",
         lambda: entries[0]["event"] != "topology"
         or any(e["event"] == "topology" for e in entries[1:])),
    )
    return next((name for name, failed in rules if name not in skip and failed()), None)


def _edges(value: list[list[str]]) -> set[tuple[str, str]]:
    return {(edge[0], edge[1]) for edge in value}


def _listed(edges: set[tuple[str, str]]) -> list[list[str]]:
    return [list(edge) for edge in sorted(edges)]


def _isolated(agents: list[str], edges: set[tuple[str, str]]) -> list[str]:
    senders = {edge[0] for edge in edges}
    return [agent for agent in agents if agent not in senders]


class _Walk:
    """The state the entry walk holds: the graph in force and what each agent last saw."""

    def __init__(self, record: Record, skip: frozenset[str] = frozenset()) -> None:
        self.record = record
        self.skip = skip
        self.agents: list[str] = record["agents"]
        self.claims: dict[str, Any] = record["claims"]
        self.entries: list[Record] = record["entries"]
        self.graph = _edges(self.entries[0]["edges"])
        self.isolated_at = {agent: 0 for agent in _isolated(self.agents, self.graph)}
        self.admitted: dict[str, list[int]] = {}
        self.by_digest = {digest(entry): index for index, entry in enumerate(self.entries)}

    def run(self) -> None:
        for index, entry in enumerate(self.entries[1:], start=1):
            getattr(self, "_" + entry["event"])(index, entry)

    def fail(self, name: str) -> None:
        """Refuse with this rule, unless a test has switched the rule off."""
        if name not in self.skip:
            raise Refusal(name)

    def _replace(self, index: int, edges: set[tuple[str, str]]) -> None:
        self.graph = edges
        now = set(_isolated(self.agents, edges))
        self.isolated_at = {agent: self.isolated_at.get(agent, index) for agent in now}

    def _delivery(self, _: int, entry: Record) -> None:
        in_force = (entry["sender"], entry["receiver"]) in self.graph
        if entry["edgeInForce"] != in_force:
            self.fail("edge_flag_mismatch")
        if entry["dropped"] and in_force:
            self.fail("drop_over_present_edge")
        if not entry["dropped"] and not in_force and self.record["enforcement"] == "enforced":
            self.fail("delivered_over_absent_edge")

    def _decision(self, index: int, entry: Record) -> None:
        new = _edges(entry["edges"])
        if (entry["removed"] != _listed(self.graph - new)
                or entry["added"] != _listed(new - self.graph)):
            self.fail("edge_delta_mismatch")
        if entry["isolated"] != _isolated(self.agents, new):
            self.fail("isolated_set_mismatch")
        if entry["responseFunction"] in ("restriction", "isolation") and entry["added"]:
            self.fail("topology_expansion_not_restriction")
        if entry["basis"].startswith("detector_"):
            if not set(entry["detectorInputs"]) <= set(self.record["messageFields"]):
                self.fail("detector_inputs_absent")
            if (len(set(entry["riskEstimates"].values())) == 1
                    and (entry["removed"] or entry["isolated"])):
                self.fail("decision_not_supported_by_estimates")
        if entry["responseFunction"] == "restoration" and self.claims.get("restorationGated"):
            returned = set(self.isolated_at) - set(entry["isolated"])
            for agent in sorted(returned):
                since = self.isolated_at[agent]
                if not any(since < at < index for at in self.admitted.get(agent, [])):
                    self.fail("reenable_without_restoration")
        self._replace(index, new)

    def _fallback(self, index: int, entry: Record) -> None:
        new = _edges(entry["edges"])
        complete = {(a, b) for a in self.agents for b in self.agents if a != b}
        if new == complete and entry["failurePosture"] != "fail_open":
            self.fail("posture_contradicted")
        if new == self.graph and entry["failurePosture"] != "fail_closed":
            self.fail("posture_contradicted")
        self._replace(index, new)

    def _restart(self, _: int, entry: Record) -> None:
        if entry["remediated"] != (entry["configBefore"] != entry["configAfter"]):
            self.fail("remediation_not_evidenced")
        if not entry["memoryCleared"]:
            self.fail("restart_memory_not_cleared")

    def _assessment(self, _: int, entry: Record) -> None:
        if entry["availability"] != "scored" and entry["score"] is not None:
            self.fail("missing_score_coerced")
        if entry["availability"] == "scored" and entry["score"] is None:
            self.fail("score_missing_unflagged")

    def _restoration(self, index: int, entry: Record) -> None:
        if not entry["admitted"]:
            return
        if not entry["evidence"]:
            self.fail("restoration_without_evidence")
        cited = []
        for item in entry["evidence"]:
            at = self.by_digest.get(item)
            if at is None or at >= index:
                self.fail("restoration_evidence_unresolved")
            cited.append(self.entries[at])
        agent = entry["agent"]
        if not any(c["event"] == "restart" and c["agent"] == agent for c in cited):
            self.fail("restoration_without_restart")
        scores = [c for c in cited if c["event"] == "assessment" and c["agent"] == agent]
        if not scores:
            self.fail("restoration_without_assessment")
        latest = max(scores, key=lambda c: c["seq"])
        if latest["score"] is None:
            self.fail("restoration_evidence_not_scored")
        if latest["witness"] == "SELF":
            self.fail("restoration_evidence_self_witnessed")
        if latest["score"] >= entry["threshold"]:
            self.fail("restoration_evidence_above_threshold")
        self.admitted.setdefault(agent, []).append(index)

    def _response(self, _: int, entry: Record) -> None:
        if entry["decision"] != "act":
            if not entry["authority"] or not entry["reason"]:
                self.fail("decision_without_authority")
            return
        delay = (_at(entry["actedAt"]) - _at(entry["alertAt"])).total_seconds()
        if delay < 0:
            self.fail("response_time_inverted")
        bound = self.claims.get("responseBoundSeconds")
        if bound is not None and delay > bound:
            self.fail("response_bound_exceeded")

    def _tool_call(self, _: int, __: Record) -> None:
        return


def _claims_failure(record: Record, skip: frozenset[str]) -> str | None:
    claims, entries = record["claims"], record["entries"]
    detector = [e for e in entries if e["event"] == "decision"
                and e["basis"].startswith("detector_")]
    failures = {
        "advisory_claimed_as_enforced": bool(claims.get("channelsClosed"))
        and record["enforcement"] == "advisory",
        "defended_claim_after_fail_open": bool(claims.get("defendedThroughout")) and any(
            e["event"] == "fallback" and e["failurePosture"] == "fail_open" for e in entries),
        "detector_output_uninformative": bool(claims.get("detectorDriven")) and not any(
            len(set(e["riskEstimates"].values())) > 1 for e in detector),
    }
    return next((name for name, failed in failures.items() if failed and name not in skip),
                None)


def judge_journal(record: Any, not_canonical: bool,
                  skip: frozenset[str] = frozenset()) -> str | None:
    """The first rule the journal fails, or None when it passes every rule."""
    early = (
        ("contract_id_missing", lambda: not isinstance(record, dict) or "contractId" not in record),
        ("contract_id_unknown", lambda: record["contractId"] != CONTRACT_ID),
        ("record_not_canonical", lambda: not_canonical),
        ("record_malformed", lambda: _malformed(record)),
        ("closed_vocabulary_violation", lambda: _closed_violation(record)),
    )
    for name, failed in early:
        if name not in skip and failed():
            return name
    failure = _chain_failure(record["entries"], skip)
    if failure:
        return failure
    try:
        _Walk(record, skip).run()
    except Refusal as refusal:
        return str(refusal)
    return _claims_failure(record, skip)


def reach(record: Record, subject: str, from_seq: int) -> dict[str, Any]:
    """The agents, deliveries and tool calls a subject reached from one entry on."""
    tainted, deliveries, tools = {subject}, 0, 0
    for entry in record["entries"][from_seq:]:
        if entry["event"] == "delivery" and not entry["dropped"] and entry["sender"] in tainted:
            tainted.add(entry["receiver"])
            deliveries += 1
        elif entry["event"] == "tool_call" and entry["agent"] in tainted:
            tools += 1
    return {"agents": sorted(tainted - {subject}), "deliveries": deliveries, "toolCalls": tools}


def _receipt_malformed(receipt: Record, record: Record) -> bool:
    agents = set(record["agents"])
    if set(receipt) != {"contractId", "journal", "subject", "fromSeq", "reached"}:
        return True
    journal, reached = receipt["journal"], receipt["reached"]
    if (not isinstance(journal, dict) or set(journal) != {"runId", "head", "entries"}
            or not isinstance(journal["runId"], str)
            or not _shape_ok("digest", journal["head"], agents)
            or not _shape_ok("count", journal["entries"], agents)):
        return True
    if (not _shape_ok("agent", receipt["subject"], agents)
            or not _shape_ok("count", receipt["fromSeq"], agents)
            or receipt["fromSeq"] >= len(record["entries"])):
        return True
    return (not isinstance(reached, dict)
            or set(reached) != {"agents", "deliveries", "toolCalls"}
            or not _shape_ok("agents", reached["agents"], agents)
            or receipt["subject"] in reached["agents"]
            or not _shape_ok("count", reached["deliveries"], agents)
            or not _shape_ok("count", reached["toolCalls"], agents))


def _understated(found: dict[str, Any], claimed: dict[str, Any]) -> bool:
    return (not set(found["agents"]) <= set(claimed["agents"])
            or claimed["deliveries"] < found["deliveries"]
            or claimed["toolCalls"] < found["toolCalls"])


def judge_receipt(receipt: Any, not_canonical: bool, record: Record,
                  skip: frozenset[str] = frozenset()) -> str | None:
    """The first rule the receipt fails against an allowed journal, or None."""
    entries = record["entries"]

    def found() -> dict[str, Any]:
        return reach(record, receipt["subject"], receipt["fromSeq"])

    rules = (
        ("receipt_contract_id_missing",
         lambda: not isinstance(receipt, dict) or "contractId" not in receipt),
        ("receipt_contract_id_unknown",
         lambda: receipt.get("contractId") != RECEIPT_CONTRACT_ID),
        ("receipt_malformed", lambda: not_canonical or _receipt_malformed(receipt, record)),
        ("receipt_journal_mismatch",
         lambda: receipt["journal"] != {"runId": record["runId"], "head": digest(entries[-1]),
                                        "entries": len(entries)}),
        ("blast_radius_understated", lambda: _understated(found(), receipt["reached"])),
        ("blast_radius_overstated", lambda: receipt["reached"] != found()),
    )
    return next((name for name, failed in rules if name not in skip and failed()), None)


def _answer(reason: str | None, allowed: str) -> dict[str, str]:
    if reason is None:
        return {"decision": ALLOW, "reason": allowed}
    return {"decision": DENY, "reason": reason}


_SKIPPED_PAST = (KeyError, TypeError, AttributeError, ValueError, IndexError)


def verify(record_path: Path, skip: frozenset[str] = frozenset()) -> dict[str, str]:
    """The reference reader's decision and reason for one journal and its receipt."""
    record, not_canonical = _strict_load(record_path)
    try:
        reason = judge_journal(record, not_canonical, skip)
    except _SKIPPED_PAST:
        if not skip:
            raise
        reason = None  # a structural rule a test switched off let a malformed record through
    receipt_path = record_path.parent / "receipt.json"
    if reason is not None or not receipt_path.is_file():
        return _answer(reason, ALLOWED_REASON)
    receipt, receipt_bad = _strict_load(receipt_path)
    try:
        reason = judge_receipt(receipt, receipt_bad, record, skip)
    except _SKIPPED_PAST:
        if not skip:
            raise
        reason = None  # as above, for a receipt rule a test switched off
    return _answer(reason, RECEIPT_REASON)


def retained(record: Record) -> dict[str, Any]:
    """What a verifier keeps from a journal: its run, enforcement and event counts."""
    entries = record.get("entries") if isinstance(record, dict) else None
    events = [e.get("event") for e in entries if isinstance(e, dict)] if isinstance(
        entries, list) else []
    return {"enforcement": record.get("enforcement") if isinstance(record, dict) else None,
            "entries": len(events),
            "events": {name: events.count(name) for name in sorted(set(map(str, events)))}}


def iter_rules() -> Iterator[str]:
    """Every reason code the corpus can name, journal rules first."""
    yield from CHECKS
    yield from RECEIPT_CHECKS


def check(
    verifier: str | list[str] | None = None, root: Path = ROOT,
    skip: frozenset[str] = frozenset(),
) -> tuple[int, list[str]]:
    """Check every case, through the named verifier or the reference reader."""
    return check_corpus(root, SUITE, verify, retained, verifier, skip)


def run(root: str, verifier: list[str] | None, report_path: str, rail_note: str) -> int:
    """Judge the corpus and write the report the package's other suites write."""
    return run_corpus(SUITE, check, root, verifier, report_path, rail_note)


def main(argv: list[str] | None = None) -> int:
    return cli(argv, __doc__, verify, check, ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
