"""Build the containment-journal cases byte-identically.

Every case is one multi-agent run's journal, and a receipt case adds the
blast-radius receipt beside it. Each denied case is built so the rule it names
is the first that fails; each allowed case is a control that keeps a verifier
from denying everything. Every member is synthetic: four agents named agent-a to
agent-d, message bodies that are fixed labelled strings, and configuration and
rule digests of fixed labels.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import sys
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[1] / "packaging"))

from agent_evidence_vectors import containmentjournal as reader  # noqa: E402

SUITE = reader.SUITE
T0 = datetime(2026, 11, 3, 9, 0, 0, tzinfo=UTC)
AGENTS = ["agent-a", "agent-b", "agent-c", "agent-d"]
FIELDS = ["body", "receiver", "sender"]
COMPLETE = sorted([a, b] for a in AGENTS for b in AGENTS if a != b)
Entry = dict[str, Any]
Record = dict[str, Any]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def label(text: str) -> str:
    return "sha256:" + _sha(f"synthetic containment-journal {text}".encode())


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def ts(seconds: float) -> str:
    return (T0 + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def without(edges: list[list[str]], agent: str) -> list[list[str]]:
    """The graph with every edge into or out of one agent cut."""
    return [edge for edge in edges if agent not in edge]


class Journal:
    """A run under construction: entries are appended and chained on build()."""

    def __init__(self, enforcement: str = "enforced", start: list[list[str]] | None = None,
                 **claims: Any) -> None:
        self.enforcement = enforcement
        self.claims = claims
        self.graph = copy.deepcopy(start if start is not None else COMPLETE)
        self.entries: list[Entry] = [{"event": "topology", "edges": copy.deepcopy(self.graph)}]

    def add(self, entry: Entry) -> Journal:
        self.entries.append(entry)
        return self

    def deliver(self, sender: str, receiver: str, dropped: bool | None = None) -> Journal:
        in_force = [sender, receiver] in self.graph
        return self.add({"event": "delivery", "sender": sender, "receiver": receiver,
                         "bodyDigest": label(f"message {len(self.entries)} {sender} {receiver}"),
                         "edgeInForce": in_force,
                         "dropped": (not in_force) if dropped is None else dropped})

    def decide(self, edges: list[list[str]], function: str = "isolation",
               basis: str = "ground_truth_oracle", **extra: Any) -> Journal:
        old = {tuple(e) for e in self.graph}
        new = {tuple(e) for e in edges}
        senders = {e[0] for e in new}
        entry = {"event": "decision", "basis": basis, "responseFunction": function,
                 "edges": sorted(list(e) for e in new),
                 "removed": sorted(list(e) for e in old - new),
                 "added": sorted(list(e) for e in new - old),
                 "isolated": [a for a in AGENTS if a not in senders]}
        entry.update(extra)
        self.graph = entry["edges"]
        return self.add(entry)

    def fallback(self, edges: list[list[str]], posture: str, error: str) -> Journal:
        self.graph = copy.deepcopy(edges)
        return self.add({"event": "fallback", "edges": copy.deepcopy(edges),
                         "failurePosture": posture, "error": error})

    def restart(self, agent: str, remediated: bool = True, cleared: bool = True,
                changed: bool | None = None) -> Journal:
        changed = remediated if changed is None else changed
        after = f"{agent} config remediated" if changed else f"{agent} config"
        return self.add({"event": "restart", "agent": agent, "remediated": remediated,
                         "memoryCleared": cleared, "configBefore": label(f"{agent} config"),
                         "configAfter": label(after)})

    def assess(self, agent: str, score: int | None, availability: str = "scored",
               witness: str = "EXTERNAL") -> Journal:
        return self.add({"event": "assessment", "agent": agent, "score": score,
                         "availability": availability, "witness": witness})

    def restore(self, agent: str, cites: list[Any], threshold: int = 5) -> Journal:
        # An int cite names an earlier entry by position; build() turns it into its digest.
        return self.add({"event": "restoration", "agent": agent, "admitted": True,
                         "threshold": threshold, "evidence": list(cites),
                         "ruleDigest": label("rule admit on an external score below threshold")})

    def respond(self, decision: str, alert: float, acted: float | None = None,
                authority: str = "incident-lead", reason: str = "recorded reason") -> Journal:
        entry = {"event": "response", "decision": decision, "alertAt": ts(alert),
                 "authority": authority, "reason": reason}
        if acted is not None:
            entry["actedAt"] = ts(acted)
        return self.add(entry)

    def tool(self, agent: str, tool: str, **extra: Any) -> Journal:
        return self.add({"event": "tool_call", "agent": agent, "tool": tool, **extra})

    def retrieve(self, agent: str, document: str, admitted: bool = True) -> Journal:
        return self.add({"event": "retrieval", "agent": agent, "documentDigest": document,
                         "admitted": admitted, "proof": inclusion(document)})

    def build(self, run_id: str, edit: Callable[[list[Entry]], None] | None = None,
              **top: Any) -> Record:
        """Chain the entries, apply an optional edit to the chained entries, and wrap."""
        entries: list[Entry] = []
        prev = reader.ZERO
        for index, raw in enumerate(self.entries):
            entry = copy.deepcopy(raw)
            if entry["event"] == "restoration":
                entry["evidence"] = [reader.digest(entries[i]) if isinstance(i, int) else i
                                     for i in entry["evidence"]]
            entry.update({"seq": index, "prev": prev, "at": ts(10 * index)})
            entries.append(entry)
            prev = _digest(entry)
        if edit is not None:
            edit(entries)
        record: Record = {"agents": list(AGENTS), "claims": dict(self.claims),
                          "contractId": reader.CONTRACT_ID, "enforcement": self.enforcement,
                          "entries": entries, "messageFields": list(FIELDS),
                          "runId": f"run-{run_id}"}
        record.update(top)
        return {key: value for key, value in record.items() if value is not None}


def _digest(entry: Entry) -> str:
    """The reader's digest, or a digest of the UTF-8 bytes for a non-ASCII entry."""
    try:
        return reader.digest(entry)
    except UnicodeEncodeError:
        data = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return "sha256:" + _sha(data.encode())


def rechain(entries: list[Entry]) -> None:
    """Recompute every prev, so an edit is not caught first as a broken chain."""
    for index in range(1, len(entries)):
        entries[index]["prev"] = _digest(entries[index - 1])


def edited(change: Callable[[list[Entry]], None]) -> Callable[[list[Entry]], None]:
    """An edit to chained entries that keeps the chain intact."""
    def apply(entries: list[Entry]) -> None:
        change(entries)
        rechain(entries)
    return apply


def isolate_c(journal: Journal, **extra: Any) -> Journal:
    return journal.decide(without(journal.graph, "agent-c"), **extra)


def gated_restoration() -> Journal:
    """agent-c isolated, restarted with its cause removed, scored low by an outside judge,
    admitted on both, then given its edges back."""
    journal = isolate_c(Journal(restorationGated=True))
    journal.deliver("agent-c", "agent-a").restart("agent-c").assess("agent-c", 2)
    journal.restore("agent-c", [3, 4])
    return journal.decide(COMPLETE, function="restoration", basis="evidence_gate")


def detector(estimates: list[str], inputs: list[str] | None = None) -> dict[str, Any]:
    return {"riskEstimates": dict(zip(AGENTS, estimates, strict=True)),
            "detectorInputs": inputs if inputs is not None else ["body", "sender"]}


UNIFORM = ["0.500000"] * 4
PEAKED = ["0.100000", "0.200000", "0.900000", "0.150000"]


def receipt(record: Record, subject: str = "agent-c", from_seq: int = 0,
            **changes: Any) -> Record:
    found = reader.reach(record, subject, from_seq)
    found.update(changes.pop("reached", {}))
    body: Record = {"contractId": reader.RECEIPT_CONTRACT_ID,
                    "journal": {"entries": len(record["entries"]),
                                "head": reader.digest(record["entries"][-1]),
                                "runId": record["runId"]},
                    "fromSeq": from_seq, "reached": found, "subject": subject}
    body.update(changes)
    return {key: value for key, value in body.items() if value is not None}


# The attested corpus: four labelled documents, hashed into a Merkle tree as RFC 9162 does.
DOCUMENTS = [label(f"snapshot document {n}") for n in range(4)]
OUTSIDE = label("a document the snapshot does not hold")


def _leaf(document: str) -> bytes:
    return hashlib.sha256(b"\x00" + bytes.fromhex(document[7:])).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


LEAVES = [_leaf(d) for d in DOCUMENTS]
PAIRS = [_node(LEAVES[0], LEAVES[1]), _node(LEAVES[2], LEAVES[3])]
SNAPSHOT_ROOT = "sha256:" + _node(*PAIRS).hex()
PROFILE = label("component profile: router, broker, receiver, journal")


def inclusion(document: str) -> list[list[str]]:
    """The path from a snapshot document to the root; any other document gets document 0's."""
    index = DOCUMENTS.index(document) if document in DOCUMENTS else 0
    sibling = LEAVES[index ^ 1]
    side = "left" if index % 2 else "right"
    other = "left" if index >= 2 else "right"
    return [[side, "sha256:" + sibling.hex()], [other, "sha256:" + PAIRS[1 - index // 2].hex()]]


def tool_run(enforcement: str = "enforced", refused: bool = True, bound: bool = True,
             **claims: Any) -> Journal:
    """agent-c isolated by a detector, then agent-a and agent-c each call a tool."""
    journal = isolate_c(Journal(enforcement, **claims), basis="detector_online_label",
                        **detector(PEAKED))
    journal.deliver("agent-c", "agent-a", dropped=enforcement == "enforced")
    grant = {"grantChainDigest": label("grant chain task to agent-a")} if bound else {}
    journal.tool("agent-a", "search", **grant)
    if refused:
        return journal.tool("agent-c", "search", refused=True,
                            refusalReason="no permit for an isolated agent")
    return journal.tool("agent-c", "search")


def reach_run() -> Record:
    journal = Journal()
    journal.deliver("agent-c", "agent-a").deliver("agent-a", "agent-b").tool("agent-b", "search")
    journal.deliver("agent-d", "agent-c").tool("agent-d", "fetch")
    return journal.build("reach")


Case = tuple[str, Record, Record | None, str, str, str]


def _allowed() -> list[Case]:
    ok = reader.ALLOWED_REASON
    drop = isolate_c(Journal(channelsClosed=True)).deliver("agent-c", "agent-a")
    advisory = isolate_c(Journal("advisory")).deliver("agent-c", "agent-a", dropped=False)
    fail_open = isolate_c(Journal()).fallback(COMPLETE, "fail_open", "detector raised an error")
    reach = reach_run()
    refused = tool_run(authorityChainChecked=True).build("refused",
                                                         componentProfileDigest=PROFILE)
    attested = Journal(retrievalAttested=True).retrieve("agent-a", DOCUMENTS[2])
    attested.retrieve("agent-b", OUTSIDE, admitted=False)
    return [
        ("allow-isolated-agents-tool-call-refused", refused, receipt(refused), "allow",
         reader.RECEIPT_REASON, "control: agent-c is isolated and its tool call is refused, "
         "agent-a's call names its grant chain, and the receipt counts no refused call"),
        ("allow-retrieval-inside-snapshot", attested.build("attested",
                                                           snapshotRoot=SNAPSHOT_ROOT), None,
         "allow", ok, "control: the admitted document's inclusion path leads to the snapshot "
         "root, and the document outside it is refused"),
        ("allow-enforced-drop-over-removed-edge", drop.build("drop"), None, "allow", ok,
         "control: agent-c is isolated and its next message is dropped by the router"),
        ("allow-advisory-run-no-closure-claim", advisory.build("advisory"), None, "allow", ok,
         "control: the cut is only an instruction, a message crosses it, and the run claims no "
         "closed channel"),
        ("allow-restoration-gated-on-external-score", gated_restoration().build("gated"), None,
         "allow", ok, "control: agent-c returns only after a remediating restart and an outside "
         "score below the threshold, both cited by digest"),
        ("allow-fallback-declared-fail-open", fail_open.build("fail-open"), None, "allow", ok,
         "control: the defence failed, restored every channel and named that fail_open"),
        ("allow-continue-with-authority", Journal().respond("continue", 0).build("continue"),
         None, "allow", ok, "control: a decision not to act names who decided and why"),
        ("allow-act-within-bound",
         Journal(responseBoundSeconds=600).respond("act", 10, 300).build("act"), None, "allow",
         ok, "control: the action came inside the declared bound after the alert"),
        ("allow-blast-radius-receipt-recomputes", reach, receipt(reach), "allow",
         reader.RECEIPT_REASON, "control: the receipt names exactly the agents, deliveries and "
         "tool calls agent-c reached"),
    ]


def _malformed_cases() -> list[Case]:
    base = isolate_c(Journal()).deliver("agent-c", "agent-a")
    unknown = reader.CONTRACT_ID.replace("/predicate/v1/", "/contract/v0/")
    non_ascii = isolate_c(Journal()).fallback(COMPLETE, "fail_open", "detector raised é")

    def drop_member(entries: list[Entry]) -> None:
        del entries[2]["dropped"]

    def bad_word(entries: list[Entry]) -> None:
        entries[1]["responseFunction"] = "quarantine"

    def gap(entries: list[Entry]) -> None:
        entries[2]["seq"] = 3

    def break_link(entries: list[Entry]) -> None:
        entries[2]["prev"] = label("not the previous entry")

    def reverse(entries: list[Entry]) -> None:
        entries[2]["at"] = ts(5)

    return [
        ("reject-contract-id-missing", base.build("cid", contractId=None), None, "deny",
         "contract_id_missing", "the journal names no contract"),
        ("reject-contract-id-unknown", base.build("cid2", contractId=unknown), None, "deny",
         "contract_id_unknown", "the journal names a contract version that does not exist"),
        ("reject-record-not-canonical", non_ascii.build("ascii"), None, "deny",
         "record_not_canonical", "a fallback error carries a character outside printable ASCII"),
        ("reject-record-malformed", base.build("shape", edited(drop_member)), None, "deny",
         "record_malformed", "a delivery leaves out whether it was dropped"),
        ("reject-closed-vocabulary-violation", base.build("word", edited(bad_word)), None, "deny",
         "closed_vocabulary_violation", "a decision names a response function outside the list"),
        ("reject-chain-seq-gap", base.build("gap", gap), None, "deny", "chain_seq_gap",
         "an entry's sequence number skips one"),
        ("reject-chain-broken", base.build("link", break_link), None, "deny", "chain_broken",
         "an entry's prev is not the digest of the entry before it"),
        ("reject-chain-time-reversed", base.build("time", edited(reverse)), None, "deny",
         "chain_time_reversed", "an entry is timed before the one it follows"),
        ("reject-topology-missing",
         Journal().decide(without(COMPLETE, "agent-c")).add(
             {"event": "topology", "edges": COMPLETE}).build("topo"), None, "deny",
         "topology_missing", "a second starting topology appears after a decision"),
    ]


def _delivery_cases() -> list[Case]:
    def forge(entries: list[Entry]) -> None:
        entries[2]["edgeInForce"] = True

    flag = isolate_c(Journal()).deliver("agent-c", "agent-a").build("flag", edited(forge))
    present = Journal().deliver("agent-a", "agent-b", dropped=True)
    absent = isolate_c(Journal(channelsClosed=True)).deliver("agent-c", "agent-a", dropped=False)
    return [
        ("reject-edge-flag-mismatch", flag, None, "deny", "edge_flag_mismatch",
         "a delivery says its edge was in force after the decision that cut it"),
        ("reject-drop-over-present-edge", present.build("present"), None, "deny",
         "drop_over_present_edge", "the router drops a message over an edge still in force"),
        ("reject-delivered-over-absent-edge", absent.build("absent"), None, "deny",
         "delivered_over_absent_edge", "an enforced run delivers agent-c's message over an edge "
         "the decision removed"),
    ]


def _decision_cases() -> list[Case]:
    def understate(entries: list[Entry]) -> None:
        entries[1]["removed"] = entries[1]["removed"][1:]

    def isolate_none(entries: list[Entry]) -> None:
        entries[1]["isolated"] = []

    expansion = Journal(start=without(COMPLETE, "agent-d")).decide(
        without(COMPLETE, "agent-c"), function="restriction")
    inputs = isolate_c(Journal(), basis="detector_online_label",
                       **detector(PEAKED, ["content", "name", "send"]))
    uniform = isolate_c(Journal(), basis="detector_online_label", **detector(UNIFORM))
    inert = Journal(detectorDriven=True).decide(COMPLETE, function="restriction",
                                                basis="detector_online_label",
                                                **detector(UNIFORM))
    reenable = isolate_c(Journal(restorationGated=True)).restart("agent-c")
    reenable.decide(COMPLETE, function="restoration", basis="fixed_schedule")
    return [
        ("reject-edge-delta-mismatch", isolate_c(Journal()).build("delta", edited(understate)),
         None, "deny", "edge_delta_mismatch", "the decision lists fewer removed edges than its "
         "new graph removes"),
        ("reject-isolated-set-mismatch",
         isolate_c(Journal()).build("isolated", edited(isolate_none)), None, "deny",
         "isolated_set_mismatch", "the decision says it isolated no agent while agent-c is left "
         "with no outgoing edge"),
        ("reject-topology-expansion-not-restriction", expansion.build("expand"), None, "deny",
         "topology_expansion_not_restriction", "a decision tagged restriction adds agent-d's "
         "edges, which the starting graph did not have"),
        ("reject-detector-inputs-absent", inputs.build("inputs"), None, "deny",
         "detector_inputs_absent", "the detector reads message fields the router never writes"),
        ("reject-decision-not-supported-by-estimates", uniform.build("uniform"), None, "deny",
         "decision_not_supported_by_estimates", "the detector gives every agent the same risk, "
         "and the decision isolates one of them"),
        ("reject-detector-output-uninformative", inert.build("inert"), None, "deny",
         "detector_output_uninformative", "the run claims detector-driven containment, and the "
         "detector's only decision gives every agent the same risk and cuts nothing"),
        ("reject-reenable-without-restoration", reenable.build("reenable"), None, "deny",
         "reenable_without_restoration", "agent-c gets its edges back on a timer after a "
         "restart, with no admitted restoration, in a run that claims gated restoration"),
    ]


def _recovery_cases() -> list[Case]:
    closed_claim = isolate_c(Journal()).fallback(COMPLETE, "fail_closed", "detector failed")
    defended = isolate_c(Journal(defendedThroughout=True)).fallback(
        COMPLETE, "fail_open", "detector raised an error")
    unchanged = isolate_c(Journal()).restart("agent-c", remediated=True, changed=False)
    memory = isolate_c(Journal()).restart("agent-c", remediated=False, cleared=False)
    coerced = isolate_c(Journal()).assess("agent-c", 0, availability="judge_missing")
    unflagged = isolate_c(Journal()).assess("agent-c", None)
    return [
        ("reject-posture-contradicted", closed_claim.build("posture"), None, "deny",
         "posture_contradicted", "a fallback restores every channel and calls that fail_closed"),
        ("reject-defended-claim-after-fail-open", defended.build("defended"), None, "deny",
         "defended_claim_after_fail_open", "the run claims it was defended throughout and its "
         "defence failed open"),
        ("reject-remediation-not-evidenced", unchanged.build("remedy"), None, "deny",
         "remediation_not_evidenced", "a restart says it removed the cause and the configuration "
         "digest did not change"),
        ("reject-restart-memory-not-cleared", memory.build("memory"), None, "deny",
         "restart_memory_not_cleared", "a restart leaves the agent's memory in place"),
        ("reject-missing-score-coerced", coerced.build("coerced"), None, "deny",
         "missing_score_coerced", "the judge returned nothing and the record carries a score of 0"),
        ("reject-score-missing-unflagged", unflagged.build("unflagged"), None, "deny",
         "score_missing_unflagged", "an assessment says it was scored and carries no score"),
    ]


def _restoring(steps: list[Callable[[Journal], Journal]], cites: list[Any]) -> Record:
    journal = isolate_c(Journal(restorationGated=True))
    for step in steps:
        journal = step(journal)
    journal.restore("agent-c", cites)
    return journal.build("restore")


def _restart(journal: Journal) -> Journal:
    return journal.restart("agent-c")


def _scored(score: int | None, availability: str = "scored",
            witness: str = "EXTERNAL") -> Callable[[Journal], Journal]:
    return lambda journal: journal.assess("agent-c", score, availability, witness)


def _restoration_cases() -> list[Case]:
    never = label("an entry this journal never carried")
    missing = _scored(None, "judge_missing")
    return [
        ("reject-restoration-without-evidence", _restoring([_restart, _scored(2)], []), None,
         "deny", "restoration_without_evidence", "agent-c is admitted back citing no evidence"),
        ("reject-restoration-evidence-unresolved",
         _restoring([_restart, _scored(2)], [2, never]), None, "deny",
         "restoration_evidence_unresolved", "the admission cites an entry the journal does not "
         "carry before it"),
        ("reject-restoration-without-restart", _restoring([_scored(2)], [2]), None, "deny",
         "restoration_without_restart", "the admission cites a score and no restart"),
        ("reject-restoration-without-assessment", _restoring([_restart], [2]), None, "deny",
         "restoration_without_assessment", "the admission cites a restart and no assessment"),
        ("reject-restoration-evidence-not-scored", _restoring([_restart, missing], [2, 3]),
         None, "deny", "restoration_evidence_not_scored", "the cited assessment has no score "
         "because the judge returned nothing"),
        ("reject-restoration-evidence-self-witnessed",
         _restoring([_restart, _scored(2, witness="SELF")], [2, 3]), None, "deny",
         "restoration_evidence_self_witnessed", "the cited score is the agent's own"),
        ("reject-restoration-evidence-above-threshold",
         _restoring([_restart, _scored(7)], [2, 3]), None, "deny",
         "restoration_evidence_above_threshold", "the cited score is above the rule's threshold"),
    ]


def _response_cases() -> list[Case]:
    advisory = isolate_c(Journal("advisory", channelsClosed=True))
    return [
        ("reject-decision-without-authority",
         Journal().respond("continue", 0, authority="", reason="").build("authority"), None,
         "deny", "decision_without_authority", "a decision not to act names nobody who decided "
         "it and no reason"),
        ("reject-response-time-inverted", Journal().respond("act", 300, 10).build("inverted"),
         None, "deny", "response_time_inverted", "the action is timed before the alert it "
         "answers"),
        ("reject-response-bound-exceeded",
         Journal(responseBoundSeconds=600).respond("act", 10, 20050).build("bound"), None,
         "deny", "response_bound_exceeded", "the action came hours after the alert, past the "
         "declared bound"),
        ("reject-advisory-claimed-as-enforced", advisory.build("closed"), None, "deny",
         "advisory_claimed_as_enforced", "the cut is only an instruction to the agents and the "
         "run claims the channels were closed"),
    ]


def _v11_cases() -> list[Case]:
    outside = Journal(retrievalAttested=True).retrieve("agent-a", OUTSIDE)
    return [
        ("reject-retrieval-admitted-outside-snapshot",
         outside.build("outside", snapshotRoot=SNAPSHOT_ROOT), None, "deny",
         "retrieval_admitted_outside_snapshot", "a document outside the snapshot is admitted, "
         "and its inclusion path does not lead to the root"),
        ("reject-tool-call-by-isolated-agent",
         tool_run("advisory", refused=False, bound=False, detectorDriven=True).build("isolated"),
         None, "deny", "tool_call_by_isolated_agent", "agent-c is isolated by the detector in "
         "an advisory run, and its tool call still runs"),
        ("reject-tool-call-authority-unbound",
         tool_run(bound=False, authorityChainChecked=True).build("unbound"), None, "deny",
         "tool_call_authority_unbound", "the run claims every tool call's authority chain was "
         "checked, and agent-a's call names no grant chain"),
    ]


def _receipt_cases() -> list[Case]:
    reach = reach_run()
    stale = receipt(reach)
    stale["journal"]["entries"] = len(reach["entries"]) - 1
    unknown = reader.RECEIPT_CONTRACT_ID.replace("/predicate/v1/", "/contract/v0/")
    return [
        ("reject-receipt-contract-id-missing", reach, receipt(reach, contractId=None), "deny",
         "receipt_contract_id_missing", "the receipt names no contract"),
        ("reject-receipt-contract-id-unknown", reach, receipt(reach, contractId=unknown),
         "deny", "receipt_contract_id_unknown", "the receipt names a contract version that does "
         "not exist"),
        ("reject-receipt-malformed", reach, receipt(reach, subject="agent-e"), "deny",
         "receipt_malformed", "the receipt's subject is an agent the journal does not list"),
        ("reject-receipt-journal-mismatch", reach, stale, "deny", "receipt_journal_mismatch",
         "the receipt counts one entry fewer than the journal carries"),
        ("reject-blast-radius-understated", reach,
         receipt(reach, reached={"agents": ["agent-a"]}), "deny", "blast_radius_understated",
         "the receipt leaves out agent-b, which agent-c reached through agent-a"),
        ("reject-blast-radius-overstated", reach,
         receipt(reach, reached={"agents": ["agent-a", "agent-b", "agent-d"]}), "deny",
         "blast_radius_overstated", "the receipt names agent-d, which sent to agent-c and was "
         "never reached by it"),
    ]


def cases() -> list[Case]:
    """Every case: id, journal, receipt or None, decision, reason, and what it shows."""
    return (_allowed() + _malformed_cases() + _delivery_cases() + _decision_cases()
            + _recovery_cases() + _restoration_cases() + _response_cases() + _v11_cases()
            + _receipt_cases())


def generate(root: Path = ROOT) -> dict[str, Any]:
    """Write every case and the manifest, and return the manifest."""
    if (root / "cases").exists():
        shutil.rmtree(root / "cases")
    entries = []
    for name, journal, bound, decision, reason, edit in cases():
        directory = root / "cases" / name
        directory.mkdir(parents=True)
        files = {"record.json": _json(journal)}
        if bound is not None:
            files["receipt.json"] = _json(bound)
        for file_name, data in files.items():
            (directory / file_name).write_bytes(data)
        expected = {"decision": decision, "reason": reason}
        observed = reader.verify(directory / "record.json")
        if observed != expected:
            raise SystemExit(f"{name}: the reader says {observed}, the case {expected}")
        entries.append({"edit": edit, "expected": expected,
                        "files": {k: _sha(v) for k, v in sorted(files.items())}, "id": name,
                        "path": f"cases/{name}", "retained": reader.retained(journal)})
    words = [entry["expected"]["decision"] for entry in entries]
    manifest = {
        "contractId": reader.CONTRACT_ID,
        "corpusDigest": _sha(_json(entries)),
        "counts": {word: words.count(word) for word in sorted(set(words))},
        "receiptContractId": reader.RECEIPT_CONTRACT_ID,
        "revision": reader.REVISION,
        "suite": SUITE,
        "synthetic": True,
        "verifierContract": ("verifier record.json --json, judging receipt.json beside it when "
                             "present; exit 0 allow, 1 deny"),
        "vectors": entries,
    }
    (root / "MANIFEST.json").write_bytes(_json(manifest))
    return manifest


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


if __name__ == "__main__":
    generate()
