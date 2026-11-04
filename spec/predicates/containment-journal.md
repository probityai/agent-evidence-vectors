# Predicate type: Containment Journal

Type URI: https://probityai.github.io/agent-evidence-vectors/predicate/v1/containment-journal

Receipt type URI: https://probityai.github.io/agent-evidence-vectors/predicate/v1/blast-radius-receipt

Version: 1.1 (corpus suite `containment-journal/v1`, `suiteRevision` 2)

> Status: DRAFT, issued under a self-hosted `predicateType` URI. The URIs will not move once
> a signed statement carries them. Revision 1.1 adds optional members only: a journal written
> to revision 1.0 keeps its shape, and its verdict changes only where it records a tool call by
> an agent that was isolated at the time (rule 9, `tool_call_by_isolated_agent`).

## Purpose

A defence for a system of cooperating agents says it contained a compromised agent: it cut
the agent's channels, isolated it, refused its actions, kept its retrievals inside an attested
corpus, fell back safely when its detector failed, and let the agent back only on evidence. A
cut can only be checked against the deliveries and tool calls that follow it, and a return
only against the evidence that precedes it, so every event is an entry of one hash-chained
journal, and a party who trusts neither the orchestrator nor the agents recomputes every claim
from the entries. A defence that rewrites the agents' communication graph (for example
TopoSHIELD, Huang et al. 2026, Findings of ACL 2026, doi 10.18653/v1/2026.findings-acl.426) is
one producer of such a journal.

## Canonical form and digests

The record is strict JSON: no repeated member, no NaN or Infinity, no float (integers only,
each of magnitude below 2^53), and every string printable ASCII (0x20 to 0x7E). Under these
limits `json.dumps(v, sort_keys=True, separators=(",", ":"))` is RFC 8785 output. An entry's
digest is `sha256:` and the lowercase hex SHA-256 of the entry's canonical bytes. A risk
estimate is a decimal string matching `^[0-9]\.[0-9]{6}$`. Times are `YYYY-MM-DDTHH:MM:SSZ`
and must name a real instant.

## The journal record

Required members: `contractId` (the type URI), `runId`, `agents` (sorted unique strings, at
least two), `enforcement` (`enforced`: the router refuses a message over an absent edge;
`advisory`: the topology is only stated to the agents), `messageFields` (sorted unique: the
fields the router writes on every delivered message), `claims`, `entries` (non-empty).

Optional members (revision 1.1):

- `snapshotRoot`: a digest, the Merkle root of the attested corpus the run's retrievals are
  checked against.
- `componentProfileDigest`: a digest of the component profile the run declares (the modules
  and the trust role of each). The reader checks its shape; a consumer compares it with the
  profile it expects.

`claims` members, each optional: `channelsClosed`, `restorationGated`, `defendedThroughout`,
`detectorDriven` (booleans), `responseBoundSeconds` (integer at least 0), and from revision
1.1 `retrievalAttested` (every admitted retrieval is inside `snapshotRoot`) and
`authorityChainChecked` (every tool call that ran was checked against a grant chain, whose
digest it carries).

Every entry carries `seq`, `prev` (entry 0 cites `sha256:` and 64 zeros), `at`, `event` and
exactly the event's members. Edge lists are sorted unique `[from, to]` pairs of listed agents
with `from` different from `to`.

| event | members |
|---|---|
| `topology` | `edges` |
| `delivery` | `sender`, `receiver`, `bodyDigest`, `edgeInForce`, `dropped` |
| `decision` | `basis`, `responseFunction`, `edges`, `removed`, `added`, `isolated`; with a `detector_` basis also `riskEstimates` (one per agent) and `detectorInputs` |
| `fallback` | `edges`, `failurePosture`, `error` (at most 300 characters) |
| `restart` | `agent`, `remediated`, `memoryCleared`, `configBefore`, `configAfter` |
| `assessment` | `agent`, `score` (0 to 10 or null), `availability`, `witness` |
| `restoration` | `agent`, `admitted`, `threshold`, `evidence` (entry digests), `ruleDigest` |
| `response` | `decision`, `alertAt`, `authority`, `reason`; `act` adds `actedAt` |
| `tool_call` | `agent`, `tool`; optional (1.1) `refused` (boolean), `refusalReason` (present exactly when `refused` is true), `grantChainDigest` |
| `retrieval` (1.1) | `agent`, `documentDigest`, `admitted` (boolean), `proof` (at most 64 steps, each `["left" or "right", digest]`) |

Closed vocabularies: `enforcement`, `event`, `basis` (`detector_online_label`,
`detector_no_label`, `random_rate_matched`, `ground_truth_oracle`, `fixed_schedule`,
`evidence_gate`), `responseFunction` (`restriction`, `isolation`, `restoration`),
`failurePosture` (`fail_open`, `fail_closed`), `availability` (`scored`, `no_output`,
`judge_missing`), `witness` (`SELF`, `EXTERNAL`), response `decision` (`act`, `continue`,
`escalate`) and a proof step's side (`left`, `right`).

### The inclusion path

A retrieval's `proof` hashes as RFC 9162 section 2.1 does. The leaf is SHA-256 over the byte
0x00 and the 32 bytes of `documentDigest`. Each step hashes the byte 0x01 with the step's
sibling on the side the step names (`left`: sibling first) and the node so far. The path
leads to `sha256:` and the hex of the last node. The reader checks membership in the declared
root; whether that root is the attested corpus is checked against the snapshot record, outside
the journal.

## Rules, in order

The reader names the first rule that fails; a journal that passes every rule is `allow` with
reason `containment_consistent`.

1. `contract_id_missing`; `contract_id_unknown`.
2. `record_not_canonical`.
3. `record_malformed`: a missing or unknown member, a wrong type or shape, an agent not
   listed, an unsorted list, a `refusalReason` without `refused: true` or the reverse.
4. `closed_vocabulary_violation`.
5. `chain_seq_gap`, then `chain_broken`, then `chain_time_reversed`.
6. `topology_missing`: entry 0 is not a topology, or a topology appears later.
7. The walk, holding the graph in force (entry 0's edges; each decision or fallback replaces
   it) and the agents with no outgoing edge in it (isolated). Per entry:
   - delivery: `edge_flag_mismatch`, `drop_over_present_edge`, `delivered_over_absent_edge`
     (enforced runs only);
   - decision: `edge_delta_mismatch`, `isolated_set_mismatch`,
     `topology_expansion_not_restriction`, `detector_inputs_absent`,
     `decision_not_supported_by_estimates`, `reenable_without_restoration` (when
     `restorationGated` is claimed);
   - fallback: `posture_contradicted`;
   - restart: `remediation_not_evidenced`, `restart_memory_not_cleared`;
   - assessment: `missing_score_coerced`, `score_missing_unflagged`;
   - admitted restoration: `restoration_without_evidence`, `restoration_evidence_unresolved`,
     `restoration_without_restart`, `restoration_without_assessment`,
     `restoration_evidence_not_scored`, `restoration_evidence_self_witnessed`,
     `restoration_evidence_above_threshold`;
   - response: `decision_without_authority`, `response_time_inverted`,
     `response_bound_exceeded`;
   - retrieval (1.1): `retrieval_admitted_outside_snapshot` when the retrieval is admitted,
     the run names a `snapshotRoot` or claims `retrievalAttested`, and the inclusion path does
     not lead to `snapshotRoot` (an absent root leads nowhere);
   - tool_call (1.1): `tool_call_by_isolated_agent` when the call is not refused and its agent
     has no outgoing edge in the graph in force. This holds under either enforcement: an
     advisory topology can state an isolation it cannot impose, and a journal that shows the
     isolated agent acting does not show containment.
8. Run-level claims, after the walk: `advisory_claimed_as_enforced`,
   `defended_claim_after_fail_open`, `detector_output_uninformative`, and (1.1)
   `tool_call_authority_unbound` when `authorityChainChecked` is claimed and a tool call that
   was not refused carries no `grantChainDigest`.

## The blast-radius receipt

Members: `contractId` (the receipt type URI), `journal` (`runId`, `head`: the digest of the
last entry, `entries`: the count), `subject` (a listed agent), `fromSeq` (0 up to the count
less one) and `reached` (`agents`: sorted unique, subject excluded; `deliveries`;
`toolCalls`). It is judged only beside an allowed journal. The reader recomputes the reach:
from `fromSeq` on, a delivery not dropped whose sender is tainted taints the receiver and
counts once, and a tool call by a tainted agent counts once unless it was refused (1.1). Rules
in order: `receipt_contract_id_missing`, `receipt_contract_id_unknown`, `receipt_malformed`,
`receipt_journal_mismatch`, `blast_radius_understated`, `blast_radius_overstated`; all pass is
`allow`, `blast_radius_consistent`.

## What a consistent journal does not show

That the defence recorded every event, that a call it marks refused did not run, that its
snapshot root is the attested corpus, or that its detector is any good. A journal that names
no snapshot and claims no attestation says nothing about its retrievals, and one that does not
claim `authorityChainChecked` says nothing about grant chains: a consumer that relies on either
requires the claim.

## Verifier contract

`verifier record.json --json` prints `{"decision": ..., "reason": ...}`, judging
`receipt.json` beside it when present, and exits 0 for `allow`, 1 for `deny`.

Corpus: [`corpora/vectors-containment-journal/`](../../corpora/vectors-containment-journal/README.md).
Rails: `corpusreaders/containmentjournal.go`, `packaging/agent_evidence_vectors/containmentjournal.py`.
