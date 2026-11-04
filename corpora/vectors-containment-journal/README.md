# Containment-journal vectors

Cases for `containment-journal/v1` and `blast-radius-receipt/v1`: whether a multi-agent
defence contained what it says it contained. A defence that rewrites the agents'
communication graph (TopoSHIELD, Huang et al. 2026, Findings of ACL 2026,
doi 10.18653/v1/2026.findings-acl.426, is one example) reports that it cut a
compromised agent's channels, isolated it, fell back safely when its detector failed and
let the agent back only on evidence. A cut can only be checked against the deliveries
that follow it, and a return only against the evidence that precedes it, so every event
is an entry of one hash-chained journal.

- Journal: `https://probityai.github.io/agent-evidence-vectors/predicate/v1/containment-journal`
- Receipt: `https://probityai.github.io/agent-evidence-vectors/predicate/v1/blast-radius-receipt`

For anyone who builds, evaluates or audits a defence for cooperating agents and wants a
reader that recomputes its containment claims from the run itself.

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-containment-journal
python3 corpora/vectors-containment-journal/check_vectors.py --verifier './verifier'
```

A verifier takes `record.json --json`, judges `receipt.json` beside it when present,
prints `{"decision": ..., "reason": ...}` and exits 0 for `allow`, 1 for `deny`.

## The journal

Entries are `topology`, `delivery`, `decision`, `fallback`, `restart`, `assessment`,
`restoration`, `response` and `tool_call`. Each carries `seq`, `prev` (the digest of the
entry before) and `at`. An entry's digest is `sha256:` and the hex SHA-256 of
`json.dumps(entry, sort_keys=True, separators=(",", ":"))`, which is RFC 8785 output
because the record carries integers only and printable ASCII strings only. The journal
also states the defence's claims: `channelsClosed`, `restorationGated`,
`defendedThroughout`, `detectorDriven` and `responseBoundSeconds`.

## What the cases force

The reader names the first rule that fails, in this order:

1. `contract_id_missing`, `contract_id_unknown`.
2. `record_not_canonical` (a float, a non-ASCII character, a repeated member).
3. `record_malformed`, then `closed_vocabulary_violation`.
4. The chain: `chain_seq_gap`, `chain_broken`, `chain_time_reversed`, then
   `topology_missing` (the run does not open with its graph).
5. The walk, holding the graph in force. Deliveries: `edge_flag_mismatch`,
   `drop_over_present_edge`, `delivered_over_absent_edge` (an enforced router let a
   message through a cut edge). Decisions: `edge_delta_mismatch`,
   `isolated_set_mismatch`, `topology_expansion_not_restriction`,
   `detector_inputs_absent` (the detector reads fields the router never writes),
   `decision_not_supported_by_estimates` (equal risk for every agent, yet one is cut),
   `reenable_without_restoration`. Fallbacks: `posture_contradicted`. Restarts:
   `remediation_not_evidenced`, `restart_memory_not_cleared`. Assessments:
   `missing_score_coerced`, `score_missing_unflagged`. Admitted restorations:
   `restoration_without_evidence`, `restoration_evidence_unresolved`,
   `restoration_without_restart`, `restoration_without_assessment`,
   `restoration_evidence_not_scored`, `restoration_evidence_self_witnessed`,
   `restoration_evidence_above_threshold`. Responses: `decision_without_authority`,
   `response_time_inverted`, `response_bound_exceeded`.
6. The claims: `advisory_claimed_as_enforced`, `defended_claim_after_fail_open`,
   `detector_output_uninformative`.

A journal that passes is `allow`, `containment_consistent`. A receipt is judged only
beside an allowed journal: `receipt_contract_id_missing`, `receipt_contract_id_unknown`,
`receipt_malformed`, `receipt_journal_mismatch`, `blast_radius_understated`,
`blast_radius_overstated`. The reader recomputes the reach from the journal: from
`fromSeq` on, every delivery the router did not drop carries taint from sender to
receiver, and every tool call by a tainted agent counts. A matching receipt is `allow`,
`blast_radius_consistent`. Counts are in `MANIFEST.json`.

## Synthetic, and labelled so

Every member is synthetic. Agents are `agent-a` to `agent-d`, message bodies and
configuration digests are fixed labels, and no member records a real system, run or
measurement. The manifest says so in `synthetic`.

## What it does not test

Whether the defence works. A consistent journal shows that its claims follow from the
events it records, not that it recorded every event or that its detector is any good.
Regenerate with `python3 corpora/vectors-containment-journal/gen_vectors.py`.
