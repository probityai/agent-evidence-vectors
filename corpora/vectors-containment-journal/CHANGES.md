# Containment-journal suite changelog

A published `suiteRevision` is never mutated in place. A normative change to the predicate or
a case added bumps the revision, and the generator rewrites the cases byte-identically.

## suiteRevision 2 (predicate revision 1.1: retrievals, refusals, refused tool calls, grant chains)

- Release note: the blast-radius reach rule is stated and forced clause by clause; a neutral
  `refusal` event records a budget or purpose-scope refusal over an edge in force; and
  `tool_call_by_isolated_agent` refuses a tool call that ran for an isolated agent.
- Blast-radius reach, exactly: the subject is tainted from the start; from `fromSeq` on, a
  delivery the router did not drop counts when its sender is tainted and taints the receiver,
  and it counts when the receiver is already tainted; a tool call counts when its agent is
  tainted, refused or not.
- New members, all optional: the `refusal` event, the `retrieval` event with its inclusion path, the run's
  `snapshotRoot` and `componentProfileDigest`, a tool call's `refused`, `refusalReason` and
  `grantChainDigest`, and the claims `retrievalAttested` and `authorityChainChecked`.
- New rules: `refusal_over_absent_edge`, `retrieval_admitted_outside_snapshot`,
  `tool_call_by_isolated_agent` and `tool_call_authority_unbound`.
- Cases added: `allow-refusal-over-present-edge`, `reject-refusal-over-absent-edge`,
  `allow-blast-radius-counts-delivery-to-tainted-receiver`,
  `allow-blast-radius-skips-dropped-delivery`, `allow-blast-radius-from-later-entry`,
  `allow-isolated-agents-tool-call-refused` (with a receipt),
  `allow-retrieval-inside-snapshot`, `reject-retrieval-admitted-outside-snapshot`,
  `reject-tool-call-by-isolated-agent`, `reject-tool-call-authority-unbound`.
- Cases changed: none. Every revision 1 case keeps its bytes and its verdict.
- Verdict change outside the corpus: a revision 1 journal that records a tool call by an agent
  with no outgoing edge in the graph in force, not refused, was allowed and is now denied with
  `tool_call_by_isolated_agent`.

## suiteRevision 1 (predicate revision 1.0)

- The journal and the blast-radius receipt.
