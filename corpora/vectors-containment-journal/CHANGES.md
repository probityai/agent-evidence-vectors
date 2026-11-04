# Containment-journal suite changelog

A published `suiteRevision` is never mutated in place. A normative change to the predicate or
a case added bumps the revision, and the generator rewrites the cases byte-identically.

## suiteRevision 2 (predicate revision 1.1: retrievals, refused tool calls, grant chains)

- New members, all optional: the `retrieval` event with its inclusion path, the run's
  `snapshotRoot` and `componentProfileDigest`, a tool call's `refused`, `refusalReason` and
  `grantChainDigest`, and the claims `retrievalAttested` and `authorityChainChecked`.
- New rules: `retrieval_admitted_outside_snapshot`, `tool_call_by_isolated_agent` and
  `tool_call_authority_unbound`. A refused tool call no longer counts toward a blast radius.
- Cases added: `allow-isolated-agents-tool-call-refused` (with a receipt),
  `allow-retrieval-inside-snapshot`, `reject-retrieval-admitted-outside-snapshot`,
  `reject-tool-call-by-isolated-agent`, `reject-tool-call-authority-unbound`.
- Cases changed: none. Every revision 1 case keeps its bytes and its verdict.
- Verdict change outside the corpus: a revision 1 journal that records a tool call by an agent
  with no outgoing edge in the graph in force, not refused, was allowed and is now denied with
  `tool_call_by_isolated_agent`.

## suiteRevision 1 (predicate revision 1.0)

- The journal and the blast-radius receipt.
