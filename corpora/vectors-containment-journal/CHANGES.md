# Containment-journal suite changelog

A published `suiteRevision` is never mutated in place. A normative change to the predicate or
a case added bumps the revision, and the generator rewrites the cases byte-identically.

## suiteRevision 4 (predicate revision 1.3: refusals take the shared registry, and a refused call reaches nothing)

- A refusal's `reasonCode` is any code of the refusal-code registry (`refusal_codes.json`, shipped
  with the package and the Go readers), where revisions 1.1 and 1.2 registered four. The four
  keep their meaning. A reader still denies a code it does not know, a code in another form and a
  code with a detail, all as `closed_vocabulary_violation`.
- A refused tool call is no reach: the blast-radius reach skips a `tool_call` whose `refused` is
  true, in both readers. A refused call did not run, so the receipt names only calls that ran.
- Cases added: `allow-refusal-registry-code-<family>` for each of the 14 registry families
  (approval, authority, delegation, gateway, governance, grants, identity, journal, key, marker,
  mesh, possession, revocation, singleuse), `reject-refusal-unknown-code`,
  `reject-refusal-code-kebab`, `reject-refusal-code-carries-detail` and
  `reject-blast-radius-counts-refused-tool-call` (the receipt that revision 3 allowed).
- Cases changed: `allow-isolated-agents-tool-call-refused`: its receipt counted the refused call
  (`toolCalls` 1) and now counts none (`toolCalls` 0). Its journal keeps its bytes. Every other
  revision 3 case keeps its bytes and its verdict.
- Verdict changes outside the corpus: a journal whose refusal names a registry code other than
  the four was denied and is now allowed; a receipt that counts a refused tool call was allowed
  and is now denied with `blast_radius_overstated`.

## suiteRevision 3 (predicate revision 1.2: a detector decision is judged by what it changes)

- `decision_not_supported_by_estimates` now fires only when a `detector_` decision with equal
  estimates removes an edge. Until revision 1.1 it also fired when the decision's `isolated`
  list was non-empty. That list is the state of the new graph (`isolated_set_mismatch` requires
  it), so a detector that restated a graph in which an earlier `evidence_gate` or oracle
  decision had isolated an agent was blamed for that earlier cut. An agent becomes isolated
  only by losing an edge, so the edge test covers every cut the detector makes.
- Case added: `allow-detector-restates-earlier-cut`.
- Cases changed: none. Every revision 2 case keeps its bytes and its verdict.
- Verdict change outside the corpus: a journal whose detector restates a graph with an
  isolated agent, under equal estimates and with no removed edge, was denied with
  `decision_not_supported_by_estimates` and is now allowed.

## suiteRevision 2 (predicate revision 1.1: retrievals, refusals, refused tool calls, grant chains)

- Release note: the blast-radius reach rule is stated and forced clause by clause; a neutral
  `refusal` event records a refusal over an edge in force under one of four registered codes
  (`budget_exhausted`, `purpose_out_of_scope`, `permit_revoked`, `authority_chain_violation`); and
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
- A minor release may add refusal codes; a reader denies only a code it does not know, and the
  verdict is the same for every registered code. Refusals of writes belong to the next major
  revision's write event.
- Cases added: `allow-refusal-over-present-edge`, `allow-refusal-permit-revoked`,
  `allow-refusal-authority-chain-violation`, `reject-refusal-over-absent-edge`,
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
