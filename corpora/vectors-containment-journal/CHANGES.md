# Containment-journal suite changelog

A published `suiteRevision` is never mutated in place. A normative change to the predicate or
a case added bumps the revision, and the generator rewrites the cases byte-identically.

## suiteRevision 6 (predicate revision 2.1: refusals take the shared registry, and a refused call reaches nothing)

- A refusal's `reasonCode` is any code of the refusal-code registry (`refusal_codes.json`, shipped
  with the package and the Go readers), where revisions 1.1 and 1.2 registered four. The four
  keep their meaning. A reader still denies a code it does not know, a code in another form and a
  code with a detail, all as `closed_vocabulary_violation`.
- A refused tool call is no reach: the blast-radius reach skips a `tool_call` whose `refused` is
  true, in both readers. A refused call did not run, so the receipt names only calls that ran. A
  refused write and a refused read never taint either: the revision 2.0 store taint follows only
  writes and reads that ran.
- Cases added: `allow-refusal-registry-code-<family>` for each of the 14 registry families
  (approval, authority, delegation, gateway, governance, grants, identity, journal, key, marker,
  mesh, possession, revocation, singleuse), `reject-closed-vocabulary-violation-refusal-code-unknown`,
  `reject-closed-vocabulary-violation-refusal-code-kebab`, `reject-closed-vocabulary-violation-refusal-code-detail` and
  `reject-blast-radius-overstated-counts-refused-tool-call` (the receipt that revision 5 allowed).
- Cases changed: `allow-isolated-agents-tool-call-refused`: its receipt counted the refused call
  (`toolCalls` 1) and now counts none (`toolCalls` 0). Its journal keeps its bytes. Every other
  earlier case keeps its bytes and its verdict.
- Verdict changes outside the corpus: a journal whose refusal names a registry code other than
  the four was denied and is now allowed; a receipt that counts a refused tool call was allowed
  and is now denied with `blast_radius_overstated`.

## suiteRevision 5 (predicate revision 2.0: every value an agent writes says who wrote it)

- Release note: two events, `write` and `store_read`. A write names its agent, store, key and
  value digests, whether it was refused and why, the value its permit bound
  (`permitValueDigest`) and, when attributed, its `principals` (user, delegation chain digest,
  and the digest of the agent, user and chain). A read back names the writer of the last write
  that ran to the key. The reader checks that writer on every read, refused or not, and checks
  the value on a read that was not refused, so a withheld read cannot name a writer that never
  wrote the key. The blast-radius reach follows taint through a shared store.
- Major revision: a reader of revision 1.x denies a journal that carries a `write` or a
  `store_read` entry with `closed_vocabulary_violation`. That is the correct behaviour for a
  reader that does not know an event, and the reason the number is 2.0. This is the write event
  revision 1.1 deferred to ("Refusals of writes belong to the next major revision's write
  event").
- New members, all optional: the claims `writesAttributed` and `writesBound`.
- New rules: `write_principals_digest_mismatch`, `write_value_not_permitted`,
  `write_by_isolated_agent`, `read_value_unwritten`, `read_writer_mismatch`,
  `write_principals_missing`, `write_unpermitted`.
- Cases added: `allow-write-attributed-and-read-back` (with a receipt that reaches agent-b
  through the store), `allow-blast-radius-store-overwritten-by-clean-writer` (with a receipt),
  `allow-write-unattributed-without-claim`, and one `reject-` case per new rule.
- Cases changed: none. Every revision 3 case keeps its bytes and its verdict.
- Verdict change outside the corpus: none for a journal without the two events.

## suiteRevision 4 (predicate revision 1.3: the authority chain and the grant chain are two members)

- Until revision 1.2 a tool call's `grantChainDigest` held the digest of the authority chain
  the guard walked from the call back to the principal's task grant (the document
  `{"chain": [...], "data_roles": [...]}`), not a chain of capability grants. Revision 1.3 names
  that digest `authorityChainDigest`, and `tool_call_authority_unbound` now reads it.
- `grantChainDigest` now means the digest of the capability grant chain the call was delegated
  under: `sha256:` over the RFC 8785 bytes of the list of the links' grant digests, root first
  (`probity_records.digests.grant_chain_digest`). It is optional and is never read as an
  authority chain.
- Case added: `allow-tool-call-names-authority-and-grant-chains`.
- Cases changed: `allow-isolated-agents-tool-call-refused` (its `record.json` names agent-a's
  authority chain as `authorityChainDigest`, and its `receipt.json` cites the new head). Every
  other revision 3 case keeps its bytes and its verdict.
- Verdict change outside the corpus: a journal that claims `authorityChainChecked` and names a
  tool call's authority chain only as `grantChainDigest` (the revision 1.2 spelling) was allowed
  and is now denied with `tool_call_authority_unbound`. It fails closed: a revision 1.2 value
  never equals the capability grant chain digest a consumer computes.

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
