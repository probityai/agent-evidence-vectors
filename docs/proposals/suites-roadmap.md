# Roadmap: from #352 cases to versioned suites

Status: proposal. Discussion: the roadmap issue that links this page.

#352 has done what an intake thread should: 157 comments, cases with owners, and readers written from a contract
alone. A case that lives only in a thread cannot be pinned, replayed or badged. This roadmap moves each family into a
versioned suite of its own.

## What a suite is

A suite is one row in `corpora/REGISTRY.toml` plus its corpus directory, checked by `scripts/corpus-registry.py`
against `corpora/REGISTRY.schema.json`. It carries a MANIFEST and corpusDigest, a corpus README stating the contract,
an Evidence run template, a row on the Agent Evidence Conformance Board ([conformance-badges.md](conformance-badges.md)),
and `contributedBy` in the manifest naming the handle of whoever brought each case. A suite whose records belong to a
registered predicate type carries that URI ([predicate-registry-rfc.md](predicate-registry-rfc.md)).

## The suites and their sources

| Suite | Source | Planned release |
| --- | --- | --- |
| request/effect join | a reader written from one contract document alone matched all ten cases on #352 | 0.36.0 |
| refund-connected contract | #432 (merged) | 0.36.0 |
| billing finality is not effect authority | #435 | 0.37.0 |
| tool-manifest effect replay | #346 | 0.37.0 |
| a changed call versus a later changed file | #350 | 0.37.0 |
| physical completion evidence | #80, built here from draft-noa-scitt-ai-agent-receipt-01 sections 8.1 to 8.3 and 1.5 | 0.37.0 |
| RTTP refusal vocabulary | #453, the five-value refusal vocabulary with its fixed priority and the lease-instant boundary | 0.37.0 |
| payment effect under EIP-3009 | #347 | after its slot is filed |
| paid-audit records | #247 | after its slot is filed |

Each release note lists the cases that changed. Existing contributions are credited in `contributedBy` now, and later
ones when they are made.

## Cross-runtime delegation and refusal

One suite spans runtimes: a delegation and refusal case set whose receipts chain across two runtimes, verified as a
federated chain by agent-evidence-verify. It counts as done when two outside runtimes execute it in their own CI. A
design note will be added under `docs/proposals/` before the first case lands.

## What stays on #352, and what leaves

New cases stay on #352 until they have a reader or a run, and so do questions about a contract before the contract
is a README. Anything with a passing reader leaves and becomes a suite and a board row within one release.
Contributors keep ownership of their cases in the manifest and on the board, and the Evidence run template remains
the way to file a run as a record of one's own.
