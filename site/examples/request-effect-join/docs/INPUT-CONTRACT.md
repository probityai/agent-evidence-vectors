# Inputs and results

This profile is `request-effect-join-fixture/v1`. Its only accepted `origin` is `synthetic`.
Use [`../fixtures/cases.json`](../fixtures/cases.json) as the full shape; [`../expected.json`](../expected.json)
gives one expected result per case, and [`../fixtures/MANIFEST.json`](../fixtures/MANIFEST.json) pins both files by SHA-256.
Every object must contain exactly its declared keys. A reader that supplies a default for a missing key has stopped
reading the record and started repairing it, and the two cases below cannot be told apart once that happens.

These are experiment inputs against the case table in [`../CASE-TABLE.md`](../CASE-TABLE.md).
The vectors are new bytes written for this contract; they are not copies of the producer's `vectors.json`, and
no producer verifier is run here. Where a case has a producer vector or a Frequency row beside it, `expected.json`
records the correspondence as a mapping and nothing more.

## Record shape

| Field | Meaning in this fixture |
|---|---|
| `case_id` | `S-00` … `S-09`. The only identifier the expected file joins on. |
| `contract` | Always `request-effect-join-fixture/v1`. |
| `source` | `producer_vector`, `frequency_row` and `note`. Free text; it carries no verdict. |
| `approved` | The action ref the decision reviewed, with the preimage it recomputes from. |
| `effective` | The action ref actually dispatched, with its preimage. Equal to `approved` when nothing was rewritten. |
| `decision` | The guardrail decision over `approved`. Preimage carries `action_ref`, `canonicalization_profile_id`, `outcome`, `policy_id`, `ts_ms`, `version`. |
| `covering_decision` | A second decision over `effective`, or `null`. Only a rewrite can need one. |
| `attempt` | The execution instance, or `null` when nothing was dispatched. |
| `result` | The terminal outcome of that attempt, or `null`. Present exactly when `attempt` is. |
| `later_observation` | A later read of the target, `null` for "no read supplied", or **absent**. Absence is invalid input, not an empty read. |

A ref is `sha256:` followed by the lowercase hex of `SHA-256(JCS(preimage))`, computed at the moment the object
describes. `JCS` is RFC 8785. Preimages are compared field by field; a reader must not normalise, coerce or
re-serialise them before hashing. `version` is `request-effect-fixture-v1` and is part of every preimage.

The chain is `approved` → `decision` → `effective` → `attempt` → `result`:
`decision.preimage.action_ref` names `approved`, `attempt.preimage.action_ref` names `effective`, and
`result.preimage.attempt_id` names `attempt`. `effective` equals `approved` unless the runtime rewrote the call
before dispatch; `covering_decision.preimage.action_ref` must then name `effective`.

`later_observation` carries `target_scope`, `content_sha256`, `observed_at_ms` and `observer_id`. It has no ref of
its own and is never hashed into the join. `observed_at_ms` may be `null`: a read whose capture time is unknown is
still a read. It establishes nothing about who wrote the bytes or when.

## Canonicalization profiles

`canonicalization_profile_id` is read before any digest is compared. Supported: `jcs-rfc8785-v1` under that alias
or under its content address `f018a62879ab01f21e8fe5e9e7486dadba0b795e9358b32fd24d38d2c1f1f07d`. A record naming
any other value is not evaluable here: report `unsupported_canonical_profile` and do not fall back to JCS.

## Classification

Exactly one of four values, applied in the order below; the first that applies is the answer.

| Value | When |
|---|---|
| `invalid_input` | The record is not well formed under this contract: a required key is absent, a key set differs, `attempt` and `result` disagree about being present, or a decision names a profile the reader does not implement. The reader raises; it must not score the record. |
| `refused` | The supplied material is complete and the join does not hold, or a claimed ref does not recompute from its own preimage. |
| `not_established` | The supplied material cannot settle the join either way — nothing was dispatched, or the terminal outcome is not `completed`. |
| `established` | Every check above passed and the effective call is bound to a decision that permits it. |

## Order of checks

1. **shape** — key set, types, `attempt`/`result` presence agreement. Failure: `invalid_input`, no finding.
2. **profile** — every supplied decision's `canonicalization_profile_id` is supported. Failure: `invalid_input`
   with `unsupported_canonical_profile`.
3. **digest** — every supplied ref equals `sha256(JCS(preimage))`. Failure: `refused` with `digest_mismatch`.
   A digest failure stops the run: the fields are not compared against a preimage that does not hash to its own ref.
4. **dispatch** — `attempt` is `null`. Then `not_established` with `join_not_established` and
   `store_mutation_not_established`, plus `refusal_observed` when the decision's outcome is not `permit`.
5. **coverage** — if `effective` differs from `approved`, a decision must name `effective` and permit it.
   No such decision: `refused` with `effective_call_not_covered`. A decision that names it and does not permit it:
   `refused` with `covering_decision_not_permit`. Binding without permission is not coverage.
6. **chain** — `attempt` names `effective` and `result` names `attempt`. A break is `refused` with
   `join_chain_broken`. `result.preimage.outcome` other than `completed` is `not_established` with
   `result_not_completed`.
7. **later state** — only for an established join: `later_state_not_supplied`, `later_state_not_comparable` when the
   read names another scope, `later_state_unchanged` when its bytes equal the committed output hash, otherwise
   `later_state_differs` with `original_result_preserved`.

## Findings

A closed set; a reader reports every finding that applies and nothing outside this list.

`join_established`, `join_not_established`, `effective_call_not_covered`, `covering_decision_not_permit`,
`digest_mismatch`, `unsupported_canonical_profile`, `join_chain_broken`, `result_not_completed`,
`refusal_observed`, `store_mutation_not_established`, `later_state_not_supplied`, `later_state_unchanged`,
`later_state_differs`, `later_state_not_comparable`, `original_result_preserved`.

On `refused` and `invalid_input` no `later_state_*` finding is reported: later state is not assessed when the join
itself is unreadable or refused. A reader's own code (the producer's `EFFECTIVE_CALL_REBINDING_FAILED`,
`POST_COMMIT_DIVERGENCE`, `NOT_ESTABLISHED`, …) is reported beside the findings in a `native` field and mapped by the
reader. The mapping is the reader's claim and is not compared by this contract.

## What counts as not established

Four statements are outside what these cases can support, and a pass on any of them is a divergence rather than a
scoring choice:

- **A missing later read is not an unchanged resource.** `later_observation: null` yields `later_state_not_supplied`
  and never `later_state_unchanged`. `S-05` and `S-00` are the same bytes apart from that key.
- **An absent key is not a null value.** `S-06` is `S-05` with the key removed and is `invalid_input`; a reader that
  treats the two alike reports `established` for a record the contract cannot read.
- **A refusal does not establish that the store was left alone.** `S-09` reports `refusal_observed` because the denial
  is observable, and `store_mutation_not_established` because an unwritten file is not. No later-read finding is
  available in that case at all.
- **A later difference is not a failed join and not a digest failure.** `S-04` keeps `join_established` and the
  original result intact; `digest_mismatch` is reserved for a preimage that does not recompute (`S-07`).

`expected.json` carries a `must_not_claim` list per case. Those are not extra credit conditions: they name the
findings that make a case a divergence when reported.

## Equivalence is a mapping, not a claim

`expected.json` records `producer_vector`, `frequency_row`, `semantic_comparable` and `provenance_equivalent` per case.
`semantic_comparable` is `true` for `S-00` and `S-04` only, matching the two Frequency rows the case table accepts as
comparable. `provenance_equivalent` is `false` for every case in this corpus, including those two: no vector here was
derived from another project's bytes, run, or verifier. A reader that treats comparability as provenance equivalence
is disagreeing with the case table, not with this contract.

## Reporting a run

Run `python3 run_contract.py` in this directory. It prints one line per case and then the comparison against
`expected.json`, exiting 0 when every case matches, 1 on a divergence and 2 when a manifest digest is stale.
Report your reader's classifications and findings for all ten cases, the `native` code you mapped onto each finding,
and the count of divergences. A reader that reports additional findings has produced a divergence to report, not a
pass with a note: the contract's contribution is that the set is comparable at all.

`run_contract.py` was written by the same author as the contract, the fixtures and the expected results, and is
answer-exposed. It shows the contract is implementable and internally consistent. It is not an independent reader,
and its agreement with `expected.json` is not evidence that another implementation will agree.

## What a pass does not establish

Nothing about any producer's behaviour outside these ten records. Not the correctness of the selected
`execution-join-ref-v1` contract, not the meaning of any tool's arguments or any file's contents, not that a store
was or was not modified, not ordering between a decision and a dispatch whose clocks are declared conventions, and
not that any project adopted, integrated or endorsed anything. The vectors are synthetic: no execution produced
them and no file was read.
