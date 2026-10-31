# A changed call and a later changed file

`giskard09` selected [execution-join-ref-v1](https://github.com/giskard09/argentum-core/blob/f4d989052bb3a61691b1b156cd6dd655793fea4f/docs/spec/execution-join-ref-v1.md)
for [the Lab's request/effect case](https://github.com/probityai/agent-evidence/issues/24#issuecomment-6247269392).
This table freezes the two situations separately so a producer, reader and file-effect observer can compare the same cases.

The producer's selected contract owns its identifier and failure-code semantics.
The cases below are our proposed experiment inputs, not a new version of that contract or a completed native run.

| Case | Decision and dispatch | Effect and later observation | Expected distinction |
| --- | --- | --- | --- |
| Unchanged approved call | The permit covers the exact dispatched path, identity, tool and arguments. | The recorded write matches that attempt. No later observation is supplied. | Establish the supported join, with later state unassessed. |
| Rewrite before dispatch | The permit covers the original call; the runtime dispatches changed arguments without a covering decision. | Whether a later file happens to match is separate. | `EFFECTIVE_CALL_REBINDING_FAILED`, the selected contract's invariant 6. A tidy internal chain cannot repair the missing approval. |
| Approved rewrite | The runtime obtains a decision covering `effective_action_ref` before dispatch. | The write matches the newly authorized attempt. | Assess the effective call under its own covering decision. Keep the original request and rewrite visible. |
| Later changed file | The original dispatch and recorded write match their covering decision. | A fresh read later sees different bytes. | Preserve the original result. Report the later difference separately. `POST_COMMIT_DIVERGENCE` is a proposed new observation code, not an adopted verifier result. |
| Changed evidence preimage | A claimed reference no longer recomputes from its supplied preimage. | This does not establish a later external change. | `DIGEST_MISMATCH` keeps the selected contract's digest meaning. |
| Missing later observation | A supported original join is supplied. | No fresh file read is supplied. | Keep later state unknown. Do not infer that the file remained unchanged. |

## What to retain for a run

Retain the original and effective preimages, covering decisions, attempt identity and original terminal output.
For a later read, retain its own target, bytes, time and observer identity.
Keep the producer's original result beside the reader's comparison; a later observation must not rewrite it.
Missing material stays missing rather than being filled from a current configuration.

The proposed post-commit observation needs an explicit consumer decision before promotion:
does it describe a changed resource, or does it reject a claim that the current state still matches?
Either way, it must not turn an earlier matching committed action into a false digest failure.

## Target coverage is another relationship

For a target-binding reader, freeze `declared_target`, `hashed_action_target` and
`executor_configured_target` as separate fields in the experiment's projection.
These are experiment field names, not aliases for a producer's native schema.

| Projection | Reader boundary |
| --- | --- |
| Hashed target absent | Target coverage is not established. |
| Hashed target differs from declared target | The declared/action relationship conflicts and must refuse. |
| Hashed target equals declared target; executor is configured for another target | The first relationship can pass. Actual dispatch remains a separate executor observation. |

Do not attribute an executor-only divergence to a reader that never observes dispatch.
Likewise, an executor configuration is not proof of where an actual request went.

## Open contributions

Bring the pinned producer verifier and vectors, run the same cases with another reader,
or retain a file-effect observation. We maintain the case table and the comparison we contribute.
Case authors, implementation authors and run operators receive separate credit.
The [approved SQL example](../approved-sql/README.md) already exercises the parallel distinction
between a matching recorded commit and a later state difference.

## Producer verifier run

`giskard09` published a verifier and nine vectors for these cases at
[`execution-join-ref-remora-bridge@f900615`](https://github.com/giskard09/execution-join-ref-remora-bridge/tree/f900615),
derived from a run of the REMORA effect bridge. We reran `python3 verify.py vectors.json` at that commit
on CPython 3.13.15; all nine checks passed with these outcomes:

| Vector | Outcome |
| --- | --- |
| AR-00 | `AUTHORIZED_EFFECTIVE_CALL` |
| AR-01, AR-02, AR-03 | `EFFECTIVE_CALL_REBINDING_FAILED` |
| AR-04 | `NOT_MODELED` (the policy/context digest is outside the `action_ref` preimage) |
| AR-05 | `POST_COMMIT_DIVERGENCE` (proposed code; original result preserved) |
| APPROVED-REWRITE | `AUTHORIZED_EFFECTIVE_CALL` |
| CHANGED-PREIMAGE | `DIGEST_MISMATCH` |
| MISSING-OBSERVATION | `LATER_STATE_UNKNOWN` |

Another reader can run the same nine vectors and add its outcomes beside these.

### Rerun after the cold mutation run

`babyblueviper1` reran the nine vectors cold with an independent RFC 8785 serializer and found, by mutation,
that the verifier at `f900615` accepted a covering decision whose `outcome` is `deny` as authorization of the
rewritten call. `giskard09` fixed it at
[`407f593`](https://github.com/giskard09/execution-join-ref-remora-bridge/commit/407f593b29d81322fc1c4e9c5796ff38913c2b19),
added a defensive profile check at
[`810bcef`](https://github.com/giskard09/execution-join-ref-remora-bridge/commit/810bcef398917b5dc9f4ab1a2790d1c468c66ea8)
and recorded the ordering limit at
[`2cc79c9`](https://github.com/giskard09/execution-join-ref-remora-bridge/tree/2cc79c9).
We reran `python3 verify.py vectors.json` at `2cc79c9` on CPython 3.13.15; all eleven checks passed. The two new
vectors:

| Vector | Outcome |
| --- | --- |
| COVERING-DENY | `EFFECTIVE_CALL_REBINDING_FAILED` (a covering decision that denies authorizes nothing) |
| COVERING-UNSUPPORTED-PROFILE | `UNSUPPORTED_CANONICAL_PROFILE` |

The other nine outcomes are unchanged from the table above. Replaying the deny mutant against `2cc79c9`
now refuses APPROVED-REWRITE. Moving the covering decision's `ts_ms` a day later still returns
`AUTHORIZED_EFFECTIVE_CALL`: the attempt timestamps in this corpus are declared conventions, so whether the
covering decision preceded the attempt stays indeterminate. A case that retains a separately bound dispatch
observation is the open contribution for that ordering question.

## Ordering cross-reference: a payment that carries the decision

`babyblueviper1` filed a run on the ordering question as its own Evidence run,
[probityai/agent-evidence#28](https://github.com/probityai/agent-evidence/issues/28).
The effect is a Base mainnet payment, not a file write, so it stays a cross-reference here and does not
change the file-shaped columns above. In exhibit 3 the EIP-3009 authorization's nonce equals the signed
verdict's `decision_ref`, so the authorization could not have been signed before the verdict existed, and the
block timestamp bounds the dispatch from above. Precedence comes from that hash dependency, not from comparing
two declared clocks. Exhibit 2 uses a random nonce and is the real negative control.

We reran it on 2026-10-23 at
[`preaction-governance-conformance@f82d691`](https://github.com/babyblueviper1/preaction-governance-conformance/tree/f82d69154d0b5eb9881f1ea1065926f86c33fec8/examples/resolution-payment-pair-v0)
on CPython 3.13.15. `check.py` and `vectors.json` hash to the values the run lists. `python3 check.py --live`
re-read both receipts and blocks from a public Base RPC, found them equal to the pinned fixture, and matched
10 of 10 cases:

| Case | Outcome |
| --- | --- |
| exhibit-3-nonce-is-decision-ref (real) | `UNRESOLVED`, `execution_policy_not_committed` |
| exhibit-2-random-nonce (real) | `UNRESOLVED`, `execution_policy_not_committed`, `payment_does_not_carry_verdict` |
| s1 to s3 (synthetic) | `AUTHORIZED`; `UNAUTHORIZED` `executed_on_verdict_outside_policy`; `UNRESOLVED` `payment_does_not_carry_verdict` |
| n1 to n5 (negative) | `UNRESOLVED`; four `verdict_does_not_cover_payment`, one `evidence_unavailable` |

Exhibit 3 stops at `UNRESOLVED` because that run committed no execution policy, which is the correct result.
One operator controlled the verdict key and both wallets, so the chain is the only party outside the run.
For a file write the same ordering needs the written bytes, or a companion manifest, to commit to the
decision reference.

## File-domain verifier for execution-join-ref-v1

`giskard09` then built a verifier for `execution-join-ref-v1` itself, with a file-domain vector for each case
at the top of this table: `file-write-rebinding-failed-001` for a rewrite before dispatch and
`post-commit-divergence-001` for a later changed file, under a proposed invariant 7, `post_commit_consistency`.
We ran `python3 examples/conformance/execution-join-ref/verify.py` at
[`argentum-core@fcee058`](https://github.com/giskard09/argentum-core/tree/fcee058367fc7f594bfb45a7490ecfb7751a0f99/examples/conformance/execution-join-ref)
on CPython 3.13.15 on 2026-10-23: 14 of 14 vectors passed. The rewrite vector fails
`effective_call_binding` with `EFFECTIVE_CALL_REBINDING_FAILED`. The later-change vector fails only
`post_commit_consistency` with `POST_COMMIT_DIVERGENCE`, so the original join keeps its result.
Invariant 7 and its code are the producer's proposal; no adopted version of the contract carries them yet.

A mutation check of that verifier at `fcee058` found two gaps, both reproduced here on 2026-10-23:

| Mutant | Verifier output |
| --- | --- |
| Positive vector, decision `outcome` set to `deny` and `decision_id` rehashed | `PASS`, 14 of 14 |
| `AUTHORIZED_EFFECTIVE_CALL`, covering decision set to `deny` and rehashed | `PASS`, 14 of 14 |
| Later-change vector with the later hash set equal to the committed hash | `PASS`; the vector still expects `POST_COMMIT_DIVERGENCE` |
| Rewrite vector with the effective path set equal to the approved path | `PASS`; the vector still expects `EFFECTIVE_CALL_REBINDING_FAILED` |

The first two rows are the deny gap from the cold mutation run above, still open in this verifier: it never reads
a decision's `outcome`. In the last two the verifier computes the invariant as true and reports a fixture
mismatch internally, but its summary counts any failure as the expected refusal, so a negative vector passes
after its defect is removed. Until both are fixed, 14 of 14 here establishes less than it reads.

`giskard09` fixed both in [argentum-core#147](https://github.com/giskard09/argentum-core/pull/147), merged as
[`bc9449b`](https://github.com/giskard09/argentum-core/tree/bc9449bff7efa956f38510504a2c4fed6237e009/examples/conformance/execution-join-ref).
`effective_call_binding` now reads the covering decision's `outcome`, so `deny` and `defer` no longer authorize the
dispatched call. A negative vector now passes only when an invariant its own `checks` declares false computes false.
He added four vectors, 18 in all: `effective-call-binding-covering-deny-001`, `effective-call-binding-covering-defer-001`,
`file-write-rebinding-fixed-001` and `post-commit-consistency-confirmed-001`. We ran the verifier at `bc9449b` on
CPython 3.13.15 on 2026-10-24: 18 of 18 passed. The same four mutants, applied to its vectors:

| Mutant at `bc9449b` | Verifier output |
| --- | --- |
| Positive vector, decision `outcome` set to `deny` and `decision_id` rehashed | `FAIL` on that vector, 17 of 18 |
| `AUTHORIZED_EFFECTIVE_CALL`, covering decision set to `deny` and rehashed | `FAIL` on that vector, 17 of 18 |
| Later-change vector with the later hash set equal to the committed hash and `post_commit_ref` rehashed | `FAIL` on that vector, 17 of 18 |
| Rewrite vector with the effective preimage set equal to the approved one and `effective_action_ref` rehashed | `FAIL` on that vector, 17 of 18 |

Both gaps are closed at `bc9449b`. Invariant 7 is still the producer's proposal.

## A synthetic claim model beside the effect bridge

`altrudev` compared Frequency's synthetic claim-status fixture with the REMORA effect bridge this table started from,
in [`lab-claim-comparison.md` at `d0c707c`](https://github.com/altrudev/frequency-open-evidence-lab/blob/d0c707cc8df1aa79f145068581ed6cb2621f8ae0/docs/lab-claim-comparison.md)
([request](https://github.com/probityai/agent-evidence/issues/24#issuecomment-6247272865)).
The Lab takes that comparison as the first shared control between a claim model and an effect bridge, on its own terms:

| Frequency row | Relationship to the REMORA effect bridge |
| --- | --- |
| AR-00, authorized and current effect confirmed | Semantically comparable, not provenance-equivalent |
| AR-05, execution reported and current effect contradicted | Semantically comparable, not provenance-equivalent |
| AR-01 to AR-04, refusals | Not equivalent: a refusal is observable, and an untouched store is not |
| The other cross-product cells | No mapping claimed |

Frequency's row names are its own; they are not the vector names in the producer verifier run above.
Frequency compares supplied state strings and observes no write, so neither column carries over to the other.
We ran `python3 -I check.py` and `python3 -I -m unittest discover -v` at `d0c707c` on CPython 3.13.15 on 2026-10-25:
12 of 12 synthetic cases and 14 of 14 tests passed, matching the posted result. That is a rerun of the fixture's own
code, not a second reader. A reader-neutral fixture contract for these seams, so a third reader can run against them
without either implementation's internals, is the open contribution.
