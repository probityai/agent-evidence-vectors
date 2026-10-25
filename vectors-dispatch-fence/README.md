# Dispatch-fence vectors

Cases for `dispatch-fence/v1`: a record of one exclusive dispatch, made of a
policy check over shared state, a fence (an exclusive hold on the context) taken
to dispatch, the effect, and the commit of its result. The expected decision and
reason for every case are in `MANIFEST.json`.

The shape under test is a check and a fence that read state separately, and an
exclusive hold shorter than the tool it covers. Each can be correct alone. The
pair is not: a fence that re-reads state cannot show it acted on the state the
check saw, and a hold that lapses while the tool runs lets a second dispatch in.

| Case | Expected |
| --- | --- |
| allow-single-read | allow, `exclusive` |
| allow-state-event-after-fence | allow, `exclusive` |
| allow-renewed-hold-covers-effect | allow, `exclusive` |
| allow-same-proposal-second-hop | allow, `exclusive` |
| allow-effect-ends-at-expiry | allow, `exclusive` |
| contract-id-missing | deny, `contract_id_missing` |
| contract-id-unknown | deny, `contract_id_unknown` |
| fence-rereads-state | deny, `fence_not_bound_to_check` |
| label-raised-between-check-and-fence | deny, `state_changed_between_check_and_fence` |
| declared-runtime-exceeds-ttl | deny, `runtime_exceeds_hold` |
| tool-outlives-hold | deny, `hold_expired_before_effect_ended` |
| second-dispatch-after-expiry | deny, `concurrent_dispatch_admitted` |
| commit-after-own-hold-expired | deny, `commit_after_hold_expired` |

Each denied case is built so the check it names is the first that fails and
every earlier check passes. The allowed cases are controls: a label raised after
the fence was appended, a hold renewed to cover a long effect, a second attempt
carrying the same proposal identifier, and an effect that ends exactly at the
hold's expiry (the boundary is inclusive).

## What a record holds

`contractId` carries
`https://probityai.github.io/agent-evidence-observer/contract/dispatch-fence/v1`.
The other fields are `contextId` and `proposalId`; `stateEvents`, the ordered
`{seq, at, kind}` events on the context; `check`, the sequence number the policy
check read; `fence`, with the sequence number it appended after, the optional
`expectedSeq` it was bound to, `acquiredAt`, `ttlSeconds` and `renewals`;
`effect`, with an optional `declaredMaxRuntimeSeconds`, `startedAt` and
`endedAt`; `commit`; and `otherAttempts` on the same context. The hold expires
at the latest of `acquiredAt` plus `ttlSeconds` and every renewal's
`expiresAt`.

## The checks, in order

A verifier names the first check that fails.

1. The record carries `contractId` (`contract_id_missing`).
2. `contractId` is the dispatch-fence contract (`contract_id_unknown`).
3. `fence.expectedSeq` is present and equals `check.readSeq`
   (`fence_not_bound_to_check`).
4. No state event has a `seq` after `check.readSeq` and at or before
   `fence.appendSeq` (`state_changed_between_check_and_fence`).
5. A `declaredMaxRuntimeSeconds` above the initial `ttlSeconds` has a recorded
   renewal (`runtime_exceeds_hold`). This one is refusable at dispatch, before
   any effect.
6. `effect.endedAt` is at or before the hold's expiry
   (`hold_expired_before_effect_ended`).
7. No attempt with a different `proposalId` was admitted with `beganAt` from
   `fence.acquiredAt` to `effect.endedAt` inclusive
   (`concurrent_dispatch_admitted`).
8. `commit.at` is at or before the hold's expiry (`commit_after_hold_expired`).
   The first dispatch must withhold its result.

A record that passes every check is `allow` with reason `exclusive`.

## What a pass establishes

The record's own sequence numbers and times are consistent with a check and a
dispatch taken on one state read, under an exclusive hold that covered the
effect and the commit.

## What a pass does not establish

- That the producer reported sequence numbers or times truthfully.
- That the store is linearizable, or that the hold is enforced across hosts.
- That the parties' clocks agree.
- That the effect stopped when `endedAt` says.
- Anything about attempts the record does not list.

## Running it

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-dispatch-fence
```

A verifier under test takes `record.json --json`, prints one JSON object
carrying `decision` and `reason`, and exits 0 for `allow` and 1 for `deny`:

```sh
agent-evidence-vectors --corpus vectors-dispatch-fence --verifier './verifier'
python3 vectors-dispatch-fence/check_vectors.py --verifier './verifier'
```

`aee-verify vectors-dispatch-fence` judges the same cases with the Go reader.
Regenerate the cases with `python3 vectors-dispatch-fence/gen_vectors.py`.
