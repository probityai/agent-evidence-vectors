# Aggregate-accounting vectors

Cases for `aggregate-accounting/v1`: the decisions an accounting authority took
against one budget shared by a principal and the delegation subtrees under it.
The expected decision and reason for every case are in `MANIFEST.json`.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

The shape under test is a limit that holds for each agent while the budget the
agents share does not. Each request can be inside its own limit and the set of
them outside the budget. A control that looks at one agent cannot see it.

| Case | Expected |
| --- | --- |
| allow-concurrent-both-fit | allow, `aggregate_held` |
| allow-race-one-admitted | allow, `aggregate_held` |
| allow-exact-fit-both-admitted | allow, `aggregate_held` |
| allow-unknown-outcome-stays-charged | allow, `aggregate_held` |
| allow-released-reservation-returns-units | allow, `aggregate_held` |
| allow-past-latency-bound-refused | allow, `aggregate_held` |
| allow-past-latency-bound-held | allow, `aggregate_held` |
| allow-latency-at-bound-admitted | allow, `aggregate_held` |
| allow-two-subtrees-one-principal | allow, `aggregate_held` |
| contract-id-missing | deny, `contract_id_missing` |
| contract-id-unknown | deny, `contract_id_unknown` |
| identity-missing-subtree | deny, `accounting_identity_missing` |
| identity-missing-action | deny, `accounting_identity_missing` |
| latency-bound-admitted | deny, `latency_bound_admitted` |
| unknown-outcome-released-after-expiry | deny, `unknown_outcome_not_charged` |
| race-both-admitted | deny, `aggregate_overspend` |
| per-agent-limits-hold-aggregate-fails | deny, `aggregate_overspend` |
| fitting-request-refused | deny, `fitting_request_refused` |
| effect-counts-disagree | deny, `effect_counts_disagree` |

Each denied case is built so the check it names is the first that fails and
every earlier check passes. The allowed cases are controls: a verifier that
refuses everything fails them, and so does one that refuses a request that
fits.

## The four cases a practical guide asks for

These are the four deterministic tests that review of the CoSAI WS4 containment
paper (section 4, accounting) proposed for its section 8.2 demonstration, with
all other authorization conditions satisfied:

| Test | Case |
| --- | --- |
| With 10 units left, two concurrent requests for 4 are both admitted | allow-concurrent-both-fit; the over-refusal fault is fitting-request-refused |
| With 10 units left, two racing requests for 6 cannot both be admitted | allow-race-one-admitted; the fault is race-both-admitted |
| A reservation with an unknown outcome stays charged past its expiry | allow-unknown-outcome-stays-charged; the fault is unknown-outcome-released-after-expiry |
| A request past the latency bound is refused or held, never allowed | allow-past-latency-bound-refused and -held; the fault is latency-bound-admitted |

Each result names the principal, subtree, budget and action in the decision it
records, and `MANIFEST.json` retains them with the effect counts.

## What a record holds

`contractId` carries
`https://probityai.github.io/agent-evidence-observer/contract/aggregate-accounting/v1`.
The other fields are `principal`; `budget`, with `id`, `unit`, `limit` and
`remainingBefore`; `latencyBoundMs`; `asOf`; `decisions`; and `effectCounts`.
Each decision carries `requestId`, `agent`, `principal`, `subtree`, `budget`,
`action`, `units`, `decision` (`admitted`, `refused` or `held`), `latencyMs`,
`outcome` (`committed`, `released`, `unknown` or `none`), `charged` and, for a
refusal, `reason` (`budget` or `latency`).

A request is charged when it was admitted and its outcome is `committed` or
`unknown`. A released reservation returns its units.

## The checks, in order

A verifier names the first check that fails.

1. The record carries `contractId` (`contract_id_missing`).
2. `contractId` is the aggregate-accounting contract (`contract_id_unknown`).
3. Every decision names its principal, subtree, budget and action
   (`accounting_identity_missing`).
4. No request was admitted after an answer slower than `latencyBoundMs`
   (`latency_bound_admitted`).
5. An admitted reservation whose outcome is unknown is still charged at
   `asOf` (`unknown_outcome_not_charged`).
6. The units charged across the principal and every subtree do not exceed
   `remainingBefore` (`aggregate_overspend`).
7. No request was refused for budget that fitted beside everything admitted
   (`fitting_request_refused`).
8. `effectCounts` equals the counts the decisions give
   (`effect_counts_disagree`).

A record that passes every check is `allow` with reason `aggregate_held`.

## What a pass establishes

The record's own decisions are consistent with an atomic admission across the
principal and each subtree: nothing was charged past the budget, nothing that
fitted was refused, an unknown outcome stayed charged, and nothing was admitted
after the authority answered too late.

## What a pass does not establish

- That the producer reported units, times or outcomes truthfully.
- That the admissions were serialized in the store, as opposed to appearing so
  in the log.
- That the parties' clocks agree.
- Anything about requests the record does not list.

## Running it

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-aggregate-accounting
```

A verifier under test takes `record.json --json`, prints one JSON object
carrying `decision` and `reason`, and exits 0 for `allow` and 1 for `deny`:

```sh
agent-evidence-vectors --corpus vectors-aggregate-accounting --verifier './verifier'
python3 vectors-aggregate-accounting/check_vectors.py --verifier './verifier'
```

`aee-verify vectors-aggregate-accounting` judges the same cases with the Go
reader. Regenerate the cases with `python3 vectors-aggregate-accounting/gen_vectors.py`.
