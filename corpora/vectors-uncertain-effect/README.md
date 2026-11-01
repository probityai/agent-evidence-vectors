# Uncertain-effect vectors

Cases for `uncertain-effect/v1`: one operation whose effect may have happened after
its reply was lost. A write commits at the service that owns the effect, and the
caller sees a timeout, a dropped connection or a lost lease. The caller does not
know whether the effect happened. The safe reading is that it is unknown: a retry
may repeat it, and capacity held for it stays charged until the effect owner says
what it holds.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

Each case is a runtime's trail for that operation, with an expected decision and
reason in `MANIFEST.json`. Each case also names the runtime scenario it pairs with:
the behaviour of a counting effect owner that puts a runtime in the same situation,
and the effect counts and outcomes a conforming runtime may leave there. A verifier
reads the trails; a runtime is driven through the scenarios.

## Run it in CI

A runtime adds one step and an adapter that performs the scenario's operation
through its own execution and retry path:

```yaml
- uses: probityai/agent-evidence-vectors@v0.30.0
  with:
    corpus: vectors-uncertain-effect
    runtime: .venv/bin/python tests/uncertain_effect_adapter.py
```

The step installs its own Python, so name the interpreter that has your runtime
installed. A verifier of runtime trails uses the same step with `verifier:` in place
of `runtime:`. A Python runtime can also pin the package and drive the owner from
its own tests:

```python
from agent_evidence_vectors import uncertaineffect, uncertaineffect_runtime as rt

for scenario in uncertaineffect.shipped_scenarios():
    with rt.effect_owner(scenario) as (url, owner):
        outcome = run_my_runtime(url, scenario["operation"])
        assert rt.judge(scenario, owner, outcome) == []
```

`tests/runtime_adapter.py` is a reference adapter with two policies. `reconcile`
asks the owner before it sends again and passes every scenario. `blind` resends
after any failure, the way a plain retry wrapper does, and fails.

## The runtime contract

- The adapter is run as `<runtime> <scenario.json>` with `AEV_EFFECT_OWNER` set to
  the owner's base URL. It must finish within a minute.
- It sends the operation with `POST {owner}/effects`, a JSON body of
  `idempotencyKey`, `args` and, when the scenario names a lease, `fencingToken`. A
  confirmed call answers 200, a definite no-effect answer is 409, and a lost reply
  is a connection the owner closes without answering.
- It may ask `GET {owner}/effects/{idempotencyKey}`, which answers
  `{"result": "present" | "absent", "final": bool}`, or 503 while the owner cannot
  answer. A lookup that is not final can miss a late commit.
- In a lease scenario it may ask `GET {owner}/lease`, which answers `{"token": n}`.
  The lease passes to another worker after the first call.
- It prints, as its last line, `{"outcome": "committed" | "not_run" | "unknown"}`
  and exits 0.

A scenario passes when the owner holds an accepted effect count and the runtime
reports the outcome accepted with it, no call reused the key with other arguments,
and no call in a lease scenario carried a missing or superseded fencing token.

| Scenario | The owner | Accepted |
| --- | --- | --- |
| `confirmed` | commits and replies | one effect, committed |
| `commit-then-lost-reply` | commits, loses the reply, does not deduplicate | one effect, committed |
| `commit-then-lost-reply-deduplicating` | commits, loses the reply, deduplicates by key | one effect, committed |
| `owner-unreachable-after-lost-reply` | commits, loses the reply, cannot answer lookups | one effect, unknown |
| `lost-before-commit` | loses the call before it commits | none and not run, or one and committed |
| `late-commit-after-missed-lookup` | commits late, after a lookup that is not final | one effect, committed |
| `definite-no-effect` | refuses with a definite no-effect answer | none and not run, or one and committed |
| `lease-lost-after-lost-reply` | commits, loses the reply, moves the lease | one effect, committed or unknown |

## What a record holds

`contractId` carries
`https://probityai.github.io/agent-evidence-vectors/predicate/v1/uncertain-effect`,
the same URI a producer writes as the `predicateType` when it signs the record as an
in-toto Statement. The other fields:

- `operation`: `id`, `action`, `idempotencyKey` and `argsDigest` (`sha256:` over the
  RFC 8785 bytes of the arguments).
- `effectOwner`: `id`, `deduplicatesByKey` and `keyRetentionSeconds` (null for no
  limit).
- `attempts`: each dispatch, with `attempt`, `idempotencyKey`, `argsDigest`,
  `dispatchedAt`, `reply` (`confirmed`, `no_effect`, `timeout` or
  `connection_lost`) and, where workers hold leases, `worker` and `fencingToken`.
- `leases` (optional): `worker`, `fencingToken`, `acquiredAt` and `expiresAt`.
- `reconciliations`: the owner's answers, each `at`, `idempotencyKey`, `result`
  (`present` or `absent`) and `final`.
- `ownerEffects`: the effects the owner's own ledger holds for the operation.
- `reservation` (optional): `units`, `expiresAt` and `charged`.
- `reported.outcome`: what the runtime reported.

A `timeout` or `connection_lost` reply leaves the attempt's outcome unknown. The
outcome the owner's answers settle is `committed` when an attempt was confirmed or a
reconciliation found the effect; `not_run` when no attempt is unknown, or a final
reconciliation after the last unknown attempt found it absent; and `unknown`
otherwise.

## The checks, in order

A verifier names the first check that fails.

1. The record carries `contractId` (`contract_id_missing`).
2. `contractId` is the uncertain-effect contract (`contract_id_unknown`).
3. The operation and every attempt carry an idempotency key and an arguments digest
   (`operation_identity_missing`).
4. No attempt reuses the operation's key with other arguments
   (`idempotency_key_args_changed`).
5. Every attempt was dispatched inside a lease its worker held, before a lease with a
   higher fencing token was granted (`dispatch_beyond_lease`).
6. No attempt follows an unknown one unless the owner deduplicates by that same key
   inside its retention window, or a final reconciliation in between found the
   effect absent (`retry_after_unknown`).
7. The owner's ledger holds at most one effect (`duplicate_effect`).
8. A reservation for an operation whose outcome is unknown is still charged, also
   after it expired (`unknown_released`).
9. The runtime did not report an unknown outcome as committed or not run
   (`outcome_settled_without_authority`).
10. The runtime reported the outcome the owner's answers settle
    (`outcome_disagrees_with_authority`).

A record that passes every check is `allow` with reason `effect_held`. Each denied
case is built so the check it names is the first that fails, and the allowed cases
are the safe controls each fault is paired with: a timeout reconciled as absent, a
resend after a final absent answer, a resend under the same key to an owner that
deduplicates, a lease handed over and reconciled, and a late commit waited for.

## What a pass establishes

The trail is consistent with at most one effect for the operation: nothing was resent
blind after a lost reply, a reused key carried the same arguments, every dispatch was
inside a live lease, an unknown stayed charged, and the reported outcome is one the
owner's answers support.

## What a pass does not establish

- That the producer recorded its attempts, replies or the owner's answers truthfully.
- That the owner's ledger count is right.
- That the parties' clocks agree.
- Anything about operations the record does not list.

## Running it

```sh
pip install agent-evidence-vectors==0.30.0
agent-evidence-vectors --corpus vectors-uncertain-effect
agent-evidence-vectors --corpus vectors-uncertain-effect --verifier './verifier'
agent-evidence-vectors runtime --corpus vectors-uncertain-effect --runtime './adapter'
```

A verifier under test takes `record.json --json`, prints one JSON object carrying
`decision` and `reason`, and exits 0 for `allow` and 1 for `deny`.
`aee-verify vectors-uncertain-effect` judges the same cases with the Go reader.
Regenerate the cases with `python3 vectors-uncertain-effect/gen_vectors.py`.
