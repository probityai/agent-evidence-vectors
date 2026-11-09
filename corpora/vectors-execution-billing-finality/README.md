# Execution billing finality vectors

Cases for `execution-billing-finality/v1`: one attempt whose execution outcome and
whose bill are settled separately, often after its reply was lost. A call can succeed
and leave its bill open, so the money held for it stays held. A final invoice,
including one for zero, settles the bill and says nothing about whether the call ran.
A settled bill is never permission to dispatch the same attempt again. This is the
sibling of [vectors-uncertain-effect](../vectors-uncertain-effect/), whose record has
one `reservation.charged` flag and no billing axis.

Each case is one runtime's observation of one scenario against its spend ledger, with
an expected decision and reason in `MANIFEST.json`. Every record was produced by
running the reference adapter over the P04 ledger, unmodified for the six controls and
with one mutant spliced in for six of the denials; the other nine denials change one
field of a control.

## Run it

```sh
pip install agent-evidence-vectors
python -m agent_evidence_vectors.executionbilling --verifier "my-verifier"
python -m agent_evidence_vectors.executionbilling_runtime --runtime "python my_adapter.py"
```

The first judges every record through a verifier; the second drives a runtime's own
ledger through the six control scenarios. `tests/billing_adapter.py` is the reference
adapter over the P04 ledger, and its `--source` option runs a mutant.

## The record

`scenario` is the input the runtime was given: `id`, `budget`, `steps` and `probes`,
in the P04 command vocabulary (`reserve`, `dispatch`, `unknown`, `outcome`,
`invoice`, `cost`, `non_dispatch`) and with no expected value. Setup reserves attempt
A for two units. The record then carries the state after the reservation (`initial`),
each step's `{exception, return, state}`, the state after the steps (`observed`), after
a reopen in a fresh process (`reopened`), each probe, and the state at the end and after
a final reopen (`end`, `endReopened`). Every state carries `executionOutcome`
(`UNKNOWN`, `SUCCEEDED`, `FAILED`, `NOT_DISPATCHED`), `billingFinality` (`UNKNOWN`,
`FINAL`, `CONFLICT`), `dispatchState` (`RESERVED`, `POSSIBLE`, `NOT_DISPATCHED`),
`knownSpendMicroUsd`, `heldMicroUsd`, `availableMicroUsd`, `unbounded` and `frozen`.
Money is a nonnegative integer; a boolean or a float is not money. `externalEffect` is
always `NOT_EVALUATED`, and `mustNotClaim` lists `external_effect_established`,
`invoice_authenticity`, `production_durability` and `upstream_acceptance`.

`dispatchState` is a required output of every state. After an accepted invoice for a
reserved attempt with no recorded dispatch it reads `POSSIBLE`: conservative
bookkeeping, not proof that a dispatch happened.

## The checks

The reader names the first check a record fails:

| # | Reason | The record fails it when |
|---|---|---|
| 1 | `contract_id_missing` | it carries no `contractId` |
| 2 | `contract_id_unknown` | `contractId` is another contract |
| 3 | `record_malformed` | a state, action or the scenario lacks its shape, or an amount is not an integer |
| 4 | `dispatch_state_missing` | a state has no `dispatchState`, or a value outside the three |
| 5 | `claim_boundary_dropped` | `externalEffect` is evaluated, or a claim boundary is missing |
| 6 | `reopen_changed_state` | a reopen reads a different state than was written |
| 7 | `execution_outcome_without_observation` | an outcome other than `UNKNOWN` has no accepted observation of it |
| 8 | `held_released_before_final_billing` | billing is not final and less than the reservation less known spend is held |
| 9 | `same_attempt_redispatched` | a dispatch of attempt A is allowed when it is not `RESERVED` with billing `UNKNOWN` |
| 10 | `dispatch_state_reserved_after_billing` | billing is final or in conflict and the dispatch state is still `RESERVED` |
| 11 | `invoice_replay_refinalized` | a replayed invoice event is new or finalizes again |

A record that passes all eleven is `allow` with reason `finality_held`.

## The verifier contract

`<verifier> <case-dir>/record.json --json` prints one JSON object carrying `decision`
and `reason`, and exits 0 for `allow` and 1 for `deny`. The manifest states it as
`verifierContract`.

## The runtime contract

The adapter is run as `<runtime> <scenario.json> --json`. It reserves attempt A for two
units on a fresh account under the scenario's budget, runs the steps through its own
ledger, reopens the ledger in a fresh process, runs the probes there, and prints one
record as its last stdout line. It exits 0 for a completed observation and nonzero for
an operational failure, which is never read as a verdict. A scenario passes when the
record echoes the scenario and the reader allows it.

## Cases and the mutants each scenario kills

Controls: F01 (the call succeeded, no final invoice, the reservation stays held), F05
(F01 followed by a final invoice), F03 (a lost reply, the second dispatch refused), F04
(a final invoice after a lost reply: billing `FINAL`, execution `UNKNOWN`, a second
dispatch refused, a new attempt admitted), F14 (the first dispatch allowed) and X1 (an
invoice before any recorded dispatch, with the state `POSSIBLE` after the reopen, the
refused dispatch, the replayed invoice and an equal cost observation).

`MANIFEST.json` carries the mutation table, recomputed by the generator: the guard
removed is killed by F03, F04 and X1; settled billing bypassing the guard by F04 and X1;
the invoice no longer writing `POSSIBLE` by X1 through check 10; that write and the
billing clause dropped together by X1 through check 9; a success releasing the
reservation by F01 and F05; an invoice marking the execution by F04 and X1. Dropping
only the guard's billing clause leaves every observation identical to the unmodified
ledger's, because every write that settles billing also moves the dispatch state off
`RESERVED`: it is recorded as equivalent in the code as written, a surviving control
and not a detected defect.

## What a pass does not establish

That an invoice is authentic, that an external effect happened or did not, that the
ledger survives a power loss, or that anything holds across different attempt ids.

## Source and credit

The ledger (`tests/p04/exposure_ledger.py`, an unmodified copy, MIT, see
`tests/p04/LICENSE` and `tests/p04/SOURCE.json`), the F-scenarios and the input
contract are mohammedmessaoudene-cmd's P04 execution and billing candidate,
agent-evidence-lab at `8db9989`. X1, the three dispatch-guard mutants and the
observation that made `dispatchState` a required output are from piiiico's
non-author run of it. Issues
[#435](https://github.com/probityai/agent-evidence-vectors/issues/435) and
[#485](https://github.com/probityai/agent-evidence-vectors/issues/485).
