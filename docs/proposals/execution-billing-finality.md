# Proposed corpus: execution outcome against billing finality

Draft contract for a sibling of `vectors-uncertain-effect`. It is a proposal: nothing here is shipped, and `uncertain-effect/v1`, its checks and its reason codes do not change. The source is the P04 execution and billing candidate by mohammedmessaoudene-cmd (agent-evidence-lab, `collaborations/open-evidence-lab/p04-execution-billing/` at `8db9989`), with the dispatch-guard mutants, the X1 case and the `dispatch_state` observation contributed by piiiico (Agent Errata) from a non-author run of it. Issue 435 tracks it.

## 1. Why a sibling corpus

`uncertain-effect/v1` has one boolean, `reservation.charged`, and it binds only while the outcome is unknown. It cannot say that a call succeeded, no final invoice has come, and the reservation must stay held (F01), or that a final invoice moves a reservation to a known cost while the execution outcome stays unknown (F04). Those need two axes the record does not carry: what happened to the execution, and whether billing has settled. A final invoice, including one for zero, answers the second question and says nothing about the first.

## 2. State

Three observed fields, kept apart:

* `execution_outcome`: `UNKNOWN`, `SUCCEEDED`, `FAILED` or `NOT_DISPATCHED`. It is never converted into a verdict on the business effect.
* `billing_finality`: `UNKNOWN`, `FINAL` or `CONFLICT`.
* `dispatch_state`: whether the ledger permits another dispatch of the same attempt. A required observable output, not an internal detail: after an accepted invoice for a reserved attempt with no recorded dispatch it reads `POSSIBLE`, conservative bookkeeping that is not proof a dispatch happened.

Money is a nonnegative integer in micro-USD; a boolean or a float is not money. `external_effect` stays `NOT_EVALUATED` in every record, so a pass can never be read as an external effect established.

## 3. Cases, in order of build

1. F01: the call succeeded, no final invoice has come. Expected: execution `SUCCEEDED`, billing `UNKNOWN`, the reservation still held. A runtime that frees the reservation because the execution succeeded is denied. Its control is the same trail after a final invoice, with the reservation moved to known cost.
2. F04: the reply was lost, then a final invoice for part of the reservation. Expected: execution `UNKNOWN`, billing `FINAL`, known cost the invoice, held zero for that attempt, and a second dispatch of the same attempt refused. A new, distinct attempt can still be reserved.
3. X1: an invoice for an already reserved attempt arrives before any recorded dispatch. It is admitted, settles billing only, and cannot open the same attempt's dispatch gate. An invoice for an unregistered attempt, or from the wrong source role, is rejected.
4. The dispatch-state requirement: the `POSSIBLE` state must survive a fresh-process reopen, a refused same-attempt dispatch, a replayed identical invoice and a later equal cost observation. The replay is not new and does not finalize again.

## 4. Mutation set

Each mutant changes the dispatch guard, and a case must kill it. Three are against the `dispatch_start` guard: the guard removed (killed by F03, F04, F08 and F09), `billing_finality != "FINAL"` added (killed by F04, F08 and F09), and the billing clause dropped so the guard reads `if dispatch_state != "RESERVED":`. The third survives all eighteen v0.1 cases, because every write that moves billing off `UNKNOWN` also moves the dispatch state off `RESERVED`, so it is recorded as equivalent in the code as written and counted as a surviving control, not a detected defect. X1 kills the pair of dropping the write of `POSSIBLE` on invoice and the billing clause together. The `dispatch_state` output kills the mutant that no longer writes `POSSIBLE` on invoice by itself, because `project()` in the v0.1 reader drops the field and no v0.1 case can see it.

## 5. What a pass does not establish

That an invoice is authentic, that an external effect happened or did not, that the ledger survives a power loss, or that anything holds across different attempt identifiers: suppressing a second dispatch of one attempt is not exactly-once behaviour in general.

## 6. Packaging

The corpus ships with a `verifierContract` entry in its manifest from the first release, which `vectors-uncertain-effect` also carries; a corpus without one leaves a verifier nothing to run it by. The runtime contract is the one the candidate's adapter uses: `<adapter> scenario.json --json`, one JSON object on the last stdout line, exit 0 for a completed observation, nonzero for an operational failure; the scenarios hold no expected values, which stay on the judge's side. The corpus id, generator, reader and registration follow the nearest small corpus. This text is its starting draft.
