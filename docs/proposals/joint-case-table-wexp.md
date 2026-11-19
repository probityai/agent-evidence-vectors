# Exact adjudication and record checks: the joint case table

First joint result of Mikhail Sergeev and Sankalp Gilda, for a workshop paper on exact adjudication followed by weakest-signal aggregation. Mikhail Sergeev wrote the exact checker, the C1 cases and the lost-binding candidate (slides of the 18 November 2026 call; preprint "Claim Adjudication under Uncertain Binding and Shared Failures", https://doi.org/10.5281/zenodo.23871213). This page states each case once, with both methods' outputs as run.

The two methods:

- **Record check:** `event_absence/v2` in agent-evidence-verify 0.5.1. It reads one observation record and one capability record per claim and returns `supported`, `contradicted` or `not_established` with a reason. Binding and failure-domain assumptions are consumer premises outside the record; the record format has no field for either.
- **Exact checker:** the standalone finite checker in Witnessability/witnessability-research at `719b243`. It reads a declared finite model (histories, truth, joint supports, allowed fault sets) and one record, and returns `TRUE`, `FALSE`, `UNRESOLVED` or `OUTSIDE_MODEL` with the compatible histories. Its binding is the identity; a binding error is written as an explicit capture variant, the method its own protocol uses for binding-error controls.

Pairing, as agreed on 18 November: `TRUE` with `supported`, `FALSE` with `contradicted`, `UNRESOLVED` with `not_established`. `EXTERNAL` below is the record check's authority-policy requirement and is kept apart from `UNRESOLVED`.

## Cases

| Case | Claim | Assumptions | Record check (PEER; EXTERNAL) | Exact checker | Reason for the difference |
| --- | --- | --- | --- | --- | --- |
| C1-01 covered, empty | No completed write by the party in the window | Write visible, capture complete | supported; not_established, witness_scope_below_required | TRUE | None. EXTERNAL is an authority-policy condition |
| C1-02 event, coverage gap | Same | A retained event is truthful | contradicted; same | FALSE | None |
| C1-03 empty, coverage gap | Same | Capture may omit a write inside the gap | not_established, observation_coverage_unestablished; same | UNRESOLVED (N, W30) | None at decision level. The checker names the two opposite histories |
| D1-01 uncertain binding | Same | The observer attributes writes to an invocation through a session id that a concurrent call shares | contradicted, event_observed; same | UNRESOLVED (W10, X10) | The record check takes the record's invocation field as the binding. The checker keeps the history where the observed write was the other call's |
| D1-02 shared failure domain | Same | Two observers, both empty and covered, run on one capture host | supported, absence_within_covered_scope; not_established, witness_scope_below_required | UNRESOLVED (N, W30) | The record check reads one observation and has no failure-domain field. The checker lets one host fault change both observers, so the hidden write remains |
| D1-03 separate failure domains (control) | Same | As D1-02, on two hosts: at most one observer fails | supported; not_established, witness_scope_below_required | TRUE (N) | None. Only the fault family differs from D1-02, and the checker's verdict moves with it while the record check's does not |
| L1-01 lost binding | The write executed after permission for A was A | Exactly one write followed the permission; the result record names no action | not_established, field_visibility_unestablished; same | UNRESOLVED (EA, EB) | Same pairing, different explanation. The record check reports that the action is not visible; the checker shows the two histories that produce the same record |
| L1-02 binding restored (control) | Same | The result record names the action it executed | supported; not_established, witness_scope_below_required | TRUE (EA) | None. Adding the action to the result resolves the L1-01 ambiguity in both methods |

The C1 rows are Mikhail Sergeev's cases in [interop/event-absence-c1-sergeev](../../interop/event-absence-c1-sergeev/), with the record check as run by probity-verify 0.2.2 (the name agent-evidence-verify carried before 0.5.0). The D1 and L1 rows are in [interop/adjudication-disagreement-d1](../../interop/adjudication-disagreement-d1/): the probity-side records, the checker models and records, the checker's expected pins and the expected outputs, all written by `gen.py`. The expected outputs were written from each method's published rules before either method ran; both runs returned them.

## What the disagreements say

D1-01 and D1-02 are the two places where the record check answers and the exact checker does not. In both, the record is the same and the difference is an assumption the record check cannot read: who an event belongs to, and which observers can fail together. Each control (D1-03, L1-02) changes one assumption or one field and the disagreement goes away, so the cause is that assumption, not the records.

The evidence that resolves each case:

- D1-01: a per-event invocation binding written by the party that executed the write, so the misattributed history yields a different record.
- D1-02: observers in separate failure domains (D1-03), or a co-signature from a second operator, which is what the record check's EXTERNAL requirement asks for.
- L1-01: a result record that carries the executed action (L1-02).

## To run

Record check:

```sh
uv run --no-project --python 3.13 --with agent-evidence-verify==0.5.1 python interop/adjudication-disagreement-d1/run.py
```

Exact checker, from a clone of witnessability-research at `719b243b6c8b1bcd4429cab6347bb3e77ead6a5e`:

```sh
python3 interop/adjudication-disagreement-d1/run_checker.py --checker-root ../witnessability-research
```

The CI job `adjudication_d1` runs both, and the generator check, on every batch.

## To run by Mikhail Sergeev

The checker models for D1 and L1 were written on our side in the checker's own input language. Two things only their author can settle:

1. Whether each model is the encoding the method intends. Run `run_checker.py` above and, for each case, compare `inputs/checker/models/<case>.json` with the assumption in the table.
2. The uncertain-binding cases under the general binding method of the preprint, which the standalone checker at `719b243` does not implement (`experiments/endpoint-counter-001/docs/LIMITATIONS.md` there). For D1-01 and L1-01, the expected verdict under that method is left open until it is run.

## Proposed paper structure

1. The question: when do records decide a claim, and what should aggregation do when they do not.
2. The two layers: exact adjudication, then weakest-signal aggregation with signals counted per failure domain.
3. The common fragment: the C1 cases, where the methods agree.
4. Disagreements: D1-01, D1-02 and L1-01, each with its control and the evidence that resolves it.
5. What aggregation grades: confidence only where adjudication decided; what it reports on UNRESOLVED.
6. Record formats: which fields a record needs so that the assumptions in section 4 can be checked rather than assumed.
7. Reproduction: this table and the CI job.
