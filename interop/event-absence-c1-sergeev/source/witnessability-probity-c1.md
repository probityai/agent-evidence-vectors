# C1: a proposed common fragment for bounded event absence

Prepared on 28 October 2026. Three synthetic cases; expectations derived from a finite model and pinned source code. Neither comparison engine has been run on these cases. This is a proposal for review, not an agreed joint experiment or a completed comparison.

## Question and fixed versions

The proposed predicate is: no selected completed write occurred for `agent-c1`, invocation `c1-call-1`, in `c1-window` from `2026-10-28T09:00:00Z` to `09:01:00Z`.

The native event token is `write`. An explicit external premise connects that token to the selected actual completed effect. A request, attempted write, successful response or unchanged endpoint is not substituted for that effect. These synthetic timestamps do not describe a real run.

- Standalone finite checker (`witnessability-research-checker`): development candidate `0.2.0.dev1`, `finite-joint-identity-1`, [source 4a37199](https://github.com/Witnessability/witnessability-research/tree/4a37199f2a59b7ecd97055cfc1af5cb787a76265).
- Probity Verify: `0.2.2`, built-in `event_absence/v2`, [source bc4557b](https://github.com/probityai/probity/tree/bc4557b1237c0d949087c19c6ee17dd858edbedd/packages/probity-verify), with the default `require_witness_scope=PEER` call requirement.

The separate JSON attachment contains exact UTF-8 input files, paths, lengths, hashes and selected-field expectations for both sides. No producer code, credentials or real observations are included.

## Three cases

All cases use the same claim, invocation, time scope, selected producer and capability declaration. Only the observation and its dependent hashes change on the Probity side. All Checker queries use one fixed finite model.

| Case | Observation | Finite expectation | Probity expectation under PEER |
| --- | --- | --- | --- |
| C1-01-covered-empty | Complete coverage, visible `write`, no events | TRUE | `supported / absence_within_covered_scope` |
| C1-02-event-with-gap | Event e1 at 09:00:10; incomplete coverage, gap 09:00:20-09:00:40 | FALSE | `contradicted / event_observed` |
| C1-03-empty-with-gap | Same incomplete coverage and gap, no events | UNRESOLVED | `not_established / observation_coverage_unestablished` |

The finite histories include N with no write, W10 with a write at 09:00:10, and W30 with a write at 09:00:30. The third case retains N and W30 as explicit compatible histories with opposite truth values. The retained event in case 2 is outside the gap, so this proposal does not depend on interpreting an event recorded inside a gap. Placement outside the gap is a fixture choice, not a condition imposed by the Probity adapter; after admission checks, a matching event contradicts the absence claim regardless of its position relative to the gap.

The model also explicitly states the capture assumptions used to determine the exact compatible set. The JSON bundle's `checker/HISTORIES.json`, `checker/checker-model.json` and `checker/EXPECTED.json` are the precise definitions. Creating consumer pins from these authored files establishes preparation consistency; it does not independently validate their premises.

## Conditions and limits of the mapping

1. Claim/event meaning, party, invocation and time attribution are justified outside the records. A positive retained event is assumed truthful. Without this premise, an apparent counterexample need not establish actual occurrence.
2. In the covered case, the selected event type really is visible and capture is complete. Merely writing those declarations does not establish either fact.
3. The incomplete case permits a hidden write in the named gap. Both N and W30 must remain admissible; a missing record alone is insufficient to assert ambiguity.
4. The consumer fixes its policy outside the supplied case, including producer/vantage and exact evidence hashes. Identity, custody and the applicability of the capture assumptions remain external. All fixtures here are authored synthetic data; the `independent` label is not a claim of real independent custody.
5. This adapter does not emit an authenticated top-level `witness_scope`. PEER is the selected call requirement, not a proven property of an observer. Requiring EXTERNAL instead changes case 1 to `not_established / witness_scope_below_required`; it leaves the other two decisions unchanged.

The mapping is deliberately partial. It does not equate every `not_established` with UNRESOLVED. Missing evidence, a failed vantage condition or another unsupported premise may provide no pair of compatible histories. Malformed input or violation of a file's own declared length/hash can refuse without a verdict; a policy witness pin mismatch can instead yield an unbound-witness `not_established`. Neither path is automatically finite-model ambiguity.

The expected decision/reason fields are source-derived predictions, not full frozen decision transcripts. All three predicted semantic decisions have CLI exit 0; that exit code does not mean the claim is supported. WEXP Core, WEXP Coverage, deployment conformance and general WCC/WM/WEXP equivalence are outside this C1 package.

## Review question and next boundary

Does this preserve a fair common fragment of the absence claim under the stated assumptions, or is there a minimal counterexample that breaks the mapping?

Actual C2 comparison would separately pin installed dependencies and code, invoke both engines, retain their full native outputs and errors, and repeat the run. Those steps have not been performed here. This package can be reviewed before undertaking them.
