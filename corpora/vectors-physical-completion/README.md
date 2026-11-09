# Physical-completion vectors

Cases for `physical-completion/v1`: what a verifier reports when a relying party asks whether an
action's physical effect happened, judged against
[draft-noa-scitt-ai-agent-receipt-01](https://www.ietf.org/archive/id/draft-noa-scitt-ai-agent-receipt-01.html).
The draft keeps three claims apart: pre-execution authorization, the outcome a controller
reported, and physical completion, which it defines as an identified witness observing the
intended effect against a criterion fixed before execution. A receipt carries none of the last
two. The claim boundary and the seven starting cases were proposed by hippoley (Noah Ellis) in
[issue 80](https://github.com/probityai/agent-evidence-vectors/issues/80), with the FlyThink
[physical-completion rail](https://github.com/hippoley/FlyThink-Anatomy-Demo/commit/1be4ff7d63e166842d67fe04ecd10bb3054fca3a)
and [claim-scope fixture](https://github.com/hippoley/FlyThink-Anatomy-Demo/commit/01297c1dbca49be19f6af6c90dda58bb08c03f9d)
as probes.

For anyone who builds a verifier over receipts, controller reports or witness observations, and
wants a check that refuses a receipt read as a physical effect and a lost reply read as a failure.

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-physical-completion
python3 corpora/vectors-physical-completion/check_vectors.py --verifier './verifier'
```

A verifier takes `record.json --json`, prints `{"decision": ..., "reason": ...}` and exits 0 for
`conformant`, 1 for `nonconformant` and 2 for `ambiguous`. In the GitHub Action, set
`corpus: vectors-physical-completion`.

## What a record is

One presentation and one result. The presentation is a receipt (verdict `EXECUTED`, dispatch
time), optionally a controller outcome, a transport acknowledgement and a physical-observation
artifact (authenticated, bound to the action, witness, criterion digest and the time it was
fixed, observation time and window end, whether the criterion was met), and the verifier's trust
configuration with the witnesses it trusts for this purpose. The result is what the verifier
reported for the `PHYSICAL_COMPLETION` intent.

## The closed vocabulary

Seven values. The four absence results of Section 8.3, which the draft tokenises: `NOT_CLAIMED`,
`NOT_PROVIDED`, `NOT_APPLICABLE`, `INDETERMINATE`. Three results the draft names and does not
tokenise, spelled here in this corpus's vocabulary, `physical-completion/v1`:
`PROVEN_TO_POLICY` (with `trustConfiguration`), `NOT_SATISFIED`, and `CONFLICT` (with `claims`
carrying both the controller's and the witness's claim).

## What the cases force

The reader applies ten checks from the draft's normative text in order and names the first that
fails: `contract_id_missing`, `contract_id_unknown`, `result_member_absent`,
`proven_without_policy` (an unqualified `PROVEN`, `PHYSICAL_COMPLETION_PROVEN`, or
`PROVEN_TO_POLICY` without a trust configuration; Section 8.2), `result_outside_vocabulary`,
`untokenised_result_as_profile_token` (`CONFLICT` presented as the draft's own vocabulary;
Section 1.5), `completion_from_receipt` and `completion_from_controller_report` (Section 8.1),
`negative_without_observation` (`NOT_SATISFIED` when no presented observation says the criterion
was not met, including a lost acknowledgement; Section 8.3) and
`absence_not_reported_as_not_provided` (Section 8.3). Counts are in `MANIFEST.json`.

## What the draft leaves open, and the rules this corpus puts forward

Section 1.5 leaves the physical-observation and controller-outcome artifacts undefined, so a rule
over their contents cannot be failed under -01. The draft does fix the failure model those
artifacts must satisfy, and Section 12 lists the negative vectors it calls for as unwritten: a
controller success with no physical evidence, a controller success against a witness reporting
non-completion, a stale or replayed observation, and the positive baselines. This corpus writes
them and puts forward ten rules, in this order: `absence_reported_as_not_claimed`,
`observation_unauthenticated`, `observation_unbound` (each owes `NOT_PROVIDED`),
`witness_unidentified`, `witness_untrusted`, `criterion_not_prefixed`,
`observation_outside_window` (each owes `INDETERMINATE`), `conflict_erased`,
`conflict_drops_a_claim` (both owe `CONFLICT`) and `observation_outcome_not_reported`. A result
that breaks one is `ambiguous` and lists two readings: the profile's, under which it is
conformant, and this corpus's, under which it is not. The rules are a proposal, marked as one in
`MANIFEST.json`, and a later revision of the draft or a companion defining the artifacts
overrides them.

## Source and credit

Each member carries `source` (the case of issue 80, the probe, or the Section 12 item it
writes), `rule`, and the sentence of the draft it rests on. `MANIFEST.json` pins the retrieved
text of the draft at sha256 `246b5da4c6ab0045e20d50f7f60ba41db03d49518255b360d8bf39b6ac0560a4`
and names the provenance as `hippoley, issue 80`. The probes are cited, not copied, and their
expected answers are not trusted: the probe's `PHYSICAL_COMPLETION_PROVEN` is the unqualified
form Section 8.2 forbids, and a member says so.

## What it does not test

Wire formats for the observation or controller artifacts, how a verifier authenticates them or
derives organizational independence, signer relationships, whether the criterion is the right
one, and safety or legal correctness. The facts are given. Every member is synthetic. Regenerate
with `python3 corpora/vectors-physical-completion/gen_vectors.py`.
