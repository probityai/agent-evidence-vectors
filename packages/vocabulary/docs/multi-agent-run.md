# Multi-agent run terms

Name what a multi-agent defence did to its agents' communication graph during one run, so that a party who does not trust the defence can check it. The [README](../README.md) is the short version of the repository; this page covers the `multi_agent_run` section, added in 0.9.0.

A defence that watches a group of agents can cut an edge between two of them, isolate one, restart it and later let it talk again. Its own log says each of those things happened. A reader who was not there needs a record that separates a cut edge from a closed channel, a restart from a clean agent, and a re-enable from the evidence that justified it. The record is one hash-chained journal of typed entries: the containment-journal predicate, whose conformance corpus is `vectors-containment-journal` in this repository. These seven terms name the parts of that journal a verifier decides, and each carries a `check`: the rule a verifier applies to decide it. All seven are `proposed`, none lists an issuer, each has `criticality: critical` and a `review_by` date, and none is canonical.

## One question, answered in terms

Did a message still cross an edge the defence said it had cut? Each delivery gets a `message_delivery_disposition`, computed by the verifier from the topology it rebuilds out of the journal, never read from the producer. Did the router refuse such messages, or did it only tell the agents the topology? That is `topology_enforcement`. What steered the decision to cut: a detector, a random draw, a timer, or knowledge of which agents were compromised? A `topology_decision_basis`. When an agent was restarted, was only its memory cleared, or also the configuration that made it hostile? A `restart_scope`. When a contained agent was let back in, which earlier entries did the admission rest on, and do they hold? A `restoration_evidence_binding`. When an assessment of an agent has no number, is that because the agent said nothing or because the judge failed? An `assessment_availability`. And when an agent's call to its model failed, is that recorded as a failure or as silence? A `generation_outcome`.

## The terms

| term | what it names | check |
|---|---|---|
| `message_delivery_disposition` | how the router handled one message relative to the topology in force | the recorded edge flag equals the recomputed edge; a drop over a present edge is refused; a delivery over an absent edge is refused in an enforced run |
| `topology_enforcement` | whether the router enforces the declared topology or only states it | an advisory run never supports a claim that a channel was closed; an absent member is malformed, never read as enforced |
| `topology_decision_basis` | what label or input steered one topology decision | reported beside every effect claim; an oracle or online-label basis is never read as an oracle-free result; a detector decision cites the fields it read and differing risk estimates |
| `restart_scope` | what a restart of one agent removed | the remediated flag equals whether the configuration digests differ; a restart that did not clear memory is refused |
| `restoration_evidence_binding` | one evaluation of the rule that admits or refuses re-enabling a contained agent, bound by digest to the entries it rests on | an admission cites earlier entries by digest, including a restart and an assessment of the agent, and the latest cited assessment is scored, externally witnessed and below the threshold |
| `assessment_availability` | whether an assessment exists as a number and, when it does not, why | a score with a missing value is refused; a missing score is never replaced by zero and never counts toward an admission |
| `generation_outcome` | the result of one call of an agent to its model | a run with any errored call is reported with its count; the assessment of an agent whose call errored is not read as a healthy observation |

## The values

| term | values |
|---|---|
| `message_delivery_disposition` | `delivered_in_topology`, `delivered_over_absent_edge`, `dropped_over_absent_edge` |
| `topology_enforcement` | `advisory`, `enforced` |
| `topology_decision_basis` | `detector_online_label`, `detector_no_label`, `random_rate_matched`, `ground_truth_oracle`, `fixed_schedule`, `evidence_gate` |
| `restart_scope` | `memory_only`, `memory_and_cause_removed` |
| `assessment_availability` | `scored`, `no_output`, `judge_missing` |
| `generation_outcome` | `produced`, `errored`, `empty_reply` |

`restoration_evidence_binding` lists no values: it is a structured record of cited entry digests, a rule digest, a threshold and the admitted flag. Every list is closed and fail-closed, so an absent or unregistered value makes the entry malformed. Each value is defined in `vocabulary.yaml` under `value_definitions`. Source paths beginning `predicate.` name members of the containment-journal predicate. `generation_outcome` names a member, `generationOutcome`, that no published predicate carries yet, so its source path fixes nothing until a predicate does.

## Terms it reuses

The journal also carries values from other sections, which this section does not redefine. A decision's `responseFunction` is an `incident_response.response_function` value (`restriction`, `isolation` or `restoration`), a fallback's `failurePosture` is an `incident_response.control_failure_posture` value, a response entry's `decision` is an `incident_response.response_decision`, and an assessment's `witness` is an `evidence_dimensions.witness_scope` value (`SELF`, `PEER` or `EXTERNAL`). See [incident-response.md](incident-response.md).

## Two splits worth knowing

`message_delivery_disposition` and `topology_enforcement` answer different questions. The first counts, message by message, whether anything crossed an edge after the defence cut it. The second says whether anything could have stopped it. A run with no `delivered_over_absent_edge` is still no evidence of a closed channel when it is `advisory`: the agents may simply have obeyed the prompt that run.

`restart_scope` and `restoration_evidence_binding` split a restart from a return. `memory_only` says the agent came back with the configuration it had, so its next assessment is the only thing standing between it and the graph. `restoration_evidence_binding` is where that assessment is cited, by digest, so a reader can check that the admission rested on an external score taken after the restart and not on the agent's own account of itself.

## Check it

```bash
python3 scripts/test_multi_agent_run.py
python3 scripts/validate_crosswalks.py
python3 scripts/check_opencre_links.py
```

The first holds the registry, the validator and this page to each other: every term starts proposed with no issuer, has a check, a definition, a promotion trigger and a review date, every value is defined, every registered value is accepted and an unregistered one refused, and this page names every term and every value; a mapping filed under the wrong section is refused by name.
