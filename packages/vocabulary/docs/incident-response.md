# Incident response terms

Name the parts of an incident response so that what was decided, what was done, what held and what was restored can be told apart. The [README](../README.md) is the short version of the repository; this page covers the `incident_response` section, proposed after 0.8.0 and not yet in a release.

When something goes wrong in an agent system, the people responding take decisions, take actions, and later end them. Their own logs say what they chose to record. A third party who was not there needs records that separate the decision from the action, the action from its effect, and a restart from the decision that was supposed to precede it. These eleven terms name the parts, and each carries a `check`: the rule a verifier applies to decide it. All eleven are `proposed`, none lists an issuer, each has `criticality: critical` and a `review_by` date, and none is canonical.

## One question, answered in terms

Did anyone decide not to act? A `response_decision` of `continue` is a signed record with the deciding authority and a reason, so a non-action is not an absence. What did an action serve? Its `response_function` values. Was it enforced beneath the subject, or only honoured by it? That is `enforcement_vantage`. What happened when the decision service gave no answer? A `control_failure_posture`. Was a revocation only issued, or refused when used? A `revocation_state`. Which channels were cut, and which were never assessed? A `containment_scope`. Did a pause stop the subject, or does its earlier work remain? A `pause_hold`. How long from the alert to someone able to act? An `escalation_outcome`. Who approved the restart, and did it follow a decision? A `restoration_decision`, and a `restoration_gate` for whether the restart that happened was preceded by one. Which two organisations' records are the same incident? An `incident_identifier`.

## The terms

| term | what it names | check |
|---|---|---|
| `response_decision` | the decision at one decision point, including a decision not to act | a `continue` carries the deciding authority and a non-empty reason; an `act` carries at least one function |
| `response_function` | the function an incident action served | `restoration` is never combined with another value; an `act` lists at least one value |
| `enforcement_vantage` | where an action was enforced and observed | never `supported` when the only evidence is at `subject_self` |
| `control_failure_posture` | what the gate did when the decision service returned no usable decision | `fail_open`, `unguarded_start` and `late_decision` never count as enforced |
| `revocation_state` | where a revocation stands at one relying party at one time | `use_after_revocation` when any accepted use is at or after the effective time; never `enforced_observed` from an issuance record alone |
| `containment_scope` | a partition of the channels a subject could use into cut, retained and unassessed | the union equals a manifest the subject does not control; a non-empty unassessed set is partial |
| `pause_hold` | whether a pause held | `effect_after_pause` only for an effect initiated at or after the pause; never `held` while an in-flight operation is unconfirmed or created state is active |
| `escalation_outcome` | whether an alert reached someone able to act in time | `pagedAt` minus `alertAt` against the bound; times from the responder's own system give `not_established` |
| `restoration_decision` | the decision that ends a recorded containment | bound to the containment, with an approver different from the activator |
| `restoration_gate` | whether an observed restart passed the gate the decision sets | the restart time comes from the substrate; no bound decision before it gives `ungated` |
| `incident_identifier` | one identifier, scoped by its issuer, for one incident | joins only on equal issuer and id, or a `related` entry; never on timing or names |

## The values

| term | values |
|---|---|
| `response_decision` | `act`, `continue`, `escalate` |
| `response_function` | `monitoring_increase`, `restriction`, `isolation`, `pause`, `remediation`, `restoration` |
| `enforcement_vantage` | `subject_self`, `co_located_runtime`, `substrate`, `relying_party` |
| `control_failure_posture` | `fail_closed`, `fail_open`, `unguarded_start`, `late_decision` |
| `revocation_state` | `issued`, `enforced_observed`, `use_after_revocation`, `not_established` |
| `pause_hold` | `held`, `in_flight_unknown`, `effect_after_pause`, `residual_state_remains`, `not_established` |
| `escalation_outcome` | `paged`, `paged_late`, `not_paged`, `not_established` |
| `restoration_decision` | `resume_full`, `resume_staged`, `remain_restricted`, `not_established` |
| `restoration_gate` | `gated`, `ungated`, `gate_unmet`, `not_established` |

`containment_scope` and `incident_identifier` list no values: the first is a digest-committed partition, the second an issuer and an id. Every list is closed and fail-closed, so an absent or unregistered value makes the statement malformed. Each value is defined in `vocabulary.yaml` under `value_definitions`. Source paths beginning `predicate.` name fields of a predicate that is not yet specified; they fix nothing until a predicate specification does.

## Two splits worth knowing

`pause_hold` separates an effect by the paused subject (`effect_after_pause`) from state the subject left behind before the pause (`residual_state_remains`). Only the first shows the pause failed to stop the subject; the second shows what remains to be remediated. When several apply, the record carries the first of `effect_after_pause`, `in_flight_unknown`, `residual_state_remains`, `held`.

`restoration_decision` records the decision, and `restoration_gate` records whether the restart that actually happened was preceded by a decision that met its requirements. A decision not to resume is `remain_restricted` and is recorded the same way as a resumption.

## Crosswalks

Five filings from outside map neighbouring guidance onto these terms. Each is `third_party_authored`, every claim is asserted from prose, and none promotes a term: a document emits no signed records, and promotion needs an emitting system's own maintainers.

| filing | maps | read for |
|---|---|---|
| [`crosswalk/nist-sp-800-61r3.yaml`](../crosswalk/nist-sp-800-61r3.yaml) | NIST SP 800-61r3 incident response recommendations | containment, eradication and recovery outcomes with no record format |
| [`crosswalk/nist-key-practices-si.yaml`](../crosswalk/nist-key-practices-si.yaml) | NIST key practices for incident readiness and response in superintelligence training and evaluation | shutdown (6.1 to 6.5) and verification plus a documented decision before resuming (7.1 to 7.6) |
| [`crosswalk/aws-agentic-ai-lens.yaml`](../crosswalk/aws-agentic-ai-lens.yaml) | AWS Well-Architected agentic AI lens, AGENTSEC07-BP04 | quarantine and restore runbooks with multi-person authorization |
| [`crosswalk/owasp-agent-control-standard.yaml`](../crosswalk/owasp-agent-control-standard.yaml) | OWASP Agent Control Standard decision events | decision failure, unguarded start and late decision |
| [`crosswalk/aiir-kill-switch-api.yaml`](../crosswalk/aiir-kill-switch-api.yaml) | the AIIR kill switch API | containment modes M1 to M5, a probe call, and the credential-event schema |

## Check it

```bash
python3 scripts/test_incident_response.py
python3 scripts/validate_crosswalks.py
python3 scripts/check_opencre_links.py
```

The first holds the registry, the validator and this page to each other: every term starts proposed with no issuer, has a check, a definition, a promotion trigger and a review date, every value is defined, and this page names every term and every value; a mapping filed under the wrong section is refused by name.
