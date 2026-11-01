# Observability evidence field set: each proposed field against this registry

This sidecar travels with [`obs-evidence-field-set.yaml`](obs-evidence-field-set.yaml). The
crosswalk is keyed by this registry's terms, so a proposed field with no term here cannot appear
in it. This table goes the other way: one row per field in the candidate set, read from
[raknor-ai/agent-governance-standard#2](https://github.com/raknor-ai/agent-governance-standard/issues/2)
and [Equilateral-AI/agent-governance-scorecard#4](https://github.com/Equilateral-AI/agent-governance-scorecard/issues/4)
as they read on 2026-09-30.

| Proposed field | Term here | Match | What would make it exact |
| --- | --- | --- | --- |
| `observation_vantage` | `observation_vantage` | partial | the closed values `substrate` and `artifact`; weakest-input composition; a consumer rule that a substrate value needs a policy-pinned root; suppression named beside influence |
| `coverage_denominator` | `coverage_denominator` | partial | the three-way partition (assessed, out of scope with a reason, routed elsewhere); a digest-committed manifest the producer does not control |
| `does_not_assert` | `does_not_assert` | partial | carried inside the signed bytes; one spelling per non-claim |
| `schema_version` | none | no term | a version identifier belongs to the record format, and this registry defines terms, not a format |
| `identity` | none | out of scope | `out_of_scope` in vocabulary.yaml excludes agent identity |
| `task` | none | no term | governance context; `field_evidence_partition` says whether the operator asserted it |
| `authority_in_effect` | none | no term | governance context; `field_evidence_partition` applies |
| `policy_version` (standard only) | none | no term | governance context; `field_evidence_partition` applies |
| `action` | none | no term | governance context; `field_evidence_partition` applies |
| `outcome` | `result` | non-equivalent, similar label | none: `outcome` is what the action led to, and `result` is a recomputed verdict over the record's own conditions |

## Terms here with no proposed field

| Term | What the record could not say without it |
| --- | --- |
| `observation_directness` | whether the record was captured live or reconstructed from state left behind |
| `witness_scope` | whose account the record is; the external witness a completeness claim was reconciled against would carry `EXTERNAL` |
| `field_evidence_partition` | which of the six governance-context fields the operator asserted and which an outside observation covers |
| `issuance_time_basis` | that the signature cannot predate a public beacon round; `commitment_anchor` (mapped in the crosswalk, from the draft SC-OB-01 clause) gives the other bound |
| `containment_posture` | the network posture of the environment the agent ran in |

## Two notes on the proposal text

The standard's issue names OBS-06 as its current text. OBS-06 is a control in
[agentbaseline/agentbaseline](https://github.com/agentbaseline/agentbaseline/blob/main/whitepaper/controls.yaml);
the standard's own Observability domain numbers its controls SC-OB-01 onward. SC-OB-01 already
requires the action, its inputs, the consequence tier, the authority level and a timestamp in
every decision record, and SC-OB-02 requires the governance constraints active at execution, so
`action`, `authority_in_effect` and `policy_version` restate mandatory controls the standard
already has. `identity`, `task` and `outcome` are new there.

Both issues are open for comment until 2026-11-30, so this mapping is against a draft. When the
field set is adopted, this file is re-read against the adopted text and the crosswalk version moves.
