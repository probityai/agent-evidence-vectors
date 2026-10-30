# Predicate type: Re-enable Decision

Type URI: https://probityai.github.io/agent-evidence-vectors/predicate/v1/re-enable-decision

Version: 0.1.0

Predicate Name: Re-enable Decision

> Status: DRAFT, issued under a self-hosted `predicateType` URI. The URI will not move once
> a signed statement carries it. Record R3 of the
> [restoration evidence profile](../../profiles/restoration-evidence.md), whose common
> members and bundle rules apply.

## Purpose

Records one decision about whether a stopped or restricted agent system may run again: the
outcome, the scope restored, who approved it and how independent each approver was, and, for
every kind of evidence incident guidance asks a restart to show, either the digest of what
was shown or an explicit statement that it was not addressed. A decision record that simply
omits the containment re-check reads the same as one whose author forgot to mention it; here
an omission is a malformed record, and "not addressed" is something the signer has to write.

## Model

The **subject** is the configuration restored, by digest: one or more members, each a
`digest` holding only `sha256` of a baseline (weights, harness, image, tool configuration).

The **predicate** carries the common members, `predecessors` (at least one record of the
profile), and:

- `restoration`: `decision`, a `restoration_decision` value (`resume_full`,
  `resume_staged`, `remain_restricted`, `not_established`); and `restoredScope`, required
  when `decision` is `resume_staged`: `{agents, tools, routes, credentials}`, each a sorted
  list of identifiers, at least one non-empty.
- `approvers`: a list of `{id, roles, independenceBasis}`, `roles` as in R1 and
  `independenceBasis` an `independence_basis` value. Where it is `independent_sources`, the
  approver's own `id` names the independent party.
- `setSufficiency`: the signer's own `set_sufficiency` judgment of the evidence below.
- `evidence`: an object with exactly the slots below. Each slot is a resource descriptor, `{"digest": {"sha256": ...}}` with optional `uri`
  and `mediaType` as in the in-toto ResourceDescriptor, or `{"notAddressed": "<reason>"}` with
  a non-empty reason. A slot can therefore point at an attestation the producer already emits,
  such as a provenance or an audit record.

| Slot | What it holds | Source of the ask |
| --- | --- | --- |
| `actorObjective` | the adversary's objective, or confirmation it is not apparent | NIST SP 800-184 Sec. 2.3.4 |
| `persistence` | persistence mechanisms understood, or non-persistence confirmed | SP 800-184 Sec. 2.3.4 |
| `rootCause` | root cause remediated before production use | SP 800-61r3 RC.RP-05 |
| `affectedScope` | affected hosts, services and similar agents identified | SP 800-61r3 RS.MI-02; Key Practices 6.3 |
| `assetIntegrity` | restoration assets checked before use | SP 800-61r3 RC.RP-03; SP 800-53 CP-10(4) |
| `restoredAssetsClean` | restored assets free of indicators and the original weakness | SP 800-61r3 RC.RP-05; SP 800-184 Sec. 6.2.2 |
| `containmentReproof` | monitors, logging, egress, shutdown and permissions shown working | Key Practices 7.3 |
| `incidentReplay` | new controls shown to catch a replay of the incident | Key Practices 7.4 |
| `restoreOrder` | dependency order of the restoration | SP 800-61r3 RC.RP-04 |
| `postRestartMonitoring` | monitoring that detects recurrence | SP 800-61r3 RC.RP-04; SP 800-184 Sec. 6.2.3 |
| `exclusiveControl` | exclusive control of the environment re-established | SP 800-184 Sec. 6.2.3 |
| `controlsNotDegraded` | controls not degraded by the restoration | SP 800-53 CP-2 |
| `residualRisk` | the remaining risk, stated and accepted | Key Practices 7.5; SP 800-61r3 RC.RP-06 |
| `seniorApproval` | senior approval, informed by outside assessment where used | Key Practices 2.6 |
| `multiPartyAuthorization` | more than one person authorized the restart | AWS Well-Architected Agentic AI Lens |
| `ownerConfirmation` | the system or asset owner confirmed the restoration | SP 800-61r3 RC.RP-04 |

The slots record what a decision cites. Which slots a relying party requires to carry a
digest, and what it does with a `notAddressed` slot, is its own admission policy.

## Rules

| # | Rule | Code |
| --- | --- | --- |
| 1 | Statement shape and Type URI as in R1 | `statement-malformed` |
| 2 | The predicate has exactly its members, each well formed | `predicate-malformed` |
| 3 | Every closed value is registered | `closed-vocabulary-violation` |
| 4 | `evidence` carries every slot, and no other | `evidence-slot-missing` |
| 5 | Every `notAddressed` reason is non-empty | `evidence-slot-unexplained` |
| 6 | `approvers` is non-empty and at least one approver holds `authorized` | `no-approver` |
| 7 | `resume_staged` carries `restoredScope` with at least one identifier | `partial-without-scope` |
| 8 | `resume_full` carries no `restoredScope` | `full-with-scope` |

A statement that passes every rule is accepted as `decision-recorded`.

## What it does not establish

That any cited evidence shows what its slot names, that the approvers were independent in
fact, or that resuming was safe. The record makes the decision checkable and its gaps
explicit. It does not make the decision correct.
