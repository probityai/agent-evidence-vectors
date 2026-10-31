# Predicate type: Incident Action Authorization

Type URI: https://probityai.github.io/agent-evidence-vectors/predicate/v1/incident-action-authorization

Version: 0.1.0

Predicate Name: Incident Action Authorization

> Status: DRAFT, issued under a self-hosted `predicateType` URI. The in-toto
> new-predicate guidelines leave the URI namespace to the predicate designer. The URI will
> not move once a signed statement carries it. Record R1 of the
> [restoration evidence profile](../../profiles/restoration-evidence.md), whose common
> members and bundle rules apply.

## Purpose

Records who authorized one incident response action on an agent system (a pause, a
restriction, an isolation, a revocation, a remediation step or a restoration), which role each
named party held, on what kind of grant the authorizer acted, and whether the authority was
committed before the action ran. An after-action report that says "the team decided" names no
one who can be asked; this record does.

## Model

The **subject** is the operation authorized, by digest: one or more members, each with a
`digest` holding only `sha256` of the operation's declared description.

The **predicate** carries the common members (`incident`, `producer`, `issuedAt`,
`registryDigest`, `doesNotAssert`) and:

- `action`: `functions`, a non-empty sorted list of `response_function` values
  (`monitoring_increase`, `restriction`, `isolation`, `pause`, `remediation`,
  `restoration`; a credential revocation is recorded as `restriction` and its sweep as an R2 record); `targets`, a non-empty list of `{id}` naming the agents, tools, routes or
  credentials acted on; and `inducedEffects`, which is `{declared: "listed", items: [...]}`,
  `{declared: "none_observed", observation: {sha256}}` or `{declared: "unknown"}`. A record
  cannot say an action caused no side effects without naming the observation that looked.
- `parties`: a non-empty list of `{id, roles, authorityBasis?, independenceBasis?}`. `roles`
  is a non-empty sorted list drawn from `advised`, `authorized`, `executed`, `accountable`.
  `authorityBasis` is one of `role_grant`, `policy_preauthorized`, `contract_third_party`,
  `executive_approval`, `unknown`, and is required on every party holding `authorized`. An
  absent basis is never read as `role_grant`; `unknown` is the value for not knowing.
- `authorizedAt`: when the authority was given. `notAfter`: when it lapses. `executedAt`,
  optional: when the action ran.
- `intentBinding`: the vocabulary term `intent_binding`, `committed_before_execution` or
  `asserted_after_execution`.
- `pause`, optional: `{hold, holdProof}` where `hold` is a `pause_hold` value and
  `holdProof` a `{sha256}` of the observation that established it.

## Rules

A reader applies these in order and reports the first that fails.

| # | Rule | Code |
| --- | --- | --- |
| 1 | The statement is strict JSON with exactly `_type`, `subject`, `predicateType`, `predicate`; `_type` is in-toto Statement v1; `predicateType` is the Type URI above | `statement-malformed` |
| 2 | The predicate has exactly its members, each well formed | `predicate-malformed` |
| 3 | Every closed value is registered | `closed-vocabulary-violation` |
| 4 | At least one party holds `authorized` | `no-authorizer` |
| 5 | At least one party holds `accountable` | `no-accountable-party` |
| 6 | Every party holding `authorized` carries `authorityBasis` | `authority-basis-missing` |
| 7 | `authorizedAt` is not after `notAfter` | `authorization-window-inverted` |
| 8 | When `intentBinding` is `committed_before_execution` and `executedAt` is present, `executedAt` is not before `authorizedAt` | `intent-not-committed-before` |
| 9 | When `executedAt` is present, it is not after `notAfter` | `authorization-expired` |
| 10 | `inducedEffects` declared `none_observed` carries `observation` | `induced-effects-unobserved` |

A statement that passes every rule is accepted as `authorization-recorded`.

## What it does not establish

That the authorizer in fact had the authority the basis names, that the action was carried
out as described, or that the induced effects listed are all there were. It records what the
signer states, in a form another party can hold the signer to.
