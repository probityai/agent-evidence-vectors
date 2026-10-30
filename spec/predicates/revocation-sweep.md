# Predicate type: Revocation Sweep

Type URI: https://probityai.github.io/agent-evidence-vectors/predicate/v1/revocation-sweep

Version: 0.1.0

Predicate Name: Revocation Sweep

> Status: DRAFT, issued under a self-hosted `predicateType` URI. The URI will not move once
> a signed statement carries it. Record R2 of the
> [restoration evidence profile](../../profiles/restoration-evidence.md), whose common
> members and bundle rules apply.

## Purpose

Records which credentials of a declared population were revoked during an incident, which
were not, and how far the producer claims the sweep reaches. "We rotated the keys" leaves
open which keys, issued when, and whether the ones an attacker held were among them. This
record puts the population, the partition and the claim side by side, so that a claim wider
than the partition is visible from the record alone.

## Model

The **subject** is the population manifest, by digest: one member whose `digest` holds only
`sha256` of the list of credential identifiers the sweep was run over. Identifiers are opaque
names, never secrets, hashes of secrets or fingerprints.

The **predicate** carries the common members, `predecessors` (at least one R1, the
authorization of the sweep), and:

- `population`: `credentials`, a non-empty sorted, duplicate-free list of identifiers.
- `partition`: a list of `{state, credentials}` parts, `state` one of `revoked`, `retained`,
  `unassessed`. The vocabulary term `coverage_denominator` names this shape.
- `revocations`: one entry per revoked credential: `credential`, `revokedAt`, `evidence`
  (a resource descriptor, `{digest, uri?, mediaType?}`, of the deny record or policy change), and `relyingParties`, a list of
  `{id, state}` with `state` a `revocation_state` value.
- `coverage`: `claim`, one of `complete_verified`, `issued_after_only`, `partial`,
  `unknown`; and `issuedAfter`, a time, required when `claim` is `issued_after_only`.

## Rules

| # | Rule | Code |
| --- | --- | --- |
| 1 | Statement shape and Type URI as in R1 | `statement-malformed` |
| 2 | The predicate has exactly its members, each well formed | `predicate-malformed` |
| 3 | Every closed value is registered | `closed-vocabulary-violation` |
| 4 | The parts are disjoint and their union equals `population.credentials` | `denominator-union-mismatch` |
| 5 | `revocations` names exactly the credentials of the `revoked` part | `revocation-entries-mismatch` |
| 6 | `complete_verified` is claimed only when every credential is in the `revoked` part | `coverage-claim-exceeds-proof` |
| 7 | `issued_after_only` carries `issuedAfter` | `coverage-claim-incomplete` |

A statement that passes every rule is accepted as `sweep-recorded`. An honest `partial` or
`issued_after_only` sweep is a well formed record. Whether a relying party accepts a system
restored under it is that party's policy.

## What it does not establish

That the population is every credential that existed, that a relying party enforced the
revocation, or that no credential was used after it. The `relyingParties` states record what
the producer observed, and `use_after_revocation` is a value precisely so that it can be said.
