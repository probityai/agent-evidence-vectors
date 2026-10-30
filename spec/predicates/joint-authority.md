# Predicate type: Joint Authority

Type URI: https://probityai.github.io/agent-evidence-vectors/predicate/v1/joint-authority

Version: 0.1.0

Predicate Name: Joint Authority

> Status: DRAFT, issued under a self-hosted `predicateType` URI. The URI will not move once
> a signed statement carries it. Record R4 of the
> [restoration evidence profile](../../profiles/restoration-evidence.md), whose common
> members and bundle rules apply.

## Purpose

Records, for an incident that crosses organisations, which party may act on which asset,
under what kind of grant, and which indicators the parties share. When an agent operated by
one organisation affects infrastructure run by another, the restart conditions in incident
guidance assume a single owner; this record names the owners and the assignment so that
each party's later R1 and R3 records can be read against it.

## Model

The **subject** is the shared indicator set, by digest: one member whose `digest` holds only
`sha256` of the canonical list of shared indicators.

The **predicate** carries the common members and:

- `sharedIndicators`: a non-empty sorted list of `{sha256}` digests of indicators both
  parties hold.
- `parties`: at least two entries `{id, organization, correlationId, authorityBasis,
  assets}`. `authorityBasis` is as in R1; `assets` is a sorted list of asset identifiers the
  party may act on.
- `actions`, optional: a list of `{party, asset, record}` naming actions already taken, where
  `record` is the `{sha256}` of the R1 statement authorizing it.

## Rules

| # | Rule | Code |
| --- | --- | --- |
| 1 | Statement shape and Type URI as in R1 | `statement-malformed` |
| 2 | The predicate has exactly its members, each well formed | `predicate-malformed` |
| 3 | Every closed value is registered | `closed-vocabulary-violation` |
| 4 | Every party carries `authorityBasis` | `authority-basis-missing` |
| 5 | The parties belong to at least two organisations | `single-organization` |
| 6 | Every action names a party in `parties` and an asset in that party's `assets` | `party-acts-outside-assignment` |

A statement that passes every rule is accepted as `assignment-recorded`.

## What it does not establish

That the parties agreed to the assignment beyond the signer's statement, or that a legal
duty to notify was met. A record co-signed by every party is stronger than one signed by
one; the envelope shows which it is.
