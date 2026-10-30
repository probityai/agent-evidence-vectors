# Predicate type: Revocation Boundary

Type URI: https://probityai.github.io/agent-evidence-vectors/predicate/v1/revocation-boundary

Version: 0.1.0

Predicate Name: Revocation Boundary

> Status: DRAFT, issued under a self-hosted `predicateType` URI. The URI will not move once
> a signed statement carries it. A member of the
> [restoration evidence profile](../../profiles/restoration-evidence.md), whose common
> members apply.

## Purpose

Revoking a credential stops new work from starting under it. It does not by itself stop work
already in flight from committing its effect afterwards: a transaction opened before the
revocation can commit after it, and a retried request can land twice. This record reports,
for one declared sink and one test window, whether any effect from an in-flight task
committed at that sink's declared commit boundary after the revocation took effect, with the
counts a reader needs to judge it.

The record states an outcome. It names no mechanism and requires none; whatever produced
the outcome is graded on the same counts.

## Model

The **subject** is the test plan, by digest: one member whose `digest` holds only `sha256`
of the declared sink and window.

The **predicate** carries the common members, optional `predecessors`, and:

- `sink`: exactly one, `{id, kind, commitBoundary}`. `kind` is one of `database`,
  `filesystem`, `http_endpoint`, `subprocess`, `queue`, `other`; `commitBoundary` is a
  non-empty text saying at which point an effect counts as committed (for example, the
  transaction commit, the rename into place, the server's durable write).
- `observer`: `{id, vantage}`, `vantage` one of `sink_side`, `agent_side`. A sink-side
  observer reads the sink's own state; an agent-side observer reads what the agent process
  reports.
- `revocation`: `credential` (an opaque identifier), `effectiveAt` (when the revocation took
  effect at the authority), and `timeSource` (a non-empty text naming the clock).
- `window`: `{start, end}`, containing `effectiveAt`.
- `counts`: non-negative integers `attempts`, `inFlightAtRevocation`,
  `postRevocationCommits`, `replaysAttempted`, `replaysCommitted`.
- `exclusions`: a list of `{count, reason}`, each reason non-empty, for attempts left out of
  the counts.
- `result`: `no_post_revocation_commit_observed`, `post_revocation_commit_observed` or
  `not_established`.

## Rules

| # | Rule | Code |
| --- | --- | --- |
| 1 | Statement shape and Type URI as in R1 | `statement-malformed` |
| 2 | The predicate has exactly its members, each well formed | `predicate-malformed` |
| 3 | Every closed value is registered | `closed-vocabulary-violation` |
| 4 | `window.start` is not after `effectiveAt`, and `effectiveAt` is not after `window.end` | `revocation-outside-window` |
| 5 | `inFlightAtRevocation` does not exceed `attempts`, `postRevocationCommits` does not exceed `inFlightAtRevocation`, and `replaysCommitted` does not exceed `replaysAttempted` | `counts-inconsistent` |
| 6 | `result` is `post_revocation_commit_observed` exactly when `postRevocationCommits` or `replaysCommitted` is positive, unless `result` is `not_established` | `result-contradicts-counts` |
| 7 | `no_post_revocation_commit_observed` requires a `sink_side` observer | `observer-not-at-sink` |

A statement that passes every rule is accepted as `boundary-recorded`.

## What it does not establish

Anything about another sink, another window or another credential: one record covers one
sink, and a claim about several sinks is several records. A zero count bounds a rate; it is
not a guarantee. The record does not say how the outcome was achieved.
