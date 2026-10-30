# About the vocabulary

Why the registry exists, what each file in the repository is for, and how the term set was chosen. The [README](../README.md) is the short version.

A closed, versioned vocabulary for terms that describe **adversarial-execution evidence claims**:
what an executed artifact attempted, what a substrate beneath it observed or refused, how directly
and from what vantage a claim was obtained, and how much of a declared population a claim actually
covers.

One question sets the scope. When a system emits a claim about an execution, what does that claim
actually say, and how would a reader who trusts nobody check it? Identity, reputation and wallets
belong to other registries, and the out-of-scope block says so in the registry file itself, where a
parser can reach it.

## Why this exists

Naming the terms in an execution-evidence claim is a well-populated space. The registries in it
share a purpose: a vocabulary that independent systems crosswalk their own claims onto, so that a
term means one thing across vendors.

Four terms here carry the axis that decides whether any of the rest can be relied on, which is who
observed the execution and through how many hands the account of it passed:

- `observation_vantage` and `observation_directness` say where a claim was obtained and how
  directly.
- `witness_scope` says whose account it is: the observed party's own (`SELF`), another
  participant's (`PEER`), or one from a party the observed cannot reach (`EXTERNAL`).
- `coverage_denominator` and `does_not_assert` say what it leaves out, and say so inside the
  signed bytes.

Full definitions and their grounding mechanisms are in vocabulary.yaml.

## Files

vocabulary.yaml is the registry itself, CC0-1.0 and public domain, so reuse it freely.
GOVERNANCE.md carries the promotion and demotion rules, the merge discipline, and the
no-self-grounding-exemption rule binding the founding maintainer's own systems identically to
anyone else's. CONTRIBUTING.md says how to file one. Filed crosswalks live one file per system
under crosswalk/, starting from TEMPLATE.yaml there.

The validator is scripts/validate_crosswalks.py, and CI runs it on every change. Hand it a file
whose shape it does not recognize and it fails, loudly, naming the file.

The alternative is silence, and silence is the expensive one. A validator that skips what it cannot
parse still reports a clean run, over crosswalks it never opened, and the filer who got the shape
wrong is told nothing at all. The unrecognized-shape branch is a dozen lines. Read it and check.

## Companion project

The `spec_anchor` field points at the adversarial-execution-evidence predicate specification,
vendored and versioned in
[probityai/agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors), the reference verifier
and conformance vector suite for that predicate, which is where the vocabulary defined here is
actually spoken.

## Status

Version 0.8.0, tagged October 26, 2026. It adds open verdict classes, a criticality for each term, the registryDigest a record carries and a resolvable URI for each term. Version 0.7.0 added two proposed terms to `evidence_dimensions`: `commitment_anchor`, a proven ceiling on when a record existed, and its companion `anchor_time_rule`. Version 0.6.0 added the `done_verification` section: eight proposed terms for deciding that an agent's work is done from outside the agent. Version 0.5.0 added ten proposed terms: attestation tier, origin kind and base-state resolution, six terms anchored on a legal instrument, and intent binding. Version 0.4.0 added the `record_lifecycle` section, the `change_admission` section that the agent change admission predicate carries, and links from eight terms to the OpenCRE requirements their definitions state.

The initial term set came from reading the nearest comparable registry term by term and recording,
for each of ours, whether it names ground nobody has named yet or overlaps something already in
use. Both answers occur. Thirty-one of the thirty-seven terms carry a why_this_registry note
saying which, and that note is a field in the file, so a reader who disagrees can point at the
line. The other four make their case in the definition itself.

Every term is meant to land as a field inside a signed statement. Nobody consuming one should have
to go hunting through documentation to learn what a claim withholds. Each release is tagged so a
crosswalk has a fixed version to file against. Filings are open, and the first came from an independent
second implementation of the predicate, in pull request 2.
