# Adversarial Execution Evidence: long-form specification material

Predicate type `https://in-toto.io/attestation/adversarial-execution-evidence/v0.7`.

The registry entry for this predicate belongs in the in-toto attestation
catalog, at `spec/predicates/adversarial-execution-evidence.md`. It is in review
as [in-toto/attestation#570](https://github.com/in-toto/attestation/pull/570), so
the catalog path does not resolve yet and the pull request is where to read it.
That page is normative and self-contained: the type URI, the schema, the
parsing rules, one line per field, the examples, and the changelog. It is
sized to the registry it sits in.

The specification also argues for itself at length. It states what a consumer
can and cannot recompute, why each encoding rule is normative rather than a
resource limit, what the run binding covers and what it deliberately does
not, which attacks the 0.7 commitments close and where each one stops, and
what a refusal may claim to have compared. That material is load-bearing for
an implementer and for a reviewer, and it is four times the size of the
largest document the catalog has accepted. It lives here instead, verbatim,
so the registry page can be read in one sitting and nothing the longer
document established is lost.

| file | what it holds |
|---|---|
| [`rationale.md`](rationale.md) | Purpose, use cases, model: the recompute split between what the substrate proves and what the assembly plane asserts, why a producer claiming less is undetectable, and why `batchRoot` binds a network attacker rather than the assembly plane. |
| [`wire-profile.md`](wire-profile.md) | The encoding profile in full: I-JSON safe integers, statement-wide duplicate members, well-formed scalar values checked on raw bytes, the noncharacter exclusion, the nesting bound of 128, BMP-only canonical surfaces, and the run binding construction with the two inputs that separate version 2 from version 1. |
| [`fields.md`](fields.md) | Every field, at length: the four-value `result` function and its three conditions, the eleven coverage validity requirements, what the 0.7 commitments do not close, the evidence tier, the closed vocabularies for `basis`, `method`, `attribution`, `actualLayer` and `networkPosture.posture`, and every reserved member an observation-record payload carries. |
| [`verification.md`](verification.md) | The parsing rules in full, including the two-stage verifier ordering and the design invariant that every property the recompute reads travels on the row; then the four consumer policy obligations and a worked policy in Rego. |
| [`changelog.md`](changelog.md) | Per-version history from the internal 0.1 through 0.7, with the rationale for each breaking change and the rename-without-alias rule. |

## How to read the two together

The registry page decides conformance. Where this material and that page
differ on a normative rule, the page governs and the difference is a defect
to report. Nothing here weakens a requirement stated there, and nothing here
adds one: these files explain and bound rules the page states.

The verbatim text carries the single document's own cross-references
("above", "below", "under Prerequisites"). Each file opens with a table
saying where the section it names now lives.

## Conformance

Conformance is established by vectors, not by agreement between readings.
The corpus in this repository is the reference suite for this predicate, and
the reference verifier is [`cmd/aee-verify`](../../../cmd/aee-verify). A
reading of the text that no vector exercises is a candidate for the next
vector rather than a settled rule, which is the specification's own position
and the reason this repository exists.
