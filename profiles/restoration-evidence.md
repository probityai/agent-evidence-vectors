# Restoration evidence profile

Profile identifier: `restoration-evidence/v1`. Version: 0.1.0, DRAFT.

When an agent system is stopped, restricted or has its credentials revoked during an
incident, someone later decides whether it may run again. Incident guidance asks for that
decision to be declared against criteria, confirmed with the system owners and documented (NIST SP 800-61 Rev. 3, RC.RP-04 to RC.RP-06; NIST SP 800-184, Sec. 6.2.3), and Key Practices 7.5 asks for the remaining risk to be recorded with it. The NIST Key Practices for SI training and
evaluation (2026-10-16, cited in these documents as Key Practices, sections 7.3 and 7.4) ask
for the containment layers to be
shown working again and the incident to be replayed against the new controls before an agent
resumes. None of those texts says what the record of that decision must contain for a party
outside the organisation to check it. This profile fixes that record.

It binds five predicate types, each defined in its own document:

| Record | Predicate type | What it records |
| --- | --- | --- |
| R1 | [`incident-action-authorization`](../spec/predicates/incident-action-authorization.md) | who authorized one response action (a stop, a restriction, an isolation, a revocation), on what basis, before or after it ran |
| R2 | [`revocation-sweep`](../spec/predicates/revocation-sweep.md) | which credentials of a declared population were revoked, which were not, and how far the sweep is claimed to reach |
| R3 | [`re-enable-decision`](../spec/predicates/re-enable-decision.md) | the decision to resume, stage or keep restricting a stopped system, who approved it, and which evidence it cites or declares not addressed |
| R4 | [`joint-authority`](../spec/predicates/joint-authority.md) | which party may act on which asset when an incident spans organisations |
| RB | [`revocation-boundary`](../spec/predicates/revocation-boundary.md) | for one declared sink, whether an effect from a task in flight committed after a credential revocation took effect |

Each type URI is under
`https://probityai.github.io/agent-evidence-vectors/predicate/v1/`, is listed in
[`spec/predicates/REGISTRY.md`](../spec/predicates/REGISTRY.md), and will not move once a
signed statement carries it.

## What the profile requires, and what it leaves to the relying party

The profile is a record contract. It says what a conforming record carries and which
records a bundle must carry together, so that a reader can check them offline and without
the producer's code. It does not say whether a decision was right. Whether a given re-enable
decision is enough to let a system run again is the relying party's own admission policy,
written against these records and outside this profile. A record that conforms is a
complete and internally consistent statement by its signer; it is not evidence that the
signer's statement is true.

## Common members

Every predicate in the profile carries these members with these meanings.

- `incident`: `issuer` (an https URL naming who assigns the identifier), `id` (a non-empty
  text) and, optionally, `related`, a list of further `{issuer, id}` pairs naming the same
  incident in another organisation's records. This is the vocabulary term
  `incident_identifier`.
- `producer`: `id`, an https URL naming the party that signs the record.
- `issuedAt`: an RFC 3339 UTC time to whole seconds.
- `registryDigest`: `{ "sha256": ... }` of the vocabulary registry the closed values are
  expressed in.
- `doesNotAssert`: a list of non-empty texts the producer states the record does not claim
  (the vocabulary term `does_not_assert`). The list may be empty; the member may not be
  absent.
- `predecessors`, where a type uses it: a list of `{predicateType, digest}` naming earlier
  records of this profile. `digest` holds `sha256` of the predecessor statement's bytes
  exactly as carried in its DSSE payload.

Rule 3 of each document covers the values the vocabulary registry defines
(`response_function`, `pause_hold`, `restoration_decision`, `revocation_state`,
`intent_binding`, `independence_basis`, `set_sufficiency`). Values a predicate document lists
itself are closed by that document and checked by its schema.

Every record is an in-toto Statement v1 carried in a DSSE envelope. Statements are strict
JSON: a duplicate member at any depth makes the statement malformed. Times are compared as
instants. A member a document does not define is refused, so that a record cannot carry
something a reader is not told how to read. This departs from the in-toto parsing rule that consumers ignore unknown fields: a later version that adds a member gets a new type URI version, so a v1 reader never meets a member it cannot read.

## A bundle

A restoration-evidence bundle is one R3 together with every record its `predecessors` name,
recursively, and any R4 or RB record the producer chooses to add. A reader checks a bundle in
this order and reports the first failure.

| # | Rule | Code |
| --- | --- | --- |
| B1 | Every record in the bundle conforms to its own predicate document | the record's own code |
| B2 | Every predecessor digest resolves to exactly one record carried in the bundle | `predecessor-not-carried` |
| B3 | The record a digest resolves to has the `predicateType` the reference names | `predecessor-type-mismatch` |
| B4 | No record names itself, directly or through other records, as its predecessor | `predecessor-cycle` |
| B5 | Every record in the bundle names the same incident, by `incident` or by one of its `related` pairs | `incident-mismatch` |
| B6 | No record's `issuedAt` is earlier than that of a record it names as a predecessor | `predecessor-issued-later` |
| B7 | Every credential an R3 restores inside `restoredScope.credentials` appears in some R2 in the bundle | `restored-credential-unswept` |

A bundle that passes every rule is reported as `bundle-consistent`. That verdict says the
records agree with each other. It says nothing about whether the relying party should admit
the decision.

## Conformance

The checker and the labelled synthetic members ship in this repository as
`vectors-restart-records/`. Until that corpus is released, a reader can conform to the
record shapes only through the JSON Schemas in `spec/schemas/`, which check shape and closed
values and none of the cross-member rules above.
