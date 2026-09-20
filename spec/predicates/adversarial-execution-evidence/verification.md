<!-- Long-form companion to the Adversarial Execution Evidence predicate. -->

# Adversarial Execution Evidence: parsing rules and consumer policy

Long-form companion to the registry page for predicate type
`https://in-toto.io/attestation/adversarial-execution-evidence/v0.7`.

The text below is verbatim from the single-document revision of the
specification (source SHA-256 `2b7f3bc08123cbe1981d287cf20193858ae5ea6d55ca067e06363a1e71a573d7`, lines 386-2002 of
`spec/predicates/adversarial-execution-evidence.md`). The registry page is the
normative statement of the predicate and carries the schema, the parsing
rules, the field list and the examples; this file carries the reasoning,
the bounds and the cases that do not fit a registry entry, so that nothing
the single document argued is lost when the page is read on its own.

Where the rest of it went:

| material | file |
|---|---|
| the predicate itself: type URI, schema, parsing rules, field list, examples | the registry page, `spec/predicates/adversarial-execution-evidence.md` upstream |
| purpose, use cases, model | [`rationale.md`](rationale.md) |
| encoding profile, I-JSON, nesting bound, BMP rule, run binding | [`wire-profile.md`](wire-profile.md) |
| parsing rules in full, consumer policy obligations, the policy example | [`verification.md`](verification.md) |
| every field, coverage validity, evidence tier, reserved record members | [`fields.md`](fields.md) |
| per-version history from 0.3 to 0.7 | [`changelog.md`](changelog.md) |

A cross-reference in the verbatim text below that reads "above", "below",
"under Prerequisites" or "under Consumer policy obligations" points at the
single document's own layout. Read it against the table above.

---

### Parsing Rules

The predicate opts in to the framework's standard parsing rules, including the
monotonic principle, with one deliberate strengthening: `result` is not an
independent claim. A consumer MUST be able to recompute it from the rest of
the predicate (rules under `result` below), and a `result` the recompute does
not reproduce makes the attestation invalid. Observation record `payload`s
follow the same verify-then-read discipline: the fields inside a payload mean
nothing until its signature verifies against a key the consumer trusts. The
`result` recompute is a function of the carried predicate alone: it never
reads `observationRecords`, signature-verification outcomes, or any consumer
trust decision. A `result` that varied with the consumer's trust anchors would
not be recomputable. The coverage validity requirements below (which read
record payloads but not signatures or consumer policy) and the evidence tier
(which reads signatures against consumer policy) are separate gates from the
recompute: the validity gate can invalidate an attestation, and the tier ranks
a row, but neither alters `result`.

A verifier proceeds in two stages. Stage one is byte-pure: four validity
steps, each a function of the carried statement alone, and all four are
consumption preconditions: (1) statement well-formedness, including the
vocabulary rules and, for substrate-carrying statements, run-binding
derivability; (2) the coverage validity requirements; (3) the `result`
recompute; (4) manifest and vocabulary digest integrity. Stage two is
trust-relative: the envelope signature and the per-row evidence tier
against consumer key policy, then the strength orderings and the rest of
consumer policy, including the anchor comparison under Consumer policy
obligations. Only the consumption preconditions stated under Coverage
validity and the evidence tier are normative in this ordering; the
sequencing itself is informative.

A design invariant follows from the recompute: any per-observation property
that the recompute or the documented consumer gating reads travels on the
row itself, as a required member, other than the record-borne binding
members defined under `observationRecords`, with a closed vocabulary,
fail-closed on missing or unknown values. Run-level pins in
`observationEnvironment` never substitute for a row-level property, because
the recompute reads rows. The instruments that corroborate a property may be
run-scoped: a run-level `arming` or `sealed` record backs a clean row's claim
through the row's own `observationRefs`, and never substitutes for a row
member. The arming and sealed records attest that a vantage was armed and
stayed armed run-wide, not that the specific channel for this row's attack
class was armed; per-channel arming completeness stays producer vocabulary
bounded by the pinned `networkPosture` digest.


### Consumer policy obligations

Four expectations are consumer policy, resolved outside the attestation and
never read from it: which keys count as substrate observation keys (the
evidence tier's input), which corpus and substrate this consumer
expects, which assessment classes it demands a run to have assessed, and
what it requires of the row-to-record binding. The first two are stated
first because they are the older pair; the second two are the closures for
two attacks no rule over the carried statement can reach, and they are stated
here rather than left as guidance for that reason.

A consumer MUST pin, out of band, the corpus digest and the
substrate digest it expects for the deployment it is admitting into, and
at consumption MUST compare them against
`observationEnvironment.corpus.digest` and
`observationEnvironment.substrate.digest`; on mismatch the attestation is
not admitted, exactly as an attestation whose covering signatures do not
verify is not admitted. The comparison is deliberately not a validity
gate: validity is a function of carried bytes alone and holds identically
for every consumer, while the expected corpus and substrate differ per
consumer. An anchor-mismatched attestation is valid evidence about the
wrong context. Verification surfaces SHOULD expose one consumer-facing
admission result that conjoins validity, tier-policy satisfaction, and the
anchor comparison, so a result-only consumer cannot read a
valid-but-wrong-context attestation as admissible.

A consumer MUST pin, out of band, the set of assessment classes it requires a
run to have assessed, and at consumption MUST compare that set against
`coverage.assessedClasses`; a statement disclosing a demanded class under
`outOfScope` or `routedElsewhere` is not admitted, exactly as an
anchor-mismatched statement is not admitted. This is the only obligation in
this section whose value a consumer must derive from what it wants rather than
from what a producer published. The corpus anchor pins bytes and says nothing
about what those bytes must contain, so a consumer that pinned a digest it
copied out of a producer's bundle has pinned whatever that producer chose to
ship. The demand is stated over classes rather than over attack identifiers
because identifiers are corpus-version scoped: a consumer pinning them re-pins
on every corpus revision, and the list it re-pins to is one it read out of the
producer's own manifest. A pin whose value comes from the party being checked
is not a demand.

The obligation exists because withdrawn coverage is invisible in the carried
bytes and provably so, and because the consumer holds the only fact that
decides it, which is what it asked for. It therefore never has to tell an
honest skipped run from a suppressed one: it refuses both, on the ground that
it demanded the class and the class was not assessed, and the producer's
intent stops being the question. A consumer that demands no class MUST record
that decision explicitly rather than reach it by omission, and MUST NOT fold
the decision into the corpus and substrate pins, which decline something else:
declining those concedes evidence about any corpus while leaving every
self-consistency requirement in this document standing, and declining this one
concedes that a producer may withdraw any class it likes, against which
nothing in this document stands at all. Absence here is not a degraded
control; it is the absence of one.

Finally, a consumer decides what it requires of the row-to-record binding and
of the run-end attack set. A consumer MAY require `attribution: pinned` on
every row whose attack the pinned corpus carries an `expectedPayloads` entry
for, and MAY require a non-empty `aeeObservedAttacks` on the seal. Each is a
refusal of a declared weakness rather than the detection of a hidden one: a
producer that declares `paired` throughout, or that presents a substrate
holding no correspondence to sign, violates no requirement in this document,
and the statement it emits is one an honest producer in the same position
emits. What the format does is put the weakness on the wire where a policy can
read it. A consumer that declines either requirement is admitting a statement
whose row-to-record assignment rests on the producer's word, and the conjoined
admission result recommended above SHOULD say so rather than report a bare
pass.

Beside those two, a consumer MAY require that every identifier in
`aeeObservedAttacks` whose attack the pinned corpus carries a
`corpus.manifest.expectedPayloads` entry for is also the `attackId` of a row
declaring `attribution: pinned`. Under that requirement the consumer re-derives
that subset of the seal's set from the corpus's declared commitments and the
carried record payloads, rather than reading it off the substrate's own
declaration, and the requirement is decidable from carried bytes with no
mechanism this document does not already define. It is a consumer option and not
a coverage validity requirement for the reason stated where `expectedPayloads`
is defined: a corpus author who writes down the raw form of a value the
substrate canonicalizes before committing has mispredicted, and that mistake
should cost a fallback to `paired` rather than the validity of an honest
statement. The complement, the identifiers the corpus declared no expectation
for, remains a substrate declaration, and no consumer policy makes it
otherwise.


### Consumer policy example (non-normative)

Naming the substrate observation keys is policy, not wire format. A
minimal policy in the style of a witness layout, keyed on both the derived
tier and the row's `method` so a reconstructed clean row is not admitted
as a live one. The check that matters is signature verification against a
key pinned out of band; a record's `keyid` is an unauthenticated lookup
hint and never the check itself:

```rego
# Pinned out of band; never read from the predicate.
substrate_keys := {"substrate-2026": "<ed25519-public-key-bytes>"}

attested(row) {
  every i in row.observationRefs {
    rec := input.predicate.observationRecords[i]
    # verify DSSE PAE(payloadType, payload) against a pinned key;
    # rec.signatures[_].keyid selects WHICH pinned key to try, nothing more
    pae_verified(rec, substrate_keys)
  }
}

deny[msg] {
  row := input.predicate.attackResults[_]
  row.basis == "substrate"
  not attested(row)
  msg := sprintf("substrate row %s is unattested", [row.attackId])
}

deny[msg] {
  row := input.predicate.attackResults[_]
  admit_only_live
  row.method != "intercepted"
  msg := sprintf("row %s covered by reconstruction, not live interception", [row.attackId])
}
```

`attested` is coverage-of-existence, not temporal completeness; transient
tolerance travels on the `method` axis, so an admission rule that needs a
live observation keys on `method: intercepted` as well as the tier. The
second rule above is the row-level half of the partition the `result`
recompute now also reduces to a token: a policy gating on `result ==
"pass"` already excludes every statement that rule would deny, and a policy
relaxed to admit `pass_indirect` MUST keep the rule, because the token
states that some clean row is indirect and never which one.

[DSSE]: https://github.com/secure-systems-lab/dsse
[ResourceDescriptor]: https://github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md
[Runtime Traces]: https://github.com/in-toto/attestation/blob/main/spec/predicates/runtime-trace.md
[SCAI]: https://github.com/in-toto/attestation/blob/main/spec/predicates/scai.md
[SVR]: https://github.com/in-toto/attestation/blob/main/spec/predicates/svr.md
[Test Result]: https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md
[VSA]: https://github.com/in-toto/attestation/blob/main/spec/predicates/vsa.md
