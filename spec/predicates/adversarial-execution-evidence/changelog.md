<!-- Long-form companion to the Adversarial Execution Evidence predicate. -->

# Adversarial Execution Evidence: changelog and migrations

Long-form companion to the registry page for predicate type
`https://in-toto.io/attestation/adversarial-execution-evidence/v0.7`.

The text below is verbatim from the single-document revision of the
specification (source SHA-256 `2b7f3bc08123cbe1981d287cf20193858ae5ea6d55ca067e06363a1e71a573d7`, lines 2003-2377 of
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

## Changelog and Migrations

A versioning discipline this predicate commits to: a member is born exactly
when a normative reader consumes it. In particular, if a future version
makes the shared-reference evidencing obligation checkable (for example by
committing per-attack expected artifacts in the corpus manifest),
attribution strength acquires a normative reader at that version and
becomes a required member then, not retroactively and not through a
verifier-invented heuristic in the meantime.

That commitment came due. 0.7 carries `expectedPayloads` in the corpus
manifest, which is the example the sentence named, so attribution strength is
a required row member from 0.7 and from no earlier version, spelled
`attribution`. The clause about retroactivity is what decided that 0.7 is a
new predicate type rather than a revision of 0.6: a rule that attaches to one
version and not to its predecessor needs the wire to say which version a
reader is holding, and `predicateType` is the only member that says so.

Versions 0.1–0.2 were internal producer iterations; 0.3 was the first shape
proposed for vetting. Relative to those internal versions, 0.3 removed all
verdict/policy semantics (moved downstream), moved intercepted-payload bytes
out in favor of commitments, moved `batchRoot` from per-record to
predicate-level, and adopted the I-JSON safe-integer profile on every rail.

0.4 incorporates review feedback on 0.3:

-   Added the required per-row `basis` field on `attackResults` (closed
    vocabulary `substrate_observed` / `artifact_reported` / `inferred`,
    fail-closed on unknown values), so each observation carries its own
    vantage and consumers can gate on it.
-   Pinned `actualLayer` clean-run behavior: rows with no containment event
    carry the literal `none` rather than omitting the field.
-   Renamed `does_not_assert` to `doesNotAssert` to match the lowerCamelCase
    convention. The rename is in place with no alias: the old spelling is
    rejected, keeping a single canonicalization per content.

0.5 revises 0.4 after review:

-   Split the per-row `basis` field into two orthogonal required fields:
    `basis` (closed vocabulary `substrate` / `artifact`) now names only the
    observation's vantage, defined by its weakest input with a stated
    artifact-sourcing criterion, and the new `method` (closed vocabulary
    `intercepted` / `reconstructed`) names its directness, with the same
    weakest-input composition rule. The 0.4 values `substrate_observed`,
    `artifact_reported`, and `inferred` are rejected, not aliased, under
    the same single-canonicalization rule as the `does_not_assert` rename;
    `inferred` has no successor because it conflated the two axes.
-   Made `actualLayer` required on every row (missing member: malformed
    statement, deliberately a different altitude than the fail-closed row
    members, per the stated design invariant) and extended its literal
    `none` to caught rows, where it states observed-but-not-enforced, so
    enforcement role never leaks into `basis`.
-   Added consumer strength orderings on both sides with a defined
    supporting set (`basis` bounds a `fail`, `method` bounds a `pass`,
    fail-closed rows at the lattice bottom, clean-row ordering extended to
    `degraded`), a coherence check of row claims against the pinned
    `observationEnvironment`, and a row-internal check that intercepted
    caught rows reference verifiable intercept records, all consumer-side.
-   Stated the row-travel design invariant under Parsing Rules and the
    producer-claim trust boundary for `basis`/`method`.

0.6 folds in the review of 0.5:

-   `basis: substrate` is now backed by substrate-signed coverage at two
    gates. Byte-checkable coverage (references resolve in range and
    class-match; every covering payload is canonical `+json` carrying the
    reserved members with `aeeRunBinding` equal to the derived run
    binding; `method` capped by the weakest signed `aeeMethod`;
    `batchRoot` recomputes) is a VALIDITY requirement and a consumption
    precondition. A consumer that consumes `result` or credits any row
    MUST evaluate it first, and a violation makes the attestation invalid,
    independent of any consumer. The one trust-relative step (the
    covering signatures verify against a consumer-named substrate key) is
    a per-row evidence tier (`attested` / `unattested` / `declared`); a
    consumer with no pinned substrate root treats every substrate row as
    `unattested`. An `unattested` substrate row ranks with `artifact` in
    both orderings: rank, never relabel; the MAY-reject-never-downgrade
    rule is retained verbatim.
-   Caught intercepted rows are covered by `interception` records,
    reconstructed rows by `examination` records, and clean intercepted
    rows by BOTH a run-level `arming` record and a `sealed` record whose
    signed payload reports the vantage stayed armed with a zero or
    self-bounded run-wide drop count and an unchanged posture digest. The
    strongest absence claim is bounded to the vantage's existence and
    continuity for the carried run, not to the absence of any event and
    not to a run population.
-   The observation vocabulary now travels in the attestation
    (`observationVocabulary`: labels, caught subset, JCS digest), so the
    recompute and the validity gate are pure functions of carried bytes
    and archived attestations stay verifiable without the producer's
    documentation.
-   Renamed `interceptRecords` to `observationRecords` and `interceptRefs`
    to `observationRefs` (old spellings rejected, no alias). Record
    signatures are DSSE PAE over `(payloadType, payload)`; coverage
    payloads MUST be canonical `+json`. `batchRoot` is pinned to RFC 6962
    with domain separation, duplicate records rejected, and is required
    whenever records exist. A new `runEntropy` digest in
    `observationEnvironment` folds a substrate-emitted run-start value
    into a versioned run binding so
    identical-configuration re-runs derive distinct bindings; the binding
    is anti-splice, not a freshness challenge, and identical-config replay
    is bounded by a stateful consumer rejecting `runEntropy` reuse.
-   Moved the run binding to `aeeBindingVersion: 2`. The pre-image gains
    `observationVocabulary`, the carried vocabulary digest, so that
    narrowing the caught set after the run breaks every record's binding
    rather than re-deriving for free; and its `networkPosture` input
    becomes the canonical digest of the carried `networkPosture` object
    rather than the value of that object's own `digest` member, which
    brings the posture string inside the signature it was sitting beside.
    Both inputs are configuration already on the wire, so the change costs
    no bytes and adds no comparison. Version 1 is retired with no alias and
    no dual-accept window: a statement built under it derives a digest no
    record carries, and a record declaring version 1 explicitly covers
    nothing. The absent-member default is now stated as the implemented
    version rather than as a fixed number, so that omitting the optional
    declaration stays legal across a version change.
-   Closed the `networkPosture.posture` vocabulary at four registered
    values and made an unregistered one malformed, resolving a divergence
    in which this document introduced the values as an example while the
    proto beside it and every shipped implementation treated them as a
    closed, fail-closed set.
-   Replaced the producer-claim trust-boundary paragraph with a field
    partition and an honest key model: the tier defeats substrate-free
    minting only where the observation key is held apart from the
    assembly plane; under a single trust root it defeats only a keyless
    downstream tamperer, and a key-holding operator who signs fiction
    stays outside the threat model. Coverage is only as trustworthy as the
    named key's un-compromised lifetime.
-   Stated the single normative read of `containmentObserved` (carried
    caught-set membership) and the criterion that an axis earns its own
    member only when a normative reader consumes it; attribution strength
    and tolerance remain non-normative. Pinned the recompute's
    independence from the validity gate and the tier. Stated the
    composition and run-population non-claims. Unknown `aeeKind` covers
    nothing and is otherwise ignored (fail-closed forward compatibility).
-   Completed the canonical-bytes profile with its string half: the
    vocabulary arrays are sorted ascending by UTF-16 code unit explicitly,
    and every signed canonical surface (covering payload member names,
    both vocabulary arrays) is BMP-only, rejected as malformed: within
    the BMP, code-unit and code-point order coincide, so conforming
    verifiers cannot split on sort order.
-   Numbered the byte-pure validity steps and separated them from the
    trust-relative stage; stated the consumer anchor obligations (pinned
    expected corpus and substrate digests, compared at consumption, with
    a single conjoined admission result recommended for verification
    surfaces) as consumer policy rather than a validity gate.
-   Recommended a publicly datable, round-unpredictable component in the
    run-entropy pre-image (proven signing-time floor; asserted ceiling
    unchanged), with the qualifications that make the floor real.
-   Added the optional `aeeRunSeq` / `aeePrevRunBinding` /
    `aeeChainScope` arming-payload members: cross-run gap evidence under
    a declared scope, ordering-only, with equivocation semantics for
    forks and duplicated geneses and a stated registration-receipt
    completion path.
-   Reclassified the shared-reference evidencing rule as a producer
    obligation outside every gate, and recorded the member-birth
    versioning discipline in this changelog. Documented the
    registered-claims lineage for reserved payload members as an
    informative note.
-   Retracted three claims that building the reference verifier and
    executing attacks against it disproved. `batchRoot` is recomputed from
    the carried records, so it establishes the internal consistency of the
    carried set and never its completeness: neither a dropped interception
    nor a dropped `arming` or `sealed` record changes a root recomputed
    over what remains, and the `method` cap is per record rather than per
    attack, so re-pointing a row's `observationRefs` at another attack's
    record inflates the row's `method` with every substrate signature still
    verifying. Each retracted sentence is replaced by a statement of the
    party the mechanism does bound, namely one who cannot re-sign the
    enclosing envelope. Coverage validity is now stated as a set of
    structural well-formedness constraints that become security properties
    only in combination with observation-record signature verification.
    Recorded two further limitations beside the coverage-bounded-observed
    one (the executed attack set is a producer assertion, and the four
    names outside the run binding are attacker-modifiable on a valid
    statement), and split the recompute goal into its recomputable
    reduction and its asserted construction. No normative requirement
    changed.
-   Required the corpus manifest to declare at least one attack identifier
    across all of its classes; a manifest declaring none makes the statement
    malformed. Coverage integrity otherwise passes vacuously on an empty
    union, zero rows carry no `basis: substrate` row, and the statement then
    legally omits `runEntropy`, `observationRecords` and `batchRoot`, which
    admitted a valid `pass` about an arbitrary subject with no substrate
    participation at all. The
    requirement is stated over attack identifiers rather than over classes so
    that a named class with an empty array is closed alongside an empty
    classes object, and it leaves the honest fully-skipped run (attack
    identifiers declared, every class disclosed under `outOfScope`, scoring
    `degraded`) valid.
-   Typed `issuedAt` as the framework's `Timestamp` rather than as a
    lowercase RFC 3339 timestamp, which is what the protobuf schema already
    did, and stated on the field the timestamp profile the type leaves open:
    uppercase designators, and a zone designator of `Z`, `+00:00` or
    `-00:00`. The zone rule was previously written only on `armedAt`, so a
    statement whose `issuedAt` carried `+05:00` was conformant while being
    off-guideline, and the case rule was written nowhere, which had already
    split two independently written verifiers on the same bytes. `armedAt`
    now cites the profile instead of restating half of it.
-   Typed `observationEnvironment.substrate` and
    `observationEnvironment.catchPolicy` as the framework's
    `ResourceDescriptor`, the type the sibling predicates already import, and
    stated the rule the other four members of that object are held under. The
    JSON member names and the wire shape are unchanged, so no signed byte, no
    digest, no signature and no conformance vector moves; in the protobuf
    schema two locally declared messages become that import. The rule is that
    a member carrying the pre-image its digest is taken over keeps that
    pre-image on the statement's own JSON surface, because the only descriptor
    member that could hold it is base64 `content`, and material inside a
    base64 member is outside every byte-level rule Prerequisites states.
-   Corrected the key-validity window recommendation, which named `issuedAt`
    as the operand a consumer checks a named key's validity against. That
    field is producer-asserted, sits outside every substrate signature, and
    is not among the run binding digest's inputs, and the one rule this
    document states about it survives moving it later, so the window was
    recommended on the single temporal value the party that key separation
    exists to constrain writes at will: back-dating it rehabilitates every
    record a since-revoked key ever signed, at no signature and no digest.
    The operand is now the `armedAt` inside an `arming` record that verifies
    under the bounded key, and a statement carrying no such record is refused
    rather than falling back. The operand is stated normatively rather than
    left to the consumer because an admission policy written independently of
    this sentence had already bounded evidence age against the same field and
    believed it bounded; one implementer choosing the defeated operand is a
    mistake, and two choosing it separately is a property of how the field
    reads. No wire byte, digest, signature or conformance vector moves: the
    correction is to a consumer obligation in stage two, which the byte-pure
    validity gate does not reach.
-   Added a fourth `result` value, `pass_indirect`, ordered between
    `degraded` and `pass`, and restated the recompute as the minimum of
    three independent conditions rather than as a cascade. The added
    condition holds when a clean row carries a `basis` other than
    `substrate` or a `method` other than `intercepted`. The top result was
    otherwise reachable by a statement carrying no substrate evidence at
    all: a party holding the enclosing envelope key alone moves every row
    to `basis: artifact`, drops the records, the batch root and the run
    entropy that a substrate row would have required, and lands above the
    run it downgraded. That mutant is byte-identical to the statement an
    honest producer with no substrate vantage emits, measured over every
    finding-bearing vector in the conformance suite, so the two are not
    separable by any function of the carried bytes and the value prices
    both rather than refusing either. The condition reads only required row
    members with closed vocabularies, so the recompute stays byte-pure, and
    it is deliberately phrased over declared vantage and directness rather
    than over the evidence tier, so the tier's independence from `result`
    survives unchanged and the one weakness the tier owns, an `unattested`
    substrate clean row, keeps the top token as it always did. Four accept
    vectors and one reject vector move their expected result; no wire
    member, digest, signature or record moves.

0.7 makes checkable four things 0.6 could only describe. It is breaking on
the wire, on the corpus and on every published conformance record:

-   The predicate type is `.../v0.7` and 0.6 is retired with no alias and no
    dual-accept window, under the same single-canonicalization rule that
    retired the 0.4 basis values and the `does_not_assert` spelling. The bump
    is neither housekeeping nor free. Three members become REQUIRED and a
    record that was conditionally required becomes unconditional, so a
    statement valid under 0.6 can be malformed under 0.7. The versioning
    discipline above says a member becomes required at the version that gives
    it a normative reader and never retroactively, and that rule is
    unimplementable unless the wire says which version a reader is holding.
    `aeeBindingVersion` cannot say it, because it scopes the run binding
    construction alone and none of these members is a binding input. A minor
    version was not available either: this document licenses a minor version
    to append a posture value, a chain dimension or a record kind without
    changing the covering semantics of an existing kind, and every change
    below changes the covering semantics of `arming` and `sealed`. So the
    discipline decides the bump, and the review calendar does not.
-   A `sealed` record is now required on every statement carrying a
    `basis: substrate` row rather than only where a clean intercepted row
    needs covering, and it carries `aeeObservedSet`, a commitment to the leaf
    hashes of every `interception` and `examination` record the substrate
    emitted. Until this, the only substrate signature made after the run was
    over carried three facts about the vantage and none about the
    observations, and a party holding the enclosing envelope key could delete
    an inconvenient interception, recompute a root over what remained, and
    emit a statement that satisfied every requirement in the document. The
    requirement is unconditional because a rule conditioned on the presence of
    the record it constrains is a rule a producer switches off by omission,
    and the statements it was switched off on were exactly the statements the
    deletion works against.
-   A record's kind constraints are now evaluated on every carried record of
    a covering kind rather than only where a row resolves one. Requiring a
    valid `sealed` record to be present, as the entry above does, says
    nothing about the invalid ones beside it, and the gap between those two
    sentences is a producer's to use: carry the `sealed` record the substrate
    signed with its moat reported down, point the row at a second seal, and
    the defective record is carried, signed, committed in `batchRoot` and
    read by nothing. The same gap holds `arming` open through a second arming
    record, `examination` through an unreferenced one, and `interception`
    through a caught row of a basis the per-row requirements above do not
    reach. It is one defect in four places, so it is repaired once, over the
    kind rather than over the reference.
-   Two structural requirements join coverage validity and need no signed
    data at all: a clean row may resolve no index to an `interception`
    record, and every carried `interception` record is resolved by at least
    one caught row. The first refuses a relabelled row that still points at
    the record its caught form cited; the second refuses the escalation of
    dropping the reference instead of the record. Neither reaches a producer
    that drops the record itself, which is what the run-end commitment is for,
    and the second is worth nothing against a producer that also withdraws
    every substrate row, which is stated where it is defined rather than
    discovered later.
-   `aeeObservedAttacks` on the seal names the attacks the run attributed at
    least one of its own observations to, and obliges a caught row for each.
    It is the one member here that survives the deletion of every interception
    record, because the seal's claim does not travel on the records the
    deletion removes. It is a lower bound in one direction by construction, it
    is available only to a substrate that dispatched the corpus, and the empty
    array is required rather than omissible so that a substrate holding no
    correspondence declares that on the wire instead of leaving an absence
    nothing records.
-   `aeeAssessedAttacks` on the arming record names the attacks the run
    declared, before injection, that it would assess, and the assessed set
    carried at run end must be a subset of it. It binds coverage inflation,
    which is the withdrawal's mirror image and the only half of that pair a
    commitment can reach: inflation must keep the run-level records its
    fabricated rows point at, and withdrawal need keep nothing at all. The
    comparison is deliberately a subset and not an equality, so that a run
    which loses coverage part-way can still disclose the loss.
-   `corpus.manifest.expectedPayloads`, `aeePayloadCommitment` on
    `interception` records, and the required row member `attribution` over the
    closed vocabulary `pinned` / `paired` together make the shared-reference
    evidencing obligation checkable, which is the change the versioning
    discipline above pre-authorised and which is what makes attribution
    strength a member at this version. A row declaring `pinned` must resolve
    at least one interception and every interception it resolves must carry a
    value the corpus declared for that attack; the quantifier is paired with
    an existence requirement because a universally quantified rule over an
    empty set is vacuously true, and without the pairing a producer could
    delete the records and keep the stronger label.
-   What none of the four closes is stated beside the coverage validity
    requirements, one member at a time, because the four stop in different
    places and a single caveat would flatten them. Two of the closures in this
    version are consumer obligations rather than validity rules, and they are
    written as obligations under Consumer policy obligations for the same
    stated reason the corpus and substrate pins are: the deciding fact is one
    the consumer holds and the statement cannot carry.
-   The run binding is unchanged and stays at version 2. Every commitment here
    travels either on a record payload or inside the corpus manifest, whose
    digest is already an input, so the construction does not move; the value
    of the `corpus` input moves on every statement carrying
    `expectedPayloads`, which is the binding working rather than changing.
-   Every published conformance record breaks, including any built by an
    independent implementer, and that cost is named rather than absorbed: an
    independent re-run is the strongest external evidence this document has
    that its text is determinate, and a breaking version spends it. The
    predicate is pre-adoption, so the price is payable once and never again.
-   Registered `moat-drop` and `uncommitted-observation`, two kinds producers
    were already signing under this run binding with no spelling here. Both
    cover nothing, and registering them changes no verdict: a verifier that
    does not implement them treats each as an unrecognized kind and reaches
    the same answer, which is why the addition sits inside this version rather
    than obliging another type. What it buys is that the two names can never
    later acquire covering semantics, that each states in its own voice what
    it cannot be used to claim, and that a producer with such an observation
    has somewhere honest to put it instead of stamping it `interception` and
    invalidating the statement it was trying to enrich.
-   Producer territory is stated to be inert to a verifier. The reserved-prefix
    paragraph granted a producer everything outside the reserved names and said
    nothing about what a verifier may do with what it finds there, which left
    the answer to be guessed once per implementation. A member of that territory
    now MUST NOT affect structural validity, `result`, or the evidence tier,
    whether or not its values can be ordered. The ordered case is named
    separately because it is the one a verifier is tempted to read: an axis a
    reader might rank looks like a strength axis, and the two this predicate
    does order are ordered because a normative reader consumes them rather than
    because they are spelled in the same payload. Both halves are stated at the
    paragraph that grants the territory rather than at each future member, so an
    implementer meets them before the member exists. The structural-validity
    half is not hypothetical: a checker built against this text gated AEE
    validity on the value of a producer-defined member, which the same
    implementation's own design document already forbade.

[DSSE]: https://github.com/secure-systems-lab/dsse
[ResourceDescriptor]: https://github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md
[Runtime Traces]: https://github.com/in-toto/attestation/blob/main/spec/predicates/runtime-trace.md
[SCAI]: https://github.com/in-toto/attestation/blob/main/spec/predicates/scai.md
[SVR]: https://github.com/in-toto/attestation/blob/main/spec/predicates/svr.md
[Test Result]: https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md
[VSA]: https://github.com/in-toto/attestation/blob/main/spec/predicates/vsa.md
