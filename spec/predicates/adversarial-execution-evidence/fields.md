<!-- Long-form companion to the Adversarial Execution Evidence predicate. -->

# Adversarial Execution Evidence: field reference

Long-form companion to the registry page for predicate type
`https://in-toto.io/attestation/adversarial-execution-evidence/v0.7`.

The text below is verbatim from the single-document revision of the
specification (source SHA-256 `2b7f3bc08123cbe1981d287cf20193858ae5ea6d55ca067e06363a1e71a573d7`, lines 431-1864 of
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

### Fields

<a id="req-fields-result-string-required-fail-degraded"></a>

`result` _string, required_

<a id="req-fields-fail-degraded-pass-indirect-pass"></a>

One of `fail`, `degraded`, `pass_indirect`, `pass` (lowercase), ordered
`fail` < `degraded` < `pass_indirect` < `pass`. Defined as a total,
deterministic, severity-independent function of the predicate, evaluated as
the minimum under that order of three independent conditions rather than as
a cascade, because worst-wins rather than evaluation order is the rule. The
first condition holds when any `attackResults` row carries a
containment-observed label from the carried caught set
(`observationVocabulary.caught`), a label outside the carried
`observationVocabulary.labels` (fail-closed), or a missing or
out-of-vocabulary `basis`, `method` or `attribution` (fail-closed, same
rule), and it contributes `fail`. The second holds when `coverage.outOfScope` or
`coverage.routedElsewhere` is non-empty, and it contributes `degraded`. The
third holds when any clean row, meaning a row whose `containmentObserved`
is in the carried labels and not in the carried caught set, carries a
`basis` other than `substrate` or a `method` other than `intercepted`, and
it contributes `pass_indirect`. A condition that does not hold contributes
`pass`. A `pass` is coverage-bounded-observed: it states what was
assessed and makes no general safety claim. There is intentionally no
severity threshold, policy ruleset, or free-text reason here; policy belongs
downstream.

`pass_indirect` is a coverage-complete result at least one of whose clean
rows rests on an observation that was indirect in vantage (`basis:
artifact`, the executed artifact's own account of itself) or indirect in
time (`method: reconstructed`, derived after the event rather than at it).
`pass` and `pass_indirect` make the same coverage claim and different
observation claims, and the ordering says only that the second is never the
stronger of the two. The distinction exists because the top result was
otherwise reachable by a statement disclaiming substrate observation
altogether. A party holding the enclosing envelope key but not the
substrate's observation key can move every row to `basis: artifact` and
then drop the observation records, the batch root and the run entropy that
those rows no longer require, and the statement it presents is well formed,
carries no substrate evidence at all, and reads at the top of the ordering.
That statement is byte-identical to one an honest producer with no
substrate vantage emits from the same configuration, so no function of the
carried bytes refuses the first without refusing the second, and refusing
both would remove the producer whose attack classes have no substrate
vantage to observe from. What the fourth value does instead is price both
below a live interception, which is the only distinction the carried bytes
support.

`pass_indirect` is not a revival of the retired 0.4 `inferred` value.
`inferred` was a row-level value whose conflation destroyed, at its only
carrier, which axis was weak; `pass_indirect` is a statement-level
reduction over `basis` and `method`, both of which remain required and
individually readable on every row, so nothing a consumer needs is
available only through the reduction. A consumer that needs to separate
indirectness of vantage from indirectness of time MUST read the two row
members and never the result token.

`pass_indirect` says nothing about signature verification, and the third
condition is deliberately not phrased over the evidence tier. A `pass` may
still rest on clean rows deriving `unattested`, which the clean-row
ordering ranks with `artifact`; that half of the weakness is key-relative,
belongs to the evidence tier rather than to the recompute, and a byte-pure
function cannot see it. Neither the token nor the tier substitutes for the
other, and a consumer crediting any `basis: substrate` row MUST derive the
tier whichever of the two top results the statement carries.

The default admission threshold is `result == "pass"`. A consumer MAY
accept `pass_indirect`, and a consumer relaxing its threshold below `pass`
MUST additionally key on each clean row's `basis` and `method` and on that
row's derived evidence tier, because below `pass` the ordinal stops
distinguishing them: a `degraded` reached through a disclosed coverage gap
and a `degraded` whose clean rows are all `artifact` carry the same token.

<a id="req-fields-attribution-enters-recompute-through-fail"></a>

`attribution` enters the recompute through the fail-closed arm of the first
condition and nowhere else. A row declaring `paired` is not a weaker result,
it is a weaker binding between the row and the records that cover it, and the
two are different questions: the recompute asks what was observed, and
`attribution` asks how firmly this row is the row that observation belongs to.
Pricing `paired` in the result would charge an honest producer for a layer
whose committed value no corpus can predict, which the member's own definition
states is a permanent condition of some layers rather than a gap in this one.
A consumer that cares about the binding reads the member; the token never
carries it, exactly as it never carries the evidence tier.

Two further bounds sit beside that one. The substrate observes what crosses
the vantages it was armed at, and this document requires nothing of it beyond
that. Some deployments run a substrate that also dispatches the corpus, and
such a substrate holds, on its own clock, which probe it issued and which of
its own records fell inside that probe's window; `aeeObservedAttacks` exists
so that a substrate holding that correspondence can sign it instead of handing
it to the assembly plane unsigned. Neither shape reaches the bound stated
here. A substrate that never saw the runner cannot verify that the runner
executed every attack the manifest names, and a substrate that dispatched the
corpus itself still says nothing about an attack that produced no observation,
because a lower bound over what was observed is silent about what was not. The
set of attacks actually executed therefore remains a producer assertion under
both shapes. Coverage integrity compares the carried rows against the carried
manifest, which catches an omission the producer failed to declare in
`coverage`, but neither comparison reaches the run, so a consumer reading a
`pass` is relying on producer integrity that nothing was silently skipped.

The second bound is that four fields sit deliberately outside the run
binding, because the substrate operates on content digests and has no view of
presentation metadata: `corpus.name`, `corpus.uri` (RECOMMENDED as a purl),
`substrate.name`, and `subject[0].name`. No digest, no record payload, and no
gate reads them, so they are attacker-modifiable on a statement that remains
fully valid. Calling them unauthenticated understates that for a reader who
assumes the enclosing envelope signature protects everything inside it: a
statement can be relabeled as evidence about a differently named corpus,
substrate, or artifact and still satisfy every requirement in this document.
Consumers MUST anchor identity on the digests rather than on these names, as
Consumer policy obligations below requires for the corpus and the substrate.

<a id="req-fields-coverage-validity-derived-carried-bytes-2"></a>

<a id="req-fields-coverage-validity-derived-carried-bytes"></a>

**Coverage validity (derived from carried bytes; a violation is malformed).**
For every `basis: substrate` row, the following MUST hold or the attestation
is invalid, exactly as a missing `actualLayer` is invalid. These read record
payloads but never signatures or consumer policy, so they are a pure function
of the carried statement, and that is what makes them runnable by a consumer
holding no keys. It is also their limit: a violation here is conclusive, since
no signature can rescue a statement that does not hang together, but the
absence of a violation concludes nothing on its own. These requirements
establish that the statement is well formed, never that it is true:

<a id="req-fields-observationrefs-non-empty-index-range"></a>

-   its `observationRefs` is non-empty and every index is in range for
    `observationRecords`;
-   the referenced records match the class the row requires: a caught row
    with `method: intercepted` references at least one `interception`
    record; a `method: reconstructed` row references at least one
    `examination` record; a clean row with `method: intercepted`
    references at least one `arming` record and at least one covering
    `sealed` record (a `sealed` record covers under the conditions stated
    at its class definition);
-   every referenced payload parses as a canonical `+json` object (see
    `observationRecords`), carries the reserved members, and its
    `aeeRunBinding` equals the run binding digest derived from this
    statement;
-   the row's `method` is no stronger than the weakest `aeeMethod` across
    its covering records (`reconstructed` is weaker than `intercepted`);
-   `batchRoot` recomputes over `observationRecords` (see `batchRoot`).

<a id="req-fields-six-further-coverage-validity-requirements"></a>

Six further coverage validity requirements hold on the statement, or on
every row rather than only on a `basis: substrate` row. Each is a function of
carried bytes on the same terms as the list above, and a violation of any of
them makes the attestation invalid:

<a id="req-fields-clean-row-resolves-observationrefs-index"></a>

-   a clean row resolves no `observationRefs` index to an `interception`
    record. A row stating that nothing was caught while pointing at a record
    in which the substrate signed that it intercepted traffic states both
    halves of a contradiction, and the check is a membership test that reads
    no signature and no key. It is stated over every row because the
    contradiction does not depend on the vantage the row declares;
-   every carried record whose payload `aeeKind` is `interception` is
    resolved by at least one `observationRefs` index on a caught row. An
    interception the statement carries and no caught row accounts for is an
    observation the substrate signed and the producer then reported nothing
    about. One record MAY be resolved by more than one row, so this costs
    none of the sharing this document already permits;
-   a statement carrying at least one `basis: substrate` row carries at least
    one `sealed` record that satisfies every constraint of its kind and whose
    `aeeRunBinding` equals the derived run binding, whether or not any row
    resolves an index to it. Before 0.7 a `sealed` record was required only
    to cover a clean intercepted row, so a statement whose rows were all
    caught carried none, and the run-end commitment defined under
    `observationRecords` had nowhere to live on exactly the statements a
    record deletion works against. A rule conditioned on the presence of the
    record it constrains is a rule a producer switches off by omission;
-   every carried record that binds to this run and whose payload `aeeKind`
    names a covering kind -- `interception`, `arming`, `sealed`,
    `examination` -- satisfies every constraint of that kind, whether or not
    any row resolves an `observationRefs` index to it. A constraint evaluated
    only where a row points is a constraint whose subject the producer
    chooses: a substrate signs a `sealed` record reporting its moat down, the
    producer carries that record and points the row at a second seal, and the
    run reads clean with the record that says otherwise sitting in the
    statement and inside `batchRoot`. The kinds registered as covering
    nothing and the kinds a verifier does not recognize are unaffected, since
    neither carries a constraint that could be violated. This is the
    universal partner of the requirement above it, over the same records on
    the same terms: that one asks whether a valid `sealed` record is present,
    this one asks whether an invalid one is;
-   `aeeObservedSet` on every carried `sealed` record equals the value
    recomputed over the carried records, by the construction stated at that
    member. A seal committing to a record set the statement does not carry
    does not hang together, in the same sense as a `batchRoot` that does not
    recompute;
-   a row declaring `attribution: pinned` resolves at least one
    `observationRefs` index to an `interception` record, its `attackId`
    carries an entry in `corpus.manifest.expectedPayloads`, and every
    `interception` record it resolves carries in its `aeePayloadCommitment`
    at least one value from that entry. A row whose `attackId` carries no
    such entry MUST declare `paired`. The first part is not redundant beside
    the third: a requirement universally quantified over an empty set is
    vacuously true, so without it a producer deletes the interception
    records, relabels the row, resolves only run-level records, and still
    declares the stronger of the two values with nothing checking it.

<a id="req-fields-these-requirements-consumption-preconditions-optional"></a>

These requirements are consumption preconditions, not optional lints: a
consumer that consumes `result`, credits any row, or applies either
strength ordering MUST first evaluate them, and on failure the attestation
is invalid and its `result` MUST NOT be consumed, the same handling as
any malformed statement.

Where a statement carries at least one `basis: substrate` row and no carried
`sealed` record satisfies every constraint of its kind, the existence
requirement and its universal partner are unmet by the same record and name
different repairs. A verifier SHOULD report the unmet existence requirement as
its primary condition and any refusal naming the defective record's kind beside
it rather than in its place, because where a satisfying record is carried beside
the defective one dropping or repairing that record reaches validity and where
none is it does not: a statement whose only seal reports its moat down is not
repaired by dropping the seal, and a producer told only that a carried record is
defective has been told to perform a repair that cannot work. This document
defines no condition vocabulary, so what is fixed is which of the two a verifier
reporting a single condition reports and which a verifier reporting a set
includes, never the identifier either is drawn under, and the obligation is
diagnostic and never a validity rule.

Where a refusal names a comparison, the set it names MUST be the set the
implementation evaluated. The requirement above governs. The shapes below are
those seen in practice and do not exhaust it. A mechanism not named here that
causes a refusal to name a comparison the implementation did not evaluate
violates the requirement all the same. Four such shapes are worth stating, and
they break it differently. A refusal naming a comparison whose operand set was
empty names a comparison that did not run: a requirement universally quantified
over an empty set is vacuously true, as the `attribution: pinned` requirement
above already turns on, so a verifier MUST NOT name such a comparison in a
refusal and SHOULD report the empty set instead, which is what it found. A
refusal naming a set wider than the one the check ranged over overstates what
was compared and tells the producer to repair records the check never read, so
a verifier MUST NOT name a wider set; where the evaluated set is a function of
the statement, as it is for the set of `arming` records a row resolves, a
verifier SHOULD name that set and its count. And a refusal naming a comparison
against a commitment -- `aeeObservedSet`, `batchRoot`, `corpus.digest` -- may
name the comparison, which genuinely ran, but MUST NOT describe it as a
comparison over a set whose membership it cannot exhibit: a digest mismatch
says the recompute differs and says nothing about which element differs, and a
refusal implying otherwise reports a capability the construction denies it. And
a refusal naming a conjunction of comparisons of which the implementation
evaluated only a prefix names comparisons that did not run. Where evaluation
short-circuits at the first false conjunct, one refusal can stand for several
distinct failures and be byte-identical across them, which tells a producer
nothing about which conjunct decided it. A verifier MUST NOT name a conjunct it
did not reach, and SHOULD name the conjunct that decided the refusal. This
shape differs from the three above in mechanism. Those turn on which elements a
comparison ranged over, and this one on which comparisons ran at all. This
document defines no condition vocabulary, so what is fixed is what a refusal
may claim to have compared, never the identifier it is drawn under, and the
obligation is diagnostic and never a validity rule.

What these requirements are is worth stating as plainly as what they
require, because their name invites a reader to take them for a security
gate on their own, and on their own they are not one. Every check above
reads record content, and record content means nothing until the record's
signature verifies, which is the verify-then-read discipline stated under
Parsing Rules. Against a party able to author a record, none of these checks
costs a secret: `aeeRunBinding` is derived entirely from material the
statement already carries in plaintext, `aeePostureDigest` is the pinned
`networkPosture` digest carried beside them, and an `arming` or `sealed`
payload describing a vantage that never existed satisfies every constraint
here. These requirements are therefore structural well-formedness
constraints. They become security properties only in combination with
observation-record signature verification against a substrate key the
consumer trusts, which is the evidence tier below. A verifier that evaluates
coverage validity and skips that verification has checked that the producer
filled the form in correctly.

**What the 0.7 commitments do not close.** Each of the four members 0.7 adds
is either a bound on inflation or a conversion of an invisible edit into a
declaration a consumer can read. None is a detector, and the four stop in
different places, so the limits are stated one at a time rather than as a
single caveat.

`aeeObservedSet` binds the deletion of a record from the carried set, and only
while the statement still has to carry the seal. It does not reach a producer
that declines to run an attack, declines to report a row, or withdraws every
`basis: substrate` row: once no row declares that basis, `runEntropy`,
`observationRecords`, `batchRoot` and the `sealed` record become optional
together, and what remains is a statement an honest producer with no substrate
vantage emits from the same configuration. It inherits, without curing,
whatever the substrate did not record, because a commitment to the emitted set
is a claim about what the substrate emitted and never a claim that nothing else
happened; an evasion at a boundary that produces no record is faithfully absent
from a verified commitment. And it is a structural constraint like every other
requirement here: against a party that can sign records it is exactly as
forgeable as the rest of the payload.

<a id="req-fields-aeeobservedattacks-binds-deletion-relabelling-member"></a>

`aeeObservedAttacks` binds the deletion and the relabelling in one member,
because deleting every interception record does not delete the seal's claim
that an attack was observed. Three things bound it in turn. It is a lower bound
by construction: a seal naming an attack obliges a caught row for that attack,
and a seal omitting one licenses nothing, so an observation the substrate could
not attribute subtracts from the claim rather than adding a false one. It is
available only to a substrate that holds the correspondence, and a substrate
that does not carries the empty array honestly, so a producer withdraws the
whole control by presenting a substrate that does not dispatch the corpus. What
the member changes there is visibility rather than reachability: the withdrawal
is an empty array on the wire instead of an absence nothing records, and a
consumer that demands a non-empty set refuses a statement rather than failing
to notice one. And it names no attack on the record that observed it, so it
cannot cap a `method` per attack and cannot tell two observations of one attack
apart.

`aeeAssessedAttacks` binds coverage inflation and nothing else. It cannot
bind coverage suppression, and that is a property of the target rather than a
weakness of the rule: a producer that withdraws its rows and discloses the
classes emits a statement byte-identical to the one an honest producer emits
after a run that could not assess them, so no rule over the carried statement
refuses the first without refusing the second. The rule that would close
suppression inside the format conditions the commitment's presence on the
disclosure itself, and its price is the artifact-only producer that has no
substrate and is honest about a class it did not cover, the fully-skipped run
this document deliberately keeps valid, and every run that loses coverage
part-way; that price is not paid here. The comparison is a subset rather than
an equality, which is what keeps the part-way loss expressible, and what the
subset bounds is the producer's own run-start declaration: a producer that
declares the whole manifest at run start has committed to the largest set the
manifest permits and is bounded there by coverage integrity alone. What the
member removes is the freedom to raise that declaration after the outcome is
known. It is also computed over the carried manifest, so it is blind to a
corpus whose manifest never declared the class a consumer wanted assessed.

<a id="req-fields-expectedpayloads-aeepayloadcommitment-attribution-bind-permut"></a>

`expectedPayloads`, `aeePayloadCommitment` and `attribution` bind the
permutation of the row-to-record assignment, and only on the layers where the
committed value is predictable from the corpus. They do not bind the deletion,
because their commitments ride the records a deletion removes; that ground
belongs to the run-end commitment and not to these. They are unavailable,
rather than merely absent, wherever a substrate commits to a value no corpus
author can compute in advance: a commitment taken under a per-run key, one over
bytes the substrate re-serialized rather than the bytes the artifact emitted,
one over bytes a scrubbing or capping policy altered, or one over a raw frame
prefix carrying values a kernel assigned. On those layers `paired` is the true
answer, and a universal `pinned` requirement would oblige a producer to state a
falsehood or oblige a substrate to give up the property that made its
commitment unpredictable. `paired` is therefore itself a free withdrawal: a
producer declaring it on every row satisfies every rule here, because a
statement claiming a weaker binding is a statement an honest producer with a
weaker binding emits.

<a id="req-fields-there-second-use-these-three"></a>

There is a second use of these three members, found by implementing them rather
than by designing them, and recorded here because it was not what they were
written for. A consumer that demands `pinned` on every attack the carried
manifest holds an expectation for learns, from its own refusals, which layers of
its own substrate cannot produce predictable commitments. The refusals are the
measurement, no adversary is involved, and the answer is about the consumer's
own stack rather than about any statement it received. Reported by the author of
the second independent implementation during review of this predicate.

<a id="req-fields-closure-against-producer-consumer-obligation"></a>

The closure against that producer is the consumer
obligation stated under Consumer policy obligations, and it is the closure
rather than a hook into one, in the same place and for the same stated reason
as the corpus and substrate pins.

<a id="req-fields-limit-common-all-four-stronger"></a>

One limit is common to all four and is stronger than any of them. A property
that compares this statement against another statement of the same run is
unreachable by any rule over one statement, whatever that statement carries: a
consumer holds one attestation, and a rule asking whether a label was different
before has no second statement to read. That is the run-population non-claim
this document already keeps loudest, wearing different clothes.

<a id="req-fields-further-limit-belongs-member-here"></a>

A further limit belongs to no member here and would not be closed by adding
one. `basis` names a class of vantage and not the substrate that holds it, so
the vantages enumerated under `substrate` -- a network boundary, syscall
supervision, a hypervisor's read of guest state -- are one value on the wire. A
monitor supervising syscalls from the host kernel and a monitor reading guest
state from outside a virtual machine satisfy the same requirement that the
observation key not be accessible to the subject artifact, and derive the same
`attested` tier, which is a function of a covering signature verifying against
a policy-named key and reads nothing about where that key is held. A consumer
that did not provision the deployment therefore cannot tell from the statement
which of the two produced a record, and the difference is a real one wherever
the consumer's threat model separates a compromised kernel from a compromised
host. This document declines to spell the distinction as a graded member, one
feeding the evidence tier or the result recompute. A self-declared value in
that position is a producer assertion about the producer's own stack, as
forgeable as the rest of the payload, and a forged value there changes a
verdict. An ungraded partition identifier is a different proposal, and this
document does not evaluate it. SLSA keeps `builder.id` REQUIRED on that
reading, as a key a consumer policy matches on rather than a claim a consumer
believes, and asks that modes with differing security attributes carry
different identifiers so that a partition stays a partition. Nothing here rules
that construction out. The closure is the refinement path stated under the
evidence tier, where consumer policy MAY subdivide `attested` into stricter
refinements, for example requiring a hardware-attested observation key. A
consumer that needs the distinction obtains it by naming the keys it will
accept, and this document spends no vocabulary on it.

<a id="req-fields-caught-row-whose-containmentobserved-label-2"></a>

<a id="req-fields-caught-row-whose-containmentobserved-label"></a>

A caught row is one whose `containmentObserved` label is in the carried
caught set (`observationVocabulary.caught`); a clean row is one whose
label is in the carried `observationVocabulary.labels` and not in the
caught set. Both sets travel in the attestation, so the distinction is a
function of carried bytes. A `basis: substrate` row whose
`containmentObserved`, `basis`, or `method` is fail-closed (outside the
carried vocabulary) cannot satisfy the class-match requirement and is
therefore invalid; a `basis: artifact` fail-closed row sits at the bottom
of both orderings as before.

**Evidence tier (derived, never carried).** Given a valid attestation, a
consumer MUST, before crediting any `basis: substrate` row or applying
either strength ordering, derive a per-row evidence tier: a `basis:
artifact` row is `declared`; a `basis: substrate` row is `attested` when
every covering record's signature verifies against a key the consumer's
policy names as a substrate observation key, and `unattested` otherwise. A
consumer with no policy-pinned substrate root MUST treat every `basis:
substrate` row as `unattested` and MUST NOT infer the substrate root from
the predicate. The tier is total and deterministic given the consumer's
key policy; it never alters `result`. Consumer policy MAY subdivide
`attested` into stricter refinements (for example requiring a
hardware-attested observation key, or agreement of multiple keys); a
refinement refines, never reorders, the three tiers, and tier names
beginning with `aee` are reserved. A carried predicate member named
`evidenceTier`, or any predicate-level member beginning with the reserved
prefix `aee`, MUST be ignored and MUST NOT alter the derivation.

`observationEnvironment` _object, required_

<a id="req-fields-digest-pinned-context-evidence-was"></a>

The digest-pinned context the evidence was earned under. Five required
members: `substrate` (the subject reference of the substrate's own
attestation), `corpus` (name, uri, RECOMMENDED as a purl; the JCS digest of
the embedded `manifest`, and the `manifest` itself, which carries a required
`classes`, a map from assessment class to the complete array of attack
identifiers it defines, and an optional `expectedPayloads` defined below; an
attackId MUST NOT appear under more than one class), `catchPolicy` (JCS digest of the
parsed catch-policy document, so an empty or permissive policy is
distinguishable from an enforcing one), `networkPosture` (the
substrate-authoritative egress posture, drawn from the closed vocabulary
registered below, with its configuration digest), and
`observationVocabulary` (the
producer's versioned observation label set carried in the attestation:
`labels`, the complete array of `containmentObserved` values the producer can
emit, and `caught`, the subset whose observation constitutes a caught
containment event; both arrays sorted ascending by UTF-16 code unit (RFC 8785
Section 3.2.3) with no duplicates and every entry BMP-only (see
Prerequisites), `caught` a subset of `labels`, and `digest` the JCS digest of
the object `{"caught": [...], "labels": [...]}`; a statement violating any
of these is malformed).
The recompute and the coverage validity requirements read only this carried
set; the producer's published documentation is commentary on the same
vocabulary, never a normative input, so archived attestations remain
verifiable after the producer's documentation moves or disappears. A sixth
member, `runEntropy` (the substrate-emitted run-start value defined under Run
binding), is required exactly when any row carries `basis: substrate`. The
manifest pre-image travels in the attestation, so a verifier re-derives
`corpus.digest` offline and any edit to the assessed set (a dropped attack, a
renamed class) fails that check.

`corpus.manifest.expectedPayloads` is an optional map from attack identifier
to the duplicate-free array of lowercase 64-hex commitment values a substrate
is expected to carry when it observes that attack. Every key MUST be an attack
identifier the same manifest's `classes` declares, every array MUST be
non-empty, sorted ascending by UTF-16 code unit and duplicate-free, and every
entry MUST be lowercase 64-hex; a manifest violating any of these is
malformed. The map is a sibling of `classes` rather than an enrichment of it,
because `classes` is the in-scope partition that the manifest floor and
coverage integrity read, and what an attack looks like on the wire can be
added, corrected or extended without repartitioning the corpus. It inherits
the manifest's digest pinning with no new mechanism: it sits inside the
pre-image `corpus.digest` is taken over, which is a run binding input, so it
is pinned out of band by the same consumer obligation that pins the classes
beside it.

The value an entry carries is the commitment as the substrate computes it, and
not a digest of the input the corpus author wrote down. Where a substrate
canonicalizes before committing, a path it normalizes or a host name it maps
to its A-label form, the corpus carries the canonical form; a corpus carrying
the raw form silently fails to match and every row it should have supported
falls back to `paired` while looking correct. This is a producer obligation
that no verifier can check, because a verifier holding the corpus and the
statement cannot tell an honest absence of an expectation from a mispredicted
one, and it is stated here because the failure is silent in the direction that
weakens the claim rather than in the direction that invalidates it.

`expectedPayloads` discharges the versioning commitment recorded in the
changelog: it is the per-attack expected artifact that example named, so
attribution strength acquires a normative reader at this version and becomes a
required row member here. It is not retroactive, and no verifier reading a
statement of an earlier version may invent the reader.

<a id="req-fields-networkposture-posture-vocabulary-closed-four-2"></a>

<a id="req-fields-networkposture-posture-vocabulary-closed-four"></a>

The `networkPosture.posture` vocabulary is closed. Four values are
registered: `allowlist`, egress permitted only to a declared destination
set; `no_network`, no egress path exists; `sinkhole`, egress is accepted and
diverted to a capture endpoint rather than reaching its destination; and
`unsafe_bypass_egress`, egress is unrestricted and uninstrumented. A
statement whose `posture` is absent, is not a string, or carries a value
outside that set is malformed, fail-closed, on the same terms as every other
closed vocabulary here; a minor version MAY append a value and MUST NOT
redefine a registered one.

<a id="req-fields-set-closed-rather-than-illustrative"></a>

The set is closed rather than illustrative for a reason that is not
housekeeping. A consumer is invited under `basis` to coherence-check a row
against the posture the run was contained under, and a substrate row
claiming a network-boundary observation under a posture that provides no
interception path at that boundary is the case that invites it. That check
cannot be written against a value whose meaning is undeclared: no verifier
can decide whether an unregistered posture provides an interception path, so
an open vocabulary leaves the check permanently unreachable while appearing
to offer it. Closing the set also settles a divergence this document was
carrying on its own: the proto beside it already described this vocabulary
as closed and fail-closed and already carried the fourth value, so an
implementer reading the two together had to pick one, and every shipped
implementation picked the closed reading.

<a id="req-fields-typing-discipline-predicate-commits-stated"></a>

A typing discipline this predicate commits to, stated here so that a later
reader inherits it rather than rediscovers the question. Each of these six
members is descriptor-shaped, and two of them are [ResourceDescriptor]s.
`substrate` and `catchPolicy` identify a resource and carry nothing beside
that identity, so they take the framework type; the `sha256` digest required
on each is a requirement the descriptor specification permits a context using
the type to impose, and a producer MAY additionally carry `uri`,
`downloadLocation` or `mediaType` there, none of which any rule in this
document reads. Reading a pinned `sha256` off a descriptor is already what
this predicate does in its most load-bearing place, since `subject` entries
are [ResourceDescriptor]s by the Statement specification and the run binding
reads `subject[0].digest.sha256`.

The other four members stay locally typed, and the reasons are stated here
rather than left to inference. Where a member carries the pre-image its digest
is taken over, that pre-image stays on the statement's own JSON surface:
`corpus` carries the `manifest` and `observationVocabulary` carries `labels`
and `caught`, and the only descriptor member that could hold either is
`content`, whose value is base64. Every byte-level rule Prerequisites imposes
is stated over the statement's JSON, namely the duplicate-member rule at any
depth, the well-formed-scalar-value requirement applied to the raw bytes
before any decoded string is read, the nesting bound of 128, and the BMP
restriction on canonical surfaces. Material inside a base64 member is outside
all four, so carrying a digest pre-image there would open a second
canonicalization boundary inside a signed statement, in a predicate whose
whole encoding profile exists so that two conforming verifiers cannot
disagree about identical bytes. Where a member instead carries further
normative material beside an identity, this predicate keeps the member
locally typed rather than extending a descriptor with members of its own,
which is the shape [Runtime Traces] uses for `monitor`. `runEntropy` is
offered as a reading rather than as a rule: its digest commits to a
substrate-emitted run-start value rather than describing a resource, so a
descriptor is the wrong vessel for it.

<a id="req-fields-coverage-object-required-coverage-bound"></a>

`coverage` _object, required_

<a id="req-fields-coverage-bound-assessedclasses-array-class"></a>

The coverage bound: `assessedClasses` (array of class codes actually
assessed), `outOfScope` and `routedElsewhere` (maps from class code to a
reason string; empty objects when complete). Disclosing a gap moves the class
into one of these maps and forces `result` to `degraded`, which is the honest
alternative to leaving it out and quietly reporting a narrower run as a full
one. The three sets are a disjoint partition of the manifest's classes: a
class appears in exactly one of `assessedClasses`, `outOfScope`,
`routedElsewhere` (a move, not a copy). A class in more than one of the three,
or a manifest class in none, is malformed - a class both assessed and
disclosed as a gap is contradictory.

`attackResults` _array of objects, required_

<a id="req-fields-row-per-executed-attack-attackid-2"></a>

<a id="req-fields-row-per-executed-attack-attackid"></a>

One row per executed attack: `attackId` (must appear in the manifest),
`containmentObserved` (a label from the carried
`observationVocabulary.labels`; consumers treat labels outside the carried
set as fail-closed), `basis` (required; the observation's vantage, see
below), `method` (required; the observation's directness, see below),
`attribution` (required; how firmly the row is bound to the records that
cover it, see below),
`actualLayer` (required; which enforcement layer acted, see below), and
`observationRefs`
(indexes into `observationRecords` binding this row to the observation
records that cover it). An `interception` index MAY be referenced by more
than one row. A producer MUST NOT reference a record from a row whose
attack the record's committed payload does not evidence. On a row declaring
`attribution: pinned` that obligation is checkable and is checked, by the
coverage validity requirement stated above: the corpus declares what the
attack's interception commits to and the verifier compares. On a row
declaring `paired` it remains an obligation outside every gate, because no
validity requirement, recompute input or tier evaluation reads it there, and
a conforming verifier neither can nor may invent an evidencing heuristic in
its place. The line between the two is exactly the line the corpus draws by
carrying an expectation or not.
No two `attackResults` rows may carry the same `attackId`: one row per
executed attack is a well-formedness invariant, and a statement with a
duplicate `attackId` across rows is malformed. Coverage integrity
set-compares row `attackId`s against the manifest, so a duplicate would
silently collapse under set semantics; uniqueness is enforced separately,
before that comparison, not left to it.
Wherever `observationRefs` is present - on any row, regardless of `basis`,
and including rows on which nothing normative reads it - every index MUST be
in range for `observationRecords`; an out-of-range index is a structural
integrity fault that makes the statement malformed, fail-closed and
independent of any gate, so a reference that does not resolve is never
silently ignored.
A row MAY carry `observationSelectors`, an array of
producer-defined string tokens positionally parallel to `observationRefs`,
each naming the sub-observation within the referenced record's committed
payload that this row rests on; token content is producer vocabulary,
nothing normative reads it, and selector presence or absence changes no
gate outcome. `arming`, `sealed`, and
`examination` indexes MAY likewise be shared: one run-level record covers
every row earned under it. The single normative reading of this value is its
membership in the carried caught set; see `method` for the
exhaustion-of-meaning rule.
Coverage integrity is checked at attack granularity: the union of attackIds
for the assessed classes must exactly equal the manifest's. That granularity
is what stops a failing attack from being quietly omitted inside a class the
producer still reports as assessed.

That comparison is only as strong as the manifest it reads against, so the
manifest carries a floor of its own: it MUST declare at least one attack
identifier across all of its classes, and a manifest declaring zero attack
identifiers makes the statement malformed. The requirement is phrased over
attack identifiers rather than over classes because a manifest whose classes
object is empty and a manifest carrying a named class with an empty array
declare the same thing, nothing to execute, and only counting identifiers
closes both; the second is the more plausible of the two, since it reads as
a real assessment class. Without the floor a zero-attack manifest satisfies
coverage integrity vacuously, comparing an empty union against an empty
union, and the rest of the statement follows from there: zero rows means
zero `basis: substrate` rows, and with no substrate row this document
permits `runEntropy`, `observationRecords` and `batchRoot` to be absent, so
every structure that would have required a substrate signature drops out and
a valid `pass` about an arbitrary subject can be minted with no substrate
participation at all. A corpus declaring no adversarial inputs is not an
adversarial corpus, which is why this sits with well-formedness rather than
with `result`: scoring it would concede that a zero-attack run is a
legitimate statement that merely scores badly. The floor bounds the manifest
and nothing beyond it. A manifest that declares attack identifiers and
assesses none of them stays valid, and the honest fully-skipped run, which
discloses its classes under `outOfScope` and scores `degraded`, is untouched
by this requirement, because its manifest declares an attack identifier.

`basis` states each observation's vantage, with a closed two-value
vocabulary:

<a id="req-fields-substrate-input-row-s-claim"></a>

-   `substrate`: every input the row's claim depends on was obtained at a
    vantage the executed artifact could neither forge nor suppress (a
    network boundary, syscall supervision, a hypervisor's read of guest
    state). This names a class of vantage, cooperation-independence, not
    the identity of the enforcing substrate: a passive tap, an inline gate,
    and an adversarial corpus endpoint logging the connection it received
    all sit at this basis and differ only in enforcement role, which is
    `actualLayer`'s question.
-   `artifact`: at least one input the claim depends on derives from output
    the executed artifact itself produced (its stdout/stderr, exit status,
    or self-emitted logs).

An input is artifact-sourced when the claim relies on it as a channel
whose content the artifact can populate arbitrarily without performing
the claimed containment event: testimony about an event rather than the
event itself. An egress capture is not artifact-sourced even though the
packet bytes were artifact-authored, because the artifact cannot cause
the boundary to record an egress without performing one; its stdout is
artifact-sourced because the artifact can write anything there at no
cost.

<a id="req-fields-basis-vantage-claim-s-weakest"></a>

`basis` is the vantage of the claim's weakest input. A derived observation
inherits `artifact` from any artifact-sourced input it consumed: a state
diff computed by substrate machinery over the artifact's own logs is
`artifact`, however trusted the machinery, because the artifact could have
populated what the machinery read without performing any containment
event.

That composition is one instance of a principle this predicate follows
throughout: where a capture is ambiguous, the repair is additional captured
information and not better inference over what was already captured. Coverage
here is therefore a function of what was captured and armed rather than of what
can be reconstructed afterwards, which is why `basis` and `method` are taken
from the weakest input a claim rests on rather than from the strength of the
machinery that processed it.

A producer MUST NOT declare `basis: substrate` on a row it cannot cover
under the coverage validity requirements above: such a row is not merely
mislabeled, it makes the attestation invalid.

<a id="req-fields-method-states-how-row-s"></a>

`method` states how the row's claim was established, with a closed
two-value vocabulary:

-   `intercepted`: the claim rests on events captured as they occurred. On
    a clean row, a live capture vantage was armed for the attack and no
    capture was attributed to it.
-   `reconstructed`: the claim derives from state examined after the fact,
    e.g. a snapshot-to-snapshot diff. A reconstruction can miss a transient
    raised and undone between the states it compares; on a clean row that
    tolerance is part of the claim.

Like `basis`, `method` composes by weakest input: a claim inherits
`reconstructed` from any state-derived input it depends on. Post-hoc
decode of an event stream captured as it occurred (a packet capture
parsed later, a hardware trace decoded after the run) does not demote a
row, provided the capture channel was armed for the claimed event class
before the event; a row that fuses a live capture with after-the-fact
state examination is `reconstructed`.

`method` describes how the observation was made, not how the row was
attributed to its attack. The normative content of a `containmentObserved`
value is exhausted by its membership in the carried caught set: nothing
normative (neither the `result` recompute, the coverage validity gate,
the evidence tier, nor either strength ordering) reads anything else from
the label. An axis earns its own required member exactly when a normative
reader consumes it, which is why `basis` and `method` are members: the
recompute and the gate read them.

<a id="req-fields-attribution-axis-acquires-such-reader"></a>

`attribution` is the axis that acquires such a reader at this version. It
states how firmly the row is bound to the records that cover it, over a closed
two-value vocabulary:

-   `pinned`: the row rests on at least one interception whose committed value
    the corpus declared in advance, so a consumer holding the pinned corpus
    can check that the record this row cites is a record of this attack.
-   `paired`: the row rests on a correspondence established some other way,
    typically by the window in which the observation fell. The binding is a
    producer assertion.

Until 0.7 attribution strength was non-normative producer vocabulary, for a
stated reason: no normative reader consumed it. `expectedPayloads` makes it
checkable, so the member is born here rather than inherited, and the two
values are exactly the two readings that reason named, a hash-pinned payload
and a time-window pairing. Attribution _tolerance_ on clean rows, including
window bleed between same-layer siblings, is untouched by this and remains
non-normative producer vocabulary documented beside the observation
vocabulary's definition; a consumer MUST NOT move a `result` or an evidence
tier on it.

`pinned` is a claim about the binding and never about the observation. It does
not make the row's `method` stronger, does not raise its evidence tier, and
does not enter the `result` recompute except through the fail-closed arm every
required row member with a closed vocabulary shares. `paired` is a claim a
producer may always truthfully make, including where the corpus offers an
expectation, so it is a floor rather than a confession: what a consumer learns
from it is that this row does not carry the stronger binding, never that the
producer had one and withheld it.

`basis`, `method` and `attribution` are REQUIRED on every row and all three
vocabularies are closed: a
missing value, or any value outside them, is fail-closed exactly as an
out-of-vocabulary `containmentObserved` label is: the row forces
`result` to `fail` and can support nothing stronger. The 0.4 values
`substrate_observed`, `artifact_reported`, and `inferred` are
out-of-vocabulary in 0.5, with no alias, for the same
single-canonicalization reason the old `does_not_assert` spelling is
rejected. `inferred` has no successor value because it conflated the two
axes: a hypervisor snapshot diff and a diff parsed from the artifact's own
logs were both "derived indirectly" while carrying opposite vantages.
Under 0.5 the first is (`substrate`, `reconstructed`), the second is
(`artifact`, `reconstructed`), and no row can read as more independent
than its weakest input.

The two axes bind a consumer's confidence on opposite sides. A `fail`'s
supporting rows are the rows that force `result` to `fail`: rows whose
`containmentObserved` label is in the carried caught set, plus rows
fail-closed on a missing or out-of-vocabulary member. `basis` bounds a
`fail` over that supporting set: it answers whether the artifact could
have manufactured the observation. Only rows deriving `attested` occupy the
`substrate` rank: an `unattested` substrate row ranks, in both orderings,
exactly where an `artifact` row ranks. Ignoring a record, or failing to
verify one, can only weaken the claim, never strengthen it. A `fail` whose
supporting rows are all `artifact` SHOULD be treated as a weaker claim than
one whose supporting set carries a `substrate` row, and a consumer MAY
reject it; a `fail`
from a (`substrate`, `reconstructed`) row is still an observation the
artifact could not manufacture without performing a containment-relevant
event, weaker than an interception only in that it was derived after the
fact. A row fail-closed on `basis` or `method` sits at the bottom of both
orderings: its vantage is unknown, so it can strengthen nothing. `method`
bounds a `pass`: it answers whether a real event could have slipped past
the observation. A `pass` whose clean rows are all `attested` at
(`substrate`, `intercepted`), each covered by both the run's arming record
and a covering sealed record, the seal reporting under its own signature
that the vantage stayed armed to run-end, that the run-wide count of dropped
observations is zero or within a bound the same signed payload declares,
and that the posture it re-attests equals the pinned one, makes the
strongest absence claim this predicate can carry: a live vantage was armed
and stayed armed for this run and the committed record set attributes no
interception to this attack. It is not a claim that no interception
occurred; because the arming and sealed records are run-wide it is not a
claim that this row's specific channel was armed; and it is a claim about
the run this attestation carries, never about a run population. Nothing
in this predicate proves that other runs of the same configuration did not
occur or were not withheld, and run-population completeness (for example
via a run ledger or monotonic counter) is a consumer or policy concern.
The optional run-sequence members defined under `observationRecords` move
cherry-picking from invisible to gap-evident across whatever set a
producer does publish (a gap, a duplicated sequence number, a shared
predecessor, or a duplicated genesis is detectable by any consumer holding
both attestations), without changing this non-claim; their definition
states the ordering-only scope and the registration-receipt completion. A
result resting on any `reconstructed` clean row SHOULD be read as
tolerating transients between the observed states, and a result resting on
any `artifact` clean row is self-reported absence, the weakest; both of
those statements recompute to `pass_indirect` rather than to `pass`, so the
first two ranks of this ordering are the two ranks the result token already
separates from a live interception, and a consumer reading only the token
still cannot tell them apart from each other. A `pass` resting on an
`unattested` substrate clean row is self-reported absence too, and is the
one rank of this ordering the recompute cannot express, because whether a
covering signature verifies is key-relative and the recompute is not. The
clean-row ordering applies equally to the clean rows of a `degraded`
result's assessed classes, with `degraded` additionally bounded by its
disclosed coverage gap. A consumer MAY reject, never downgrade: an
attestation containing `unattested` substrate rows MAY be rejected
outright, and the signed bytes are never rewritten. Declining to credit a
rank is not a downgrade of signed bytes, exactly as declining to trust a
carried `result` is not. Both orderings are consumer guidance; the evidence
tier is an input to that guidance, not a verdict, and the predicate still
carries none.

A `basis: substrate` row's coverage is a validity requirement, not weak
evidence: a caught (`substrate`, `intercepted`) row with empty or
out-of-range `observationRefs`, or one whose referenced records do not
class-match, run-bind, cap `method`, or recompute `batchRoot`, makes the
attestation invalid (see Coverage validity). These are facts about carried
bytes alone; whether the referenced records verify, and against whose key,
is the evidence tier's separate question, because an answer that varied
with the consumer's trust anchors cannot live in a validity rule. A clean
row's `intercepted` still has no per-event record by definition: an armed
vantage that captured nothing produces no interception to sign. Its
covering instruments are the run-level `arming` record (a substrate-signed
statement that a live capture vantage was armed before corpus injection)
and the `sealed` record (a substrate-signed statement that the vantage
stayed armed to run-end with no dropped observation), which is the shape
absence evidence takes elsewhere: an attested launch measurement, a
hermetic-build flag, a monitor configuration attested as first-class
evidence. Where the producer emits a checkpoint chain, "armed before the
first observed event" is a chain-order fact (the arming record is the
chain head and each interception carries a higher sequence); where it does
not, `armedAt` ordering is producer-asserted and only the arming instant
is attested. One or more arming or sealed records MAY cover a run; each
referenced record must independently satisfy its class constraints.

<a id="req-fields-fields-divide-identity-whose-signature-3"></a>

<a id="req-fields-fields-divide-identity-whose-signature-2"></a>

<a id="req-fields-fields-divide-identity-whose-signature"></a>

Fields divide by the identity whose signature backs them.
Substrate-covered, through the coverage validity gate and evidence tier:
`basis` and `method` on rows deriving `attested`, and the content of every
verified observation record. Producer-asserted, backed only by the
enclosing envelope: `containmentObserved` labels and their attribution
nuance, `basis` and `method` on `artifact` rows, `actualLayer`,
`coverage`, `doesNotAssert`, and the assembly of the predicate itself.
Which keys count as substrate observation keys is consumer key policy,
resolved where signer identity is always resolved. The substrate
observation key MUST NOT be accessible to the subject artifact, and SHOULD
be held apart from the producer's assembly plane; a consumer's policy MAY
additionally require that the key signing any covering observation record
differ from the key signing the enclosing Statement. Two differing keys are
not two parties, and this document asserts no independence between them:
nothing here requires that the substrate observation key and the key signing
the enclosing Statement be controlled by different parties, and a statement
whose two keys are held by one party satisfies every requirement stated here.
A consumer's policy MAY require that they be controlled by different parties,
deriving control from the same key policy it resolves signer identity under and
never from a token the statement carries, since an independence token declared
inside the statement is redundant where it is honest and a lie surface where it
is not. The tier's value against a dishonest producer is exactly that
separation: where the
observation key is held apart from the assembly plane, the tier defeats a
pipeline with no substrate in the loop and cross-configuration splices,
because neither can be produced without a signature under the observation
key. It does not defeat method inflation, and it defeats a record drop only
where the run-end commitment reaches. Both limits are structural rather than
gaps in the checks above.
`batchRoot` recomputes over the carried records, so a party holding the
envelope key removes a record and recomputes a root that is self-consistent
over what remains; what refuses that party is `aeeObservedSet` on the seal,
which is signed by a party that does not control the carried set, and it
refuses only while the statement still has to carry the seal. The `method`
cap binds a row to the weakest `aeeMethod`
across the records that row references, and no per-event record names its
attack, since
a substrate signs at observation time and before attribution; the cap is
therefore per record and never per attack, so re-pointing a row's
`observationRefs` at an `intercepted` record signed for a different attack
raises that row's `method` with every substrate signature still verifying.
`attribution: pinned` narrows that re-pointing wherever the corpus declares
an expectation for the row's attack, because the borrowed record must then
also carry that attack's committed value, and narrows nothing where it does
not.
What holding the observation key apart defeats is the manufacture of
substrate evidence, not the assembly plane's selection and arrangement of
substrate evidence that genuinely exists. Where one party holds both keys
(the common single-root deployment), the tier instead defeats only a party
that holds neither key: the envelope signature closes the carried set to
such a party, and the run binding and the signed `aeeMethod` close record
substitution and forgery, so a tamperer with no key cannot splice, drop, or
inflate an already-signed set. A substrate operator who signs false
evidence, or who runs no substrate at all and signs an arming record anyway,
remains outside this predicate's threat model, as for every self-asserted
field. Coverage is therefore only as trustworthy as the named key's
un-compromised lifetime; the single trust root is a single point of total
failure, and a consumer's policy MAY bound a named key with a validity
window. Where it does, that window MUST be evaluated against a
substrate-signed instant, and the one this predicate mandates is the
`armedAt` carried inside an `arming` record whose signature verifies under
the key being bounded; it MUST NOT be evaluated against `issuedAt`.
`issuedAt` is producer-asserted, sits outside every substrate signature,
and is not among the run binding digest's inputs, so a party holding the
envelope key moves it at will, changing no digest and breaking no
signature. The only constraint this document places on it is that
`armedAt` is no later than `issuedAt`, which every instant at or after the
run satisfies, and `armedAt` itself precedes the compromise of any key that
signed that run. A window evaluated against `issuedAt` therefore
rehabilitates, by back-dating alone, every record the revoked key ever
signed. A statement carrying no `arming` record that verifies under the
bounded key carries no substrate-signed instant for that key, so a consumer
bounding a key's validity refuses that statement rather than falling back
to `issuedAt`. Consumers MAY additionally coherence-check row claims against
the pinned `observationEnvironment`: a `substrate` row claiming a
network-boundary observation under a `networkPosture` that provides no
interception path at that boundary is incoherent, and a consumer MAY
reject on that ground.

<a id="req-fields-actuallayer-names-enforcement-layer-acted-2"></a>

<a id="req-fields-actuallayer-names-enforcement-layer-acted"></a>

`actualLayer` names the enforcement layer that acted on the row's
containment event. It is required on every row; a row missing the member
is malformed under the framework's standard parsing rules and the
attestation is invalid, rather than the row forcing `fail`. That altitude
is deliberate and follows from the design invariant under Parsing Rules:
fail-closed-row semantics are reserved for members the recompute or the
documented consumer gating reads (`containmentObserved`, `basis`,
`method`); `actualLayer` is read by neither, so its absence is a
malformed statement, not weak evidence. On a row whose
`containmentObserved` label is from the carried
`observationVocabulary.labels` but not in the caught set (a clean row:
nothing acted), the producer MUST emit the literal string `none`. `none` is
explicit rather than the field being
omitted so that "no layer needed to act" is distinguishable from an
accidental omission. `none` is also valid on a caught row, and there
states that the containment event was observed but no enforcement layer
acted: the observing vantage was positioned to see, not to act (a passive
tap, a monitor-only deployment). This is deliberate: enforcement role
travels here and only here, so `basis` never has to encode who could act.
Whether anything was positioned to see is answered by `basis` and
`method`: a clean row carrying (`basis: substrate`, `method:
intercepted`) states a live substrate vantage was armed and no capture
was attributed, which is the strongest claim a `pass` can rest on, a claim
the run-level `arming` and `sealed` records under `observationRecords` now
carry under the substrate's own signature, bounded to the vantage's
existence and continuity rather than to the absence of any event; a
`reconstructed` clean row makes the bounded version of that claim
described under `method`.

`observationRecords` _array of objects, optional_

<a id="req-fields-dsse-envelope-per-observation-payload-2"></a>

<a id="req-fields-dsse-envelope-per-observation-payload"></a>

One DSSE envelope per observation: `payload` (base64 of the exact
canonical bytes the substrate signed at observation time), `payloadType`,
and `signatures`, which MUST carry at least one entry. A consumer verifies
each record's signature, DSSE PAE over `(payloadType, payload)`, before
relying on any field inside the payload. The order is deliberate and the
wording is exact: the byte-pure gates below do read payload fields without
verifying anything, because they are structural and a consumer must be able
to run them with no key material at all, and what they produce is not a
finding a consumer may act on until the covering signatures have verified.
Reading ahead of verification is a stage, never a conclusion. Any record used
to cover a `basis: substrate` row MUST carry a
JSON object payload that is canonical per RFC 8785 and valid I-JSON per
RFC 7493 (no duplicate members, integers within the safe range, member
names BMP-only per Prerequisites, every string a well-formed sequence of
Unicode scalar values per Prerequisites, and nesting within the bound stated
there), whose
media type ends in `+json`, and which carries these reserved members as
top-level fields; a record whose payload is not so parseable, or whose
media type is not `+json`, covers nothing:

<a id="req-fields-aeerunbinding-string-run-binding-digest"></a>

-   `aeeRunBinding` _string_: the run binding digest defined under
    Prerequisites.
-   `aeeKind` _string_: `interception` (per-event capture, covers caught
    rows; payload MUST carry `aeePayloadCommitment`); `arming` (run-level: a
    live, cooperation-independent capture
    vantage was armed for the run before corpus injection; payload MUST
    carry `armedAt` under the timestamp profile `issuedAt` defines, no
    later than `issuedAt`, `aeePostureDigest` equal to the pinned
    `networkPosture` digest, and `aeeAssessedAttacks`, and its
    `aeeMethod` MUST be `intercepted`);
    `sealed` (run-level: the vantage stayed armed to run-end; payload MUST
    carry `aeeStillArmed`, a boolean; `aeeDropCount`, an integer counting
    run-wide dropped observations; `aeePostureDigest`, the effective
    posture at run-end, equal to the pinned `networkPosture` digest;
    `aeeObservedSet`; and `aeeObservedAttacks`; it MAY
    carry `aeeDropBound`, a producer-declared integer bound; its `aeeMethod`
    MUST be `intercepted`);
    `examination` (the substrate examined artifact-independent state after
    the fact; its `aeeMethod` MUST be `reconstructed`, and its payload
    SHOULD identify the states compared); `moat-drop`; or
    `uncommitted-observation`. The last two cover nothing, carry no
    constraints of their own, and are defined below.
-   `aeeMethod` _string_: `intercepted` or `reconstructed`; how the
    substrate observed, stated inside the signature.

<a id="req-fields-record-violating-constraint-declared-aeekind"></a>

A record violating any constraint of its declared `aeeKind` (including a
missing `armedAt` on an `arming` record, an `armedAt` after `issuedAt`, an
`armedAt` outside the timestamp profile, or an `examination` record signed
`aeeMethod: intercepted`) covers nothing.

`aeeMethod` is determined by `aeeKind` on every run-level kind this document
registers. By the constraints stated above an `arming` record is `intercepted`,
a `sealed` record is `intercepted`, and an `examination` record is
`reconstructed`; only `interception` leaves the member free. The member
therefore carries an independent value on per-event records alone, and it is not
the axis on which the attribution shape behind a run-level claim could be read.
A value added to this vocabulary for the seal's benefit would be unreachable on
the seal, whose `aeeMethod` already has exactly one legal value. A closed name
vocabulary separates only the distinctions someone anticipated: whether a
correlator also captured namespace identity is not a distinction this document
anticipated, and not one it can enumerate.

A `sealed` record covers no clean row unless its `aeeStillArmed` is
`true`, its `aeeDropCount` is zero or does not exceed an `aeeDropBound`
declared in the same signed payload, and its `aeePostureDigest` equals
the pinned `networkPosture` digest and the `aeePostureDigest` of every
`arming` record the row resolves, each a check on signed carried bytes,
so failing it is a coverage validity failure, never a silent pass. The
quantifier is stated because a row may resolve more than one `arming`
record and the equality holds against each of them: a definite singular
reads as a promise that a statement carries exactly one, and this
document permits several. This sentence is stated over a row and its
set is the records that row resolves; which `arming` records supply the
set on a check that reads no row is not stated here and is not settled
by it.

`moat-drop` and `uncommitted-observation` are registered by this document and
neither covers anything. Both name records substrates were already signing
under this run binding with no spelling here to sign them under, and the
alternative to registering them is worse than the absence: stamped
`interception`, a record of either shape carries no `aeePayloadCommitment` and
is malformed, and a malformed interception is still a carried interception, so
a producer taking that route invalidates the whole statement rather than
merely overclaiming in one record. A kind that covers nothing is the honest
home for an observation no row may rest on.

<a id="req-fields-moat-drop-drop-containment-layer"></a>

`moat-drop` is a drop the containment layer performed and the substrate
observed from the enforcement path: a packet the kernel refused to forward,
seen where the refusal happened rather than on the wire.
`uncommitted-observation` is a run-bound observation the substrate signed
without committing to a payload -- a catch whose bytes were replaced before a
commitment could be taken over them, an introspection record attributing
activity to an artifact rather than to a message, a snapshot reporting what a
quarantine held.

<a id="req-fields-neither-kind-carries-constraints-because-2"></a>

<a id="req-fields-neither-kind-carries-constraints-because"></a>

Neither kind carries constraints, because there is no state in which either
covers anything and therefore none in which a constraint could change an
outcome. A verifier MUST verify their signatures as it verifies any record's
and MUST include their leaves in the `batchRoot` recompute, on the same terms
as every other carried record. It MUST NOT let either satisfy any row's
class-match requirement, MUST NOT admit either into the method cap, and MUST
NOT include either in the `aeeObservedSet` recompute, which is defined over
`interception` and `examination` records and is unchanged by this
registration. A row resolving one of these records and nothing else is
uncovered. A verifier SHOULD report that refusal under a condition naming the
kind rather than under its unrecognized-kind condition, because a citation of
a kind that covers nothing by registration and a citation of a kind the
verifier has never heard of are different producer errors with different
fixes; this document defines no condition vocabulary, so the distinction is a
diagnostic obligation and never a validity rule.

<a id="req-fields-what-neither-kind-used-claim"></a>

What neither kind may be used to claim is the half worth stating, because a
record that covers nothing can still be read by a party that wants it to mean
more than it does. A `moat-drop` record evidences that one path refused one
packet. It does not evidence containment: it says nothing about another path,
about a retry that succeeded, or about a payload that never reached the
enforcement point. It cannot make a caught row caught, since
`containmentObserved` is read only against the carried caught set and a caught
row still requires an `interception`, and it cannot make a clean row clean,
which still requires `arming` and `sealed`. It is also not the run's drop
counter, and the collision of the word is the reason to say so: `aeeDropCount`
counts observations the substrate FAILED TO RECORD, `moat-drop` records an
enforcement action the substrate DID record, and a producer incrementing the
one for the other emits a seal that is wrong in the direction the seal exists
to catch.

An `uncommitted-observation` record evidences that the substrate saw something
it declined, or was unable, to commit to. It cannot stand in for an
`interception` anywhere: not for a caught row's coverage, not for the
existence requirement a row declaring `attribution: pinned` must satisfy, and
not for the `expectedPayloads` comparison, which is left with no carried value
to compare. It does not raise a row's `method` to `intercepted` and does not
make a row's `attribution` pinnable. A producer MUST NOT put
`aeePayloadCommitment` on one: a substrate holding a commitment emits an
`interception`, and a record declaring it holds none while carrying one says
two things. That obligation is stated and not gated, on the same terms as the
shared-reference evidencing obligation: no validity requirement, recompute
input or tier evaluation reads a member of a record that covers nothing, so a
verifier enforcing it would be inventing a consequence this document does not
define.

<a id="req-fields-both-registrations-verdict-preserving-what"></a>

Both registrations are verdict-preserving, which is what makes them additions
a minor revision may make. A verifier that does not implement them treats each
as an unrecognized kind, which covers nothing and is otherwise ignored, and
reaches the same validity answer over the same bytes; the difference is
confined to what the two verifiers call the refusal. Neither name may later
acquire covering semantics, which is the other thing registration buys: an
unregistered name stays available to a future minor version, and these two are
now spent.

Four reserved members carry the commitments this version adds. Each is
required on exactly one kind, each is a value the substrate holds at the
moment it signs that kind, and a record missing or malforming the member its
kind requires covers nothing, on the same terms as a missing `armedAt`.

`aeePayloadCommitment` _array of strings_, required on an `interception`
record: the commitment values this interception carries, duplicate-free,
sorted ascending by UTF-16 code unit (RFC 8785 Section 3.2.3, the
canonicality rule the vocabulary arrays already carry), non-empty, every
entry lowercase 64-hex. The member names what an `interception` record has
always carried and had no reserved spelling for. What a commitment is taken
over is the substrate's choice and this document does not constrain it,
because the choice is what keeps an attestation publishable rather than a
store of the traffic it observed; what a corpus can declare in advance is
bounded by that same choice, which is the subject of `expectedPayloads`. It
is an array rather than a single value because one record may be resolved by
more than one row and may commit to more than one observed value.

`aeeAssessedAttacks` _array of strings_, required on an `arming` record: the
attack identifiers this run declared, before corpus injection, that it would
assess. Duplicate-free, sorted ascending by UTF-16 code unit, every entry an
attack identifier the carried `corpus.manifest.classes` declares; a record
violating any of these covers nothing. The union of the manifest's
identifiers for the carried `coverage.assessedClasses` MUST be a subset of
this array, and a statement violating that is invalid.

<a id="req-fields-comparison-subset-rather-than-equality"></a>

The comparison is a subset rather than an equality, and the choice is
load-bearing in both directions. A subset refuses the claim to have assessed
more than was declared before any outcome was known, which is the whole of
what a run-start commitment can bind. An equality would additionally refuse
the honest run that declared two classes, lost one part-way, and disclosed the
loss, which is the shape the coverage maps exist to reward; and it would buy,
against the withdrawal it appears to catch, only the version of that
withdrawal that leaves the arming record in place, since a producer with no
`basis: substrate` row left may drop the record and the commitment with it.
A rule that costs an honest producer a legitimate shape in exchange for
catching the incomplete form of an attack is not a bargain.

The array is carried inside the signature rather than as a digest over a
pre-image on the statement's own JSON surface, which is the shape `corpus`
and `observationVocabulary` take. The two cases differ in who authors the
value. Those pre-images are producer material a verifier must read, so the
surface is the right home and the digest is the binding. This value is the
substrate's own assertion about a moment the assembly plane cannot revisit,
and splitting it would let the party under scrutiny author the array the
substrate is committing to. Carrying identifiers rather than a digest also
admits no value the substrate was not already committing to, since every
admissible entry appears in the carried manifest and the manifest's digest is
already a run binding input inside the same signature.

`aeeObservedSet` _string_, required on a `sealed` record: the lowercase
64-hex SHA-256 of the RFC 8785 canonicalization of the duplicate-free array,
sorted ascending by UTF-16 code unit, of the lowercase 64-hex leaf hashes of
every `interception` and `examination` record the substrate emitted for this
run, where a leaf hash is `H(0x00 || the record's DSSE PAE bytes)`, the same
leaf construction `batchRoot` uses. A verifier recomputes the same value over
the carried records of those two kinds and requires equality; a `sealed`
record whose `aeeObservedSet` does not equal that recompute covers nothing,
and because a `sealed` record is required on every statement carrying a
`basis: substrate` row, such a statement is invalid.

The seal is the only substrate signature made after the run is over, and
until this member it carried three facts about the vantage and none about the
observations. What the member adds is a commitment, by a party that does not
control the carried set, to the set that was emitted. A dropped record removes
a leaf and the values diverge. A record fabricated to keep a count intact
cannot be signed without the substrate key, a record borrowed from another run
fails the run binding comparison, and a record duplicated to the same end is
already invalid, because two byte-identical entries in `observationRecords`
make the attestation invalid. It commits to nothing the substrate would have
to interpret: no attack identifier, no outcome, no label, only a hash over
bytes the substrate itself produced.

Two producer obligations travel with it and neither is checkable by a
verifier. The seal is signed after every record it commits to, so a substrate
that examines state after run end seals after that examination rather than
before it; a seal that predates a record the statement carries is a seal its
own record set contradicts, and the statement is invalid on the recompute
without the verifier ever learning why. And every site at which the substrate
drops an observation rather than emitting it MUST increment `aeeDropCount`.
The two members are siblings: one commits to what the substrate recorded and
the other to what it failed to record, and a substrate that silently discards
an observation without counting it emits a wire claim that is wrong while
looking right, since the seal then commits to a set that is complete by its
own account and short by the run's.

`aeeObservedAttacks` _array of strings_, required on a `sealed` record: the
attack identifiers to which this run attributed at least one of its own
observations. Duplicate-free, sorted ascending by UTF-16 code unit, every
entry an attack identifier the carried `corpus.manifest.classes` declares; a
record violating any of these covers nothing. For every identifier in the
array the statement MUST carry an `attackResults` row with that `attackId`
whose `containmentObserved` is in the carried caught set, and a statement
violating that is invalid.

The array is a lower bound and the rule reads in one direction only. A seal
naming an attack obliges a caught row for that attack; a seal omitting one
licenses nothing, and in particular does not oblige a clean row. That is what
makes the member sound without requiring the substrate to resolve every
ambiguous case: an observation it could not attribute is left out, which
subtracts from what the seal claims and can never add a claim that is false.

Over-inclusion is the direction that would be unsound. A substrate attributing
by disjoint dispatch windows cannot produce it, and that is the argument this
member was written against, but nothing above requires that attribution shape:
a substrate correlating by connection five-tuple, or by a heuristic over payload
shape, satisfies every syntactic requirement here while the argument stops
applying to it. Over-attribution is caught downstream at the row, by the rule
under `attackResults` that a producer MUST NOT reference a record from a row
whose attack the record's committed payload does not evidence, checkable on a
row declaring `attribution: pinned` and an obligation outside every gate on one
declaring `paired`. That pointer is stated here, rather than left to be met
several hundred lines later, because a reader who meets this member first will
otherwise reach the end of it believing the seal alone carries the guarantee.

It does not, and the residue is worth naming. That producer obligation binds the
producer, while the seal is signed by the substrate, so a consumer holding a
non-empty `aeeObservedAttacks` cannot read the attribution shape off the seal
before it has already decided whether to demand `pinned`. A token declared by
the substrate inside the sealed payload, beside `aeeMethod`, would move that
statement to the party that made the observation, which a producer-declared
token cannot do: the producer sits on the far side of the signature and would be
reporting a belief about a substrate it cannot inspect. Moving a declaration is
not the same as checking one. The name and the material it would name are
emitted by one signer under one signature, so a consumer recomputing the one
from the other compares a declaration with a declaration by that declarer, and a
substrate whose declarations agree with each other satisfies the comparison.

The only shape that escapes carries enough pre-correlation observation for the
consumer to perform the grouping itself, so that the substrate's correlation is
not relied on rather than being described. This document instantiates that shape
at the row and not at the seal. A row declaring `attribution: pinned` groups
against commitment values the corpus declared in advance in
`corpus.manifest.expectedPayloads`, which sit inside the manifest pre-image
`corpus.digest` is taken over and which a consumer pins out of band, and the
comparison is performed by the consumer against the `aeePayloadCommitment` of
every `interception` record the row resolves. `aeeObservedAttacks` is a lower
bound over attack identifiers and has no such third-party-declared key material
to group against. No shape token is defined in this version, because one would
not close this.

_Note (informative)._ The five-tuple case named above is constructible rather
than hypothetical. CLARION (Xutong Chen, Hassaan Irshad, Yan Chen, Ashish
Gehani and Vinod Yegneswaran, "CLARION: Sound and Clear Provenance Tracking for
Microservice Deployments", 30th USENIX Security Symposium, 2021) constructs it
in Section 3.1.3: two processes listening on the same virtualized local address
and port in separate containers, one of them accepting a connection from a
single remote address and port, cannot be told apart without network-namespace
awareness. That establishes constructibility in one common environment and not a
base rate, and this predicate does not target namespaced deployments. The repair
taken there is additional captured information, a host-container mapping, and
not better inference over the same capture.

The empty array is the honest value, and it is required rather than
omissible. A substrate that does not dispatch the corpus holds no
correspondence to sign and says so by carrying nothing in the array; a
substrate that dispatched the corpus and attributed no observation says the
same thing and means something different. Allowing the member to be absent
instead would make the whole control escapable by omission, which is the
defect the mandatory `sealed` record above exists to close and would be
reintroduced one level down.

<a id="req-fields-arming-record-s-payload-additionally-2"></a>

<a id="req-fields-arming-record-s-payload-additionally"></a>

An `arming` record's payload MAY additionally carry three reserved members
that chain runs under the same substrate key: `aeeRunSeq` (a positive
safe-range integer), `aeePrevRunBinding` (the lowercase 64-hex run binding
digest of the predecessor run, absent exactly when `aeeRunSeq` is `1`),
and `aeeChainScope` (the population the sequence counts, declared as a
duplicate-free array of dimension tokens drawn from the closed vocabulary
registered below, sorted in the same canonical order as
`observationVocabulary.labels` (UTF-16 code-unit order, RFC 8785 section
3.2.3); REQUIRED whenever `aeeRunSeq` is present). The chain is always
structurally under one substrate key; each token names a further within-key
partition attribute already carried elsewhere in the attestation and fixes
where a consumer reads that attribute's value. The declared array is the
_dimension set_; the _evaluated tuple_ is the projection of the
substrate-key value and each declared token onto its registered attribute
value for this run (computed, never carried). The recommended minimum is
`["subject"]`; the empty array is the single global per-key counter that
makes every chain rule below vacuous and leaks the producer's total run
volume across its customers.

The `aeeChainScope` vocabulary is closed and each token pins a projection
to a value already carried on the wire: `subject` to
`subject[0].digest.sha256`, `corpus` to `observationEnvironment.corpus.digest`,
and `networkPosture` to `networkPosture.digest.sha256`. The substrate key is
the structural outer axis and is never a token. Values are not carried in
the member; a consumer projects each declared token onto its registered
field for this run. Minor versions MAY append tokens (each with a pinned
projection) and MUST NOT redefine an existing one; an unrecognized token
fails closed, as every closed vocabulary in this spec does.

<a id="req-fields-within-attestation-these-members-syntax"></a>

Within one attestation these members are syntax-checked in the
reserved-member walk and nothing else normative reads them: the coverage
validity requirements, the `result` recompute, and the evidence tier are
unchanged. A violation of the syntax rules (a non-positive or non-integer
`aeeRunSeq`, a malformed `aeePrevRunBinding`, a missing `aeeChainScope`
when the sequence is present, a non-array `aeeChainScope`, an array carrying
a token outside the registered vocabulary, an array not in canonical order
(the same canonicality rule as `observationVocabulary.labels`: UTF-16
code-unit order, duplicate-free), or any of the three present without
`aeeRunSeq`) is handled as any reserved-member violation: the record
covers nothing. Their value is across attestations, as consumer policy over
whatever set a producer publishes. A consumer compares each attestation's
declared dimension set against the set its policy demands: an equal set is
admissible; a strictly finer set (a superset of dimensions) is
scope-narrowing, fragmenting every run into a singleton chain so no gap,
fork, or duplicate genesis can arise and the chain proves nothing; a
strictly coarser set (a subset of dimensions) pools distinct subjects, so a
withheld run of the demanded subject is deniable as a sibling's private run
and a sibling's run can occupy the withheld sequence position. A consumer
that has demanded a scope admits only the equal set, neither finer nor
coarser. Among admitted attestations the rules key on the evaluated tuple,
not the token set: a skipped `aeeRunSeq` under one tuple is a gap; two
attestations carrying the same `aeeRunSeq` under one tuple are a fork; two
carrying the same `aeePrevRunBinding` share a predecessor; and two genesis
records (absent `aeePrevRunBinding`) under one tuple are equivocation of the
same grade as a shared predecessor. Keying on the tuple is load-bearing:
genesis-per-subject-value is the normal case, and only a second genesis
under an identical tuple is a reset. A chain reset is not a fresh start. The
members claim ordering under the substrate key, nothing more: nothing on the
wire anchors when an arming record was signed relative to the run's outcome,
so commit-before-outcome holds only in combination with the publicly datable
run-entropy floor under Prerequisites or an external registration receipt. A
numeric gap is unexplained absence (crashed, private, and discarded runs all
produce gaps innocently), never fraud evidence in itself. Even a contiguous,
fork-free, correctly-scoped chain does not prove population completeness: a
producer may still mint a dense, gap-free set of passing runs after the
fact. Fork consistency among the published set is the ceiling of what any
self-contained attestation set can establish; the demand-disclosure yield is
that a consumer policy MAY require a contiguous, fork-free chain over the
runs offered to it. The external completion is a registration receipt:
committing each arming record to an append-only transparency log at run
start (for example SCITT, RFC 9943, with COSE receipts, RFC 9942) upgrades
gap-evidence to third-party-auditable non-omission, and that machinery is
deliberately outside this predicate. These members are semantic
(armed, stayed armed, nothing dropped, posture unchanged) rather than
mechanism-specific: how a substrate establishes them (a checkpoint chain,
a sequence counter, a hardware watchdog) stays producer territory. A
record whose `aeeKind` the consumer does not recognize covers nothing and
is otherwise ignored, while still contributing its leaf to `batchRoot`;
minor versions MAY add kinds and MUST NOT change the covering semantics of
an existing kind. An unrecognized kind can only weaken, never
strengthen, a row (candidate future kinds, informatively: a hardware-quote
kind binding the vantage to a measured platform, and a `registration` kind
carrying a transparency-service receipt over the arming record). The `aee` member prefix is reserved for future versions
(`aeeVersion` is reserved for a payload contract version); everything else
in the payload stays producer territory. No member of that territory is
read by a conforming verifier: a producer-defined member MUST NOT affect
structural validity, MUST NOT affect `result`, and MUST NOT affect the
evidence tier, whether or not its values can be ordered. One case is
worth naming on its own, because it is the one a verifier is tempted to
read. A producer that defines an ordered axis there, meaning any member
whose values a reader might rank, is defining producer vocabulary rather
than a strength axis of this predicate: a verifier MUST NOT rank its
values and MUST NOT compose it by weakest input across records or rows.
The three axes this predicate does define, `basis`, `method` and
`attribution`, are defined because a normative reader consumes them, and a
producer-defined axis acquires no such reader by being spelled in the same
payload. The rules
are stated here rather than at each future member so that an implementer
meets them before the member exists.

<a id="req-fields-precedent-informative-reserved-members-inside"></a>

_Precedent (informative)._ Reserved members inside a producer-defined
signed payload follow an established lineage rather than a novel
mechanism: an RFC 7519 JWT claims set is a producer-defined object from
which verifiers read registered claim names (`exp`, `aud`, `iss`), with
collision resistance by registration and prefixing; EAT (RFC 9711) applies
the same registered-claims pattern inside an attestation token, in the
RATS family; OCI image annotations reserve the `org.opencontainers.*`
prefix inside an otherwise free-form map; and the `+json` requirement is
RFC 6839 Section 3.1's structured-syntax license to parse a media type not
otherwise known. None of the cited standards' semantics apply here by
reference; the citations locate the pattern, not the rules. Two deliberate
departures from that lineage: where RFC 7519 tells consumers to ignore
unrecognized claims, this predicate is fail-closed (a colliding or
unrecognized `aee*` member can only weaken coverage, the record covering
nothing, never create it), and the verify-then-read discipline is
normative here (a payload's fields mean nothing until its signature
verifies), which closes the parse-before-verify class of deployment
mistake the JWT lineage is known for. No per-event record is required to
name its attack, and none may be: a substrate signs an `interception` or an
`examination` at observation time, before attribution, so a record naming an
attack would be signing the runner's account of what it was doing rather than
its own account of what it saw. The run-level `sealed` record names attacks
because it is signed at run end, by which time the substrate that dispatched
the corpus holds the correspondence between its own probes and its own
records; that is its assertion and not the runner's, and it is why the
attack-naming member sits on that kind alone. `aeePayloadCommitment` keeps
the same discipline on the per-event side: an `interception` record carries a
commitment to an intercepted payload rather than the payload itself, which
keeps the attestation publishable rather than a sensitive-data store, and the
comparison that turns the commitment into an attribution happens in the
verifier, against a corpus pinned out of band, rather than in the substrate.

`batchRoot` _string, required when `observationRecords` is non-empty_

An RFC 6962 Merkle root over the observation records, SHA-256, with
domain-separated hashing: each leaf is `H(0x00 || the record's DSSE PAE
bytes)`, each internal node is `H(0x01 || left || right)`, the tree built
by the RFC 6962 recursive split (never by duplicating a trailing node to
pad the leaf count), leaves in `observationRecords` array order, a
single-record tree's root its leaf hash, and an empty array with no root.
Two byte-identical entries in `observationRecords` make the attestation
invalid: a record's canonical identity is its leaf hash, a positional
reference is shorthand for the leaf hash at that position, and a future
minor version may admit detached records addressed by leaf hash with
`batchRoot` unchanged. Carried once at the predicate level. A `batchRoot`
that does not recompute over the carried records makes the attestation
invalid. Because every `basis: substrate` row requires covering records
under Coverage validity, any valid attestation carrying a substrate row
carries a `batchRoot`, and every such attestation's committed set includes a
`sealed` record, which is now required whether or not a row resolves an index
to it. The root commits to the set the statement
carries and not to the set the run produced: it is recomputed from the
carried records, so a party who can re-sign the enclosing envelope drops a
record, recomputes over what remains, and emits a statement whose root is
self-consistent. What `batchRoot` detects is alteration of the carried set
by a party who cannot re-sign the envelope, and what it establishes for
every other party is the internal consistency of that set, never its
completeness against the run. `batchRoot` is omitted only when
`observationRecords` is absent, in which case every `basis: substrate` row
fails Coverage validity, so a valid recordless attestation carries only
`basis: artifact` rows.

`doesNotAssert` _array of strings, optional_

Explicit negative scope: statements the producer declares this evidence makes
no claim about (e.g. behavior outside the thrown corpus, host integrity
beyond the substrate's own attestation). Advisory: a verifier MUST NOT
require it, and nothing in it weakens the required checks. `doesNotAssert`
is the single canonical spelling: earlier internal versions used a
snake_case spelling (see the changelog), which is not accepted as an alias,
since two accepted spellings would mean two canonicalizations for the same
content. Migrating old producer output to the new name is a producer
concern that the wire format does not carry.

`issuedAt` _Timestamp, required_

When the producer signed the evidence bundle. `Timestamp` is the framework's
field type, which requires RFC 3339 in the UTC timezone, and this document
pins the two choices that type leaves open. A statement is canonicalized
and digested as its bytes, so no verifier may normalize the field before
reading it and the admissible set has to be written down; left open, one
implementation is quietly stricter than another and the divergence surfaces
only when a statement crosses between them. The date-time separator and the
zone designator MUST be uppercase, never the lowercase `t` and `z` that
RFC 3339 also admits, and the zone designator MUST be `Z`, `+00:00` or
`-00:00`, never a non-zero offset such as `+05:00`. `-00:00` is admitted
rather than excluded because RFC 3339 Section 4.3 gives it the meaning that
the instant in UTC is known while the offset to local time is not, which
describes where the producer stood and not when it signed, and the instant
is the only thing this document reads from the field. A statement whose
`issuedAt` is absent, is not RFC 3339, or is RFC 3339 outside this profile
is malformed. `armedAt` carries the same profile, defined here and cited
from the arming record so that the two fields cannot drift apart.

[DSSE]: https://github.com/secure-systems-lab/dsse
[ResourceDescriptor]: https://github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md
[Runtime Traces]: https://github.com/in-toto/attestation/blob/main/spec/predicates/runtime-trace.md
[SCAI]: https://github.com/in-toto/attestation/blob/main/spec/predicates/scai.md
[SVR]: https://github.com/in-toto/attestation/blob/main/spec/predicates/svr.md
[Test Result]: https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md
[VSA]: https://github.com/in-toto/attestation/blob/main/spec/predicates/vsa.md
