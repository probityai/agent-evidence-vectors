<!-- Long-form companion to the Adversarial Execution Evidence predicate. -->

# Adversarial Execution Evidence: encoding profile and run binding

Long-form companion to the registry page for predicate type
`https://in-toto.io/attestation/adversarial-execution-evidence/v0.7`.

The text below is verbatim from the single-document revision of the
specification (source SHA-256 `2b7f3bc08123cbe1981d287cf20193858ae5ea6d55ca067e06363a1e71a573d7`, lines 94-293 of
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

## Prerequisites

<a id="req-wireprofile-toto-attestation-framework-plus-understanding"></a>

The in-toto Attestation Framework, plus an understanding of
[DSSE](https://github.com/secure-systems-lab/dsse) (each observation record is
a DSSE-shaped envelope) and [RFC 8785 (JCS)](https://www.rfc-editor.org/rfc/rfc8785)
canonical JSON, which the digest bindings are defined over. Producers MUST
enforce the RFC 7493 (I-JSON) safe-integer profile on canonicalized content:
integers with magnitude at or above 2^53 MUST be rejected, so every rail
(producer and verifier, in any language) derives identical bytes.

The whole statement JSON is parsed as strict I-JSON: a duplicate member
anywhere in the statement, at any depth and not only inside a covering record
payload, makes the statement malformed. A lenient parser that silently keeps
the last of a repeated member would let two rails disagree on identical bytes,
so a verifier MUST reject a duplicate member statement-wide, fail-closed.

Strict I-JSON also constrains the bytes of every string, and for the same
reason. A verifier MUST reject, statement-wide and fail-closed, any statement
in which a string literal is not a well-formed sequence of Unicode scalar
values. That means: the statement MUST be valid UTF-8, with no overlong form
and no surrogate encoded directly in UTF-8 (CESU-8); a `\u` escape naming a
high surrogate MUST be immediately followed by a `\u` escape naming a low
surrogate, and an unpaired surrogate escape of either half is malformed; and a
string MUST NOT contain a raw unescaped character below U+0020. A `\u` escape
MUST consist of exactly four hexadecimal digits, with no sign, no whitespace
and no radix prefix, so that a reader built on a permissive integer parser does
not accept `\u+041` where a strict one rejects it. The profile also excludes the
Unicode noncharacters -- the code points U+FDD0 through U+FDEF, and U+nFFFE and
U+nFFFF in every plane -- which RFC 7493 section 2.1 forbids in the same sentence
as surrogates. A noncharacter is a valid scalar value that nothing substitutes
for, so unlike an ill-formed sequence it is not a cross-rail decoding split; it
is excluded so that a verifier implementing the RFC 7493 label does not reject a
record another verifier accepts, and it is rejected wherever a string literal
appears, at any depth and in both member-name and value position.

This rule exists because a lenient decoder does not fail on ill-formed bytes,
it substitutes U+FFFD for them, and every check downstream of the decode then
reads a string the producer never wrote. Where a digest is recomputed from
decoded strings rather than compared against carried bytes -- which is how the
`observationVocabulary` digest is defined below -- a producer could otherwise
emit ill-formed bytes, derive the digest over the substituted form, and obtain
a statement that one conforming verifier calls valid and another calls
malformed. A verifier MUST therefore apply this check to the raw bytes, before
any decoded string is read.

A verifier MUST reject, fail-closed, a statement whose JSON nesting depth
exceeds 128. Nesting depth is the number of arrays and objects that are open
at a given point, counting the outermost `{` of the statement as depth 1;
scalar values do not increase it. The bound is normative because it is not a
resource limit alone: with no bound stated, implementations pick their own, and
two conforming verifiers then disagree about whether identical bytes are
evidence at all over the entire range between their choices. The counting rule
is stated because implementations that increment per parsed value rather than
per open container arrive one level apart from an identical constant. Record
payloads are parsed under the same bound.

The identical-bytes requirement has a string half. On every signed canonical
surface (object member names in covering record payloads and the
`observationVocabulary.labels`/`caught` arrays), strings MUST be BMP-only:
no code point above U+FFFF, no surrogate pair. RFC 8785 sorts object members
by UTF-16 code unit; a verifier that instead compares Unicode code points
orders a supplementary-plane name differently from one in U+E000 through
U+FFFF, so two otherwise-conforming verifiers could disagree on whether
identical bytes are canonical, which under the coverage validity gate is
attestation-valid versus attestation-invalid on the same bytes. Restricting
the sorted strings to the BMP makes UTF-16 code-unit order and code-point
order coincide, so that divergence is unconstructible. A verifier MUST treat
a violation exactly as it treats non-canonical bytes: a supplementary-plane
member name makes the covering payload cover nothing, and a
supplementary-plane vocabulary entry makes the statement malformed.

These bounds close the divergences the text can foresee: a stated depth, a fixed
sort order, a pinned encoding. They do not close the ones it cannot. Where the
text underdetermines a reading and no conformance vector exercises it, two
implementations agreeing on that reading is evidence the text is determinate, not
proof of it -- the reading is untested rather than confirmed, and a third
implementation could differ there in silence. Conformance is established by
vectors; an agreement no vector has exercised is a candidate for the next vector,
not a settled rule.

<a id="req-wireprofile-run-binding-statement-carrying-least"></a>

**Run binding.** For any statement carrying at least one `basis: substrate`
row, the run binding digest is the lowercase 64-hex SHA-256 of the RFC 8785
canonicalization of the object `{"aeeBindingVersion": "2", "catchPolicy":
"<catchPolicy.digest.sha256>", "corpus": "<corpus.digest.sha256>",
"networkPosture": "<the lowercase 64-hex SHA-256 of the RFC 8785
canonicalization of the carried networkPosture object>",
"observationVocabulary": "<observationVocabulary.digest.sha256>",
"runEntropy": "<runEntropy.digest.sha256>", "subject":
"<subject[0].digest.sha256>", "substrate": "<substrate.digest.sha256>"}`.
Every input is a property of the run's configuration and is fixed before
corpus injection. That is not incidental and it is the test any proposed
input must pass: the arming record carries this digest inside its own
signature and is signed before injection, so a value the producer could not
know at that moment would make the arming record unsignable, and an outcome
of the run can therefore never be an input here. `runEntropy` is a run-start
value the substrate emits and commits inside the arming record's signature;
its pre-image is the substrate's run-start checkpoint, so two executions
sharing every other input still derive distinct bindings. The pre-image
SHOULD additionally fold in a publicly datable value that was unpredictable
before its round (a drand round output, or an epoch identifier in the
RFC 9334 Section 10.3 sense), in addition to, never in place of, the
substrate-unique run-start component, with the round reference recoverable
by the consumer (carrying it in the arming payload as producer vocabulary
suffices, since the digest binds it). A signature over a value that did not
exist before its round cannot predate the round, so the arming record gains
a proven earliest-possible signing time, a floor. `issuedAt` remains the
asserted ceiling; the pair is deliberately not a two-sided proof, by the
asserted-versus-attested rule this predicate applies everywhere. The floor
bounds recency only where consumer policy couples the folded round to its
freshness window (the producer selects the round, so an uncoupled round
proves age, never freshness), and a beacon inside the producer's own trust
domain yields no floor against that producer. The value is fetched at
arming time, never cached: a stale round silently folded as current would
defeat the same coupling. Public rounds also make two consumers'
`runEntropy`-reuse observations comparable against a shared public time
axis rather than against the producer's clock.
For this predicate `subject` MUST contain exactly one entry on a statement
of any basis; a statement carrying zero or more than one subject is
malformed, regardless of whether any row is `basis: substrate`. Separately,
`catchPolicy`, `corpus`, `runEntropy`, `substrate` and `subject[0]` MUST each
carry a `sha256` digest whose value is already lowercase 64-hex, and so MUST
`networkPosture`, whose pinned digest this construction no longer reads
verbatim but which is still compared byte for byte against the
`aeePostureDigest` a record carries; a substrate-row-carrying statement
violating this digest requirement is malformed. The
`observationVocabulary` digest carries no rule of its own here, because the
digest-integrity step recomputes it from the arrays beside it and a value
that is not lowercase 64-hex cannot equal that recompute; restating the
requirement would add a check that could never be the one to fail. Values
are taken verbatim (no case-folding, no
null fill). A statement whose rows are all `basis: artifact` derives no
binding and need not carry `runEntropy`. A verifier derives the digest from
the statement alone; no field carries it. Every substrate-signed
observation record commits to the run by carrying this digest inside its
signed payload (see the reserved members under `observationRecords`). The
binding is anti-splice: a record signed under a different subject, corpus,
catch policy, network posture, observation vocabulary, substrate, or
run-start entropy value cannot
be spliced in. It is not anti-forge and not a freshness challenge: it
carries no verifier nonce, and identical-configuration re-runs are
distinguished only by the substrate-emitted `runEntropy` value, so a
consumer that must exclude replay of a genuine record into a later
identical-configuration run does so by rejecting reuse of a `runEntropy`
value it has already seen. `aeeBindingVersion` names this construction;
a future version that changes the construction (another hash algorithm,
additional inputs, multiple subjects or substrates) names a new binding
version, and a verifier MUST reject, fail-closed, a binding version it does
not implement rather than attempt more than one construction. An arming
record's payload MAY carry an explicit `aeeBindingVersion` member declaring
its construction; a verifier reads it before deriving and rejects it
fail-closed (the arming record covers nothing) when the value is a version it
does not implement, distinguishably from a run-binding digest mismatch. An
absent member defaults to the version this document defines; the carried
value never drives the
derivation (a verifier derives only under the version it implements, so a
record declaring the implemented version but constructed otherwise still
fails on the digest). Defaulting the absent member to the implemented
version rather than to any fixed number is what keeps the member optional:
a default pinned to a superseded version would reject every statement that
simply declines to carry it. A future
minor version admitting multiple subjects or multiple substrates binds all
of them in canonical name-then-digest order.

Two inputs distinguish version 2 from version 1, both of them configuration
the statement already carries, so neither costs a byte on the wire and
neither needs a new comparison: each closes through the equality every
record's `aeeRunBinding` is already put to.

Version 1's `networkPosture` input was the value of that member's own
`digest.sha256`. That left the `posture` string beside it outside every
signature. The posture configuration this predicate digests is not carried
anywhere in the statement, so nothing can check the string against the
digest, and a party holding only the envelope key could replace one posture
value with another, change no digest, and break no signature. Version 2
takes the canonical digest of the carried `networkPosture` object instead,
so the string, its pinned digest, and any further member a producer carries
there all sit inside the binding. The object the binding covers is the
carried one: a producer that adds, removes or edits a `networkPosture`
member after the arming record is signed derives a binding its own records
do not carry, and its statement is invalid on that ground.

`observationVocabulary` was not an input at all. Its `caught` array decides
which labels are caught, and the coverage validity requirements and the
`result` recompute both read it, so a producer that narrows the caught set
after the run turns a caught row into a clean one. Nothing resisted that:
the vocabulary's own digest is verified only against the arrays beside it,
so it re-derives for free, and no record's binding moved. Binding the
carried digest closes it, since a narrowed vocabulary derives a different
run binding and every record then fails the comparison.

Version 2 is unchanged in 0.7 and no version 3 is defined. Every commitment
0.7 adds travels either on a record payload, where a substrate signature
already covers it, or inside the corpus manifest, whose digest is already an
input here. The manifest gaining `expectedPayloads` therefore changes the
value of the `corpus` input on every statement carrying one and changes
nothing about how that input is built, so a producer editing
`expectedPayloads` after the arming record is signed derives a binding its
own records do not carry, by the same mechanism that already covers the class
map beside it.

[DSSE]: https://github.com/secure-systems-lab/dsse
[ResourceDescriptor]: https://github.com/in-toto/attestation/blob/main/spec/v1/resource_descriptor.md
[Runtime Traces]: https://github.com/in-toto/attestation/blob/main/spec/predicates/runtime-trace.md
[SCAI]: https://github.com/in-toto/attestation/blob/main/spec/predicates/scai.md
[SVR]: https://github.com/in-toto/attestation/blob/main/spec/predicates/svr.md
[Test Result]: https://github.com/in-toto/attestation/blob/main/spec/predicates/test-result.md
[VSA]: https://github.com/in-toto/attestation/blob/main/spec/predicates/vsa.md
