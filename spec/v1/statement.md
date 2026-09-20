# Statement-layer conformance profile

This file is NOT a vendored copy and NOT a competing source of truth for the
in-toto Statement. The Statement is specified by the in-toto Attestation
Framework; this file records the statement-layer rules **this corpus tests**,
for the cases where the framework's own text leaves a rail free to choose and
two rails then choose differently. Every rule below cites the framework text it
resolves, and a rule with no citation does not belong here.

A predicate-level rule belongs in that predicate's specification, not here. The
Adversarial Execution Evidence predicate is vendored at
[`../predicates/adversarial-execution-evidence.md`](../predicates/adversarial-execution-evidence.md)
and is byte-verbatim; nothing in this file edits it.

## `predicate` presence: absent, `null` and `{}` are one input

The framework types `predicate` as optional and says what optional means, in
[`spec/v1/statement.md`](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
lines 62-66 (read at in-toto/attestation commit `512e386d`):

> `predicate` _object, optional_
>
> Additional parameters of the [Predicate]. Unset is treated the same as
> set-but-empty. MAY be omitted if `predicateType` fully describes the
> predicate.

That sentence resolves two of the three states a JSON member can be in. It does
not name `null`. SLSA resolves all three, as a MUST, inside a predicate that is
itself an in-toto predicate, in its "Parsing rules" section
(slsa-framework/slsa, `spec/build-provenance.md` line 110, read at commit
`54b88b00`):

> Unset, null, and empty field values MUST be interpreted equivalently.

**The rule this corpus tests.** A verifier MUST treat an absent `predicate`
member, `"predicate": null` and `"predicate": {}` as one input, decoding all
three to the empty predicate object, and MUST emit for all three the identical
verdict and the identical reason codes.

### Why the rule binds the reason and not only the verdict

"Treated the same" binds the treatment, not its summary. A verifier that agrees
on the verdict and disagrees on the reason has still made the producer's choice
of spelling observable, and the reason is what a relying party acts on: it is
the difference between "this statement is not evidence because it carries no
claim" and "this statement is not evidence because its predicate type is one I
do not implement". Those are opposite findings about the same bytes, and a
corpus that scored only the verdict would certify a rail that reports the second
for an AEE statement whose predicate is merely absent.

The same argument the vendored predicate makes for the nesting-depth bound
applies here: with the state unresolved, implementations pick their own reading,
and two conforming verifiers then disagree about identical bytes over the whole
range between their choices.

### Why `null` cannot be given a meaning of its own

Not by preference, but because the framework's own reference bindings cannot
express one. The framework declares the member as
`google.protobuf.Struct predicate = 4;`
(`protos/in_toto_attestation/v1/statement.proto`, same commit), and protobuf's
canonical JSON mapping skips a field on JSON `null` unless the field type is
`google.protobuf.Value` or `google.protobuf.NullValue`
(`google.golang.org/protobuf@v1.36.12`, `encoding/protojson/decode.go` lines
214-215: "No need to set values for JSON null unless the field type is
google.protobuf.Value or google.protobuf.NullValue"). A Go or Python
implementation built on protojson
receives absent and `null` as the same nil Struct and has nothing left to
discriminate on. A rule that gave them different meanings would be
unimplementable on the bindings the framework ships, which is why the
requirement level here is MUST and not SHOULD.

### What the rule does not say

It does not make `predicate` optional in practice for this predicate, and it
does not make the empty predicate acceptable. An AEE predicate carries `result`,
`issuedAt`, `observationEnvironment`, `coverage` and `attackResults` as required
members, so the empty predicate fails statement well-formedness on each of them
and the statement is invalid. The rule fixes only this: which failure a verifier
reports MUST NOT depend on which of the three spellings the producer chose.

A `predicate` present and neither an object nor `null` -- a string, a number, an
array -- is a different fault and keeps its own code. The equivalence class is
the three empty states, not every ill-typed value.

### Where it is tested

Three reject vectors, one per state, carrying the identical expected verdict and
the identical expected code set, listed in
[`../../vectors/reject/INDEX.md`](../../vectors/reject/INDEX.md) under condition
`aee-c-109`. `scripts/predicate-state-gate.py` asserts the equivalence directly
on both rails this repository ships, because the corpus harness scores reject
codes disjunctively and by design (see `comparisonSurface` in
`vectors/MANIFEST.json`) and therefore cannot fail a rail that rejects all three
for three different reasons.
