# Nine underdetermined passages, decided against the rails

An outside implementer built a second rail against this predicate from the
specification text alone, reached full agreement with the corpus, and recorded
nine passages where our text let him choose. This file answers each one from the
**code**, which is the only artifact that can say what a reading actually is, and
states the replacement sentence that leaves one reading standing.

## Where these edits land, and why not here

The specification in this repository is **vendored**, not authored.
`spec/VENDOR-PIN.json` names the upstream commit, and
`scripts/spec-drift-gate.py` refuses a vendored file whose bytes no pinned commit
contains, in its own words: "The vendored spec was edited in place instead of
re-vendored. Edit the spec upstream, then run scripts/vendor-spec.py so the pin
names a commit that actually contains these bytes."

So the rewritten passages below are an upstream patch. They land on the
specification's own pull request, and re-vendoring brings them here with a corpus
regeneration and a revision bump behind them. Writing them into the vendored copy
on this branch would produce a file that no gate accepts and no reader can trace
to a commit.

## What the audit was worth, stated before the detail

Six of the nine readings he took are the readings both our rails implement. He
found those by reading the text, which is the outcome the text is supposed to
produce.

The remaining three are worth more than the six, and two of them are defects on
our side rather than ambiguities:

- **Passages one and three: his rail and ours disagree, and the corpus cannot
  see it.** He read the safe-integer rule as reaching only numbers written in
  integer form, so his rail accepts an exponent-form integer above the bound.
  Both of ours reject it, deliberately and with exact arithmetic. Neither run
  caught the split because **the corpus contains no exponent-form number literal
  at all**, so every vector agrees with every reading. A third rail decides this
  by guessing.
- **Passage eight: our two first-party rails disagree with each other.** On a
  predicate carrying no observation vocabulary, the Go rail runs the result
  recompute and reports a mismatch; the Python rail skips the recompute and
  reports nothing. His reading matches Go. The Python guard is a defect in our
  rail, not a reading, and it is recorded here and fixed separately, because a
  vector that needs the rail changed has found a rail bug rather than a corpus
  gap.
- **Passage nine agrees and the sentence is still wrong**, because our own run
  binding derives a second, different digest and calls it by the same name.

---

## 1. Does the safe-integer rule reach exponent-form numbers

**Current text** (`spec/predicates/adversarial-execution-evidence.md`, the
Prerequisites paragraph):

> Producers MUST enforce the RFC 7493 (I-JSON) safe-integer profile on
> canonicalized content: integers with magnitude at or above 2^53 MUST be
> rejected, so every rail (producer and verifier, in any language) derives
> identical bytes.

**The two readings.** Written-form: "integers" means numbers written as integer
literals, so an exponent-form number is not one and passes whatever its value.
Value: any number whose value is integral and at or above the bound is refused
however it is spelled.

**What the rails do: the value reading, on the raw literal, with exact
arithmetic.** `aee/jcs.go`, `checkSafeInteger`, parses the literal with
`new(big.Rat).SetString(s)` and tests `new(big.Int).Abs(r.Num()).Cmp(maxSafeIntBig) >= 0`.
Its own comment states the intent and names the case:

> an integer with magnitude at or above 2^53 is rejected, including one written
> in exponent form (1e21) or with a decimal point (1.0e21) that a notation-blind
> check would miss.

and records that this is a divergence already found once:

> Exact rational arithmetic is used deliberately so an exponent-notation integer
> such as 1e21 cannot slip past a float64 approximation of the bound -- the
> divergence the two number paths otherwise hid, where "1e21" contains 'e' and
> was never range-checked.

The same function refuses every non-integer outright
(`if !r.IsInt() { return ErrNonIntegerNumber }`). The Python rail agrees and uses
`decimal.Decimal(s)` on the literal for the same two tests, preferring `Decimal`
to `Fraction` so that `1e1000000000`, a legal token in a few bytes, does not
expand to a billion digits inside the parse.

**Replacement text.**

> Producers and verifiers MUST enforce the RFC 7493 (I-JSON) safe-integer
> profile on canonicalized content. The profile is defined over the **value a
> number literal denotes, not over the notation it is written in**: a verifier
> MUST refuse any number whose exact value is integral with magnitude at or
> above 2^53, whether it is written as an integer (`9007199254740993`), in
> exponent form (`1e21`), or with a decimal point (`1.0e21`). A verifier MUST
> also refuse any number whose exact value is not integral, because this
> predicate's canonicalized content admits no fractional numbers. Both tests are
> applied to the literal **as carried**, using exact arithmetic rather than a
> binary floating-point approximation of the bound, so that a notation-blind or
> float-rounded check cannot accept a value another rail refuses.

**The blind spot, measured directly.** A text search cannot answer this, because
the numbers live inside base64 DSSE payloads. Decoding every payload in the
corpus and scanning every JSON number literal in both the statements and the
decoded bytes -- with the statement count and the decoded-payload count as
positive controls, both non-zero -- returns **no exponent-form number literal
anywhere in the corpus**. The safe-integer bound is exercised by a single
integer-form literal above it, and the non-integer rule by a single fractional
literal; the notation axis is untouched. So `checkSafeInteger` uses exact
rational arithmetic precisely so that an exponent-form integer cannot slip the
bound, and nothing in the corpus ever hands it one.

**Vector.** A reject vector carrying `1e21` in a field the chain hash covers,
expecting the unsafe-integer refusal. It is the discriminating case by
construction: a rail holding the written-form reading accepts the statement this
one refuses. Recorded as absent today: a whole-tree search for `1e-7` and for
`1234567890123456789` exits clean with no file, against a control that returns
four files for the safe-integer boundary already covered.

---

## 2. What the PAE runs over

**Current text** (the `observationRecords` field):

> One DSSE envelope per observation: `payload` (base64 of the exact canonical
> bytes the substrate signed at observation time), `payloadType`, and
> `signatures`, which MUST carry at least one entry. A consumer verifies each
> record's signature, DSSE PAE over `(payloadType, payload)`, before relying on
> any field inside the payload.

**The two readings.** The PAE body is the base64 text as carried, or the bytes it
decodes to. The sentence names `payload`, and `payload` has just been defined as
the base64 text.

**What the rails do: the decoded bytes.** `aee/validity.go` decodes first and
paes second:

    payload, err := base64.StdEncoding.Strict().DecodeString(p.Records[i].PayloadB64)
    ...
    states[i].pae = PAE(p.Records[i].PayloadType, payload)

**Replacement text.** Replace "DSSE PAE over `(payloadType, payload)`" with:

> DSSE PAE over `(payloadType, D)`, where `D` is the byte string obtained by
> strict base64 decoding of `payload` -- never the base64 text itself. The
> distinction is normative because the two produce different signatures over the
> same envelope.

**Vector.** A reject vector whose record signature is valid over the base64 text
rather than over the decoded bytes, expecting a signature failure. A rail holding
the text reading accepts it.

---

## 3. Where the safe-integer rule is enforced

**Current text.** The Prerequisites sentence quoted in passage one says
"Producers MUST enforce", and names no verifier obligation and no point in the
pipeline.

**The two readings.** The check belongs on the way in, against the raw literal,
and a serialiser that also refused would duplicate it in the wrong place; or the
canonicaliser polices what it is handed and the reader need not.

**What the rails do: both, deliberately, and the reader is the normative one.**
The parse-time check is `checkSafeInteger` on the literal, reached through
`CheckIJSON`. The serialiser carries a second copy as a backstop, commented in
`aee/jcs.go` as being there to "never emit an unsafe integer even if reached
without a prior CheckIJSON". The reader's copy is the one that sees the bytes the
producer wrote; the serialiser's copy cannot, because by then the literal is
gone.

**Replacement text.** Fold into passage one's replacement, which already says
"applied to the literal as carried", and add:

> A verifier MUST apply both tests during the parse of the carried bytes, before
> any value is converted to a host-language number. A check applied after that
> conversion is not equivalent: a conversion through binary floating point can
> alter the value, so the check would be reading a number the producer did not
> write. An implementation MAY also refuse on serialisation, which is a backstop
> and never a substitute.

**Vector.** The decode-boundary reject vector described in the JCS-edge section
below: the carried literal `1234567890123456789` becomes `1234567890123456800`
in any rail that parses to a double first, so the value such a rail refuses is
not the value it was given.

---

## 4. Noncharacters produced by escapes

**Current text** (the strict-I-JSON string paragraph):

> The profile also excludes the Unicode noncharacters -- the code points U+FDD0
> through U+FDEF, and U+nFFFE and U+nFFFF in every plane -- which RFC 7493
> section 2.1 forbids in the same sentence as surrogates. [...] it is rejected
> wherever a string literal appears, at any depth and in both member-name and
> value position.

**The two readings.** The rule is about code points, so a noncharacter reached
through an escape is refused exactly as a literal one is; or only literal
noncharacters are refused and an escape passes.

**What the rails do: refuse all three routes.** `aee/jcs.go` checks the literal
UTF-8 route, the single-escape route, and -- the case he singled out -- the
surrogate-pair route, reassembling the code point before testing it:

    if cp := uint32(0x10000) + (hi-0xD800)<<10 + (lo - 0xDC00); isNoncharacter(cp) {

with `isNoncharacter` covering both families in one expression:

    return r&0xFFFE == 0xFFFE || (r >= 0xFDD0 && r <= 0xFDEF)

**Replacement text.** Replace the final clause with:

> and it is rejected wherever a string literal appears, at any depth and in both
> member-name and value position, **whether the code point is encoded directly
> in UTF-8, named by a single `\u` escape, or assembled from a surrogate-pair
> escape.** The rule is over the code point a string denotes, never over the
> bytes that spell it: were an escaped noncharacter admitted, any noncharacter
> could be carried by escaping it and the rule would have no effect.

**Vector.** A reject vector whose member name carries `\ud83f\udffe`, the
surrogate-pair spelling of U+1FFFE, expecting the ill-formed-string refusal. A
rail that tests only decoded literal bytes accepts it.

---

## 5. The empty observed set

**Current text.** `aeeObservedSet` is defined as a digest over the array of leaf
hashes of every `interception` and `examination` record, and the `sealed` kind
requires the member on every such record. No sentence names the case where that
array is empty.

**The two readings.** The definition is a total function of the carried records,
so an empty array canonicalizes and the member carries the digest of `[]`; or the
empty case is unreachable and the value is undefined.

**What the rails do: the digest of the empty array.** `aee/commitments.go`,
`observedSetDigest`, collects qualifying leaves into a slice, sorts it, and
digests the canonicalization unconditionally. With no qualifying record the
canonical form is the two bytes `[]`, whose SHA-256 is
`4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945`. There is no
guard and no special case.

**Replacement text.** Append to the `aeeObservedSet` definition:

> The array MAY be empty. A run whose carried records include no `interception`
> and no `examination` record commits to the canonicalization of the empty
> array, so `aeeObservedSet` is the SHA-256 of the two bytes `[]`. The member is
> required on every `sealed` record without exception: omitting it would assert
> silence where the empty digest asserts that nothing was emitted, and those are
> different claims.

**Vector.** An accept vector whose only records are an `arming` and a `sealed`
record, with the seal carrying the empty-array digest. A rail treating the case
as undefined cannot produce the expected value.

---

## 6. Raw bytes, or a decoder that refuses to substitute

**Current text:**

> A verifier MUST therefore apply this check to the raw bytes, before any decoded
> string is read.

**The two readings.** Scan the raw bytes without decoding; or decode with a
decoder that raises instead of substituting, which manufactures no U+FFFD and so
leaves no downstream check reading a string the producer never wrote.

**What the rails do: the raw-byte scan.** `aee/jcs.go`, `checkStringScalars`,
"walks raw JSON bytes and applies checkStringLiteral to every string literal in
the document, at any depth and in both member-name and value position". The
literal checker reads bytes and distinguishes a genuine U+FFFD from an ill-formed
sequence by the decoded size, never by a decoder's exception:

> DecodeRune reports (RuneError, 1) for every ill-formed sequence, including an
> overlong encoding and a surrogate encoded in UTF-8; a genuine U+FFFD decodes
> with size 3 and is legal.

The two readings are equivalent for the defects the paragraph names, which is
what he argued. They are not equivalent as obligations, because the second one is
satisfiable by any number of decoders whose substitution behaviour a reader has
to go and check.

**Replacement text.**

> A verifier MUST therefore apply this check to the raw bytes of each string
> literal, including member names, before any decoded string is read and before
> any object model exists. A strict decoder that raises on an ill-formed sequence
> rather than substituting U+FFFD satisfies this requirement for the encoding
> defects named above, and an implementation MAY rely on one; it does not satisfy
> it for a lenient decoder, and the raw-byte scan is the normative form because
> it does not depend on a decoder's configuration. A genuine U+FFFD carried as
> its own well-formed encoding is legal and MUST NOT be refused.

**Vector.** Already covered by the ill-formed-string family; the replacement
tightens an obligation rather than adding a case, and no new vector is owed.

---

## 7. A missing `containmentObserved` under the first condition

**Current text** (the `result` field):

> The first condition holds when any `attackResults` row carries a
> containment-observed label from the carried caught set
> (`observationVocabulary.caught`), a label outside the carried
> `observationVocabulary.labels` (fail-closed), or a missing or
> out-of-vocabulary `basis`, `method` or `attribution` (fail-closed, same rule),
> and it contributes `fail`.

**The two readings.** The sentence spells out *missing* for three axes and not
for `containmentObserved`. So either absent counts as "outside the carried
labels" and the condition holds, or the omission is a well-formedness fault only
and the recompute runs over the remaining rows.

**What the rails do: absent is outside.** `aee/recompute.go`, `classifyRow`,
reaches the fail-closed arm for an absent member because the zero value is in no
carried set:

    case !labels[row.ContainmentObserved]:
        return rowForcesFail // fail-closed: label outside carried vocabulary

and the comment above it states the invariant the ordering exists to guarantee:
"a row missing or out of vocabulary on either member can never be classified as
clean and can never reach the indirect arm".

**Replacement text.** Replace the first clause with:

> The first condition holds when any `attackResults` row carries a
> containment-observed label from the carried caught set
> (`observationVocabulary.caught`), or **a missing or out-of-vocabulary
> `containmentObserved`** (fail-closed), or a missing or out-of-vocabulary
> `basis`, `method` or `attribution` (fail-closed, same rule), and it contributes
> `fail`. Absent is treated as out-of-vocabulary on every one of these four
> axes: a member that is not carried is in no carried set, and the recompute is
> total, so it answers rather than declining.

**Vector.** A reject vector with `containmentObserved` omitted from one row and a
declared `result` above `fail`, expecting the recompute mismatch. A rail that
treats the omission as a well-formedness fault only recomputes a different
result.

---

## 8. The recompute on a malformed predicate, and a defect in our own rail

**Current text** (the `result` field):

> Defined as a total, deterministic, severity-independent function of the
> predicate, evaluated as the minimum under that order of three independent
> conditions rather than as a cascade, because worst-wins rather than evaluation
> order is the rule.

**The two readings.** The function never declines: anything it cannot read
resolves fail-closed, and an absent vocabulary yields empty carried sets, which
puts every label outside them. Or the recompute may assume a well-formedness gate
ran first.

**What the rails do: they disagree, and this is a defect rather than an
ambiguity.** The Go rail is total. `aee/recompute.go` builds empty sets and
proceeds:

    labels := map[string]bool{}
    caught := map[string]bool{}
    if p.Env != nil && p.Env.Vocabulary != nil {
        labels = stringSet(p.Env.Vocabulary.Labels)
        caught = stringSet(p.Env.Vocabulary.Caught)
    }

The Python rail guards instead, and on a predicate with no vocabulary it emits no
recompute finding at all. `packaging/run_vectors.py`,
`_check_result_recompute`:

    if labels is not None and caught is not None and rows:
        recomputed = self._recompute(rows, labels, caught, coverage)

**Corrected by measurement, and the correction is worth more than the original
finding.** The sentence that stood here said that on a statement carrying no
`observationVocabulary` and a declared `result` above `fail`, the Go rail reports
a recompute mismatch and the Python rail reports nothing, that no verdict moves,
and that the difference is a code-set one. Each of those three claims is wrong,
and all three were wrong for the same reason: the comparison was made between two
FUNCTIONS and written up as a comparison between two RAILS.

Running the two rails over that statement:

- **Neither rail reports a recompute mismatch on a predicate carrying no
  vocabulary, because the Go rail never reaches the recompute.** `aee/verify.go`,
  `Evaluate`, returns at the first failing gate -- `if codes := Gate0(s);
  len(codes) > 0 { return nil, codes, nil }` -- and `Gate0` emits
  `vocabulary-missing` for an absent vocabulary. `Recompute` is total; the
  pipeline around it short-circuits before calling it.
- **The vocabulary arm of the Python guard is therefore unreachable in any state
  where the Go rail would answer differently.** Go reaches the recompute only
  after Gate 0 has accepted the vocabulary, and in that state the Python rail's
  `labels` and `caught` are lists rather than `None`.
- **The reachable arm is `rows`, and the divergence it produces is a VERDICT.**
  The guard also declines when `attackResults` is empty. On a statement carrying
  `attackResults: []`, a coverage map that accounts for every manifested attack,
  and a declared `result` the zero-row recompute does not derive, the Go rail
  answers **invalid** with `result-recompute-mismatch` and the Python rail
  answered **valid** -- and emitted a `result` and a tier column for it, which is
  the one thing the behaviour contract says an invalid statement never carries.
  Measured on `vc7a74e2cef5586ed` with its rows emptied and its coverage
  re-derived, at three of the four declared result tokens.

So the defect was one rail admitting a statement the other refuses, and
publishing a result token the definition never produces, rather than two rails
naming different conditions for the same refusal. The corpus could not see it for
a reason the original write-up had right: no vector carried the shape.

**Replacement text.**

> Defined as a total, deterministic, severity-independent function of the
> predicate. Total is normative and is stated as an obligation on the
> implementation: the recompute MUST return a result for every syntactically
> parseable predicate, including one that is malformed on other grounds, and MUST
> NOT raise, decline, or depend on a well-formedness gate having run first. A
> member the predicate does not carry contributes the fail-closed reading of its
> axis; an absent `observationVocabulary` yields empty carried label and caught
> sets, which places every row's label outside the carried labels and therefore
> contributes `fail`. A verifier that skips the recompute on a malformed
> predicate reports a different set of conditions from one that does not, over
> identical bytes.

**Landed.** The guard is gone: `_check_result_recompute` now recomputes
unconditionally, treating an absent or unreadable vocabulary as empty carried
sets and an absent or empty `attackResults` as zero rows. `Recompute`'s totality
is pinned on the Go side by `TestRecomputeIsTotal`, which fails if anyone adds
the same guard there.

**Vectors.** Two, and the second is why one was not enough.

- `ve3c7f7a8d918c70c` carries the discriminating shape: `attackResults` emptied,
  coverage re-derived so every manifested attack is out of scope, and the
  parent's `pass_indirect` kept against a zero-row derivation of `degraded`. Both
  rails now answer `invalid` with exactly `result-recompute-mismatch`; a rail
  that declines to recompute over zero rows fails it on the verdict.
- `v6945133925a03e15` is the no-vocabulary twin of the shipped `v089e746847cd0af2`
  with its carried result re-derived to `fail` under the empty-carried-sets
  reading. Neither vector forces that reading alone, because the statement is
  invalid on `vocabulary-missing` either way and the harness grades a reject
  expectation by intersection. Across the PAIR the two readings invert: a rail
  reading an absent vocabulary as admitting every label reports a recompute
  mismatch on the twin and none on `v089e746847cd0af2`, which is the opposite of
  what both rails now do.

**Gate.** Nothing in this repository compared the two rails to each other before
this change. `aee/vectors_test.go` asserts the Go rail's PRIMARY code is in each
vector's declared set, so a differing secondary code is compared against nothing;
`scripts/observed-code-closure-gate.py` pins the full set the PYTHON rail emits
and says in its own words that it is "a check over the REFERENCE rail", singular,
importing `run_vectors`. Both gates looked complete and neither looked at the
other rail. `scripts/rail-parity-gate.py` now replays both over every member,
refuses a verdict split unconditionally, and holds every code-set difference to a
recorded row in `docs/RAIL-PARITY-BASELINE.json`. Thirty rows are recorded today;
twenty-seven of them are the Go pipeline stopping at an earlier gate than the one
that produced the code, which `vectors/MANIFEST.json` already declares measured
rather than normative. Read honestly, the gate would have passed the day before
this fix: it compares the rails on the shapes the corpus carries, and the shape
was not one of them. The vector puts the shape into the membership; the gate
stops the next divergence drifting once it is there.

---

## 9. Which value is "the pinned `networkPosture` digest"

**Current text**, in three places -- the `arming` kind, the `sealed` sweep, and
the plain-reading paragraph:

> `aeePostureDigest` equal to the pinned `networkPosture` digest

> its `aeePostureDigest` equals the pinned `networkPosture` digest and the
> `aeePostureDigest` of every `arming` record the row resolves

> `aeePostureDigest` is the pinned `networkPosture` digest carried beside them

**The two readings.** The digest the member carries,
`observationEnvironment.networkPosture.digest.sha256`; or a digest taken over the
whole carried `networkPosture` object. He recorded that these "accept and refuse
disjoint sets of statements", which is right.

**What the rails do: the carried member, and both rails agree.** Go takes
`pinnedPosture := p.Env.NetworkPosture.Sha256()`, and `Sha256()` returns
`n.Digest["sha256"]`. Python takes
`pinned_posture = _digest_of(st.env.get("networkPosture"))`, and `_digest_of`
returns `obj["digest"]["sha256"]`.

**Why the sentence is nonetheless defective, which is the part worth having.**
The other reading is not hypothetical: **our own run binding computes it, and
calls it `networkPosture`.** `aee/runbinding.go`, `posturePreimageDigest`, is
documented as

> the version-2 networkPosture input: the RFC 8785 canonical digest of the
> CARRIED networkPosture object, never of that object's own digest member.

and it enters the binding preimage under the member name `networkPosture`. So the
specification contains two distinct digests over the same environment member,
uses the bare phrase "the pinned `networkPosture` digest" for one of them, and
uses the name `networkPosture` for the other inside a preimage. A reader who
meets the binding first takes the wrong one, and every substrate row diverges.

**Replacement text**, applied at all three sites:

> `aeePostureDigest` equal to `observationEnvironment.networkPosture.digest.sha256`
> -- the configuration digest that member carries, written out here because it is
> **not** the `networkPosture` input to the run binding, which is the RFC 8785
> canonical digest of the whole carried `networkPosture` object. The two values
> differ for every statement, they serve different purposes, and a verifier
> comparing `aeePostureDigest` against the binding input refuses every statement
> a conforming verifier accepts on a `basis: substrate` row.

**A fourth site, and it is the one the three others exist to work around: the
preimage member name itself.** The run-binding paragraph at spec:176-182 names
the member `networkPosture` and then spends two lines of prose saying its value
is not what that name means anywhere else in the document -- "the lowercase
64-hex SHA-256 of the RFC 8785 canonicalization of the carried networkPosture
object". So a reader has to hold three things under one word: the environment
member, the digest that member carries, and a second digest taken over the whole
member. The replacement above disambiguates the two digests every time the
document names one. The member name would disambiguate them once, for every
reader, without a clause.

**Replacement text for that site**, and its cost stated rather than buried:

> `"networkPostureObjectDigest": "<the lowercase 64-hex SHA-256 of the RFC 8785
> canonicalization of the carried networkPosture object>"`, replacing the
> `"networkPosture"` member of the version-2 pre-image, so that no member of the
> pre-image carries the name of an environment member whose own digest it is not.

That rename is **binding version 3, not a correction to version 2**, and the
document says so itself: "`aeeBindingVersion` names this construction; a future
version that changes the construction ... names a new binding version"
(spec:237-241). The member name is inside the hashed bytes, JCS orders members by
name, and `aeeRunBinding` is committed inside every observation record's own
signature -- so the rename moves the binding digest of every statement carrying a
`basis: substrate` row, regenerates and re-signs every such vector, and makes
every rail that implemented version 2 from the published text non-conforming
until it carries the new construction. One of those rails is the only
implementation in `docs/IMPLEMENTATION-REPORT.md` independent of the
specification's author.

**What landed, and what is held.** The parameter carrying that value through our
own Go rail was also called `networkPosture`, which is the shape of the defect
inside our implementation rather than inside the document, and it is renamed to
`networkPostureObjectDigest` (`aee/runbinding.go`). `posturePreimageDigest`'s own
comment now names all three values and says which one `aeePostureDigest` holds.
Those change no bytes: no vector's binding moves and none is regenerated, which
is the truthful count rather than a convenient one. The Python rail already named
its function `posture_preimage_digest` and needed no rename. **The wire member
name is held**, because moving it is a version-3 construction change that begins
upstream, and doing half of it here -- our rails renamed, the specification and
every other rail not -- would produce exactly the silent divergence this passage
is about, in the one place where divergence is unrecoverable: inside bytes that
are already signed.

**Vector.** A reject vector whose `aeePostureDigest` carries the run-binding
posture preimage digest instead of the member's own digest, expecting the
arming-constraint refusal. It is the discriminating case: a rail holding the
object-digest reading accepts exactly this statement and refuses the accept
vectors.

---

## The two JCS number edges, and what our own gate refused

A third-party rail published the number cases that had bitten it and stated its
coverage bar: if two implementations agree on `1e21`, `1e-7`, and integers past
2^53, they have covered what bit us. Its sharper finding was a decode-boundary
one -- a safe-integer guard inside a canonicalizer "turned out to be theatre",
because `1234567890123456789` has already become `1234567890123456800` in the
JavaScript parser before the canonicalizer sees it.

Measured against this repository, with a proven read path: a whole-tree search
for `1e-7` exits one with no file, the same for `1234567890123456789`, and a
control search for the safe-integer boundary already covered exits zero with four
files. Both edges were genuinely absent.

**Landed: the decode-boundary case.** `v1a09354386e0ed57`, a reject vector in
`vectors-ai-agent-action/` under `aia-c-14`, carrying the literal in a signed
field and expecting the unsafe-integer refusal. Its expectation declares both
renderings -- the literal as carried and the rendering a lossy parse produces --
so a reader can compare a rail's own report against them. What it does **not** do
is separate the two placements of the check by verdict or by code, because both
the literal and its lossy double sit at or above the bound and every placement
refuses. The placement is decided in the specification text instead, by passages
one and three above, and the vector's own description says so rather than
implying more.

**Not landed, and refused by our own gate: `1e-7`.** The vector was written,
generated, and verified green -- and `scripts/surface-leakage-gate.py` then
refused the corpus, because adding it moved two surface measurements:
`identifier` outside its null, and `shape` up from its recorded figure. The
diagnosis is attributable and was confirmed by measurement, by generating the
corpus with the reject vector alone and watching the gate pass.

The cause is structural and already declared in this repository. The number
family is accept-only, which the gate already records as "blocked by the Appendix
B family having no reject counterpart", and the block is not an oversight: a
number in this corpus can only live in an uncarried content payload, because the
safe-integer profile binds the fields the chain hash covers and a float in a
signed record field is a different refusal with a different code. So the family
cannot be given a reject twin without a payload-carrying vector shape the corpus
does not have.

That is a design change, not a vector, and the honest sequence is that order.
Loosening a published anti-scoreability ratchet to admit one accept vector into a
structurally unbalanced family trades a measured guarantee for a single edge case.
The edge is worth having and lands the moment the family can be balanced.

**Owed, as one follow-up, and now designed rather than owed in the abstract:**
[docs/NUMBER-FAMILY-BALANCE.md](NUMBER-FAMILY-BALANCE.md) carries the
payload-carrying vector shape for the number family, its reject counterpart, the
measured arithmetic of the refusal that blocks it, and the ordered sequence that
lands it. Two corrections to the paragraphs above belong with it.

**The block is the fingerprint-drift check, not the two surface measurements this
file named.** `scripts/surface-leakage-gate.py` pins each corpus's nulls to the
class counts they were calibrated over and refuses when either class moves by
more than ten per cent. `vectors-ai-agent-action` is recorded at 16 rejects and
holds 17, so the budget is already 6.25 per cent spent and the next reject is
12.5 per cent and over the bound -- for any reject, number or not. Measured by
staging the tree and running the real gate, a matched accept-and-reject pair
moves every leakage-bearing surface DOWN (`lexicon` 0.7886 to 0.7405, `paths`
0.7862 to 0.7571, `all` 0.7785 to 0.7408) and pulls `identifier` to 0.5175, under
its null; a reject alone pushes `identifier` to 0.5285, over it. So the pair is
required and the ratchet is not loosened by landing it, which is the opposite of
what this file previously implied.

**`vf1492a40d7a7c2c9` has never existed in this repository.** `git log -S` and
`git grep` across all 1172 commits on all refs both return nothing for it,
against a control that returns two commits and three files in the same session.
Identifiers here are digests of the bytes, so a vector written in a working tree
and never committed mints none. The vector was real; the identifier is not, and
it should not be quoted as though a vector had been removed.

**Four of the notation cases landed here instead, in the corpus where they can
be decided.** See passage one's vector note: `vd3ead02f7ed16d0a` (`1e21`),
`vd5e0b3f3d1fabb05` (`1E2`), `v97c6888cf7e88f42` (`1.0e2`) and
`v13ede3e42645eb1a` (`-0e0`).
