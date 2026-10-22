# Obligations nothing cites

A vector count says how much the corpus does. It never says which sentences of
the specification are behind those vectors, and the two answers came apart
here: reading the document sentence by sentence against everything that cites
it -- the condition registry, the per-vector anchor column, the interpretation
registry and the unforced-coverage cells -- found **sixteen obligation-bearing
sentences and five SHOULDs that nothing addressed at all**. Not weakly covered.
Not covered by a paragraph-level anchor. Cited by nothing.

This file dispositions all twenty-one, and it is the standing record for one
distinction the vector count cannot make: an obligation **nobody has tested**
reads exactly like one **deliberately ruled untestable**, and without a written
ruling the next reader has to re-derive which is which from scratch.

Every row carries one of exactly four dispositions.

**The fourth was added after three proved insufficient, and the gap is worth
recording rather than smoothing over.** The vocabulary began with (a), (b) and
(c). One row fitted none of them: a vector was written, executed on both rails
and proved, and the citation still could not be recorded, because the accept
index carries no spec-anchor column to record it in. Filed as (a) it asserted an
obligation was closed, while `spec/READINGS.toml` correctly went on declaring the
same sentence uncited -- two documents disagreeing, neither of them wrong.
`scripts/uncited-crosscheck-gate.py` is what surfaced it, on its first run.

- **(a) A vector is owed, and the citation now exists.** The sentence states
  something a conformance vector can decide. Two remedies are possible and the
  row says which applied: a NEW vector, or a CITATION where a vector already
  forced the sentence and its anchor named a different line. A row is only (a)
  once something machine-readable actually points at the sentence.
- **(d) A vector forces it and the citation is BLOCKED.** The behaviour is
  proved, and nothing in the corpus can yet record that fact -- so the sentence
  remains uncited, keeps its `[[uncited]]` row, and continues to count against
  the coverage figure. The row names the blocker. This disposition is not a
  softer (a); it is an open item with its evidence already in hand.
- **(b) Structurally untestable by a conformance vector.** The row states the
  precise reason -- an obligation on a producer that a verifier cannot observe,
  an obligation about a consumer's out-of-band policy, or an obligation about
  process rather than about bytes.
- **(c) The sentence should not be normative.** It uses an RFC 2119 keyword
  where it means description or guidance. The row carries the proposed
  replacement wording.

## What the measurement was, and how to re-derive it

`measure_sentence_coverage.py`, a private script kept beside the
consuming repository, run against
`spec/predicates/adversarial-execution-evidence.md` (2,194 lines, content digest
`7abe0db0`). It splits prose outside fenced code into sentences, keeps the ones
carrying an RFC 2119 keyword (74; 67 obligation-bearing, 7 SHOULD-only), and
tests each against the union of every `Lnnn` span anything in the corpus cites.

Two properties of that method matter when reading the rows below, and both were
found the hard way rather than assumed.

**A sentence's line is where its FIRST CHARACTERS fall, and the script can be
one line early.** The script attributes a sentence to the last buffered line
whose cumulative offset does not exceed the sentence's start, so a sentence
beginning mid-line is attributed to the line the PREVIOUS sentence began on.
Row 2 below is exactly this: the subject-cardinality obligation begins on line
210, was reported at line 209, and is forced by two vectors that anchor
L210-213.
Widening that anchor to L209-213 was tried and `scripts/spec-anchor-gate.py`
refused it, printing the line it now addressed -- "axis rather than against the
producer's clock". **An uncited count is an upper bound until each sentence's
true start line is confirmed.**

**Uncited is not untested.** Three of the sixteen turned out to be already
forced, by vectors whose anchor named the schema line that introduces a member
rather than the sentence that states the rule over it. The first draft of this
work proposed a NEW vector for the L946 row and the mutation proof killed it:
narrowing the rail's reference check made TWO vectors go red, not one, and the
second was `bad-724`, which had been forcing the rule since it was written.

## The rows

### Obligation-bearing sentences

| Line | The sentence, in short | Disposition | Remedy and evidence |
|------|------------------------|-------------|---------------------|
| L88 | A consumer MUST NOT infer a composite guarantee from this predicate composed with a sibling execution predicate unless its policy binds both to the same execution | **(b) untestable** | The obligation binds an inference drawn across TWO attestations, one of which is not an AEE statement and is not carried here. A conformance vector is a single statement, so no arrangement of bytes inside one can witness compliance or violation. Testable only by a policy-engine suite that consumes two attestations, which is a different artifact from this corpus |
| L210 | `subject` MUST contain exactly one entry on a statement of any basis | **(a) already satisfied** | No action, and the anchor must NOT be widened. Forced by `v6f6941efba2cbe28` and `v423dab49f4ed4d29`, condition `aee-c-58`, anchored L210-213. The measurement first reported this obligation at L209, the line above, because sentence line attribution used the offset of the space joining two lines rather than the sentence's first character. That is fixed at its source, and the row stands as the record of what the defect produced |
| L625 | The coverage requirements are consumption preconditions: a consumer that consumes `result` or credits any row MUST evaluate them first, and on failure `result` MUST NOT be consumed | **(a) citation** | Forced already, cited by nothing. `v85caf3c6f7516ba2` is the shape that forces it: the statement is invalid on a coverage precondition while its carried `result` IS the recompute, so a rail that reads `result` without evaluating the preconditions admits it. `bad-201` now anchors `L561-562; L1310-1317; L625-629`. Proved by `scripts/uncited-obligations-proof.py`: a rail that lets a matching carried `result` stand in for the coverage preconditions fails `bad-201` and `bad-208` and no others, so the forcing set is those two and this row originally named one |
| L946 | Wherever `observationRefs` is present, on any row regardless of basis and including rows nothing normative reads, every index MUST be in range | **(a) citation** | Forced already by `v3300d78454ab852f`, which anchored only L552-553 -- the schema line, where the rule reads as a duplicate of `bad-102` on a substrate row. Now anchors `L552-553; L946-951`, and condition `aee-c-11` records the universality in its own text. Proved by `scripts/uncited-obligations-proof.py`: a rail that scopes the check to substrate rows fails this vector and, since the corpus gained two more artifact-row shapes, `vc19ea5aaacc5b72a` and `v1a3d0ce04c3f7524` -- an in-range index before the bad one, and a bad index on the row after a fully covered substrate row -- and no others |
| L1031 | A producer MUST NOT declare `basis: substrate` on a row it cannot cover; such a row makes the attestation invalid | **(a) citation** | Forced already by `ve025b4bed04cfb68` and `v132435a4d6d10043`, both anchored L557-560. Both now anchor `L557-560; L1031-1033`. Proved by `scripts/uncited-obligations-proof.py`: a rail that reads an uncoverable substrate row as a weaker claim rather than as the invalid statement this sentence says it makes fails `bad-106`, `bad-107` and `v5dcc150714259e09` and no others. `bad-714` forces the rule as well and this row did not name it |
| L1198 | The substrate observation key MUST NOT be accessible to the subject artifact | **(b) untestable** | A property of key custody in the producer's deployment. Nothing on the wire distinguishes a key held apart from one the artifact could reach: the same bytes, the same signatures, the same tier. The specification places the value of the tier on that separation and leaves the separation to consumer key policy, which is where it can be checked |
| L1527 | Every site at which the substrate drops an observation rather than emitting it MUST increment `aeeDropCount` | **(b) untestable** | The document rules on this itself two sentences earlier: "Two producer obligations travel with it and neither is checkable by a verifier." A verifier sees the count the producer wrote and never the sites that should have moved it. What IS checkable -- the count against its self-declared bound -- is condition `aee-c-65` and is forced |
| L1556 | Over-attribution is caught downstream at the row, by the `attackResults` rule that a producer MUST NOT reference a record from a row whose attack the record's committed payload does not evidence | **(c) not normative** | A pointer added under `aeeObservedAttacks` so that a reader meeting the seal first does not finish it believing the seal carries the attribution guarantee. The rule is stated normatively under `attackResults` at L931-934, which is where the corpus addresses it; this sentence imposes nothing of its own, and citing it separately would make one obligation look like two. Of the two halves it names, the `pinned` half is checked by the coverage validity requirement and the `paired` half the document declares outside every gate in the same breath |
| L1700 | A verifier MUST NOT rank the values of a producer-defined ordered axis and MUST NOT compose it by weakest input | **(a) citation** | Forced by `v7400cd757fd046e9`, which now anchors `L1700-1703` in the accept index's `spec` column -- the whole rule, subject through both `MUST NOT`s, rather than the opening line it was first drawn on. A covering interception payload carries `exampleFidelity: "reconstructed"` beside a signed `aeeMethod` of `intercepted`; a rail that folds the member into the weakest-input method composition reports `method-cap-exceeded` on a statement no requirement refuses. `ok-021` carries producer members too, but content-free ones, so it forces only that such a member does not stop the record covering. The measurement reads the sentence as cited, and the `forcible-but-unforced` declaration that stood in for it is deleted |
| L1792 | The date-time separator and zone designator MUST be uppercase, and the zone designator MUST be `Z`, `+00:00` or `-00:00` | **(a) citation** | Forced already by six vectors -- `bad-727`, `bad-750`, `bad-751` on `armedAt` and `bad-820`, `bad-821`, `bad-822` on `issuedAt` -- every one of which anchored L1784, the line that names the field. Condition `aee-c-85` now anchors `L1784; L1792-1795` and states the profile rather than only the requirement to carry the field. Proved by `scripts/uncited-obligations-proof.py`: a rail that keeps RFC 3339 and drops the two choices this sentence pins fails exactly those six and no others |
| L1837 | A consumer MUST pin, out of band, the set of assessment classes it requires, and at consumption MUST compare it against `coverage.assessedClasses` | **(b) untestable** | The document names this as the one obligation in its section "whose value a consumer must derive from what it wants rather than from what a producer published". The pinned set is not in the statement and provably must not be: a demand read out of the producer's own bundle is not a demand. No vector can carry it |
| L1857 | A consumer that demands no class MUST record that decision explicitly and MUST NOT fold it into the corpus and substrate pins | **(b) untestable** | An obligation about how a consumer records a policy decision. Nothing about it reaches the wire, in either direction |
| L1935 | A policy relaxed to admit `pass_indirect` MUST keep the row-level rule | **(c) not normative** | The sentence sits inside `### Consumer policy example (non-normative)` (L1896-L1942), a section the document declares non-normative in its own heading, and it is the only RFC 2119 keyword in that section. Proposed replacement: "a policy relaxed to admit `pass_indirect` needs to keep the rule, because the token states that some clean row is indirect and never which one." The substantive claim is unchanged; the keyword is what does not belong in an example |
| L2011 | A consumer that consumes `result` or credits any row MUST evaluate coverage validity first | **(c) not normative** | Changelog restatement of row 3 (L625), inside `## Changelog and Migrations`. The rule is stated normatively in the body and forced there. Proposed replacement: "...had to be evaluated first, and a violation made the attestation invalid, independent of any consumer" -- past tense, describing what 0.6 changed, which is what a changelog does |
| L2035 | Coverage payloads MUST be canonical `+json` | **(c) not normative** | Changelog restatement of conditions `aee-c-17` and `aee-c-19`, forced by `v85caf3c6f7516ba2` and `vbea799eb2cd2852c`. Proposed replacement: "coverage payloads became canonical `+json`" |
| L2198 | Three members become REQUIRED and a record that was conditionally required becomes unconditional | **(c) not normative** | `REQUIRED` here is describing a schema change, not imposing one; the requirements themselves are stated at the members and forced by `bad-968`, `bad-974`, `bad-975`, `bad-977` and the `aee-c-96` family. Proposed replacement: lowercase "required", which removes the keyword without touching the sentence |
| L2304 | A member of producer territory now MUST NOT affect structural validity, `result`, or the evidence tier | **(c) not normative** | Changelog restatement of L1695-1703, which states it normatively and is forced by `ok-021` and now `ok-054`. Proposed replacement: "...is now stated to affect neither structural validity, nor `result`, nor the evidence tier, whether or not its values can be ordered" |

### SHOULD-bearing sentences

| Line | The sentence, in short | Disposition | Reason |
|------|------------------------|-------------|--------|
| L191 | The run-binding pre-image SHOULD additionally fold in a publicly datable unpredictable value | **(b) untestable** | The pre-image inputs are fixed by `aeeBindingVersion`, so a folded round changes no byte a verifier reads; the round reference travels as producer vocabulary, which by L1695-1703 nothing normative may read. A vector carrying one and a vector carrying none derive the same verdict, which is the definition of a sentence no vector can decide |
| L303 | The substrate SHOULD carry its own attestation | **(b) untestable** | A statement about a second artifact in the producer's supply chain. Nothing in an AEE statement carries or could carry it |
| L634 | A verifier SHOULD report the unmet existence requirement as its primary condition, and any refusal naming the defective record's kind beside it rather than in its place | **(a) citation** | Forced already, cited by nothing until this re-vendor. `vd538496f284b4761` is the witness: its only sealed record reports the moat down, so the existence requirement and its universal partner are unmet by the same record, and the vector declares `sealed-record-absent` alone with `sealed-covers-nothing` in `also carries`. It now anchors `L586-594; L595-608; L634-643; L1361-1366`. Proved by mutation: a rail that reports only the refusal naming the defective record's kind, in place of the unmet existence requirement, fails `bad-1017` and no other vector, so the forcing set is exactly one |
| L1116 | A `fail` whose supporting rows are all `artifact` SHOULD be treated as a weaker claim, and a consumer MAY reject it | **(b) untestable** | A consumer-side reading, and one the same sentence makes optional. The format half -- that the basis is on the wire per row and the tier derives from it -- is forced by `vcf5a4601dee5c2ee` and `v9cc570167acf4ae8`. What a consumer then does with it is policy, and a vector that demanded either behaviour would refuse a conforming rail |
| L1146 | A result resting on any `reconstructed` clean row SHOULD be read as tolerating transients | **(c) not normative** | This is guidance to a human reader about what a result means, not an obligation any implementation can meet or miss. The checkable half is the `pass_indirect` token, which is normative elsewhere and forced by `ok-006`, `ok-044` and `ok-045`. Proposed replacement: "A result resting on any `reconstructed` clean row tolerates transients between the observed states, and a result resting on any `artifact` clean row is self-reported absence, the weakest" |
| L1875 | The conjoined admission result SHOULD say so when a consumer declines either optional requirement | **(b) untestable** | An obligation on what a verification surface reports to its own operator, downstream of the verdict this corpus checks. The harness contract reads a verdict, a code set, a result and a tier list; nothing in it carries an admission narrative, and widening it to carry one would dictate a user interface to every rail |

## Why a citation now costs the same as a vector

The first version of this file closed four rows with a citation and one with a
vector, and only the vector was proved. That asymmetry was the defect, because a
citation is the cheaper of the two by a wide margin: it is a line range typed
into an anchor column, it raises the measured coverage the instant it is typed,
and nothing checked it. `scripts/spec-anchor-gate.py` says so in its own
docstring -- it is "deliberately weaker than checking the anchor against the
wording of the claim beside it" -- and the aim question it does ask is asked
only of registry decisions, never of the per-vector and condition-registry
anchors all four citations were written into.

So the claim was attacked rather than reviewed. An anchor reading `L1837-1860`
was appended to `v03547f8918e0d7dc`, a vector about a dropped
corpus manifest, naming rows 10 and 11 above -- two consumer obligations this
file rules structurally untestable by any conformance vector. The measurement
rose from 55 obligations cited to 57. `scripts/spec-anchor-gate.py` pinned the
new span and reported 846 anchors holding; `--sync` reported that no anchor
addressed different text than the ledger recorded; the condition registry,
distinctness and regenerability gates passed; both rails ran 250 of 250 green. A
fabricated citation and a correct one were indistinguishable to every check in
the corpus, and the fabricated one was worth two obligations.

Two things now stop it, both in `scripts/uncited-obligations-proof.py`.

**Each citation is paid for by a mutation.** A rail is built that stops
enforcing exactly what the cited sentence says, and the corpus must go red at
the vectors named and no others. Doing this corrected two rows: L625 is forced
by `bad-208` as well as `bad-201`, and L1031 by `bad-714` as well as `bad-106`
and `bad-107`. Each row above now names its full forcing set, because pinning
the set is what fails the day one of those vectors is rewritten into something
that no longer forces the rule.

**A ratchet pins the measured set itself.** The obligation-bearing sentences
that vector anchors cite are recomputed from the specification and the two index
files and compared against a set on record: forty-one lines inherited, plus the
four paid for here. A line entering that set without an entry fails and is
printed with the sentence it would have claimed; a line leaving fails too, since
a citation dropped by a re-vendor reads exactly like one that was never there.
`scripts/uncited-obligations-proof-test.py` is the mutation proof for the
ratchet: a fabricated anchor, a widened anchor, a deleted citation, a
re-split specification and a mutation that did not run each drive it red with a
named phrase, against a control that passes.

## Open items this work did not close

**A negative index on a non-substrate row is admitted by both rails.** L946
says every index MUST be in range, and a negative index is not in range. The
harness records the narrower reading in a comment -- "Negative indexes stay the
substrate `ref-malformed` path's concern" -- and `cmd/aee-verify` agrees with
it, so a statement violating the sentence as written passes both rails today.
Probed directly: an artifact row carrying `observationRefs: [0, -1]` against a
two-record statement is `valid` on the Go rail and carries no code on the
reference rail, while the same row carrying `[0, 7]` is `ref-out-of-range` on
both. Closing it needs, in order: a reading recorded in the interpretation
registry (is the narrow scope deliberate?); if it is not, `_check_refs_in_range`
in `packaging/run_vectors.py` and its counterpart in `cmd/aee-verify` extended
to negative indexes; then a vector `bad-XXX-artifact-row-ref-negative`, parent
`ok-029`, condition `aee-c-11`, expected code set `{ref-malformed,
ref-out-of-range}`. All three files are outside this work's ownership, which is
why the item is written down rather than done.

**An accept vector can cite a specification span, and now does.**
`vectors/accept/INDEX.md` carries a `spec` column on every row, appended after
`exercises` so that every positional reader of the first four cells is untouched,
and `v7400cd757fd046e9` anchors `L1700-1703` on it. The measurement counts that
sentence as cited, the `forcible-but-unforced` declaration for it has been
deleted from `spec/READINGS.toml` as no longer true, and the changelog
restatement at L2304 keeps its own declaration on its own merits rather than as
cover for an unforced obligation. Nothing in the reader changed: it takes spans
from every cell of every vector row, so the column was picked up by being
written. Every obligation whose only possible instrument is an accept vector is
now reachable by the same route.

The thing that column lacked is closed, and closing it cost more than the one
line this paragraph used to ask for. `scripts/spec-anchor-gate.py` collects
anchors from `AUTHORED` and `GENERATED` only and `vectors/accept/INDEX.md` was
in neither, so `L1700` was pinned by nothing. The index is generated, so the
file that belongs in `AUTHORED` is `vectors/accept/gen_valid_vectors.py`, whose
anchor map is the source of that cell; putting the index there instead fails,
because a generated table is checked against the source it was generated from
and that source was in neither list either. Both are now listed, the map's entry
is keyed by an owner pattern for its slug, and `spec/ANCHOR-PINS.json` carries
two new pins for the span.

The anchor was `L1700` when those pins were first written, and the pin is what
made the drawing readable: its `closes` excerpt repeated its `opens` excerpt,
because the span was one line long while the rule it cites runs to four. The
line names the rule's subject and the sentence's two `MUST NOT`s land below it,
so the anchor read as covering an obligation it stopped short of. It is
`L1700-1703` now, and the pin's `closes` carries the second `MUST NOT`, which
is the shortest available proof that the span reaches the rule. The alternative
was to narrow `scripts/uncited-obligations-proof.py`, which had cited the whole
rule all along, and the corpus decides against it: anchors here are ranges far
more often than single lines, a single line is used where that line carries the
obligation, and suiteRevision 25 records widening four anchors for exactly this
reason -- rules enforced while the anchor named a different line, which reads as
covered and is not. Swept across all three indexes at the time this was drawn,
no other span opened a sentence bearing a normative keyword and closed before
the keyword landed.

Two further readers had to be fixed for the pin to mean anything. The vector-row
selector in the same gate was still spelled `bad-\d` and matched none of the two
hundred and nine reject-index rows, so no vector row in either index was being
compared against its own source row; it reads `VECTOR_ID_PATTERN` now, and the
gate prints how many generated anchors got the per-row question on every run so
that a selector going dead moves a published number. And `ANCHOR_PATHS` in
`scripts/vendor-spec.py` omitted the accept generator, so a real re-vendor would
have moved this line out from under an anchor it never touched -- which is what
the gate's re-vendor test began refusing the moment the anchor was pinned.

The second half of this item -- a row regex matching ``| `ok-`` against an index
that writes `| ok-`, so that it read zero accept rows either way -- is closed.
Both per-vector readers in
`scripts/reading-differential.py` find their rows through
`gen_manifest.table_rows`, by the table whose first column is called `vector`,
and that function refuses a row it cannot read instead of skipping it. The
reject reader had the identical defect and it was live: keyed on the retired
`bad-` prefix, it matched nothing once identifiers became content addresses,
reported an empty citation index in silence, and layer 0 called five obligations
uncited that five reject vectors cite by line range. A citation source keyed on
a vector NAME is the bug; names are content addresses now and will move again.

**The reverse question is still open.** The same measurement reports that 62 of
98 condition-registry spans contain no RFC 2119 sentence at all, so the
condition-to-specification link is paragraph-level in both directions. This file
addresses only the sentences nothing cites.

## Re-deriving the state of this file

```
python3 measure_sentence_coverage.py   # a private script in the consuming repo
python3 scripts/uncited-obligations-proof.py                            # the two vectors, proved
python3 packaging/run_vectors.py                                        # reference rail
python3 packaging/run_vectors.py --verifier "./aee-verify -validity-only -json"  # external rail
```

At the time of writing the measurement reads 55 of 67 obligations and 2 of 7
SHOULDs cited, up from 51 and 2, with the twelve remaining obligations being
rows 1, 2, 6, 7, 8, 10, 11, 12, 13, 14, 15 and 16 above -- one attribution
artifact, four untestable, one awaiting an accept-index anchor column, and five
that should not carry an RFC 2119 keyword at all.
