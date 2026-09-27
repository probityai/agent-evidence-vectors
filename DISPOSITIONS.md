# Disposition of comments

Every objection this suite has received from someone who is not its author, what
was decided about it, and why. One entry per objection, published with each
release, kept permanently.

The reason to publish this is not politeness. A conformance suite asks a stranger
to accept that a set of bytes decides whether their implementation is correct,
and the only evidence a stranger has about how that set is maintained is what
happens when somebody disagrees with it. A changelog says what changed. It does
not say what was proposed and refused, which is the half that tells a reader
whether the change process is real. So this file carries the refusals too, and
carries them in the objector's frame rather than in the resolution's.

**A disposition table that records only the objections its author was pleased to
accept is worse than no table**, because it reads as evidence of scrutiny while
being evidence of selection. The row to read first is therefore the declined one.
It is a live divergence between this suite's reference rails and the one
implementation independent of them, on a sentence that genuinely did not decide
the question; the objector was right that the text was silent and the resolution
went the other way anyway, with the reason stated and the reversal condition
recorded. If that row were missing, nothing else here would be worth reading.

## What a row is, and what it is checked against

Three fields carry the weight: **the objection**, stated as its author framed it;
**the resolution**, from a closed vocabulary that includes declining; and **the
reason**, which is the argument and not the outcome restated. A residual is
required wherever the resolution leaves something unsettled, so a partial
disposition cannot absorb a gap behind a status word.

Rows are not free prose. The ledger is `docs/DISPOSITIONS.json` and
`scripts/dispositions-gate.py` refuses a row whose landing revision is not one
`vectors/CHANGES.md` carries, whose forcing vectors are not in
`vectors/MANIFEST.json`, or whose cited record no longer contains the phrase the
row quotes from it. The table below that line is rendered from the ledger and
diffed against it, so editing the table alone changes what a reader sees and not
what the gate reads:

```
python3 scripts/dispositions-gate.py            # check every row and the table
python3 scripts/dispositions-gate.py --render   # rewrite the rendered span
```

That command is also the only source for any count of these rows. No number about
this ledger is written by hand, here or anywhere else in the repository; the gate
prints the tally by resolution on every run.

**One honest limit on the rows themselves.** Standards practice states an
objection verbatim beside its resolution. Every row below predates this ledger and
none was captured that way at the time, so each is transcribed from the repository
record that carries it and is labelled `paraphrased-from-the-record`. From the
first release after this file exists, an objection is recorded in the words its
author used, and a row labelled `quoted` carries those words unedited.

## If you disagree with a disposition

Say so in the issue tracker of this repository, or in the upstream pull request
that carries the predicate specification, or in the tracker of any implementation
of it. Every one of those is public and none of them can be edited after the fact.
A disagreement raised anywhere becomes a row here with its own identifier,
including a disagreement about a row already in this file — a second row citing
the first, never an edit to it, because the ledger is append-only and a
disposition that can be quietly rewritten is not a disposition.

**What this repository cannot offer today is an appeal to anyone other than its
maintainer**, and it is better to print that than to imply otherwise. The
resolution of every row below was decided by the person who wrote the artifact
being objected to. The only routes that do not run through him are the ones
outside his control: the upstream specification's own review thread, where the
predicate is settled by people who are not him, and any independent
implementation's tracker, where a divergence can be recorded whatever this
repository decides. A genuinely independent appeal needs a steward that does not
exist yet. That is the limit, stated as a limit and not as a plan, and it is the
one property in `GOVERNANCE.md` that a reader should treat as unmet.

## What this ledger cannot catch

**Omission.** The gate runs one way. It stops a row being invented, because every
row has to resolve against a record already in this repository — a revision that
exists, a vector that exists, a phrase that is still present in the file it is
attributed to. Nothing here can tell that an objection was received and never
written down. That asymmetry is structural and no amount of checking closes it;
the only party who can see a missing row is the person whose comment is missing,
which is why the section above matters more than this one.

**Paraphrase.** A row labelled `paraphrased-from-the-record` is this author's
account of somebody else's objection, checked against a contemporaneous record
and still this author's account. The label is on every such row so a reader can
weigh it, and the fix is prospective rather than retrospective: the rows are not
going to be re-elicited years later, and pretending to quote what was never
quoted would be worse than the paraphrase.

**Objections nobody made.** A suite with one independent implementation receives
the objections one reader happens to find. Every row below comes from the same
person, which is a statement about how thin the review of this artifact has been
and not a statement about how few faults it has. The independence column in
`README.md` makes the same point about scores; it applies at least as strongly
here.

---

<!-- rendered from docs/DISPOSITIONS.json by scripts/dispositions-gate.py -->

| # | Raised by | Where | Resolution | Landed | Forcing vectors |
| --- | --- | --- | --- | --- | --- |
| DC-01 | Rul1an | in-toto/attestation#570 | **adopted** | suiteRevision 4 | `v08251931ec038e91` |
| DC-02 | Rul1an | Rul1an/aee-checker#3 | **adopted** | suiteRevision 6 | `vb2af33bb3cc0da77`, `v83f4b7fe6068ef86` |
| DC-03 | Rul1an | in-toto/attestation#570 | **declined** | suiteRevision 2 | `v70e970d18ae52833` |
| DC-04 | Rul1an | in-toto/attestation#570 | **adopted** | suiteRevision 2 | `v1b0b0cafb5ee8d08` |
| DC-05 | Rul1an | in-toto/attestation#570 | **adopted** | suiteRevision 2 | `vf14f5310b2f02875` |
| DC-06 | Rul1an | in-toto/attestation#570 | **adopted** | suiteRevision 2 | `v423dab49f4ed4d29` |
| DC-07 | Rul1an | in-toto/attestation#570 | **adopted** | no corpus revision | none |
| DC-08 | Rul1an | in-toto/attestation#570 (round 8) | **adopted** | suiteRevision 3 | `vb3c92d4ecb62bbfb`, `ved230b46692c0ada` |
| DC-09 | Rul1an | in-toto/attestation#570 | **adopted** | suiteRevision 2 | `v164cf7f3f529eaff`, `v692f9605520a617d`, `v5a842871df5bfe33` |

### DC-01 · in-toto/attestation#570

**Raised by** Rul1an, author of Rul1an/aee-checker, the only implementation of this specification independent of its author. **Date** not recorded: the round is recorded in vectors/CHANGES.md; this repository did not transcribe per-comment dates before suiteRevision 5.

**The objection** (paraphrased-from-the-record). The specification states no maximum JSON nesting depth, so an implementer has to choose one. This checker chose 256 where the reference rails had chosen 128, which makes the same bytes valid evidence to one conformant verifier and malformed to another.

**Resolution: adopted.** An unstated bound is not an implementation preference; it is a parity failure the document has to decide, because two verifiers disagreeing about identical bytes is exactly the outcome a conformance suite exists to prevent. The bound was made normative at 128 with its counting rule stated beside it, in the vendored specification rather than only in the rails, so a from-spec reader reaches it without seeing any implementation.

**Note.** The corpus did not exercise the new rule at the revision that made it normative, and the changelog entry says so in its own words rather than leaving a reader to discover it. The vector arrived at the next revision, and the boundary case at the one after that, under DC-02.

**Recorded in** `vectors/CHANGES.md`, `docs/ADOPTION.md`.

### DC-02 · Rul1an/aee-checker#3

**Raised by** Rul1an, author of Rul1an/aee-checker, the only implementation of this specification independent of its author. **Date** 2026-07-28.

**The objection** (paraphrased-from-the-record). The vector that pins the bound sits well past it, and that is the one shape a verifier counting depth per parsed value also rejects. A constant-only fix and a correct counting rule therefore score the same against this corpus, so the vector does not test what its entry says it tests.

**Resolution: adopted.** The objection is about discrimination rather than about a verdict, and it was right: nothing in the corpus sat at the boundary. An accept vector at the exact bound and a reject vector carrying an empty-container leaf one level past it separate the two counting rules, because a verifier that charges depth per parsed child never charges an empty container its own level.

**Note.** The pair also closed a split between this repository's own two reference rails, which had disagreed on identical bytes at one exact depth for as long as both existed. Five rails written by one author could not show it to each other; one outside reader surfaced it on contact.

**Recorded in** `vectors/CHANGES.md`, `docs/ADOPTION.md`.

### DC-03 · in-toto/attestation#570

**Raised by** Rul1an, author of Rul1an/aee-checker, the only implementation of this specification independent of its author. **Date** not recorded: recorded as an open corner in docs/interpretation-decisions-open.md rather than as a dated comment.

**The objection** (paraphrased-from-the-record). A class named in both the assessed set and one of the gap maps should be tolerated. The text requires the sets to be complete over the manifest's classes and does not say they are disjoint, so a completeness-only reading is conformant, and this checker accepts what the reference rails reject.

**Resolution: declined.** A class declared both assessed and disclosed as a gap is a contradiction about the same class, and the recompute must not be asked to arbitrate it. The disjoint-partition reading the rails already implemented was kept, and the specification text was changed to state it, so the divergence is settled in the document rather than left standing as two conformant readings of one sentence. Declining the objection while changing the text is the whole of the disposition: the objector was right that the sentence did not decide, and wrong that the tolerant reading is the one to adopt.

**Residual.** This is the one editorial call among the corners raised at that revision, and it is recorded as reversible at vetting. Nothing about the corpus forces the direction; a later decision to tolerate the overlap would retire this vector and change the text, and it would not be a defect in either reading.

**Recorded in** `docs/interpretation-decisions-open.md`, `vectors/CHANGES.md`.

### DC-04 · in-toto/attestation#570

**Raised by** Rul1an, author of Rul1an/aee-checker, the only implementation of this specification independent of its author. **Date** not recorded: recorded against decision 8 in docs/interpretation-decisions-open.md rather than as a dated comment.

**The objection** (paraphrased-from-the-record). The arming timestamp reads as requiring a zero offset, because the text says UTC. The reference rails accept a non-zero offset and compare the two timestamps as instants, so a statement they admit is one this checker refuses.

**Resolution: adopted.** This one is not an editorial call at all: the text already mandated UTC, so accepting an offset was a rail defect rather than a permitted reading, and it was fixed in both rails with the zone pinned explicitly in the text.

**Note.** The fix was half a fix and stayed half a fix for eight revisions, which the repository record now says plainly. The rule was written on one field and applied at one call site, so the sibling timestamp carried no zone rule at all and the sentence that pinned the zone never pinned the case of the designator. Both halves closed at suiteRevision 10 by running every timestamp through one parse that carries the whole profile.

**Recorded in** `docs/interpretation-decisions-open.md`, `vectors/CHANGES.md`.

### DC-05 · in-toto/attestation#570

**Raised by** Rul1an, author of Rul1an/aee-checker, the only implementation of this specification independent of its author. **Date** not recorded: recorded as an open corner in docs/interpretation-decisions-open.md rather than as a dated comment.

**The objection** (paraphrased-from-the-record). Two rows carrying the same attack identifier: the specification does not say whether that is a union or a malformed statement, and an implementer has to choose without the text deciding for them.

**Resolution: adopted.** One row per executed attack is a well-formedness invariant, and the coverage comparison is set-based, so a duplicate collapsed silently and every rail accepted it. Two contradictory rows about one attack are exactly the ambiguity the recompute must refuse rather than resolve. The uniqueness sentence went into the text and both rails now detect the duplicate before the set comparison runs.

**Recorded in** `docs/interpretation-decisions-open.md`, `vectors/CHANGES.md`.

### DC-06 · in-toto/attestation#570

**Raised by** Rul1an, author of Rul1an/aee-checker, the only implementation of this specification independent of its author. **Date** not recorded: recorded as an open corner in docs/interpretation-decisions-open.md rather than as a dated comment.

**The objection** (paraphrased-from-the-record). A statement whose rows are all artifact-basis carries two subjects. Legal or malformed? The cardinality rule reads as scoped to statements carrying substrate rows, and nothing says what the artifact-only case means.

**Resolution: adopted.** One executed artifact per statement is the model everywhere else in the document, and a two-subject artifact-only statement has no coherent reading. The cardinality requirement was made unconditional and only the binding-digest inputs stayed scoped to substrate-carrying statements. Both rails had enforced cardinality only under the substrate condition, so this was a live gap rather than a clarification.

**Residual.** The direction, unconditional against substrate-scoped, is recorded as an editorial call reversible at vetting. The gap it closed is not reversible; only the scope of the requirement is.

**Recorded in** `docs/interpretation-decisions-open.md`, `vectors/CHANGES.md`.

### DC-07 · in-toto/attestation#570

**Raised by** Rul1an, author of Rul1an/aee-checker, the only implementation of this specification independent of its author. **Date** not recorded: recorded in docs/interpretation-decisions-open.md as raised in the round-8 discussion.

**The objection** (paraphrased-from-the-record). The registry of forced readings is an answer key if it is read before implementing. An independence claim made by someone who read it first is worth less than one made without it, and nothing in the repository said so.

**Resolution: adopted.** The objection is about what a claim of independence means, which is the property this suite's whole citation case rests on, and the fix costs nothing but has to be said out loud. The registry is a post-run reconciliation surface: it shows where two committed readings diverged without either author arbitrating, and it is not an answer sheet to consult beforehand. The document now states that a genuinely independent conformance result is one produced without reading the registry, the rail source, or the manifest's expected condition codes.

**No corpus revision.** A statement about what an independence claim means, recorded in the document that carries the registry. It changed no vector and bumped no revision, and a row that invented a landing revision to look tidier would be a false entry.

**Note.** Every figure this suite publishes for that implementation is now labelled blind or directed on its author's own reading of the run, and one of them is labelled directed because its author said so and the label would otherwise have been ours to choose.

**Recorded in** `docs/interpretation-decisions-open.md`.

### DC-08 · in-toto/attestation#570 (round 8)

**Raised by** Rul1an, author of Rul1an/aee-checker, the only implementation of this specification independent of its author. **Date** not recorded: the round is recorded in vectors/CHANGES.md; this repository did not transcribe per-comment dates before suiteRevision 5.

**The objection** (paraphrased-from-the-record). The partition rule reads in both directions over all three coverage sets, and this corpus forces it on one of them. The other two are an untested consequence of a rule the text already states.

**Resolution: adopted.** An untested consequence of a written rule is precisely the class of gap an outside reader can see and an author cannot, because the author knows what the rails do. Both rails already enforced it, so no behaviour changed; what changed is that a third party is now obliged to implement it, which is the only thing a vector can be for.

**Recorded in** `vectors/CHANGES.md`, `docs/interpretation-decisions-open.md`.

### DC-09 · in-toto/attestation#570

**Raised by** Rul1an, author of Rul1an/aee-checker, the only implementation of this specification independent of its author. **Date** not recorded: the eleven decisions were posted with the implementation rather than as dated comments.

**The objection** (paraphrased-from-the-record). These are the readings an outside implementer had to commit to in order to implement the text at all, recorded as a list. Several of them are rules the document states and the corpus never exercises.

**Resolution: adopted.** A list of the readings an outside implementer was forced to make is the most useful thing a specification author can be handed, because each entry is a place the text either decided something and was not tested or failed to decide at all. Three of them became forcing vectors in the same revision and the whole list became a machine-readable registry with a gate over it, so a later revision cannot quietly stop locking one.

**Note.** A fourth corner recorded at the same time, out-of-range references on artifact rows, needed no change: the corpus already locked it.

**Recorded in** `vectors/CHANGES.md`, `docs/interpretation-decisions-open.md`.

<!-- end rendered -->
