<!--
Implementation report for the AEE v0.7 predicate conformance suite.
Corpus SSOT: vectors/MANIFEST.json (suiteRevision 30, 277 vectors: 61 accept, 214 reject, 2 indeterminate).
Honest scoping: every claim below states exactly what each implementation was verified against.
Independence is counted by authorship, not by implementation count; see "How independence
is counted here" before adding any row to the table.
-->
# AEE v0.7 implementation report

A W3C-style "multiple independent interoperable implementations" report for the
Adversarial Execution Evidence predicate (in-toto/attestation PR #570). The
purpose is one claim, made honestly: the specification is determinate enough that
a party who did not write it, working in a different language, reaches the same
verdict on the same bytes.

## How independence is counted here

Independence is a property of authorship, not of implementation count. Six
implementations clear this corpus and one author wrote five of them. Those five
share a single reading of RFC 8785 and RFC 7493, so when they agree they have
confirmed that the reading was transcribed consistently across five languages,
which is worth having and is not the claim this report exists to make. A
misreading of the text produces the same agreement.

**The count of implementations independent of the specification's author is one:**
`Rul1an/aee-checker`. Every determinacy claim below rests on that column and on
nothing else. The first-party rails appear because a conformance suite should
state what it actually runs, not to be counted toward independence.

A measured instance of why the distinction matters: the specification did not pin
a maximum JSON nesting depth, so all five first-party rails chose 128 and agreed
at every depth, while the independent checker read the same text and chose 256.
For the 127 depths between them, identical bytes were valid evidence to one
conformant verifier and malformed to another. No amount of first-party agreement
could have surfaced that; the outside implementation surfaced it immediately. The
bound is now normative at 128 and the checker adopted it (suiteRevision 5,
149/149). Reading it back also surfaced a second split the first-party rails hid
from each other: the reference Go rail charged nesting depth per parsed child, so
an empty-container leaf slipped one level past the bound while the Python rail
rejected it — our own two rails disagreeing on identical bytes at one exact depth,
fixed this round and now pinned by a boundary vector pair.

The same shape recurred at suiteRevision 9 and is worth recording, because it
says something about what a corpus can and cannot see. A newly landed condition
(a record's `signatures` member must carry at least one entry) had one vector,
that vector carried one fault, and every rail passed it. Two rails were
nonetheless answering differently: one asked the entry count per record inside
its payload-decode loop rather than once over the record set, so a statement
whose first record failed to decode and whose second carried no signature
reported a different condition there than everywhere else; and one decoded the
member into a typed list, so a member of the wrong JSON type reported the parse
catch-all instead of the condition. Neither divergence was reachable by a
single-fault vector or by a vector testing only the empty-array spelling, which
is the general lesson: a condition is under-tested until the corpus reaches every
spelling of it and fixes its precedence against the conditions it can collide
with. Both rails were corrected and both readings are now pinned.

## Reference corpus

`vectors/MANIFEST.json`, suiteRevision 30: **277 vectors (61 accept, 214 reject, 2 indeterminate)**.
Each accept vector must verify valid with its expected `result` token; each reject
vector must be invalid with a failure code drawn from the manifest's code set. The
corpus is regenerated deterministically from the generators and its vendored spec
digest is pinned and CI-checked (`scripts/spec-drift-gate.py`).

## Implementations

| Implementation | Language | Author | Verified against | Result |
|---|---|---|---|---|
| Reference rail (`aee/`) | Go | spec author | reference corpus, suiteRevision 30 | **277 / 277** |
| Reference rail (`packaging/run_vectors.py`) | Python | spec author | reference corpus, suiteRevision 30 | **277 / 277** |
| `Rul1an/aee-checker` | Rust | **independent, from-spec text alone** | author-run suiteRevision 6 (153), 2026-07-28 (aee-checker#4), suiteRevision 22 (232), 2026-08-03 (`reports/v0.7-RUN.md`), suiteRevision 25 (250), 2026-08-12 (in-toto/attestation#570) and suiteRevision 28 (272), 2026-09-06 (aee-checker#21); suiteRevisions 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 26, 27 and 29 not run by its author | **272 / 272** at suiteRevision 28, directed; **250 / 250** at suiteRevision 25, directed; **179 / 232** blind and **232 / 232** directed at suiteRevision 22; **153 / 153** at suiteRevision 6, directed; **125 / 125** blind at suiteRevision 1; suiteRevisions 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 26, 27 and 29 not run by author (see note 1) |
| `ts-verify` | TypeScript | spec author | its vendored set (272 vectors) + cross-rail parity tests | pass (see note 2) |
| `py-verify` | Python | spec author | its vendored set (272 vectors) + parity tests | pass (see note 2) |
| MCP server rail `_aee.py` | Python | spec author | its vendored set (272 vectors) + parity tests | pass (see note 2) |

The five first-party rails are separate decompositions rather than shared code, so
they do catch each other's transcription errors, and the differential fuzzer over
them catches drift. What they cannot catch is a misreading of the specification,
because they inherit one. Read their agreement as a drift check, not as
corroboration.

The Rust checker is the load-bearing result: built from the spec text alone, with
its own I-JSON parser, RFC 8785 serializer, RFC 6962 Merkle root over DSSE PAE,
run-binding derivation, and Ed25519 tier, with no sight of the reference
implementation and no reading of the corpus condition codes.

## Feature coverage

Three eras. The **core** predicate and the **round-7** additions were read
independently first: the from-spec Rust checker re-ran against the round-7 corpus
(suiteRevision 2) and reached 138/138 after a spec-diff-led update (132/138 on the
unchanged build). The suiteRevision-3 corpus is a separate case and its figure is
not a spec-diff-led one: the same unchanged build cleared it at 140/140 on a first
run, with no change made for the two vectors that revision added, which is why the
ledger records it as first-run-unchanged-build evidence and as unprompted. Reading
the two together as one spec-diff-led result would spend the unprompted half of
this column on a pass that did not need it. It then cleared
the **suiteRevision-5** byte-level tier (`bad-733` through `bad-741`) at 149/149
once it adopted the normative depth bound and moved its counter into the container
branch (aee-checker#3, 2026-07-28). That is one independent reading of each era so
far, corroborated by the first-party rails rather than the other way round. The
**suiteRevision-6** additions, the two depth-boundary vectors and the two
noncharacter vectors below, have since been run as well, at 153/153
(aee-checker#4, 2026-07-28), but that run is directed in its author's own account:
the rule was written and the vectors named before that checker ran. It is evidence
that the corrected rule is implementable by a reader who has only the text, and it
is not evidence that a second reader arrived at the rule. The two readings should
not be added together. **suiteRevision 4** is a case of its own. No run was posted
at it, and note 1 records why that matters; but the two rules it made normative
are exactly the two the revision-5 byte-level tier exercises, so they are read
independently after all — in the directed revision-5 run above, not in the
140/140 that preceded them.

The third era is **v0.7**, and it is the largest reading this report carries. At
suiteRevision 22, on 2026-08-03, a build written from the pinned v0.7 text alone
scored 179/232 on its first run (accepts 8/54, rejects 169/176, indeterminate
2/2), and a directed pass reached 232/232, accepts 54/54, rejects 176/176,
indeterminate 2/2. That corpus contains every vector the suite gained across
**suiteRevision 7 through 22**: the signature-entry requirement `bad-745`
carries and the precedence and wrong-type spellings `bad-748` and `bad-749` pin,
the corpus manifest attack floor of `bad-746` and `bad-747`, the timestamp
profile, the version-2 run binding that re-minted every decodable record
identity, the fourth `result` value, the registered posture vocabulary, and the
vendored amendments that followed. The sentence that used to stand here, that
nothing after revision 6 had been read independently at all, is withdrawn rather
than softened.

What the two figures separate is what the blind half reached. Three of the rules
the directed pass implemented recovered no vector and the first run never reached
them, namely the registered `networkPosture.posture` vocabulary, non-empty `signatures`,
and `attribution` as a substrate-row validity requirement, each forced by a vector
of the 232 at suiteRevision 22 (`bad-823`, `bad-745`, `bad-968`), so their correctness in this
run is directed and says nothing about whether the text determines them. The
report corrects its own earlier claim that no vector was a blind mismatch on any of
them: `ok-047` and `ok-048` are attribution vectors and both were blind
mismatches. The directed pass also followed an adversarial review of that
implementation for `bad-902`, which caught a covering check comparing the pinned
posture conjunct and dropping the arming-record one, which is half of a sentence that
draft had quoted. So the reading to take from this era is the author's own: the
directed 232/232 is not evidence about the determinacy of the text, and the blind
179/232 is.

| Feature | Go ref | Python ref | Rust (3rd-party) | TS rail | MCP rail |
|---|---|---|---|---|---|
| I-JSON / RFC 8785 canonical payloads | yes | yes | yes | yes | yes |
| RFC 6962 batch root over DSSE PAE | yes | yes | yes | yes | yes |
| `result` recompute (pass/degraded/fail) | yes | yes | yes | yes | yes |
| Evidence tier (declared/unattested/attested) | yes | yes | yes | yes | yes |
| The 17 interpretation decisions | yes | yes | 1–16 | yes | yes |
| chain-scope machine-comparable array (round-7) | yes | yes | yes | yes | yes |
| statement-wide strict I-JSON (round-7, decision 11) | yes | yes | yes | yes | yes |
| read-first `aeeBindingVersion` (round-7) | yes | yes | yes | yes | yes |
| out-of-range refs fail-closed any row (round-7) | yes | yes | yes | yes | yes |
| `armedAt` zero UTC offset (round-7, decision 8) | yes | yes | yes | yes | yes |
| corners A/B/C: dup attackId / partition / cardinality | yes | yes | yes | yes | yes |

## Notes (the honest scoping)

1. **The author's run history, each record bound in that author's own provenance
   index to the checker source that produced it, with two exceptions this note names
   by name.** A blind first run at suiteRevision 1 scored 125/125. At
   suiteRevision 2 the unchanged build scored 132/138 and a spec-diff-led update
   reached 138/138 — the six diverging vectors were exactly the round-7 changes (two
   of which were defects in the checker, the rest spec-boundary adoptions). At
   suiteRevision 3 the same build cleared 140/140, on a first run against those
   vectors with no change made for them: its rule for the reason-map side came from
   the spec text and predates them, so the two met rather than one driving the
   other. The author is explicit that the suiteRevision-2 pass was not blind, since
   the changelog was read before implementing, unlike the 125/125.

   At suiteRevision 5 the checker scored 149/149 (aee-checker#3). The vector
   `v08251931ec038e91` had pinned the nesting bound at 128
   where that build read 256; it adopted 128 and, rather than only move the constant,
   moved the depth increment from per parsed value into the container branch, which
   is the counting rule the spec states next to the bound.

   **The last author-run is suiteRevision 6 at 153/153 (2026-07-28,
   aee-checker#4)**, 36/36 accepts and 117/117 rejects, on a record naming checker
   source `sha256:1c3e2e78` and suite commit `6aa7c60`, and it is the revision that
   checker's CI now verifies continuously. The unchanged revision-5 build scored 151/153
   against it: the depth-boundary pair `ok-036` and `bad-742` passed on the counter
   already moved, and `bad-743` and `bad-744` did not, because that build had
   not implemented the RFC 7493 section 2.1 noncharacter exclusion the revision makes
   normative. The run is recorded as directed, in the author's own wording: "the rule was
   written and the vectors named before this checker ran, so what it demonstrates is
   that the corrected rule is implementable from the text, not that an independent
   reader found it." This report carries that unsoftened.

   **The v0.7 run is suiteRevision 22, on 2026-08-03**, posted as
   `reports/v0.7-RUN.md` with two records in that provenance index. A build written
   from the pinned v0.7 text alone scored 179/232 on its first run at
   suiteRevision 22 (accepts 8/54, rejects 169/176, indeterminate 2/2), and a
   directed pass reached 232/232, accepts 54/54, rejects 176/176, indeterminate
   2/2. The report partitions the 53
   first-run mismatches by the message the blind build emitted, and says that is
   the only partition its published run records support: 42 report that
   `aeeRunBinding` does not equal the run binding derived from the statement, 7
   returned `valid` with no reason, and 4 report a carried `pass_indirect` against
   a recomputed `pass`. An earlier per-fix attribution published there is withdrawn
   rather than restated, because attributing a recovery to a particular fix needs a
   bisection against the blind build. The report claims no reason-parity figure for
   this run at all: the checker emits free prose and no condition codes, two
   constructions of a prose-to-code map over the same run disagreed sharply, and the
   ambiguity is published as a runnable script rather than resolved by picking one.

   **The blind half of that run carries no source digest, and it is the first of
   the two exceptions the head of this note names.** The directed build is recorded under
   checker source `sha256:56f440e6` against suite commit `4cd65a16` and reproduces
   from the author's working tree. The blind build does not: it was never committed
   on its own, one commit carrying both the v0.7 implementation and the published
   number, so no tree in that repository hashes to the build that produced 179/232
   and the figure is not independently reproducible, including by its author. The
   checker's `reports/INDEX.json` records that as an explicit null digest beside a
   `sourceUnrecoverable` field rather than borrowing the directed build's digest,
   which would name a different implementation, and records it as a breach of
   the rule that run's own protocol had fixed in advance. The suite commit does
   resolve in a fresh clone of this repository and carries the 232 vectors of
   suiteRevision 22. This report publishes the blind figure with that caveat
   attached and never without it.

   **The suiteRevision-25 run is 250/250, on 2026-08-12**, posted as a comment on
   in-toto/attestation#570 rather than as a run report in that provenance index.
   At suiteRevision 25 that is accepts 55/55, rejects 193/193 and indeterminate 2/2,
   with reason parity 69/193, against suite commit `97ba4ff`, whose manifest carries
   250 vectors in exactly that partition and the vendored spec digest `759d2383` the
   comment names. The run was verified on a clean runner at a public CI run that
   checks the spec digest before it counts anything. It is directed, and the author's
   own opening words are the reason this report records it that way: "Repinned and
   implemented first, then measured your open question." That record names the suite
   commit, the spec digest
   and the runner, and no checker source digest, so it is the second of the two
   exceptions the head of this note names, and this report states that rather than
   leaving a reader to assume a digest exists.

   **The run at suiteRevision 28 is 272/272, on 2026-09-06**, recorded in the
   checker's own provenance index by aee-checker#21, and at suiteRevision 28 that is
   accepts 61/61, rejects 209/209 and indeterminate 2/2, with reason parity 80/209,
   against suite commit `94c163c` as posted (`e98de66` after the 2026-09-18 history
   rewrite, which left its vectors unchanged), whose manifest carries the 272 vectors of
   suiteRevision 28 in that partition. The checker labels it
   revision 27 because it counts one run per corpus it read and it read
   suiteRevision 25 twice; the corpus at that commit opens its changelog at
   suiteRevision 28, and this report uses the corpus's number. The run is
   directed and pre-registered, and its author claims one property only: the
   build predates every vector in the corpus and its source digest did not move,
   so no vector-driven fix is possible in either direction. It called the checker
   on the vectors directly, not through this package's `--verifier` path, so the
   reference-rail fallback that 0.12.1 fixed could not have supplied the figure.

   The three figures that carry unprompted evidence are the blind 125/125 at
   suiteRevision 1, the first-run 140/140 at suiteRevision 3, and the blind
   179/232 at suiteRevision 22; no other figure here may be described that way. In
   particular the 138/138 was spec-diff-led and the 140/140 was not, and the two
   are not to be stated together as one result.

   **The checker has not been run against suiteRevision 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 26, 27 or 29, so this report
   publishes no score for it at any of them.** Three different things put a
   revision on that list, and only one of them is that the requirement went
   unexercised. Two of the five at the end of the list fall between that v0.7 run
   and the suiteRevision-25 one: suiteRevision 23 added sixteen reject vectors and
   a second declared condition on a seventeenth, and suiteRevision 24 moved the
   vendored text without moving a vector. The other two fall between the
   suiteRevision-25 run and the suiteRevision-28 one: suiteRevision 26 added eight
   boundary vectors and moved no vendored text, and suiteRevision 27 pinned what the
   reference rail emits beyond each reject vector's declared codes without changing
   a vector file. The suiteRevision-28 corpus carries every vector both added. suiteRevision 29 came after that run and added three reject vectors, one per empty predicate state.
   suiteRevisions 7 through 21 are a different case. Every vector they added is
   inside the suiteRevision-22 corpus that run covered, so the requirements they carry
   are not unread; what no record of that checker names is the corpus AT any of those
   revisions, and that is not a formality, because verdicts moved between them and
   a pass at one revision is not a pass at another. suiteRevision 4 is on the
   list for a third reason. Its corpus is the revision-3 corpus of 140 vectors,
   the same verdicts, the same codes — so the revision-3 run did put those bytes
   through the checker. What moved at revision 4 was the text: it made encoding
   well-formedness and the 128-deep nesting bound normative over a corpus that, in
   the words of its own changelog entry, exercised neither, so an implementation
   could pass it at 140/140 while getting both new rules wrong. One of them this
   checker did get wrong — when suiteRevision 5 published, it still read the bound as
   256, and aee-checker#3 is where it adopted 128 — which is the concrete reason a
   revision-3 pass is not a revision-4 pass. Recording revision 4 as run would
   assert a conformance no posted record carries. Every one of these cells reads
   "not run by author" until a record and its source digest are posted. An earlier
   edition of this note carried our own derived expectation for `bad-743`
   and `bad-744`; the author's run has replaced it, which is the outcome a derived
   expectation should always have.
2. **The consumer rails carry the suiteRevision-28 corpus.** The TypeScript rail,
   the standalone Python rail and the MCP server rail each vendor all 272 vectors of
   suiteRevision 28 byte-for-byte (`VENDOR-STAMP.json` pins the source spec digest,
   upstream commit and a content digest; a consumer-side drift gate fails CI on any
   change without a re-vendor). "pass" means the rail implements the rule, is
   parity-tested on it, and replays the full 272. The three rails are two vendored
   copies: the TypeScript rail and the standalone Python rail replay the same
   directory, and the MCP server rail keeps its own. Both were read from their own
   stamps rather than assumed, and `bad-745` through `bad-749` together with the
   `ind-001`/`ind-002` family — the signature-entry requirement, the manifest floor,
   the wrong-type spelling, and the readings the specification leaves open — are
   in both, so the sentence that used to say those vectors were not yet exercised
   there is gone rather than softened. The MCP server rail's placement fix at
   suiteRevision 9 kept a rail-local test from when its copy lagged; the vectors
   that pin the same reading are now in that copy too.

   This note is no longer maintained by whoever remembers it. Every figure in it,
   and the vendored-set cell for each rail in the table above, is checked by
   `scripts/consumer-lag-gate.py` against `vectors/CONSUMERS.json`, whose one row
   per rail is filled from that rail's own vendor stamp; the gate fails when a row
   is not the corpus this repository's default branch publishes, and fails again
   when these sentences are not the corpus it just measured. The default branch and
   not the branch being checked, because that is the only corpus a rail in another
   repository can fetch: a change here creates its obligation on the rails when it
   lands, not while it is a branch nobody could vendor. It is checked because it was wrong: written at
   suiteRevision 6 and still claiming 153 vectors at suiteRevision 14, while the
   corpus moved through eight revisions and both copies were re-vendored to
   follow it, and nothing anywhere disagreed. The count of rails named in the
   table is checked against the count of rows in that ledger for the same
   reason — this note described three rails while the ledger carried two, and the
   rail it left out was the only one nothing here was reading.

## What this report does NOT claim

One independent implementation agreeing is strong evidence the text is
determinate; it is not proof it is unambiguous. Two readers can share a
reasonable but unforced reading, and a single outside reader is a sample of one.
Nor does agreement on 277 vectors say anything about the surface no vector
touches, which is where the nesting-depth divergence above lived. The
interpretation-decision registry
(`vectors/interpretation-decisions.json`) records where the text forces the reading
and locks each with a vector; every decision it carries is now classified `forced`
and its open-corner list is empty. The three corners that were once open — duplicate
`attackId`, subject cardinality, and the coverage partition — are each resolved into
a forced decision with a forcing vector; the coverage partition is the single
editorial call kept reversible at vetting, with the audit trail in
`docs/interpretation-decisions-open.md`. This report is a determinacy claim about
the corpus surface, not a security claim about any assessed artifact.
