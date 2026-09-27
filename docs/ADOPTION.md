# Adoption and independent runs

Who uses this suite, and which implementations outside this repository have run it. Part of the [agent-evidence-vectors](../README.md) documentation; the [index](README.md) lists every page.

## Used by

- [in-toto's AI Agent Action predicate proposal](https://github.com/in-toto/attestation/pull/588/files) names this suite as its conformance corpus, pins release `v0.8.0` by commit and digest, and makes passing it a MUST.
- Listed in the OECD.AI [Catalogue of Tools and Metrics for Trustworthy AI](https://oecd.ai/en/catalogue/tools/agent-evidence-conformance-suite), published 2026-09-14.
- [Rul1an/aee-checker](https://github.com/Rul1an/aee-checker/pull/21), an independent Rust verifier written from the specification alone, scores 272/272 on suiteRevision 28 (its own index calls the run revision 27) with its build frozen before the corpus moved.
- [giskard09](https://github.com/a2aproject/a2a-tck/pull/228#issuecomment-5359047401) ran the 57 RFC 8785 vectors blind against argentum-core before opening the generators: 57/57.
- The maintainer of [VATE](https://github.com/Poke-nushi/Verifiable-Agent-Trust-Envelope/blob/main/docs/interop/aee-native-boundary-review.md) regenerated all 308 generated files byte for byte and recorded 258/258 in his own repository.
- Curated in [awesome-agent-runtime-security](https://github.com/bureado/awesome-agent-runtime-security/blob/main/README.md) under attestation and recompute-verify, and on the [awesome-ai-security-tools watchlist](https://github.com/scadastrangelove/awesome-ai-security-tools/blob/main/WATCHLIST.md) with `Co-authored-by` credit on the curation commit.

## On independence

I wrote the Go core here, the sibling Python implementation, and the three
consumer rails in two first-party stacks. Five implementations,
one author, one reading of RFC 8785 and RFC 7493. They catch each other's
transcription errors and the differential fuzzer catches drift between them, but
they cannot catch a misreading of the specification, because they all inherit
the same one. Counting them as independent would be counting the same opinion
five times.

**The number of implementations independent of this specification's author is
one.** [`Rul1an/aee-checker`][aee-checker] is a from-spec Rust implementation
with its own I-JSON parser, RFC 8785 serializer, RFC 6962 Merkle root,
run-binding derivation, and Ed25519 tier, built with no sight of the reference
code. It cleared 125/125 at suiteRevision 1, then re-ran against the round-7
corpus and reached 138/138 at suiteRevision 2 after a spec-diff-led update
(132/138 on the unchanged build), cleared suiteRevision 3 at 140/140, cleared
suiteRevision 5 at 149/149 after it adopted the normative nesting bound of 128
and moved its depth counter from per parsed value into the container branch
(aee-checker#3), and cleared suiteRevision 6 at 153/153, 36/36 accepts and
117/117 rejects, after implementing the Unicode noncharacter exclusion RFC 7493
section 2.1 requires (aee-checker#4, 2026-07-28; the unchanged revision-5 build
scored 151/153 against it).

The same author then ran the v0.7 corpus, and it is the largest reading this
column carries.
At suiteRevision 22, on 2026-08-03, a build written from the pinned v0.7 text
alone scored 179/232 on its first run (accepts 8/54, rejects 169/176,
indeterminate 2/2), and a directed pass reached 232/232, accepts 54/54, rejects
176/176, indeterminate 2/2. The directed pass is directed twice over in the
author's own account: it followed a spec diff already read and, for one vector, an
adversarial review of that implementation. That account partitions the 53 first-run
mismatches by the message the blind build emitted, and says that is the only
partition its published run records support: 42 report that `aeeRunBinding` does
not equal the run binding derived from the statement, 7 returned `valid` with no
reason, and 4 report a carried `pass_indirect` against a recomputed `pass`. An
earlier draft of that report published a per-fix attribution, withdrawn rather
than restated, because attributing a recovery to a particular fix needs
a bisection against the blind build and that build no longer exists. The report
claims no reason-parity figure for the run at all: the checker emits free prose and no
condition codes, two constructions of a prose-to-code map over the same run
disagreed sharply, and the ambiguity is published as a runnable script rather
than resolved by picking one of them.

Each of those figures moves this column only because a record and the source
digest that produced it were posted with it. The revision-6 record names checker
source `sha256:1c3e2e78` and suite commit `6aa7c60`, and it is the revision that
checker's CI now verifies continuously. That suite commit no longer resolves in a
fresh clone of this repository, because the history it sat on was rewritten here
after the record was pinned; the commit that carries the identical tree, and so the
identical 153 vectors of suiteRevision 6, is `6aa7c60`, which is where a
reproduction of the record should point until it is repinned.

The v0.7 record splits on exactly that requirement, and the half this suite leans
on is the half with no digest. The directed build is recorded under checker source
`sha256:56f440e6…` against suite commit `4cd65a16`, and reproduces from the
author's working tree. The blind build does not, and the author says so before
anyone else could: it was never committed on its own, one commit carrying both the
v0.7 implementation and the published number, so no tree in that repository hashes
to the build that produced 179/232 and the figure is not independently reproducible,
including by its author. The checker's `reports/INDEX.json` records that as an
explicit null digest beside a `sourceUnrecoverable` field rather than borrowing the
directed build's digest, which would name a different implementation, and records
the whole thing as a breach of the rule that run's own protocol had fixed in advance.
That suite commit does resolve in a fresh clone here and carries the 232 vectors
of suiteRevision 22. This suite carries the blind figure with the null-digest
caveat attached and never without it.

The most recent reading is against the current corpus. On 2026-08-12, in the same
thread, the author posted 250/250 at suiteRevision 25 — accepts 55/55, rejects
193/193, indeterminate 2/2, reason parity 69/193 — against suite commit
`97ba4ff`, whose manifest carries 250 vectors in exactly that partition and the
vendored spec digest `759d2383` the run names. It was verified on a clean runner
at a public CI run that checks the spec digest before it counts anything. It is
directed, and the author's opening words are why this suite records it that way:
"Repinned and implemented first, then measured your open question." The record
names the suite commit, the spec digest and the runner, and it names no checker
source digest, so it is the second figure in this column carried without one and
this suite says so rather than letting a reader assume otherwise.

Only three of those figures are evidence that an outside reader reached a rule
unaided. The 125/125 was the first full corpus run with no vector-driven fixes.
The 140/140 was a first run by an unchanged build whose rule for the two new
vectors was derived from the spec text and predated them, so the vectors met a
rule that was already there rather than driving it. The blind 179/232 at
suiteRevision 22 is the third and the only one taken against the v0.7 text; in
the author's own report it is the only figure in that run bearing on whether the
text is determinate from a cold start. The other figures each
followed a spec diff the author had read, and two of them followed more than that.
In the author's own words,
kept here because paraphrasing it would soften it: "This one is directed, and
more so than revision 2 was: the rule was written and the vectors named before
this checker ran, so what it demonstrates is that the corrected rule is
implementable from the text, not that an independent reader found it." A
directed 153/153 says the corrected rule is implementable by someone who has only
the text. It is not the same evidence as 125/125 and this suite does not present
it as such.

It has not been run against suiteRevision 4, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 26, 27, 29 or 30, so
this suite publishes no score for it at any of them. They are on that list for
three different reasons, and only one of them is that the requirement went
unexercised. Two of the five at the end of the list fall between that v0.7 run
and the suiteRevision-25 one: suiteRevision 23 added sixteen reject vectors and a
second declared condition on a seventeenth, and suiteRevision 24 moved the
vendored text without moving a vector. The other two fall between the
suiteRevision-25 run and the suiteRevision-28 one: suiteRevision 26 added eight
boundary vectors and moved no vendored text, and suiteRevision 27 pinned what the
reference rail emits beyond each reject vector's declared codes without changing a
vector file. The suiteRevision-28 corpus carries every vector both added. suiteRevision 29 came after that run and added three reject vectors, one per empty predicate state. suiteRevisions
7 through 21 are the opposite case and the distinction is worth being exact
about. Every vector those revisions added is inside the suiteRevision-22 corpus
that run covered, so the requirements they carry, the signature-entry requirement
and its precedence and wrong-type spellings, the corpus manifest attack floor, the
timestamp profile, the version-2 run binding, the fourth `result` value, the
registered posture vocabulary and the vendored amendments that followed, are not
unread. What no record of that checker names is the corpus AT any of those
revisions, and that is not a formality: suiteRevision 13 moved five of the
corpus's results, so a verdict set at one revision is not the verdict set at
another, and a pass at suiteRevision 22 says nothing about what this checker
would have answered at suiteRevision 13. suiteRevision 4 is on the list
for a third reason: its corpus is the revision-3 corpus, 140 vectors with
the same verdicts and the same codes, so the revision-3 run did put those bytes
through this checker. What that revision changed was the text, which made
encoding well-formedness and the 128-deep nesting bound normative over a corpus
that, as its own changelog entry says, exercised neither. A pass at 140/140 was
therefore compatible with getting both new rules wrong, and one of them this
checker did get wrong: when suiteRevision 5 published, it still read the bound as
256, and aee-checker#3 is where it adopted 128. Recording revision 4 as run
would assert a conformance no posted record carries. It keeps its own
authorship, history, and CI. The link is pinned to the build that recorded the
153/153 run.

That one reading has already earned its keep, twice. The specification did not
pin a maximum JSON nesting depth, so all five of my rails chose 128 and agreed at
every depth; the independent checker read the same text and chose 256. For the
127 depths in between, identical bytes were valid evidence to one conformant
verifier and malformed to another. Five agreeing rails could not surface that;
one outside reader surfaced it on contact, and the bound is now normative at 128.
Reading it back a second time surfaced a split the five rails had hidden from
each other: the reference Go rail counted nesting depth per parsed child, so an
empty-container leaf slipped one level past the bound where the Python rail
rejected it -- two first-party rails disagreeing on identical bytes at one exact
depth. That one is fixed and pinned by a boundary vector pair; both findings came
from the same outside reader, and neither could have come from the rails alone.

More outside implementations are wanted, and the count above is the reason.
Wiring one in means answering the external-verifier contract above: a verdict in
the exit status, a single-line JSON object carrying the codes and the recomputed
result, and a key policy read from `AEE_SUBSTRATE_KEYS` so the two tier columns
can be compared. A conformant checker passes even when it evaluates in a
different order, since the suite compares verdicts and code sets and ignores both
message text and evaluation order. The shortest way to see the whole contract
working is the CLI in this repository, which CI drives through it on every push:

```
go build -o aee-verify ./cmd/aee-verify
python3 packaging/run_vectors.py --verifier "$PWD/aee-verify -json"
```

[aee-checker]: https://github.com/Rul1an/aee-checker/tree/f8bd3a787ef0b4610e96054ee1f167368f2ccdc2
