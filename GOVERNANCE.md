# Governance

Who decides what this suite says, how a change is proposed and dispositioned, how
often it moves, and what an outsider is entitled to when they disagree.

This file exists because a conformance suite is only useful to a party who trusts
neither the producer nor the implementer, and such a party cannot evaluate a set
of bytes without knowing how the bytes are maintained. A citing document has to be
able to say what happens when the suite changes, who could change it, and what
recourse a disagreeing implementer has. Everything below is written so that
question has an answer that does not require asking anyone.

## Who decides

**One maintainer, named in [`CITATION.cff`](CITATION.cff), decides every change to
this repository.** That is stated first because it is the weakest property here
and the one a reader should weigh hardest. There is no committee, no vote, and no
neutral steward. A reader evaluating whether to cite this suite should treat the
governance below as a set of constraints the maintainer has bound himself to in
public and mechanised where mechanisation is possible — which is a real thing and
a different thing from an artifact whose custody is genuinely distributed.

**The stated intent is to place the corpus, the failure-code registry and the
change process under a steward that is not the maintainer.** It has not happened.
Until it does, the honest description of this artifact is single-maintainer with
published constraints, and any document citing it should describe it that way
rather than taking this paragraph as evidence of the thing it describes. When it
does happen, it lands as an amendment to this file, dated, with the objection
route in [`DISPOSITIONS.md`](DISPOSITIONS.md) pointing at the steward's process
instead of at the maintainer's inbox.

There is no committer ladder, and the rule for adding one is written now rather
than when it would be convenient. Nobody but the maintainer holds write
access, so a ladder today would describe a body that does not exist. What is
stated instead is the constraint on the first addition: commit access follows a
sustained record of maintenance in this repository (changes landed, objections
answered in the ledger, gates kept green through revisions the person did not
author), and it follows nothing else. Not affiliation, not employment, not
funding, not an implementation whose conformance the corpus decides. Adding
someone lands as an amendment to this file, dated, naming the person and the
record it was granted on, so a reader can check the record against the reason
rather than being told there was one.

### What the maintainer does not decide

Three things sit outside that authority, and the boundaries matter more than the
authority does.

**The specification text is upstream's.** The predicate is settled in the
in-toto attestation project's own review process by people who are not the
maintainer. This repository vendors a pinned copy of that text and records the
commit it came from in [`spec/VENDOR-PIN.json`](spec/VENDOR-PIN.json), written
from git at vendor time rather than by hand. A change to what the predicate
*requires* is proposed there and arrives here as a re-vendor. What this repository
decides is what the corpus *forces*, which is a narrower and more checkable thing.

**Where the specification is silent, the suite does not get to legislate.** Two
conformant verifiers can reject the same bytes and name different conditions, and
the specification says of its own sequencing that it is informative. Pinning one
answer would fail a conformant rail; naming both in one expected set would stop
measuring the question. So a genuine ambiguity becomes an *indeterminate* vector
that declares every reading a conformant rail may take and holds a rail to one of
them coherently, rather than to the maintainer's. The mechanism is described in
[`README.md`](README.md) and the bucket is `vectors/indeterminate/`.

**Whether an implementation passes is decided by the corpus, mechanically.** The
suite compares verdicts and code sets, ignores message text, ignores evaluation
order, and reads a rail's answers through a fixed external contract. No pass or
failure is at anyone's discretion, and there is no recognition list, no
certificate and nothing to grant. An implementer who disagrees with a verdict can
rerun the corpus themselves; the whole suite is offline, dependency-free on the
consuming side, and runs against any command.

No implementation has standing here. The reference rails and named external
verifiers are evidence about the corpus, never its definition. Their behavior
does not justify adding a vector, widening an expectation, or retiring a rule.
The repository may name work maintained by Probity AI, including Probity Verify.
It does not name the separate company's website or private products. The
identity guards enforce that boundary in files and commit history.

## What is governed

| Surface | What changing it means |
| --- | --- |
| `vectors/` and `vectors/MANIFEST.json` | the corpus. A change here changes what a third party is obliged to implement |
| `aee/codes.go` and the failure-code registry in `README.md` | the vocabulary a rail reports in. Additive only; see below |
| `aee/`, `packaging/`, `cmd/`, `witnessattestor/` | the reference rails. They are evidence about the corpus, never the definition of it |
| `spec/predicates/` | vendored upstream bytes. Not this repository's to edit; a change is a re-vendor with the pin rewritten |
| `docs/FORCING-BASELINE.json` | what the corpus forces, held as a tighten-only ratchet |
| `docs/DISPOSITIONS.json` | this repository's answers to objections. Append-only |
| `GOVERNANCE.md`, `CONTRIBUTING.md` | this process. Amended by the route at the end of this file |

### What a vector says about itself

A vector obliges a stranger to implement something, so it has to answer which
predicate it is an obligation under and where it came from. The two halves are
recorded in different places and one of them is weaker, which is why both are
described here rather than only the tidy one.

The specification revision it targets is in the bytes. Every vector file
carries the `predicateType` it was written against, and `vectors/MANIFEST.json`
carries that type once for the corpus beside `specDigest`, the upstream commit
the vendored text was taken from, and the thread it tracks. The digest is an
input to generation, so a vector written against a specification revision other
than the one the manifest names cannot regenerate, and
`scripts/regenerability-gate.py` refuses it on the push that adds it. A vector
declaring some other type is one testing that a verifier refuses a type it does
not implement, and a vector that is not parseable JSON at all declares nothing;
both are reject vectors, and each is that way in its own bytes on purpose.

The origin is in the revision that added it, and in the objection when there
was one. The changelog entry in [`vectors/CHANGES.md`](vectors/CHANGES.md) for
a revision says what its additions force and what brought them; a vector added
because somebody outside read the text and reached a different answer is also
named in that person's row in `docs/DISPOSITIONS.json`, and
`scripts/dispositions-gate.py` refuses a row whose vectors are not in the
manifest. The limit is worth stating plainly: origin is not a field on the
manifest entry, which carries the identifier, the kind, the file, the conditions
and the expected outcome and nothing about provenance. So origin is reached
through the revision or through the ledger rather than read off the vector, and a
reader who wants it for one vector reads the entry for the revision that
introduced it.

## The revision cadence

The corpus is versioned and immutable per revision, and the rule has two halves
that are equally load-bearing.

**A published `suiteRevision` is never mutated in place.** A conformance claim
names a revision, so silently changing the bytes behind a revision number would
invalidate every claim anyone has made against it without any of them becoming
detectably wrong. If a published vector turns out to be incorrect, the correction
is a new revision that says so in [`vectors/CHANGES.md`](vectors/CHANGES.md); it
is never an edit to the old one.

**A change to what a conformant implementation must do bumps the revision.** That
includes a corpus addition, a normative change arriving from upstream, and a
re-vendor that moves the specification digest — the digest is itself a corpus
input, so every vector regenerates byte-identically from its generators whenever
the vendored text moves. `scripts/regenerability-gate.py` runs that regeneration
into a copy and diffs it, so a file no generator produces fails on the push that
adds it.

**Cadence is event-driven, not calendar-driven.** There is no release train. A
revision happens when a change of the kind above happens, which historically has
been often. Two consequences a citing document should know: a citation to a
version stays valid forever because that version's bytes never move, and a
citation to the branch is worth nothing.

**Every revision that changes what a conformant implementation must do is tagged
and released from this file's adoption onward.** The history behind that is worth
stating plainly rather than implying otherwise: one release exists today, carrying
the current revision, and the earlier revisions are reachable as commits rather
than as tags. The changelog carries every revision either way.

### What never changes

These are commitments to implementers, not aspirations, and each is enforced by a
gate named in `CONTRIBUTING.md`:

- **a published failure code's spelling never changes, and neither does the
  condition it names.** A changed condition is a new code, never a redefined one;
- **a code is never removed while any published revision names it**, so a rail
  written against an older revision still recognises the vocabulary;
- **vector identifiers are never reused.** A retired vector's identifier is
  retired with it;
- **message text is never part of the contract, at any revision**, so a rail is
  free to say whatever it likes about a rejection it names correctly;
- **precedence between two conditions is contractual only where `README.md` pins
  it.** Everywhere else, either answer is conformant, and the suite says so with a
  vector rather than with silence.

## How a change is proposed, and how it is dispositioned

The mechanics — what a vector needs, what a code needs, which gate runs, how to
wire an external verifier — are in [`CONTRIBUTING.md`](CONTRIBUTING.md). What
follows is the decision process over them.

**Anything may be proposed by anyone.** There is no membership, no account
requirement beyond whatever the hosting platform imposes, and no distinction
between an implementer's proposal and the maintainer's. A proposal is an issue or
a pull request; a proposal about the predicate's text belongs upstream and this
repository will say so and point at the thread.

A merge is not agreement, and nothing here should be cited as though it were.
A pull request merged in this repository is one person's decision written into
git. It is not a vote, not an approval by implementers, not a review by anybody
other than the maintainer, and not evidence that a second reader looked at the
change at all. The only agreement this repository can show is a second
implementation reaching the same verdicts against the same bytes, published with
the score it produced; the only venue where a disagreement about the predicate is
settled by more than one party is upstream's review of the specification text. A
citing document that reads a merge commit here as consensus has counted one
person twice.

**Every proposal reaches one of four dispositions, from a closed set:** `adopted`,
`adopted-in-part`, `declined`, or `open`. The last two are not synonyms —
`declined` is a decision with a reason and it is final until somebody raises a new
objection against it; `open` means received and unresolved, and it is required to
carry the thing that would settle it.

**A disposition that leaves anything unsettled states the residual in the row
itself.** A partial resolution with no residual is how a gap gets absorbed behind
a status word, which is the failure this rule exists to prevent.

**Every disposition of an objection raised by someone other than the maintainer is
published**, with the objector named, the objection in their frame, the resolution
and the reason, in [`DISPOSITIONS.md`](DISPOSITIONS.md). Including the ones that
were declined. A record of only the agreeable objections is worse than none,
because it reads as evidence of scrutiny while being evidence of selection.

**The ledger is append-only.** A disposition is not edited after publication. A
later disagreement about an earlier row is a new row citing it, so the sequence of
decisions stays readable rather than being replaced by its outcome.

### A thread converges by a date, and silence is not agreement

Every open proposal that asks more than one party to agree names a date by which
it should converge. If it has not converged by then, whoever opened it posts the
options that emerged and asks a narrower yes-or-no question. A reply that never
came is recorded as no reply, never as consent: a proposal nobody answered stays
`open`, and its row says what answer would settle it.

### Every pull request with no reviewer is named until it has one

A pull request that has waited a week with no reviewer goes on the next maintainer
review as a standing line, with one question: who reviews it, by when. The line
stays until a reviewer is named or the pull request is closed with a reason, so a
change cannot wait in silence until it is merged unread or abandoned.

## How an outsider objects, and what they get

Raise it in this repository's issue tracker, in the upstream pull request carrying
the predicate specification, or in the tracker of any implementation of it. All
three are public and none can be edited after the fact.

**What you are entitled to.** An objection about this suite's content gets a
disposition with a reason, published in the ledger under its own identifier, and
the identifier is permanent whichever way the decision goes. If the decision goes
against you, the reason is published in full alongside your objection rather than
being summarised into agreement. If your objection is about a fault you found in
the corpus and it is adopted, it lands as a vector and the changelog entry says
where it came from.

**What you are not entitled to, today.** An appeal to anyone other than the
maintainer. Every disposition below is decided by the person who wrote the thing
being objected to, and the routes that do not run through him are the ones outside
his control: the upstream review thread and any independent implementation's own
tracker, where a divergence can be recorded whatever this repository decides. A
genuinely independent appeal needs the steward this file's first section says does
not exist. That is stated as a limit rather than as a plan, and it is the single
property here that a citing committee should treat as unmet.

**What makes the answer checkable rather than promised.** The ledger is not free
prose. `scripts/dispositions-gate.py` refuses a row whose landing revision is not
one the changelog carries, whose forcing vectors are not in the manifest, or whose
cited record no longer contains the phrase it quotes, and it renders the published
table from the ledger so an edit to the table alone fails. The gate runs one way:
it stops a row being invented and it cannot stop one being omitted. That asymmetry
is printed in the ledger itself, because the only party who can see a missing row
is the person whose comment is missing.

## The properties this governance is for

A citing document needs each of these to hold, and each is checked by something
rather than asserted:

- **nothing changes silently.** Every revision is in the changelog, every count in
  prose is checked against the source that derives it, every citation into the
  vendored specification is pinned to the prose it was drawn around, and every
  generated file is regenerated and diffed in CI;
- **the artifact is obtainable without asking anyone.** Public repository, an
  SPDX-identified permissive licence in [`LICENSE`](LICENSE), no membership, no
  registration, no fee, and a consuming side with no third-party dependency;
- **the limits are published before anyone asks for them.** What the corpus does
  not force is a measured number rather than a silence; the independence of the
  one implementation not written by the maintainer is stated with the scores it
  did not produce; the appeal route's absence is in this file;
- **every published run says who produced it.** A score appears labelled
  first-party or independent wherever it is quoted, because an unlabelled score
  is read as independent and that is the direction a mislabelling always favours.
  The first-party rails are reported as first-party and are not counted toward
  independence at all. An outside run is transcribed from
  `docs/INDEPENDENT-RUNS.json` exactly as its author posted it (never rounded,
  never restated as a fraction of a different corpus, never called unprompted
  when its author called it directed), and `scripts/independent-runs-gate.py`
  refuses prose that disagrees with that ledger, including prose that is silent
  about the revisions the outside implementation has not run.

## Amending this file

A change to this file or to `CONTRIBUTING.md` is a pull request like any other,
and it is dispositioned by the same process it describes. Two constraints on the
maintainer, stated here so that departing from them is visible:

- **a commitment in the section above is not removed in the same change that makes
  it inconvenient.** Retiring one is its own change, with its own reason,
  referenced from the changelog entry of the revision that follows it;
- **an amendment that narrows what an outsider is entitled to is published in the
  disposition ledger as its own row**, so the narrowing appears in the record
  beside the objections it affects rather than only in a diff.
