# Independent runs

One row per run of a corpus in this repository by an implementation that this
repository did not write, posted publicly with a record a reader can fetch.

This file exists because the only claim this suite makes that matters is that
somebody else can run it and get the same answers. Five rails written by one
author catch each other's transcription errors and share one reading of the
specification; they cannot catch a misreading, because they all inherit it.
An outside run can.

## What a row has to carry

- **who ran it**, by the handle they posted under;
- **where they posted it**, as a link that resolves;
- **which corpus and which suiteRevision**, because a figure without a revision
  is a figure about nothing;
- **the figure exactly as they posted it**, never rounded, never restated as a
  fraction of a different corpus;
- **the label its own author gave it.** A run whose author called it directed is
  recorded as directed here, whatever it scored;
- **their own words**, quoted, so the row cannot soften what they said.

**Blind and directed are different evidence and are never added together.** A
blind run says something about whether the specification text is determinate
from a cold start. A directed run, where the author read a specification diff or
a changelog before implementing, says the corrected text is implementable, which
is a weaker and still useful thing. This file keeps the label beside the figure
for that reason.

A row is licensed by a posting, not by a conversation. If a run was not posted
with a record, it does not get a row, however good the figure was.

## The runs

### Rul1an, `Rul1an/aee-checker`, revision 27 of the AEE corpus

| | |
| --- | --- |
| Reporter | `Rul1an` |
| Implementation | `Rul1an/aee-checker`, an independent Rust verifier with its own I-JSON parser, RFC 8785 serializer, RFC 6962 Merkle root, run-binding derivation and Ed25519 tier |
| Posted at | [`Rul1an/aee-checker#21`](https://github.com/Rul1an/aee-checker/pull/21), opened and merged 2026-09-06 |
| Corpus | `vectors/`, at the corpus commit that pull request pins |
| suiteRevision | 27 |
| Result | 61/61 accepts, 209/209 rejects, 2/2 indeterminate, zero mismatches |
| Reason parity | 80/209, which its author reports and explicitly does not promote |
| Label, by its author | **directed** |

What the run is evidence of, in his words:

> the build under test predates every vector in this corpus and every word of
> the spec delta, and its source was not modified, so no vector-driven fix is
> possible in either direction.

And what it is not evidence of, also his:

> This is not a determinacy result. The figure that bears on whether the text is
> determinate from a cold start is still the blind 179/232

Both quotations are transcribed with the posting's markdown emphasis removed and
nothing else changed.

Three things in that posting belong in this file rather than in a summary of it.
The first is a disclosure its author made before any figure: an unregistered
exploratory pass had run earlier the same day and a comment describing the
specification change had been read beforehand, so the run is labelled directed
under his own protocol rather than presented as blind. The second is scope: the
corpus was pinned to a vendored specification 4393 bytes behind the upstream
head of the review thread, and the rule those bytes add is exercised by no
vector in the corpus, so the parity figure is not evidence about that rule and
his record says so. The third is that his own reproduction recipe and one
provenance note were found to be wrong in the course of the run and were
corrected in it, which is the kind of finding an outside run produces and an
in-house one does not.

His summary of what the frozen build did across the advance:

> The corpus advanced 282 commits and 250 → 272 vectors and the frozen build
> agreed on all of them.

## The ledger this file is not

[`docs/INDEPENDENT-RUNS.json`](docs/INDEPENDENT-RUNS.json) is the gated record
behind the independence column in [`README.md`](README.md) and
[`docs/IMPLEMENTATION-REPORT.md`](docs/IMPLEMENTATION-REPORT.md):
`scripts/independent-runs-gate.py` derives the not-run set from it and refuses
prose that disagrees. This file is the reader-facing scoreboard, one row per
posting, and it adds no figure that its posting does not carry.

That ledger also carries an `attempts` array, and it is the half of the record
nothing used to hold. A row in `runs` is what licenses a figure, and every row
there carries a `figures` array, so a dispatch that was authorised, ran and
produced no score had no shape in the file and was invisible to the gate. Two of
them had already happened. An attempt therefore records the corpus commit, the
checker ref, the authorization packet, the dispatch and where its artifacts
survive, with `figures` null beside a note saying why there is none; it carries no
`suiteRevision`, because the not-run set is computed over `runs` and a revision
there would let a dispatch with no figure license the one it has none of. The
gate reads the array, holds it to that shape, and refuses a sentence in either
publishing document that names an attempt's dispatch and a figure together.

**Known divergence, stated rather than left for a reader to find.** That ledger
carries rows up to revision 25 and does not yet carry the revision-27 run above.
Until it does, the independence column's not-run set still names revision 27,
which is now wrong in the direction of understating what was run. The repair is
a ledger row transcribed from the posting, and it is a change to the gated
ledger and the prose it governs rather than to this file.

## Reporting your own

The form is
[`.github/ISSUE_TEMPLATE/independent-run.yml`](.github/ISSUE_TEMPLATE/independent-run.yml).
Nothing in it asks you to agree with the corpus. If your verifier answered
differently on a vector, that is the row worth having, and
[`CONTRIBUTING.md`](CONTRIBUTING.md) says what happens to it: it becomes a
disposition row under a permanent identifier, in your frame, whichever way it is
resolved.
