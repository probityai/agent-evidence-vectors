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

### Rul1an, `Rul1an/aee-checker`, suiteRevision 28 of the AEE corpus

| | |
| --- | --- |
| Reporter | `Rul1an` |
| Implementation | `Rul1an/aee-checker`, an independent Rust verifier with its own I-JSON parser, RFC 8785 serializer, RFC 6962 Merkle root, run-binding derivation and Ed25519 tier |
| Posted at | [`Rul1an/aee-checker#21`](https://github.com/Rul1an/aee-checker/pull/21), opened and merged 2026-09-06 |
| Corpus | `vectors/`, at the corpus commit that pull request pins |
| suiteRevision | 28, which the checker's own index labels revision 27: it counts one run per corpus it read, and it read suiteRevision 25 twice |
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

### The 0.12.1 harness fix and this row

Releases 0.6.0 to 0.12.0 printed the reference rail's pass when the verifier
named with `--verifier` never ran, which `SECURITY.md` records. This row is not
touched by it: the run called `aee-checker` on the corpus directly, through its
own conformance workflow, and never went through this package's `--verifier`
path, so the fallback could not have supplied its figure. A run that does go
through the harness shows it in its report: `rail` reads `external` and
`verifier.vectorsExecuted` equals the vector count.

### MoltyCel, `MoltyCel/moltrust-api`, the a2a-jcs-v01 corpus

This corpus is not in this repository. It is the A2A Agent Card
canonicalisation set, `conformance-vectors/a2a-jcs-v01` in
[`a2aproject/a2a-tck`](https://github.com/a2aproject/a2a-tck), written by this
repository's maintainer. It has no suiteRevision; the row pins it by commit and
corpus digest instead, and it is not a row of the ledger below, which counts AEE
revisions only.

| | |
| --- | --- |
| Reporter | `MoltyCel` |
| Implementation | `MoltyCel/moltrust-api` at commit `c81b57165d6d62bda1548b55db96fcf75d367db4`, with `lib/agent_card_verify.py` at blob `dc908ba47ed9622263484a6fb6f8f2597beddaf8` and `app/signature.py` at blob `f7193f49c09bac55d9a9882d4518820fa2e5b05e` |
| Posted at | [`a2aproject/A2A#1882`, comment of 2026-10-01](https://github.com/a2aproject/A2A/pull/1882#issuecomment-5932794122), and the repository's own CI, [run 36871040292](https://github.com/MoltyCel/moltrust-api/actions/runs/36871040292), on a merge ref that includes that commit, under Python 3.9 and 3.12 |
| Corpus | `a2a-jcs-v01` at `a2aproject/a2a-tck` commit `97b007237ee4c3b802ed563829e3937a5529244e`, corpus digest `29b3f2c5a9c2e6b07dc7e925b13c81563e2efd407a62ce05df513fca04e9361c` |
| Raw canonicaliser, `app/signature.py` `canonicalize` | 53/53, target `rfc8785` |
| Card signing, `app/signature.py` `sign_agent_card` | 57/57, target `card-signing-input` |
| Card verify, `lib/agent_card_verify.py` `verify_agent_card` | 57/57, target `card-signing-input`, refusal class `CardVerificationError` |
| Label, by its author | none given |

Each path is listed with its own refusal class because a score means nothing
without the class the runner counted as a refusal. The author said so, and
corrected his own earlier figure on exactly that ground:

> That number depended on a setting in the runner I used.

The earlier runner counted any exception on a reject vector as a refusal.
Under `CardVerificationError` the verify path then scored 52/57; under the
runner's default of `ValueError` it scored 54/57. The five vectors that
separate them are the lone-surrogate rejects A3-REJECT-011, A3-REJECT-012 and
A4-REJECT-013 to 015, where the path refused the input but raised
`UnicodeEncodeError`. Commit `c81b571` makes those raise `CardVerificationError`,
and the class now derives from `ValueError`.

The CI run above declared both `CardVerificationError` and `builtins:ValueError`
as refusals for the verify path. The figure in the table is the narrower one:
the same scorer at the same corpus commit, with `CardVerificationError` as the
only refusal, gives 57/57 on the verify path over that commit's code, and 52/57
over `lib/agent_card_verify.py` from the parent commit `a708e98`. The
`builtins:ValueError` declaration is being removed from the workflow, which the
author said was no longer needed after his fix.

The author gave the run no blind or directed label, and this file does not
supply one. It is not a cold-start result: the fix it measures was made after
the author saw which vectors failed, and the scoring workflow was contributed
to his repository by this repository's maintainer. What it shows is that the
corrected text is implementable on three paths of one codebase, each scored
against the function it provides.

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
produced no score had no shape in the file and was invisible to the gate. Two
had already happened by the time the array was added, and the count is written
that way on purpose: the array is where the current number lives, and a total
restated here would rot the next time one is dispatched. An attempt records the
corpus commit, the
checker ref, the authorization packet, the dispatch and where its artifacts
survive, with `figures` null beside a note saying why there is none; it carries no
`suiteRevision`, because the not-run set is computed over `runs` and a revision
there would let a dispatch with no figure license the one it has none of. The
gate reads the array, holds it to that shape, and refuses a sentence in either
publishing document that names an attempt's dispatch and a figure together.

## Reporting your own

The form is
[`.github/ISSUE_TEMPLATE/independent-run.yml`](.github/ISSUE_TEMPLATE/independent-run.yml).
Nothing in it asks you to agree with the corpus. If your verifier answered
differently on a vector, that is the row worth having, and
[`CONTRIBUTING.md`](CONTRIBUTING.md) says what happens to it: it becomes a
disposition row under a permanent identifier, in your frame, whichever way it is
resolved.
