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

This corpus is the A2A Agent Card canonicalisation set,
`conformance-vectors/a2a-jcs-v01` in
[`a2aproject/a2a-tck`](https://github.com/a2aproject/a2a-tck), written by this
repository's maintainer. It is carried here byte for byte as
[`corpora/vectors-a2a-jcs-v01/`](corpora/vectors-a2a-jcs-v01/README.md), locked to the commit and
digest below, so it replays through the harness and the GitHub Action with
`--corpus vectors-a2a-jcs-v01`. It has no suiteRevision; the row pins it by commit and
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
over `lib/agent_card_verify.py` from the parent commit `a708e98`. The verify
path's `builtins:ValueError` declaration was removed in
[MoltyCel/moltrust-api#526](https://github.com/MoltyCel/moltrust-api/pull/526),
so `CardVerificationError` is its only declared refusal. Because the runner
matches a refusal class exactly, the raw and signing paths declare both
`ValueError` (the three number rejects) and `UnicodeEncodeError` (the five
lone-surrogate rejects) as of `1e4c4b7c`. The author reports the four results
unchanged on both corpus states, `97b0072` and `7a3197d`: raw 53/53, signing
57/57, verify 57/57 and negative control 53/57
([A2A#1882](https://github.com/a2aproject/A2A/pull/1882#issuecomment-6000735988)).

The author gave the run no blind or directed label, and this file does not
supply one. It is not a cold-start result: the fix it measures was made after
the author saw which vectors failed, and the scoring workflow was contributed
to his repository by this repository's maintainer. What it shows is that the
corrected text is implementable on three paths of one codebase, each scored
against the function it provides.

### Mayur021, `Mayur021/agent-audit-record-reader`, the agent audit record corpus

The first run of `vectors-agent-audit-record` by a reader this repository did
not write. That corpus is not an AEE revision, so like the row above it is not
a row of the ledger below.

| | |
| --- | --- |
| Reporter | `Mayur021` |
| Implementation | [`Mayur021/agent-audit-record-reader`](https://github.com/Mayur021/agent-audit-record-reader) at commit `0ad911a39d7942d5fabd9a4ea0b9093bb04f88a7`, a Python reader written from `draft-gilda-wimse-agent-audit-record-01`, RFC 8785, RFC 7493 and DSSE, depending on `cryptography` only |
| Posted at | [`ietf-wg-wimse/draft-ietf-wimse-aims#144`, comment of 2026-10-01](https://github.com/ietf-wg-wimse/draft-ietf-wimse-aims/issues/144#issuecomment-5934905211), with `FINDINGS.md` in the reader's repository |
| Corpus | `vectors-agent-audit-record` at release 0.16.0, 47 members, corpus digest `9617291fd6c1721dfd9430d3f15987da716ee5c722094f74431a95a2d4b3c3c6`, fetched at run time and not vendored |
| Result | 47 of 47 agree: 9 accept members valid, 36 reject members malformed, and N1 and N2 both valid, a listed reading of each |
| Label, by its author | none given |

What the run is evidence of, in his words:

> It shares no code with the reference verifier, and none with jcs-admit, dsse
> or agent-evidence-vocabulary either

The figure was reproduced here before this row was written: his reader at that
commit, run over the corpus fetched from tag `v0.16.0` with his own
`fetch_corpus.sh`, gives the same result, with N1 and N2 reaching `valid`.

It is not a cold-start result, and he says so. Two vectors caught a first pass
of the reader, T2 on verifying over the payload as transmitted rather than its
canonical bytes, and T3 on checking duplicate member names after the signature,
and he fixed both before posting. He also reported a finding against the draft:
the write-chain replay that sections 4.4, 4.6 and 5.3 require is not defined in
the body and had to be recovered from the accept members.

### Laurent-Lemonnier, `Laurent-Lemonnier/dps-scitt-decision-layer`, the agent audit record corpus

The second run of `vectors-agent-audit-record` by a reader this repository did
not write, and the first written from revision -02 of the draft.

| | |
| --- | --- |
| Reporter | `Laurent-Lemonnier` |
| Implementation | [`interop/gilda/gilda_verify_independent.py`](https://github.com/Laurent-Lemonnier/dps-scitt-decision-layer/tree/f72f092/interop/gilda) at `Laurent-Lemonnier/dps-scitt-decision-layer@f72f092`, Python, standard library and `cryptography` for Ed25519, written from `draft-gilda-audit-agent-audit-record-02` Sections 4 and 5 |
| Posted at | [#335](https://github.com/probityai/agent-evidence-vectors/issues/335), opened 2026-10-30, with the per-member report [`judge-20261029.json`](https://github.com/Laurent-Lemonnier/dps-scitt-decision-layer/blob/f72f092/interop/gilda/judge-20261029.json) |
| Corpus | `vectors-agent-audit-record` at release 0.28.0 (tag `v0.28.0`, commit `3a3c5b0`), 141 members: 59 accept, 81 reject, 1 indeterminate |
| Result | 141 of 141 agree with `MANIFEST.json` on the verdict, the refusal codes, the derived tier, `withinLimit` and the set checks; the first refusal code agrees on 81 of 81 reject members |
| Label, by its author | an outside run, replayed by the reader's own CI on every change and weekly |

What the run is evidence of, in his words:

> It imports nothing from this package and shares no code with the reference
> rail; the only inputs taken from the corpus are the members and the test keys
> published in `MANIFEST.json`.

What it did not attempt, also his: anchor validation of retained records
(Section 4.7.2). The bracket checks that need an anchor time, R3, R7 and R11,
are reported as not attempted, never as passed. He also reported what the reading
needed from outside the text of -02: the empty-tree constant and the 300-second
skew tolerance, taken from `MANIFEST.json`, and the reading of CS7 and CS17 on
when a held permit was issued. Revision -03 states all three.

The figure was not reproduced here before this row was written.

### Laurent-Lemonnier, `Laurent-Lemonnier/dps-scitt-decision-layer`, the agent audit record corpus, rerun at release 0.31.0

The same reader as the row above, rerun against revision -03 of the draft and release 0.31.0 of the corpus.

| | |
| --- | --- |
| Reporter | `Laurent-Lemonnier` |
| Implementation | [`interop/gilda/gilda_verify_independent.py`](https://github.com/Laurent-Lemonnier/dps-scitt-decision-layer/tree/3961a3642263a08ba921d7266ef2edcc9d9472de/interop/gilda) at `Laurent-Lemonnier/dps-scitt-decision-layer@3961a36`, Python |
| Posted at | [#335, comment of 2026-10-31](https://github.com/probityai/agent-evidence-vectors/issues/335#issuecomment-6549594533), with the log [`run-20261031.txt`](https://github.com/Laurent-Lemonnier/dps-scitt-decision-layer/blob/3961a3642263a08ba921d7266ef2edcc9d9472de/interop/gilda/run-20261031.txt) and the per-member report [`judge-20261031-0.31.0.json`](https://github.com/Laurent-Lemonnier/dps-scitt-decision-layer/blob/3961a3642263a08ba921d7266ef2edcc9d9472de/interop/gilda/judge-20261031-0.31.0.json) |
| Corpus | `vectors-agent-audit-record` at release 0.31.0, read against draft -03 |
| Result | 184 of 184 members agree with `MANIFEST.json` on the verdict, the refusal codes, the derived tier, `withinLimit` and the set checks, and for the 22 retained members on the dating block; the first refusal code agrees on 101 of 101 reject members |
| Not attempted | 0 anchors; `rfc3161` is the only anchor kind the verifier does not validate, and the corpus carries none |
| Label, by its author | an outside run |

His three stated limits: the rules CS18 to CS40 and the X codes were implemented from the corpus README and not from the text of -03 ("text plus README"); the empty-tree constant is a question he raised; and anchors are read over the recomputed digest (X12).

The figure was not reproduced here before this row was written.

### Laurent-Lemonnier, `Laurent-Lemonnier/dps-scitt-decision-layer`, the approval binding corpus

The first outside run of `vectors-approval-binding`, by a reader this repository did not write.

| | |
| --- | --- |
| Reporter | `Laurent-Lemonnier` |
| Implementation | [`interop/gilda/approval_binding_verify_independent.py`](https://github.com/Laurent-Lemonnier/dps-scitt-decision-layer/tree/fdc5f6352795fc713309cd25ac2669d22840e0cc/interop/gilda) at `Laurent-Lemonnier/dps-scitt-decision-layer@fdc5f63`, Python, written from the checks in the corpus README, importing nothing from the package |
| Posted at | [#401](https://github.com/probityai/agent-evidence-vectors/issues/401), opened 2026-11-01, with the logs and per-case reports beside the verifier |
| Corpus | `vectors-approval-binding` at releases 0.31.0 and 0.28.0, 23 cases, the same corpus digest `49f077e5` at both |
| Result | 23 of 23 cases agree with `MANIFEST.json` on decision and reason, by his judge and by the corpus's own harness driving the verifier through its command-line contract |
| Label, by its author | an outside run |

The readings the text left to the verifier are stated in the docstring of the verifier. One of them, that the ambiguity check compares every member of the two objects, is the reading the corpus now states in check 4 and pins with the case `approval-id-reused-unread-member`.

The figure was not reproduced here before this row was written.

### telleroutlook, `telleroutlook/agent-evidence-cold-readers`, the refund-connected corpus, `input_aps` layer

The first run of `vectors-refund-connected` by a reader this repository did not
write, and it covers one layer of six: `input_aps`, the layer
[`docs/reference/refund-connected-input-aps.md`](docs/reference/refund-connected-input-aps.md)
states as a contract. It says nothing about `input_pic`, `admission`,
`signature_trust`, `execution` or `observed_effect`, and it is not a run of the
complete refund flow. Like the rows above it is not a row of the ledger below.

| | |
| --- | --- |
| Reporter | `telleroutlook` |
| Implementation | [`telleroutlook/agent-evidence-cold-readers`](https://github.com/telleroutlook/agent-evidence-cold-readers/tree/e979326a05608d1fa67ed1925f26daa8bed49d71/refund-connected-input-aps) at commit `e979326a05608d1fa67ed1925f26daa8bed49d71`, path `refund-connected-input-aps/`, Python with the standard library only, including its own RFC 8032 Ed25519 verifier |
| Posted at | [#352, comment of 2026-11-07](https://github.com/probityai/agent-evidence-vectors/issues/352#issuecomment-6699728316) |
| Corpus | `vectors-refund-connected` at `0a4fef2c7fec16fb3f27e537d5c248c042fe6bde`, `input_aps` expectation of each vector in `MANIFEST.json`, corpus digest `1588224056bb6f7f5971386164b4a737c422ec6b16bcdea3ca8dc559adb5f9a5` |
| Result | All ten scored vectors match: `j01`, `n3-reissue` and `n4-lost-ack` `ESTABLISHED`, `n1b-aps-payload` `REFUSED:PAYLOAD_REF`, `n3b-old-pic` `REFUSED:APPROVAL_AFTER_CONSUMPTION`, in both runs `r1` and `r2`. The two `n1a-pic-args` vectors are `NOT_REACHED` in the manifest and are not scored |
| Label, by its author | blind pass |

What the run is evidence of, in his words:

> Written from `docs/reference/refund-connected-input-aps.md` alone (steps 0–26) — no code imported from the packaged reader.

On `n1a-pic-args` his reader returns `REFUSED:PIC_ARGS_NOT_PAYLOAD` (step 26,
`pic_args.amount_minor` 4100 against `payload.amount_minor` 4000), because it
implements only this layer and is asked about that input. The manifest's
`NOT_REACHED` is the verdict a caller assigns when an earlier layer
(`input_pic`, `REFUSED:PIC_ARGS_DIGEST`) has already refused, which the
contract says in so many words, so the two do not conflict. He chose not to make
the reader emit `NOT_REACHED`, and that choice is the contract's.

The figure was reproduced here before this row was written: his reader at that
commit, run over the corpus at `0a4fef2c7` with `--admission-state` set to each
run's `admission/state.json`, returned the same ten verdicts and
`REFUSED:PIC_ARGS_NOT_PAYLOAD` for both `n1a-pic-args` vectors.

## Runs of this repository's code on another operator's host

The rows above are runs of implementations this repository did not write. The
rows in this section are not: each is this repository's own reader and tests,
run by someone else on a machine this repository does not control. That is the
label `second-party-same-code` in
[`docs/INDEPENDENT-RUNS.json`](docs/INDEPENDENT-RUNS.json). It says the code
behaves the same on that host; it says nothing about whether a second reading of
the specification agrees, and no figure here is added to a figure above.

### mohammedmessaoudene-cmd, `interop/action-tuple-framed-v1` on a Windows host

| | |
| --- | --- |
| Reporter | `mohammedmessaoudene-cmd`, who found the Windows path mismatch the reader carried and fixed it in [#111](https://github.com/probityai/agent-evidence-vectors/pull/111) |
| Code | [`interop/action-tuple-framed-v1`](interop/action-tuple-framed-v1/README.md) at head [`454d01c`](https://github.com/probityai/agent-evidence-vectors/commit/454d01ca115112c533367d01b639d3471b478d58) of that pull request |
| Posted at | [#111, comment of 2026-10-20](https://github.com/probityai/agent-evidence-vectors/pull/111#issuecomment-6300148972) |
| Host | Windows NT build 26200 (Windows 11), CPython 3.14.3 and 3.12.5, 64-bit, `core.autocrlf=true` inherited from the system Git config |
| Manifest | SHA-256 `0a81393d3e9af4e5ef020a7325a0d7c51196506f83292064ec17c6676f1446f1`, all 39 pinned members matching |
| Tests, each runtime | 20 run: 17 pass, 3 errors, suite exit 1. The three errors are WinError 1314, the privilege to create symlinks, which that host did not grant. The Windows-path, autocrlf checkout and numeric `EEXIST` tests pass |
| Corpus, each runtime | exit 0, 36/36 declared outcomes matched, expected refusals included |
| Label, by its author | a project-controlled local portability retest |

In his words, what it does not show:

> It does not turn the symlink cases into passing tests or provide independent
> host identity attestation.

The hosted Windows and Linux matrix at the same head passed all four cells,
symlink tests included. This row is the result from a host outside GitHub's
runners, where the symlink privilege was missing.

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
