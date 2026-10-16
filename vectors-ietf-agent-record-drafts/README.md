# IETF agent-record drafts conformance vectors

Conformance cases for three individual Internet-Drafts of the October 2026
SCITT wave, built from each draft's own structures, and each answering one
question: what must a conforming verifier say about this input, and what does
that verdict not establish?

| draft | what the cases test |
| --- | --- |
| [draft-emirdag-scitt-ai-agent-execution-01](https://datatracker.ietf.org/doc/draft-emirdag-scitt-ai-agent-execution/01/) | the AgentInteractionRecord hash chain of Sections 5.5 to 5.8 |
| [draft-mih-scitt-checkpointed-local-log-02](https://datatracker.ietf.org/doc/draft-mih-scitt-checkpointed-local-log/02/) | checkpoint verification (Section 4.3) and the Consistency Registration Policy (Section 4.5) |
| [draft-gruszka-scitt-statement-identification-02](https://datatracker.ietf.org/doc/draft-gruszka-scitt-statement-identification/02/) | whether a statement reference stays stable across equivalent encodings |

```
uv run --extra generators python vectors-ietf-agent-record-drafts/gen_vectors.py
uv run --extra generators python vectors-ietf-agent-record-drafts/check_vectors.py
```

The generator rebuilds `cases/`, `MANIFEST.json` and `INDEX.md` byte for byte.
The Go rail, `corpora/ietfagentrecord.go`, restates the same rules with its own
CBOR decoder, and `aee-verify vectors-ietf-agent-record-drafts` runs it.
The checker judges every member, re-reads every member under each draft's own
procedure, decodes every CBOR item a second time with cbor2, and disables each
rule in turn to show it is load-bearing. [INDEX.md](INDEX.md) lists every
member with its verdict, its verdict under the draft's own steps, and its
parent.

## How to score a verifier

A member is one case file: the bytes the verifier reads, as hex, and the state
it reads them against (preceding records, a Transparency Service's registered
history and clock, a reference digest). The answer lives in `MANIFEST.json`,
never in the case. A verifier conforms on a member when its verdict equals
`expected.verdict`; for the one indeterminate member, when its verdict is any
of those `readings` lists. `codes` name the reference reader's first refusal,
for comparing where two implementations stopped; the drafts define none.

Every member also carries:

- `draftReading`: the verdict the draft's own verification steps reach, with
  every rule marked `[corpus]` below switched off. Where it differs from the
  expected verdict, the draft's text does not catch the case.
- `does_not_assert`: what the expected verdict does not establish. A refused
  splice does not say which history the record continues; a refused late
  checkpoint does not say its entries were fabricated.
- `parent`: for every reject and the indeterminate member, the accept member it
  is one change from.

## draft-emirdag-scitt-ai-agent-execution-01

Records are COSE_Sign1 under ES256 with the draft's protected header fields
(`content_hash`, `prev_chain_hash`, `chain_hash`, `sequence_number`,
`action_timestamp_ms`, `agent_id`). The chain hash is the Section 5.7 pre-image:
`content_hash`, `prev_chain_hash`, the timestamp as a big-endian u64, then
`agent_id` as UTF-8 behind a big-endian u32 length. The draft
names no JSON form for its `bstr` fields; these payloads write them as
lowercase hex, and no verdict here depends on that choice. A verifier is given
the preceding records and the candidate records.

Section 5.8 takes the preceding `chain_hash` as an input and never compares it:
step 2 recomputes the chain hash from the header's own `prev_chain_hash`, and
step 4 compares only `sequence_number`. Three cases follow from that, and each
passes the draft's steps:

- `air-prev-chain-hash-mismatch`: record 1 whose `prev_chain_hash` is another
  chain's hash. Expected: invalid, `prev-chain-hash-mismatch`.
- `air-two-records-one-position`: two Issuer-signed records at sequence 1 over
  the same record 0, one completed and one failed. Expected: invalid,
  `chain-position-equivocation`.
- `air-timestamp-before-predecessor`: record 2 stamped one day before record 0,
  in header and payload alike. Section 6.3 compares only captured time with
  action time. Expected: invalid, `timestamp-regression`.

A fourth, `air-header-payload-time-differ`, has a header time, the one bound
into `chain_hash`, that differs from the payload's; nothing requires the two
copies to agree.

## draft-mih-scitt-checkpointed-local-log-02

The published checkpoints cp1 to cp4 are used as published. The draft's vector
repository is vendored verbatim at
[upstream/cll-02-vectors.json](upstream/cll-02-vectors.json), taken from
`action-state-group/checkpointed-local-log` at `4e8f098b`; the generator refuses
it unless its SHA-256 is the `7eec8d86...` that repository's `SHA256SUMS`
publishes, and re-signs each checkpoint with the 0x07 fixture seed to confirm
its bytes. A case gives the checkpoint, the service it registers at, that
service's registered history and clock, and the other services the producer
names.

- `cll-cp4-registered-two-weeks-late`: the published cp4, unchanged, registered
  on 27 October against an `issued_at` of 13 October and a cadence of 3600
  seconds. Neither Section 4.3 nor the Section 4.5 policy reads `issued_at` or
  `cadence`. Expected: invalid, `registration-late`.
- `cll-second-history-same-identity`: a first checkpoint for the same
  `(iss, sub)` over three other entries, registered first-seen at a second named
  service while the first holds cp1 to cp4. Section 4.5 lets the second service
  start a history, and nothing compares the two. Expected: invalid,
  `history-fork`.
- `cll-commitment-key-repeated`: a first checkpoint whose payload map writes
  `commitment` twice, cp1's and then a forked one. A last-wins decoder (cbor2)
  reads the fork and a first-wins decoder reads cp1; each reading passes
  Section 4.3. Section 4.2 requires the producer to encode deterministically,
  and no verifier step requires the check. Expected: malformed,
  `cbor-not-deterministic`.

`cll-issued-at-regression` adds the ordering case: cp3's claims issued again at
01:45, after cp3's 02:00 registration.

**The draft's reference verifier.** Every member was run through `cll02.py`,
the reference verifier in that repository, at `4e8f098b`, and its outcome is
recorded per member under `referenceVerifier`:

```
uv run --extra generators python vectors-ietf-agent-record-drafts/reference_run.py \
    <a clone of action-state-group/checkpointed-local-log at 4e8f098b>
```

It refuses the repeated-key checkpoint, because its strict decoder rejects
unsorted or repeated keys, which the draft's text does not require. It accepts
the late registration and the regression as `continuous`, and the second
history as `first-seen`, because it has no clock, no `issued_at` comparison and
no view of a second service.

## draft-gruszka-scitt-statement-identification-02

Statement 01 of Appendix A as printed, and the reference digest statement 02
carries (`c3f5f137...9dbc`, SHA-256 over ToBeSigned). The issuer and auditor
keys are the seeds Appendix A.2 publishes.

`sid-header-keys-reordered` is statement 01 re-signed by its own issuer seed,
with the decoded protected header and the payload unchanged and the header keys
written 15, 4, 3, 1. The draft hashes the header bytes as written, so its rule
reports NO_MATCH with a valid signature: the issuer decides whether a
reference reaches its own statement. The member is indeterminate with two
conforming readings:

- valid: the identifier is computed over the deterministic encoding of the
  protected header, so it stays stable across equivalent encodings;
- malformed: the scheme defines a canonical encoding and refuses a header not in
  it.

Reading the candidate as a different statement is not conforming.

Payload bytes stay identity-bearing in both readings: the payload is
application-defined, and no case here re-encodes it.

## Rules

A rule marked `[corpus]` is one this corpus adds; the draft's text does not
state it. The full text of every rule is in `MANIFEST.json` under `rules`, and
in [INDEX.md](INDEX.md).

| draft | rules the draft states | rules this corpus adds |
| --- | --- | --- |
| emirdag | `cose-shape`, `signature`, `content-hash`, `chain-hash`, `sequence` | `header-payload`, `prev-chain-link`, `time-order`, `position-unique` |
| mih | `cose-shape`, `signature`, `claims`, `continuity` | `deterministic-encoding`, `issued-at-order`, `registration-time`, `history-fork` |
| gruszka | `duplicate-key`, `signature`, `identity` (header bytes as written) | `identity` over the deterministic header encoding |

## Keys

Every key is a PUBLISHED TEST KEY. The AIR operator key is P-256, derived from
`sha256("agent-evidence-ietf-agent-record-drafts-test-key/air-operator/v1")`,
and signs with the deterministic nonce of RFC 6979. The CLL key is the 0x07
fixture of the draft's own vectors. The statement identification keys are the
seeds printed in that draft. Never use any of them for a real record.
