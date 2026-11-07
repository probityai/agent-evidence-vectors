# refund-connected/v1 · the `input_pic` layer as an external contract

`corpora/vectors-refund-connected` retains a multi-party run, and the packaged reader
re-derives six verdicts per case from its bytes. [refund-connected-input-aps.md](refund-connected-input-aps.md)
states the second layer, `input_aps`, as a contract an outside reader can implement alone.
This document does the same for the first layer, `input_pic`. It is written from the
retained bytes and the packaged reader's behaviour; where the two disagree, the bytes win
and this document is wrong.

## What the layer decides

Whether the PIC proposal the caller is about to act on carries one valid, trusted merchant
attestation, and whether that attestation's three digests cover exactly the arguments, the
claims and the intent text the proposal carries. It then checks that the runner's own PIC
result file is about these same bytes and says `allow`.

It answers one question: **did a trusted merchant key sign exactly these refund arguments,
this claim and this intent, and did the runner record that it allowed them?**

It does not decide whether the APS approval exists, is unexpired or matches the payload,
whether the admission record committed, or whether anything was executed. Those are later
layers. Unlike `input_aps`, this layer takes no values from a caller: it is the first layer
and reads only the case directory.

## Inputs

Paths are relative to `source/<run>/cases/<case>/` inside the corpus.

| File | Role |
| --- | --- |
| `inputs/pic-proposal.json` | the PIC proposal: `action`, `claims`, `evidence`, `impact`, `intent` (other members, such as `protocol` and `provenance`, are not read) |
| `trust/pic-keys.json` | the PIC keyring: trusted keys by key id, and a list of revoked key ids |
| `inputs/pic-verification.json` | the runner's PIC result for this proposal |
| `inputs/aps-intent.json`, `inputs/aps-approval.json`, `inputs/aps-action.json`, `inputs/aps-payload.json`, `inputs/decision-evidence.json`, `trust/aps-consumption.json`, `trust/handoff-issuance.json`, `trust/handoff-evaluation.json` | not read by this layer, but each must be present and must strict-parse (step 0) |

Step 0 covers these eleven files and no others: the three above plus the eight in the last row.

## Canonical forms

| Form | Definition |
| --- | --- |
| `JCS(v)` | RFC 8785 canonical JSON of `v` as UTF-8 bytes |
| `sha_hex(b)` | lowercase hex SHA-256 of the bytes `b`, with **no** `sha256:` prefix |
| `file_ref(b)` | `"sha256:" + sha_hex(b)`, over the raw file bytes exactly as stored |
| strict parse | UTF-8; duplicate member names refused at every depth; any number with a fraction or exponent part refused (integers of any size are accepted); `NaN`/`Infinity` refused |
| equality | same JSON type and same value; `true` is not `1`; list order is significant |
| hex64 | a string of exactly 64 characters from `0-9a-f` |
| printable ASCII id | a non-empty string whose every character is in `0x20`..`0x7E` |
| base64 | RFC 4648 section 4 standard alphabet with `=` padding; a character outside the alphabet, or wrong padding, is a decode failure |
| Ed25519 | RFC 8032 section 5.1.7 verification of the 64-byte signature over `message` with the 32-byte public key; a signature of any other length fails |

Two digests are taken over JSON values (`JCS`), and one over a plain string's UTF-8 bytes.
Keep them apart:

```
args digest   : sha_hex(JCS(proposal.action.args))
claims digest : sha_hex(JCS(proposal.claims))
intent digest : sha_hex(UTF-8 bytes of proposal.intent)
signature     : Ed25519 over JCS(att), where att is the parsed attestation object
```

The signature message is `JCS` of the **parsed** attestation, not the raw `payload` string.
In the corpus the two are byte-identical, because the payload is written in JCS form; a
reader that verifies over the raw string agrees on every retained vector but is not
following this contract.

## Procedure

Let `prop` be the parsed proposal, `keys` the parsed keyring and `result` the parsed runner
result. Steps run in this order and the first failing one decides the layer. Where a step
reads a member of a value that is not an object, or a member that is absent, the step fails.

| # | Condition | Code |
| --- | --- | --- |
| 0a | all eleven case files listed under Inputs are present | `NOT_ESTABLISHED:input-files-missing` |
| 0b | every one of them strict-parses | `REFUSED:STRICT_PARSE` |
| 1 | `prop` is an object; `prop.evidence` is a list of exactly one element; that element (call it `entry`) is an object with `entry.type == "sig"` | `REFUSED:PIC_EVIDENCE` |
| 2 | `entry.payload` is a string; it strict-parses (call the result `att`); `att` is an object with exactly the members `attestation_version`, `tool`, `impact`, `provenance_ids`, `args_digest`, `claims_digest`, `intent_digest`, `expires_at`; and `att.attestation_version == "PIC-ATT/1.0"` | `REFUSED:PIC_ATTESTATION` |
| 3 | `keys` is an object with exactly the members `trusted_keys` and `revoked_keys`; `trusted_keys` is an object; `revoked_keys` is a list | `REFUSED:PIC_KEYRING` |
| 4 | `entry.key_id == entry.signer`, and `entry.key_id` is not an element of `revoked_keys` | `REFUSED:PIC_KEY` |
| 5 | `trusted_keys[entry.key_id]` exists; it is either a hex64 string, or an object whose `public_key` is a hex64 string; that string is the public key | `REFUSED:PIC_KEY` |
| 6 | `entry.signature` is a string that base64-decodes (a missing or non-string `signature` fails this step); `entry.alg == "ed25519"` (lowercase); and the decoded signature verifies over `JCS(att)` with the public key from step 5 | `REFUSED:PIC_SIGNATURE` |
| 7 | `prop.action` is an object with `action.tool == "refund"`; `prop.impact == "money"`; `att.tool == "refund"`; `att.impact == "money"`; and `att.provenance_ids` is the one-element list `[entry.id]` | `REFUSED:PIC_PROFILE` |
| 8 | `args = prop.action.args` is an object with exactly `payment_id`, `amount_minor`, `currency`; `payment_id` is a string matching `[A-Za-z0-9_-]+`; `amount_minor` is an integer (not a boolean) with `0 < amount_minor <= 2**53 - 1`; `currency == "EUR"` | `REFUSED:PIC_PROFILE` |
| 9 | `sha_hex(JCS(args)) == att.args_digest` | `REFUSED:PIC_ARGS_DIGEST` |
| 10 | `sha_hex(JCS(prop.claims)) == att.claims_digest` (taken before the claims' shape is checked; an absent `claims` member fails here) | `REFUSED:PIC_CLAIMS_DIGEST` |
| 11 | `prop.intent` is a string and `sha_hex(UTF-8(prop.intent)) == att.intent_digest` | `REFUSED:PIC_INTENT_DIGEST` |
| 12 | `prop.claims` is a list of exactly one element; that element is an object with exactly the members `text` and `evidence`; `evidence` is the one-element list `[entry.id]`; `text` is a string | `REFUSED:PIC_CLAIM` |
| 13 | `text` strict-parses (call it `claim`); `claim` is an object with exactly `approval_ref` and `decision_id`; `JCS(claim)`, decoded as UTF-8, equals `text` exactly (the claim text must already be canonical); `claim.approval_ref` is hex64; `claim.decision_id` is a printable ASCII id | `REFUSED:PIC_CLAIM` |
| 14 | `result` is an object with exactly the members `schema`, `contract_revision`, `run_id`, `pic_sdk_commit`, `proposal_file_ref`, `pic_trust_file_ref`, `evaluated_at`, `result`, `tool`, `impact`, `args_digest`, `claims_digest`, `intent_digest`, `error_code` | `CONTRADICTED:PIC_RESULT_SHAPE` |
| 15 | `result.result == "allow"` and `result.error_code` is `null` | `CONTRADICTED:PIC_RESULT_BLOCKS` |
| 16 | `result.schema == "refund-sandbox-pic-result/0.1"`, `result.contract_revision == "review-2026-10-23"`, `result.pic_sdk_commit == "330fdd817ef81d43461ea1787939e0d1cc87d589"` | `CONTRADICTED:PIC_RESULT_SCHEMA` |
| 17 | `result.proposal_file_ref == file_ref(raw bytes of inputs/pic-proposal.json)` | `CONTRADICTED:PIC_RESULT_PROPOSAL_REF` |
| 18 | `result.pic_trust_file_ref == file_ref(raw bytes of trust/pic-keys.json)` | `CONTRADICTED:PIC_RESULT_TRUST_REF` |
| 19 | `result.args_digest`, `result.claims_digest` and `result.intent_digest` equal `att.args_digest`, `att.claims_digest` and `att.intent_digest` | `CONTRADICTED:PIC_RESULT_DIGESTS` |
| 20 | `result.tool == "refund"` and `result.impact == "money"` | `CONTRADICTED:PIC_RESULT_TOOL` |

If every step holds the layer is `ESTABLISHED`.

### The runner-allowed rule

Steps 0b to 13 refuse. One rule rewrites a refusal after the fact: when a step from 0b to
13 refuses with code `X`, and `inputs/pic-verification.json` strict-parsed to an object
whose `result` member is the string `"allow"`, the verdict is
`CONTRADICTED:runner-allowed-X` instead of `REFUSED:X` (for example
`CONTRADICTED:runner-allowed-PIC_ARGS_DIGEST`). The proposal is bad, and the
runner's own record says it let the proposal through; that is a contradiction between two
parties' bytes, not a clean refusal. When the runner's result says `block`, or is missing,
or did not parse, the refusal stands. The rule does not apply to `input-files-missing`,
which is not a refusal.

So the layer produces four kinds of verdict: `ESTABLISHED`, `REFUSED:<code>` (steps 0b to
13), `CONTRADICTED:<code>` (steps 14 to 20, and the runner-allowed rule) and
`NOT_ESTABLISHED:input-files-missing` (step 0a). It never produces `NOT_REACHED`, because
nothing runs before it.

## What the layer hands to the next one

An `ESTABLISHED` verdict also yields the values the
[`input_aps` contract](refund-connected-input-aps.md#inputs) takes from its caller:

| Value | From this layer |
| --- | --- |
| `claim` | `claim` from step 13 |
| `pic_args` | `args` from step 8 |
| `attestation_expires_at` | `att.expires_at` from step 2 |
| `consumed_at` fallback | `result.evaluated_at`, used by `input_aps` only when no admission record names `claim.approval_ref` |

A caller that chains the two contracts runs `input_aps` only when this layer is
`ESTABLISHED`; otherwise `input_aps` is `NOT_REACHED`, assigned by the caller.

## Coverage in the corpus

The manifest carries one expected verdict per vector per layer. For this layer all twelve
vectors are scored, and they split into two observed outcomes:

- **established**: `j01`, `n1b-aps-payload`, `n3-reissue`, `n3b-old-pic` and `n4-lost-ack`, in both runs (ten vectors). `n1b` and `n3b` are bad at the APS layer, not here: their PIC proposals are sound.
- **`REFUSED:PIC_ARGS_DIGEST`**: `n1a-pic-args`, in both runs (two vectors).

Every other code in the procedure is unexercised by these bytes. That is a property of the
corpus, not of the contract: an implementation that returns `ESTABLISHED` for the ten and
`REFUSED:PIC_ARGS_DIGEST` for the two is consistent with every vector, and one that returns
anything else for any of them is not.

## Running an independent verifier

The layer needs only the case directory:

```
<cmd> source/<run>/cases/<case> --json
```

The last nonempty stdout line is one JSON object on one line, for example
`{"verdict": "ESTABLISHED"}` or `{"verdict": "REFUSED:PIC_ARGS_DIGEST"}`. The exit status is
`0` for `ESTABLISHED` and nonzero otherwise. Score it against the `input_pic` value in each
vector's `expected.steps`. A one-shot run is not a conformance claim; pin the corpus at a
release or a commit and say which run and which case each verdict came from, as
`docs/VERIFIERS.md` asks.

## Worked example: `r1` / `n1a-pic-args`

The merchant signed an attestation over a refund of 4000 minor units of EUR on `pay_C`;
the proposal then carries `amount_minor: 4100`. Steps 1 to 8 hold: the signature is
valid, because the attestation itself was not touched, and the arguments still have the
refund shape. Step 9 is where it shows:

```
sha_hex(JCS({"amount_minor":4100,"currency":"EUR","payment_id":"pay_C"}))
  = 3de849c198291237785735b7a1d013fd13e9f164f80e4d296ea08aac8e1393c5
att.args_digest
  = 6a0df2560801d3e76a4b8052fca7e84790bcfc7c5773bbefd353ba73fd53dede
  = sha_hex(JCS({"amount_minor":4000,"currency":"EUR","payment_id":"pay_C"}))
```

They differ, so the layer refuses with `PIC_ARGS_DIGEST`. The runner's result for this
case says `"result": "block"` with `"error_code": "PIC_EVIDENCE_FAILED"`, so the
runner-allowed rule does not apply and the verdict stays `REFUSED:PIC_ARGS_DIGEST`. Nothing
downstream is read for this case.

## What this contract does not do

- It does not judge the run. A verdict from it is a verdict for `input_pic` only.
- It does not check the PIC attestation's own `expires_at`; `input_aps` compares it with the consumption instant (its step 25).
- It does not cover `input_aps` (see [refund-connected-input-aps.md](refund-connected-input-aps.md)), `admission`, `signature_trust`, `execution` or `observed_effect`.
- The manifest's `verifierContract` names the `input_aps` layer. This document is the interface for `input_pic` in the same shape; a verifier built from it answers for that layer alone.
