# Input contract: the `input_aps` layer of `refund-connected/v1`

Profile id: `refund-connected-aps-input/v0`.

`MANIFEST.json` declares a verifier contract for one of the six layers of this corpus, `input_aps`. This file is
that contract. It states the inputs, the byte constructions, the order of checks and the closed result vocabulary,
so that a reader can be written from this text alone, without importing `agent_evidence_vectors.refundconnected`,
the aps-receipt adapter or the APS SDK. Its fixtures are under [`input-aps/`](input-aps/).

The order of checks and the codes are the ones of
[`docs/reference/refund-connected-input-aps.md`](../../docs/reference/refund-connected-input-aps.md), which describes
the same layer; the column "Reference step" below maps one numbering onto the other. This file adds what
[#428](https://github.com/probityai/agent-evidence-vectors/issues/428) settled:

- the consumption instant is an input to this layer, never derived by it, and check 3j runs before check 7b, so
  `n3b-old-pic` is `REFUSED:APPROVAL_AFTER_CONSUMPTION`;
- the ordering of the PIC result's `evaluated_at` against the consumption instant belongs to the PIC layer and is
  not checked here;
- the receipt schema and stage rules of APS SDK 8.0.1 are normative (see "Receipt validity"), and one fixture
  breaks only a stage rule;
- the codes stay coarse; a reader's finer codes go in its `native` field.

## Scope

The layer answers one question per case: do the retained APS intent and approval receipts, their decision
evidence, the action and payload references and the PIC claim's binding to the approval hold at the consumption
instant, under the supplied APS trust selection?

It does not verify the PIC attestation signature or the PIC runner's result file (`input_pic`), the admission
record (`admission`), the handoff signature (`signature_trust`), dispatch (`execution`) or the provider record
(`observed_effect`). A case whose `input_pic` is not `ESTABLISHED` is not given to this layer; the corpus records
`input_aps` as `NOT_REACHED` for it (`n1a-pic-args`), and the caller assigns that verdict, not this layer.

## Inputs

A case is a directory holding these eleven regular files, plus one supplied value.

| Input | Used by this layer |
| --- | --- |
| `trust/aps-consumption.json` | the APS keys selected for consumption |
| `inputs/aps-intent.json` | the action-intent receipt |
| `inputs/aps-approval.json` | the policy-decision receipt |
| `inputs/decision-evidence.json` | the four decision components |
| `inputs/aps-action.json` | the action reference input |
| `inputs/aps-payload.json` | the refund tuple |
| `inputs/pic-proposal.json` | three members only: the claim text, the cited attestation's `expires_at`, `action.args` |
| `inputs/pic-verification.json` | presence and parse only |
| `trust/pic-keys.json` | presence and parse only |
| `trust/handoff-issuance.json` | presence and parse only |
| `trust/handoff-evaluation.json` | presence and parse only |
| `consumed_at` (supplied) | the consumption instant, exact UTC milliseconds `YYYY-MM-DDTHH:MM:SS.sssZ` |

`consumed_at` is not inside any of the eleven files. It is supplied beside the case: for a retained case in
[`input-aps/retained.json`](input-aps/retained.json), for a fixture in its `expected.json`. A reader takes it as
given.

From `inputs/pic-proposal.json` the layer reads:

- the claim: `claims[0].text` parsed as JSON, an object with exactly `approval_ref` and `decision_id`;
- the cited attestation's `expires_at`: `evidence[0].payload` parsed as JSON (the member is a JSON string), then its
  `expires_at`, written `YYYY-MM-DDTHH:MM:SSZ`;
- the PIC arguments: `action.args`.

Their shape is checked by `input_pic`, which runs first.

### Parsing

Each file is parsed once, strictly: UTF-8 without a byte order mark, no duplicate member names, no number written
with a fraction or an exponent, no `NaN` or `Infinity`. A file that fails is `REFUSED:STRICT_PARSE`. A missing file is
`NOT_ESTABLISHED:input-files-missing`. Missing files are checked before parsing.

### Constants of the refund profile

| Name | Value |
| --- | --- |
| worker | `did:example:refund-worker` |
| approval boundary | `did:example:refund-approval-boundary` |
| scope | `["payments:refund"]` |
| target | starts with `https://payments.operator.example/v1/payments/` and ends with `/refunds`; the payment id is what lies between |
| refund tuple | an object with exactly `payment_id` (a string matching `[A-Za-z0-9_-]+`), `amount_minor` (an integer, `0 < amount_minor <= 2**53 - 1`) and `currency` (`"EUR"`) |

## Byte constructions

`JCS(x)` is RFC 8785 over the parsed value. `H(b)` is lowercase hex SHA-256 of the bytes `b`. `0x00` is one zero
byte. Tags are ASCII.

| Value | Construction |
| --- | --- |
| receipt id | `H("APS-RECEIPT-ID-V1" 0x00 JCS(receipt without receipt_id and signatures))` |
| receipt signature message | `"APS-RECEIPT-SIG-V1" 0x00 JCS({"receipt": receipt without signatures, "signer": signature entry without value})`; Ed25519; `value` is the signature as lowercase hex |
| decision component ref | `H(tag 0x00 JCS(component))`, tags `APS-DECISION-AUTHORITY-V1` (`authority_state`), `APS-DECISION-POLICY-V1` (`policy_input`), `APS-DECISION-CONTEXT-V1` (`decision_context`), `APS-DECISION-OUTPUT-V1` (`decision_output`) |
| decision ref | `H("APS-DECISION-REF-V1" 0x00 JCS({"profile": "aps-decision-ref-v1", "action_ref": approval.action_ref, "authority_state_ref": …, "policy_ref": …, "context_ref": …, "decision_output_ref": …}))` |
| action ref | `H("APS-ACTION-REF-V2" 0x00 JCS(aps-action.json))` |
| payload ref | `H("APS-ACTION-PAYLOAD-V1" 0x00 JCS(aps-payload.json))` |

### Receipt validity

A receipt of type `T` from issuer `I` is valid when all of these hold:

1. `profile` is `aps-receipt-v1`, `receipt_type` is `T`, `issuer` is `I`.
2. Envelope schema. Its members are exactly `profile, receipt_id, receipt_type, issuer, subject_agent, action_ref,
   delegation_ref, issued_at, evidence_refs, result, signatures`, plus `decision_ref` and `prev` where present.
   `receipt_type`, `issuer` and `subject_agent` are non-empty strings; `delegation_ref` matches
   `sha256:[0-9a-f]{64}`; `receipt_id`, `action_ref`, and `decision_ref` and `prev` when present, match
   `[0-9a-f]{64}`; `issued_at` is exact UTC milliseconds; `result` is an object; every integer is within
   `-(2**53 - 1)` to `2**53 - 1`; no string or member name holds a lone surrogate or a Unicode noncharacter. `evidence_refs` is an array of objects with exactly `artifact_type` (a non-empty string) and
   `sha256` (`[0-9a-f]{64}`), sorted by (`artifact_type`, `sha256`) as UTF-8 bytes with no duplicate.
3. Signature entries. `signatures` is a non-empty array of objects with exactly `signer, key_id, alg, value`:
   non-empty `signer` and `key_id`, `alg` equal to `Ed25519`, `value` matching `[0-9a-f]{128}`, sorted by (`signer`,
   `key_id`) as UTF-8 bytes with no duplicate, and at least one entry whose `signer` is `I`.
4. `receipt_id` equals the receipt id construction.
5. Every signature entry verifies. Its key is the entry of `trust/aps-consumption.json` with the same `signer` and
   `key_id`, with `not_before <= issued_at`, and `not_after` null or `issued_at < not_after`; for the intent also
   `revoked_at` null or `issued_at < revoked_at`. For the approval, revocation is not read at issuance; it is read at
   the consumption instant by check 3l.
6. Stage rules. For `aps:action-intent:v1`: `issuer == subject_agent`, no `prev`, no `decision_ref`, and `result` is
   exactly `{"profile": "aps-action-intent-result-v1", "status": "declared"}`. For `aps:policy-decision:v1`: `prev`
   and `decision_ref` are present; `result` is a core decision output, an object with exactly `profile`
   (`aps-core-decision-output-v1`), `verdict` (`permit`, `deny` or `narrow`), `effective_authority_ref`,
   `constraints` and `valid_until`, where `effective_authority_ref` is `[0-9a-f]{64}` and `valid_until` is exact UTC
   milliseconds unless the verdict is `deny` (then both are null), and `constraints` is an array of strings in NFC,
   sorted as UTF-8 bytes, with no duplicate; and when the verdict is not `deny`, `valid_until` is later than
   `issued_at`.

Items 2, 3 and 6 are the rules of `validateReceiptV1` and `validateReceiptStageV1` in `agent-passport-system` 8.0.1
(`dist/src/v2/receipt-core/receipt.js`, `stage.js` and `decision-ref.js`; the installed package tree has sha256
`4926ca17ecc588e1aad98866530a946ae000f589ec14937103f45994bacd1da5` under the rule: for every file in sorted path
order, its path relative to the package root, a newline, the sha256 hex of its bytes and a newline). The packaged
reader checks items 1, 4 and 5, and of item 3 only that `signatures` is a non-empty list of entries with `alg`
`Ed25519` and a string `value`. Item 5 asks every entry to verify, which is the packaged reader's rule; the SDK
requires the issuer's entry and reports the others separately, so a receipt with a second entry that does not
verify is valid to the SDK and not valid here. No fixture exercises that difference.

## The consumption instant

The corpus derives the instant per case, and this contract freezes the derived value:

- if `admission/state.json` of the run holds a committed record whose decision id is the claim's `decision_id` and
  whose `approval_ref` is the claim's `approval_ref`, the instant is that record's `committed_at` with `.000` added
  before the `Z`;
- otherwise it is `evaluated_at` of `inputs/pic-verification.json`.

[`input-aps/retained.json`](input-aps/retained.json) carries the value and which of the two rules gave it for every
retained case this layer decides. A reader that derives the instant itself is reading another layer.

## Order of checks

Checks run in this order. The first that fails gives the verdict, and nothing after it is evaluated.
[`input-aps/check-order.json`](input-aps/check-order.json) holds the same order as data.

| # | Reference step | Verdict | Fails when |
| --- | --- | --- | --- |
| 0a | 0 | `NOT_ESTABLISHED:input-files-missing` | any of the eleven files is missing |
| 0b | 0 | `REFUSED:STRICT_PARSE` | any file fails strict parsing |
| 1 | 1 | `REFUSED:TRUST_SELECTION` | the trust file is not exactly `schema, profile, scope, keys` with `schema` `hs-aps-consumption-trust/0.1`, `profile` `aps-receipt-v1`, `scope` `["payments:refund"]` and a non-empty `keys`; or a key is not exactly `signer, key_id, role, public_key, not_before, not_after, revoked_at` with `public_key` 64 lowercase hex characters |
| 2a | 2 | `REFUSED:INTENT_IDENTITY` | the intent's `issuer` or `subject_agent` is not the worker |
| 2b | 3 | `REFUSED:INTENT_NOT_VALID` | the intent is not a valid `aps:action-intent:v1` receipt from the worker |
| 3a | 4 | `REFUSED:DECISION_COMPONENTS` | `decision-evidence.json` is not exactly `authority_state, policy_input, decision_context, decision_output` |
| 3b | 5 | `REFUSED:APPROVAL_ISSUER` | the approval's `issuer` is not the approval boundary |
| 3c | 6 | `REFUSED:APPROVAL_NOT_VALID` | the approval is not a valid `aps:policy-decision:v1` receipt from the boundary |
| 3d | 7 | `REFUSED:DECISION_NOT_BOUND` | the decision ref construction is not the approval's `decision_ref`, or `JCS(decision_output) != JCS(approval.result)` |
| 3e | 8 | `REFUSED:APPROVAL_PREV` | `approval.prev` is not the intent's `receipt_id` |
| 3f | 9 | `REFUSED:APPROVAL_INTENT_ACTION` | the approval and the intent differ in `action_ref` or `subject_agent` |
| 3g | 10 | `REFUSED:APPROVAL_BEFORE_INTENT` | `approval.issued_at < intent.issued_at` |
| 3h | 11 | `REFUSED:VERDICT_NOT_PERMIT` | `approval.result.verdict` is not `permit` |
| 3i | 12 | `REFUSED:DECISION_CONSTRAINTS` | `approval.result.constraints` is not an empty array |
| 3j | 13 | `REFUSED:APPROVAL_AFTER_CONSUMPTION` | `consumed_at < approval.issued_at` |
| 3k | 14 | `REFUSED:DECISION_EXPIRED_AT_CONSUMPTION` | `approval.result.valid_until <= consumed_at` |
| 3l | 15 | `REFUSED:APPROVAL_SIGNER_REVOKED_AT_CONSUMPTION` | a key that signed the approval has `revoked_at <= consumed_at` |
| 4a | 16 | `REFUSED:ACTION_INPUT` | the action's `profile` is not `aps-action-ref-v2`, `action_type` not `refund`, `scope_required` not `["payments:refund"]`, or `agent_id` not the worker |
| 4b | 17 | `REFUSED:TARGET` | `target` does not start with the target prefix and end with `/refunds` |
| 4c | 18 | `REFUSED:ACTION_REF` | the action ref construction is not `approval.action_ref` |
| 5a | 19 | `REFUSED:PAYLOAD_SCHEMA` | the payload is not a refund tuple |
| 5b | 20 | `REFUSED:PAYLOAD_REF` | the payload ref construction is not `action.payload_ref` |
| 5c | 21 | `REFUSED:TARGET_PAYMENT_ID` | `payload.payment_id` is not the payment id in `target` |
| 6 | 22 | `REFUSED:DECISION_ID` | `decision_evidence.policy_input.merchant_decision.decision_id` is absent or not a non-empty printable ASCII string |
| 7a | 23 | `REFUSED:PIC_DECISION_ID` | the claim's `decision_id` differs from the merchant decision id |
| 7b | 24 | `REFUSED:PIC_APPROVAL_REF` | the claim's `approval_ref` differs from the approval's `receipt_id` |
| 7c | 25 | `REFUSED:PIC_EXPIRED_AT_CONSUMPTION` | the cited attestation's `expires_at` is not later than `consumed_at` |
| 7d | 26 | `REFUSED:PIC_ARGS_NOT_PAYLOAD` | `JCS(proposal.action.args) != JCS(payload)` |

Timestamps here are exact UTC milliseconds, fixed width, so comparing them as strings compares the instants.
`expires_at` is written to the second; compare it after adding `.000` before the `Z`.

Check 3j precedes check 7b. That order decides `n3b-old-pic`: its claim names the earlier approval of `j01`, so the
instant is the commit of `j01`, earlier than the new approval, and the case is refused at 3j.

## Result vocabulary

Exactly one verdict per case:

- `ESTABLISHED`: every check passed.
- `REFUSED:<code>`: the first failing check, steps 0b to 7d, `<code>` from the table.
- `NOT_ESTABLISHED:input-files-missing`: step 0a.

The set is closed. A reader may report its own finer code beside the verdict in a `native` field (for example an
SDK failure code, or a split of `ACTION_INPUT` into action type, scope and worker); the mapping is the reader's claim
and is not compared.

## Fixtures

[`input-aps/retained.json`](input-aps/retained.json) lists the retained cases this layer decides, each with its frozen
`consumed_at` and the corpus's `input_aps` verdict from `MANIFEST.json`. They exercise three outcomes:
`ESTABLISHED`, `REFUSED:PAYLOAD_REF` and `REFUSED:APPROVAL_AFTER_CONSUMPTION`.

`input-aps/cases/<id>/` holds one more fixture each: `case/` with the case files, and `expected.json` with the
supplied `consumed_at`, the check the fixture is meant to reach, the expected verdict, and what the packaged reader
returns for this layer. Every fixture starts from `source/j01-connected-20261028-r2/cases/j01`.

| Fixture | Edit of r2 `j01` | Check | Expected |
| --- | --- | --- | --- |
| `x-trust-scope` | trust `scope` set to `["payments:charge"]` | 1 | `REFUSED:TRUST_SELECTION` |
| `x-intent-edit` | intent `issued_at` one millisecond earlier | 2b | `REFUSED:INTENT_NOT_VALID` |
| `x-decision-edit` | `decision_context.channel` set to another string | 3d | `REFUSED:DECISION_NOT_BOUND` |
| `x-consumed-early` | `consumed_at` one second before the approval's `issued_at` | 3j | `REFUSED:APPROVAL_AFTER_CONSUMPTION` |
| `x-consumed-late` | `consumed_at` equal to the approval's `valid_until` | 3k | `REFUSED:DECISION_EXPIRED_AT_CONSUMPTION` |
| `x-boundary-revoked` | the boundary key's `revoked_at` one second before `consumed_at` | 3l | `REFUSED:APPROVAL_SIGNER_REVOKED_AT_CONSUMPTION` |
| `x-action-edit` | action `nonce` changed | 4c | `REFUSED:ACTION_REF` |
| `x-payload-dup` | payload written with `currency` twice | 0b | `REFUSED:STRICT_PARSE` |
| `x-file-missing` | `inputs/aps-action.json` removed | 0a | `NOT_ESTABLISHED:input-files-missing` |
| `s-intent-result-status` | intent `result.status` set to `submitted`, chain re-signed | 2b | `REFUSED:INTENT_NOT_VALID` |

The nine `x-` fixtures need no new signature: the trust file and `consumed_at` are unsigned inputs, and every other
edit breaks a value the reader recomputes. The packaged reader returns the expected verdict for each of them.

`s-intent-result-status` breaks only the `aps:action-intent:v1` stage rule on `result` (item 6 above). Every other
value holds: the intent and the approval are signed again with keys of their own, the approval's `prev` names the new
intent, the claim names the new approval, and the PIC attestation and the runner's result are rebuilt over the new
claim, so `input_pic` is `ESTABLISHED`. The keys are Ed25519 seeds `sha256(label + role)`, with the label and the
roles in `expected.json`, so that anyone can rebuild the signatures; they are test keys. A reader that applies the SDK
8.0.1 stage rules refuses the case at 2b. The packaged reader, which does not, returns `ESTABLISHED`; `expected.json`
records both, and this is the fixture on which the two split.

`gen_vectors.py` writes every file under `input-aps/` and refuses when a byte edit does not occur exactly once or
when the packaged reader does not return what the paragraphs above say it returns.

## Running a reader

```
verifier refund-connected/v1 <case-dir> --consumed-at <instant> --json
```

`<case-dir>` is a retained case directory or `input-aps/cases/<id>/case`, and `<instant>` the frozen `consumed_at`
for it. The last non-empty line on stdout is one JSON object, `{"verdict": "<verdict>", "native": "<code or null>"}`.
The exit status is `0` for `ESTABLISHED` and `1` for any other verdict.

Report, per case: the verdict, the `native` code, and whether the verdict equals the expected one; then the number of
differences. Name the reader's language, its source location and commit, and state that it does not import
`agent_evidence_vectors.refundconnected`, the aps-receipt adapter or the APS SDK. A reader written by the author of
this contract, or by the author of either existing reader, shows that the text can be implemented; it is not
agreement evidence.

## What counts as not established

- **A refusal at this layer says nothing about dispatch.** A refused case is checked downstream only for leaks (an
  admission record or a consumed approval after the refusal); this layer reports neither.
- **The consumption instant is an input, not a finding.**
- **A valid receipt is not a legitimate merchant, a moved refund or a real key.** The keys are test keys selected by
  the trust file; nothing here says who holds them.
- **`ESTABLISHED` at this layer does not establish `input_pic`.** The PIC attestation signature and the runner's
  result are read by another layer; this layer reads three members of the proposal.

## What a pass does not establish

Nothing about the other five layers, the pilot outside these cases, APS or PIC in general, any production
deployment, or any project's adoption of anything. The source runs had one operator, public test keys and an
admission stand-in.
