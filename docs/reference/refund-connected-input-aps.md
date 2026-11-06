# refund-connected/v1 · the `input_aps` layer as an external contract

`corpora/vectors-refund-connected` retains a multi-party run: two separate systems
produced the bytes, and the packaged reader re-derives six verdicts from them. Until
now the only way to check the corpus was to run that packaged reader, so an outside
implementation had to re-implement all six layers before it could score anything.

This document isolates **one** of the six layers — `input_aps` — and states it as a
contract that can be implemented and scored on its own. It is written from the
retained bytes and the packaged reader's behaviour; where the two disagree, the bytes
win and this document is wrong.

## What the layer decides

Whether the approval boundary's policy decision can be joined to the worker's action
intent, the action reference and the payload the caller is about to send — and whether
that approval was still usable at the instant the admission record consumed it.

It answers one question: **was there a single, unexpired, unrevoked, correctly bound
permit for exactly this action and exactly these arguments, at the moment of use?**

It does not decide whether the signature on the handoff is trusted, whether the
admission record committed, whether the executor ran, or whether an effect exists.
Those are other layers.

## Inputs

Paths are relative to `source/<run>/cases/<case>/` inside the corpus.

| File | Role |
| --- | --- |
| `inputs/aps-intent.json` | the worker's action-intent receipt (`aps:action-intent:v1`) |
| `inputs/aps-approval.json` | the boundary's policy-decision receipt (`aps:policy-decision:v1`) |
| `inputs/aps-action.json` | the action reference the approval points at |
| `inputs/aps-payload.json` | the arguments about to be sent |
| `inputs/decision-evidence.json` | the four decision components the approval summarises |
| `trust/aps-consumption.json` | the consumption trust snapshot the receipts are verified against |
| `inputs/pic-proposal.json` | only in that the caller takes the claim and the attested arguments from it (below) |
| `inputs/pic-verification.json` | only as the fallback source of the consumption instant (below) |
| `trust/handoff-issuance.json`, `trust/handoff-evaluation.json`, `trust/pic-keys.json` | not read by this layer, but their absence is an input-failure (below) |

Four values are supplied by the caller, because they come from the layers before this
one and this layer must not re-decide them:

| Value | Where the caller gets it |
| --- | --- |
| `claim` | parse `claims[0].text` of `inputs/pic-proposal.json`; an object whose members are exactly `approval_ref` and `decision_id` |
| `pic_args` | `action.args` of `inputs/pic-proposal.json` — the arguments the PIC attestation covers |
| `attestation_expires_at` | `expires_at` of the parsed `evidence[0].payload` of `inputs/pic-proposal.json` (that member is a JSON string, so parse it first) |
| `consumed_at` | the `committed_at` of the admission record in `admission/state.json` whose `approval_ref` equals `claim.approval_ref`, with `Z` replaced by `.000Z`; when no such record exists, `evaluated_at` from `inputs/pic-verification.json` |

If the caller has no verdict for the layer that produces these values, it may still
run this layer, but it must then say so: a reference to a claim it did not itself
establish is not the same evidence.

## Canonical forms

| Form | Definition |
| --- | --- |
| `JCS(v)` | RFC 8785 canonical JSON of `v` as UTF-8 bytes |
| `sha_hex(b)` | lowercase hex SHA-256 of the bytes `b` |
| `file_ref(b)` | `"sha256:" + sha_hex(b)` |
| `tag_ref(tag, v)` | `sha_hex(tag as ASCII + 0x00 + JCS(v))`, with **no** `sha256:` prefix |
| strict parse | UTF-8; duplicate member names refused; floats refused; `NaN`/`Infinity` refused |
| typed equality | same type and same value; `true` is not `1`; object member order is irrelevant; list order is significant |
| timestamp compare | the corpus writes `YYYY-MM-DDTHH:MM:SSZ` and `...SS.mmmZ`; comparisons are byte comparisons after the caller normalises to the precision the step names |
| Ed25519 | verify the signature bytes over `message` with the 32-byte key in the trust snapshot |

Domain separators, verbatim:

```
receipt id : "APS-RECEIPT-ID-V1"       + 0x00 + JCS(body)
receipt sig: "APS-RECEIPT-SIG-V1"      + 0x00 + JCS({"receipt": unsigned, "signer": descriptor})
action ref : "APS-ACTION-REF-V2"       + 0x00 + JCS(action document)
payload ref: "APS-ACTION-PAYLOAD-V1"   + 0x00 + JCS(payload document)
decision   : "APS-DECISION-REF-V1", "APS-DECISION-AUTHORITY-V1", "APS-DECISION-POLICY-V1",
             "APS-DECISION-CONTEXT-V1", "APS-DECISION-OUTPUT-V1"
```

`unsigned` is the receipt with its `signatures` member removed and every other member, `receipt_id` included, kept. The receipt id is the lowercase hex SHA-256 of the receipt-id preimage above.

A receipt is well-formed when it is an object with `profile == "aps-receipt-v1"`, the
expected `receipt_type`, the expected `issuer`, and a non-empty `signatures` list;
when `receipt_id` equals the receipt-id form over its body (every member except
`receipt_id` and `signatures`); and when **every** signature is well-formed and
verifies. A signature is well-formed when it has `alg == "Ed25519"` and a string
`value`; its key is looked up in the trust snapshot by `(signer, key_id)` and must
satisfy `issued_at >= not_before`, `not_after` is null or `issued_at < not_after`, and
— for the intent only — `revoked_at` is null or `revoked_at > issued_at`.
`descriptor` is the signature object without `value`.

Two fixed identifiers appear in this layer and are not configuration:
worker `did:example:refund-worker`, boundary `did:example:refund-approval-boundary`.
The refund target is `https://payments.operator.example/v1/payments/<payment_id>/refunds`.

## Procedure

Steps run in this order and the first failing one decides the layer. `REFUSED:<code>`
is the only verdict kind this layer produces.

| # | Condition | Code |
| --- | --- | --- |
| 0 | every retained case file is present; every one strict-parses | `NOT_ESTABLISHED:input-files-missing` / `REFUSED:STRICT_PARSE` |
| 1 | the trust snapshot is an object with exactly `schema`, `profile`, `scope`, `keys`; schema `hs-aps-consumption-trust/0.1`; profile `aps-receipt-v1`; scope exactly `["payments:refund"]`; `keys` a non-empty list, and every key has exactly `signer`, `key_id`, `role`, `public_key`, `not_before`, `not_after`, `revoked_at` with `public_key` 64 lowercase hex characters | `TRUST_SELECTION` |
| 2 | `intent.issuer` and `intent.subject_agent` both the worker | `INTENT_IDENTITY` |
| 3 | the intent receipt is well-formed and verifies, with revocation checked at issuance | `INTENT_NOT_VALID` |
| 4 | `decision` has exactly `authority_state`, `policy_input`, `decision_context`, `decision_output` | `DECISION_COMPONENTS` |
| 5 | `approval.issuer` is the boundary | `APPROVAL_ISSUER` |
| 6 | the approval receipt is well-formed and verifies, with revocation **not** checked at issuance | `APPROVAL_NOT_VALID` |
| 7 | `tag_ref("APS-DECISION-REF-V1", components) == approval.decision_ref`, where `components` is `profile: "aps-decision-ref-v1"`, `action_ref: approval.action_ref`, and the four tag refs of the decision's four members under their own separators, under the keys `authority_state_ref`, `policy_ref`, `context_ref` and `decision_output_ref`; and `JCS(decision.decision_output) == JCS(approval.result)` | `DECISION_NOT_BOUND` |
| 8 | `approval.prev == intent.receipt_id` | `APPROVAL_PREV` |
| 9 | `approval.action_ref == intent.action_ref` and `approval.subject_agent == intent.subject_agent` | `APPROVAL_INTENT_ACTION` |
| 10 | `intent.issued_at <= approval.issued_at` | `APPROVAL_BEFORE_INTENT` |
| 11 | `approval.result.verdict == "permit"` | `VERDICT_NOT_PERMIT` |
| 12 | `approval.result.constraints == []` | `DECISION_CONSTRAINTS` |
| 13 | `approval.issued_at <= consumed_at`, compared as strings | `APPROVAL_AFTER_CONSUMPTION` |
| 14 | `consumed_at < approval.result.valid_until`, compared as strings | `DECISION_EXPIRED_AT_CONSUMPTION` |
| 15 | for every approval signature, its key's `revoked_at` is null or later than `consumed_at` | `APPROVAL_SIGNER_REVOKED_AT_CONSUMPTION` |
| 16 | `action.profile == "aps-action-ref-v2"`, `action_type == "refund"`, `scope_required == ["payments:refund"]`, `agent_id` the worker | `ACTION_INPUT` |
| 17 | `action.target` starts with the payments prefix and ends with `/refunds` | `TARGET` |
| 18 | `sha_hex(action-ref form over the action document) == approval.action_ref` | `ACTION_REF` |
| 19 | the payload is an object with exactly `payment_id`, `amount_minor`, `currency`; `payment_id` matches `[A-Za-z0-9_-]+`; `amount_minor` is an integer with `0 < amount_minor <= 2**53 - 1`; `currency == "EUR"` | `PAYLOAD_SCHEMA` |
| 20 | `sha_hex(payload-ref form over the payload) == action.payload_ref` | `PAYLOAD_REF` |
| 21 | `payload.payment_id` equals the `payment_id` inside `action.target` | `TARGET_PAYMENT_ID` |
| 22 | `decision.policy_input.merchant_decision.decision_id` is a non-empty printable ASCII string | `DECISION_ID` |
| 23 | `claim.decision_id` equals that merchant decision id | `PIC_DECISION_ID` |
| 24 | `claim.approval_ref == approval.receipt_id` | `PIC_APPROVAL_REF` |
| 25 | `consumed_at < attestation_expires_at` normalised to milliseconds | `PIC_EXPIRED_AT_CONSUMPTION` |
| 26 | `JCS(pic_args) == JCS(payload)` | `PIC_ARGS_NOT_PAYLOAD` |

If every step holds the layer is `ESTABLISHED`.

Step 1 through step 26 are all `REFUSED`. The layer has no `CONTRADICTED` codes: every
failure it can see is a decision not to permit, or a document that cannot be read. When
a caller does not run the layer at all — because an earlier layer refused or did not
establish the case — the verdict is `NOT_REACHED`, and the caller assigns it, not this
layer.

Reading a case file that exists but does not strict-parse is `STRICT_PARSE`; a file the
corpus says should be there and is not is `input-files-missing`.

## Coverage in the corpus

The manifest carries one expected verdict per vector per layer. For this layer the
vectors split into three observed outcomes and one absence:

- **established** — the permit holds at the instant of consumption (`j01`, `n3-reissue`, `n4-lost-ack` in both runs);
- **`REFUSED:PAYLOAD_REF`** — `n1b-aps-payload`, where the payload was altered after the approval was issued, so the action's `payload_ref` no longer covers the bytes being sent;
- **`REFUSED:APPROVAL_AFTER_CONSUMPTION`** — `n3b-old-pic`, where an approval issued after the admission record consumed it is offered as if it had permitted it;
- **`NOT_REACHED`** — `n1a-pic-args`, where the earlier layer refuses on the PIC digest, so this layer is never asked.

Every other code in the procedure is unexercised by these bytes. That is a property of
the corpus, not of the contract: an implementation that returns `ESTABLISHED` for the
three established cases and the two named refusals above is consistent with every
vector, and an implementation that returns a different code for one of them is not.

## Running an independent verifier

The contract is deliberately routable at one case: give the implementation a case
directory and the four caller-supplied values, and read one verdict back.

```
<cmd> source/<run>/cases/<case> --consumed-at <instant> --pic-proposal source/<run>/cases/<case>/inputs/pic-proposal.json --json
```

The last nonempty stdout line is one JSON object on one line, `{"verdict": "ESTABLISHED"}`
or `{"verdict": "REFUSED:<code>"}`, and the exit status is `0` for `ESTABLISHED` and
nonzero for a refusal. A one-shot run is not a conformance claim; pin the corpus at a
release or a commit and say which run and which case each verdict came from, as
`docs/VERIFIERS.md` asks.

## Worked example: `r2` / `n1b-aps-payload`

The approval was issued over one payload and the run then carries another. Step 20 is
where it shows: recomputing the payload ref over the bytes in `inputs/aps-payload.json`
does not equal `action.payload_ref`, so the layer refuses with `PAYLOAD_REF` before any
step that asks about trust, admission or execution. Nothing downstream is read, and
nothing downstream may be claimed from this case.

## What this contract does not do

- It does not make the corpus scoreable by itself: an independent verifier still needs
  the caller-supplied values from the earlier layers, and a verdict for one layer is not
  a verdict for the run.
- It does not judge the run. The manifest's `verifierContract` declares this document as the
  interface for the `input_aps` layer only; a verdict from it says nothing about the other
  layers.
- It does not cover `input_pic`, `admission`, `signature_trust`, `execution` or
  `observed_effect`. Each of those would need its own document, and the two layers that
  the corpus exercises least — `execution` and `observed_effect` — would be the least
  scoreable ones to start with.
