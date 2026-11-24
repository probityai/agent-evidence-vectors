# vectors-x402-payment-binding

Cases for `x402-payment-binding/v1`: what binds an x402 evidence record to one payment, judged as two verdicts. The authorization verdict asks whether the record identifies one EIP-3009 authorization; the settlement verdict asks whether a chain read identifies the Transfer log that settled it.

For: x402 facilitators, resource servers and verifiers that report payment evidence, and for the evidence XPs of the Evidence Chain RFP.

`gen_vectors.py` writes every case, `MANIFEST.json`, `INDEX.md` and `profile.json`. The manifest pins EIP-3009 and the x402 specification by commit and links the discussion the cases come from (x402-foundation/wg-identity#37 and x402-foundation/tsc#21).

## Run it

```bash
pip install agent-evidence-vectors
python corpora/vectors-x402-payment-binding/check_vectors.py
```

It prints `answered N of N cases`. Add `--verifier "/path/to/verifier"` to judge them with your own.

## Verifier contract

`<verifier> <case-dir>/case.json --json` prints one JSON object:

```json
{"authorization": {"state": "verified", "reason": "authorization_identified"},
 "settlement": {"state": "indeterminate", "reason": "authorization_not_yet_used"}}
```

It exits 0 when both states are `verified`, 1 when either is `contradicted`, and 2 otherwise. Each state is one of the four of the Evidence Chain RFP: `verified`, `contradicted`, `indeterminate`, `not_evaluated`. Each reason is the first rule that fires in its table, in the order of `agent_evidence_vectors.x402binding`.

## Why two verdicts

A record can identify its authorization while its settlement is still open. Case C carries the network, asset contract, payer and nonce, so it identifies one authorization, and the chain shows no `AuthorizationUsed` for it yet. Case A carries the accepted option and a time, and two payments in one transaction fit it, so it identifies neither. A verifier that answers one decision with one reason gives both "unresolved" and loses what C identifies; here that verifier fails C.

## What binds the record

| Binding | Scope | What it can establish |
| --- | --- | --- |
| the authorization's one-time value | network, asset contract, payer and nonce together | one authorization, whether or not it was used |
| a settlement reference beside it | network, transaction hash, and the log index where the transaction carries more than one Transfer | which Transfer settled the authorization |
| the accepted option only | network, asset, payTo and amount | never one authorization: unresolved, and never a settled transfer |

Network identifiers stay in the record as the origin served them. They are compared after mapping: a CAIP-2 identifier names itself, an x402 v1 name maps through the table in `profile.json` (taken from x402 at the pinned commit), and any other identifier is unknown and leaves the comparison unresolved.

## Decisions the discussion left open

- **Exactly one payment fits an option-only record.** The revised wording says unresolved where more than one fits. A chain read covers some transactions, not every payment the option could match, so one fit is still unresolved (`bound_by_accepted_option_only`).
- **Pairing a Transfer with its authorization.** EIP-3009 puts `AuthorizationUsed` before the Transfer only in its reference implementation, so no verifier pairs them by position. In a transaction with more than one Transfer of the asset, the log index is what names the transfer.
- **Not found is two answers.** `transferWithAuthorization` requires block time before `validBefore`. Unused before `validBefore` is pending (`authorization_not_yet_used`). Unused at a finalized head past `validBefore` can never settle (`authorization_expired_unused`, contradicted). The clock is the head's time, never the verifier's, and a head that is not final keeps the answer pending.
- **A read that failed is not a read that found nothing.** Both are indeterminate and both carry their own reason. No read at all is `not_evaluated`, so an offline run does not count against a record.
- **A broadcast hash is not a settlement.** x402 v2 lets a facilitator return `settlement_pending` with the hash it broadcast; the read decides.

## Cases

`INDEX.md` lists every case with both verdicts and its twin; each case's `rationale` in `MANIFEST.json` says where it comes from and what was decided.

| Case | Authorization | Settlement |
| --- | --- | --- |
| b-batch-log-index-names-transfer (case B) | verified | verified |
| a-option-only-two-payments-fit (case A) | indeterminate, `option_fits_more_than_one_payment` | indeterminate, `authorization_not_identified` |
| c-authorization-not-yet-used (case C) | verified | indeterminate, `authorization_not_yet_used` |
| c-valid-before-passed | verified | contradicted, `authorization_expired_unused` |
| c-confirmed-single-transfer and c-confirmed-network-served-as-base | verified | verified |
| network-identifier-unknown | indeterminate, `binding_network_unknown` | indeterminate, `authorization_not_identified` |
| c-chain-read-failed | verified | indeterminate, `chain_read_failed` |

## The checker is held to its rules

`mutation_check.py` switches each rule of both tables off alone; the corpus must catch every such mutant. A test also runs a verifier that collapses the two verdicts into one and requires the corpus to fail it.

## Pin it in your CI

```yaml
- run: pip install agent-evidence-vectors==X.Y.Z
- run: python -m agent_evidence_vectors.x402binding --verifier "your-verifier"
```

Pin the exact version; conformant means passing that version's cases.

## What it does not test

The fixtures are synthetic: chain reads are modelled fields, never fetched, and signatures are not verified. Whether the offer, payment, settlement and delivery join is [vectors-x402-evidence-join](../vectors-x402-evidence-join/); the buyer's authority to pay is [vectors-agent-payment-mandate](../vectors-agent-payment-mandate/).
