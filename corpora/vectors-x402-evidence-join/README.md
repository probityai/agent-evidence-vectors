# vectors-x402-evidence-join

Cases for `x402-evidence-join/v1`: one x402 evidence package, judged from its own record, for whether the offer, the payment, the settlement and the delivery join.

For: x402 resource servers, facilitators, client SDKs and verifiers that need a third party to recompute the offer-to-settlement join from the evidence alone.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

`gen_vectors.py` writes every case, `MANIFEST.json`, `INDEX.md` and `profile.json`. Field names follow the x402 v2 specification (`PaymentRequirements`, `ResourceInfo`, `SettlementResponse`) at the commit `MANIFEST.json` pins.

## Run it

```bash
pip install agent-evidence-vectors
python corpora/vectors-x402-evidence-join/check_vectors.py
```

It prints `answered N of N cases`. Add `--verifier "/path/to/verifier"` to judge them with your own.

## Verifier contract

`<verifier> <case-dir>/case.json --json` prints one JSON object with `decision` and `reason`, and exits 0 for `accepted`, 1 for `rejected`, 2 for `indeterminate`. The reason is the first rule that fires, in the order of `agent_evidence_vectors.x402join`.

The record carries the seller domain and its keys, the signed offer, the payment authorization, the facilitator's `SettlementResponse`, a ledger read, the delivered body, the receipt and the fulfilment evaluation. The reader recomputes the offer and delivery digests rather than trusting the fields that claim them.

## Three decisions

The decisions map onto the outcomes of the x402 Evidence Chain RFP, sections 4.4.1 and 4.4.3:

| Decision | RFP outcome | Meaning here |
| --- | --- | --- |
| `accepted`, `join_holds` | verified | every join recomputes |
| `rejected` | contradicted | evidence present fails the join |
| `indeterminate` | indeterminate | evidence needed for the join is absent |
| `fulfilment.evaluated: false` | not evaluated | recorded; does not block acceptance |

A facilitator assertion alone is never accepted as ledger proof (RFP 4.4.2).

## Cases

| Case | Expected | What it is |
| --- | --- | --- |
| evm-exact-join | accepted, `join_holds` | EVM exact payment, ledger agrees, fulfilment not evaluated |
| solana-exact-join | accepted, `join_holds` | Solana exact payment, ledger agrees, fulfilment not evaluated |
| evm-exact-join-fulfilment-met | accepted, `join_holds` | declared fulfilment criteria evaluated and met |
| seller-key-outside-domain | rejected, `seller_key_not_domain_bound` | receipt key not listed by the seller domain |
| offer-terms-edited | rejected, `offer_digest_mismatch` | amount changed after the offer digest |
| payment-for-other-offer | rejected, `payment_not_for_offer` | payment names another offer |
| payer-not-signer | rejected, `payer_not_authorization_signer` | payment signed by an address other than the payer |
| payee-swapped | rejected, `payee_not_offer_payee` | authorization pays another address than payTo |
| amount-short | rejected, `amount_not_offer_amount` | one atomic unit short of the offer amount |
| receipt-names-other-offer | rejected, `receipt_names_other_offer` | receipt names another offer |
| receipt-omits-offer-digest | indeterminate, `receipt_offer_unbound` | receipt carries no offer digest |
| no-transaction-reference | indeterminate, `settlement_reference_missing` | no transaction in the receipt or a ledger read |
| facilitator-success-ledger-reverted | rejected, `settlement_conflict` | facilitator says success, ledger says reverted |
| ledger-pays-other-address | rejected, `ledger_transfer_not_offer_terms` | ledger credits another address than payTo |
| facilitator-only-settlement | indeterminate, `settlement_asserted_by_facilitator_only` | facilitator assertion, no ledger read |
| delivered-body-differs | rejected, `delivery_digest_mismatch` | delivered body differs from the bound digest |
| fulfilment-not-met | rejected, `fulfilment_not_met` | declared criteria evaluated, not met |

Each case that is not accepted is one mutation from the twin `INDEX.md` names.

## The checker is held to its rules

`mutation_check.py` switches each rule off alone; the corpus must catch every such mutant.

## Pin it in your CI

```yaml
- run: pip install agent-evidence-vectors==X.Y.Z
- run: python -m agent_evidence_vectors.x402join --verifier "your-verifier"
```

Pin the exact version; conformant means passing that version's cases.

## What it does not test

The fixtures are synthetic: signatures and ledger reads are modelled fields, never verified or fetched. It does not test the buyer's authority to pay (S1) or what happens after settlement (S8): those are in [vectors-agent-payment-mandate](../vectors-agent-payment-mandate/), [vectors-delegation-lifecycle](../vectors-delegation-lifecycle/) and [vectors-refund-connected](../vectors-refund-connected/).
