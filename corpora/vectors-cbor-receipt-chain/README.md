# CBOR receipt chain vectors

Cases for `cbor_receipt_chain/v1` (suite `cbor-receipt-chain/v1`): a stream of signed CBOR
receipts, one per authorization decision and each linked to the one before it by the SHA-256 of
its bytes, judged as one ordered chain. Every receipt in a stream can verify on its own while the
stream is not what was written. A receipt can appear twice, one signed request can be allowed twice,
two receipts can swap places, the tail can be cut, a restart can hide a gap, and a record can be
re-signed under a key the consumer never trusted. A reader that checks only signatures passes all
of them.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-blue?style=flat-square&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

For anyone who builds or audits an authorization system that writes signed receipts, and wants a
reader that treats the stream as the evidence and not each receipt alone.

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-cbor-receipt-chain
python3 corpora/vectors-cbor-receipt-chain/check_vectors.py --verifier './verifier'
```

A verifier takes `case.json --json`, prints `{"decision": ..., "reason": ...}` and exits 0 for
`supported`, 1 for `contradicted` and 3 for `not_established`. In the GitHub Action, set
`corpus: vectors-cbor-receipt-chain`.

## What the cases force

Every trust input comes from the consumer's `case.json` (the pinned signer keys, the head the consumer
kept outside the stream, the count, an optional predecessor of the first receipt) and never from the
stream. The wire format is a pinned profile, `profile.json` (`cbor-receipt-profile/v1`): field numbers, the
signature context, the key form and the outer member names. A new format needs a new profile, not a new
reader. The neutral profile here is invented for the corpus; a profile that matches a real system is
a separate file under that system's owner.

The reference reader runs seven checks in order and names the first that fails, decision
`contradicted`: `receipt_shape`, `signature`, `signer_pinned`, `no_duplicate_receipt`, `single_use`,
`chain_order` and `head_anchor`. Each refusal case changes an accepting control so its own check is the
first to fail, and the tests switch each check off in turn and expect its cases to turn.

Three decisions are `not_established`, which is not an allow: `head_not_anchored` (no head was pinned,
so the stream may be a prefix, even when it is intact), `chain_reset` (a receipt names no
predecessor after the first, so the gap cannot be told from a restart) and `effect_not_recorded` (the
consumer needs the effect of the action and the format records the decision only). A cut tail with no
pinned head is `not_established` as well: nothing in the bytes shows a receipt is missing.

Controls: an intact anchored chain, a chain that continues an earlier run through the pinned
predecessor, and a denied request that is tried again, which is allowed because single use binds only
allowed receipts. The eighteen cases are 3 `supported`, 11 `contradicted` and 4 `not_established`;
the counts and the digest of every file are in `MANIFEST.json`.

## What it does not test

Which key a consumer should trust, key rotation, and the meaning of the action a receipt records. The
corpus gives the trust inputs and tests what a reader does with them. Every member is synthetic and is
signed with keys derived from fixed public labels that carry no trust outside this corpus.
Regenerate with `python3 corpora/vectors-cbor-receipt-chain/gen_vectors.py`.
