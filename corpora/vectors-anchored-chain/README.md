# Anchored record chain vectors

Cases for `anchored-record-chain/v1`: a stored history of signed agent memory
records, an anchor over that history signed by a key the store does not hold,
and the decision a verifier must reach. The edits are the storage-level
edits of
[draft-khandelwal-bmwg-agent-memory-integrity-01](https://datatracker.ietf.org/doc/draft-khandelwal-bmwg-agent-memory-integrity/),
Section 6, and the whole-store snapshot rollback the
[agmi](https://github.com/tech4biz-yasha/agmi) suite measures as T9, applied to a
signed chain, plus a rollback to an abandoned branch,
a re-anchoring attempt and three controls. The expected decision and reason
for every case are in `MANIFEST.json`.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

The point of the corpus is the column headed "every signature verifies". An
adversary with write access to the store and no key can delete, reorder,
replay and roll back records the system signed itself. Those stores pass any
check that verifies signatures and nothing else. Only the chain links and the
anchor catch them, and the corpus says which one.

| Case | Draft edit | Every signature verifies | Expected | Caught by |
| --- | --- | --- | --- | --- |
| intact | control | yes | verified, `chain_anchored` | |
| records-after-last-anchor | control | yes | verified, `records_after_last_anchor` | |
| t1-content-tamper | T1 | no | rejected, `signature_invalid` | record signature |
| t2-tail-removal | T2 | yes | rejected, `anchored_head_missing` | anchor |
| t2-tail-removal-after-last-anchor | T2 | yes | verified, `chain_anchored` | nothing can |
| t3-middle-deletion | T3 | yes | rejected, `chain_link_broken` | chain link |
| t4-reorder | T4 | yes | rejected, `chain_link_broken` | chain link |
| t5-forged-insertion | T5 | no | rejected, `signature_invalid` | record signature |
| t6-cross-context-replay | T6 | yes | rejected, `record_from_other_chain` | chain identity |
| t7-rollback-older-record | T7 | yes | rejected, `chain_link_broken` | chain link |
| t8-metadata-tamper | T8 | no | rejected, `signature_invalid` | record signature |
| t9-snapshot-rollback | T9 (agmi) | yes | rejected, `anchored_head_missing` | anchor |
| rollback-to-abandoned-branch | rollback | yes | rejected, `anchored_head_mismatch` | anchor |
| tail-removal-reanchored | T2, re-anchored | yes | rejected, `anchor_signature_invalid` | anchor key |

Three rows carry the findings a signature-only reading misses:

- **Tail removal is caught only by the anchor, and only for records written
  before it.** `t2-tail-removal-after-last-anchor` deletes records the last
  anchor never covered. What remains is byte for byte an honest store anchored
  at its head, so the case expects `verified`, and a verifier that rejects it
  is refusing an honest store.
- **Restoring one older record in place of the newest is caught by the chain
  links**, without the anchor: the restored record names the wrong
  predecessor.
- **Restoring the whole store to an older state is caught only by the
  anchor.** `rollback-to-abandoned-branch` holds records the producer really
  signed on a branch it later abandoned. Every signature verifies and every
  link holds.

## Running it

The package judges the corpus with its own reader:

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-anchored-chain
```

A verifier under test takes `case.json --json`, prints one JSON object
carrying `decision` and `reason`, and exits 0 for `verified` and 1 for
`rejected`:

```sh
agent-evidence-vectors --corpus vectors-anchored-chain --verifier './verifier'
python3 vectors-anchored-chain/check_vectors.py --verifier './verifier'
```

The reader checks in this order and names the first check that fails:
record signature, anchor signature, chain identity, chain link, anchored
record present, anchored record digest. The order is part of the contract, so
a store that fails two checks has one expected reason.

Regenerate the cases with `python3 vectors-anchored-chain/gen_vectors.py`.
The keys are Ed25519 seeds derived from published labels in the generator, so
anyone can rebuild every signature; they protect nothing.

Passing these cases does not establish that the anchor was published where a
second organisation can read it, how often anchors are taken, or that the
producer key was held only by the component that signed.
