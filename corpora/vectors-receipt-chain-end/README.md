# Receipt chain end vectors

Cases for `receipt-chain-end/v1`: a chain of signed agent action receipts, the
consumer's trust inputs, sometimes a head the consumer kept outside the chain,
and the decision a verifier must reach about where the chain ends. The receipts
use the ActionReceipt v1 wire format a flight-recording egress proxy writes:
an Ed25519 signature over the SHA-256 of the compact action record, a
hash link to the previous receipt, a sequence number per signing key, session
open and close records, and key rotation markers with an endorsement signed by
the retiring key. The expected decision and reason for every case are in
`MANIFEST.json`, and each case says what it does not assert.

[![Checked with Probity](https://img.shields.io/badge/checked-with_Probity-0969da?logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAkFBMVEX8%2B%2Bzr5NPgyrfKyLnSq5Wzo4tWltqRkZI2kPU1kvk1j%2FMwkPgzjfI2jO80jO40jO3MdWOZc1SLblN1aFxxXFJzVDY2i%2B40i%2B00i%2Bw0i%2Bs0ius1iOZAapwugNYtdbUqaq0qV4tkRzJXOB47Oz43JRkjNEYiHBwlFxIfFxMcEg0XEQ0WEAwXDAUWCAEOCQcJAgCa503RAAAB3klEQVR42rWT2ZacIBCGceHYoN240SK2Crig4vL%2BbxfszJyZTmaSm6S4rI9a%2FwK3vxj41wDj5E9AwS%2Foxjn7DmARqgVHCBHyJcBxJeZtEG2Nv4hAGEPXYVumddvWAbFfgJJECDfDukxa63ldmw%2FiCTCEK%2BteFzNbQI%2BbQPwzwKJGjNO2LMacxNqK1wgcNfO2mqfbHMs8NEkeXT8AjurRTKfbMlqOa5vFyc8cZclu4PSvWptlPlOMeb4PsQu78MoYQWFIwKUet0nPZl%2FMki1H3x%2FKd1PVhhdkS2tDgM7m9bR3XX8EXtYde59SSVVXNx2NMwuIbbGl74HUu%2BcFXrArSpXqlVSpGz8sUG%2FjoCej1RHA6ZAgl1SmUvVUQjduEGDIdt0MxuwjCHYNAZSwT1IbhaZ%2BFt7BrUAXbguxnx3gZ9AJVJLal0hKaYv4OShGbu249Z4F4jhQ1PcpTUYLDBF5WxZB9dBB14O%2Bm6eu48QQpjBXIizf113iS9sF0LYxZMD1PODbVvtznu96sGOrWyFEiwQEwHNcC8gaF58UxfG1qiqMqzx2AACJ0i0qXyRXEIwjwnD1SBOYdKJ%2B7vxF1eRUaxGF9ePRVgiX3xxOccdhiK5v6v%2Fysgp2Z%2BR%2F3ebv9gP5RU8tSdZhDwAAAABJRU5ErkJggg%3D%3D)](https://github.com/probityai/probity)

The point of the corpus is the difference between a valid chain and a whole
chain. A writer who can edit the stored receipts needs no key to cut the tail,
and a cut chain is a valid prefix: every signature verifies and every link
holds. Only two things bound the end. One is a signed close of a run that
nothing resumes. The other is a head the consumer retained outside the
writer's reach, named by its hash. A sequence number without a hash binds a
length, not a content, and it restarts at every key rotation.

| Case | Every signature verifies | Expected | What the case is |
| --- | --- | --- | --- |
| control-closed-run | yes | verified, `end_proven_close` | control: one run, opened and closed |
| control-closed-run-retained-head | yes | verified, `end_proven_close` | control: the same run with the consumer's final head |
| control-open-prefix | yes | prefix, `end_unproven` | control: a run still recording |
| control-open-run-final-head | yes | verified, `end_proven_head` | control: no close, final head retained when recording stopped |
| control-rotation-endorsed | yes | verified, `end_proven_close` | control: the key rotates mid-run, the retiring key endorses it |
| control-timestamp-tie | yes | verified, `end_proven_close` | control: three receipts share one timestamp |
| tail-truncation | yes | prefix, `end_unproven` | the newest receipts and the close deleted |
| tail-truncation-retained-head | yes | rejected, `head_missing` | the same cut, checked against the retained final head |
| prefix-replay-shared-session-close | yes | prefix, `end_unproven` | a resumable session cut at its first close |
| prefix-replay-other-run | yes | rejected, `head_missing` | a genuine closed run shown in place of the retained one |
| fork-branch-against-retained-head | yes | rejected, `head_missing` | two receipts signed at one sequence; the other branch shown |
| fork-branch-against-retained-seq | yes | prefix, `end_unproven` | the same fork against a retained sequence number with no hash |
| fork-both-branches | yes | rejected, `chain_link_broken` | both branches in one file |
| rotation-resigned-tail-keys-pinned | yes | rejected, `rotation_unendorsed` | the new key cuts the old key's tail and re-roots; both keys pinned |
| rotation-resigned-tail-endorsement | yes | rejected, `rotation_unendorsed` | the same chain against the genuine endorsement |
| stale-head-honest-extension | yes | verified, `end_proven_close` | no edit: an interim head, then the run continued and closed |
| stale-head-truncated-to-it | yes | prefix, `end_unproven` | the chain cut exactly at an interim head |
| seq-reset-hides-gap | yes | rejected, `head_position_mismatch` | cut at the old key's sequence number that equals the real final one |
| reorder-timestamp-tie | yes | rejected, `chain_link_broken` | two tied receipts swapped |
| signature-tamper | no | rejected, `signature_invalid` | one receipt edited, its signature kept |
| untrusted-genesis-key | yes | rejected, `signer_untrusted` | a whole run signed by a key the consumer does not hold |
| close-count-forged | yes | rejected, `close_binding_invalid` | the close claims one more receipt than the run holds |
| final-head-not-at-end | yes | rejected, `head_not_final` | the chain continues past the retained final head |
| seq-reset-control-endorsed | yes | verified, `end_proven_close` | control: the whole rotated run against the same retained position |

## Running it

The package judges the corpus with its own reader, and `aee-verify` judges it
with the Go reader:

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-receipt-chain-end
aee-verify vectors-receipt-chain-end/
```

A verifier under test takes `case.json --json`, prints one JSON object
carrying `decision` and `reason`, and exits 0 for `verified`, 3 for `prefix`
and 1 for `rejected`:

```sh
agent-evidence-vectors --corpus vectors-receipt-chain-end --verifier './verifier'
python3 vectors-receipt-chain-end/check_vectors.py --verifier './verifier'
```

The reader checks in this order and names the first check that fails:
receipt signature, root key, chain link, rotation endorsement, close binding,
retained head present, retained head position, retained final head at the
end. The order is part of the contract, so a chain that fails two checks has
one expected reason.

Regenerate the cases with `python3 vectors-receipt-chain-end/gen_vectors.py`.
The keys are Ed25519 seeds derived from published labels in the generator, so
anyone can rebuild every signature; they protect nothing.

Passing these cases does not establish that the recorder saw every action the
agent took, that the retained head was kept out of the writer's reach, or that
a signing key was held only by the recorder.
