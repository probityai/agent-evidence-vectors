# Chunked-export vectors

Cases for `chunked-export/v1`: an export gate's view when one chunk of a flagged
dataset is presented, and the decision the gate must reach. The expected
decision and reason for every case are in `MANIFEST.json`.

Each chunk is reversible on its own, through a documented delete-from-destination
capability, so every per-step class is honestly `reversible`. The chain is not:
once enough of the dataset has left, the recipient can reconstruct it, and
deleting the chunks no longer undoes the disclosure. A seal that takes the
maximum of the per-step labels says `reversible` while the chain is
irreversible. The column headed "steps" is the point of the corpus: six members
whose every step is reversible are still denied, and only the composition
decides them.

| Case | Rule | Chunks out | Steps | Seal | Expected |
| --- | --- | --- | --- | --- | --- |
| variant-a-below-threshold | count, k=3 | 0, 1 | reversible | reversible | allow, `reversible_so_far` |
| variant-a-at-crossing | count, k=3 | 0, 1, 2 | reversible | irreversible | deny, `export_irreversible` |
| variant-a-final-chunk | count, k=3 | 0 to 4 | reversible | irreversible | deny, `export_irreversible` |
| variant-a-max-of-labels-seal | count, k=3 | 0, 1, 2 | reversible | reversible | deny, `seal_understates_composition` |
| threshold-committed-after-first-chunk | count, k=3, committed late | 0, 1 | reversible | reversible | deny, `threshold_not_precommitted` |
| sets-three-chunks-no-reconstructing-set | sets {0,1,2} or {3} | 0, 1, 4 | reversible | reversible | allow, `reversible_so_far` |
| sets-key-field-chunk-alone | sets {0,1,2} or {3} | 3 | reversible | irreversible | deny, `export_irreversible` |
| count-same-three-chunks | count, k=3 | 0, 1, 4 | reversible | irreversible | deny, `export_irreversible` |
| sets-key-field-max-of-labels-seal | sets {0,1,2} or {3} | 3 | reversible | reversible | deny, `seal_understates_composition` |
| step-class-irreversible | count, k=3 | 0 | irreversible | irreversible | deny, `export_irreversible` |
| contract-id-missing | count, k=3 | 0, 1 | reversible | reversible | deny, `contract_id_missing` |
| contract-id-unknown | count, k=3 | 0, 1 | reversible | reversible | deny, `contract_id_unknown` |

The Variant A decisions (boundary B2) are the ones Mayur Agnihotri posted on
[agent-evidence#24](https://github.com/probityai/agent-evidence/issues/24#issuecomment-6247271570):
a gate reading the maximum of the per-step labels permits at every chunk, and a
composition-aware gate permits below the threshold and denies at the crossing
chunk and at every chunk after it. The denial is not one-shot. The set cases
follow his point on the same comment: reconstruction can depend on which chunks
have left (one chunk carrying the key field, an erasure-coded set) rather than
on how many, so the general rule is a predicate over the set, not a count.

## What a record holds

Every record carries `contractId` with the value
`https://probityai.github.io/agent-evidence-vectors/contract/chunked-export/v1`,
except the two contract cases. It also carries:

- `chunks`: the exported chunks, each with `index`, `leftAt`, `payloadFile`,
  `payloadSha256` and its own `stepClass`;
- `exported`: the chunk indices in the order they left, the presented chunk last;
- `reconstruction`: the rule the issuer committed to, with `committedAt`. A
  `count` rule names `k`; a `sets` rule names `minimalSets`, each a set of chunk
  indices that reconstructs the dataset;
- `seal`: the `maxClass` the seal declares;
- `dataset`: the digest and chunk count of the whole dataset.

## The checks

A reader derives the composed class: `irreversible` when an exported chunk's
own step is irreversible, or when the rule holds over the exported chunks (a
`count` rule once `k` chunks have left, a `sets` rule once one minimal set has
left whole). It then checks in this order and names the first check that fails:

1. the record carries `contractId` (`contract_id_missing`);
2. `contractId` is the chunked-export contract (`contract_id_unknown`);
3. the rule was committed no later than the first chunk left
   (`threshold_not_precommitted`). This follows the pre-fixed completion
   criterion of [agent-evidence-vectors#80](https://github.com/probityai/agent-evidence-vectors/issues/80);
4. the seal's `maxClass` is the composed class (`seal_understates_composition`).
   Proposed;
5. the composed class is `reversible` (`export_irreversible`). Proposed.

A record that passes all five is `allow` with reason `reversible_so_far`. The
`sets` rule and the order of the seal check and the composition check are Proposed: no published contract
states them yet.

## What these cases cannot establish

A committed rule makes the seal checkable from the receipts alone and stops the
issuer moving the threshold after the fact. It does not show that the rule is
right. A `k` or a minimal set that was derived wrongly yields records that are
internally consistent, verify cleanly, and are still wrong, and no reader of
these records can tell. How the reconstruction rule is derived for a dataset is
out of scope for this corpus.

## Run it

```sh
python3 vectors-chunked-export/check_vectors.py
python3 vectors-chunked-export/check_vectors.py --verifier "<your verifier>"
GOWORK=off go run ./cmd/aee-verify vectors-chunked-export
```

The external-verifier contract: `<verifier> <case-dir>/record.json --json`
prints one JSON object carrying `decision` and `reason`, and exits 0 for
`allow` and 1 for `deny`.

## Regenerate

```sh
python3 vectors-chunked-export/gen_vectors.py
```

The generator writes every case and `MANIFEST.json` byte-identically; the
corpus tests in `tests/` fail on any difference.
