# chunked-export/v1 · the export gate as an external contract

`corpora/vectors-chunked-export` holds twelve records, each the view an export gate has when
one chunk of a flagged dataset is presented. Every chunk is reversible on its own, through a
documented delete-from-destination capability, and the chain is not: once enough of the
dataset has left, the recipient can rebuild it. This document states the decision a gate owes
on each record as a contract an outside reader can implement alone. It is written from the
retained records and from the two packaged readers
([`chunkedexport.py`](../../packaging/agent_evidence_vectors/chunkedexport.py) and
[`chunkedexport.go`](../../corpusreaders/chunkedexport.go)); where the records and this
document disagree, the records win and this document is wrong.

The cases come from Mayur Agnihotri ([@Mayur021](https://github.com/Mayur021)), who posted the
Variant A gate decisions for boundary B2 and pointed out that reconstruction can depend on
which chunks have left rather than how many
([#352](https://github.com/probityai/agent-evidence-vectors/issues/352#issuecomment-6529872181)).

## What the contract decides

Whether the gate may let the presented chunk leave. It answers one question: **given the
reconstruction rule the issuer committed to before the export began, has the export so far
become irreversible as a whole, and does the seal say so?**

It does not decide whether the committed rule is the right one for the dataset. A `k` or a
minimal set that was derived wrongly gives records that are internally consistent, pass every
check below and are still wrong, and no reader of these records can tell. How the rule is
derived is out of scope.

## Inputs

One file, `cases/<case>/record.json`, a JSON object. The chunk payload files beside it are
checked by the corpus harness (see [The corpus harness](#the-corpus-harness)) and are not read
by the decision.

| Member | Read by | Meaning |
| --- | --- | --- |
| `contractId` | checks 1, 2 | the contract the record claims; the value for this contract is `https://probityai.github.io/agent-evidence-vectors/contract/chunked-export/v1` |
| `chunks` | the composed class, check 3 | the exported chunks, each an object with `index` (integer), `leftAt` (RFC 3339 instant), `stepClass` (`reversible` or `irreversible`), `payloadFile` and `payloadSha256` |
| `exported` | the composed class, check 3 | the indices of the chunks that have left, in the order they left, the presented chunk last; each index names an entry of `chunks` |
| `reconstruction` | the composed class, check 3 | the rule the issuer committed to: `kind` (`count` or `sets`), `committedAt` (RFC 3339 instant), and `k` (integer) for `count` or `minimalSets` (a list of lists of chunk indices) for `sets` |
| `seal` | check 4 | `maxClass`, the class the seal declares: `reversible` or `irreversible` |
| `dataset` | nothing | `sha256` and `chunkCount` of the whole dataset; carried for the record, read by no check |

## The composed class

Let `E` be the set of indices in `exported`, and let each exported chunk be the entry of
`chunks` whose `index` it names. The composed class is `irreversible` when either holds, and
`reversible` otherwise:

- some exported chunk has `stepClass` equal to `irreversible`;
- the committed rule holds over `E`.

### The `count` rule

A `count` rule holds when `E` has at least `k` members. Indices are counted once each, and which
indices they are does not matter: chunks 0, 1 and 4 under `k = 3` hold the rule exactly as
chunks 0, 1 and 2 do.

### The `sets` rule

A `sets` rule holds when **some list in `minimalSets` has every one of its indices in `E`**.
Formally: the rule holds if and only if some `S` in `minimalSets` is a subset of `E`.

Which chunks have left decides, not how many. Under `minimalSets` `[[0, 1, 2], [3]]`:

| `E` | Holds | Why |
| --- | --- | --- |
| {0, 1, 4} | no | three chunks out, but {0, 1, 2} is missing chunk 2 and {3} is missing chunk 3 |
| {3} | yes | {3} is in `E` whole: one chunk carrying the key field rebuilds the dataset on its own |

The same three chunks {0, 1, 4} hold a `count` rule with `k = 3` and do not hold this `sets`
rule; that pair is what tells the two rules apart.

## The checks

Steps run in this order. The first one that fails decides the record, and the gate denies with
that step's reason. A record that passes all five is allowed.

| # | Condition | On failure |
| --- | --- | --- |
| 1 | the record has a `contractId` member | `deny`, `contract_id_missing` |
| 2 | `contractId` is the string `https://probityai.github.io/agent-evidence-vectors/contract/chunked-export/v1`, compared byte for byte | `deny`, `contract_id_unknown` |
| 3 | `reconstruction.committedAt` is no later than the earliest `leftAt` among the exported chunks | `deny`, `threshold_not_precommitted` |
| 4 | `seal.maxClass` equals the composed class | `deny`, `seal_understates_composition` |
| 5 | the composed class is `reversible` | `deny`, `export_irreversible` |
| | every step holds | `allow`, `reversible_so_far` |

Instants in step 3 are compared as points in time, not as strings. Step 3 is the pre-fixed
completion criterion of
[agent-evidence-vectors#80](https://github.com/probityai/agent-evidence-vectors/issues/80) in
this shape: a rule committed after the first chunk left could have been chosen to fit the
export.

### Why the seal is checked before the composition

Step 4 comes before step 5 on purpose. When a seal says `reversible` and the export has become
irreversible, both steps fail, and the reason the gate reports is `seal_understates_composition`.
That reason names the record that states the wrong class out loud, which is the failure a
responder needs to see: the issuer's seal is wrong, not only the export. Two members fail
both steps, and both expect `seal_understates_composition`, so the order is fixed by the
corpus and a reader that checks the composition first fails them.

## Each case and the rule that decides it

"Failing steps" lists every step the record fails, in order; the first is the one that decides.
A member that fails two steps pins the order of those two.

| Case | Rule | `E` | Composed | Seal | Failing steps | Expected | Deciding rule |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `variant-a-below-threshold` | count, k = 3 | {0, 1} | reversible | reversible | none | `allow`, `reversible_so_far` | count rule: 2 members, below `k` |
| `variant-a-at-crossing` | count, k = 3 | {0, 1, 2} | irreversible | irreversible | 5 | `deny`, `export_irreversible` | count rule: "at least `k`", so the crossing chunk itself is denied |
| `variant-a-final-chunk` | count, k = 3 | {0, 1, 2, 3, 4} | irreversible | irreversible | 5 | `deny`, `export_irreversible` | count rule past the crossing: the denial is not one-shot |
| `variant-a-max-of-labels-seal` | count, k = 3 | {0, 1, 2} | irreversible | reversible | 4, 5 | `deny`, `seal_understates_composition` | step 4 before step 5 |
| `threshold-committed-after-first-chunk` | count, k = 3, committed 30 s after chunk 0 left | {0, 1} | reversible | reversible | 3 | `deny`, `threshold_not_precommitted` | step 3 |
| `sets-three-chunks-no-reconstructing-set` | sets {0, 1, 2} or {3} | {0, 1, 4} | reversible | reversible | none | `allow`, `reversible_so_far` | `sets` rule: no listed set is in `E` whole |
| `sets-key-field-chunk-alone` | sets {0, 1, 2} or {3} | {3} | irreversible | irreversible | 5 | `deny`, `export_irreversible` | `sets` rule: {3} is in `E` whole |
| `count-same-three-chunks` | count, k = 3 | {0, 1, 4} | irreversible | irreversible | 5 | `deny`, `export_irreversible` | count rule: which indices does not matter |
| `sets-key-field-max-of-labels-seal` | sets {0, 1, 2} or {3} | {3} | irreversible | reversible | 4, 5 | `deny`, `seal_understates_composition` | `sets` rule, then step 4 before step 5 |
| `step-class-irreversible` | count, k = 3 | {0} | irreversible | irreversible | 5 | `deny`, `export_irreversible` | composed class: an exported chunk's own step is `irreversible` |
| `contract-id-missing` | count, k = 3 | {0, 1} | reversible | reversible | 1 | `deny`, `contract_id_missing` | step 1 |
| `contract-id-unknown` | count, k = 3 | {0, 1} | reversible | reversible | 2 | `deny`, `contract_id_unknown` (the record names `.../chunked-export/v0`) | step 2 |

Six members have only `reversible` steps and are still denied or called understated:
`variant-a-at-crossing`, `variant-a-final-chunk`, `variant-a-max-of-labels-seal`,
`sets-key-field-chunk-alone`, `count-same-three-chunks` and `sets-key-field-max-of-labels-seal`.
A gate that takes the maximum of the per-step labels allows them, or denies them with the
wrong reason, on exactly those six; the corpus tests hold that.

## What the cases fix, and what they leave open

The cases fix the `sets` rule (three members), the count rule including its boundary (the
crossing chunk is denied at exactly `k`), the composed class from a single irreversible step,
each of the five reasons, and the order of steps 4 and 5 (two members). A reader that returns
the expected decision and reason on all twelve is consistent with every member, and one that
returns anything else on any of them is not.

These are not exercised by any member. Both packaged readers behave as the procedure above
says, but a reader that differs on them still agrees with all twelve:

- **The position of steps 1 to 3.** No member fails one of steps 1 to 3 together with another
  step, so the order of steps 1 to 3 among themselves and ahead of steps 4 and 5 is the order
  both readers apply and is not pinned by a case. Steps 1 and 2 cannot both fail.
- **A seal that overstates.** Step 4 is equality, so both readers also deny a seal that says
  `irreversible` while the composed class is `reversible`, with the same reason. No member
  carries such a seal.
- **A commitment at the same instant as the first chunk.** "No later than" allows it; no
  member has `committedAt` equal to the earliest `leftAt`.
- **`contractId` present with the value `null`.** The two readers differ here: the Python
  reader reports `contract_id_unknown`, the Go reader `contract_id_missing`. No member carries
  it, and this contract does not settle it.
- **A step class other than the two values.** Both readers count any `stepClass` other than
  `irreversible` as not irreversible. Only `reversible` and `irreversible` appear in the corpus.
- **An empty list in `minimalSets`.** Under the `sets` rule as written it is in `E` whole, so
  the rule holds before any chunk leaves. No member carries one.
- **Malformed records.** An `exported` index with no entry in `chunks`, an empty `exported`, a
  `kind` other than `count` or `sets`, or a timestamp that does not parse as RFC 3339 stops both
  readers with an error rather than a decision. A record that lacks another member is not
  handled the same way by the two. Such records are outside this contract.

## The corpus harness

Two checks run on every member whichever verifier is under test, and a failure is a corpus
error rather than a verifier's disagreement: each chunk's `payloadFile` hashes to its
`payloadSha256`, and the composed class above equals the member's `composedClass` in
`MANIFEST.json`. A verifier need not repeat either.

## Running an independent verifier

```sh
python3 corpora/vectors-chunked-export/check_vectors.py --verifier "<your verifier>"
```

The harness runs `<verifier> cases/<case>/record.json --json` once per member. The verifier
prints one JSON object carrying `decision` (`allow` or `deny`) and `reason` (one of the six
strings above), and exits `0` for `allow` and `1` for `deny`. Only `decision` and `reason` are
compared, and an exit status that disagrees with the printed decision is a disagreement. Score
the run against `expected` in each member's manifest entry. A one-shot run is not a
conformance claim; pin the corpus at a release or a commit, as
[`docs/VERIFIERS.md`](../VERIFIERS.md) asks.

## Changes

- **0.37.0 (next minor, not yet released).** This document is published, and the Proposed
  marks on the `sets` rule and on the order of the seal and composition checks are lifted: the
  contract states both and three members (the `sets` rule) and two members (the order) fix
  them. No member, record, payload, expected decision or reason changed. `corpusDigest` is
  still `8d9e15ebf4e6a6b76960491fff189ccdad8521479fff71de1da8ddc43f22b12a`, and the `cases`
  tree is the same tree as in 0.22.0. The corpus README changed: it links here, drops the two
  Proposed marks, and corrects its Python run commands to the `corpora/` paths. Since 0.22.0 the
  manifest has also gained its `counts` block; nothing a decision reads moved.
