# PriorSeal exact-call seam vectors

Cases for `priorseal-exact-call-seams/v1`: inputs of the exact-call envelope matrix in
[imokokok/PriorSeal](https://github.com/imokokok/PriorSeal/tree/2ff89d86611257b4440232e5c2793926b3d52043/examples/open-evidence-lab-exact-call-matrix-v1),
judged against its input contract, version 1.0.1. Three are the seams G9 to G11 found in issue
352 on this repository; the rest are decided by the 1.0.1 text and keep a reader from passing
the seams by ignoring time or chain identity.

For anyone who maintains a reader of that matrix and wants it run on the inputs the contract
leaves open, without the run deciding them.

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-priorseal-exact-call-seams
python3 corpora/vectors-priorseal-exact-call-seams/check_vectors.py --verifier './reader'
```

A verifier takes `case.json --json` and prints `{"decision": "bound" | "not_bound",
"reasonCodes": [...]}` or `{"decision": "open", "question": "..."}`, exiting 0, 1 or 2.
`case.json` holds the matrix's signed source record under `source`, unchanged, and the observed
envelope under `observed`.

## The three seams

Each open case is the matrix's case-00 with one field changed. A reader may answer it with any
reading's answer or with `open`; any other answer fails it, and so does stopping without one.

| case | change to case-00 | readings |
|---|---|---|
| `open-g9-missing-time` | no `executedAt`, no `observedAt` | `skip`: bound; `zero`: `OUTSIDE_AUTHORIZATION_WINDOW`; `outside`: both window codes |
| `open-g10-executedat-not-a-number` | `executedAt: "late"` | `comparison-false`: bound; `outside`: both window codes |
| `open-g11-chainid-decimal-string` | `chainId: "8453"` | `decimal-string`: bound; `json-type`: `CHAIN_MISMATCH` |

- **G9.** The window rows of section 4 compare "`executedAt` (fallback `observedAt`)" with the
  windows, and no rule covers a case with neither. The paragraph "Comparison semantics" maps "a
  missing or null value through the empty string" for comparisons of values; the window rows
  are order comparisons. The shipped profile also emits `AUTHORIZATION_AFTER_EXECUTION`, which
  is not in the section 4 map.
- **G10.** Section 2.1 types the authorization's instants as JSON numbers. No sentence types the
  observed `executedAt`, and the paragraph says "whether the producer should reject
  non-canonical forms is an open question, deliberately not settled in 1.0.1."
- **G11.** The row reads "strict equality of the integer values". The paragraph says values
  compare after `String()` coercion, "a JSON integer participates through its canonical decimal
  string", and "a numeric nonce `7` and the string `"7"` are the same value." Read as written,
  `"8453"` and `8453` are the same chain. The row's word strict, the matrix's `expected.json`
  (`strict-equality` for `chainId`, `strict-string-equality-default-0` for `nonce`) and both
  shipped paths keep the JSON type.

Each open case lists in `reportedAnswers` what every reader in the thread and the shipped
profile answered, quoted from the comment that reported it. The contract's owner decides the
three questions; this corpus records them until a revision does.

## The decided cases

`control-case-00` and `control-case-05` are the matrix's own envelopes.
`decided-observedat-fallback-inside` and `-late` drop `executedAt` and keep an `observedAt`
inside or after both windows. `decided-chainid-other-integer` (8454) mismatches under every
reading. `decided-nonce-json-number` is the paragraph's own example.

The reference reader (`packaging/agent_evidence_vectors/priorsealseams.py`) implements section 4
with one named reading per question. A case is decided when every combination of readings gives
one answer and open when its answer moves with one question; the generator and the tests refuse
a manifest that says otherwise. Under every combination it gives the six answers the matrix's
`expected.json` records, and PriorSeal's own `reader.mjs` passes every decided case and takes
`skip`, `comparison-false` and `json-type` on the seams.

## Source and credit

The seams were found by piiiico
([comment](https://github.com/probityai/agent-evidence-vectors/issues/352#issuecomment-6529875972)),
reproduced by ogasurfproject-jpg with priorseal-reader-v0, changed in `1bdbebc5`
([comment](https://github.com/probityai/agent-evidence-vectors/issues/352#issuecomment-6529876371)),
and by Tetsurohhori with a reader of the 1.0.0 text
([comment](https://github.com/probityai/agent-evidence-vectors/issues/352#issuecomment-6529877263)).
imokokok, who maintains the contract, recorded them as candidate gaps G9 to G11
([comment](https://github.com/probityai/agent-evidence-vectors/issues/352#issuecomment-6529876820)).

`source/` holds the contract, `expected.json`, the signed source record, the case-00 and case-05
envelopes and the licence, byte for byte from PriorSeal at `2ff89d8` (MIT, copyright imokokok),
each pinned by sha256 in `MANIFEST.json`. The contract is unchanged at PriorSeal `b39d217`.

## What it does not test

The EIP-712 digest, signer recovery and acceptance signature of section 2, evidence
availability (section 5) and the outcome vocabulary of section 8. Every case is synthetic.
Regenerate with `python3 corpora/vectors-priorseal-exact-call-seams/gen_vectors.py`.
