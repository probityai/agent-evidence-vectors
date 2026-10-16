# TRACE registry anchor vectors

Cases for `trace-registry-anchor/v1`: the Level 2 anchor check of
[TRACE](https://github.com/agentrust-io/trace-spec), as
[Registry Anchor Format v1](https://github.com/agentrust-io/trace-spec/blob/95e160a8ef1c54081d987c6ce4dfcce121d9440b/spec/registry-anchor-v1.md)
states it with the amendment proposed in
[trace-spec#533](https://github.com/agentrust-io/trace-spec/pull/533): a Level 2
verdict rests on the registry entry itself, and a `merkle_root` or `leaf_count`
the receipt carries is checked against that entry rather than replayed
against.

Each case hands a verifier the three inputs section 5.1 names: the claim, the
receipt, and the section 4 registry entry, any of which an attacker may leave
out or bend. The expected decision and reason for every case are in
`MANIFEST.json`, with the section each rests on and the attack it carries.

TRACE's own [anchor-inclusion set](https://github.com/agentrust-io/trace-spec/tree/95e160a8ef1c54081d987c6ce4dfcce121d9440b/conformance/tests/vectors/anchor-inclusion)
covers the section 5.1 replay: tree shapes, path order, the leaf prefix and the
two canonicalizations. It supplies a matching entry to every case, so the
replay is the only thing under test. This corpus holds the replay to a few
controls and tests the layer around it: what a verifier does when the entry
is missing, malformed or not the one the receipt describes.

| Case | Expected | Reason | TR-ANC-002 at main | at #533 |
| --- | --- | --- | --- | --- |
| anchored-one-leaf | anchored | | anchored | anchored |
| anchored-five-leaves-right-edge | anchored | | anchored | anchored |
| anchored-eight-leaves-interior | anchored | | anchored | anchored |
| anchored-proof-only-receipt | anchored | | **refused** | **refused** |
| anchored-non-ascii-signed-record | anchored | | anchored | anchored |
| anchored-max-safe-integer | anchored | | anchored | anchored |
| anchored-transparency-names-other-batch | anchored | | anchored | anchored |
| receipt-absent | refused | `receipt_absent` | refused | refused |
| receipt-path-uppercase-hex | refused | `receipt_malformed` | refused | refused |
| receipt-index-boolean | refused | `receipt_malformed` | refused | refused |
| receipt-root-unprefixed | refused | `receipt_malformed` | refused | refused |
| entry-absent | refused | `entry_absent` | **anchored** | refused |
| self-anchored-no-entry | refused | `entry_absent` | **anchored** | refused |
| entry-leaf-count-boolean | refused | `entry_malformed` | refused | refused |
| entry-producer-empty | refused | `entry_malformed` | **anchored** | refused |
| entry-missing-ts | refused | `entry_malformed` | **anchored** | refused |
| self-anchored-with-real-entry | refused | `receipt_root_mismatch` | **anchored** | refused |
| receipt-root-lies | refused | `receipt_root_mismatch` | refused | refused |
| receipt-subtree-root | refused | `receipt_root_mismatch` | **anchored** | refused |
| receipt-count-lies | refused | `receipt_count_mismatch` | **anchored** | refused |
| index-equals-count | refused | `index_out_of_range` | refused | refused |
| index-negative | refused | `index_out_of_range` | refused | refused |
| claim-float | refused | `claim_outside_profile` | refused | refused |
| claim-integer-2-53 | refused | `claim_outside_profile` | refused | refused |
| pre-signature-anchored | refused | `proof_does_not_replay` | refused | refused |
| truncated-path | refused | `proof_does_not_replay` | refused | refused |
| proof-only-receipt-other-batch | refused | `proof_does_not_replay` | refused | refused |

The two right-hand columns are measured by
[interop/trace-anchor-tr-anc](../interop/trace-anchor-tr-anc/README.md), which
runs TRACE's own check at `6fb2570` (main on 2026-10-15) and at `95e160a`
(the #533 head). Three rows carry the findings:

- **`self-anchored-no-entry`.** A record anchored nowhere writes itself a
  one-leaf receipt whose root is its own leaf hash. A check that replays the
  proof against the root the receipt brings passes it, so before #533 any
  record could reach a TR-ANC-002 pass. The amendment closes it, and so does
  every other bold row in the main column.
- **`receipt-count-lies`.** Leaf 2 of a five-leaf batch has a path that
  replays to the same root whether the receipt says 5 leaves or 6. Only the
  comparison with the entry's count catches it.
- **`anchored-proof-only-receipt`.** The proof in exactly the section 5 shape,
  `leaf_index` and `audit_path`, with the entry supplied. Section 6 as amended
  says a verifier checks a root or count *where the receipt carries one*, which
  makes them optional, and the entry supplies both. The suite at #533 still
  refuses the receipt as missing them. Either the suite takes the root and
  count from the entry, or section 5 says a receipt MUST carry them.

`anchored-transparency-names-other-batch` is anchored because nothing yet
defines how a `transparency` value identifies an entry (trace-spec#448
finding 21); its reason, `included_link_unchecked`, is the statement #533
requires. It flips to refused once that link is defined.

## Running it

The package judges the corpus with its own reader:

```sh
pip install agent-evidence-vectors
agent-evidence-vectors --corpus vectors-trace-anchor
```

The Go directory reader judges it too, with its own replay over `math/big`, and
agrees on every case:

```sh
go run ./cmd/aee-verify vectors-trace-anchor
```

A verifier under test takes `case.json --json`, prints one JSON object
carrying `decision` and `reason`, and exits 0 for `anchored` and 1 for
`refused`:

```sh
agent-evidence-vectors --corpus vectors-trace-anchor --verifier './verifier'
python3 vectors-trace-anchor/check_vectors.py --verifier './verifier'
python3 vectors-trace-anchor/check_vectors.py --verifier './verifier' --decision-only
```

`--decision-only` holds a verifier to the decision alone, for one whose
refusals use its own words. The reader checks in this order and names the
first check that fails: receipt present, receipt well formed, entry present,
entry well formed, carried root equals the entry's, carried count equals the
entry's, index inside the batch, claim inside the section 1 profile, and the
section 5.1 replay against the entry. The order is part of the contract, so a
case that fails two checks has one expected reason.

The generator builds every tree with the RFC 6962 recursive split, which
shares no code with the iterative replay the reader runs. Regenerate with
`python3 vectors-trace-anchor/gen_vectors.py`; the tests in `tests/` require
the output to be byte-identical, and switching any one check off must change
the answer of every case that names it.

Passing these cases does not establish that a registry is append-only, that
its entries can be fetched without the operator's credentials, that the
claim's signature verifies (section 5.2 keeps that a separate step), or that a
`transparency` value names the entry a verifier was given.
