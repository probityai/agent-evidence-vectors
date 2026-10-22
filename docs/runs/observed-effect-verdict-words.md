# Observed-effect reject verdict words at e6f1784f

Rul1an's reader, run against `vectors-observed-effect` at commit `e6f1784fe4572bbbb3069648a562a9c76f5f3ce4`, rejected every reject member, and its verdict word disagreed with the corpus on some of them ([#29](https://github.com/probityai/agent-evidence-vectors/issues/29#issuecomment-5994714914)). He posted his word for every reject member ([#29](https://github.com/probityai/agent-evidence-vectors/issues/29#issuecomment-6095207826)), and the last column below carries it.

What the comparison showed, and what changed:

- All 22 differences go one way: where the manifest says `malformed` or `invalid`, the reader said `refused`. It never named the other stage's word. Each of those checks implements a predicate sentence that says a verifier MUST refuse or reject and names no word, so the reader had no word to take from the text.
- The predicate at 0.6.0 fixed the word by stage only implicitly, and its stage-one list included the `tier` recompute and the `inScope` label, whose refusals every verifier calls `invalid`. At 0.6.1 [the predicate](../../spec/predicates/observed-effect.md) lists each stage-two gate, states that a stage-one refusal is `malformed` and a stage-two refusal is `invalid`, and gives the one exception (a signature whose bytes cannot be decoded is `malformed` in either stage). No verdict moved. `vectors-observed-effect/check_vectors.py` now fails when the stage lists in the document and the words the reference verifier raises disagree.
- The code is not fixed by the predicate text. None of the reject codes below appears in the predicate; each is defined only by the manifest. A reader built from the predicate alone can reach the right verdict and still name a different code, so code agreement is a property of the manifest, not of the predicate.

| Member | Slug | Verdict | Code | Rul1an's reader |
| --- | --- | --- | --- | --- |
| `v7e4d940d69f97e29` | self-refuting-mutation-none | malformed | `mutation-contradicted-by-writes` | malformed |
| `v1d76b9cd283a415a` | broken-write-chain | malformed | `write-chain-broken` | malformed |
| `v2ac338b4f730dd1e` | chain-does-not-reach-after-root | malformed | `write-chain-does-not-reach-after-root` | malformed |
| `vaaaac1d178f31156` | vacuous-authoritative | invalid | `authoritative-empty-path-scope` | invalid |
| `vcdec1eae37009e6d` | authoritative-with-self-vantage | invalid | `authoritative-vantage-not-independent` | invalid |
| `vcd3492b6b01ac2d1` | authoritative-without-commitment | malformed | `prior-commitment-absent-for-vantage` | refused |
| `v52c98ad858f5a5e0` | commitment-keyid-is-an-observed-signer | invalid | `commitment-keyid-not-disjoint` | refused |
| `vabd9aa604a7e379f` | commitment-after-interval-opened | invalid | `commitment-not-prior` | refused |
| `v72fce89d104668b1` | commitment-digest-mismatch | malformed | `commitment-digest-mismatch` | malformed |
| `v78a0bd5c8ec00a85` | wrong-empty-tree-constant | malformed | `empty-tree-constant-wrong-algorithm` | malformed |
| `v198d833e5e421c6b` | unknown-base-resolution | malformed | `base-resolution-unknown` | malformed |
| `v7b035bf7ff5fc755` | zero-length-byte-range | malformed | `byte-range-empty` | malformed |
| `va2be29185b8aa39b` | range-digest-over-bytes-alone | malformed | `range-digest-preimage-wrong` | refused |
| `v9b138b3f67ffb314` | glob-path-scope | malformed | `path-scope-glob-metacharacter` | refused |
| `va7712f602d394556` | write-outside-scope-marked-in-scope | invalid | `write-outside-path-scope` | invalid |
| `v072a5d43bda0f573` | write-scope-label-inverted | invalid | `write-in-scope-mislabelled` | refused |
| `v567b290b71a20bfd` | read-not-chained | malformed | `read-pre-state-not-in-interval` | malformed |
| `v6e71bd22b5d75d1c` | coverage-contradiction | malformed | `coverage-self-contradictory` | malformed |
| `ve43b9ec3533e5ade` | agreement-not-derivable | malformed | `agreement-not-derivable` | malformed |
| `v28e22244b87001ae` | duplicate-member | malformed | `duplicate-member` | malformed |
| `v394126d5a8818106` | mutation-none-with-a-null-write | malformed | `mutation-contradicted-by-writes` | malformed |
| `vffe1c186018034c1` | mutation-observed-without-writes | malformed | `mutation-observed-without-writes` | malformed |
| `v721049b4e1bc6708` | required-member-absent | malformed | `required-member-absent:doesNotAssert` | malformed |
| `v1393248410a343af` | unknown-vantage-at-voluntary-tier | malformed | `vantage-unknown` | malformed |
| `vd3291ebb0e6cd9ef` | interval-not-ordered | malformed | `interval-not-ordered` | refused |
| `v701feb37d4134d5b` | subject-is-not-the-after-root | malformed | `subject-not-the-after-root` | refused |
| `v34256c23f64d1996` | predicate-type-is-another-predicates | malformed | `predicate-type-unexpected` | refused |
| `vfadad657edabdd3a` | commitment-timestamp-with-an-offset | malformed | `timestamp-not-utc-basic:priorCommitment.committedAt` | refused |
| `v6239dcf033566d17` | write-path-escapes-with-dot-dot | malformed | `path-not-normalized` | refused |
| `v6ce98959d7ea4ae4` | write-under-a-sibling-prefix | invalid | `write-in-scope-mislabelled` | refused |
| `v9f015d3b8d563328` | bytes-read-from-the-empty-tree | malformed | `bytes-read-from-the-empty-tree` | refused |
| `v1cccb4774a282210` | incomplete-coverage-naming-no-gap | malformed | `coverage-incomplete-without-gaps` | malformed |
| `v895c39cafad19175` | authoritative-with-a-named-gap-in-scope | invalid | `authoritative-coverage-incomplete` | invalid |
| `v46fecb94beb7228f` | retry-duplicate-reported-as-one | malformed | `dual-value-not-recomputable` | refused |
| `v3513d5ff4fe13690` | retry-timeout-read-as-no-write | invalid | `authoritative-coverage-incomplete` | invalid |
| `v2c0d86ed85140136` | observed-signer-in-another-case | malformed | `keyid-not-lowercase-hex` | refused |
| `v9e50798ce9232c13` | commitment-signed-by-nobody | invalid | `commitment-signature-invalid` | refused |
| `v90141a91a4a8486a` | commitment-signature-in-uppercase-hex | malformed | `commitment-signature-malformed` | malformed |
| `v0cff3afffe48e741` | commitment-signature-with-a-space | malformed | `commitment-signature-malformed` | malformed |
| `vf95eb18620e0f71e` | dual-value-the-record-refutes | malformed | `dual-value-not-recomputable` | refused |
| `vb93cfbfa5c5ee255` | dual-value-with-no-values | malformed | `dual-value-carries-no-value` | malformed |
| `vd9adf23e325d45da` | vacuous-authoritative-universal-scope | invalid | `authoritative-without-observed-rows` | refused |
| `va298a5a5e92123a0` | byte-range-past-the-ijson-bound | malformed | `integer-not-ijson-safe` | refused |
| `v6a253129f4e98f05` | log-import-wearing-a-vantage | malformed | `origin-cannot-carry-below-observed-vantage` | refused |
| `vc7460368853137cd` | imported-log-claiming-hardware | malformed | `import-origin-requires-software-only-platform` | refused |
| `v92a64c2222f342eb` | imported-log-with-no-platform | malformed | `import-origin-requires-software-only-platform` | refused |

## Rerun at efe2dd9: 46 of 46

Rul1an reran the same reader at `efe2dd9da05f4f97435cc19ef5b9e86f343d51cd`, the merge of predicate 0.6.1, whose observed-effect manifest is byte-identical to the one at `e6f1784f` ([#29](https://github.com/probityai/agent-evidence-vectors/issues/29#issuecomment-6147963317)). With the manifest's blob supplied, its test observer key anchored, and one directed reader option that words each refusal by the 0.6.1 rule, the verdict word matches the manifest on all 46 reject members, up from 24. Outcomes did not move: 12 of 12 accepts, 46 of 46 rejects, and the indeterminate member still gets one of its listed readings (`valid`). The 22 words that changed are the 22 marked `refused` in the last column above.

The option keeps a word the reader already gave and maps a `refused` to `invalid` when its gate is in the stage-two list and to `malformed` otherwise. The reader is still the directed, agent-written reader described above, and the option was written after reading this table, so the run shows that the 0.6.1 rule yields a word for every refusal once each gate is placed, not that a reader starting from the text alone lands there.

Two of its stage-one placements were made by elimination: `interval-not-ordered` and `range-digest-over-bytes-alone`. Predicate 0.6.2 names both gates in the stage-one list (the interval order, and the `rangeDigest` recompute against a blob the consumer holds), so a reader no longer has to place them by ruling out stage two. Both remain `malformed`.
