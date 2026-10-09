# Observed-effect reject verdict words at e6f1784f

Rul1an's reader, run against `vectors-observed-effect` at commit `e6f1784fe4572bbbb3069648a562a9c76f5f3ce4`, rejected every reject member, and its verdict word disagreed with the corpus on some of them ([#29](https://github.com/probityai/agent-evidence-vectors/issues/29#issuecomment-5994714914)). This page lists every reject member with the verdict and code the manifest expects, so the disagreeing members can be named once his per-member words are in hand.

What the predicate text fixes, and what it does not:

- The verdict word is fixed by the stage. Stage one of [the predicate](../../spec/predicates/observed-effect.md) is byte-pure and a failure there is `malformed`; a failure of a stage-two recompute, or of an authoritative-tier clause, is `invalid`.
- The code is not fixed by the predicate text. None of the reject codes below appears in the predicate; each is defined only by the manifest. A reader built from the predicate alone can reach the right verdict and still name a different code, so code agreement is a property of the manifest, not of the predicate.
- The members most exposed to a word disagreement are the ones where a clause can be read as either stage: an authoritative-tier statement missing its prior commitment (`malformed` here, because the member is absent), and the signature pair where a malformed signature is `malformed` while a well-formed signature by no key is `invalid`.

| Member | Slug | Verdict | Code |
| --- | --- | --- | --- |
| `v7e4d940d69f97e29` | self-refuting-mutation-none | malformed | `mutation-contradicted-by-writes` |
| `v1d76b9cd283a415a` | broken-write-chain | malformed | `write-chain-broken` |
| `v2ac338b4f730dd1e` | chain-does-not-reach-after-root | malformed | `write-chain-does-not-reach-after-root` |
| `vaaaac1d178f31156` | vacuous-authoritative | invalid | `authoritative-empty-path-scope` |
| `vcdec1eae37009e6d` | authoritative-with-self-vantage | invalid | `authoritative-vantage-not-independent` |
| `vcd3492b6b01ac2d1` | authoritative-without-commitment | malformed | `prior-commitment-absent-for-vantage` |
| `v52c98ad858f5a5e0` | commitment-keyid-is-an-observed-signer | invalid | `commitment-keyid-not-disjoint` |
| `vabd9aa604a7e379f` | commitment-after-interval-opened | invalid | `commitment-not-prior` |
| `v72fce89d104668b1` | commitment-digest-mismatch | malformed | `commitment-digest-mismatch` |
| `v78a0bd5c8ec00a85` | wrong-empty-tree-constant | malformed | `empty-tree-constant-wrong-algorithm` |
| `v198d833e5e421c6b` | unknown-base-resolution | malformed | `base-resolution-unknown` |
| `v7b035bf7ff5fc755` | zero-length-byte-range | malformed | `byte-range-empty` |
| `va2be29185b8aa39b` | range-digest-over-bytes-alone | malformed | `range-digest-preimage-wrong` |
| `v9b138b3f67ffb314` | glob-path-scope | malformed | `path-scope-glob-metacharacter` |
| `va7712f602d394556` | write-outside-scope-marked-in-scope | invalid | `write-outside-path-scope` |
| `v072a5d43bda0f573` | write-scope-label-inverted | invalid | `write-in-scope-mislabelled` |
| `v567b290b71a20bfd` | read-not-chained | malformed | `read-pre-state-not-in-interval` |
| `v6e71bd22b5d75d1c` | coverage-contradiction | malformed | `coverage-self-contradictory` |
| `ve43b9ec3533e5ade` | agreement-not-derivable | malformed | `agreement-not-derivable` |
| `v28e22244b87001ae` | duplicate-member | malformed | `duplicate-member` |
| `v394126d5a8818106` | mutation-none-with-a-null-write | malformed | `mutation-contradicted-by-writes` |
| `vffe1c186018034c1` | mutation-observed-without-writes | malformed | `mutation-observed-without-writes` |
| `v721049b4e1bc6708` | required-member-absent | malformed | `required-member-absent:doesNotAssert` |
| `v1393248410a343af` | unknown-vantage-at-voluntary-tier | malformed | `vantage-unknown` |
| `vd3291ebb0e6cd9ef` | interval-not-ordered | malformed | `interval-not-ordered` |
| `v701feb37d4134d5b` | subject-is-not-the-after-root | malformed | `subject-not-the-after-root` |
| `v34256c23f64d1996` | predicate-type-is-another-predicates | malformed | `predicate-type-unexpected` |
| `vfadad657edabdd3a` | commitment-timestamp-with-an-offset | malformed | `timestamp-not-utc-basic:priorCommitment.committedAt` |
| `v6239dcf033566d17` | write-path-escapes-with-dot-dot | malformed | `path-not-normalized` |
| `v6ce98959d7ea4ae4` | write-under-a-sibling-prefix | invalid | `write-in-scope-mislabelled` |
| `v9f015d3b8d563328` | bytes-read-from-the-empty-tree | malformed | `bytes-read-from-the-empty-tree` |
| `v1cccb4774a282210` | incomplete-coverage-naming-no-gap | malformed | `coverage-incomplete-without-gaps` |
| `v895c39cafad19175` | authoritative-with-a-named-gap-in-scope | invalid | `authoritative-coverage-incomplete` |
| `v46fecb94beb7228f` | retry-duplicate-reported-as-one | malformed | `dual-value-not-recomputable` |
| `v3513d5ff4fe13690` | retry-timeout-read-as-no-write | invalid | `authoritative-coverage-incomplete` |
| `v2c0d86ed85140136` | observed-signer-in-another-case | malformed | `keyid-not-lowercase-hex` |
| `v9e50798ce9232c13` | commitment-signed-by-nobody | invalid | `commitment-signature-invalid` |
| `v90141a91a4a8486a` | commitment-signature-in-uppercase-hex | malformed | `commitment-signature-malformed` |
| `v0cff3afffe48e741` | commitment-signature-with-a-space | malformed | `commitment-signature-malformed` |
| `vf95eb18620e0f71e` | dual-value-the-record-refutes | malformed | `dual-value-not-recomputable` |
| `vb93cfbfa5c5ee255` | dual-value-with-no-values | malformed | `dual-value-carries-no-value` |
| `vd9adf23e325d45da` | vacuous-authoritative-universal-scope | invalid | `authoritative-without-observed-rows` |
| `va298a5a5e92123a0` | byte-range-past-the-ijson-bound | malformed | `integer-not-ijson-safe` |
| `v6a253129f4e98f05` | log-import-wearing-a-vantage | malformed | `origin-cannot-carry-below-observed-vantage` |
| `vc7460368853137cd` | imported-log-claiming-hardware | malformed | `import-origin-requires-software-only-platform` |
| `v92a64c2222f342eb` | imported-log-with-no-platform | malformed | `import-origin-requires-software-only-platform` |
