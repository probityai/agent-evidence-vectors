# Provenance

Every policy artifact in this repository was derived from a working tree that is not
published. That tree is where the four admission rails were written, exercised, and
argued over, and publishing them here does not publish it. So the binding between what
you can read here and what was derived is written down instead of assumed: per file, the
path it occupied in the source bundle, the source commit it was taken at, and the SHA-256
of the source file's bytes at that commit.

A SHA-256 digest of the source bytes sits in the last column of the table below, and it
is the part that carries weight. A commit identifier alone binds nothing a reader can
check without the tree it names; a content digest is a claim about bytes, and it stays a
claim about the same bytes whether or not the tree is ever opened.

Derived on 2026-09-11. Source tree at commit
`f1a5c4fbefcb02e5ad7ad041acb69fc3f3756991`; every path below is relative to
`deploy/admission/` inside that tree.

## What was lifted

| here | source path | source commit | source date | SHA-256 of the source bytes |
|---|---|---|---|---|
| `rego/execution_evidence.rego` | `rego/` (renamed on derivation) | `cab1190fd4253cca74e2d9da1331dd98dba839c7` | 2026-08-29 | `f35ccee8cd4b8b06fe8ddaca857770f424f88ce0019768fd382deb0e100837e6` |
| `rego/execution_evidence_test.rego` | `rego/` (renamed on derivation) | `6a823860fcf229d8ac7218bfd8af29509888f6a7` | 2026-09-04 | `143a2f4e92c438e27b9a799e0ce260ecec7a7af8a7e14270f9ba868dd50429a6` |
| `rego/corpus_vectors.json` | `rego/corpus_vectors.json` | `6a823860fcf229d8ac7218bfd8af29509888f6a7` | 2026-09-04 | `f6649b4a75396963e4954bf02e9c8c9680d471fcab2814d806191dfd8c385a94` |
| `rego/corpus_scope.py` | `rego/corpus_scope.py` | `6a823860fcf229d8ac7218bfd8af29509888f6a7` | 2026-09-04 | `04d5701225402a925a14a5ac58c6f8bc2fa6adf9808c81192c13b8aa6e118793` |
| `rego/gen_corpus_vectors.py` | `rego/gen_corpus_vectors.py` | `6a823860fcf229d8ac7218bfd8af29509888f6a7` | 2026-09-04 | `1fe669dd23bffba6d7867d8d5f88673b0abad461583b37c382367362de4c0234` |
| `rego/test_consumer_pins.json` | `rego/test_consumer_pins.json` | `123c5e9ed6af7a005f1ddd5b000adbe6f39e4f57` | 2026-07-29 | `54dae9b186c95fd630f19a00f818c60f6d6d2acb4721dd5057d438357ade1770` |
| `kyverno/clusterpolicy-adversarial-execution-evidence.yaml` | same path | `2f803029396a3e3054dcf05ee26dc0098ad7f795` | 2026-08-29 | `f64f79a8a399d6b92dcc7c9a0f211ab01d3b1460afd7ffe2c0be01497517d412` |
| `kyverno/clusterpolicy-adversarial-execution-evidence-audit.yaml` | same path | `2f803029396a3e3054dcf05ee26dc0098ad7f795` | 2026-08-29 | `88cfb917b3994225142901bf3f32ab22eaaca5926bd32f63cbe174f3c6211f7d` |
| `kyverno/clusterpolicy-adversarial-execution-evidence-freshness.yaml` | same path | `2f803029396a3e3054dcf05ee26dc0098ad7f795` | 2026-08-29 | `a73b2ceaa2f0dee78f2202507182fe4e1f1e22e962adf0d40c3585d4a2341a70` |
| `kyverno/imagevalidatingpolicy-adversarial-execution-evidence.yaml` | same path | `2f803029396a3e3054dcf05ee26dc0098ad7f795` | 2026-08-29 | `186c7c79f91a64fb2a735e45a100e2a567fe6543debad369882f27115a283b90` |
| `policy-controller/clusterimagepolicy-adversarial-execution-evidence.yaml` | same path | `1f4e0d6afe25c6d348f35ba16df45318ca608ddc` | 2026-07-31 | `a3d0e518df18ac7dc38c798fcda554460e41f576dab1dc7d177819b74dedbdd5` |
| `policy-controller/clusterimagepolicy-adversarial-execution-evidence-cue.yaml` | same path | `1f4e0d6afe25c6d348f35ba16df45318ca608ddc` | 2026-07-31 | `e9ebdea274563b07a5aaafcca6fd4cbf46c8add46e9b7b225d6fa050cbbe5286` |
| `policy-controller/clusterimagepolicy-adversarial-execution-evidence-soundness.yaml` | same path | `cab1190fd4253cca74e2d9da1331dd98dba839c7` | 2026-08-29 | `9c2b7c65a35384b5e9c94ed102ff7acc9106c03ac54789cd0d79aa0916c7a726` |
| `policy-controller/gen_soundness_cip.py` | same path | `1f4e0d6afe25c6d348f35ba16df45318ca608ddc` | 2026-07-31 | `f5762ae4a3c851c57c02d26af6ddc8fcbbdd019a282883df1f55da702303b91d` |
| `conformance/run_policy_conformance.py` | same path | `80e1628ea0e6dec465ea4b94340e0c604160d15b` | 2026-09-08 | `04a27ed8321698d3765cae4f2bce326d53c8f11c789962d91baf59572bb710a9` |
| `samples/adversarial-execution-evidence.pass.predicate.json` | same path | `1f4e0d6afe25c6d348f35ba16df45318ca608ddc` | 2026-07-31 | `5dc5f761bb711acc89d561f7e18fad651c9e1a27d4f57a47e207564429c2cdb2` |
| `samples/adversarial-execution-evidence.pass.statement.json` | same path | `1f4e0d6afe25c6d348f35ba16df45318ca608ddc` | 2026-07-31 | `cc938c6038536dcb0d63269dd96cd64bed2d8d575fe212b72593c7f2ca92399b` |
| `samples/pod.yaml` | same path | `dbba5e306a1d10a4c0f223a7f6d0a6af3a2a67ba` | 2026-07-06 | `7fefb7179eac4e7eac764c4783ccb519d1d53ca3b119a54fc5305217603b525c` |
| parts of `README.md` | `README.md` | `6a823860fcf229d8ac7218bfd8af29509888f6a7` | 2026-09-04 | `e6bb0dcee447385c3fe2339d5d6206eed31151fcd15b82dbb64ed5d3ac28fe8d` |

No lifted file is byte-identical to its source, and the table would be misleading if it
implied otherwise. Four classes of edit were applied on derivation, and all four are
visible in the files themselves rather than only here.

1. Branches for predicate types published under a separate namespace were deleted,
   nine of them, named one by one in `README.md` under "What was removed".
   `known_predicate_types` now has exactly one member and
   `verdict_types_requiring_catch_policy` is empty; three tests hold that shape.
2. The rego module and its test file were renamed, and the module's package is
   `sigstore`, which is the package name sigstore policy-controller evaluates.
3. Every reference to a private host, path, or internal identifier was removed. No
   deployment key ships here: `keys/observation-key.pub` is a throwaway ed25519 public
   key generated for this bundle, its private half destroyed, and it is a placeholder
   in all four rails at once so the cross-rail key-parity check stays a real check.
4. The corpus projection was rewired to a published checkout.
   `rego/gen_corpus_vectors.py` now takes `--corpus <vectors checkout>` and a `--check`
   that refuses a stale projection, rather than reading a path inside the source tree.

## What has no upstream

`registry/conditions.json`, `profiles/`, `PROFILE-REGISTRY.md`,
`docs/ADVERSARIAL-RATCHET.{json,md}`, `docs/CONSUMER-POLICY.md`, `scripts/`, the
workflows under `.github/`, `CITATION.cff`, `LICENSE`, and this file have no upstream.
The profile maps in particular could not have been lifted: they are a measurement of
these four artifacts against a named corpus digest, and a measurement carried over from
somewhere else would be a claim about different bytes.

## The corpus these rails are measured against

Not lifted, and not vendored wholesale. `rego/corpus_vectors.json` is a mechanical
projection of the published conformance corpus at the tag `v0.30.0` of
[probityai/agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors)
at commit `c74c8a7337b2186ec120eb4f988d7daab9f16caa`, corpus digest
`bf3e5befd71640757ff1b3f0af63507364b823b5e3f9059678f72f64a46e11c1`. Continuous
integration installs the published `agent-evidence-vectors` 0.30.0 package from PyPI,
which ships that corpus unchanged, pinned by version and wheel SHA-256 in
`requirements-vectors.txt`. It refuses a package whose corpus digest is not the one
the repository-root `.github/workflows/package-admission.yml` records as measured,
and re-derives the projection; a projection that no longer reproduces fails the build
rather than being quietly regenerated. `scripts/vectors-pin-gate.py` holds this page,
the README, `llms.txt` and the design page to the same version and digest.
