# APS raw JSON and receipt comparison

This adapter reads the original bytes before parsing. It compares APS's
in-memory JCS serializer, its native strict receipt parser and `jcs-admit`
without combining their policies.

The source and unchanged corpus are pinned in [source-lock.json](source-lock.json):
APS `646490a834e1eca4aad230033502b73f3b5cd9d1` and `jcs-admit`
`ecc8b5ef4b380a2fe38e5079d128307a1c702717`. Expected canonical bytes come
from the pinned RFC reference and Go corpus, not from APS. The attack and
number tables keep their original provenance in the corpus checkout.

Clone those revisions into `source/aps` and `source/jcs-admit`, then run:

```bash
cd source/aps
npm ci --ignore-scripts --no-audit --no-fund
cd ../..
cargo build --locked --manifest-path interop/aps-jcs/runner/Cargo.toml
node --import ./source/aps/node_modules/tsx/dist/loader.mjs interop/aps-jcs/check.mjs \
  --aps source/aps --jcs source/jcs-admit \
  --rust-bin interop/aps-jcs/runner/target/debug/probity-aps-jcs-probe \
  --output comparison.json
```

Raw input is decoded with fatal UTF-8 validation. `parseStrictIJson` receives
that text directly. The serializer baseline deliberately uses `JSON.parse`
first, so the report shows where duplicate-member evidence disappears.
Plain and escape-aliased duplicates are also inserted into a genuinely signed
receipt: the parsed-object verifier still verifies, while APS's serialized
verifier rejects them before checking signatures.

Safe integers, noncharacters, fractions and resource limits keep their native
policy differences. The serialized receipt controls distinguish a parse error,
a wrong signing key and an indeterminate resource ceiling. These are finite
fixture and byte checks. The report keeps harness authorship separate from
execution: in GitHub Actions, controller and operator are the workflow's
`GITHUB_REPOSITORY`. A fork run names the fork; an APS host run names APS.
Local runs leave the operator unrecorded rather than inferring it from authorship.

[The Node matrix](../../.github/workflows/ci.yml) (job `aps_jcs`) runs both APS native
tests and this comparison on Node 20 and 22. Each run retains the raw native
probe output, per-case comparison, logs, tool versions and SHA-256 manifest.
The upstream integration target is a pinned test dependency and required
checks for APS receipt and JCS changes; maintainer acceptance remains open.

For a host CI job, pass `--candidate true` with the APS checkout under test.
The corpus stays pinned; the report retains the actual candidate commit and
source-file hashes beside the baseline revision. This lets a receipt or JCS
change prove its own behavior against the dependency.
