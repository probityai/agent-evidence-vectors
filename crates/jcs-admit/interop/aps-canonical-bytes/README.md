# APS canonical-byte comparison

The published `jcs-admit` 0.1.0 matches all canonical bytes and SHA-256 digests
in the APS lab's v1 (8 cases) and v2 (10 cases) fixtures. The inputs are pinned
to lab commit `5829e2ff00d75f49ce21e9d87e756658deb1ef33`. This is a byte
comparison on these cases, not an APS conformance or production claim.

Run it from the repository root:

```bash
python3 interop/aps-canonical-bytes/check.py
```

Expected output:

```text
v1: 8/8 byte and digest matches; negative control detected
v2: 10/10 byte and digest matches; negative control detected
```

The runner calls `jcs_admit::admit` on each input's raw JSON token bytes.
`serde_json::value::RawValue` preserves those tokens, including integer
spellings above 2^53, until the crate reads them. Every expected byte and
digest comes from the fixture. `runner/Cargo.lock` pins the published crate
and all dependencies; there is no path dependency on this checkout.

`MANIFEST.json` records the input and crate digests and the crate's published
source revision. `results/` holds the per-case output from rustc 1.90.0.
The check compares every field except the compiler version. It then changes
one expected byte and its digest and requires exactly that row to mismatch,
so a runner that copies the expectations does not pass.

The v1 and v2 inputs are copied unchanged from
[the APS lab](https://github.com/Agent-Authority-Conformance/aps-conformance-suite/tree/5829e2ff00d75f49ce21e9d87e756658deb1ef33/fixtures/canonical-bytes).
Their Apache-2.0 license and attribution remain in `fixtures/LICENSE`.

## Verification split

Canonical bytes and SHA-256 / 8 v1 and 10 v2 fixture cases; runner:
Sankalp Gilda; Mode A; author-produced; implementation: `jcs-admit` 0.1.0.
The runner authored the crate, so this is not an independent implementation
run under the lab's contribution policy. An external run remains open.

These records are attributed per layer. Merge of this record is not an
end-to-end verification or a family-level verdict.
