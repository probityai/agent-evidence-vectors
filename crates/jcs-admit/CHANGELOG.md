# Changelog

All notable changes to this crate are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this crate
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.1.4

### Changed

- The `serde_json_canonicalizer` floor is now `0.4.1`, up from `0.3.2`. The new release makes
  the delegate's own serializer refuse a duplicate object key reaching its object assembly
  directly, instead of silently keeping the first one (its `pipe` and `Value` entry points are
  unaffected: `serde_json::Value` has already collapsed the duplicate to the last member before
  either reaches the delegate). This crate already refuses a duplicate object member on the raw
  bytes, in `parse.rs`, before any entry point is called, so nothing this crate admits or
  refuses changes. `tests/incumbent_differential.rs` is updated to match: the entry point that
  used to be a second, disagreeing acceptance is now a second refusal, and the test and its
  doc comment say so rather than silently going green on an overbroad old assertion.

## 0.1.3

### Changed

Package metadata only. The `repository` field now points at the monorepo,
https://github.com/probityai/agent-evidence, where the crate is developed. No code,
test vector, refusal or public API changed.

## 0.1.2

### Added

- Optional `serde` serialization of the existing error enum and a shared
  `Options::check_input_length` byte-cap check for allocation boundaries. The
  check does not parse or admit bytes. Native defaults and refusal fields are
  unchanged.
- A separate public WASM binding crate for raw-byte `admit` and `admit_ijson`,
  requiring Rust 1.81 or newer and retaining its own dependency lock. It does not
  raise the native core's Rust or dependency floors.
- An ESM npm package for Node and browsers, with one Rust-built WASM artifact,
  `Uint8Array` input and output, and `JcsError` preserving native variants and
  fields. Its first version is `0.1.0`, with its own `npm-v0.1.0` release tag and
  registry artifact identity.
- Packed Node, browser and TypeScript consumer checks against the native core
  and retained independent fixtures, plus an OIDC release workflow that publishes
  the qualified tarball with provenance.

## 0.1.1 - 2026-09-30

### Changed

- The `serde` requirement is now `1.0.100`, down from `1.0.229`. 0.1.0 asked for more than it
  uses, so a dependent on serde 1.0.228 had its lockfile moved to 1.0.229, and serde_derive
  1.0.229 brought syn 3 in beside syn 2. 1.0.100 is the lowest the dependency graph allows:
  `serde_json_canonicalizer` 0.3.2 needs `serde_json` 1.0.87, which needs serde 1.0.100.
- The `serde_json` dev-dependency is now `1.0.87`, so the suite can run at that floor.

### Added

- `tests/dependency_floor.rs`, which fails when a runtime floor changes.
- CI: the suite on stable with rustfmt, clippy and rustdoc as errors; on the MSRV; and on the
  MSRV with every dependency resolved to its lowest allowed version (`-Z minimal-versions`).

## 0.1.0 - 2026-09-19

First release. Admission control for JSON about to be signed, decided on the raw bytes before
any decode, with RFC 8785 canonicalization delegated to `serde_json_canonicalizer`.

### Added

Three entry points that canonicalize, and two that answer a verifier's question directly:

- `admit`, `admit_ijson` and `admit_with`: `&[u8]` in, canonical `Vec<u8>` out.
- `is_canonical` and `is_canonical_with`, because a verifier must hash the bytes it received
  rather than bytes it re-serialized.

Taking bytes is a design decision rather than a convenience. A surrogate written directly in
UTF-8 and an overlong form cannot be represented in a Rust string, so a `&str` entry point
cannot be handed them at all.

Then the supporting surface:

- `Options`, with seven `const` builder methods, so you can build a profile in a static.
- `Error`, `#[non_exhaustive]`, ten variants, each carrying a byte offset or the offending
  token.
- `DEFAULT_MAX_DEPTH` (128, the value in-toto's normative text carries),
  `MAX_SUPPORTED_DEPTH` (512) and `DEFAULT_MAX_BYTES` (20 MiB).

**What this refuses that a serializer over a parsed value cannot.** Structural faults, which a parse destroys on its way past them:

- A repeated object member, compared on the decoded name. By the time a `serde_json::Value`
  exists the repeat has collapsed to last-wins.
- Nesting past a depth cap, charged per open container.
- An input past a size cap. A depth cap bounds the stack; a size cap bounds the heap.

String faults, checked before any decode:

- Unpaired or mispaired surrogate escapes.
- Surrogates encoded directly in the bytes, and overlong forms.
- Unicode noncharacters, under the I-JSON profile only.

Number faults, decided on the digit string:

- An integer at or above 2^53 under the safe-integer profile. The check is notation-blind, so
  `1e21` is seen as the integer it denotes.
- A number with a fractional part, under the integers-only tightening.
- A number token with no finite double.
