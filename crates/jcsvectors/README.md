# jcsvectors

RFC 8785 (JSON Canonicalization Scheme) test vectors for Rust, embedded in the crate and checked against their SHA-256 digests before any case is returned.

It is for anyone who writes or depends on a JCS canonicalizer in Rust and wants a fixed, shared set of accept and refuse cases in `cargo test`, with no download and no network.

```toml
[dev-dependencies]
jcsvectors = "=0.1.0"
```

## Example

```rust
#[test]
fn my_canonicalizer_matches_rfc8785() {
    for v in jcsvectors::canonical().unwrap() {
        let got = my_crate::canonicalize(&v.input).unwrap();
        assert_eq!(Some(got), v.canonical, "{}/{}", v.corpus, v.id);
    }
    for v in jcsvectors::reject().unwrap() {
        assert!(my_crate::canonicalize(&v.input).is_err(), "{}/{} was accepted", v.corpus, v.id);
    }
}
```

## What is in it

| Function | Cases | A canonicalizer must |
|---|---|---|
| `canonical()` | every accept case, with the exact output bytes | print exactly `canonical` |
| `reject()` | duplicate members, lone surrogates, other input with no RFC 8785 form | refuse the input |
| `drifts()` | bytes a real printer presents as canonical that are not (HTML escapes, non-ASCII escapes, number format) | not treat `presented` as canonical |
| `too_deep()`, `depth_admitted()` | nesting one level past, and exactly at, a cap of 128 | refuse, or accept and print, under that cap |
| `files()` | the raw embedded files at their corpus paths | (for your own reader) |

The files are byte copies of `corpora/vectors-a2a-jcs-v01` and `corpora/jcs-byte-vectors` in [agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors). The same files ship as the Go module `github.com/probityai/agent-evidence-vectors/jcsvectors`, so Rust and Go implementations tested with them are held to the same bytes.

## Pinning

Pin an exact version. A release that adds a case can turn a passing implementation red, so such a release is a minor version, never a patch, and its notes list the cases that changed. Add a Dependabot `cargo` entry for the directory that holds your `Cargo.toml` so each release opens a pull request your tests run.

## Status

0.1.0. MSRV 1.74. Licensed MIT OR Apache-2.0.
