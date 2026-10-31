# jcs-admit

[![crates.io](https://img.shields.io/crates/v/jcs-admit.svg)](https://crates.io/crates/jcs-admit)
[![Downloads](https://img.shields.io/crates/d/jcs-admit.svg)](https://crates.io/crates/jcs-admit)
[![docs.rs](https://img.shields.io/docsrs/jcs-admit)](https://docs.rs/jcs-admit)
[![license](https://img.shields.io/crates/l/jcs-admit.svg)](https://github.com/probityai/agent-evidence/tree/main/crates/jcs-admit#license)
[![CI](https://github.com/probityai/agent-evidence/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/probityai/agent-evidence/actions/workflows/ci.yml)

Admission control for JSON that is about to be signed or verified. It checks the raw bytes before
any parser sees them, refuses documents that two parsers could read differently, and then writes
the RFC 8785 canonical form.

It's for Rust code that signs, verifies or hashes canonical JSON, such as in-toto statements,
DSSE payloads or signed receipts.

## Quick start

Add it as a pinned dependency of a new project:

```bash
cargo new jcs-admit-demo && cd jcs-admit-demo
cargo add jcs-admit@=0.1.3
```

Then put this in `src/main.rs` to admit a document before you sign it:

```rust
use jcs_admit::{admit, Error};

fn main() -> Result<(), Error> {
    let canonical = admit(br#"{ "b": 1, "a": [1.0, 1e30] }"#)?;
    assert_eq!(canonical, br#"{"a":[1,1e+30],"b":1}"#);

    // One document, two readings: refused before any parser picks one.
    let refused = admit(br#"{"a":1,"a":2}"#);
    assert!(matches!(refused, Err(Error::DuplicateMember { .. })));

    println!("{}", String::from_utf8_lossy(&canonical));
    Ok(())
}
```

`cargo run` prints `{"a":[1,1e+30],"b":1}`.

## What it refuses

It refuses a repeated object member, compared on the decoded name; nesting past a depth cap, 128
by default, the value the in-toto attestation specification sets; a string whose bytes aren't
Unicode scalar values, such as an unpaired surrogate or an overlong form; a number with no finite
double, and under the opt-in I-JSON profile an integer at or above 2^53; and an input past a size
cap. Each refusal is a named error variant with structured fault details, such as a byte offset
or offending token. Number formatting is delegated to
[serde_json_canonicalizer](https://crates.io/crates/serde_json_canonicalizer).

## Status

Version 0.1.3 on [crates.io](https://crates.io/crates/jcs-admit), minimum Rust 1.74. The tests
load vectors produced by the Go implementation in
[agent-evidence-vectors](https://github.com/probityai/agent-evidence-vectors), never by this crate,
and every refusal is mutation-tested.

Version 0.1.2 adds optional error serialization and the shared byte-cap
check. The npm package has its own version and release, and is not yet on the npm registry.
The Python wheel is built and tested from `python/` and is not yet on PyPI.

## Documentation

| page | read it for |
| --- | --- |
| [JavaScript and WebAssembly](https://github.com/probityai/agent-evidence/blob/main/crates/jcs-admit/docs/NPM.md) | raw-byte Node and browser API, packed consumer checks and release verification |
| [Python](https://github.com/probityai/agent-evidence/blob/main/crates/jcs-admit/docs/PYTHON.md) | the `probityai` wheel's bytes-in, bytes-out API, its refusal contract and the corpora it is tested on |
| <a name="what-a-serializer-cannot-check"></a><a name="what-the-delegate-does-with-a-hostile-document"></a><a name="what-it-delegates"></a><a name="evidence"></a>[Design and evidence](https://github.com/probityai/agent-evidence/blob/main/crates/jcs-admit/docs/DESIGN.md) | why a serializer can't make these checks, what the delegate does with a hostile document, and the test evidence |
| [APS canonical-byte comparison](https://github.com/probityai/agent-evidence/blob/main/crates/jcs-admit/interop/aps-canonical-bytes/README.md) | pinned 8-case and 10-case byte results and how to reproduce them |
| [Python byte-profile comparison](https://github.com/probityai/agent-evidence/blob/main/crates/jcs-admit/interop/rfc8785-py/README.md) | independent byte cases, native raw-input refusals and a source-pinned Python consumer |
| [Go raw-admission adapter](https://github.com/probityai/agent-evidence/blob/main/crates/jcs-admit/interop/go-jcs/README.md) | pinned Go bytes, original input admission and explicit root/profile boundaries |
| [Version 0.1.3 API reference](https://docs.rs/jcs-admit/0.1.3/jcs_admit/) | every function, option and error variant in the installed release |
| [Agent guide](llms.txt) | raw-input admission, profile selection and runnable comparisons |
| [Comparison with other RFC 8785 crates](https://github.com/probityai/agent-evidence/blob/main/crates/jcs-admit/docs/INCUMBENT-MEASUREMENT.md) | how seven RFC 8785 crates on crates.io handle hostile input |
| [Mutation sweep](https://github.com/probityai/agent-evidence/blob/main/crates/jcs-admit/docs/MUTATION-SWEEP.md) | how each refusal was shown to be tested |
| [Contributing](https://github.com/probityai/agent-evidence/blob/main/crates/jcs-admit/CONTRIBUTING.md) and [changelog](https://github.com/probityai/agent-evidence/blob/main/crates/jcs-admit/CHANGELOG.md) | how to propose a change, and what each release changed |

## License

MIT OR Apache-2.0, at your option.
