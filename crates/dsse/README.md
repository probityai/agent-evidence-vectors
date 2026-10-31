# dsse

[![crates.io](https://img.shields.io/crates/v/dsse.svg)](https://crates.io/crates/dsse)
[![Downloads](https://img.shields.io/crates/d/dsse.svg)](https://crates.io/crates/dsse)
[![docs.rs](https://img.shields.io/docsrs/dsse)](https://docs.rs/dsse)
[![license](https://img.shields.io/crates/l/dsse.svg)](https://github.com/probityai/agent-evidence/tree/main/crates/dsse#license)
[![CI](https://github.com/probityai/agent-evidence/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/probityai/agent-evidence/actions/workflows/ci.yml)

DSSE, the Dead Simple Signing Envelope that in-toto and Sigstore sign inside, as a Rust crate on
its own: no in-toto dependency and no Sigstore dependency.

It's for Rust code that signs or verifies in-toto attestations and other DSSE envelopes and wants
the envelope without taking a whole attestation stack along with it.

## Quick start

Add it as a pinned dependency of a new project:

```bash
cargo new dsse-demo && cd dsse-demo
cargo add dsse@=0.1.6
```

Then put this in `src/main.rs` to sign an envelope and verify it:

```rust
use dsse::{sign, verify, Ed25519Signer};

fn main() -> Result<(), dsse::Error> {
    // A demo key; load yours from a secret store.
    let signer = Ed25519Signer::from_bytes(&[7u8; 32])?.with_key_id("demo");
    let envelope = sign("application/vnd.in-toto+json", br#"{"a":1}"#, &signer)?;

    // Verify, then read: the payload comes back only from a verified envelope.
    let verified = verify(&envelope, &[&signer.verifier()], 1)?;
    assert_eq!(verified.payload, br#"{"a":1}"#);

    println!("verified {} bytes of {}", verified.payload.len(), verified.payload_type);
    Ok(())
}
```

`cargo run` prints `verified 7 bytes of application/vnd.in-toto+json`.

The signature covers the payload type as well as the payload, so a signature made over one
payload type can't be replayed under another.

## What it refuses

Six things a permissive implementation accepts: a length prefix that counts characters where DSSE
counts bytes, non-canonical base64, an envelope with no signatures, a threshold of zero, a threshold met
by one key's signature copied several times, and a key hint used to exclude a key rather than to
order the attempts. DSSE's own reference implementation allows four of the six;
[PROVENANCE.md](https://github.com/probityai/agent-evidence/blob/main/crates/dsse/PROVENANCE.md) names the four.

To use a key other than ed25519, such as ECDSA, a KMS or a Sigstore signer, turn off the default
ed25519 feature and implement the `Signer` and `Verifier` traits.

## Status

Version 0.1.6 on [crates.io](https://crates.io/crates/dsse). The rules come from DSSE's
specification text at version 1.0.2, and the tests load cross-language fixtures built by the
DSSE reference Go implementation, recorded in PROVENANCE.md.

Version 0.1.3 adds optional error serialization. The npm package described in
[the JavaScript guide](https://github.com/probityai/agent-evidence/blob/main/crates/dsse/docs/NPM.md) has its own version, 0.1.0, and is not yet on the npm registry.

## Documentation

| page | read it for |
| --- | --- |
| <a name="what-a-signature-covers"></a><a name="verify-then-read"></a><a name="bring-your-own-signatures"></a><a name="tests"></a><a name="provenance"></a>[Design and evidence](https://github.com/probityai/agent-evidence/blob/main/crates/dsse/docs/DESIGN.md) | the pre-authentication encoding, why verification returns the payload, each refusal and its reason, and the tests |
| [Version 0.1.6 API reference](https://docs.rs/dsse/0.1.6/dsse/) | every type, trait and error in the installed release |
| [Agent guide](llms.txt) | installation, API entry points and runnable comparisons |
| [Sigstore JS consumer](https://github.com/probityai/agent-evidence/blob/main/crates/dsse/docs/SIGSTORE-JS-THRESHOLD.md) | runnable offline threshold checks under consumer-selected keys |
| [JavaScript and browser verification](https://github.com/probityai/agent-evidence/blob/main/crates/dsse/docs/NPM.md) | raw-byte Ed25519 verification, checked payloads and package identity |
| [Provenance](https://github.com/probityai/agent-evidence/blob/main/crates/dsse/PROVENANCE.md) | the specification text and commit each rule was read from |
| [Contributing](https://github.com/probityai/agent-evidence/blob/main/crates/dsse/CONTRIBUTING.md) and [changelog](https://github.com/probityai/agent-evidence/blob/main/crates/dsse/CHANGELOG.md) | how to propose a change, and what each release changed |

## License

Apache-2.0.
