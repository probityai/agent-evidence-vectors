//! PINNED VECTOR. Every case here is copied from the DSSE specification itself,
//! `protocol.md` and `envelope.md` at
//! github.com/secure-systems-lab/dsse commit 851704a287847d8dcaf7ae1ca76ce9169511ee88
//! (spec version 1.0.2, dated May 10 2024). Nothing here is invented.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use dsse::{pae, Envelope};

/// protocol.md, "Test Vectors": SERIALIZED_BODY `hello world`, PAYLOAD_TYPE
/// `http://example.com/HelloWorld`, and the PAE the specification prints.
#[test]
fn spec_pae_vector() {
    let got = pae("http://example.com/HelloWorld", b"hello world");
    assert_eq!(
        got,
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
    );
}

/// protocol.md, "Test Vectors": the JSON envelope printed beside that PAE.
/// The signature is ECDSA P-256, which this crate has no backend for, so the
/// case pins the container and the base64 of the payload, not the signature.
#[test]
fn spec_envelope_vector() {
    let json = br#"{"payload": "aGVsbG8gd29ybGQ=",
 "payloadType": "http://example.com/HelloWorld",
 "signatures": [{"sig": "A3JqsQGtVsJ2O2xqrI5IcnXip5GToJ3F+FnZ+O88SjtR6rDAajabZKciJTfUiHqJPcIAriEGAHTVeCUjW2JIZA=="}]}"#;

    let env = Envelope::from_json(json).expect("the specification's own envelope must parse");
    assert_eq!(env.payload_type, "http://example.com/HelloWorld");
    assert_eq!(env.payload, "aGVsbG8gd29ybGQ=");
    assert_eq!(env.signatures.len(), 1);
    // envelope.md parsing rules: keyid is OPTIONAL and MAY be unset.
    assert_eq!(env.signatures[0].keyid, None);
}

/// The reference implementation's doctest (`implementation/signing_spec.py`)
/// prints this envelope with a `keyid` of `66301bbf` present.
#[test]
fn spec_reference_envelope_with_keyid() {
    let json = br#"{"payload": "aGVsbG8gd29ybGQ=", "payloadType": "http://example.com/HelloWorld", "signatures": [{"keyid": "66301bbf", "sig": "A3JqsQGtVsJ2O2xqrI5IcnXip5GToJ3F+FnZ+O88SjtR6rDAajabZKciJTfUiHqJPcIAriEGAHTVeCUjW2JIZA=="}]}"#;
    let env = Envelope::from_json(json).expect("the reference envelope must parse");
    assert_eq!(env.signatures[0].keyid.as_deref(), Some("66301bbf"));
}

/// envelope.md parsing rules: "Producers, or future versions of the spec, MAY
/// add additional fields. Consumers MUST ignore unrecognized fields."
#[test]
fn spec_unrecognised_members_are_ignored() {
    let json = br#"{"payload": "aGVsbG8gd29ybGQ=", "payloadType": "t",
      "signatures": [{"sig": "AAAA", "futureField": 1}], "envelopeExtension": {"x": [1,2]}}"#;
    let env = Envelope::from_json(json).expect("an envelope with future members must parse");
    assert_eq!(env.payload_type, "t");
}
