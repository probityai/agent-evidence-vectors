//! Synthetic Rust API pair for decoded-payload signing.
//! DSSE signs `PAE(payloadType, payload)` over decoded bytes. The envelope's
//! `payload` member carries those bytes as base64. This pair changes only the
//! signed pre-image: base64 transport text is refused; decoded bytes verify.

#![cfg(feature = "ed25519")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use base64::Engine as _;
use dsse::{pae, Ed25519Signer, Envelope, Signature, Signer};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";
const PAYLOAD: &[u8] = br#"{"_type":"https://in-toto.io/Statement/v1","subject":[]}"#;

fn signer() -> Ed25519Signer {
    Ed25519Signer::from_bytes(&[7; 32])
        .unwrap()
        .with_key_id("k")
}

fn envelope_signed_over(signer: &Ed25519Signer, pre_image: &[u8]) -> Envelope {
    Envelope {
        payload: B64.encode(PAYLOAD),
        payload_type: PAYLOAD_TYPE.to_string(),
        signatures: vec![Signature {
            keyid: Some("k".to_string()),
            sig: B64.encode(signer.sign(pre_image).unwrap()),
        }],
    }
}

/// The signature covers PAE of the base64 TEXT. A conforming verifier computes
/// PAE over the decoded bytes, so the signature does not verify.
#[test]
fn a_signature_over_the_base64_text_is_rejected() {
    let s = signer();
    let encoded = B64.encode(PAYLOAD);
    let env = envelope_signed_over(&s, &pae(PAYLOAD_TYPE, encoded.as_bytes()));

    let v = s.verifier();
    assert!(
        dsse::verify(&env, &[&v], 1).is_err(),
        "PAE is computed over the decoded payload, never its base64 encoding"
    );
}

/// The control: the same key over PAE of the decoded bytes verifies, so the
/// rejection above is caused by the pre-image and nothing else.
#[test]
fn the_same_key_over_the_decoded_bytes_verifies() {
    let s = signer();
    let env = envelope_signed_over(&s, &pae(PAYLOAD_TYPE, PAYLOAD));

    let v = s.verifier();
    let verified = dsse::verify(&env, &[&v], 1).unwrap();
    assert_eq!(verified.payload, PAYLOAD);
}
