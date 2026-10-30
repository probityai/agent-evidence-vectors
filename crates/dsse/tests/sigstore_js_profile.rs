//! Authored finite controls for the Sigstore-source Ed25519 threshold consumer.
//! The original Go-produced vectors remain unchanged. No task, authority,
//! target-effect, outside-operator or research-population claim is made here.

#![cfg(feature = "ed25519")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use dsse::{Ed25519Verifier, Envelope, Verifier};
use serde::Deserialize;

#[derive(Deserialize)]
struct Controls {
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    envelope: Envelope,
    trusted_keys: Vec<Key>,
    threshold: usize,
    expected: Expected,
}

#[derive(Deserialize)]
struct Key {
    id: String,
    public_hex: String,
}

#[derive(Deserialize)]
struct Expected {
    decision: String,
    accepted_keys: Vec<String>,
    rust_message: Option<String>,
}

fn verifier(key: &Key) -> Ed25519Verifier {
    let raw: Vec<u8> = key
        .public_hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair.as_slice()).unwrap(), 16).unwrap())
        .collect();
    Ed25519Verifier::from_bytes(&raw)
        .unwrap()
        .with_key_id(&key.id)
}

#[test]
fn frozen_controls_match_native_rust_decisions_and_exact_refusals() {
    let controls: Controls = serde_json::from_str(include_str!(
        "../interop/sigstore-js-threshold-2026-10-04/cases.json"
    ))
    .unwrap();
    assert_eq!(controls.cases.len(), 17);
    for case in controls.cases {
        let keys: Vec<Ed25519Verifier> = case.trusted_keys.iter().map(verifier).collect();
        let references: Vec<&dyn Verifier> = keys.iter().map(|key| key as &dyn Verifier).collect();
        match dsse::verify(&case.envelope, &references, case.threshold) {
            Ok(verified) => {
                assert_eq!(case.expected.decision, "verified", "{}", case.id);
                assert_eq!(
                    verified.accepted_keys, case.expected.accepted_keys,
                    "{}",
                    case.id
                );
                assert_eq!(
                    verified.payload_type, case.envelope.payload_type,
                    "{}",
                    case.id
                );
            }
            Err(error) => {
                assert_eq!(case.expected.decision, "refused", "{}", case.id);
                assert_eq!(
                    error.to_string(),
                    case.expected.rust_message.unwrap(),
                    "{}",
                    case.id
                );
            }
        }
    }
}
