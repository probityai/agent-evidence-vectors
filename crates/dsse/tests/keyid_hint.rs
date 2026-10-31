//! INVENTED CASES. `keyid` sits outside the pre-authentication encoding, so it
//! is attacker-controlled on any envelope an attacker can touch. The protocol
//! says it MUST NOT be used for security decisions and MAY only narrow the
//! selection of keys to try. An implementation that treats a mismatch as a
//! reason to skip a key turns that unauthenticated string into a way to make a
//! valid signature unverifiable.

#![cfg(feature = "ed25519")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use dsse::{sign_with, Ed25519Signer, Envelope};

fn signer(seed: u8, id: &str) -> Ed25519Signer {
    Ed25519Signer::from_bytes(&[seed; 32])
        .unwrap()
        .with_key_id(id)
}

/// A valid signature carrying somebody else's `keyid`. The signature is genuine
/// and the key is trusted, so the envelope must verify.
#[test]
fn a_wrong_keyid_does_not_block_a_valid_signature() {
    let a = signer(1, "key-a");
    let env = sign_with("t", b"payload", &[&a]).unwrap();

    let mut forged = env.clone();
    forged.signatures[0].keyid = Some("not-the-signing-key".to_string());

    let va = a.verifier();
    let verified = dsse::verify(&forged, &[&va], 1)
        .expect("an unauthenticated hint must not decide verification");
    assert_eq!(verified.payload, b"payload");
    assert_eq!(verified.accepted_keys, vec!["key-a".to_string()]);
}

/// The same with `keyid` stripped entirely. The schema says absent and
/// set-but-empty are the same value, and neither withholds verification.
#[test]
fn an_absent_or_empty_keyid_does_not_block_verification() {
    let a = signer(1, "key-a");
    let env = sign_with("t", b"payload", &[&a]).unwrap();
    let va = a.verifier();

    for keyid in [None, Some(String::new())] {
        let mut probe = env.clone();
        probe.signatures[0].keyid = keyid.clone();
        let verified = dsse::verify(&probe, &[&va], 1)
            .unwrap_or_else(|e| panic!("keyid {keyid:?} must not block verification: {e:?}"));
        assert_eq!(verified.payload, b"payload");
    }
}

/// A verifier that reports no identifier at all still verifies, and is named by
/// its position so a caller can tell which key was accepted.
#[test]
fn an_anonymous_key_verifies_and_is_named_by_position() {
    let a = Ed25519Signer::from_bytes(&[1u8; 32]).unwrap();
    let env = sign_with("t", b"payload", &[&a]).unwrap();
    assert_eq!(env.signatures[0].keyid, None, "no hint is written");

    let va = a.verifier();
    let verified = dsse::verify(&env, &[&va], 1).unwrap();
    assert_eq!(verified.accepted_keys, vec!["#0".to_string()]);
}

/// A correct `keyid` changes nothing about the outcome. It is the control: the
/// hint is allowed to narrow the order of attempts, never the result.
#[test]
fn a_correct_keyid_gives_the_same_result_as_a_wrong_one() {
    let a = signer(1, "key-a");
    let env = sign_with("t", b"payload", &[&a]).unwrap();
    let va = a.verifier();

    let right = dsse::verify(&env, &[&va], 1).unwrap();

    let mut wrong_env = env;
    wrong_env.signatures[0].keyid = Some("wrong".into());
    let wrong = dsse::verify(&wrong_env, &[&va], 1).unwrap();

    assert_eq!(right, wrong);
}

/// With two trusted keys and one signature, a misleading hint must not stop the
/// scan before it reaches the key that actually signed.
#[test]
fn a_misleading_hint_does_not_stop_the_scan() {
    let a = signer(1, "key-a");
    let b = signer(2, "key-b");
    let env = sign_with("t", b"payload", &[&b]).unwrap();

    let mut forged = env;
    forged.signatures[0].keyid = Some("key-a".to_string());

    let (va, vb) = (a.verifier(), b.verifier());
    let verified = dsse::verify(&forged, &[&va, &vb], 1)
        .expect("the scan must reach key-b despite the hint naming key-a");
    assert_eq!(verified.accepted_keys, vec!["key-b".to_string()]);
}

/// Verified bytes come from the verify call, and match the payload that was
/// signed rather than anything re-read from the envelope afterwards.
#[test]
fn verified_bytes_come_from_the_verify_call() {
    let a = signer(1, "key-a");
    let payload = b"the exact bytes that were signed";
    let env: Envelope = sign_with("t", payload, &[&a]).unwrap();
    let va = a.verifier();

    let verified = dsse::verify(&env, &[&va], 1).unwrap();
    assert_eq!(verified.payload.as_slice(), payload.as_slice());
    assert_eq!(verified.payload_type, "t");
}
