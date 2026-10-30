//! INVENTED CASES. A threshold is the one place in DSSE where a verifier counts
//! something, and counting the wrong thing is exploitable: the protocol says a
//! `(t, n)` envelope is valid when signatures verify under at least `t` of `n`
//! **unique** trusted keys, and an implementation that counts signature entries
//! instead lets one key satisfy any threshold.

#![cfg(feature = "ed25519")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use dsse::{sign_with, Ed25519Signer, Envelope, Error, Signature, Verifier};

fn signer(seed: u8, id: &str) -> Ed25519Signer {
    Ed25519Signer::from_bytes(&[seed; 32])
        .unwrap()
        .with_key_id(id)
}

/// One key, its single valid signature copied three times, a threshold of two.
/// Three entries verify. One key signed. The envelope must be refused.
#[test]
fn a_duplicated_signature_does_not_satisfy_a_higher_threshold() {
    let a = signer(1, "key-a");
    let env = sign_with("t", b"payload", &[&a]).unwrap();
    assert_eq!(env.signatures.len(), 1);

    let entry = env.signatures[0].clone();
    let padded = Envelope {
        signatures: vec![entry.clone(), entry.clone(), entry],
        ..env
    };

    let va = a.verifier();
    let err = dsse::verify(&padded, &[&va], 2).unwrap_err();
    assert_eq!(
        err,
        Error::ThresholdNotMet {
            accepted: 1,
            threshold: 2
        },
        "three copies of one signature are one key, not three; got {err:?}"
    );
}

/// The same envelope at a threshold of one is valid, and reports exactly one
/// accepted key rather than three. This is the control: it shows the refusal
/// above is about counting keys, not about rejecting repeated entries.
#[test]
fn a_duplicated_signature_counts_once_at_a_threshold_of_one() {
    let a = signer(1, "key-a");
    let env = sign_with("t", b"payload", &[&a]).unwrap();
    let entry = env.signatures[0].clone();
    let padded = Envelope {
        signatures: vec![entry.clone(), entry],
        ..env
    };

    let va = a.verifier();
    let verified = dsse::verify(&padded, &[&va], 1).unwrap();
    assert_eq!(verified.accepted_keys, vec!["key-a".to_string()]);
}

/// Two distinct keys, two signatures, a threshold of two: valid, and both keys
/// are named. This is the positive control for the counting rule.
#[test]
fn two_distinct_keys_meet_a_threshold_of_two() {
    let a = signer(1, "key-a");
    let b = signer(2, "key-b");
    let env = sign_with("t", b"payload", &[&a, &b]).unwrap();
    assert_eq!(env.signatures.len(), 2);

    let (va, vb) = (a.verifier(), b.verifier());
    let verified = dsse::verify(&env, &[&va, &vb], 2).unwrap();
    assert_eq!(verified.accepted_keys.len(), 2);
    assert!(verified.accepted_keys.contains(&"key-a".to_string()));
    assert!(verified.accepted_keys.contains(&"key-b".to_string()));
    assert_eq!(verified.payload, b"payload");
}

#[test]
fn two_labels_for_one_key_do_not_meet_a_threshold_of_two() {
    let a = signer(1, "key-a");
    let alias = signer(1, "key-b");
    let env = sign_with("t", b"payload", &[&a]).unwrap();

    let va = a.verifier();
    let vb = alias.verifier();
    assert_eq!(
        dsse::verify(&env, &[&va, &vb], 2).unwrap_err(),
        Error::DuplicateKeyIdentity {
            first: 0,
            second: 1
        }
    );
}

#[test]
fn a_custom_verifier_needs_a_key_identity_for_threshold_two() {
    struct LabelOnly(dsse::Ed25519Verifier);
    impl Verifier for LabelOnly {
        fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
            self.0.verify(message, signature)
        }

        fn key_id(&self) -> Option<String> {
            self.0.key_id()
        }
    }

    let a = signer(1, "key-a");
    let b = signer(2, "key-b");
    let env = sign_with("t", b"payload", &[&a, &b]).unwrap();
    let va = LabelOnly(a.verifier());
    let vb = LabelOnly(b.verifier());

    assert_eq!(
        dsse::verify(&env, &[&va, &vb], 2).unwrap_err(),
        Error::UnidentifiedKeyIdentity { index: 0 }
    );
    assert!(dsse::verify(&env, &[&va], 1).is_ok());
}

#[test]
fn custom_verifiers_with_key_identities_meet_threshold_two() {
    struct Named(dsse::Ed25519Verifier);
    impl Verifier for Named {
        fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
            self.0.verify(message, signature)
        }

        fn key_id(&self) -> Option<String> {
            self.0.key_id()
        }

        fn key_identity(&self) -> Option<Vec<u8>> {
            self.0.key_identity()
        }
    }

    let a = signer(1, "key-a");
    let b = signer(2, "key-b");
    let env = sign_with("t", b"payload", &[&a, &b]).unwrap();
    let va = Named(a.verifier());
    let vb = Named(b.verifier());

    let verified = dsse::verify(&env, &[&va, &vb], 2).unwrap();
    assert_eq!(verified.accepted_keys, vec!["key-a", "key-b"]);
}

/// A threshold above the number of trusted keys can never be met, and must be
/// reported as a threshold failure rather than silently succeeding.
#[test]
fn threshold_above_the_trusted_key_count_is_refused() {
    let a = signer(1, "key-a");
    let env = sign_with("t", b"payload", &[&a]).unwrap();
    let va = a.verifier();
    let err = dsse::verify(&env, &[&va], 3).unwrap_err();
    assert_eq!(
        err,
        Error::ThresholdNotMet {
            accepted: 1,
            threshold: 3
        }
    );
}

/// A signature from an untrusted key contributes nothing, and is not an error on
/// its own: the protocol says to skip over a signature that does not verify.
#[test]
fn an_untrusted_signature_is_skipped_not_fatal() {
    let a = signer(1, "key-a");
    let stranger = signer(9, "stranger");
    let env = sign_with("t", b"payload", &[&a, &stranger]).unwrap();

    let va = a.verifier();
    let verified = dsse::verify(&env, &[&va], 1).unwrap();
    assert_eq!(verified.accepted_keys, vec!["key-a".to_string()]);
}

/// A tampered payload invalidates every signature over the old pre-image, so
/// no threshold is met even though the envelope is well formed.
#[test]
fn a_tampered_payload_meets_no_threshold() {
    let a = signer(1, "key-a");
    let mut env = sign_with("t", b"payload", &[&a]).unwrap();
    env.payload = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(b"tampered")
    };

    let va = a.verifier();
    let err = dsse::verify(&env, &[&va], 1).unwrap_err();
    assert_eq!(
        err,
        Error::ThresholdNotMet {
            accepted: 0,
            threshold: 1
        }
    );
}

/// Changing only the payload type invalidates the signature, because the type is
/// inside the pre-image. This is the cosign type-confusion class, checked on a
/// real signature rather than described.
#[test]
fn a_swapped_payload_type_meets_no_threshold() {
    let a = signer(1, "key-a");
    let mut env = sign_with("application/vnd.a+json", b"payload", &[&a]).unwrap();
    env.payload_type = "application/vnd.b+json".to_string();

    let va = a.verifier();
    let err = dsse::verify(&env, &[&va], 1).unwrap_err();
    assert_eq!(
        err,
        Error::ThresholdNotMet {
            accepted: 0,
            threshold: 1
        }
    );
}

/// A signature of the wrong length must make the verifier return false, never
/// panic. Verified through a signature member truncated to 32 bytes.
#[test]
fn a_short_signature_is_false_not_a_panic() {
    let a = signer(1, "key-a");
    let va = a.verifier();
    assert!(!va.verify(b"message", &[]));
    assert!(!va.verify(b"message", &[0u8; 32]));
    assert!(!va.verify(b"message", &[0u8; 65]));
}

/// An envelope whose signature member is well-formed base64 but the wrong length
/// is a threshold failure, not a decode failure.
#[test]
fn a_wrong_length_signature_is_a_threshold_failure() {
    let a = signer(1, "key-a");
    let env = sign_with("t", b"payload", &[&a]).unwrap();
    let short = Envelope {
        signatures: vec![Signature {
            keyid: Some("key-a".into()),
            sig: "AAAA".into(),
        }],
        ..env
    };
    let va = a.verifier();
    let err = dsse::verify(&short, &[&va], 1).unwrap_err();
    assert_eq!(
        err,
        Error::ThresholdNotMet {
            accepted: 0,
            threshold: 1
        }
    );
}
