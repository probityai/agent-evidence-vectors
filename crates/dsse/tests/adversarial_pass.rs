//! What an adversarial pass over this crate found, pinned so it cannot come back.
//!
//! Four cases. Two were the crate returning `Ok` where it had no business doing
//! so, and two were the crate refusing an envelope an attacker had merely
//! decorated. All four were run against the unpatched crate first and are logged
//! in the report that accompanied the patch.

// A failing assertion is this file's purpose, so the crate's deny on `expect`,
// `unwrap`, indexing and `panic` is relaxed here and nowhere else. Library code
// keeps all four.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use base64::Engine as _;
use dsse::{
    sign, sign_with, verify, Ed25519Signer, Ed25519Verifier, Envelope, Error, Signature, Verifier,
};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

fn signer(seed: u8, id: &str) -> Ed25519Signer {
    Ed25519Signer::from_bytes(&[seed; 32])
        .expect("32 bytes is a valid seed")
        .with_key_id(id)
}

fn envelope() -> (Ed25519Signer, Envelope) {
    let s = signer(7, "k1");
    let env = sign("application/vnd.example+json", br#"{"a":1}"#, &s).expect("signing");
    (s, env)
}

// ---------------------------------------------------- one key is not two keys

#[test]
fn one_key_supplied_twice_does_not_satisfy_a_two_of_n() {
    // The attack: hand `verify` the same trusted key twice and ask for 2. Before
    // the check existed this returned Ok, and `accepted_keys` came back
    // ["k1", "k1"] -- the result carried the proof that the count was wrong and
    // nothing looked at it.
    let (s, env) = envelope();
    let v = s.verifier();
    assert_eq!(
        verify(&env, &[&v, &v], 2).unwrap_err(),
        Error::DuplicateKeyId {
            key_id: "k1".to_owned()
        }
    );
    // Three copies and a 3-of-n, which is the same attack asking for more.
    assert_eq!(
        verify(&env, &[&v, &v, &v], 3).unwrap_err(),
        Error::DuplicateKeyId {
            key_id: "k1".to_owned()
        }
    );
    // Two DISTINCT verifier objects over one key, reporting one identifier: the
    // shape a trust set assembled from a directory with a duplicated entry has.
    let a = s.verifier();
    let b = s.verifier();
    assert_eq!(
        verify(&env, &[&a, &b], 2).unwrap_err(),
        Error::DuplicateKeyId {
            key_id: "k1".to_owned()
        }
    );
}

#[test]
fn a_threshold_above_one_refuses_a_key_that_cannot_be_named() {
    // Anonymous keys cannot be told apart, so the same key twice is
    // indistinguishable from two keys. Before the check, two anonymous verifiers
    // over ONE key satisfied a 2-of-n and reported accepted_keys ["#0", "#1"].
    struct Anon(Ed25519Verifier);
    impl Verifier for Anon {
        fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
            self.0.verify(message, signature)
        }
    }
    let (s, env) = envelope();
    let a = Anon(s.verifier());
    let b = Anon(s.verifier());
    assert_eq!(
        verify(&env, &[&a, &b], 2).unwrap_err(),
        Error::UnidentifiedKey { index: 0 }
    );
    // A 1-of-n has nothing to count, so an anonymous key still verifies there.
    let verified = verify(&env, &[&a], 1).expect("a 1-of-n needs no identity");
    assert_eq!(verified.accepted_keys, vec!["#0".to_owned()]);
}

#[test]
fn two_genuinely_distinct_keys_still_meet_a_two_of_n() {
    // The positive control. Without it the two refusals above are satisfied by a
    // check that refuses every threshold above one.
    let a = signer(7, "ka");
    let b = signer(9, "kb");
    let env =
        dsse::sign_with("application/vnd.example+json", br#"{"a":1}"#, &[&a, &b]).expect("signing");
    let verified = verify(&env, &[&a.verifier(), &b.verifier()], 2).expect("two keys, two of two");
    assert_eq!(
        verified.accepted_keys,
        vec!["ka".to_owned(), "kb".to_owned()]
    );
}

// -------------------------------------- a decorated envelope is still verified

#[test]
fn an_appended_unusable_signature_entry_does_not_brick_a_valid_envelope() {
    // `signatures` is outside every signature, so appending an entry costs an
    // attacker nothing. Before the fix, an entry whose `sig` was not decodable
    // made the whole envelope `Err(NonCanonicalBase64)` -- a denial of
    // verification over an envelope that was, and still is, validly signed.
    let (s, env) = envelope();
    let v = s.verifier();

    let mut junk_b64 = env.clone();
    junk_b64.signatures.push(Signature {
        keyid: None,
        sig: "!!!!".to_owned(),
    });
    assert_eq!(
        verify(&junk_b64, &[&v], 1)
            .expect("the valid entry still verifies")
            .accepted_keys,
        vec!["k1".to_owned()]
    );

    // Non-canonical base64 is the same case: refused for the payload, skipped for
    // an entry.
    let mut trailing_bits = env.clone();
    trailing_bits.signatures.push(Signature {
        keyid: Some("k1".to_owned()),
        sig: "eB==".to_owned(),
    });
    assert!(verify(&trailing_bits, &[&v], 1).is_ok());

    // And an entry that decodes to the wrong length, and one that is a valid
    // length but a wrong signature.
    let mut wrong = env.clone();
    wrong.signatures.push(Signature {
        keyid: Some("k1".to_owned()),
        sig: B64.encode([0u8; 64]),
    });
    assert!(verify(&wrong, &[&v], 1).is_ok());
}

#[test]
fn an_envelope_in_which_nothing_decodes_is_still_refused_by_field() {
    // The diagnostic the skip must not cost: if NO entry decodes there is no
    // valid signature to protect and the caller should hear why.
    let (s, env) = envelope();
    let mut all_bad = env;
    all_bad.signatures = vec![Signature {
        keyid: None,
        sig: "!!!!".to_owned(),
    }];
    assert_eq!(
        verify(&all_bad, &[&s.verifier()], 1).unwrap_err(),
        Error::NonCanonicalBase64 {
            field: "signatures[].sig"
        }
    );
}

#[test]
fn more_signature_entries_than_the_cap_are_refused_before_any_are_checked() {
    let (s, env) = envelope();
    let mut many = env;
    let good = many.signatures[0].clone();
    while many.signatures.len() <= dsse::MAX_SIGNATURES {
        many.signatures.push(good.clone());
    }
    assert_eq!(
        verify(&many, &[&s.verifier()], 1).unwrap_err(),
        Error::TooManySignatures {
            got: dsse::MAX_SIGNATURES + 1,
            cap: dsse::MAX_SIGNATURES,
        }
    );

    // And exactly AT the cap still verifies. A refusal test that only feeds
    // inputs past the bound cannot tell a correct guard from one that refuses
    // good evidence, which is the direction nobody tests.
    many.signatures.truncate(dsse::MAX_SIGNATURES);
    assert_eq!(many.signatures.len(), dsse::MAX_SIGNATURES);
    assert!(
        verify(&many, &[&s.verifier()], 1).is_ok(),
        "an envelope of exactly MAX_SIGNATURES entries must be verified"
    );
}

// ------------------------------------------------- a type that binds nothing

#[test]
fn an_empty_payload_type_is_refused_at_both_ends() {
    // PAE("", body) is "DSSEv1 0  <len> <body>". It is a well-formed pre-image
    // over a type that names nothing, and the crate used to mint it and verify it.
    let s = signer(7, "k1");
    assert_eq!(
        sign("", br#"{"a":1}"#, &s).unwrap_err(),
        Error::EmptyPayloadType
    );

    // Verification refuses it independently, because an envelope does not have to
    // have come from `sign`.
    let hand_rolled = Envelope {
        payload: B64.encode(br#"{"a":1}"#),
        payload_type: String::new(),
        signatures: vec![Signature {
            keyid: Some("k1".to_owned()),
            sig: B64.encode([0u8; 64]),
        }],
    };
    assert_eq!(
        verify(&hand_rolled, &[&s.verifier()], 1).unwrap_err(),
        Error::EmptyPayloadType
    );
}

// ----------------------------------------------- an envelope nobody can accept

#[test]
fn signing_with_no_signers_is_refused() {
    // An empty signer list used to mint an envelope with `signatures: []`, which
    // `verify` refuses. It is refused at minting, with the error verification gives.
    assert_eq!(
        sign_with("application/vnd.in-toto+json", br#"{"a":1}"#, &[]).unwrap_err(),
        Error::NoSignatures
    );
}
