//! The envelope-layer shapes the November 2026 teardowns built against other
//! projects' verifiers, run against this crate.
//!
//! Those verifiers accepted a record signed by a key made for the purpose when
//! no signer was pinned, a record relabelled outside the signed bytes, a member
//! named twice that one reader resolves to its first value and another to its
//! last, and members the signature did not cover riding on a verified record.
//! Here the trusted keys are an argument, the payload type is inside the
//! pre-authentication encoding, and the only bytes handed back are the ones the
//! signature covered. A member named twice in the envelope must not parse: the
//! two readings are two envelopes, and only one of them was checked.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use dsse::{sign, verify, Ed25519Signer, Envelope, Error, Verifier};

const TYPE: &str = "application/vnd.in-toto+json";

fn signer(seed: u8, id: &str) -> Ed25519Signer {
    Ed25519Signer::from_bytes(&[seed; 32])
        .unwrap()
        .with_key_id(id)
}

/// `~` stands for a backslash, so `~u0070` reaches the parser as a JSON escape.
fn escaped(doc: &str) -> String {
    doc.replace('~', "\\")
}

/// A signed envelope as JSON members, so a test can repeat or respell one.
fn genuine() -> (Ed25519Signer, Envelope) {
    let pinned = signer(1, "pinned");
    let env = sign(TYPE, br#"{"amount":10}"#, &pinned).unwrap();
    (pinned, env)
}

/// A whole envelope re-signed under a key made a moment earlier verifies only
/// under that key. Against the pinned key it is refused, and a `keyid` naming
/// the pinned key does not change that.
#[test]
fn a_record_signed_by_a_fresh_key_is_refused_against_the_pinned_one() {
    let (pinned, _) = genuine();
    let forger = signer(9, "pinned");
    let forged = sign(TYPE, br#"{"amount":10}"#, &forger).unwrap();
    assert_eq!(forged.signatures[0].keyid.as_deref(), Some("pinned"));
    let pinned_verifier = pinned.verifier();
    let err = verify(&forged, &[&pinned_verifier as &dyn Verifier], 1).unwrap_err();
    assert!(matches!(err, Error::NoValidSignature { .. }), "{err:?}");
}

/// A record relabelled outside the signed bytes: the payload type is inside
/// the pre-image, so changing it, even by case, breaks the signature.
#[test]
fn a_relabelled_payload_type_is_refused() {
    let (pinned, env) = genuine();
    let v = pinned.verifier();
    for other in [
        "application/vnd.in-toto+JSON",
        "application/vnd.in-toto+json ",
        "application/vnd.example+json",
    ] {
        let mut relabelled = env.clone();
        relabelled.payload_type = other.to_owned();
        let err = verify(&relabelled, &[&v as &dyn Verifier], 1).unwrap_err();
        assert!(
            matches!(err, Error::NoValidSignature { .. }),
            "{other}: {err:?}"
        );
    }
}

/// A payload swapped for one carrying a member the signer never wrote is
/// refused, so nothing unsigned reaches the caller through the payload.
#[test]
fn a_payload_with_an_added_member_is_refused() {
    let (pinned, mut env) = genuine();
    env.payload = STANDARD.encode(br#"{"amount":10,"policy":"allow-all"}"#);
    let v = pinned.verifier();
    let err = verify(&env, &[&v as &dyn Verifier], 1).unwrap_err();
    assert!(matches!(err, Error::NoValidSignature { .. }), "{err:?}");
}

/// Unknown envelope members are ignored on the way in, as the specification
/// requires, and never reach the caller: the verified result carries only the
/// signed payload type and the signed bytes.
#[test]
fn an_unsigned_envelope_member_never_reaches_the_caller() {
    let (pinned, env) = genuine();
    let sig = &env.signatures[0].sig;
    let json = format!(
        r#"{{"payload":"{}","payloadType":"{TYPE}","signatures":[{{"keyid":"pinned","sig":"{sig}"}}],"policy":"allow-all","payloadType2":"text/plain"}}"#,
        env.payload
    );
    let parsed = Envelope::from_json(json.as_bytes()).unwrap();
    let v = pinned.verifier();
    let out = verify(&parsed, &[&v as &dyn Verifier], 1).unwrap();
    assert_eq!(out.payload, br#"{"amount":10}"#);
    assert_eq!(out.payload_type, TYPE);
}

/// A member named twice, in the envelope or in a signature entry, in plain or
/// escaped spelling: the envelope does not parse.
#[test]
fn an_envelope_member_named_twice_does_not_parse() {
    let (_, env) = genuine();
    let p = &env.payload;
    let sig = &env.signatures[0].sig;
    let other = STANDARD.encode(br#"{"amount":999999}"#);
    let docs = [
        format!(
            r#"{{"payload":"{p}","payload":"{other}","payloadType":"{TYPE}","signatures":[{{"sig":"{sig}"}}]}}"#
        ),
        format!(
            r#"{{"payload":"{p}","payloadType":"{TYPE}","payloadType":"text/plain","signatures":[{{"sig":"{sig}"}}]}}"#
        ),
        format!(
            r#"{{"payload":"{p}","payloadType":"{TYPE}","signatures":[{{"sig":"{sig}"}}],"signatures":[]}}"#
        ),
        format!(
            r#"{{"payload":"{p}","payloadType":"{TYPE}","signatures":[{{"sig":"{sig}","sig":"AAAA"}}]}}"#
        ),
        format!(
            r#"{{"payload":"{p}","payloadType":"{TYPE}","signatures":[{{"keyid":"a","keyid":"b","sig":"{sig}"}}]}}"#
        ),
        escaped(&format!(
            r#"{{"payload":"{p}","~u0070ayload":"{other}","payloadType":"{TYPE}","signatures":[{{"sig":"{sig}"}}]}}"#
        )),
    ];
    // Control: the same envelope with each member once parses, so a refusal
    // below is the repeat and not a typo in the fixture.
    let once = escaped(&format!(
        r#"{{"~u0070ayload":"{p}","payloadType":"{TYPE}","signatures":[{{"keyid":"a","sig":"{sig}"}}]}}"#
    ));
    assert_eq!(Envelope::from_json(once.as_bytes()).unwrap().payload, *p);
    let mut parsed = Vec::new();
    for doc in &docs {
        if let Ok(env) = Envelope::from_json(doc.as_bytes()) {
            parsed.push(format!("{doc}\n  read as payload {}", env.payload));
        }
    }
    assert!(parsed.is_empty(), "parsed: {parsed:#?}");
}

/// A lone surrogate or a non-string where the envelope needs a string does not
/// parse; nothing is substituted for it.
#[test]
fn a_malformed_envelope_string_does_not_parse() {
    let (_, env) = genuine();
    let p = &env.payload;
    let sig = &env.signatures[0].sig;
    for doc in [
        escaped(&format!(
            r#"{{"payload":"{p}","payloadType":"~ud800","signatures":[{{"sig":"{sig}"}}]}}"#
        )),
        format!(r#"{{"payload":"{p}","payloadType":7,"signatures":[{{"sig":"{sig}"}}]}}"#),
        format!(r#"{{"payload":null,"payloadType":"{TYPE}","signatures":[{{"sig":"{sig}"}}]}}"#),
        format!(r#"{{"payload":"{p}","payloadType":"{TYPE}","signatures":{{"sig":"{sig}"}}}}"#),
    ] {
        assert!(Envelope::from_json(doc.as_bytes()).is_err(), "{doc}");
    }
}

/// One signature copied into many entries is one key, and does not meet a
/// threshold of two.
#[test]
fn a_copied_signature_does_not_meet_a_threshold_of_two() {
    let (pinned, mut env) = genuine();
    let second = signer(2, "second");
    let copy = env.signatures[0].clone();
    env.signatures = vec![copy.clone(), copy.clone(), copy];
    let (a, b) = (pinned.verifier(), second.verifier());
    let err = verify(&env, &[&a as &dyn Verifier, &b as &dyn Verifier], 2).unwrap_err();
    assert!(
        matches!(
            err,
            Error::ThresholdNotMet {
                accepted: 1,
                threshold: 2
            }
        ),
        "{err:?}"
    );
}
