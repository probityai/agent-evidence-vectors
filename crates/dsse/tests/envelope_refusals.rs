//! INVENTED CASES. Each one is an envelope this crate must refuse, constructed
//! to exercise a decode the specification's own reference implementation
//! accepts.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use dsse::{Envelope, Error};

fn parse(json: &str) -> Result<Envelope, Error> {
    Envelope::from_json(json.as_bytes())
}

/// The envelope schema requires at least one signature. An empty list can never
/// meet any threshold, so accepting it and failing later leaves a verifier that
/// reports a threshold failure for what is a malformed envelope.
#[test]
fn envelope_with_no_signatures_is_refused() {
    let env = parse(r#"{"payload":"eA==","payloadType":"t","signatures":[]}"#).unwrap();
    let err = dsse::verify(&env, &[], 1).unwrap_err();
    assert_eq!(err, Error::NoSignatures, "got {err:?}");
}

/// Base64 with non-zero trailing bits. `eB==` and `eA==` both decode to the
/// single byte `x` under a lenient decoder: the last symbol's discarded bits are
/// not zero. Accepting both means two distinct envelopes carry one signature,
/// so anything that content-addresses the envelope can be made to disagree with
/// anything that verifies it.
#[test]
fn payload_with_non_zero_trailing_bits_is_refused() {
    let env =
        parse(r#"{"payload":"eB==","payloadType":"t","signatures":[{"sig":"AAAA"}]}"#).unwrap();
    let err = dsse::verify(&env, &[], 1).unwrap_err();
    assert_eq!(
        err,
        Error::NonCanonicalBase64 { field: "payload" },
        "got {err:?}"
    );
}

/// The same malleability in a signature member.
#[test]
fn signature_with_non_zero_trailing_bits_is_refused() {
    let env =
        parse(r#"{"payload":"eA==","payloadType":"t","signatures":[{"sig":"eB=="}]}"#).unwrap();
    let err = dsse::verify(&env, &[], 1).unwrap_err();
    assert_eq!(
        err,
        Error::NonCanonicalBase64 {
            field: "signatures[].sig"
        },
        "got {err:?}"
    );
}

/// Unpadded base64. RFC 4648 Base64 is padded, so an unpadded string is not the
/// output of applying it to any byte sequence; accepting it is the same
/// malleability as the trailing-bits case.
#[test]
fn unpadded_payload_is_refused() {
    let env = parse(r#"{"payload":"eA","payloadType":"t","signatures":[{"sig":"AAAA"}]}"#).unwrap();
    let err = dsse::verify(&env, &[], 1).unwrap_err();
    assert_eq!(err, Error::NonCanonicalBase64 { field: "payload" });
}

/// A string mixing the two alphabets is in neither. `-` belongs to URL-safe and
/// `+` to standard, so a decoder that fell back from one alphabet to the other
/// per character would accept a string no producer emits.
#[test]
fn payload_mixing_both_alphabets_is_refused() {
    let env =
        parse(r#"{"payload":"a-b+cd==","payloadType":"t","signatures":[{"sig":"AAAA"}]}"#).unwrap();
    let err = dsse::verify(&env, &[], 1).unwrap_err();
    assert_eq!(err, Error::NonCanonicalBase64 { field: "payload" });
}

/// Both alphabets must be accepted on their own, because the protocol says a
/// verifier MUST accept either. This is the control for the three refusals
/// above: it proves they fail on canonicality rather than on the alphabet.
#[test]
fn both_alphabets_are_accepted_when_canonical() {
    // The byte 0xFB encodes as `+w==` in standard and `-w==` in URL-safe.
    for (label, encoded) in [("standard", "+w=="), ("url-safe", "-w==")] {
        let json = format!(
            r#"{{"payload":"{encoded}","payloadType":"t","signatures":[{{"sig":"AAAA"}}]}}"#
        );
        let env = parse(&json).unwrap();
        let err = dsse::verify(&env, &[], 1).unwrap_err();
        assert_eq!(
            err,
            Error::ThresholdNotMet {
                accepted: 0,
                threshold: 1
            },
            "{label} alphabet must decode, then fail only on the threshold; got {err:?}"
        );
    }
}

/// A threshold of zero would accept an envelope no trusted key signed.
#[test]
fn zero_threshold_is_refused() {
    let env =
        parse(r#"{"payload":"eA==","payloadType":"t","signatures":[{"sig":"AAAA"}]}"#).unwrap();
    let err = dsse::verify(&env, &[], 0).unwrap_err();
    assert_eq!(err, Error::ZeroThreshold, "got {err:?}");
}

/// A missing required member is a malformed envelope, not an empty one.
#[test]
fn missing_required_members_are_refused() {
    for json in [
        r#"{"payloadType":"t","signatures":[{"sig":"AAAA"}]}"#,
        r#"{"payload":"eA==","signatures":[{"sig":"AAAA"}]}"#,
        r#"{"payload":"eA==","payloadType":"t"}"#,
        r#"{"payload":"eA==","payloadType":"t","signatures":[{"keyid":"k"}]}"#,
    ] {
        let err = parse(json).unwrap_err();
        assert!(
            matches!(err, Error::MalformedEnvelope(_)),
            "{json} should be malformed, got {err:?}"
        );
    }
}

/// An empty payload is legal: the schema requires the member to be set, not to
/// be non-empty. This is the control that the refusals above are about
/// canonicality rather than emptiness.
#[test]
fn empty_payload_is_legal() {
    let env = parse(r#"{"payload":"","payloadType":"t","signatures":[{"sig":"AAAA"}]}"#).unwrap();
    let err = dsse::verify(&env, &[], 1).unwrap_err();
    assert_eq!(
        err,
        Error::ThresholdNotMet {
            accepted: 0,
            threshold: 1
        },
        "an empty payload must decode cleanly; got {err:?}"
    );
}
