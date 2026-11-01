//! PINNED VECTORS. All 11 cases are loaded from
//! `vectors/cross_lang_signing.json`, which `vectors/generate` writes with the
//! DSSE reference Go implementation (`github.com/secure-systems-lab/go-securesystemslib/dsse`,
//! at the version recorded in the file's `generated_by` member). Each case
//! carries a payload type, the PAE bytes that implementation produced, a real
//! ed25519 signature over them, and the whole envelope it emitted, so the two
//! implementations agree byte for byte or a case fails. Nothing here is written
//! by this crate.
//!
//! `canonical_b64` is the signed body. `envelope` is the reference
//! implementation's envelope over that body, parsed here through this crate's
//! own [`Envelope`] type.

#![cfg(feature = "ed25519")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use dsse::{pae, Ed25519Signer, Ed25519Verifier, Envelope, Signature, Verifier};

const VECTORS: &str = include_str!("../vectors/cross_lang_signing.json");

fn b64(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

/// The 32 raw bytes of the fixture's ed25519 public key, taken from the tail of
/// its SPKI DER. The 12-byte prefix `302a300506032b6570032100` is the fixed
/// ed25519 SubjectPublicKeyInfo header.
fn fixture_key(v: &serde_json::Value) -> Ed25519Verifier {
    let pem = v["public_key_pem"].as_str().unwrap();
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = b64(&body);
    assert_eq!(der.len(), 44, "SPKI DER for ed25519 is 44 bytes");
    assert_eq!(
        der[..12],
        [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]
    );
    let raw = &der[12..];
    let key_id = v["key_id"].as_str().unwrap().to_string();
    Ed25519Verifier::from_bytes(raw)
        .unwrap()
        .with_key_id(key_id)
}

fn vectors() -> serde_json::Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn fixture<'a>(v: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    v["fixtures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["name"] == name)
        .unwrap_or_else(|| panic!("fixture {name} must be present"))
}

/// Our PAE must reproduce, byte for byte, the pre-image the Go implementation
/// signed. Eleven cases across five payload types, including one whose payload
/// is raw binary, one with an empty body, and one whose payload type is longer
/// in bytes than in characters.
#[test]
fn pae_matches_the_go_implementation_byte_for_byte() {
    let v = vectors();
    let fixtures = v["fixtures"].as_array().unwrap();
    assert_eq!(fixtures.len(), 11, "the fixture file carries 11 cases");

    let mut types = std::collections::BTreeSet::new();
    for f in fixtures {
        let name = f["name"].as_str().unwrap();
        let payload_type = f["payload_type"].as_str().unwrap();
        let want_pae = b64(f["pae_b64"].as_str().unwrap());
        let payload = b64(f["canonical_b64"].as_str().unwrap());
        types.insert(payload_type.to_string());

        let got = pae(payload_type, &payload);
        assert_eq!(
            got,
            want_pae,
            "PAE mismatch for {name}\n got {:?}\nwant {:?}",
            String::from_utf8_lossy(&got),
            String::from_utf8_lossy(&want_pae)
        );
    }
    assert_eq!(types.len(), 5, "five distinct payload types");
}

/// Every fixture signature must verify against the PAE we reconstruct. This is
/// the byte-identity claim with the cryptography attached: if our PAE differed
/// from theirs by one byte, no signature would verify.
#[test]
fn every_fixture_signature_verifies_against_our_reconstruction() {
    let v = vectors();
    let key = fixture_key(&v);
    let mut checked = 0usize;

    for f in v["fixtures"].as_array().unwrap() {
        let name = f["name"].as_str().unwrap();
        let payload_type = f["payload_type"].as_str().unwrap();
        let payload = b64(f["canonical_b64"].as_str().unwrap());
        let sig = b64(f["signature_b64"].as_str().unwrap());
        assert_eq!(sig.len(), 64, "{name}: ed25519 signatures are 64 bytes");

        let pre_image = pae(payload_type, &payload);
        assert!(
            key.verify(&pre_image, &sig),
            "{name}: fixture signature did not verify against our PAE"
        );
        checked += 1;
    }
    assert_eq!(checked, 11);
}

/// Every envelope the reference implementation emitted must parse through our
/// `Envelope` type and verify end to end through the public API.
#[test]
fn every_reference_envelope_verifies_through_the_public_api() {
    let v = vectors();
    let key = fixture_key(&v);

    for f in v["fixtures"].as_array().unwrap() {
        let name = f["name"].as_str().unwrap();
        let json = serde_json::to_vec(&f["envelope"]).unwrap();
        let env = Envelope::from_json(&json).unwrap();
        assert_eq!(env.payload, f["canonical_b64"].as_str().unwrap(), "{name}");
        assert_eq!(
            env.payload_type,
            f["payload_type"].as_str().unwrap(),
            "{name}"
        );

        let verified = dsse::verify(&env, &[&key], 1).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(verified.payload, b64(f["canonical_b64"].as_str().unwrap()));
        assert_eq!(verified.accepted_keys.len(), 1);
    }
}

/// Signing with the published test seed must reproduce the reference
/// implementation's signature bytes. ed25519 is deterministic, so this checks
/// our signing path, not only our verification path.
#[test]
fn our_signer_reproduces_the_reference_signatures() {
    let v = vectors();
    let seed = hex(v["test_seed_hex"].as_str().unwrap());
    let signer = Ed25519Signer::from_bytes(&seed)
        .unwrap()
        .with_key_id(v["key_id"].as_str().unwrap());

    for f in v["fixtures"].as_array().unwrap() {
        let name = f["name"].as_str().unwrap();
        let payload = b64(f["canonical_b64"].as_str().unwrap());
        let env = dsse::sign(f["payload_type"].as_str().unwrap(), &payload, &signer).unwrap();
        assert_eq!(
            env.signatures[0].sig,
            f["signature_b64"].as_str().unwrap(),
            "{name}: our signature differs from the reference implementation's"
        );
        assert_eq!(env.payload, f["canonical_b64"].as_str().unwrap(), "{name}");
    }
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// One fixture's payload is raw binary: a big-endian u64 count followed by a
/// 32-byte root, so it contains NUL bytes and is not valid UTF-8. The payload
/// must survive base64 and PAE verbatim.
#[test]
fn binary_payload_survives_the_round_trip() {
    let v = vectors();
    let key = fixture_key(&v);
    let f = fixture(&v, "binary_batch_root");

    let payload = b64(f["canonical_b64"].as_str().unwrap());
    assert_eq!(payload.len(), 40, "u64 count plus a 32-byte root");
    assert!(
        payload.starts_with(&[0, 0, 0, 0, 0, 0, 0, 8]),
        "count is 8 BE"
    );
    assert!(
        String::from_utf8(payload.clone()).is_err(),
        "this payload is deliberately not valid UTF-8"
    );

    let payload_type = f["payload_type"].as_str().unwrap();
    let sig = b64(f["signature_b64"].as_str().unwrap());
    assert!(key.verify(&pae(payload_type, &payload), &sig));
}

/// The PAE length field counts bytes. A payload type whose UTF-8 encoding is
/// longer than its character count pins that: counting characters produces a
/// different pre-image, and the reference signature would not verify over it.
#[test]
fn payload_type_length_counts_bytes_not_characters() {
    let v = vectors();
    let f = fixture(&v, "unicode_payload_type");
    let payload_type = f["payload_type"].as_str().unwrap();
    assert!(payload_type.len() > payload_type.chars().count());

    let want = b64(f["pae_b64"].as_str().unwrap());
    let prefix = format!("DSSEv1 {} {} ", payload_type.len(), payload_type);
    assert!(want.starts_with(prefix.as_bytes()));
}

/// The empty body is legal and its length prefix is zero.
#[test]
fn empty_body_has_a_zero_length_prefix() {
    let v = vectors();
    let f = fixture(&v, "empty_body");
    let payload_type = f["payload_type"].as_str().unwrap();
    assert!(b64(f["canonical_b64"].as_str().unwrap()).is_empty());
    let want = format!("DSSEv1 {} {} 0 ", payload_type.len(), payload_type);
    assert_eq!(b64(f["pae_b64"].as_str().unwrap()), want.as_bytes());
}

/// A whole envelope built from fixture parts must verify end to end through the
/// public API, not only through `pae` directly.
#[test]
fn fixture_verifies_through_the_public_envelope_api() {
    let v = vectors();
    let key = fixture_key(&v);
    let f = &v["fixtures"].as_array().unwrap()[0];

    let env = Envelope {
        payload: f["canonical_b64"].as_str().unwrap().to_string(),
        payload_type: f["payload_type"].as_str().unwrap().to_string(),
        signatures: vec![Signature {
            keyid: Some(v["key_id"].as_str().unwrap().to_string()),
            sig: f["signature_b64"].as_str().unwrap().to_string(),
        }],
    };

    let verified = dsse::verify(&env, &[&key], 1).expect("fixture envelope must verify");
    assert_eq!(verified.payload, b64(f["canonical_b64"].as_str().unwrap()));
    assert_eq!(verified.payload_type, f["payload_type"].as_str().unwrap());
    assert_eq!(verified.accepted_keys.len(), 1);
}

/// A signature minted for one payload type must not verify under another. The
/// fixtures give several real types signed by the same key, so the cross-type
/// attempt uses genuine material rather than a constructed one.
#[test]
fn fixture_signature_does_not_verify_under_another_payload_type() {
    let v = vectors();
    let key = fixture_key(&v);

    let record = fixture(&v, "record_0");
    let other = fixture(&v, "statement_0");

    let payload = b64(record["canonical_b64"].as_str().unwrap());
    let sig = b64(record["signature_b64"].as_str().unwrap());
    let wrong_type = other["payload_type"].as_str().unwrap();
    assert_ne!(wrong_type, record["payload_type"].as_str().unwrap());

    assert!(
        key.verify(
            &pae(record["payload_type"].as_str().unwrap(), &payload),
            &sig
        ),
        "control: the signature verifies under its own type"
    );
    assert!(
        !key.verify(&pae(wrong_type, &payload), &sig),
        "a signature must not verify once the payload type is swapped"
    );
}
