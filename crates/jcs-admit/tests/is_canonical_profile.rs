//! ATTACK: a gate that answers a different question than the verifier asks.
//!
//! `is_canonical` answered for RFC 8785 as written, with no way to ask under a
//! profile. Measured before the fix: a document carrying U+FFFF canonicalizes
//! under the default profile, `is_canonical` on those bytes returns `true`, and
//! `canonicalize_ijson` on the SAME bytes returns
//! `StringNotScalar: Unicode noncharacter in string`. A verifier that admits a
//! document with the gate and then verifies it under the profile has admitted
//! bytes its own profile refuses -- one document, two answers, from one crate.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use jcs_admit::{admit, admit_ijson, is_canonical, is_canonical_with, Options};

fn noncharacter_document() -> Vec<u8> {
    // Built from the code point, never typed.
    let doc = format!("{{\"k\":\"\\u{:04x}\"}}", 0xFFFF_u32);
    admit(doc.as_bytes()).expect("RFC 8785 as written accepts it")
}

#[test]
fn the_gate_can_be_asked_under_the_profile_the_caller_verifies_with() {
    let bytes = noncharacter_document();
    assert!(
        admit_ijson(&bytes).is_err(),
        "the profile must refuse these bytes, or this test proves nothing"
    );
    assert!(
        !is_canonical_with(&bytes, &Options::ijson()),
        "the gate must not admit what the profile refuses"
    );
    // And the plain gate still answers for RFC 8785 as written, which is a
    // different and still-correct answer, not a bug being preserved.
    assert!(is_canonical(&bytes), "RFC 8785 as written has no such rule");
}

#[test]
fn the_gate_still_agrees_with_canonicalization_on_ordinary_documents() {
    for doc in [
        &b"{}"[..],
        b"[]",
        br#"{"a":1,"b":[1,2]}"#,
        br#""ab""#,
        b"1e+30",
    ] {
        let canonical = admit(doc).expect("valid");
        assert!(is_canonical(&canonical));
        assert!(
            is_canonical_with(&canonical, &Options::ijson()) == admit_ijson(&canonical).is_ok()
        );
        if *doc != canonical {
            assert!(!is_canonical(doc), "non-canonical input must not pass");
        }
    }
}
