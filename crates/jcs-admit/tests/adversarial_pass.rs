//! What an adversarial pass over this crate found, pinned so it cannot come back.
//!
//! One correction and three attacks that failed. The failures are here on
//! purpose: an attack nobody wrote down is a refusal nobody can show is
//! load-bearing, and the second time somebody asks "what about normalisation"
//! the answer should be a test rather than a memory.

// A failing assertion is this file's purpose, so the crate's deny on `expect`,
// `unwrap`, indexing and `panic` is relaxed here and nowhere else. Library code
// keeps all four.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use jcs_admit::{admit, admit_ijson, is_canonical, Error};

// --------------------------------------------------- the correction

#[test]
fn the_default_profile_rewrites_an_unsafe_integer_and_only_the_ijson_profile_refuses_it() {
    // The crate's front-page differential table said `Error::UnsafeInteger` in
    // its "this crate" column for `9007199254740993`, with no profile named, and
    // the test cited as keeping that row true called `admit_ijson`. `admit` --
    // the default, the one the doc example uses, the one the verifier calls --
    // hands back the same different integer the delegate does.
    //
    // Which is CORRECT. RFC 8785 section 3.2.2.3 defers to ECMAScript and
    // ECMAScript has one numeric type, so the default cannot refuse this without
    // failing the specification it implements. The defect was the claim, not the
    // behaviour, and this test is the claim's other half.
    assert_eq!(
        admit(b"9007199254740993").expect("admitted"),
        b"9007199254740992"
    );
    assert_eq!(
        admit(br#"{"n":9007199254740993}"#).expect("admitted"),
        br#"{"n":9007199254740992}"#
    );
    assert_eq!(
        admit(b"18446744073709551617").expect("admitted"),
        b"18446744073709552000"
    );
    assert!(matches!(
        admit_ijson(b"9007199254740993"),
        Err(Error::UnsafeInteger { .. })
    ));
    // `is_canonical` is the seam a verifier actually stands on, and it tells the
    // truth here without needing the profile: the bytes are not their own
    // canonical form, so a verifier hashing what it received and a producer
    // hashing what it canonicalized would disagree, and this says so.
    assert!(!is_canonical(b"9007199254740993"));
    assert!(is_canonical(b"9007199254740992"));
}

// --------------------------------------------------- attacks that failed

#[test]
fn two_member_names_that_are_one_grapheme_in_different_normal_forms_are_two_members() {
    // ATTACK: sneak a second member past the duplicate check by spelling one name
    // NFC and the other NFD, so they render identically to a human reviewing the
    // document and differ only in bytes.
    //
    // It is admitted, and that is right. RFC 8785 section 3.2.3 orders member
    // names by UTF-16 code unit and normalizes nothing, so U+00E9 and
    // U+0065 U+0301 are two distinct names and the document genuinely has two
    // members. Every conforming implementation reads it the same way, which is
    // the only property that matters here -- there is no split view, just a
    // document that looks confusing. Refusing would be this crate inventing a
    // rule the specification does not have, and two rails disagreeing about a
    // document is precisely what it exists to prevent.
    let nfc_and_nfd = "{\"\u{e9}\":1,\"e\u{301}\":2}";
    let canonical = admit(nfc_and_nfd.as_bytes()).expect("two distinct names");
    let text = String::from_utf8(canonical).expect("utf-8");
    assert!(text.contains("\u{e9}") && text.contains("e\u{301}"));
    assert_eq!(text.matches(':').count(), 2, "both members survive");

    // The compatibility pair and the singleton, same answer for the same reason.
    assert!(admit("{\"\u{fb01}\":1,\"fi\":2}".as_bytes()).is_ok());
    assert!(admit("{\"\u{212a}\":1,\"K\":2}".as_bytes()).is_ok());

    // And the spellings that ARE one name after decoding are still refused, which
    // is what keeps this test from reading as a hole.
    assert!(matches!(
        admit(br#"{"a":1,"\u0061":2}"#),
        Err(Error::DuplicateMember { .. })
    ));
    assert!(matches!(
        admit("{\"\\u00e9\":1,\"\u{e9}\":2}".as_bytes()),
        Err(Error::DuplicateMember { .. })
    ));
}

#[test]
fn the_depth_cap_charges_a_mixed_nest_exactly_as_it_charges_a_uniform_one() {
    // ATTACK: reach depth 129 through alternating arrays and objects, on the
    // chance the counter is charged per array or per parsed child rather than per
    // open container. It is charged per open container, so the mix costs the same.
    fn mixed(n: usize) -> Vec<u8> {
        let mut s = Vec::new();
        for i in 0..n {
            if i % 2 == 1 {
                s.extend_from_slice(br#"{"a":"#);
            } else {
                s.push(b'[');
            }
        }
        s.push(b'1');
        for i in (0..n).rev() {
            s.push(if i % 2 == 1 { b'}' } else { b']' });
        }
        s
    }
    assert!(
        admit(&mixed(128)).is_ok(),
        "128 mixed containers are admitted"
    );
    assert!(matches!(
        admit(&mixed(129)),
        Err(Error::TooDeep { limit: 128, .. })
    ));
    // Starting with the object rather than the array, in case the parity matters.
    let object_first = {
        let mut s = mixed(129);
        s.remove(0);
        s.pop();
        [br#"{"a":"#.to_vec(), s, b"}".to_vec()].concat()
    };
    assert!(matches!(
        admit(&object_first),
        Err(Error::TooDeep { limit: 128, .. })
    ));
}

#[test]
fn there_is_no_entry_point_that_takes_an_already_parsed_value() {
    // ATTACK: build the document as a `serde_json::Value` instead of parsing it,
    // so the byte-level refusals never run -- the shape that makes both incumbent
    // canonicalizers unable to see a duplicate member in the first place.
    //
    // There is no such entry point. `admit`, `admit_ijson`, `admit_with`,
    // `is_canonical` and `is_canonical_with` are the whole public surface and all
    // five take `&[u8]`. This test is the compile-time proof: it names every one
    // of them through a fn pointer of byte-taking type, so an entry point added
    // later that takes a value has to be added beside a test that says it is the
    // hole this crate exists to close.
    type ByBytes = fn(&[u8]) -> Result<Vec<u8>, Error>;
    type Gate = fn(&[u8]) -> bool;
    let by_bytes: [ByBytes; 2] = [admit, admit_ijson];
    let gates: [Gate; 1] = [is_canonical];
    for f in by_bytes {
        assert!(matches!(
            f(br#"{"a":1,"a":2}"#),
            Err(Error::DuplicateMember { .. })
        ));
    }
    for g in gates {
        assert!(!g(br#"{"a":1,"a":2}"#));
    }
    // The bytes that no `&str` can hold, which is the other half of the same
    // argument: a surrogate written directly in UTF-8 cannot be handed to an
    // entry point that takes text at all.
    let cesu8: Vec<u8> = vec![b'"', 0xED, 0xA0, 0x80, b'"'];
    assert!(
        core::str::from_utf8(&cesu8).is_err(),
        "these bytes are not text, so no &str entry point could take them"
    );
    assert!(matches!(admit(&cesu8), Err(Error::StringNotScalar { .. })));
}
