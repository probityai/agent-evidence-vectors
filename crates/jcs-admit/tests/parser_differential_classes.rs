//! What this crate does with each parser-differential class.
//!
//! A parser differential is one byte string that two decoders read as two
//! different documents. The classes below are the ones a signed record most
//! often meets: member names that collide only under case folding (including
//! U+0130 and U+0131 against ASCII `I` and `i`), repeated members below the top
//! level, integers outside the I-JSON range, one integer spelled several ways,
//! a token with no finite double, a very long token, and negative zero.
//!
//! Each test pins this crate's disposition, so a project using it as the oracle
//! in a differential test knows which side of each class it lands on. Where RFC
//! 8785 as written admits a class (case-variant names are distinct members, a
//! respelled integer has one canonical form), the test says so; the profile or
//! byte comparison that closes it is named beside it. The cases are this crate's
//! own.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use jcs_admit::{admit, admit_ijson, is_canonical, Error};

fn canonical(raw: &[u8]) -> String {
    String::from_utf8(admit(raw).expect("RFC 8785 as written admits it")).unwrap()
}

/// RFC 8785 compares member names by UTF-16 code unit with no case folding, so
/// `I`, `i`, U+0130 and U+0131 are four distinct members, sorted by code unit.
/// A decoder that matches names case-insensitively reads them as one field;
/// this crate does not, and the bytes it emits keep all four.
#[test]
fn names_that_collide_only_under_case_folding_are_distinct_members() {
    let doc = format!(
        "{{\"i\":1,\"I\":2,\"{}\":3,\"{}\":4}}",
        char::from_u32(0x130).unwrap(),
        char::from_u32(0x131).unwrap()
    );
    let want = format!(
        "{{\"I\":2,\"i\":1,\"{}\":3,\"{}\":4}}",
        char::from_u32(0x130).unwrap(),
        char::from_u32(0x131).unwrap()
    );
    assert_eq!(canonical(doc.as_bytes()), want);
    assert_eq!(admit_ijson(doc.as_bytes()).unwrap(), want.as_bytes());
}

/// A lone case variant of a signed field is a different member, not the field.
#[test]
fn a_case_variant_member_is_a_different_member() {
    assert_eq!(
        canonical(br#"{"revoked":false,"Revoked":true}"#),
        r#"{"Revoked":true,"revoked":false}"#
    );
}

/// A repeat is refused at any depth, under both profiles, with its own name,
/// including a repeat written with an escape.
#[test]
fn a_repeat_below_the_top_level_is_refused_under_both_profiles() {
    let cases: [(&[u8], &str); 3] = [
        (br#"{"a":{"x":1,"x":2}}"#, "x"),
        (
            br#"{"a":{"b":{"c":{"role":"user","role":"admin"}}}}"#,
            "role",
        ),
        (br#"{"a":[{"role":"user","role":"admin"}]}"#, "role"),
    ];
    for (raw, member) in cases {
        for (profile, result) in [("rfc8785", admit(raw)), ("ijson", admit_ijson(raw))] {
            match result {
                Err(Error::DuplicateMember { name, .. }) => assert_eq!(name, member),
                other => panic!(
                    "{profile}: want DuplicateMember {member}, got {other:?} for {}",
                    String::from_utf8_lossy(raw)
                ),
            }
        }
    }
}

/// RFC 8785 as written rewrites an integer past 2^53 to its nearest double;
/// the I-JSON profile refuses it.
#[test]
fn an_integer_outside_the_ijson_range_is_rewritten_or_refused_by_profile() {
    for (token, nearest) in [
        ("9007199254740993", "9007199254740992"),
        ("-9007199254740993", "-9007199254740992"),
    ] {
        assert_eq!(canonical(token.as_bytes()), nearest);
        assert!(
            matches!(
                admit_ijson(token.as_bytes()),
                Err(Error::UnsafeInteger { .. })
            ),
            "{token}"
        );
    }
}

/// One integer has one canonical spelling. Every other spelling admits to it
/// and is not itself canonical, so a verifier that compares the bytes it
/// received with their canonical form catches the respelling.
#[test]
fn a_respelled_integer_has_one_canonical_form() {
    for spelling in ["1000.0", "1e3", "1E3", "1000e0", "10e2", "1.000e3"] {
        assert_eq!(canonical(spelling.as_bytes()), "1000", "{spelling}");
        assert!(!is_canonical(spelling.as_bytes()), "{spelling}");
    }
    assert!(is_canonical(b"1000"));
}

/// `1e400` has no finite double. RFC 8785 has no serialization for it; the
/// I-JSON profile reports the integer bound it crosses first.
#[test]
fn a_token_with_no_finite_double_is_refused() {
    assert!(matches!(
        admit(b"1e400"),
        Err(Error::NonFiniteNumber { .. })
    ));
    assert!(matches!(
        admit_ijson(b"1e400"),
        Err(Error::UnsafeInteger { .. })
    ));
}

/// A 1,000-digit integer is past every double; a 1,000-digit fraction rounds to
/// zero, which RFC 8785 admits as `0` and the I-JSON profile refuses as inexact
/// (its double does not hold the token). Bounding a token's length is a
/// separate rule, not one RFC 8785 or RFC 7493 states.
#[test]
fn a_thousand_digit_token_is_refused_or_rounded_by_value() {
    let integer = format!("1{}", "0".repeat(999));
    assert_eq!(integer.len(), 1000);
    assert!(matches!(
        admit(integer.as_bytes()),
        Err(Error::NonFiniteNumber { .. })
    ));
    assert!(matches!(
        admit_ijson(integer.as_bytes()),
        Err(Error::UnsafeInteger { .. })
    ));

    let fraction = format!("0.{}1", "0".repeat(997));
    assert_eq!(fraction.len(), 1000);
    assert_eq!(canonical(fraction.as_bytes()), "0");
    assert!(matches!(
        admit_ijson(fraction.as_bytes()),
        Err(Error::InexactNumber { .. })
    ));
}

/// Negative zero serializes as `0` (ECMAScript `Number::toString`), so a record
/// signed as `-0` and one signed as `0` canonicalize to the same bytes, and
/// `-0` as received is not canonical.
#[test]
fn negative_zero_canonicalizes_to_zero() {
    for spelling in ["-0", "-0.0", "-0e0", "0.0"] {
        assert_eq!(canonical(spelling.as_bytes()), "0", "{spelling}");
        assert!(!is_canonical(spelling.as_bytes()), "{spelling}");
    }
}
