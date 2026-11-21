//! The JSON-layer shapes the November 2026 teardowns built against other
//! projects' verifiers, run against this crate.
//!
//! Each of those verifiers accepted a record it should have refused, and the
//! JSON-layer part of each acceptance is a token or a member a canonicalizer
//! sees before any signature is checked: a `NaN` amount that compares as inside
//! a cap, a member named twice that one reader resolves to its first value and
//! another to its last, a member name that only an escape distinguishes, a
//! `__proto__` member a JavaScript reader drops from the signed bytes, a lone
//! surrogate, and a number with more precision than any double holds. A shape
//! that is a relying-party decision (who signed, which audience, whether a
//! retraction was shown) is not a JSON fault and is held by the `dsse` crate's
//! own copy of this file, or by the verifier above both.
//!
//! The RFC 7493 section 2.2 rows are the profile's own named examples: "for
//! example, 1E400 or 3.141592653589793238462643383279". An entry point that
//! calls itself the I-JSON profile admits neither.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use jcs_admit::{admit, admit_ijson, is_canonical, Error};

/// `~` stands for a backslash, so an escape such as `~u0079` reaches the parser
/// as the six bytes of a JSON escape rather than as the letter it names.
fn escaped(doc: &str) -> String {
    doc.replace('~', "\\")
}

fn refused_by_both(doc: &str) -> (Error, Error) {
    let a = admit(doc.as_bytes()).expect_err(doc);
    let b = admit_ijson(doc.as_bytes()).expect_err(doc);
    (a, b)
}

/// A non-finite amount compares as inside every cap (`NaN > 1000` is false), so
/// a reader that admits the token lets the record through a limit check.
#[test]
fn a_non_finite_amount_has_no_canonical_form() {
    for doc in [
        r#"{"amount":NaN}"#,
        r#"{"amount":Infinity}"#,
        r#"{"amount":-Infinity}"#,
        r#"{"amount":nan}"#,
    ] {
        let (a, b) = refused_by_both(doc);
        assert!(matches!(a, Error::Syntax { .. }), "{doc}: {a:?}");
        assert!(matches!(b, Error::Syntax { .. }), "{doc}: {b:?}");
    }
    for doc in [r#"{"amount":1e999}"#, r#"{"amount":-1E400}"#] {
        let (a, b) = refused_by_both(doc);
        assert!(matches!(a, Error::NonFiniteNumber { .. }), "{doc}: {a:?}");
        assert!(
            matches!(
                b,
                Error::NonFiniteNumber { .. } | Error::UnsafeInteger { .. }
            ),
            "{doc}: {b:?}"
        );
    }
}

/// A nonce carrying a raw line break poisons a line-oriented replay ledger.
#[test]
fn a_raw_control_character_in_a_string_is_refused() {
    for doc in [
        "{\"nonce\":\"n-1\nn-2\"}",
        "{\"nonce\":\"a\u{0}b\"}",
        "{\"nonce\":\"\tx\"}",
    ] {
        let (a, b) = refused_by_both(doc);
        assert!(matches!(a, Error::StringNotScalar { .. }), "{doc:?}: {a:?}");
        assert!(matches!(b, Error::StringNotScalar { .. }), "{doc:?}: {b:?}");
    }
    // The escaped spelling is a real string, admitted, and written escaped.
    assert_eq!(
        admit(br#"{"nonce":"n-1\nn-2"}"#).unwrap(),
        br#"{"nonce":"n-1\nn-2"}"#
    );
}

/// The same member named twice, at the top and nested, in plain and escaped
/// spellings: one reader keeps the first value, another the last, and a
/// signature over either reading verifies.
#[test]
fn a_member_named_twice_is_refused_in_every_spelling() {
    for doc in [
        r#"{"payer":"A","transaction":"t1","payer":"B"}"#,
        r#"{"payer":"A","pa~u0079er":"B"}"#,
        r#"{"payer":"A","~u0070~u0061~u0079~u0065~u0072":"B"}"#,
        r#"{"receipt":{"transaction":"t1","transaction":"t2"}}"#,
        r#"[{"a":1},{"b":{"c":[{"d":1,"d":1}]}}]"#,
        r#"{"__proto__":{"policy":"deny"},"__proto__":{"policy":"allow"}}"#,
    ] {
        let doc = &escaped(doc);
        let (a, b) = refused_by_both(doc);
        assert!(matches!(a, Error::DuplicateMember { .. }), "{doc}: {a:?}");
        assert!(matches!(b, Error::DuplicateMember { .. }), "{doc}: {b:?}");
    }
}

/// A `__proto__` member is an ordinary member here: it is kept in the signed
/// bytes, never dropped, so two cards that differ only there canonicalize to
/// different bytes.
#[test]
fn a_proto_member_stays_in_the_canonical_bytes() {
    let with = admit(br#"{"name":"x","__proto__":{"policy":"allow-all"}}"#).unwrap();
    let without = admit(br#"{"name":"x"}"#).unwrap();
    assert_eq!(with, br#"{"__proto__":{"policy":"allow-all"},"name":"x"}"#);
    assert_ne!(with, without);
}

/// An unpaired surrogate, escaped or raw, has no canonical form: a decoder that
/// substitutes U+FFFD would make two different cards one byte string.
#[test]
fn a_lone_surrogate_is_refused() {
    let escapes = [
        r#"{"name":"~ud800"}"#,
        r#"{"name":"~udc00x"}"#,
        r#"{"name":"~ud800~u0041"}"#,
    ];
    let mut docs: Vec<Vec<u8>> = escapes.iter().map(|d| escaped(d).into_bytes()).collect();
    // A high surrogate written directly in UTF-8 (ED A0 80), which no &str holds.
    docs.push(b"{\"name\":\"\xed\xa0\x80\"}".to_vec());
    for doc in &docs {
        assert!(
            matches!(admit(doc), Err(Error::StringNotScalar { .. })),
            "{}",
            String::from_utf8_lossy(doc)
        );
    }
}

/// RFC 7493 section 2.2 names 1E400 and 3.141592653589793238462643383279 as
/// numbers an I-JSON message does not carry. The I-JSON profile refuses every
/// number token whose value is not the value of the double it reads as, so the
/// bytes a signer canonicalizes and the number an exact reader reads are one
/// value. These are also the cases probityai/probity's `jcs_canonical/v1`
/// refuses (tests/test_jcs_number_precision.py).
#[test]
fn the_ijson_profile_refuses_a_number_no_double_holds() {
    let mut admitted = Vec::new();
    for token in [
        "3.141592653589793238462643383279",
        "1e-400",
        "-1e-400",
        "9007199254740993",
        "-9007199254740993",
        "12345678901234567890",
        "9007199254740993.0",
        "9007199254740991.4",
        "333333333.33333329",
        "0.1000000000000000000000001",
        "1E400",
    ] {
        let doc = format!(r#"{{"n":{token}}}"#);
        if let Ok(out) = admit_ijson(doc.as_bytes()) {
            admitted.push(format!("{token} as {}", String::from_utf8_lossy(&out)));
        }
    }
    assert!(admitted.is_empty(), "admit_ijson admitted: {admitted:#?}");
}

/// A token whose value is its double's value keeps its form under the profile.
#[test]
fn the_ijson_profile_admits_a_number_its_double_holds() {
    for (token, canonical) in [
        ("9007199254740991", "9007199254740991"),
        ("0.1", "0.1"),
        ("1.10", "1.1"),
        ("-0.0", "0"),
        ("0.30000000000000004", "0.30000000000000004"),
        ("1e-7", "1e-7"),
        ("2.5e-3", "0.0025"),
        ("5e-324", "5e-324"),
        ("4.50", "4.5"),
    ] {
        let doc = format!(r#"{{"n":{token}}}"#);
        assert_eq!(
            admit_ijson(doc.as_bytes()).unwrap(),
            format!(r#"{{"n":{canonical}}}"#).into_bytes(),
            "{token}"
        );
    }
}

/// RFC 8785 as written keeps its reference behaviour: its own sample input
/// carries 333333333.33333329 and 1E30, and writes them rounded.
#[test]
fn rfc8785_as_written_still_rounds_its_own_sample() {
    assert_eq!(
        admit(br#"[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001]"#).unwrap(),
        br#"[333333333.3333333,1e+30,4.5,0.002,1e-27]"#
    );
}

/// Bytes that were not stored canonically are not called canonical, so a
/// verifier hashing what it received is told the two differ.
#[test]
fn reordered_or_spaced_bytes_are_not_canonical() {
    assert!(is_canonical(br#"{"a":1,"b":2}"#));
    assert!(!is_canonical(br#"{"b":2,"a":1}"#));
    assert!(!is_canonical(br#"{"a":1, "b":2}"#));
    assert!(!is_canonical(br#"{"a":1.0}"#));
    assert!(!is_canonical(escaped(r#"{"a":"~u0041"}"#).as_bytes()));
}
