//! PROPERTY 3: the RFC 7493 I-JSON safe-integer profile.
//!
//! An integer at or above 2^53 has no exact IEEE-754 double, so two
//! implementations that both round it correctly still write different bytes for
//! the same wire integer. Under this profile it is refused rather than rounded.
//!
//! The whole table in `the_pinned_number_table` is copied from
//! `aee/jcs_number_test.go` (`TestSafeIntegerProfile`) in the Go implementation
//! this crate ports; see `tests/vectors/PROVENANCE.md`. The 1e21 row is the
//! regression that table exists for: a notation-blind range check only inspected
//! tokens with no 'e', so the integer 10^21 walked past the bound.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use jcs_admit::{admit, admit_ijson, Error, Options};

/// The token, whether the profile refuses it, and which refusal.
type Row = (&'static str, bool, &'static str);

/// Copied verbatim from `TestSafeIntegerProfile`, one row per case.
const PINNED: &[Row] = &[
    ("0", false, ""),
    ("100", false, ""),
    ("1e2", false, ""),              // exponent-notation SAFE integer
    ("100.0", false, ""),            // decimal-point SAFE integer
    ("9007199254740991", false, ""), // 2^53 - 1
    ("-9007199254740991", false, ""),
    ("9007199254740992", true, "unsafe"),     // 2^53
    ("9007199254740993", true, "unsafe"),     // 2^53 + 1, still fits i64
    ("99999999999999999999", true, "unsafe"), // beyond i64
    ("1e21", true, "unsafe"),                 // THE bypass: 10^21
    ("1E21", true, "unsafe"),
    ("1.0e21", true, "unsafe"),
    ("-1e21", true, "unsafe"),
    ("1.5", true, "non-integer"),
    ("-0.1", true, "non-integer"),
];

#[test]
fn the_pinned_number_table() {
    // The Go rail bundles integers-only into one profile; here it is a separate
    // switch, so the table is run with both turned on.
    let opts = Options::ijson().integers_only(true);
    let mut failures = Vec::new();
    for (token, want_refused, kind) in PINNED {
        let got = jcs_admit::admit_with(token.as_bytes(), &opts);
        match (&got, want_refused) {
            (Err(Error::UnsafeInteger { .. }), true) if *kind == "unsafe" => {}
            (Err(Error::NonIntegerNumber { .. }), true) if *kind == "non-integer" => {}
            (Ok(_), false) => {}
            _ => failures.push(format!(
                "{token}: want refused={want_refused} ({kind}), got {got:?}"
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} rows diverge:\n{}",
        failures.len(),
        PINNED.len(),
        failures.join("\n")
    );
}

/// Copied from the tail of `TestSafeIntegerProfile`: a safe integer written in
/// exponent form canonicalizes to plain form, so the profile refuses the unsafe
/// ones without also refusing the notation.
#[test]
fn a_safe_integer_in_exponent_form_canonicalizes_to_plain_form() {
    assert_eq!(admit_ijson(b"1e2").unwrap(), b"100");
    assert_eq!(admit_ijson(b"100.0").unwrap(), b"100");
}

/// The bound is exclusive at 2^53 and it is exact in both directions.
#[test]
fn the_boundary_is_exact() {
    assert!(admit_ijson(b"9007199254740991").is_ok());
    assert!(admit_ijson(b"-9007199254740991").is_ok());
    assert!(matches!(
        admit_ijson(b"9007199254740992"),
        Err(Error::UnsafeInteger { .. })
    ));
    // One digit fewer is safe whatever the digits are, one digit more is unsafe.
    assert!(admit_ijson(b"9999999999999999999999".get(..15).unwrap()).is_ok());
    assert!(matches!(
        admit_ijson(b"1000000000000000000"),
        Err(Error::UnsafeInteger { .. })
    ));
}

/// The profile is OPT-IN, and this is the load-bearing half of that decision:
/// the RFC 8785 reference suite contains 1e30 and 1e-27, so a crate whose
/// DEFAULT refused them would fail the specification it is named after.
#[test]
fn the_default_profile_does_not_refuse_them() {
    assert!(admit(b"1e21").is_ok());
    assert_eq!(admit(b"9007199254740993").unwrap(), b"9007199254740992");
    assert_eq!(admit(b"1.5").unwrap(), b"1.5");
}

/// Refusal reaches every position, not only a top-level number.
#[test]
fn the_profile_reaches_nested_positions() {
    for raw in [
        &br#"{"a":1e21}"#[..],
        &br#"[[[1e21]]]"#[..],
        &br#"{"a":{"b":[0,9007199254740992]}}"#[..],
    ] {
        assert!(
            matches!(admit_ijson(raw), Err(Error::UnsafeInteger { .. })),
            "{}",
            String::from_utf8_lossy(raw)
        );
    }
}

/// A Unicode noncharacter is refused under the profile and accepted without it.
/// RFC 7493 section 2.1 forbids them in the same sentence as surrogates.
#[test]
fn noncharacters_are_refused_under_the_profile_only() {
    let noncharacters = [
        "{\"a\":\"\u{fffe}\"}",  // U+FFFE, literal
        "{\"a\":\"\u{fdd0}\"}",  // U+FDD0, in the FDD0..FDEF block
        "{\"\u{ffff}\":1}",      // U+FFFF, in a member NAME
        "{\"a\":\"\u{1fffe}\"}", // U+1FFFE, the same pair one plane up
        r#"{"a":"\ufffe"}"#,     // and written as an escape
    ];
    for raw in noncharacters {
        assert!(
            matches!(
                admit_ijson(raw.as_bytes()),
                Err(Error::StringNotScalar { .. })
            ),
            "profile must refuse {raw}"
        );
        assert!(admit(raw.as_bytes()).is_ok(), "default must accept {raw}");
    }
    // A literal U+FFFD is a real scalar and stays legal under both.
    assert!(admit_ijson("{\"a\":\"\u{fffd}\"}".as_bytes()).is_ok());
}

/// The over-refusal guard for the profile: ordinary documents still pass.
#[test]
fn ordinary_documents_pass_under_the_profile() {
    for raw in [
        &br#"{"n":0,"m":-1,"big":9007199254740991}"#[..],
        &br#"[1,2,3,"a",true,null,{}]"#[..],
    ] {
        assert!(admit_ijson(raw).is_ok(), "{}", String::from_utf8_lossy(raw));
    }
}

/// A number token whose exponent does not fit an `i64` is still a valid JSON
/// number, and the profile must answer it as a NUMBER verdict or not at all --
/// never as "invalid JSON at byte 0", which is a claim about the input that the
/// input does not support, at an offset the fault is not at.
///
/// Before this was fixed the range check parsed the exponent into an `i64` and
/// turned overflow into a fabricated syntax error, so `0e99999999999999999999`
/// canonicalized to `0` under RFC 8785 and was refused as malformed JSON under
/// the I-JSON profile: the same bytes, two answers, one of them false. Zero is a
/// safe integer however its exponent is written.
#[test]
fn an_exponent_beyond_i64_is_a_number_verdict_not_a_syntax_error() {
    for token in [
        "0e99999999999999999999",
        "-0e99999999999999999999",
        "0.0e99999999999999999999",
        "0e-99999999999999999999",
        "-0.0e-99999999999999999999",
        "0.0e-9223372036854775808",
    ] {
        let got = admit_ijson(token.as_bytes());
        assert_eq!(
            got.as_deref().map(String::from_utf8_lossy).as_deref(),
            Ok("0"),
            "{token}: zero is a safe integer in every notation, got {got:?}"
        );
    }

    // A magnitude this far past 2^53 is an unsafe integer, and that is the
    // verdict the profile owes; the base profile has no double for it at all.
    for token in ["1e99999999999999999999", "1e9223372036854775808"] {
        assert!(
            matches!(
                admit_ijson(token.as_bytes()),
                Err(Error::UnsafeInteger { .. })
            ),
            "{token}: want UnsafeInteger, got {:?}",
            admit_ijson(token.as_bytes())
        );
        assert!(
            matches!(admit(token.as_bytes()), Err(Error::NonFiniteNumber { .. })),
            "{token}: the base profile owes NonFiniteNumber",
        );
    }

    // A magnitude that far BELOW 1 underflows to zero, which ECMAScript writes
    // as "0", and the profile accepts it exactly as RFC 8785 does.
    for token in [
        "1e-99999999999999999999",
        "1e-9223372036854775809",
        "123e-9223372036854775807",
    ] {
        assert_eq!(
            admit_ijson(token.as_bytes())
                .as_deref()
                .map(String::from_utf8_lossy)
                .as_deref(),
            Ok("0"),
            "{token}"
        );
    }

    // Whatever the verdict, it is never a syntax verdict: the parser already
    // accepted these bytes as one JSON number.
    for token in [
        "0e99999999999999999999",
        "1e99999999999999999999",
        "1e-99999999999999999999",
        "0.0e-9223372036854775808",
        "1e9223372036854775808",
    ] {
        assert!(
            !matches!(admit_ijson(token.as_bytes()), Err(Error::Syntax { .. })),
            "{token} was reported as invalid JSON by a number range check"
        );
    }
}
