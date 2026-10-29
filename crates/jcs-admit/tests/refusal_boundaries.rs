//! Every bound, from BOTH sides.
//!
//! A refusal test that only feeds inputs past the bound cannot tell a correct
//! guard from an over-tight one, and an over-tight guard on a verifier refuses
//! documents that are perfectly good evidence. Each case here pairs the largest
//! admitted input with the smallest refused one.
//!
//! Two of these exist because planning the mutation sweep found nothing that
//! would catch the corresponding mistake. No test carried a NEGATIVE non-finite
//! token, so a finiteness check written as `value != f64::INFINITY` passed the
//! whole suite; and no test asserted that an input of exactly
//! `DEFAULT_MAX_BYTES` is admitted, so a size check written `>=` passed it too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use jcs_admit::{admit, admit_ijson, Error, DEFAULT_MAX_BYTES, DEFAULT_MAX_DEPTH};

/// Both signs of overflow. `-1e400` is the case a one-sided comparison misses,
/// and the sign of a number is not a detail in a document somebody signs.
#[test]
fn a_non_finite_number_is_refused_at_either_sign() {
    for token in ["1e400", "-1e400", "1e309", "-1e309", "1e99999", "-1e99999"] {
        match admit(token.as_bytes()) {
            Err(Error::NonFiniteNumber { token: got }) => assert_eq!(got, token),
            other => panic!("{token}: want NonFiniteNumber, got {other:?}"),
        }
    }
    // The largest finite double and its negative are admitted, so the guard is
    // not simply refusing everything large.
    for token in ["1.7976931348623157e308", "-1.7976931348623157e308"] {
        assert!(
            admit(token.as_bytes()).is_ok(),
            "{token} is finite and must be admitted"
        );
    }
    // Underflow is not overflow: a magnitude far below 1 becomes zero, which
    // ECMAScript writes as "0", and RFC 8785 admits it.
    for token in ["1e-400", "-1e-400"] {
        assert_eq!(
            admit(token.as_bytes()).expect("underflow is admissible"),
            b"0",
            "{token} underflows to zero"
        );
    }
}

/// An input of exactly the cap is admitted; one byte more is refused.
#[test]
fn the_size_cap_admits_exactly_the_cap() {
    // A document of exactly DEFAULT_MAX_BYTES: an array of spaces around a null.
    let mut at_cap = vec![b' '; DEFAULT_MAX_BYTES];
    at_cap[0] = b'[';
    at_cap[1..5].copy_from_slice(b"null");
    let last = at_cap.len() - 1;
    at_cap[last] = b']';
    assert_eq!(at_cap.len(), DEFAULT_MAX_BYTES);
    assert!(
        admit(&at_cap).is_ok(),
        "an input of exactly {DEFAULT_MAX_BYTES} bytes must be admitted, or the cap \
         is off by one in the direction that refuses good evidence"
    );

    let mut over = at_cap.clone();
    over.insert(1, b' ');
    assert_eq!(over.len(), DEFAULT_MAX_BYTES + 1);
    match admit(&over) {
        Err(Error::TooLarge { len, limit }) => {
            assert_eq!(len, DEFAULT_MAX_BYTES + 1);
            assert_eq!(limit, DEFAULT_MAX_BYTES);
        }
        other => panic!("want TooLarge, got {:?}", other.map(|b| b.len())),
    }
}

/// Zero is an integer in every notation it can be written in.
///
/// Added because the mutation sweep found it. Reducing `is_integer` to
/// `exp10 >= 0` -- dropping the empty-digits case -- makes `0.0` a NON-integer
/// and gets it refused under the integers-only profile, and the whole
/// integration suite passed with that in place. Only a unit test on the
/// decomposition caught it, and a unit test on a private helper does not survive
/// the helper being replaced. This states the rule at the entry point instead.
#[test]
fn zero_is_an_integer_in_every_notation_at_the_entry_point() {
    use jcs_admit::{admit_with, Options};
    let opts = Options::ijson().integers_only(true);
    for token in [
        "0",
        "-0",
        "0.0",
        "-0.0",
        "0e100",
        "0e-100",
        "0.000e-3",
        "-0.000e-3",
    ] {
        assert_eq!(
            admit_with(token.as_bytes(), &opts).unwrap_or_else(|e| panic!("{token}: {e}")),
            b"0",
            "{token} is the integer zero and canonicalizes to 0"
        );
    }
}

/// The safe-integer bound is exclusive at 2^53 and exact on the digits, in both
/// signs and in every notation.
#[test]
fn the_safe_integer_bound_is_exclusive_and_two_sided() {
    for token in [
        "9007199254740991",
        "-9007199254740991",
        "9007199254740991.0",
        "9.007199254740991e15",
    ] {
        assert!(admit_ijson(token.as_bytes()).is_ok(), "{token} is exact");
    }
    for token in [
        "9007199254740992",
        "-9007199254740992",
        "9007199254740992.0",
        "9.007199254740992e15",
    ] {
        assert!(
            matches!(
                admit_ijson(token.as_bytes()),
                Err(Error::UnsafeInteger { .. })
            ),
            "{token} is 2^53 or beyond, in whatever notation"
        );
    }
}

/// The depth cap admits exactly `DEFAULT_MAX_DEPTH` containers and refuses one
/// more, counted per OPEN container so an empty one cannot slip a level past.
#[test]
fn the_depth_cap_admits_exactly_the_cap_including_an_empty_innermost() {
    let filled = |n: usize| format!("{}null{}", "[".repeat(n), "]".repeat(n));
    // An empty innermost container is the case a cap charged per parsed CHILD
    // misses: there is no child to charge for.
    let empty = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    for build in [&filled as &dyn Fn(usize) -> String, &empty] {
        let at = build(DEFAULT_MAX_DEPTH);
        assert!(
            admit(at.as_bytes()).is_ok(),
            "exactly {DEFAULT_MAX_DEPTH} containers must be admitted"
        );
        let over = build(DEFAULT_MAX_DEPTH + 1);
        assert!(
            matches!(
                admit(over.as_bytes()),
                Err(Error::TooDeep {
                    limit: DEFAULT_MAX_DEPTH,
                    ..
                })
            ),
            "{} containers must be refused",
            DEFAULT_MAX_DEPTH + 1
        );
    }
}
