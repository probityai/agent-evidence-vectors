//! The number half of admission: refusals decided on the *token*, before any
//! double exists.
//!
//! No serialization lives here. RFC 8785 section 3.2.2.3 defers number output to
//! ECMAScript `Number::toString`, `serde_json_canonicalizer` implements it over
//! `ryu_js`, and this crate delegates to it rather than carrying a third copy.
//! What cannot be delegated is the part that has to happen before the token
//! becomes an `f64`: a token at or above 2^53 still parses, and the double it
//! parses to is a *different* integer, so a check made after the parse is made
//! against the wrong number.

use crate::{Error, Options};

/// `2^53`, as its decimal digits. An integer whose magnitude is at or above this
/// has no exact IEEE-754 double.
const MAX_SAFE_DIGITS: &str = "9007199254740992";

/// A JSON number token decomposed into an exact `digits * 10^exp10`, with
/// `digits` carrying no leading and no trailing zero.
///
/// The decomposition is exact, which is what lets the check below see `1e21` and
/// `1.0e21` as the integer 10^21. A notation-blind range check -- one that only
/// inspects tokens without an 'e' or a '.' -- lets that integer walk straight
/// past the bound, and that is not hypothetical: it is the bypass the pinned
/// table in `tests/ijson_profile.rs` exists to hold shut.
struct Decomposed {
    digits: String,
    exp10: i64,
}

impl Decomposed {
    /// Whether the value is an integer, zero included.
    fn is_integer(&self) -> bool {
        self.digits.is_empty() || self.exp10 >= 0
    }

    /// Whether the magnitude is at or above `2^53`.
    ///
    /// Decided on the digit string rather than through an `f64`, so a token
    /// beyond double precision cannot round itself into the safe range on the
    /// way to being range-checked.
    fn is_unsafe_magnitude(&self) -> bool {
        if self.digits.is_empty() || self.exp10 < 0 {
            return false;
        }
        let Ok(exp) = usize::try_from(self.exp10) else {
            return true;
        };
        let Some(width) = self.digits.len().checked_add(exp) else {
            return true;
        };
        match width.cmp(&MAX_SAFE_DIGITS.len()) {
            core::cmp::Ordering::Less => false,
            core::cmp::Ordering::Greater => true,
            core::cmp::Ordering::Equal => {
                let mut padded = self.digits.clone();
                padded.push_str(&"0".repeat(exp));
                padded.as_str() >= MAX_SAFE_DIGITS
            }
        }
    }
}

/// Read a JSON exponent, saturating rather than failing.
///
/// A JSON exponent is an unbounded digit string, so `1e99999999999999999999` is
/// a valid number token and no fixed-width integer holds its exponent. Failing
/// there is what a range check must never do: the parser has already accepted
/// these bytes as one JSON number, so reporting them as invalid JSON is a false
/// statement about the input, and it was one the profile made at an offset the
/// fault was not at.
///
/// Saturating is exact for every decision made from this value. A token whose
/// exponent does not fit an `i64` is past the safe-integer bound by a factor no
/// arithmetic error here can reach, and whether the value is an integer at all
/// is decided by the sign, which saturation preserves.
fn exponent_of(text: &str) -> i64 {
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let mut value: i64 = 0;
    for byte in digits.bytes() {
        let digit = i64::from(byte.wrapping_sub(b'0'));
        value = value.saturating_mul(10).saturating_add(digit);
    }
    if negative {
        value.saturating_neg()
    } else {
        value
    }
}

/// Split a JSON number token into digits and a power of ten.
///
/// Infallible on purpose. The parser has already matched the JSON number
/// grammar, and every remaining quantity is computed with saturating arithmetic,
/// so there is no shape of valid token this can refuse to read -- and therefore
/// no path by which a number profile reports a syntax error.
fn decompose(token: &str) -> Decomposed {
    let body = token.strip_prefix('-').unwrap_or(token);
    let (mantissa, exponent) = match body.split_once(['e', 'E']) {
        Some((m, e)) => (m, exponent_of(e)),
        None => (body, 0),
    };
    let (int_part, frac_part) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let mut digits = String::with_capacity(int_part.len() + frac_part.len());
    digits.push_str(int_part);
    digits.push_str(frac_part);
    let mut exp10 = exponent.saturating_sub(i64::try_from(frac_part.len()).unwrap_or(i64::MAX));

    let leading = digits.len() - digits.trim_start_matches('0').len();
    digits.drain(..leading);
    while digits.ends_with('0') {
        digits.pop();
        exp10 = exp10.saturating_add(1);
    }
    Decomposed { digits, exp10 }
}

/// Apply the number half of admission to one token.
///
/// # Why the profile is consulted before finiteness
///
/// Both refusals can be true of one token and they carry different amounts of
/// information, so the order is a decision rather than a sequence.
/// `1e99999999999999999999` has no finite double AND is an integer far past
/// 2^53; a caller running the RFC 7493 profile is told which rule it broke, and
/// a caller running RFC 8785 as written -- where no integer bound exists -- is
/// told the only thing that is wrong there, that the specification has no
/// serialization for it. Deciding finiteness first collapses both callers onto
/// the weaker answer.
///
/// The finiteness refusal is the one that is unconditional, because
/// RFC 8785 section 3.2.2.3 defers to ECMAScript `Number::toString` and that
/// algorithm has no output for a value that is not finite.
pub(crate) fn check(token: &str, opts: &Options) -> Result<(), Error> {
    if opts.wants_safe_integers() || opts.wants_integers_only() {
        let d = decompose(token);
        if opts.wants_integers_only() && !d.is_integer() {
            return Err(Error::NonIntegerNumber {
                token: token.to_owned(),
            });
        }
        if opts.wants_safe_integers() && d.is_integer() && d.is_unsafe_magnitude() {
            return Err(Error::UnsafeInteger {
                token: token.to_owned(),
            });
        }
    }
    // Decided here rather than left to the delegate. `serde_json_canonicalizer`
    // does refuse a non-finite double, as an untyped `io::Error` reading "NaN
    // and +/-Infinity are not permitted in JSON" from inside a serializer; a
    // caller cannot match on it and it names no token. Measured 2026-09-19:
    // `pipe("1e400")` returns `number out of range at line 1 column 5`.
    if !token.parse::<f64>().is_ok_and(f64::is_finite) {
        return Err(Error::NonFiniteNumber {
            token: token.to_owned(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn exponent_notation_decomposes_as_an_integer() {
        let d = decompose("1e21");
        assert_eq!(d.digits, "1");
        assert_eq!(d.exp10, 21);
        assert!(d.is_integer());
        assert!(d.is_unsafe_magnitude());
    }

    #[test]
    fn zero_is_a_safe_integer_in_every_notation() {
        for token in ["0", "-0", "0.0", "0e100", "-0.000e-3"] {
            let d = decompose(token);
            assert!(d.is_integer(), "{token}");
            assert!(!d.is_unsafe_magnitude(), "{token}");
        }
    }

    #[test]
    fn the_safe_integer_boundary_is_exact_on_the_digits() {
        assert!(!decompose("9007199254740991").is_unsafe_magnitude());
        assert!(decompose("9007199254740992").is_unsafe_magnitude());
        assert!(decompose("9007199254740993").is_unsafe_magnitude());
        // Same digit width, smaller value: the comparison is not a width test.
        assert!(!decompose("1000000000000000").is_unsafe_magnitude());
        assert!(!decompose("9007199254740991.0").is_unsafe_magnitude());
    }

    #[test]
    fn a_fraction_is_not_an_integer_however_it_is_written() {
        assert!(!decompose("1.5").is_integer());
        assert!(!decompose("15e-1").is_integer());
        assert!(decompose("15e-1").exp10 == -1);
        assert!(decompose("100.0").is_integer());
    }
}
