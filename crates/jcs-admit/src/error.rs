//! The single error type every entry point returns.
//!
//! Every variant names a fault a caller can branch on, and that is half the
//! reason this crate exists. The canonicalizer it delegates to reports what it
//! does refuse as an untyped `serde_json::Error` -- measured 2026-09-19, a lone
//! surrogate escape and nesting past its limit and a number out of range all
//! arrive as one opaque type carrying a line and a column -- so a verifier
//! reading it cannot treat a split-view document differently from a typo, and no
//! refusal names the cap it crossed or the member it repeated.

use core::fmt;

/// Why a document was refused.
///
/// Every variant is a refusal, never a repair. A canonicalizer that repairs its
/// input produces bytes two parties can disagree about, which is the whole
/// failure canonicalization exists to remove.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "variant", content = "fields"))]
#[non_exhaustive]
pub enum Error {
    /// The bytes are not one syntactically valid JSON value.
    Syntax {
        /// Byte offset where the scan stopped.
        offset: usize,
        /// What the parser expected there.
        reason: &'static str,
    },
    /// A complete JSON value was followed by something other than whitespace.
    TrailingContent {
        /// Byte offset of the first unexpected byte.
        offset: usize,
    },
    /// An object repeated a member name.
    ///
    /// Collapsing a repeat to last-wins is a split-view attack: two parties
    /// read the same bytes as two different documents, and a signature over
    /// either reading verifies.
    DuplicateMember {
        /// The repeated member name.
        name: String,
        /// Byte offset of the repeated name's opening quote.
        offset: usize,
    },
    /// A string literal's bytes do not denote a sequence of Unicode scalar
    /// values: an unpaired surrogate escape, a surrogate escape pair that is
    /// not high-then-low, a raw control character, invalid UTF-8 (which
    /// includes an overlong form and a surrogate encoded directly in UTF-8),
    /// or, under the I-JSON profile, a Unicode noncharacter.
    ///
    /// The check runs on the raw bytes before any decode, because a decoder
    /// cannot report it afterwards: a decoder that substitutes U+FFFD leaves
    /// three distinct wire strings canonicalizing to identical bytes.
    StringNotScalar {
        /// Byte offset inside the document.
        offset: usize,
        /// Which fault was found.
        reason: &'static str,
    },
    /// An integer outside the range where an IEEE-754 double is exact,
    /// refused under the I-JSON safe-integer profile.
    UnsafeInteger {
        /// The offending number token, as written.
        token: String,
    },
    /// A number with a fractional part, refused under the integers-only
    /// tightening of the I-JSON profile.
    NonIntegerNumber {
        /// The offending number token, as written.
        token: String,
    },
    /// A number token whose value is not finite as an IEEE-754 double, so
    /// RFC 8785 has no serialization for it.
    NonFiniteNumber {
        /// The offending number token, as written.
        token: String,
    },
    /// Nesting exceeded the configured depth cap.
    ///
    /// The cap refuses rather than recursing. Without it a crafted document
    /// overflows the stack, which is not catchable and happens before any
    /// signature is checked.
    TooDeep {
        /// The cap that was exceeded.
        limit: usize,
        /// Byte offset of the container that would have crossed it.
        offset: usize,
    },
    /// The delegate refused to serialize a document this crate admitted.
    ///
    /// Unreachable for an admitted document, and present rather than a panic:
    /// `serde_json_canonicalizer` returns a `serde_json::Error` that is neither
    /// `Clone` nor `Eq`, so it is carried as its rendered text. A caller that
    /// sees this variant is looking at a disagreement between the admission
    /// layer and the canonicalizer, which is a defect in one of them and not a
    /// statement about the input.
    Canonicalization {
        /// What the delegate reported, rendered.
        detail: String,
    },
    /// The input exceeded the configured size cap.
    ///
    /// A depth cap bounds the stack; a size cap bounds the heap. Both are
    /// needed, because a depth limit alone leaves memory use proportional to
    /// input length.
    TooLarge {
        /// Input length in bytes.
        len: usize,
        /// The cap that was exceeded.
        limit: usize,
    },
}

/// How much attacker-chosen text one refusal message may carry.
///
/// Long enough that no honest member name or number token is clipped, short
/// enough that whoever sent a document cannot choose the size of the
/// recipient's log line. Measured before this bound existed: a 2 MiB document
/// repeating a 1 MiB member name rendered a 1,048,618-character message, and a
/// verifier that logs why it refused a document is the ordinary case, so the
/// amplification sits on the path that matters.
const RENDER_BUDGET: usize = 96;

/// Render `value` for a message, escaped and bounded.
///
/// Escaping first and clipping second is the order that matters. `Debug` for a
/// string is what keeps a member name carrying a newline from adding a line to
/// someone's log, and escaping can multiply the length -- ninety control
/// characters are ninety bytes and four hundred and fifty rendered -- so a bound
/// applied before it is not a bound on what gets written.
fn clipped(value: &str) -> String {
    let escaped = format!("{value:?}");
    if escaped.len() <= RENDER_BUDGET {
        return escaped;
    }
    let end = (0..=RENDER_BUDGET)
        .rev()
        .find(|i| escaped.is_char_boundary(*i))
        .unwrap_or(0);
    format!(
        "{}... [{} bytes elided]",
        &escaped[..end],
        value.len().saturating_sub(end)
    )
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax { offset, reason } => {
                write!(f, "invalid JSON at byte {offset}: {reason}")
            }
            Self::TrailingContent { offset } => {
                write!(f, "trailing content after the JSON value at byte {offset}")
            }
            Self::DuplicateMember { name, offset } => {
                write!(
                    f,
                    "duplicate object member {} at byte {offset}",
                    clipped(name)
                )
            }
            Self::StringNotScalar { offset, reason } => write!(
                f,
                "JSON string is not a sequence of Unicode scalar values at byte {offset}: {reason}"
            ),
            Self::UnsafeInteger { token } => {
                write!(
                    f,
                    "integer outside the I-JSON safe range: {}",
                    clipped(token)
                )
            }
            Self::NonIntegerNumber { token } => {
                write!(
                    f,
                    "non-integer number outside the integers-only profile: {}",
                    clipped(token)
                )
            }
            Self::NonFiniteNumber { token } => {
                write!(
                    f,
                    "number is not a finite IEEE-754 double: {}",
                    clipped(token)
                )
            }
            Self::TooDeep { limit, offset } => {
                write!(
                    f,
                    "JSON nesting exceeds the maximum depth {limit} at byte {offset}"
                )
            }
            Self::TooLarge { len, limit } => {
                write!(f, "JSON input of {len} bytes exceeds the maximum {limit}")
            }
            Self::Canonicalization { detail } => {
                write!(
                    f,
                    "canonicalization of an admitted document failed: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for Error {}
