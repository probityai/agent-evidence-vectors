//! Admission control for JSON that is about to be signed or verified.
//!
//! One document has one canonical form, and a signature means nothing unless
//! every party agrees which bytes those are. RFC 8785 says how to write them.
//! This crate decides which documents are allowed to have them, refuses the rest
//! on the raw bytes, and then hands the writing to
//! [`serde_json_canonicalizer`].
//!
//! # Why a separate layer
//!
//! The two canonicalizers on crates.io are serde `Serializer`s. That is the
//! right shape for their job and it fixes where they can stand: a value has
//! already been parsed before either of them is reached, and the faults that
//! matter to a verifier are the ones that vanish during that parse. A repeated
//! object member is gone -- the map kept one of the two and nothing downstream
//! can tell it happened. There is no layer below them to put the check in, so the
//! check goes above them, on the bytes, which is this crate.
//!
//! Measured against `serde_json_canonicalizer` 0.3.2 on 2026-09-19 (the run is
//! pinned in `tests/incumbent_differential.rs`, which fails if any of it stops
//! being true):
//!
//! | input | the delegate | this crate |
//! |---|---|---|
//! | `{"a":1,"a":2}` | `{"a":2}` via `pipe`, `{"a":1}` straight into its serializer | [`Error::DuplicateMember`] |
//! | 129 nested arrays | accepted by `to_vec`; 10,000 aborts the process | [`Error::TooDeep`] |
//! | `9007199254740993` | `9007199254740992`, a different integer | [`Error::UnsafeInteger`] under [`admit_ijson`]; [`admit`] rewrites it the same way |
//! | 12 MB of array | accepted | [`Error::TooLarge`] |
//!
//! The third row's right-hand cell names [`admit_ijson`] and the qualification is
//! load-bearing: the RFC 8785 default *admits* that token and canonicalizes it to
//! `9007199254740992`, the same different integer the delegate produces, because
//! section 3.2.2.3 defers to ECMAScript and ECMAScript has one numeric type. The
//! The first row is the one to read twice. One document, one crate, two canonical
//! forms depending on which of its entry points you used, and both of them
//! signable.
//!
//! What the delegate gets right, it gets right for us: it formats numbers through
//! `ryu_js`, which is the ECMAScript `Number::toString` variant RFC 8785 section
//! 3.2.2.3 requires, and it reads the RFC's own awkward reference number
//! `333333333.33333329` correctly. This crate stands on that rather than carrying
//! a third copy of it.
//!
//! # What it refuses
//!
//! 1. **A repeated object member** ([`Error::DuplicateMember`]). Collapsing a
//!    repeat to last-wins is a split view: two parties read the same bytes as two
//!    different documents and a signature over either reading verifies.
//!    Comparison is on the *decoded* name, so `"a"` and `"a"` are one member.
//! 2. **Nesting past a cap** ([`DEFAULT_MAX_DEPTH`], 128 -- the value RFC 8785's
//!    in-toto profile made normative). Without a cap a crafted document
//!    overflows the stack, which no caller can catch and which happens before any
//!    signature is checked.
//! 3. **A string whose bytes are not Unicode scalar values**
//!    ([`Error::StringNotScalar`]): an unpaired surrogate escape, a surrogate
//!    written directly in UTF-8, an overlong form, a raw control character.
//!    Checked before any decode, because a decoder that substitutes U+FFFD
//!    leaves `"\ud800"`, `"\udc00"` and a literal U+FFFD canonicalizing to
//!    identical bytes.
//! 4. **A number with no finite double** ([`Error::NonFiniteNumber`]), and under
//!    the opt-in RFC 7493 profile ([`admit_ijson`]) an integer at or above 2^53
//!    ([`Error::UnsafeInteger`]) or a Unicode noncharacter.
//! 5. **An input past a size cap** ([`Error::TooLarge`]). A depth cap bounds the
//!    stack; a size cap bounds the heap.
//!
//! # Examples
//!
//! ```
//! use jcs_admit::{admit, Error};
//!
//! assert_eq!(admit(br#"{ "b": 1, "a": [1.0, 1e30] }"#)?, br#"{"a":[1,1e+30],"b":1}"#);
//!
//! // The refusal the layer exists for, and it names the member.
//! assert!(matches!(
//!     admit(br#"{"a":1,"a":2}"#),
//!     Err(Error::DuplicateMember { .. })
//! ));
//! # Ok::<(), Error>(())
//! ```

#![doc(html_root_url = "https://docs.rs/jcs-admit/0.1.1")]

mod delegate;
mod error;
mod number;
mod parse;

pub use error::Error;

/// The default depth cap: at most 128 nested arrays and objects.
///
/// Not arbitrary. 128 is the nesting limit `serde_json` enforces by default, it
/// is the `MAX_DEPTH` the in-toto attestation specification carries as normative
/// text, it is far below the stack-overflow point so the counter trips with an
/// ordinary error first, and it is orders of magnitude above any real signed
/// payload. Three values exist in the wild -- 128, 256, and none at all -- and
/// the third is a crash.
pub const DEFAULT_MAX_DEPTH: usize = 128;

/// The deepest nesting this crate honours, whatever a caller configures.
///
/// A depth cap is only a refusal while it is below the stack. The admission walk
/// recurses, one frame per open container, so a cap above the stack is not a cap:
/// measured on this machine before the ceiling existed, an unbounded cap on
/// 19,414 nested arrays aborted the process with "fatal runtime error: stack
/// overflow" -- not an `Err`, not catchable, reached through safe API in a crate
/// that forbids `unsafe` entirely. [`Options::max_depth`] saturates here: four
/// times the default, sized against the *unoptimized* build because that is the
/// profile a caller's own tests run under.
pub const MAX_SUPPORTED_DEPTH: usize = 512;

/// The default size cap on untrusted input, 20 MiB.
pub const DEFAULT_MAX_BYTES: usize = 20 << 20;

/// What to refuse beyond the RFC 8785 baseline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    max_depth: usize,
    max_bytes: Option<usize>,
    safe_integers: bool,
    integers_only: bool,
    reject_noncharacters: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self::rfc8785()
    }
}

impl Options {
    /// RFC 8785 as written, with the depth and size caps applied.
    #[must_use]
    pub const fn rfc8785() -> Self {
        Self {
            max_depth: DEFAULT_MAX_DEPTH,
            max_bytes: Some(DEFAULT_MAX_BYTES),
            safe_integers: false,
            integers_only: false,
            reject_noncharacters: false,
        }
    }

    /// RFC 8785 plus the RFC 7493 I-JSON profile: an integer must lie inside the
    /// range where an IEEE-754 double is exact, and a Unicode noncharacter is
    /// refused in a string literal.
    ///
    /// Opt-in rather than default, and the reason is load-bearing: the RFC 8785
    /// reference suite carries `1e30` and `1e-27`, so a crate whose default
    /// refused them would fail the specification it implements.
    #[must_use]
    pub const fn ijson() -> Self {
        Self {
            safe_integers: true,
            reject_noncharacters: true,
            ..Self::rfc8785()
        }
    }

    /// Set the maximum number of nested arrays and objects.
    ///
    /// Lowered freely; raised only as far as [`MAX_SUPPORTED_DEPTH`], where a
    /// larger request saturates. The clamp is the difference between a
    /// configuration and a crash.
    #[must_use]
    pub const fn max_depth(mut self, limit: usize) -> Self {
        self.max_depth = if limit > MAX_SUPPORTED_DEPTH {
            MAX_SUPPORTED_DEPTH
        } else {
            limit
        };
        self
    }

    /// Set the maximum input size in bytes, or `None` for no cap.
    #[must_use]
    pub const fn max_bytes(mut self, limit: Option<usize>) -> Self {
        self.max_bytes = limit;
        self
    }

    /// Check only the configured byte cap before allocating an input buffer.
    ///
    /// This does not inspect, parse or admit any bytes. Passing the check means
    /// only that `len` is within the configured cap, or that no cap is set.
    /// Admission still requires [`admit_with`], which uses this same check first.
    ///
    /// ```
    /// use jcs_admit::{admit_with, Error, Options};
    /// let opts = Options::rfc8785().max_bytes(Some(16));
    /// assert_eq!(opts.check_input_length(16), Ok(()));
    /// assert_eq!(opts.check_input_length(17),
    ///     Err(Error::TooLarge { len: 17, limit: 16 }));
    /// // A length within the cap does not establish valid JSON.
    /// assert!(opts.check_input_length(1).is_ok());
    /// assert!(admit_with(b"{", &opts).is_err());
    /// ```
    pub fn check_input_length(&self, len: usize) -> Result<(), Error> {
        if let Some(limit) = self.max_bytes {
            if len > limit {
                return Err(Error::TooLarge { len, limit });
            }
        }
        Ok(())
    }

    /// Refuse an integer outside the range where an IEEE-754 double is exact.
    #[must_use]
    pub const fn safe_integers(mut self, refuse: bool) -> Self {
        self.safe_integers = refuse;
        self
    }

    /// Refuse any number with a fractional part.
    ///
    /// Tighter than RFC 7493, which permits one. Two implementations that never
    /// format a float can never disagree about one, so pinning integers only
    /// removes a class of cross-language divergence rather than testing for it.
    #[must_use]
    pub const fn integers_only(mut self, refuse: bool) -> Self {
        self.integers_only = refuse;
        self
    }

    /// Refuse a Unicode noncharacter in a string literal (RFC 7493 section 2.1).
    #[must_use]
    pub const fn reject_noncharacters(mut self, refuse: bool) -> Self {
        self.reject_noncharacters = refuse;
        self
    }

    pub(crate) const fn depth_limit(&self) -> usize {
        self.max_depth
    }

    pub(crate) const fn wants_safe_integers(&self) -> bool {
        self.safe_integers
    }

    pub(crate) const fn wants_integers_only(&self) -> bool {
        self.integers_only
    }

    pub(crate) const fn wants_noncharacter_check(&self) -> bool {
        self.reject_noncharacters
    }
}

/// Admit one JSON document and return its RFC 8785 canonical form.
///
/// Takes `&[u8]` rather than `&str` on purpose: a document arrives off a socket
/// or off disk as bytes, and the faults this crate refuses include ones no `&str`
/// can hold. A surrogate written directly in UTF-8 and an overlong form are
/// unrepresentable in a Rust string, so an entry point taking `&str` cannot be
/// handed them at all and its caller has to validate the bytes first -- which is
/// the check, moved back onto the caller. Measured 2026-09-19: the delegate's
/// only byte-facing entry point, `pipe`, takes `&str`.
///
/// # The number it hands back may not be the number it was given
///
/// RFC 8785 section 3.2.2.3 defers number formatting to ECMAScript, and
/// ECMAScript has one numeric type. So `admit(b"9007199254740993")` returns
/// `9007199254740992` and `admit(b"18446744073709551617")` returns
/// `18446744073709552000`: admitted, canonical, and a different number than the
/// wire carried. That is the specification working as written rather than a
/// defect in it -- the RFC's own reference vectors carry `1e30` and
/// `333333333.33333329`, so a default that refused inexact tokens would fail the
/// specification this crate implements.
///
/// A *producer* canonicalizing before it signs is the caller who cannot live with
/// that, because it signs the rewritten number. [`admit_ijson`] is the answer:
/// the RFC 7493 safe-integer profile refuses the token instead of rewriting it.
/// A verifier that hashes the bytes it received rather than bytes it
/// re-serialized is unaffected, which is why the profile is opt-in.
///
/// # Errors
///
/// Returns [`Error`] when the input is not one valid JSON value, repeats an
/// object member, carries a string that is not a sequence of Unicode scalar
/// values, nests past [`DEFAULT_MAX_DEPTH`], exceeds [`DEFAULT_MAX_BYTES`], or
/// carries a number with no finite double.
pub fn admit(input: &[u8]) -> Result<Vec<u8>, Error> {
    admit_with(input, &Options::rfc8785())
}

/// Admit one JSON document under the RFC 7493 I-JSON profile.
///
/// # Errors
///
/// As [`admit`], and additionally for an integer at or above 2^53 or a Unicode
/// noncharacter in a string literal.
pub fn admit_ijson(input: &[u8]) -> Result<Vec<u8>, Error> {
    admit_with(input, &Options::ijson())
}

/// Admit one JSON document under explicit options.
///
/// # Errors
///
/// As [`admit`], under the supplied [`Options`].
pub fn admit_with(input: &[u8], opts: &Options) -> Result<Vec<u8>, Error> {
    opts.check_input_length(input.len())?;
    let node = parse::Parser::new(input, opts).document()?;
    serde_json_canonicalizer::to_vec(&node).map_err(|e| Error::Canonicalization {
        detail: e.to_string(),
    })
}

/// Whether `input` is admissible AND already its own canonical form.
///
/// The question a verifier has. It must hash the bytes it received, not
/// bytes it re-serialized, so what it needs to know is whether those two are the
/// same -- and a document that parses but was not stored canonically is exactly
/// the disagreement a second implementation exists to catch. Neither canonicalizer
/// on crates.io exposes this; a caller has to canonicalize and compare, and get
/// the comparison right.
#[must_use]
pub fn is_canonical(input: &[u8]) -> bool {
    is_canonical_with(input, &Options::rfc8785())
}

/// Whether `input` is admissible and already canonical under `opts`.
///
/// [`is_canonical`] answers for RFC 8785 as written, which is the wrong question
/// for a caller who verifies under a profile: a document carrying a Unicode
/// noncharacter is canonical by RFC 8785 and refused by [`admit_ijson`], so a
/// verifier that admits bytes with the plain gate and then verifies them under
/// the profile has admitted a document its own profile will not accept. Ask with
/// the options the verify path uses.
#[must_use]
pub fn is_canonical_with(input: &[u8], opts: &Options) -> bool {
    admit_with(input, opts).is_ok_and(|canonical| canonical == input)
}
